//! Host-verified Unix-socket transport: the container driver's replacement for
//! the shared-secret tier (#2446, step 1).
//!
//! # The problem this solves
//!
//! A Firecracker pod's proxy serves over vsock, and the guest kernel stamps
//! every accepted connection with the peer CID — "this came from the host" is
//! a kernel fact, so the HMAC tier is unreachable there
//! (`pod_mgmt::peer_is_host`). A container pod has no vsock: its proxy sidecar
//! listens on loopback TCP and the only thing separating the host's requests
//! from the agent's is `NUCLEUS_TOOL_PROXY_AUTH_SECRET`, a key delivered in the
//! container's environment, which every process in the container can read.
//! That is the bare shared-secret tier the owner decided to deprecate.
//!
//! # What replaces it
//!
//! A Unix domain socket whose peers are identified by the kernel
//! (`SO_PEERCRED` / `LOCAL_PEERCRED`), never by a secret:
//!
//! - the socket lives in a directory the node bind-mounts into exactly one
//!   container, so possession of the path is already scoped to that pod and
//!   the host;
//! - every accepted connection's peer credentials are read from the kernel and
//!   checked by [`PeerPolicy::admits`] BEFORE the stream reaches the router.
//!   An untrusted peer is dropped at accept, so the request layer never sees
//!   it and `AppState::host_verified_transport` is a sound description of
//!   every request it does see;
//! - on Linux a peer outside the proxy's pid namespace reports `pid == 0`
//!   (the kernel translates the peer's pid into the receiver's namespace and
//!   yields 0 when it is not visible there). Through a socket mounted only
//!   into this container, "not in my pid namespace" is "the host": that is the
//!   analogue of the vsock host CID. A peer INSIDE the namespace is admitted
//!   only when its uid is the proxy's own or one the operator listed
//!   (`--peer-uids`), which is the same-container loopback trust the HMAC tier
//!   stood in for, now enforced below the application instead of by a key the
//!   agent can read.
//!
//! # What this does and does not claim
//!
//! - It binds the TRANSPORT to a kernel-verified peer. It does not bind an
//!   identity a delegation certificate can act for: like `HostVsock`, this
//!   tier has `DelegationAuthority::Unbound` (`pod_cert::delegation_authority`)
//!   and a certificate presented on it is refused.
//! - Off Linux, `pid` is a real pid (or absent), so the "outside my namespace"
//!   host rule never fires and only the uid rule admits; the container driver
//!   runs on Linux, and the tests pin both rules.
//! - `--listen-unix` and a vsock binding are mutually exclusive: one
//!   host-verified transport per proxy, so the audit record's `AuthMethod`
//!   names the transport that actually carried the request.

use std::path::{Path, PathBuf};

use axum::Router;
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use crate::ApiError;
use crate::pod_mgmt::{self, BoundVsock, VsockConfig};
use crate::startup_trace::Startup;
use crate::workload::BoundProxy;

/// Where to bind and whom to admit; resolved from the CLI before the state is
/// built, like `pod_mgmt::resolve_vsock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnixConfig {
    pub(crate) path: PathBuf,
    pub(crate) peer_uids: Vec<u32>,
}

/// Resolve the Unix-socket binding from the CLI. `None` when not configured.
///
/// Refuses the combination with a vsock binding: two host-verified transports
/// on one proxy would make `AuthMethod` ambiguous in the audit record.
pub(crate) fn resolve_unix(
    listen_unix: Option<&Path>,
    peer_uids: &[u32],
    vsock: Option<&VsockConfig>,
) -> Result<Option<UnixConfig>, ApiError> {
    let Some(path) = listen_unix else {
        if !peer_uids.is_empty() {
            return Err(ApiError::Spec(
                "--peer-uids requires --listen-unix".to_string(),
            ));
        }
        return Ok(None);
    };
    if vsock.is_some() {
        return Err(ApiError::Spec(
            "--listen-unix and a vsock binding are mutually exclusive: one host-verified transport per proxy"
                .to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(ApiError::Spec(format!(
            "--listen-unix must be an absolute path, got {}",
            path.display()
        )));
    }
    Ok(Some(UnixConfig {
        path: path.to_path_buf(),
        peer_uids: peer_uids.to_vec(),
    }))
}

/// The admission rule for a peer, over facts the kernel reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerPolicy {
    /// The proxy's own effective uid: a same-container peer running as the
    /// proxy itself (the usual sidecar layout) is admitted.
    own_uid: u32,
    /// Operator-listed additional uids (e.g. an agent running as a dedicated
    /// unprivileged user in the same container).
    peer_uids: Vec<u32>,
}

impl PeerPolicy {
    pub(crate) fn new(own_uid: u32, peer_uids: Vec<u32>) -> Self {
        Self { own_uid, peer_uids }
    }

    /// Is a peer with these kernel-reported credentials admitted?
    ///
    /// - `pid == Some(0)`: the peer is outside this pid namespace. Through a
    ///   socket mounted only into this container that is the host — the
    ///   container analogue of `peer_is_host` on vsock.
    /// - otherwise the peer is inside the namespace and is admitted only by
    ///   uid: the proxy's own, or an operator-listed one.
    ///
    /// `pid == None` (a platform that does not report it) falls through to the
    /// uid rule, never to the host rule.
    pub(crate) fn admits(&self, uid: u32, pid: Option<i32>) -> bool {
        if pid == Some(0) {
            return true;
        }
        uid == self.own_uid || self.peer_uids.contains(&uid)
    }
}

/// A bound, listening Unix socket with its admission policy.
pub(crate) struct BoundUnix {
    listener: UnixListener,
    path: PathBuf,
    policy: PeerPolicy,
}

/// Bind the socket (replacing a stale file from a previous run), write the
/// announce file if asked, and attach the admission policy.
pub(crate) async fn bind_unix(
    cfg: UnixConfig,
    announce_path: Option<PathBuf>,
) -> Result<BoundUnix, ApiError> {
    if let Some(parent) = cfg.path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    match tokio::fs::remove_file(&cfg.path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(&cfg.path)?;
    if let Some(path) = announce_path {
        tokio::fs::write(path, unix_url(&cfg.path)).await?;
    }
    let policy = PeerPolicy::new(current_uid(), cfg.peer_uids);
    Ok(BoundUnix {
        listener,
        path: cfg.path,
        policy,
    })
}

/// The URL form the workload and the announce file carry for a Unix socket.
pub(crate) fn unix_url(path: &Path) -> String {
    format!("unix://{}", path.display())
}

fn current_uid() -> u32 {
    // The same std-only uid read the workload launcher uses (`/proc/self`
    // owner on Linux, cwd owner elsewhere): no FFI, so no `unsafe` block for
    // the exemplar ratchet to count, and one definition of "our uid".
    crate::workload::nix_getuid()
}

/// The axum listener that enforces [`PeerPolicy`] at accept time.
struct PeerVerifiedUnixListener {
    inner: UnixListener,
    policy: PeerPolicy,
}

impl axum::serve::Listener for PeerVerifiedUnixListener {
    type Io = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    // FAIL CLOSED ON PEER IDENTITY, before the router sees the
                    // stream. The facts come from the kernel; if it cannot
                    // report them the peer is not admitted.
                    let cred = match stream.peer_cred() {
                        Ok(c) => c,
                        Err(err) => {
                            warn!(
                                "rejecting unix-socket connection: peer credentials unavailable: {err}"
                            );
                            drop(stream);
                            continue;
                        }
                    };
                    if !self.policy.admits(cred.uid(), cred.pid()) {
                        warn!(
                            peer_uid = cred.uid(),
                            peer_pid = ?cred.pid(),
                            "rejecting unix-socket connection from an unadmitted peer"
                        );
                        drop(stream);
                        continue;
                    }
                    return (stream, addr);
                }
                Err(err) => {
                    tracing::error!("unix-socket accept error: {err}");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Serve the router over the bound socket until the listener errors out.
pub(crate) async fn serve_unix(app: Router, bound: BoundUnix) -> Result<(), ApiError> {
    info!(
        "nucleus-tool-proxy listening on unix socket {} (peer-credential admission)",
        bound.path.display()
    );
    let listener = PeerVerifiedUnixListener {
        inner: bound.listener,
        policy: bound.policy,
    };
    axum::serve(listener, app).await?;
    Ok(())
}

/// The one host-verified transport a proxy may serve on: vsock in a microVM,
/// a peer-verified Unix socket in a container. `main` binds whichever is
/// configured and serves it the same way; the HMAC tier is unreachable on both
/// (`auth::select_auth_tier`).
pub(crate) enum HostBound {
    Vsock(BoundVsock),
    Unix(BoundUnix),
}

impl HostBound {
    /// What the workload's `NUCLEUS_TOOL_PROXY_URL` should name.
    pub(crate) fn proxy(&self) -> BoundProxy {
        match self {
            Self::Vsock(b) => BoundProxy::Vsock {
                cid: b.cid(),
                port: b.port(),
            },
            Self::Unix(b) => BoundProxy::Unix(b.path.clone()),
        }
    }

    pub(crate) async fn serve(self, app: Router) -> Result<(), ApiError> {
        match self {
            Self::Vsock(b) => pod_mgmt::serve_vsock(app, b).await,
            Self::Unix(b) => serve_unix(app, b).await,
        }
    }
}

/// Bind the configured host-verified transport, if any, recording the bind in
/// the startup trace under the transport's own mark.
pub(crate) async fn bind_host_verified(
    vsock: Option<VsockConfig>,
    unix: Option<UnixConfig>,
    announce_path: Option<PathBuf>,
    st: &mut Startup,
) -> Result<Option<HostBound>, ApiError> {
    if let Some(v) = vsock {
        let bound = st
            .timed("vsock_bind", pod_mgmt::bind_vsock(v, announce_path))
            .await?;
        return Ok(Some(HostBound::Vsock(bound)));
    }
    if let Some(u) = unix {
        let bound = st.timed("unix_bind", bind_unix(u, announce_path)).await?;
        return Ok(Some(HostBound::Unix(bound)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn the_host_rule_is_pid_zero_only() {
        let p = PeerPolicy::new(1000, vec![]);
        assert!(p.admits(0, Some(0)), "outside-namespace peer is the host");
        assert!(p.admits(65534, Some(0)), "even an unmapped uid, if outside");
        assert!(!p.admits(0, Some(1)), "in-namespace root is NOT the host");
        assert!(!p.admits(0, None), "no pid never means host");
    }

    #[test]
    fn the_uid_rule_admits_self_and_listed_only() {
        let p = PeerPolicy::new(1000, vec![2000]);
        assert!(p.admits(1000, Some(42)));
        assert!(p.admits(2000, Some(42)));
        assert!(p.admits(1000, None));
        assert!(!p.admits(3000, Some(42)));
        assert!(!p.admits(0, Some(42)));
    }

    #[test]
    fn resolve_refuses_ambiguous_and_relative_configs() {
        let v = VsockConfig { cid: 3, port: 5000 };
        let err = resolve_unix(Some(Path::new("/run/x.sock")), &[], Some(&v)).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
        let err = resolve_unix(Some(Path::new("rel.sock")), &[], None).unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
        let err = resolve_unix(None, &[7], None).unwrap_err();
        assert!(err.to_string().contains("requires --listen-unix"), "{err}");
        assert_eq!(resolve_unix(None, &[], None).unwrap(), None);
        let ok = resolve_unix(Some(Path::new("/run/x.sock")), &[7, 8], None)
            .unwrap()
            .unwrap();
        assert_eq!(ok.peer_uids, vec![7, 8]);
    }

    #[test]
    fn unix_url_names_the_path() {
        assert_eq!(
            unix_url(Path::new("/run/nucleus/proxy.sock")),
            "unix:///run/nucleus/proxy.sock"
        );
    }

    /// The admission is enforced at accept: a connection from an unadmitted
    /// peer is closed before any byte is answered, an admitted one is served.
    /// Both directions are exercised against a real bound socket, in-process
    /// (so the peer uid is our own and the pid is a real in-namespace pid).
    #[tokio::test]
    async fn accept_drops_unadmitted_peers_and_serves_admitted_ones() {
        async fn bind_with(policy: PeerPolicy) -> (PathBuf, tokio::task::JoinHandle<()>) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let app = Router::new().route("/ping", axum::routing::get(|| async { "pong" }));
            let l = PeerVerifiedUnixListener {
                inner: listener,
                policy,
            };
            let h = tokio::spawn(async move {
                let _keep = dir;
                let _ = axum::serve(l, app).await;
            });
            (path, h)
        }

        async fn get_ping(path: &Path) -> std::io::Result<String> {
            let mut s = UnixStream::connect(path).await?;
            s.write_all(b"GET /ping HTTP/1.0\r\nHost: x\r\n\r\n")
                .await?;
            let mut buf = String::new();
            s.read_to_string(&mut buf).await?;
            Ok(buf)
        }

        // Admitted: our own uid.
        let (path, h) = bind_with(PeerPolicy::new(current_uid(), vec![])).await;
        let reply = get_ping(&path).await.unwrap();
        assert!(reply.contains("200") && reply.ends_with("pong"), "{reply}");
        h.abort();

        // Unadmitted: a policy whose own uid is not ours and lists nobody.
        let foreign = current_uid().wrapping_add(1);
        let (path, h) = bind_with(PeerPolicy::new(foreign, vec![])).await;
        let reply = get_ping(&path).await.unwrap_or_default();
        assert!(
            !reply.contains("pong"),
            "an unadmitted peer must never be answered, got {reply:?}"
        );
        h.abort();
    }
}
