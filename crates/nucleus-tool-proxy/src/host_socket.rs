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
//!
//! # The pod-peer tier: the socket beside vsock (#2988)
//!
//! A Firecracker guest's proxy serves vsock, and the vsock listener admits ONLY
//! the host (`peer_is_host`), so an in-guest process — the workload, or a
//! sub-agent it spawned — cannot reach its own proxy over vsock at all. The
//! Unix socket is that path. It may now be bound BESIDE vsock, and the
//! ambiguity that used to forbid the pair is resolved per connection rather
//! than per proxy: every accepted Unix connection carries the peer's
//! kernel-reported credentials into the request as [`PodPeer`] (axum
//! connect-info), and `auth::select_auth_tier` names an in-namespace peer
//! `AuthTier::PodPeer`, distinct from `HostVsock`. The audit record still
//! names the transport that carried the request — more precisely than before.
//!
//! A pod peer is a BOUND identity for the authority exchange: `(uid, pid)`
//! from `SO_PEERCRED`, which no guest process can forge, is what makes two
//! sub-agents two bidders (`authority_round::Bidder::PodPeer`). It is still
//! NOT an identity a delegation certificate can act for — `delegation_authority`
//! keeps the tier `Unbound` and a certificate header on it is refused — because
//! a uid is not a SPIFFE leaf. The ceiling a peer bids under is the POD's own
//! certificate, which is exactly the authority it was already acting under.

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
/// May be combined with a vsock binding (#2988): the two carry different
/// peers — the host over vsock, in-guest processes over the socket — and each
/// request names its own transport, so nothing is ambiguous in the record.
pub(crate) fn resolve_unix(
    listen_unix: Option<&Path>,
    peer_uids: &[u32],
) -> Result<Option<UnixConfig>, ApiError> {
    let Some(path) = listen_unix else {
        if !peer_uids.is_empty() {
            return Err(ApiError::Spec(
                "--peer-uids requires --listen-unix".to_string(),
            ));
        }
        return Ok(None);
    };
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
    // Admission is decided by the kernel-reported peer credentials at accept,
    // not by the file mode — so when other uids are admitted by policy, the
    // socket must be connectable by them at all (connect needs write on the
    // socket file). Without listed peers the default mode stays: the only
    // admitted in-namespace peer is our own uid.
    if !cfg.peer_uids.is_empty() {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&cfg.path, std::fs::Permissions::from_mode(0o666)).await?;
        warn_if_unreachable(&cfg.path).await;
    }
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

/// Say so when a listed peer uid cannot possibly reach the socket.
///
/// `connect(2)` needs write on the socket AND execute on every directory above
/// it. The socket's own mode is set just above, but a parent directory the
/// operator chose can still exclude everyone — and then `--peer-uids` is an
/// allowlist that admits nobody: a gate that decides nothing, reported as
/// configuration rather than discovered as silence. Found live (#2988): a
/// socket under `/run/nucleus`, which the guest keeps at mode 700 because it
/// holds the pod's SVID, refused every workload connect with EACCES.
///
/// A warning, not a refusal: an operator may have chowned the directory to the
/// listed uid, which this cannot see from the mode alone.
async fn warn_if_unreachable(sock: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut dir = sock.parent();
    while let Some(d) = dir {
        let Ok(meta) = tokio::fs::metadata(d).await else {
            break;
        };
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o001 == 0 {
            warn!(
                dir = %d.display(),
                mode = format!("{mode:o}"),
                socket = %sock.display(),
                "--peer-uids lists peers that cannot reach the socket: this directory \
                 is not traversable by other uids, so every listed peer will be refused \
                 at connect with EACCES before admission is ever consulted"
            );
            return;
        }
        if d.parent() == Some(d) {
            break;
        }
        dir = d.parent();
    }
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

/// The kernel-reported identity of an admitted Unix-socket peer, carried into
/// every request on that connection as axum connect-info
/// (`ConnectInfo<PodPeer>`).
///
/// `pid == Some(0)` is a peer outside the proxy's pid namespace — the host,
/// through a socket mounted into a container — and [`PodPeer::is_in_pod`] is
/// false for it. Everything else is a process inside the pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PodPeer {
    pub(crate) uid: u32,
    pub(crate) pid: Option<i32>,
}

impl PodPeer {
    /// An in-namespace process: a bidder the exchange can tell from another.
    /// The host (pid 0) is not a pod peer; a platform that reports no pid at
    /// all yields no in-pod identity either, so it cannot bid.
    pub(crate) fn is_in_pod(&self) -> bool {
        matches!(self.pid, Some(p) if p != 0)
    }
}

/// What `ConnectInfo<PodPeer>` is filled from: the address the listener
/// returned at accept, which IS the peer's credentials.
impl
    axum::extract::connect_info::Connected<
        axum::serve::IncomingStream<'_, PeerVerifiedUnixListener>,
    > for PodPeer
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, PeerVerifiedUnixListener>) -> Self {
        *stream.remote_addr()
    }
}

/// The axum listener that enforces [`PeerPolicy`] at accept time.
struct PeerVerifiedUnixListener {
    inner: UnixListener,
    policy: PeerPolicy,
}

impl axum::serve::Listener for PeerVerifiedUnixListener {
    type Io = UnixStream;
    type Addr = PodPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, _addr)) => {
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
                    return (
                        stream,
                        PodPeer {
                            uid: cred.uid(),
                            pid: cred.pid(),
                        },
                    );
                }
                Err(err) => {
                    tracing::error!("unix-socket accept error: {err}");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        // The listener's own address is not a peer; the connect-info of a
        // request is what carries identity, and that is set per connection in
        // `accept`. Reported as "nobody, no pid" so it can never read as a pod
        // peer or as the host.
        Ok(PodPeer {
            uid: u32::MAX,
            pid: None,
        })
    }
}

/// Serve the router over the bound socket until the listener errors out. Every
/// request carries `ConnectInfo<PodPeer>` for the connection that brought it.
pub(crate) async fn serve_unix(app: Router, bound: BoundUnix) -> Result<(), ApiError> {
    info!(
        "nucleus-tool-proxy listening on unix socket {} (peer-credential admission)",
        bound.path.display()
    );
    let listener = PeerVerifiedUnixListener {
        inner: bound.listener,
        policy: bound.policy,
    };
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<PodPeer>(),
    )
    .await?;
    Ok(())
}

/// The host-verified transports a proxy serves on: vsock in a microVM (the
/// host's path), a peer-verified Unix socket (the host's path in a container,
/// and the in-pod processes' path everywhere). Either, or both (#2988). The
/// HMAC tier is unreachable on both (`auth::select_auth_tier`).
pub(crate) struct HostBound {
    vsock: Option<BoundVsock>,
    unix: Option<BoundUnix>,
}

impl HostBound {
    /// What the workload's `NUCLEUS_TOOL_PROXY_URL` should name.
    ///
    /// The Unix socket when there is one: it is the only transport an in-guest
    /// process can actually use, since the vsock listener admits the host and
    /// nobody else. A vsock-only proxy names vsock, as it always has.
    pub(crate) fn proxy(&self) -> BoundProxy {
        match (&self.unix, &self.vsock) {
            (Some(u), _) => BoundProxy::Unix(u.path.clone()),
            (None, Some(v)) => BoundProxy::Vsock {
                cid: v.cid(),
                port: v.port(),
            },
            (None, None) => unreachable!("HostBound is constructed with at least one transport"),
        }
    }

    /// Serve every bound transport; the first to fail ends the proxy.
    pub(crate) async fn serve(self, app: Router) -> Result<(), ApiError> {
        match (self.vsock, self.unix) {
            (Some(v), Some(u)) => {
                tokio::try_join!(pod_mgmt::serve_vsock(app.clone(), v), serve_unix(app, u))?;
                Ok(())
            }
            (Some(v), None) => pod_mgmt::serve_vsock(app, v).await,
            (None, Some(u)) => serve_unix(app, u).await,
            (None, None) => Ok(()),
        }
    }
}

/// Bind the configured host-verified transports, if any, recording each bind
/// in the startup trace under its own mark. The announce file names the
/// transport the WORKLOAD should use (see [`HostBound::proxy`]).
pub(crate) async fn bind_host_verified(
    vsock: Option<VsockConfig>,
    unix: Option<UnixConfig>,
    announce_path: Option<PathBuf>,
    st: &mut Startup,
) -> Result<Option<HostBound>, ApiError> {
    if vsock.is_none() && unix.is_none() {
        return Ok(None);
    }
    let vsock_announce = if unix.is_some() {
        None
    } else {
        announce_path.clone()
    };
    let vsock = match vsock {
        Some(v) => Some(
            st.timed("vsock_bind", pod_mgmt::bind_vsock(v, vsock_announce))
                .await?,
        ),
        None => None,
    };
    let unix = match unix {
        Some(u) => Some(st.timed("unix_bind", bind_unix(u, announce_path)).await?),
        None => None,
    };
    Ok(Some(HostBound { vsock, unix }))
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
    fn resolve_refuses_relative_and_orphaned_configs() {
        let err = resolve_unix(Some(Path::new("rel.sock")), &[]).unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
        let err = resolve_unix(None, &[7]).unwrap_err();
        assert!(err.to_string().contains("requires --listen-unix"), "{err}");
        assert_eq!(resolve_unix(None, &[]).unwrap(), None);
        let ok = resolve_unix(Some(Path::new("/run/x.sock")), &[7, 8])
            .unwrap()
            .unwrap();
        assert_eq!(ok.peer_uids, vec![7, 8]);
    }

    /// A directory the listed peers cannot traverse makes the allowlist inert,
    /// and the proxy must say so. Driven on the real shape that produced it: a
    /// mode-700 parent, which refused every workload connect in a live run.
    #[tokio::test]
    async fn an_unreachable_socket_directory_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{Arc, Mutex};

        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || CaptureWriter(sink.clone()))
            .finish();

        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private");
        std::fs::create_dir(&private).unwrap();
        let sock = private.join("p.sock");
        std::fs::write(&sock, b"").unwrap();

        // A thread-local guard rather than `with_default`, so the subscriber
        // survives the `.await`s below on this single-threaded test runtime.
        let guard = tracing::subscriber::set_default(subscriber);

        // The assertions name the DIRECTORY the warning blames, not merely
        // whether one was emitted: the enclosing temp root is itself mode 700
        // on macOS, so "no warning at all" is not a property this test can
        // hold anywhere — and a warning about the temp root is CORRECT, just
        // not the subject.
        let named = |what: &str| -> bool {
            logs.lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|l| l.contains("cannot reach the socket") && l.contains(what))
        };
        let private_dir = private.display().to_string();

        // Traversable: this directory is not what blocks anyone.
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        warn_if_unreachable(&sock).await;
        assert!(
            !named(&format!("dir={private_dir}")),
            "a traversable directory must not be blamed: {:?}",
            logs.lock().unwrap()
        );

        // Mode 700, the live shape: every listed peer is refused at connect.
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        warn_if_unreachable(&sock).await;
        drop(guard);
        assert!(
            named(&format!("dir={private_dir}")),
            "a mode-700 parent must be named, got {:?}",
            logs.lock().unwrap()
        );
    }

    /// Collects `tracing` output into a shared buffer so the test can assert on
    /// what an operator would actually be told.
    struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(String::from_utf8_lossy(buf).into_owned());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The host is not a pod peer, and neither is a peer with no pid; only an
    /// in-namespace process is a bidder.
    #[test]
    fn only_an_in_namespace_process_is_a_pod_peer() {
        assert!(
            PodPeer {
                uid: 1000,
                pid: Some(42)
            }
            .is_in_pod()
        );
        assert!(
            !PodPeer {
                uid: 1000,
                pid: Some(0)
            }
            .is_in_pod(),
            "the host"
        );
        assert!(
            !PodPeer {
                uid: 1000,
                pid: None
            }
            .is_in_pod(),
            "no pid reported"
        );
    }

    #[test]
    fn unix_url_names_the_path() {
        assert_eq!(
            unix_url(Path::new("/run/nucleus/proxy.sock")),
            "unix:///run/nucleus/proxy.sock"
        );
    }

    /// The admission is enforced at accept: a connection from an unadmitted
    /// peer is closed before any byte is answered, an admitted one is served —
    /// and the served request carries the peer's kernel-reported credentials
    /// as connect-info, which is what the exchange bids under. Both directions
    /// are exercised against a real bound socket, in-process (so the peer uid
    /// is our own and the pid is a real in-namespace pid).
    #[tokio::test]
    async fn accept_drops_unadmitted_peers_and_serves_admitted_ones() {
        use axum::extract::ConnectInfo;

        async fn bind_with(policy: PeerPolicy) -> (PathBuf, tokio::task::JoinHandle<()>) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.sock");
            let listener = UnixListener::bind(&path).unwrap();
            // The handler answers with the peer it saw: the assertion below is
            // that this equals the kernel's view of THIS process.
            let app = Router::new().route(
                "/ping",
                axum::routing::get(|ConnectInfo(peer): ConnectInfo<PodPeer>| async move {
                    format!("pong uid={} pid={:?}", peer.uid, peer.pid)
                }),
            );
            let l = PeerVerifiedUnixListener {
                inner: listener,
                policy,
            };
            let h = tokio::spawn(async move {
                let _keep = dir;
                let _ = axum::serve(l, app.into_make_service_with_connect_info::<PodPeer>()).await;
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

        // Admitted: our own uid — and the request saw OUR uid and a real pid,
        // which is the identity the exchange would bid under.
        let (path, h) = bind_with(PeerPolicy::new(current_uid(), vec![])).await;
        let reply = get_ping(&path).await.unwrap();
        assert!(reply.contains("200"), "{reply}");
        assert!(
            reply.contains(&format!("pong uid={}", current_uid())),
            "the peer's uid must reach the handler: {reply}"
        );
        assert!(
            reply.contains(&format!("pid=Some({})", std::process::id())),
            "the peer's pid must reach the handler: {reply}"
        );
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
