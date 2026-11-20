//! The node's half of the host link relay (ADR 0017 L4b).
//!
//! Every Firecracker pod on a node with `--egress-proxy-bin` gets one more
//! confined child of the same binary, in `--mode link`
//! (`nucleus_egress_proxy::link`): stdin is the pod's `PodLink` listener
//! (vsock 1030), stdout its decision channel, and `--link-control-socket`
//! names a Unix socket this module binds in the pod directory, owns, and
//! writes `LINK`/`SEVER` lines to (`pod_links`). It is spawned and verified by
//! the same [`egress_proxy::spawn_confined`] as the egress proxy, so the two
//! cannot be confined differently.
//!
//! # The decision
//!
//! [`LinkDecider`] answers the link proxy's `Decide` frames with the egress
//! decider's two halves around one different middle. `begin` checks the frame,
//! its number and the node's own digest over the canonical summary (C-2); the
//! route is the node's link table — the summary's origin must be the link name
//! of a destination this pod has a row to, on that port, or the answer is
//! `RouteRefused` and the proxy connects nothing; `finish` asks the pod's
//! `PodPolicy` through `authorize_effect`, journals, and redeems the decision
//! id (C-4). Every request asked about is recorded in the table as
//! `LinkTable::connect` then `LinkTable::request` with the host's answer.
//!
//! The source pod is the one whose `{uds}_1030` socket the connection arrived
//! on (this proxy is that pod's), never anything the guest sends.
//!
//! # The CA
//!
//! When the pod has a CA (an eval cell, E3), the link proxy gets its own half
//! (`MintedCa::split`), as the first bytes on its decision channel
//! (`--tls-ca-channel`). The proxy terminates TLS only for announced link names
//! (`nucleus_egress_proxy::link::Links::permits`).
//!
//! # What only Linux shows
//!
//! That the confined proxy, as its unprivileged uid and after Landlock, can
//! `connect(2)` the control socket (it connects before Landlock; the socket is
//! chowned to it) and each destination's `vsock.sock` (connected per request,
//! after Landlock; that socket is the jail's). Recorded in ADR 0017 §10.

// The spawn is reached from `spawn_firecracker_pod`, which is linux-only.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nucleus_decision_protocol::{DenyReason, GuestFrame};
use nucleus_egress_proxy::link::link_dst;
use nucleus_ifc_kernel::extracted::link::Link;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::egress_proxy::{
    Close, Decided, EgressDecider, EgressRoutes, Spawn, Spawned, spawn_confined,
};
use crate::host_decide::{ChannelError, SharedPodPolicy};
use crate::pod_links::SharedLinks;
use crate::upstreams::CallCharge;

/// Where the link proxy writes its log, in the pod directory.
pub(crate) const LINK_PROXY_LOG: &str = "link-proxy.log";

/// The control socket's name, in the pod directory. The node binds and owns
/// it; only the link proxy's uid may connect.
pub(crate) const CONTROL_SOCKET: &str = "link-control.sock";

/// How long the proxy has to connect the control socket after its start.
const CONTROL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The node's end of one link proxy's control socket.
#[derive(Debug)]
pub(crate) struct Control {
    stream: tokio::sync::Mutex<tokio::net::UnixStream>,
}

impl Control {
    pub(crate) fn new(stream: tokio::net::UnixStream) -> Self {
        Self {
            stream: tokio::sync::Mutex::new(stream),
        }
    }

    /// Write one control line (`LINK …` or `SEVER …`), newline added.
    ///
    /// # Errors
    /// The write's I/O error: the proxy is gone, and with it every connection
    /// it carried.
    pub(crate) async fn send(&self, line: &str) -> std::io::Result<()> {
        let mut s = self.stream.lock().await;
        s.write_all(line.as_bytes()).await?;
        s.write_all(b"\n").await?;
        s.flush().await
    }
}

/// What `pod_links` needs of a pod's link proxy: its control socket, the pod's
/// Firecracker vsock socket (where a link TO this pod is dialled), and where and
/// as whom the node lays this proxy's per-link forwarder sockets.
#[derive(Debug)]
pub(crate) struct Relay {
    pub control: Arc<Control>,
    pub vsock: PathBuf,
    /// The pod directory: the proxy can reach it (its control socket is here).
    pub pod_dir: PathBuf,
    /// The proxy's uid and gid, which own its forwarder sockets.
    pub run_as: (u32, u32),
}

/// The node's byte pipe for one link, from the SOURCE pod's link proxy to the
/// DESTINATION pod's Firecracker vsock socket.
///
/// Found on the first Linux run (2026-11-19, local rehearsal): the destination's
/// vsock socket sits in its jail root, mode 0700 and owned by the jail user, which
/// the unprivileged link proxy cannot traverse, so every admitted request ended
/// `LinkUnreachable`. Loosening the jail would widen every pod's; instead the
/// node, which can reach every jail, listens on a socket in the source pod's
/// directory, owned by the proxy's uid alone (0600), and pipes each connection
/// to the destination. Bytes only: the proxy still performs the vsock
/// handshake and preamble, and decides every request before it writes one.
/// Dropping it closes the listener and every connection it carries, so a
/// `SEVER` is enforced on the node's side as well as the proxy's.
#[derive(Debug)]
pub(crate) struct Forwarder {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Forwarder {
    /// Listen on `path` (owned by `run_as`, 0600) and pipe each connection to
    /// `dst_vsock`.
    ///
    /// # Errors
    /// The bind, chown or chmod failed.
    pub(crate) fn start(
        path: PathBuf,
        dst_vsock: PathBuf,
        run_as: (u32, u32),
    ) -> Result<Self, String> {
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|e| format!("link forwarder socket: {e}"))?;
        give_to(&path, run_as)?;
        let task = tokio::spawn(async move {
            let mut pipes = tokio::task::JoinSet::new();
            while let Ok((mut inbound, _)) = listener.accept().await {
                let dst = dst_vsock.clone();
                pipes.spawn(async move {
                    if let Ok(mut out) = tokio::net::UnixStream::connect(&dst).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
                    }
                });
                while pipes.try_join_next().is_some() {}
            }
        });
        Ok(Self { path, task })
    }

    /// The socket the proxy dials for this link.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        // Aborting the accept loop drops its JoinSet, which aborts every pipe.
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The node's decision service for one pod's link proxy.
pub(crate) struct LinkDecider {
    inner: EgressDecider,
    src: Uuid,
    links: SharedLinks,
    next_conn: u64,
}

impl std::fmt::Debug for LinkDecider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkDecider")
            .field("src", &self.src)
            .finish_non_exhaustive()
    }
}

impl LinkDecider {
    pub(crate) fn new(src: Uuid, links: SharedLinks, policy: SharedPodPolicy, epoch: u64) -> Self {
        Self {
            // No operator routes: a link proxy's only route is the link table.
            inner: EgressDecider::new(src, Arc::new(EgressRoutes::none()), policy, epoch),
            src,
            links,
            next_conn: 0,
        }
    }

    /// Answer one frame from the link proxy.
    ///
    /// # Errors
    /// A [`Close`]: the channel ends and the proxy refuses what it asked.
    pub(crate) async fn step(
        &mut self,
        frame: GuestFrame,
        now: u64,
    ) -> Result<(Vec<u8>, Decided), Close> {
        let (seq, digest, summary) = self.inner.begin(frame)?;
        let row = link_dst(&summary.origin.host).map(|dst| Link {
            src: self.src.as_u128(),
            dst,
            port: u32::from(summary.origin.port),
        });
        // Held across the decision, so the row cannot be unmade between the
        // route check and the record (an unlink waits, then severs).
        let mut links = self.links.lock().await;
        let routed = match row {
            None => Err((
                DenyReason::NotRegistered,
                format!("{} is not a link name", summary.origin),
            )),
            Some(row) if links.has_row(row) => Ok((
                format!("link {} {}", Uuid::from_u128(row.dst), row.port),
                // The node dispatches nothing upstream for a link: the relay
                // carries the bytes. Stated, never defaulted.
                CallCharge::operator(0),
            )),
            Some(_) => Err((
                DenyReason::RouteRefused,
                format!("no link from {} to {}", self.src, summary.origin),
            )),
        };
        let was_routed = routed.is_ok();
        let out = self.inner.finish(seq, digest, &summary, routed, now)?;
        if let (Some(row), true) = (row, was_routed) {
            let id = self.next_conn;
            self.next_conn = self.next_conn.wrapping_add(1);
            links.record_request(id, row, matches!(out.1, Decided::Allowed { .. }));
        }
        Ok(out)
    }
}

/// Serve one link proxy's channel until it closes or a frame closes it.
pub(crate) async fn serve_link_decisions<S>(
    stream: S,
    mut decider: LinkDecider,
) -> Result<(), Close>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(stream);
    loop {
        let Some(frame) = crate::host_decide::read_frame(&mut r).await? else {
            return Ok(());
        };
        let (reply, decided) = decider.step(frame, now_unix()).await?;
        match &decided {
            Decided::Allowed { route, decision } => {
                tracing::info!(pod = %decider.src, route, decision, "link request allowed");
            }
            Decided::Refused { reason, detail } => {
                tracing::info!(pod = %decider.src, ?reason, detail, "link request refused");
            }
        }
        w.write_all(&reply)
            .await
            .map_err(|e| Close::Channel(ChannelError::Io(e.kind())))?;
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What the node needs to start one pod's link proxy.
pub(crate) struct LinkLaunch<'a> {
    pub binary: &'a Path,
    pub vsock_path: &'a Path,
    pub pod_dir: &'a Path,
    pub jail_owner: Option<(u32, u32)>,
    /// Who the proxy runs as. Never 0.
    pub run_as: (u32, u32),
    pub decider: LinkDecider,
    /// The pod's CA half for links (`MintedCa::split`); `None`: no TLS on links.
    pub ca: Option<crate::pod_ca::MintedCa>,
}

/// A running link proxy, owned by its pod.
#[derive(Debug)]
pub(crate) struct LinkProxy {
    child: tokio::process::Child,
    decisions: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
    control_path: PathBuf,
}

impl LinkProxy {
    /// Bind the control socket, spawn the proxy confined, hand it the CA, take
    /// its control connection, and serve its decisions.
    ///
    /// # Errors
    /// Any step, named. A proxy that started is killed before this returns an
    /// error.
    pub(crate) async fn start(launch: LinkLaunch<'_>) -> Result<(Self, Arc<Control>), String> {
        let LinkLaunch {
            binary,
            vsock_path,
            pod_dir,
            jail_owner,
            run_as,
            decider,
            ca,
        } = launch;
        let control_path = pod_dir.join(CONTROL_SOCKET);
        // Never a path a guest can reach: Firecracker routes a guest's connect to
        // `{vsock}_{port}`, and this socket is the node's alone.
        if control_path
            .to_string_lossy()
            .starts_with(vsock_path.to_string_lossy().as_ref())
        {
            return Err("link proxy control socket would share the vsock path's prefix".into());
        }
        let _ = std::fs::remove_file(&control_path);
        let control = tokio::net::UnixListener::bind(&control_path)
            .map_err(|e| format!("link proxy control socket: {e}"))?;
        give_to(&control_path, run_as)?;

        let mut args: Vec<std::ffi::OsString> = vec![
            "--mode".into(),
            "link".into(),
            "--link-control-socket".into(),
            control_path.clone().into_os_string(),
        ];
        if ca.is_some() {
            args.push("--tls-ca-channel".into());
        }
        let Spawned {
            mut child,
            mut node_end,
            socket_path,
        } = spawn_confined(Spawn {
            what: "link proxy",
            binary,
            vsock_path,
            listener: nucleus_ifc_kernel::VsockListener::PodLink,
            log: &pod_dir.join(LINK_PROXY_LOG),
            jail_owner,
            run_as,
            args,
        })
        .await?;
        let fail = async |child: &mut tokio::process::Child, why: String| {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err::<(Self, Arc<Control>), String>(why)
        };
        // The proxy reads the CA first, then connects the control socket.
        if let Some(ca) = ca {
            if let Err(e) = ca.hand_over(&mut node_end).await {
                return fail(&mut child, format!("link proxy CA handover: {e}")).await;
            }
        }
        let stream = match tokio::time::timeout(CONTROL_DEADLINE, control.accept()).await {
            Ok(Ok((stream, _))) => stream,
            Ok(Err(e)) => return fail(&mut child, format!("link proxy control: {e}")).await,
            Err(_) => {
                return fail(
                    &mut child,
                    "link proxy did not connect its control socket".into(),
                )
                .await;
            }
        };
        // One connection only: nothing else may speak for the node.
        drop(control);
        let decisions = tokio::spawn(async move {
            if let Err(e) = serve_link_decisions(node_end, decider).await {
                tracing::warn!(error = %e, "link proxy decision channel closed by the node");
            }
        });
        Ok((
            Self {
                child,
                decisions,
                socket_path,
                control_path,
            },
            Arc::new(Control::new(stream)),
        ))
    }

    /// Kill the proxy, stop its decisions, unlink its sockets.
    pub(crate) async fn shutdown(mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), self.child.wait()).await;
        self.decisions.abort();
        let _ = tokio::fs::remove_file(&self.socket_path).await;
        let _ = tokio::fs::remove_file(&self.control_path).await;
    }
}

/// The control socket belongs to the proxy's uid alone: owner `run_as`, mode
/// 0600, so only that uid (and root) may connect.
fn give_to(path: &Path, (uid, gid): (u32, u32)) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
        .map_err(|e| format!("link proxy control socket owner: {e}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("link proxy control socket mode: {e}"))
}

/// Start the pod's link proxy if the node has the proxy binary, and record its
/// relay so `pod_links` reaches it.
///
/// # Errors
/// Anything that stops it starting confined: the pod is refused rather than
/// run with links that a weaker relay would carry.
#[cfg(target_os = "linux")]
pub(crate) async fn start_for_pod(
    state: &crate::NodeState,
    pod: Uuid,
    vsock_path: &Path,
    pod_dir: &Path,
    jail_owner: Option<(u32, u32)>,
    ca: Option<crate::pod_ca::MintedCa>,
) -> Result<Option<LinkProxy>, crate::ApiError> {
    use crate::egress_proxy::ProxyConfig;
    let (binary, uid, gid) = match &state.egress_proxy {
        ProxyConfig::NotConfigured => return Ok(None),
        ProxyConfig::Binary { path, uid, gid } => (path, *uid, *gid),
    };
    let refuse = |why: String| crate::ApiError::Driver(format!("pod refused: {why}"));
    let policy = state
        .authority
        .host_policy(pod)
        .await
        .map_err(|e| refuse(format!("link proxy has no pod policy: {e}")))?;
    let epoch = state
        .decision_epochs
        .next()
        .map_err(|_| refuse("the node has no decision epochs left".into()))?;
    let decider = LinkDecider::new(pod, Arc::clone(&state.links), policy, epoch);
    let (proxy, control) = LinkProxy::start(LinkLaunch {
        binary,
        vsock_path,
        pod_dir,
        jail_owner,
        run_as: (uid, gid),
        decider,
        ca,
    })
    .await
    .map_err(refuse)?;
    crate::pod_links::relay_started(
        state,
        pod,
        Relay {
            control,
            vsock: vsock_path.to_path_buf(),
            pod_dir: pod_dir.to_path_buf(),
            run_as: (uid, gid),
        },
    )
    .await;
    tracing::info!(pod = %pod, "link proxy confined and listening");
    Ok(Some(proxy))
}

#[cfg(all(test, feature = "local-driver"))]
#[path = "link_proxy_tests.rs"]
mod tests;
