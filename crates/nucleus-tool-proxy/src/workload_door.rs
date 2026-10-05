//! The workload door: the proxy's second listener, for the workload alone
//! (#3031 option B, #2696 P1).
//!
//! # Why a second door
//!
//! The proxy's main listener belongs to the host. In a microVM it is vsock and
//! drops every peer that is not the host's CID (`pod_mgmt::peer_is_host`), and
//! a process inside the guest cannot vsock-connect to its own guest anyway. So a
//! workload had no way to reach the proxy that mediates it: the URL it was given
//! (`vsock://<cid>:<port>`) failed with `ENODEV`, and its egress URLs with it.
//! Loosening the main listener is not the fix. It serves the control plane
//! (approvals, sub-pods, the workload's own result), and the agent must never
//! reach that.
//!
//! # What this module guarantees, and how
//!
//! - **A separate route table, not a filter.** [`router`] is built from
//!   [`DoorRoute::ALL`] and nothing else. A control-plane route is not in that
//!   enum, so it is not on this router; there is no allowlist to get wrong
//!   (ADR 0007 D, E). The tests check every path the main listener serves and
//!   find each one that is not a door route answering 404 here.
//! - **The caller is the workload's uid, by the kernel's word.** Every accepted
//!   connection's `SO_PEERCRED` is checked by [`admit`] before the stream
//!   reaches the router. Only the uid the workload runs as is admitted, and that
//!   uid comes from the admitted launch plan ([`crate::workload::WorkloadUid`]),
//!   never from configuration. "Could not read the credentials" is a refusal
//!   (ADR 0007 A-2).
//! - **No secret.** The workload's environment carries no proxy credential; it
//!   authenticates by being that uid on this socket.
//! - **The same decision.** The door binds each route to the handler the main
//!   listener binds to the same path, under the same `auth_middleware` and the
//!   same fail-closed panic layer. The handlers are where `http_kernel_decide`,
//!   the flow graph and the effect gate run, so a door call is decided exactly
//!   as a host call is. The middleware selects
//!   [`crate::auth::AuthTier::WorkloadDoor`] from the connection's [`DoorPeer`],
//!   so the request is recorded as the workload's, never the host's.
//!
//! # What it does not do
//!
//! It does not stop the workload calling the network directly where the pod's
//! network policy lets it (that is the netns fence's job), and it does not
//! confine the workload's filesystem view (P3). It does not distinguish the
//! workload's processes from each other: every process running as the
//! workload's uid is the workload.

use std::path::{Path, PathBuf};

use axum::Router;
use axum::extract::{ConnectInfo, Request, connect_info::Connected};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, post};
use axum::serve::IncomingStream;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::ApiError;
use crate::workload::WorkloadUid;

/// A route the workload door serves. The door's whole route set.
///
/// Tool calls and the workload's own credentialed egress. Nothing the node
/// calls: no approval, escalation or declassification, no sub-pod management,
/// no workload result or logs, no artifact collection, no health.
///
/// **`/v1/run` is withheld for now.** Under `ContainmentMode::MicroVM` a
/// `/v1/run` child is not yet dropped from the proxy's uid (root), so serving
/// it here would hand the workload a root shell. #3119 (P0b) drops it to the
/// workload uid; `Run` joins this enum when that lands, with its test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DoorRoute {
    Read,
    Write,
    WebFetch,
    Glob,
    Grep,
    WebSearch,
    MemoryWrite,
    MemoryRecall,
    Egress,
}

impl DoorRoute {
    /// Every door route. [`table`] folds over this and nothing else.
    pub(crate) const ALL: [DoorRoute; 9] = [
        DoorRoute::Read,
        DoorRoute::Write,
        DoorRoute::WebFetch,
        DoorRoute::Glob,
        DoorRoute::Grep,
        DoorRoute::WebSearch,
        DoorRoute::MemoryWrite,
        DoorRoute::MemoryRecall,
        DoorRoute::Egress,
    ];

    /// The path, identical to the main listener's for the same tool.
    pub(crate) const fn path(self) -> &'static str {
        match self {
            DoorRoute::Read => "/v1/read",
            DoorRoute::Write => "/v1/write",
            DoorRoute::WebFetch => "/v1/web_fetch",
            DoorRoute::Glob => "/v1/glob",
            DoorRoute::Grep => "/v1/grep",
            DoorRoute::WebSearch => "/v1/web_search",
            DoorRoute::MemoryWrite => "/v1/memory/write",
            DoorRoute::MemoryRecall => "/v1/memory/recall",
            DoorRoute::Egress => "/v1/egress/{name}/{*path}",
        }
    }
}

/// The door's route table: each [`DoorRoute`], bound by `bind`, and nothing
/// else. Generic over the binding so the tests can drive the real table
/// without a full `AppState`.
fn table<S>(bind: impl Fn(DoorRoute) -> MethodRouter<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    DoorRoute::ALL
        .into_iter()
        .fold(Router::new(), |router, route| {
            router.route(route.path(), bind(route))
        })
}

/// The production binding: each route to the handler the main listener binds
/// to the same path. `the_door_binds_the_main_listeners_handlers` pins that.
fn handler(route: DoorRoute) -> MethodRouter<crate::AppState> {
    match route {
        DoorRoute::Read => post(crate::read_file),
        DoorRoute::Write => post(crate::write_file),
        DoorRoute::WebFetch => post(crate::web_fetch),
        DoorRoute::Glob => post(crate::glob_search),
        DoorRoute::Grep => post(crate::grep_search),
        DoorRoute::WebSearch => post(crate::web_search),
        DoorRoute::MemoryWrite => post(crate::memory::memory_write),
        DoorRoute::MemoryRecall => post(crate::memory::memory_recall),
        DoorRoute::Egress => post(crate::egress::credentialed_egress),
    }
}

/// The door's router: the door table, each route under the main listener's
/// own auth middleware and the door's route admission ([`entered`]), all under
/// the main listener's fail-closed panic layer.
///
/// The auth middleware is layered per route rather than over the router, so it
/// runs only on a matched door route and always after [`entered`] has bound the
/// request to that route. That binding is what lets the attestation
/// requirement accept the door's peer credentials on the door's routes and
/// nowhere else.
pub(crate) fn router(state: crate::AppState) -> Router {
    let auth = state.clone();
    table(move |route| {
        entered(
            route,
            handler(route).layer(axum::middleware::from_fn_with_state(
                auth.clone(),
                crate::auth_middleware,
            )),
        )
    })
    .with_state(state)
    .layer(tower_http::catch_panic::CatchPanicLayer::custom(
        crate::fail_closed_panic_response,
    ))
}

/// A request that reached one of the door's own routes through a peer the
/// door admitted: the evidence the attestation requirement accepts in place of
/// a client certificate ([`crate::attestation::TransportEvidence::DoorPeer`]).
///
/// Its fields are private and it is built in one place, [`enter`], which needs
/// a [`DoorPeer`] (built only by the door's accept path) and a [`DoorRoute`]
/// (supplied only by the door's route table). So a request on the main
/// listener cannot carry one, and nor can a door request off the door's table
/// (ADR 0007 C-1, C-2, C-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoorAdmission {
    peer: DoorPeer,
    route: DoorRoute,
}

impl DoorAdmission {
    pub(crate) fn uid(&self) -> u32 {
        self.peer.uid()
    }

    pub(crate) fn route(&self) -> DoorRoute {
        self.route
    }
}

/// Wrap a door route's handler so every request it serves carries its
/// [`DoorAdmission`].
fn entered<S>(route: DoorRoute, inner: MethodRouter<S>) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    inner.layer(axum::middleware::from_fn(
        move |request: Request, next: Next| enter(route, request, next),
    ))
}

/// Bind a request to the door route it matched, from the peer the door's
/// listener admitted. A request with no door peer is refused: a door route is
/// only reachable through the door's listener, so that is not a door caller.
async fn enter(route: DoorRoute, mut request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<DoorPeer>>()
        .map(|ConnectInfo(peer)| peer.clone());
    match peer {
        Some(peer) => {
            request
                .extensions_mut()
                .insert(DoorAdmission { peer, route });
            next.run(request).await
        }
        None => (
            StatusCode::FORBIDDEN,
            "a workload door route was reached without the door's peer admission",
        )
            .into_response(),
    }
}

/// What the kernel reported about a connected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerFacts {
    pub(crate) uid: u32,
    /// `Some(0)` on Linux when the peer is outside this pid namespace.
    pub(crate) pid: Option<i32>,
}

/// Why the door turned a connection away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DoorRefusal {
    /// The kernel could not say who the peer is.
    #[error(
        "the kernel could not report the peer's credentials ({0}); an unidentified peer is \
         not the workload"
    )]
    PeerCredentialsUnavailable(String),
    /// The peer is outside this pid namespace. The workload is this proxy's
    /// child and runs inside it, so such a peer is someone else, whatever its uid.
    #[error("the peer is outside this pid namespace, so it is not this proxy's workload")]
    OutsideThisPidNamespace,
    /// The peer runs as some uid other than the workload's.
    #[error(
        "peer uid {peer} is not the workload's uid {workload}; the door serves the workload alone"
    )]
    NotTheWorkload { peer: u32, workload: u32 },
}

/// A peer the door admitted: the connect-info every door request carries.
///
/// Constructed only by [`admit`] (ADR 0007 C-1), and the auth middleware reads
/// its presence as "this request came through the door". The main listener
/// never produces one, so a host request cannot be read as the workload's, nor
/// the reverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoorPeer {
    uid: u32,
}

impl DoorPeer {
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
}

/// The door's admission decision, over what the kernel reported.
///
/// Private: it mints the [`DoorPeer`] the attestation requirement trusts, so
/// only the door's own listener may call it (ADR 0007 C-2).
///
/// # Errors
/// [`DoorRefusal`] naming why the peer is not the workload.
fn admit(peer: Result<PeerFacts, String>, workload: WorkloadUid) -> Result<DoorPeer, DoorRefusal> {
    let facts = peer.map_err(DoorRefusal::PeerCredentialsUnavailable)?;
    if facts.pid == Some(0) {
        return Err(DoorRefusal::OutsideThisPidNamespace);
    }
    if facts.uid != workload.get() {
        return Err(DoorRefusal::NotTheWorkload {
            peer: facts.uid,
            workload: workload.get(),
        });
    }
    Ok(DoorPeer { uid: facts.uid })
}

/// The door's listener: runs [`admit`] on every accepted connection before the
/// router sees it. A refused peer is dropped without a byte of reply.
struct DoorListener {
    inner: UnixListener,
    admits: WorkloadUid,
}

impl axum::serve::Listener for DoorListener {
    type Io = UnixStream;
    type Addr = DoorPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, _)) => {
                    let facts = stream
                        .peer_cred()
                        .map(|c| PeerFacts {
                            uid: c.uid(),
                            pid: c.pid(),
                        })
                        .map_err(|e| e.to_string());
                    match admit(facts, self.admits) {
                        Ok(peer) => return (stream, peer),
                        Err(refusal) => {
                            warn!(%refusal, "workload door: refusing a connection");
                            drop(stream);
                        }
                    }
                }
                Err(err) => {
                    // Back off rather than spin on a persistent error (EMFILE).
                    error!("workload door: accept error: {err}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the workload door identifies peers, not addresses",
        ))
    }
}

impl Connected<IncomingStream<'_, DoorListener>> for DoorPeer {
    fn connect_info(stream: IncomingStream<'_, DoorListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// A bound door, not yet serving. Typestate: [`UnservedDoor::serve`] consumes
/// it and needs the [`WorkloadUid`] only an admitted launch can mint, so a door
/// cannot serve before the workload's uid is decided (ADR 0007 D-1).
#[must_use = "a bound door that is never served leaves the workload pointed at a socket nobody answers"]
pub(crate) struct UnservedDoor {
    listener: UnixListener,
    path: PathBuf,
}

impl UnservedDoor {
    /// Bind the door at `path`, replacing a stale socket from a previous run.
    ///
    /// The socket file is made connectable by every uid (0666) because
    /// connecting to a Unix socket needs write permission on it, and the
    /// workload is not the proxy's uid. That is not the admission:
    /// [`admit`] is, at accept, by the kernel's report of the peer.
    ///
    /// # Errors
    /// A relative path, or a socket that cannot be created.
    pub(crate) fn bind(path: &Path) -> Result<Self, ApiError> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        // A named function, not a closure bound to a local: a call through a
        // local binding is an unresolved path to the call-graph lints, and
        // `bind` is reachable from the workload-spawn root
        // (workload_identity_isolation, FM-5).
        fn failed_at(path: &Path, what: &str, e: std::io::Error) -> ApiError {
            ApiError::Spec(format!(
                "could not {what} the workload door at {}: {e}",
                path.display()
            ))
        }
        if !path.is_absolute() {
            return Err(ApiError::Spec(format!(
                "the workload door must be an absolute path, got {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            // guest-init's umask is 077, so DirBuilder::mode(0755) alone
            // creates 0700 directories. Set each directory we create explicitly;
            // never widen an existing private ancestor. A racing creator makes
            // create() fail rather than handing us somebody else's directory.
            let missing: Vec<_> = parent.ancestors().take_while(|p| !p.exists()).collect();
            for dir in missing.into_iter().rev() {
                std::fs::DirBuilder::new()
                    .mode(0o755)
                    .create(dir)
                    .map_err(|e| failed_at(dir, "create parent directory for", e))?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| failed_at(dir, "set parent directory mode for", e))?;
            }
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(failed_at(path, "remove a stale socket at", e)),
        }
        let std_listener =
            std::os::unix::net::UnixListener::bind(path).map_err(|e| failed_at(path, "bind", e))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| failed_at(path, "set the mode of", e))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| failed_at(path, "configure", e))?;
        let listener =
            UnixListener::from_std(std_listener).map_err(|e| failed_at(path, "register", e))?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// The URL the workload is given: `unix://<path>`, the same form every
    /// Unix-socket URL in this crate takes (`host_socket::unix_url`).
    pub(crate) fn url(&self) -> String {
        crate::host_socket::unix_url(&self.path)
    }

    /// Serve `app` on the door, admitting only `admits`, for the life of the
    /// process.
    pub(crate) fn serve(self, app: Router, admits: WorkloadUid) {
        info!(
            path = %self.path.display(),
            workload_uid = admits.get(),
            "nucleus-tool-proxy serving the workload door (peer-credential admission)"
        );
        let listener = DoorListener {
            inner: self.listener,
            admits,
        };
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<DoorPeer>(),
            )
            .await
            {
                error!("workload door stopped serving: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests;
