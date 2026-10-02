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
use axum::extract::connect_info::Connected;
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

/// The door's router: the door table, under the main listener's own auth
/// middleware and fail-closed panic layer, in the same order.
pub(crate) fn router(state: crate::AppState) -> Router {
    table(handler)
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::auth_middleware,
        ))
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            crate::fail_closed_panic_response,
        ))
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
/// # Errors
/// [`DoorRefusal`] naming why the peer is not the workload.
pub(crate) fn admit(
    peer: Result<PeerFacts, String>,
    workload: WorkloadUid,
) -> Result<DoorPeer, DoorRefusal> {
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

        let failed = |what: &str, e: std::io::Error| {
            ApiError::Spec(format!(
                "could not {what} the workload door at {}: {e}",
                path.display()
            ))
        };
        if !path.is_absolute() {
            return Err(ApiError::Spec(format!(
                "the workload door must be an absolute path, got {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            // Traversable by the workload's uid, writable only by the proxy.
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent)
                .map_err(|e| failed("create the directory of", e))?;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(failed("remove a stale socket at", e)),
        }
        let std_listener =
            std::os::unix::net::UnixListener::bind(path).map_err(|e| failed("bind", e))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| failed("set the mode of", e))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| failed("configure", e))?;
        let listener = UnixListener::from_std(std_listener).map_err(|e| failed("register", e))?;
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
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::routing::{any, get};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    const WORKLOAD: u32 = 65534;

    fn facts(uid: u32, pid: Option<i32>) -> Result<PeerFacts, String> {
        Ok(PeerFacts { uid, pid })
    }

    // ── the caller check ────────────────────────────────────────────────

    #[test]
    fn the_workload_uid_is_admitted() {
        let peer = admit(facts(WORKLOAD, Some(42)), WorkloadUid::for_test(WORKLOAD))
            .expect("the workload's own uid is the one admitted");
        assert_eq!(peer.uid(), WORKLOAD);
    }

    /// Root, the proxy's own uid in a guest, is not the workload. Nor is any
    /// other uid. The refusal names both uids.
    #[test]
    fn a_wrong_uid_is_refused_with_a_named_reason() {
        for other in [0, 1000, WORKLOAD - 1, WORKLOAD + 1] {
            let refusal = admit(facts(other, Some(42)), WorkloadUid::for_test(WORKLOAD))
                .expect_err("only the workload uid is admitted");
            assert_eq!(
                refusal,
                DoorRefusal::NotTheWorkload {
                    peer: other,
                    workload: WORKLOAD
                }
            );
            let msg = refusal.to_string();
            assert!(
                msg.contains(&other.to_string()) && msg.contains("65534"),
                "{msg}"
            );
        }
    }

    /// "Could not look" is not "looked and it was fine" (ADR 0007 A-2).
    #[test]
    fn missing_peer_credentials_are_refused() {
        let refusal = admit(Err("ENOTSUP".to_string()), WorkloadUid::for_test(WORKLOAD))
            .expect_err("an unidentified peer is not admitted");
        assert!(matches!(
            refusal,
            DoorRefusal::PeerCredentialsUnavailable(_)
        ));
        assert!(refusal.to_string().contains("ENOTSUP"), "{refusal}");
    }

    /// A peer outside the pid namespace is not this proxy's child, even with
    /// the workload's uid. (On the main Unix listener the same fact means "the
    /// host"; here it means "not the workload".)
    #[test]
    fn a_peer_outside_the_pid_namespace_is_refused() {
        assert_eq!(
            admit(facts(WORKLOAD, Some(0)), WorkloadUid::for_test(WORKLOAD)),
            Err(DoorRefusal::OutsideThisPidNamespace)
        );
        // A platform that reports no pid falls through to the uid rule.
        assert!(admit(facts(WORKLOAD, None), WorkloadUid::for_test(WORKLOAD)).is_ok());
    }

    // ── the route table ─────────────────────────────────────────────────

    /// The door's route set, written out. Adding a route to the door is a
    /// decision, so it has to change this list too.
    #[test]
    fn the_door_serves_exactly_these_routes() {
        let paths: Vec<&str> = DoorRoute::ALL.iter().map(|r| r.path()).collect();
        assert_eq!(
            paths,
            [
                "/v1/read",
                "/v1/write",
                "/v1/web_fetch",
                "/v1/glob",
                "/v1/grep",
                "/v1/web_search",
                "/v1/memory/write",
                "/v1/memory/recall",
                "/v1/egress/{name}/{*path}",
            ]
        );
    }

    /// Every `.route("<path>"` the main listener's router declares in
    /// `main.rs`, read from source so a control-plane route added there later
    /// is checked here without anyone remembering to.
    fn main_listener_paths() -> Vec<String> {
        let src: String = include_str!("main.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut out = Vec::new();
        let mut rest = src.as_str();
        while let Some(at) = rest.find(".route(\"") {
            let after = &rest[at + ".route(\"".len()..];
            let end = after.find('"').expect("a closed path literal");
            out.push(after[..end].to_string());
            rest = &after[end..];
        }
        out
    }

    /// A concrete request path for a route pattern.
    fn concrete(path: &str) -> String {
        path.replace("{name}", "model_api")
            .replace("{*path}", "v1/x")
    }

    /// The table, bound to a stub that echoes which route answered. This is the
    /// real [`table`]; only the handlers are stand-ins.
    fn echo_table() -> Router {
        table(|route| any(move || async move { route.path() }))
    }

    async fn status_and_body(app: Router, path: &str) -> (StatusCode, String) {
        let response = app
            .oneshot(Request::post(path).body(Body::empty()).expect("a request"))
            .await
            .expect("infallible");
        let status = response.status();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("a body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// **A control-plane route requested through the door is not found.** Every
    /// path the main listener serves that is not a door route answers 404 on
    /// the door, by the route table, with no secret involved. The list comes
    /// from `main.rs`, so it includes `/v1/approve`, `/v1/escalate`,
    /// `/v1/declassify`, `/v1/pod/*`, `/v1/workload/*`, `/v1/artifact`,
    /// `/v1/health` and (until #3119) `/v1/run`.
    ///
    /// Red if the door were the main router, or a filter over it that let a
    /// control route through.
    #[tokio::test]
    async fn control_plane_routes_are_not_found_on_the_door() {
        let main_paths = main_listener_paths();
        let door: Vec<&str> = DoorRoute::ALL.iter().map(|r| r.path()).collect();
        let control: Vec<&String> = main_paths
            .iter()
            .filter(|p| !door.contains(&p.as_str()))
            .collect();
        // Non-vacuity: the source scan found the control plane, including the
        // routes #3031 names.
        for must in [
            "/v1/approve",
            "/v1/escalate",
            "/v1/declassify",
            "/v1/pod/create",
            "/v1/workload/result",
            "/v1/health",
            "/v1/run",
        ] {
            assert!(
                control.iter().any(|p| p.as_str() == must),
                "the scan of main.rs lost {must}: {control:?}"
            );
        }
        for path in control {
            let (status, body) = status_and_body(echo_table(), &concrete(path)).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{path} is reachable through the workload door (answered by {body:?})"
            );
        }
    }

    /// The other half: every door route is served, by itself, and is one the
    /// main listener also serves, so the door adds no entry point of its own.
    #[tokio::test]
    async fn every_door_route_is_served_and_is_a_main_listener_route() {
        let main_paths = main_listener_paths();
        for route in DoorRoute::ALL {
            assert!(
                main_paths.iter().any(|p| p == route.path()),
                "{route:?} is not a main-listener route, so the door would be a new entry point"
            );
            let (status, body) = status_and_body(echo_table(), &concrete(route.path())).await;
            assert_eq!(status, StatusCode::OK, "{route:?}");
            assert_eq!(body, route.path(), "{route:?} answered by the wrong route");
        }
    }

    /// **The same decision.** Each door route is bound to the handler the main
    /// listener binds to the same path, and the door router carries the main
    /// listener's auth middleware and panic layer. The handlers are where the
    /// kernel decides, so a door call reaches the same `http_kernel_decide`, the
    /// same flow graph and the same effect gate.
    ///
    /// A source pin, because a behavioural test would need a full `AppState`
    /// (`tests/memory_ifc_e2e.rs` and `mcp.rs` record why that is avoided). It
    /// is a parity check across two declarations (ADR 0007 G-2): the main
    /// router's literal `.route(..)` lines are what `cargo xtask mediation`
    /// counts, so they stay where they are, and this check lives beside the
    /// door's copy.
    #[test]
    fn the_door_binds_the_main_listeners_handlers() {
        let squash = |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
        let main = squash(include_str!("main.rs"));
        let door_src = squash(include_str!("workload_door.rs"));
        let handler_body = {
            let start = door_src
                .find("fnhandler(route:DoorRoute)")
                .expect("the door's handler binding");
            let rest = &door_src[start..];
            // Whitespace is gone, so the match's and the fn's closing braces
            // are adjacent.
            &rest[..rest.find("}}").expect("the end of `handler`")]
        };
        for route in DoorRoute::ALL {
            let key = format!(".route(\"{}\",", route.path());
            let at = main
                .find(&key)
                .unwrap_or_else(|| panic!("{route:?} not in main.rs"));
            let binding = &main[at + key.len()..];
            let main_binding = &binding[..=binding.find(')').expect("a verb call")];

            let arm_key = format!("DoorRoute::{route:?}=>");
            let arm_at = handler_body
                .find(&arm_key)
                .unwrap_or_else(|| panic!("{route:?} has no arm in `handler`"));
            let arm = &handler_body[arm_at + arm_key.len()..];
            let door_binding = arm[..arm.find(',').expect("an arm")].replace("crate::", "");

            assert_eq!(
                door_binding, main_binding,
                "{route:?}: the door binds {door_binding} where the main listener binds \
                 {main_binding}; a door call would not reach the same decision"
            );
        }
        let router_body = &door_src[door_src.find("pubfnrouter(").expect("router")..];
        for layer in [
            "crate::auth_middleware",
            "crate::fail_closed_panic_response",
        ] {
            assert!(router_body.contains(layer), "the door router lacks {layer}");
            assert!(
                main.contains(layer.trim_start_matches("crate::")),
                "non-vacuity: main.rs no longer has {layer}"
            );
        }
    }

    // ── the listener, over a real socket ────────────────────────────────

    async fn get_who(path: &Path) -> std::io::Result<String> {
        let mut s = UnixStream::connect(path).await?;
        s.write_all(b"GET /who HTTP/1.0\r\nHost: x\r\n\r\n").await?;
        let mut buf = String::new();
        s.read_to_string(&mut buf).await?;
        Ok(buf)
    }

    fn who_app() -> Router {
        Router::new().route(
            "/who",
            get(|ConnectInfo(peer): ConnectInfo<DoorPeer>| async move {
                format!("uid={}", peer.uid())
            }),
        )
    }

    /// Served over a real bound socket: an admitted peer's requests carry its
    /// kernel-reported uid as `DoorPeer` (what the auth middleware reads), and
    /// an unadmitted peer is dropped before any byte is answered. In-process,
    /// so the peer uid is this test's own.
    #[tokio::test]
    async fn the_door_admits_by_peer_credentials_and_tells_the_router_who() {
        let me = crate::workload::nix_getuid();
        let dir = tempfile::tempdir().expect("tempdir");

        let path = dir.path().join("admitted").join("door.sock");
        let door = UnservedDoor::bind(&path).expect("bind");
        assert_eq!(door.url(), format!("unix://{}", path.display()));
        door.serve(who_app(), WorkloadUid::for_test(me));
        let reply = get_who(&path).await.expect("connect");
        assert!(
            reply.contains("200") && reply.ends_with(&format!("uid={me}")),
            "{reply}"
        );

        let path = dir.path().join("refused.sock");
        UnservedDoor::bind(&path)
            .expect("bind")
            .serve(who_app(), WorkloadUid::for_test(me.wrapping_add(1)));
        let reply = get_who(&path).await.unwrap_or_default();
        assert!(
            !reply.contains("uid="),
            "a peer that is not the workload must never be answered, got {reply:?}"
        );
    }

    /// The socket is connectable by other uids (the workload is not the
    /// proxy's), and a stale socket from a previous run is replaced.
    #[tokio::test]
    async fn bind_makes_the_socket_connectable_and_replaces_a_stale_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("door.sock");
        drop(UnservedDoor::bind(&path).expect("first bind"));
        assert!(path.exists(), "the stale socket file is left behind");
        let _door = UnservedDoor::bind(&path).expect("a stale socket is replaced");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o666);
        assert!(UnservedDoor::bind(Path::new("rel/door.sock")).is_err());
    }
}
