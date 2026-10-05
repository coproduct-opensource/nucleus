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
    let src: String = include_str!("../main.rs")
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
    let main = squash(include_str!("../main.rs"));
    let door_src = squash(include_str!("../workload_door.rs"));
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
    let router_body = &door_src[door_src.find("pub(crate)fnrouter(").expect("router")..];
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
        get(
            |ConnectInfo(peer): ConnectInfo<DoorPeer>| async move { format!("uid={}", peer.uid()) },
        ),
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

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test-only self-execution isolates the process-global umask from other tests"
)]
fn restrictive_umask_keeps_new_door_parents_traversable() {
    const CHILD: &str = "NUCLEUS_TEST_DOOR_UMASK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "workload_door::tests::restrictive_umask_keeps_new_door_parents_traversable",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "isolated umask regression failed");
        return;
    }
    // This is a separate test process running only this test. The
    // process-global mask cannot affect other tests or a production process.
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("door/nested");
        let _door = UnservedDoor::bind(&parent.join("workload.sock")).unwrap();
        for dir in [root.path().join("door"), parent] {
            assert_eq!(
                std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(
            std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o700,
            "an existing private ancestor must not be made public"
        );
    });
}

// ── the attestation requirement, by transport ──────────────────────

use crate::attestation::{AttestationConfig, AttestationVerifier, TransportEvidence};

fn attestation_required() -> AttestationVerifier {
    AttestationVerifier::new(AttestationConfig::required())
}

/// The attestation step of `crate::auth_middleware`, verbatim: read the
/// transport evidence, decide the requirement over it. Only the rest of
/// the middleware (tiers, HMAC, lockdown) is left out, because it needs a
/// full `AppState`.
async fn attestation_step(
    axum::extract::State(verifier): axum::extract::State<AttestationVerifier>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let decided = TransportEvidence::of(request.extensions())
        .and_then(|evidence| verifier.admit(&evidence, request.headers()));
    match decided {
        Ok(()) => next.run(request).await,
        Err(reason) => (StatusCode::FORBIDDEN, reason).into_response(),
    }
}

/// The handler reports the evidence it was reached with.
async fn evidence_kind(request: axum::extract::Request) -> String {
    match TransportEvidence::of(request.extensions()) {
        Ok(TransportEvidence::DoorPeer(admission)) => {
            format!("door uid={} route={:?}", admission.uid(), admission.route())
        }
        Ok(TransportEvidence::ClientCert(_)) => "client-cert".to_string(),
        Ok(TransportEvidence::None) => "none".to_string(),
        Err(e) => format!("refused: {e}"),
    }
}

/// The real door table and the real per-route admission ([`entered`]),
/// each route under the attestation step, as [`router`] builds it.
fn door_app(verifier: AttestationVerifier) -> Router {
    table(move |route| {
        entered(
            route,
            axum::routing::post(evidence_kind).layer(axum::middleware::from_fn_with_state(
                verifier.clone(),
                attestation_step,
            )),
        )
    })
}

/// The main listener's shape: routes under a router-level attestation
/// step, on the same path a door route uses.
fn tcp_app(verifier: AttestationVerifier) -> Router {
    Router::new()
        .route("/v1/read", axum::routing::post(evidence_kind))
        .layer(axum::middleware::from_fn_with_state(
            verifier,
            attestation_step,
        ))
}

async fn serve_tcp(app: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    addr
}

async fn post_raw<S>(mut stream: S, path: &str, extra_headers: &str) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request =
        format!("POST {path} HTTP/1.0\r\nHost: x\r\nContent-Length: 0\r\n{extra_headers}\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.expect("read");
    reply
}

async fn post_tcp(addr: std::net::SocketAddr, path: &str, extra_headers: &str) -> String {
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    post_raw(stream, path, extra_headers).await
}

/// **A door request to an attestation-required proxy is served.** The
/// workload holds no certificate; the door's peer-credential admission is
/// its authentication, and on a door route it meets the requirement.
///
/// Red on 4ea594278: the attestation check read only a client certificate
/// or the header, so every door call was refused "attestation required but
/// not provided" on exactly the pods that need the door.
#[tokio::test]
async fn a_door_request_to_an_attestation_required_proxy_is_served() {
    let me = crate::workload::nix_getuid();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("door.sock");
    UnservedDoor::bind(&path)
        .expect("bind")
        .serve(door_app(attestation_required()), WorkloadUid::for_test(me));

    let stream = UnixStream::connect(&path).await.expect("connect");
    let reply = post_raw(stream, "/v1/read", "").await;
    assert!(
        reply.starts_with("HTTP/1.0 200") && reply.ends_with(&format!("door uid={me} route=Read")),
        "{reply}"
    );
}

/// **A TCP request without a certificate is still refused** by the same
/// requirement, on the same route path. Non-vacuity: the same app with the
/// requirement off serves it, so the refusal is the requirement's.
#[tokio::test]
async fn a_tcp_request_without_a_cert_is_refused() {
    let required = serve_tcp(tcp_app(attestation_required())).await;
    let reply = post_tcp(required, "/v1/read", "").await;
    assert!(
        reply.starts_with("HTTP/1.0 403")
            && reply.contains("attestation required but not provided"),
        "{reply}"
    );

    let open = serve_tcp(tcp_app(AttestationVerifier::new(
        AttestationConfig::default(),
    )))
    .await;
    let reply = post_tcp(open, "/v1/read", "").await;
    assert!(
        reply.starts_with("HTTP/1.0 200") && reply.ends_with("none"),
        "{reply}"
    );
}

/// **A `DoorPeer` cannot arise on the TCP listener.** Over a real TCP
/// connection the evidence is `None` whatever the request says about
/// itself, and a door route's admission layer mounted on TCP refuses
/// rather than mint an admission, because only the door's accept path
/// produces the `DoorPeer` it needs. (`DoorAdmission`'s and `DoorPeer`'s
/// fields and [`admit`] are private to this module, so nothing else in the
/// crate can build either.)
#[tokio::test]
async fn the_tcp_listener_never_carries_door_evidence() {
    let app = Router::new()
        .route("/v1/read", axum::routing::post(evidence_kind))
        .route(
            "/v1/write",
            entered(DoorRoute::Write, axum::routing::post(evidence_kind)),
        );
    let addr = serve_tcp(app).await;
    let forged = "x-nucleus-door-peer: 65534\r\nx-nucleus-workload-uid: 65534\r\n";

    let reply = post_tcp(addr, "/v1/read", forged).await;
    assert!(
        reply.ends_with("none"),
        "TCP evidence must be None: {reply}"
    );

    let reply = post_tcp(addr, "/v1/write", forged).await;
    assert!(
        reply.starts_with("HTTP/1.0 403") && reply.contains("without the door's peer admission"),
        "a door route on TCP must refuse, not admit: {reply}"
    );
}

/// The impossible shapes are refusals, never a fall-through to "a main
/// listener caller with no certificate" (ADR 0007 A-2): a door connection
/// off the door's table, an admission without a door connection, and an
/// admission naming a different peer.
#[test]
fn evidence_refuses_every_mismatched_door_shape() {
    use axum::http::Extensions;
    let peer = DoorPeer { uid: WORKLOAD };
    let admission = DoorAdmission {
        peer: peer.clone(),
        route: DoorRoute::Read,
    };

    let mut both = Extensions::new();
    both.insert(ConnectInfo(peer.clone()));
    both.insert(admission.clone());
    assert!(matches!(
        TransportEvidence::of(&both),
        Ok(TransportEvidence::DoorPeer(a)) if a.uid() == WORKLOAD
    ));

    let mut connection_only = Extensions::new();
    connection_only.insert(ConnectInfo(peer));
    let mut admission_only = Extensions::new();
    admission_only.insert(admission.clone());
    let mut mismatched = Extensions::new();
    mismatched.insert(ConnectInfo(DoorPeer { uid: WORKLOAD + 1 }));
    mismatched.insert(admission);
    for (name, ext) in [
        ("connection only", connection_only),
        ("admission only", admission_only),
        ("mismatched", mismatched),
    ] {
        let got = TransportEvidence::of(&ext);
        assert!(got.is_err(), "{name}: {got:?}");
    }
    assert!(matches!(
        TransportEvidence::of(&Extensions::new()),
        Ok(TransportEvidence::None)
    ));
}

/// The requirement over each kind of evidence, directly: a door admission
/// meets it, `None` and a certificate without an attestation fail closed,
/// and with the requirement off `None` passes.
#[test]
fn the_requirement_over_each_evidence() {
    let headers = axum::http::HeaderMap::new();
    let admission = DoorAdmission {
        peer: DoorPeer { uid: WORKLOAD },
        route: DoorRoute::Egress,
    };
    let required = attestation_required();
    assert_eq!(
        required.admit(&TransportEvidence::DoorPeer(&admission), &headers),
        Ok(())
    );
    let refused = required
        .admit(&TransportEvidence::None, &headers)
        .expect_err("no evidence on a required proxy is refused");
    assert!(refused.contains("not provided"), "{refused}");
    assert!(
        required
            .admit(&TransportEvidence::ClientCert(&[0x30, 0x00]), &headers)
            .is_err()
    );
    let open = AttestationVerifier::new(AttestationConfig::default());
    assert_eq!(open.admit(&TransportEvidence::None, &headers), Ok(()));
}
