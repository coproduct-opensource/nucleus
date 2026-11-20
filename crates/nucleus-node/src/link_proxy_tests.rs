//! The link proxy composed with the node, host side (ADR 0017 L4b): the real
//! link-mode proxy (`nucleus_egress_proxy::serve::Proxy::link`) over a real
//! socketpair to the real [`LinkDecider`], the node's link table behind the
//! real routes (`pod_links`), the control lines over a real Unix socket, and a
//! fake destination that speaks Firecracker's host-initiated vsock handshake
//! (`CONNECT`/`OK`) and the L4c relay's `PORT` preamble. Every case checks
//! what the destination SAW.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Extension;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use nucleus_egress_proxy::decision::SharedDecider;
use nucleus_egress_proxy::link::{Control as ProxyControl, LinkTarget, Links, Route, link_name};
use nucleus_egress_proxy::resolve::NoOutboundPath;
use nucleus_egress_proxy::serve::{Proxy, Served};
use portcullis::PermissionLattice;
use portcullis::kernel::Kernel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tower::ServiceExt;

use super::*;
use crate::NodeState;
use crate::auth::CallerScope;
use crate::host_decide::PodPolicy;
use crate::host_decide::evidence::Evidence;
use crate::pod_api::handler_tests::{register_as, state};

const TENANT_A: &str = "spiffe://tenant-a.example.invalid/ns/rt-a/sa/alice";
const TENANT_A2: &str = "spiffe://tenant-a.example.invalid/ns/rt-a/sa/bob";

/// This process's uid and gid, from a directory it made: forwarder sockets are
/// chowned to the proxy's uid, which in a test is ours.
fn me(dir: &std::path::Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(dir).unwrap();
    (m.uid(), m.gid())
}

fn tenant() -> CallerScope {
    CallerScope::Tenant("tenant-a.example.invalid".to_owned())
}

/// What one connection to the fake destination carried.
#[derive(Debug, Default)]
struct Seen {
    handshake: String,
    preamble: String,
    request: String,
}

/// The fake destination: Firecracker's vsock mux plus the L4c guest relay.
struct Dst {
    path: PathBuf,
    connections: Arc<AtomicUsize>,
    seen: mpsc::UnboundedReceiver<Seen>,
    closed: mpsc::UnboundedReceiver<()>,
}

async fn read_line(s: &mut UnixStream) -> String {
    let mut out = Vec::new();
    loop {
        let b = s.read_u8().await.unwrap();
        if b == b'\n' {
            return String::from_utf8(out).unwrap();
        }
        out.push(b);
    }
}

/// `hold`: answer the head, then hold the connection open until the proxy
/// closes it, and report that on `closed`.
fn dst_mux(dir: &tempfile::TempDir, hold: bool) -> Dst {
    let path = dir.path().join("dst-vsock.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let (seen_tx, seen) = mpsc::unbounded_channel();
    let (closed_tx, closed) = mpsc::unbounded_channel();
    let count = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            let seen_tx = seen_tx.clone();
            let closed_tx = closed_tx.clone();
            tokio::spawn(async move {
                let handshake = read_line(&mut s).await;
                s.write_all(b"OK 7\n").await.unwrap();
                let preamble = read_line(&mut s).await;
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(b[0]);
                }
                let _ = seen_tx.send(Seen {
                    handshake,
                    preamble,
                    request: String::from_utf8_lossy(&request).into_owned(),
                });
                if hold {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\npart").await;
                    let mut b = [0u8; 1];
                    let _ = s.read(&mut b).await;
                    let _ = closed_tx.send(());
                } else {
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi")
                        .await;
                }
            });
        }
    });
    Dst {
        path,
        connections,
        seen,
        closed,
    }
}

/// The node, two linked-to-be pods of one tenant, the source's link proxy
/// composed with the node's decider, its control lines over a real socket,
/// and the destination's relay recorded at the fake mux.
struct Rig {
    st: NodeState,
    a: Uuid,
    b: Uuid,
    proxy: Arc<Proxy<UnixStream, NoOutboundPath>>,
    proxy_links: Arc<Links>,
    dst: Dst,
    _journal: tempfile::TempDir,
    _dir: tempfile::TempDir,
    _keep: UnixStream,
}

async fn rig(hold: bool) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let st = state(&dir);
    let a = register_as(&st, None, Some(TENANT_A)).await;
    let b = register_as(&st, None, Some(TENANT_A2)).await;

    // The source's control socket: the node binds and accepts; the proxy
    // connects and follows, as `LinkProxy::start` and the proxy's `run` do.
    let control_path = dir.path().join(CONTROL_SOCKET);
    let control = UnixListener::bind(&control_path).unwrap();
    let proxy_side = UnixStream::connect(&control_path).await.unwrap();
    let (node_side, _) = control.accept().await.unwrap();
    let proxy_links = Arc::new(Links::default());
    let follow = Arc::clone(&proxy_links);
    tokio::spawn(async move { follow.follow(proxy_side).await });

    let dst = dst_mux(&dir, hold);
    crate::pod_links::relay_started(
        &st,
        a,
        Relay {
            control: Arc::new(Control::new(node_side)),
            vsock: dir.path().join("src-vsock.sock"),
            pod_dir: dir.path().to_path_buf(),
            run_as: me(dir.path()),
        },
    )
    .await;
    let (keep, b_control) = UnixStream::pair().unwrap();
    crate::pod_links::relay_started(
        &st,
        b,
        Relay {
            control: Arc::new(Control::new(b_control)),
            vsock: dst.path.clone(),
            pod_dir: dir.path().join("dst-pod"),
            run_as: me(dir.path()),
        },
    )
    .await;

    // The source's decider: the real table, a permissive pod policy.
    let journal = tempfile::tempdir().unwrap();
    let evidence = Evidence::create(
        a,
        journal.path(),
        Arc::new(SigningKey::from_bytes(&[9; 32])),
    )
    .unwrap();
    let policy = PodPolicy::new(Kernel::new(PermissionLattice::permissive()), evidence);
    let decider = LinkDecider::new(a, Arc::clone(&st.links), policy, 1);
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    tokio::spawn(async move {
        let _ = serve_link_decisions(node_end, decider).await;
    });
    let proxy = Arc::new(Proxy::link(
        SharedDecider::new(proxy_end, Duration::from_secs(2)),
        Arc::clone(&proxy_links),
    ));
    Rig {
        st,
        a,
        b,
        proxy,
        proxy_links,
        dst,
        _journal: journal,
        _dir: dir,
        _keep: keep,
    }
}

async fn call(
    st: &NodeState,
    method: &str,
    uri: String,
    body: Option<serde_json::Value>,
) -> StatusCode {
    let app = crate::pod_links::routes()
        .layer(Extension(tenant()))
        .with_state(st.clone());
    let mut req = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    app.oneshot(req.body(body).unwrap()).await.unwrap().status()
}

async fn link(r: &Rig, port: u32) -> StatusCode {
    call(
        &r.st,
        "POST",
        format!("/v1/pods/{}/links", r.a),
        Some(serde_json::json!({"dst": r.b, "port": port})),
    )
    .await
}

/// Until the proxy has the route the node announced (or `want` is false and
/// it has none).
async fn proxy_sees(r: &Rig, want: bool) {
    for _ in 0..200 {
        if r.proxy_links.has_dst(r.b.as_u128()) == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the proxy never saw the control line (want {want})");
}

fn get(r: &Rig, port: u16) -> String {
    let name = link_name(r.b.as_u128());
    format!("GET http://{name}:{port}/v1/x HTTP/1.1\r\nHost: {name}:{port}\r\n\r\n")
}

async fn send(r: &Rig, request: String) -> (Served, String) {
    let (mut g, p) = tokio::io::duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    let served = tokio::spawn(async move { proxy.connection(p).await });
    g.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), g.read_to_end(&mut out)).await;
    (
        served.await.unwrap(),
        String::from_utf8_lossy(&out).into_owned(),
    )
}

/// A request over a link the node made is decided by the node's table and
/// the pod's policy, and delivered with the L4c preamble; the table records
/// the connection.
#[tokio::test]
async fn a_request_over_a_made_link_is_decided_by_the_table_and_delivered() {
    let mut r = rig(false).await;
    assert_eq!(link(&r, 8080).await, StatusCode::OK);
    proxy_sees(&r, true).await;
    let (served, out) = send(&r, get(&r, 8080)).await;
    assert_eq!(served, Served::Forwarded, "{out}");
    assert!(out.ends_with("hi"), "{out}");
    let seen = r.dst.seen.recv().await.unwrap();
    assert_eq!(seen.handshake, "CONNECT 1031");
    assert_eq!(seen.preamble, "PORT 8080");
    assert!(
        seen.request.starts_with("GET /v1/x HTTP/1.1\r\n"),
        "{}",
        seen.request
    );
    let links = r.st.links.lock().await;
    assert!(links.has_row(Link {
        src: r.a.as_u128(),
        dst: r.b.as_u128(),
        port: 8080
    }));
}

/// A route the proxy holds but the node's table does not (a stale or forged
/// announcement): the node refuses, and the destination sees zero bytes.
#[tokio::test]
async fn a_link_not_in_the_table_is_refused_by_the_node_and_nothing_is_connected() {
    let r = rig(false).await;
    r.proxy_links.apply(ProxyControl::Link(
        LinkTarget {
            dst: r.b.as_u128(),
            port: 9090,
        },
        Route {
            uds: r.dst.path.clone(),
            guest_port: nucleus_spec::LINK_RELAY_GUEST_PORT,
        },
    ));
    let (served, out) = send(&r, get(&r, 9090)).await;
    assert_ne!(served, Served::Forwarded, "{out}");
    assert!(
        out.contains("403") || out.contains("route_refused"),
        "{out}"
    );
    assert_eq!(r.dst.connections.load(Ordering::SeqCst), 0);
}

/// Unlink writes `SEVER` over the real control socket before its receipt:
/// the held connection is closed, and the proxy forgets the route.
#[tokio::test]
async fn unlink_severs_a_live_connection_through_the_control_socket() {
    let mut r = rig(true).await;
    assert_eq!(link(&r, 8080).await, StatusCode::OK);
    proxy_sees(&r, true).await;
    let (mut g, p) = tokio::io::duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    let served = tokio::spawn(async move { proxy.connection(p).await });
    g.write_all(get(&r, 8080).as_bytes()).await.unwrap();
    let mut head = [0u8; 23];
    g.read_exact(&mut head).await.unwrap();
    let _ = r.dst.seen.recv().await.unwrap();
    let status = call(
        &r.st,
        "DELETE",
        format!("/v1/pods/{}/links/{}/8080", r.a, r.b),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), r.dst.closed.recv())
        .await
        .expect("severed when unlinked")
        .unwrap();
    proxy_sees(&r, false).await;
    let _ = served.await;
}

/// A link port must be a TCP port: one the proxy cannot carry would make its
/// control line unparseable, and an unparseable line severs every link.
#[tokio::test]
async fn a_link_port_outside_tcp_is_refused_before_any_control_line() {
    let r = rig(false).await;
    assert_eq!(link(&r, 70_000).await, StatusCode::BAD_REQUEST);
    assert_eq!(link(&r, 0).await, StatusCode::BAD_REQUEST);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(r.proxy_links.is_empty());
}

/// E3 over a link: the node's half of the CA goes over the decision channel
/// (`hand_over`), the proxy reads exactly the bundle (`read_bundle`), and link
/// termination admits only names the node has announced.
#[tokio::test]
async fn the_ca_arrives_on_the_channel_and_tls_admits_only_announced_links() {
    use nucleus_egress_proxy::tls::{PodCa, now_unix, read_bundle};
    use nucleus_ifc_kernel::extracted::tls::TlsVerdict;

    let r = rig(false).await;
    let minted = crate::pod_ca::MintedCa::mint(Uuid::new_v4(), &[], now_unix(), 3600).unwrap();
    let (_egress, for_links) = minted.split();
    let (node_end, proxy_end) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut node_end = {
        node_end.set_nonblocking(true).unwrap();
        UnixStream::from_std(node_end).unwrap()
    };
    for_links.hand_over(&mut node_end).await.unwrap();
    node_end.write_all(b"FIRST-FRAME").await.unwrap();
    let mut proxy_end = proxy_end;
    let bundle = tokio::task::spawn_blocking(move || {
        let b = read_bundle(&mut proxy_end).unwrap();
        let mut rest = [0u8; 11];
        std::io::Read::read_exact(&mut proxy_end, &mut rest).unwrap();
        assert_eq!(&rest, b"FIRST-FRAME", "not one byte past the bundle");
        b
    })
    .await
    .unwrap();
    let ca = PodCa::from_bundle(&bundle).unwrap();
    let termination = nucleus_egress_proxy::link::termination(
        ca,
        rustls::RootCertStore::empty(),
        now_unix,
        &r.proxy_links,
    )
    .unwrap();
    let name = link_name(r.b.as_u128());
    let now = now_unix();
    assert_eq!(
        termination.verdict(now, Some(&name), true, true),
        TlsVerdict::RefusedNameNotPermitted,
        "not announced yet"
    );
    assert_eq!(link(&r, 443).await, StatusCode::OK);
    proxy_sees(&r, true).await;
    assert_eq!(
        termination.verdict(now, Some(&name), true, true),
        TlsVerdict::Decided
    );
    assert_eq!(
        termination.verdict(now, Some("api.example.test"), true, true),
        TlsVerdict::RefusedNameNotPermitted,
        "a link proxy terminates link names only"
    );
}

/// `connect_request_close_bounded`, on the node: every request over a link is
/// recorded as connect, request and close, so a link that carries many
/// requests leaves no connection open in the table. Before `close`, each one
/// stayed (found 2026-11-19, `9c8ed39b0`).
#[tokio::test]
async fn many_requests_over_a_link_leave_no_connection_open() {
    let mut r = rig(false).await;
    assert_eq!(link(&r, 8080).await, StatusCode::OK);
    proxy_sees(&r, true).await;
    for _ in 0..20 {
        let (served, out) = send(&r, get(&r, 8080)).await;
        assert_eq!(served, Served::Forwarded, "{out}");
        let _ = r.dst.seen.recv().await.unwrap();
    }
    assert_eq!(r.st.links.lock().await.open_conns(), 0);
}

/// Found on the first Linux run (local rehearsal, 2026-11-19): a destination's
/// vsock socket is in its jail root (0700, the jail user's), which the
/// unprivileged link proxy cannot traverse, so every admitted request ended
/// `LinkUnreachable`. The proxy is therefore given the node's forwarder in the
/// SOURCE pod's directory, never the destination's socket; unlinking removes
/// it, and with it every connection it carried.
#[tokio::test]
async fn the_proxy_dials_the_nodes_forwarder_never_the_destination_jail() {
    let r = rig(false).await;
    assert_eq!(link(&r, 8080).await, StatusCode::OK);
    proxy_sees(&r, true).await;
    let target = LinkTarget {
        dst: r.b.as_u128(),
        port: 8080,
    };
    let (route, _) = r.proxy_links.live(target).expect("the link was announced");
    assert_ne!(
        route.uds, r.dst.path,
        "the proxy must never be sent to the destination's jail"
    );
    assert!(
        route.uds.starts_with(r._dir.path()),
        "the forwarder lives in the source pod's directory: {}",
        route.uds.display()
    );
    assert!(route.uds.exists(), "the forwarder is listening");
    let (served, out) = send(&r, get(&r, 8080)).await;
    assert_eq!(
        served,
        Served::Forwarded,
        "delivered through the forwarder: {out}"
    );
    let status = call(
        &r.st,
        "DELETE",
        format!("/v1/pods/{}/links/{}/8080", r.a, r.b),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    proxy_sees(&r, false).await;
    assert!(!route.uds.exists(), "unlinking removes the forwarder");
}
