//! Link mode (ADR 0017 L4b), end to end in-process: a stand-in node on the
//! decision channel, the node's control lines, and a fake destination that
//! speaks Firecracker's host-initiated vsock handshake (`CONNECT`/`OK`, as in
//! `nucleus-node`'s `vsock_bridge` tests) and the L4c relay's `PORT` preamble.
//! Every case checks what the destination SAW, not only what the guest got.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use nucleus_decision_protocol::host::DecisionLedger;
use nucleus_decision_protocol::{DenyReason, GuestFrame, HostFrame, LEN_PREFIX, Verdict, body_len};
use rustls::RootCertStore;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use super::*;
use crate::link::{Control, LinkTarget, Links, Route, link_name, parse_uuid};
use crate::refusal::REFUSAL_HEADER;
use crate::tls::{PodCa, Termination, now_unix, test_ca};

const DST: &str = "0123abcd-0000-4000-8000-00000000beef";
const GUEST_PORT: u32 = 1031;
const FAR: u64 = 4_000_000_000;

fn dst() -> u128 {
    parse_uuid(DST).unwrap()
}

/// A stand-in node: allows, or denies with `deny`; counts what it is asked.
fn node(end: UnixStream, deny: Option<DenyReason>, asked: Arc<AtomicUsize>) {
    tokio::spawn(async move {
        let mut end = end;
        let mut ledger = DecisionLedger::new(7);
        loop {
            let mut prefix = [0u8; LEN_PREFIX];
            if end.read_exact(&mut prefix).await.is_err() {
                return;
            }
            let mut body = vec![0u8; body_len(prefix).unwrap()];
            end.read_exact(&mut body).await.unwrap();
            let GuestFrame::Decide {
                seq, args_digest, ..
            } = GuestFrame::decode_body(&body).unwrap()
            else {
                panic!("the proxy sends only Decide");
            };
            asked.fetch_add(1, Ordering::SeqCst);
            let verdict = match deny {
                None => Verdict::Allowed {
                    decision_id: ledger.allow(args_digest).unwrap(),
                },
                Some(reason) => Verdict::Denied { reason },
            };
            let reply = HostFrame::Verdict { seq, verdict }.encode().unwrap();
            end.write_all(&reply).await.unwrap();
        }
    });
}

/// What one connection to the fake destination carried.
#[derive(Debug, Default)]
struct Seen {
    handshake: String,
    preamble: String,
    request: String,
}

/// How the fake destination answers.
#[derive(Clone, Copy)]
enum Answer {
    /// A whole response, then close.
    Whole,
    /// Response headers, then hold the connection open and report when the
    /// proxy closes it.
    Hold,
}

/// A fake destination at a fresh socket path: the vsock mux plus the guest
/// relay. Each connection's bytes go to `seen`; `closed` reports when a held
/// connection is closed by the proxy.
struct Dst {
    path: PathBuf,
    connections: Arc<AtomicUsize>,
    seen: mpsc::UnboundedReceiver<Seen>,
    closed: mpsc::UnboundedReceiver<()>,
}

fn dst_mux(answer: Answer) -> Dst {
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "nlk-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_file(&path);
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
                match answer {
                    Answer::Whole => {
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi")
                            .await;
                    }
                    Answer::Hold => {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\npart").await;
                        let mut b = [0u8; 1];
                        // Returns when the proxy closes its end.
                        let _ = s.read(&mut b).await;
                        let _ = closed_tx.send(());
                    }
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

struct Rig {
    proxy: Arc<Proxy<UnixStream, crate::resolve::NoOutboundPath>>,
    links: Arc<Links>,
    asked: Arc<AtomicUsize>,
}

fn rig(deny: Option<DenyReason>) -> Rig {
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    node(node_end, deny, Arc::clone(&asked));
    let links = Arc::new(Links::default());
    let proxy = Proxy::link(
        SharedDecider::new(proxy_end, Duration::from_secs(2)),
        Arc::clone(&links),
    );
    Rig {
        proxy: Arc::new(proxy),
        links,
        asked,
    }
}

fn announce(r: &Rig, d: &Dst, port: u16) {
    r.links.apply(Control::Link(
        LinkTarget { dst: dst(), port },
        Route {
            uds: d.path.clone(),
            guest_port: GUEST_PORT,
        },
    ));
}

/// Send `request` as the guest; return what the proxy concluded and what the
/// guest read back.
async fn send(r: &Rig, request: &str) -> (Served, String) {
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

fn refusal_of(response: &str) -> Option<&str> {
    response
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{REFUSAL_HEADER}: ")))
}

fn get(port: u16) -> String {
    let name = link_name(dst());
    format!("GET http://{name}:{port}/v1/x HTTP/1.1\r\nHost: {name}:{port}\r\nAccept: */*\r\n\r\n")
}

/// An admitted request on a live link reaches the destination's relay with
/// Firecracker's handshake, the relay's preamble and the request the node
/// decided, re-serialised in origin form; the answer comes back.
#[tokio::test]
async fn an_admitted_request_is_delivered_with_the_preamble() {
    let r = rig(None);
    let mut d = dst_mux(Answer::Whole);
    announce(&r, &d, 8080);
    let (served, response) = send(&r, &get(8080)).await;
    assert_eq!(served, Served::Forwarded, "{response}");
    assert!(response.ends_with("hi"), "{response}");
    let seen = d.seen.recv().await.unwrap();
    assert_eq!(seen.handshake, format!("CONNECT {GUEST_PORT}"));
    assert_eq!(seen.preamble, "PORT 8080");
    let name = link_name(dst());
    assert!(
        seen.request
            .starts_with(&format!("GET /v1/x HTTP/1.1\r\nhost: {name}:8080\r\n")),
        "{}",
        seen.request
    );
    assert!(seen.request.contains("connection: close"));
    assert_eq!(r.asked.load(Ordering::SeqCst), 1);
}

/// A request the node denies never reaches the destination: zero
/// connections, zero bytes.
#[tokio::test]
async fn a_denied_request_never_reaches_the_destination() {
    let r = rig(Some(DenyReason::NotGranted));
    let d = dst_mux(Answer::Whole);
    announce(&r, &d, 8080);
    let (served, response) = send(&r, &get(8080)).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::Denied(DenyReason::NotGranted))
    );
    assert_eq!(refusal_of(&response), Some("denied_not_granted"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(d.connections.load(Ordering::SeqCst), 0);
}

/// The node allows, but this pod holds no live link to that pod and port
/// (never announced, another port, or severed): `may_deliver` says no and
/// nothing is connected.
#[tokio::test]
async fn a_request_on_a_link_that_is_not_live_is_never_connected() {
    let r = rig(None);
    let d = dst_mux(Answer::Whole);
    let (served, response) = send(&r, &get(8080)).await;
    assert_eq!(served, Served::Refused(Refusal::LinkNotLive), "{response}");
    announce(&r, &d, 9090);
    let (served, _) = send(&r, &get(8080)).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::LinkNotLive),
        "another port"
    );
    announce(&r, &d, 8080);
    r.links.apply(Control::Sever(LinkTarget {
        dst: dst(),
        port: 8080,
    }));
    let (served, _) = send(&r, &get(8080)).await;
    assert_eq!(served, Served::Refused(Refusal::LinkNotLive), "severed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(d.connections.load(Ordering::SeqCst), 0);
    assert_eq!(r.asked.load(Ordering::SeqCst), 3, "the node decided each");
}

/// `SEVER` closes a live connection at once, mid-response: the destination
/// sees its connection closed and the guest's read ends.
#[tokio::test]
async fn sever_closes_live_connections() {
    let r = rig(None);
    let mut d = dst_mux(Answer::Hold);
    announce(&r, &d, 8080);
    let (mut g, p) = tokio::io::duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    let served = tokio::spawn(async move { proxy.connection(p).await });
    g.write_all(get(8080).as_bytes()).await.unwrap();
    let _ = d.seen.recv().await.unwrap();
    let mut part = [0u8; 23];
    g.read_exact(&mut part).await.unwrap();
    assert_eq!(&part, b"HTTP/1.1 200 OK\r\n\r\npart");
    r.links.apply(Control::Sever(LinkTarget {
        dst: dst(),
        port: 8080,
    }));
    tokio::time::timeout(Duration::from_secs(2), d.closed.recv())
        .await
        .expect("the destination's connection closes on sever")
        .unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), g.read_to_end(&mut rest))
        .await
        .expect("the guest's side ends on sever")
        .unwrap();
    assert!(rest.is_empty());
    assert_eq!(served.await.unwrap(), Served::Forwarded);
}

/// The fail-closed path: a broken control channel severs everything.
#[tokio::test]
async fn a_broken_control_channel_severs_live_connections() {
    let r = rig(None);
    let mut d = dst_mux(Answer::Hold);
    let (mut control, follow) = tokio::io::duplex(1024);
    let links = Arc::clone(&r.links);
    let following = tokio::spawn(async move { links.follow(follow).await });
    control
        .write_all(
            format!(
                "LINK {DST} 8080 {GUEST_PORT} {}\n",
                d.path.to_str().unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    while r.links.is_empty() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (mut g, p) = tokio::io::duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    tokio::spawn(async move { proxy.connection(p).await });
    g.write_all(get(8080).as_bytes()).await.unwrap();
    let _ = d.seen.recv().await.unwrap();
    drop(control);
    following.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), d.closed.recv())
        .await
        .expect("closed when the node's channel ends")
        .unwrap();
    assert!(r.links.is_empty());
}

/// TLS from the source, terminated with the pod CA for the link name (E3);
/// the destination receives the decided request in clear over vsock.
#[tokio::test]
async fn tls_over_a_link_is_terminated_and_delivered() {
    let name = link_name(dst());
    let (cert, key) = test_ca::mint(&[name.as_str()], FAR);
    let ca = PodCa::from_bundle(&PodCa::to_bundle(&cert, &key)).unwrap();
    let termination = Termination::new(ca, RootCertStore::empty(), now_unix).unwrap();
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    node(node_end, None, Arc::clone(&asked));
    let links = Arc::new(Links::default());
    let proxy = Arc::new(
        Proxy::link(
            SharedDecider::new(proxy_end, Duration::from_secs(2)),
            Arc::clone(&links),
        )
        .with_tls(termination),
    );
    let mut d = dst_mux(Answer::Whole);
    links.apply(Control::Link(
        LinkTarget {
            dst: dst(),
            port: 443,
        },
        Route {
            uds: d.path.clone(),
            guest_port: GUEST_PORT,
        },
    ));

    let (mut g, p) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn({
        let proxy = Arc::clone(&proxy);
        async move { proxy.connection(p).await }
    });
    g.write_all(format!("CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut established = [0u8; 39];
    g.read_exact(&mut established).await.unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.clone())).unwrap();
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(name.clone()).unwrap(), g)
        .await
        .unwrap();
    tls.write_all(format!("GET /v1/x HTTP/1.1\r\nHost: {name}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    let out = String::from_utf8_lossy(&out).into_owned();
    assert!(out.ends_with("hi"), "{out}");
    assert_eq!(served.await.unwrap(), Served::Forwarded);
    let seen = d.seen.recv().await.unwrap();
    assert_eq!(seen.preamble, "PORT 443");
    assert!(
        seen.request
            .starts_with(&format!("GET /v1/x HTTP/1.1\r\nhost: {name}\r\n")),
        "{}",
        seen.request
    );
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    assert_eq!(
        proxy.tls_journal()[0].verdict,
        nucleus_ifc_kernel::extracted::tls::TlsVerdict::Decided
    );
}

/// Smuggling shapes are refused by the shared parser before the node is
/// asked, and the destination is never connected.
#[tokio::test]
async fn smuggling_shapes_are_refused_before_anything_is_connected() {
    let r = rig(None);
    let d = dst_mux(Answer::Whole);
    announce(&r, &d, 8080);
    let name = link_name(dst());
    let url = format!("http://{name}:8080/x");
    let cases = [
        (
            format!(
                "POST {url} HTTP/1.1\r\nHost: {name}:8080\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
            "transfer_encoding",
        ),
        (
            format!(
                "GET {url} HTTP/1.1\r\nHost: {name}:8080\r\n\r\nGET {url} HTTP/1.1\r\nHost: {name}:8080\r\n\r\n"
            ),
            "malformed",
        ),
        (
            format!(
                "GET {url} HTTP/1.1\r\nHost: {name}:8080\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            ),
            "upgrade",
        ),
        (
            format!("CONNECT {name}:8080 HTTP/1.1\r\nHost: {name}:8080\r\n\r\n"),
            "connect",
        ),
    ];
    for (request, code) in cases {
        let (served, response) = send(&r, &request).await;
        assert_eq!(
            refusal_of(&response),
            Some(code),
            "{request:?} -> {served:?}"
        );
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(d.connections.load(Ordering::SeqCst), 0);
    assert_eq!(r.asked.load(Ordering::SeqCst), 0, "none reached the node");
}

/// The link proxy refuses a host that is not a link name, without asking
/// the node: it has no other upstream.
#[tokio::test]
async fn the_link_proxy_refuses_a_name_that_is_not_a_link() {
    let r = rig(None);
    let (served, response) = send(
        &r,
        "GET http://api.test/x HTTP/1.1\r\nHost: api.test\r\n\r\n",
    )
    .await;
    assert_eq!(served, Served::Refused(Refusal::NotALink), "{response}");
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
}

/// The egress proxy refuses a link name before asking the node: a link can
/// never leave the node by the egress path.
#[tokio::test]
async fn the_egress_proxy_refuses_a_link_name() {
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    node(node_end, None, Arc::clone(&asked));
    let proxy = Arc::new(Proxy::new(
        SharedDecider::new(proxy_end, Duration::from_secs(2)),
        crate::resolve::NoOutboundPath,
        vec!["169.254.0.0/16".parse().unwrap()],
    ));
    let (mut g, p) = tokio::io::duplex(1 << 16);
    let served = tokio::spawn(async move { proxy.connection(p).await });
    g.write_all(get(8080).as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = g.read_to_end(&mut out).await;
    assert_eq!(served.await.unwrap(), Served::Refused(Refusal::LinkNotHere));
    assert_eq!(
        refusal_of(&String::from_utf8_lossy(&out)),
        Some("link_not_here")
    );
    assert_eq!(asked.load(Ordering::SeqCst), 0);
}
