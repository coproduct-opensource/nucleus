//! The proxy end to end, host side only, against a stand-in node.
//!
//! The stand-in answers the real decision frames with a ledger-minted id, so
//! these tests exercise the proxy's own checks: the parser's refusals, the
//! address rule, and no-answer-is-a-denial. Whether a request is ALLOWED is
//! the node's (`nucleus-node`'s egress-proxy tests decide with the real
//! registry and pod policy).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use nucleus_decision_protocol::host::DecisionLedger;
use nucleus_decision_protocol::{DenyReason, GuestFrame, HostFrame, LEN_PREFIX, Verdict, body_len};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};

use super::*;
use crate::decision::HostUnavailable;
use crate::refusal::REFUSAL_HEADER;
use crate::resolve::StaticResolver;
use crate::summary;

/// How the stand-in node behaves.
#[derive(Clone, Copy)]
enum Node {
    /// Answer every `Decide` with an allow.
    Allow,
    /// Answer every `Decide` with this denial.
    Deny(DenyReason),
    /// Read the frame and never answer.
    Silent,
    /// Read the frame and close the channel.
    Close,
}

/// Run a stand-in node on `end`; count the `Decide` frames it receives.
fn stand_in(end: UnixStream, node: Node, asked: Arc<AtomicUsize>) {
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
                seq,
                op,
                subject,
                args_digest,
            } = GuestFrame::decode_body(&body).unwrap()
            else {
                panic!("the proxy sends only Decide");
            };
            asked.fetch_add(1, Ordering::SeqCst);
            // The proxy's binding is the one the node recomputes (C-2).
            assert_eq!(op, summary::OPERATION);
            assert_eq!(args_digest, summary::digest(subject.as_str()));
            assert!(summary::Summary::parse(subject.as_str()).is_ok());
            let verdict = match node {
                Node::Allow => Verdict::Allowed {
                    decision_id: ledger.allow(args_digest).unwrap(),
                },
                Node::Deny(reason) => Verdict::Denied { reason },
                Node::Silent => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    return;
                }
                Node::Close => return,
            };
            let reply = HostFrame::Verdict { seq, verdict }.encode().unwrap();
            end.write_all(&reply).await.unwrap();
        }
    });
}

/// An upstream that counts the connections it accepts and answers `200 ok`.
async fn fixture() -> (u16, Arc<AtomicUsize>, Arc<tokio::sync::Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let (h, s) = (Arc::clone(&hits), Arc::clone(&seen));
    tokio::spawn(async move {
        loop {
            let (mut c, _) = listener.accept().await.unwrap();
            h.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 8192];
            let n = c.read(&mut buf).await.unwrap_or(0);
            s.lock().await.extend_from_slice(&buf[..n]);
            let _ = c
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await;
        }
    });
    (port, hits, seen)
}

struct Harness {
    proxy: Proxy<UnixStream, StaticResolver>,
    asked: Arc<AtomicUsize>,
}

fn harness(node: Node, resolver: StaticResolver, deadline: Duration) -> Harness {
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    stand_in(node_end, node, Arc::clone(&asked));
    let floor = vec![
        "169.254.0.0/16".parse().unwrap(),
        "10.200.0.0/24".parse().unwrap(),
    ];
    Harness {
        proxy: Proxy::new(SharedDecider::new(proxy_end, deadline), resolver, floor),
        asked,
    }
}

/// Send `raw` as the guest; return what the proxy concluded and what the
/// guest read back.
async fn exchange(h: &Harness, raw: &[u8]) -> (Served, String) {
    let (mut guest, proxy_side) = tokio::io::duplex(1 << 20);
    guest.write_all(raw).await.unwrap();
    let served = h.proxy.connection(proxy_side).await;
    let mut out = Vec::new();
    guest.read_to_end(&mut out).await.unwrap();
    (served, String::from_utf8_lossy(&out).into_owned())
}

fn refusal_of(response: &str) -> Option<&str> {
    response
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{REFUSAL_HEADER}: ")))
}

fn get(origin: &str, host: &str) -> Vec<u8> {
    format!("GET {origin}/v1/x HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n").into_bytes()
}

/// Positive control: an allowed request to a registered literal reaches the
/// upstream, in the form the proxy wrote, and its answer is relayed.
#[tokio::test]
async fn an_allowed_request_is_performed_and_relayed() {
    let (port, hits, seen) = fixture().await;
    let h = harness(
        Node::Allow,
        StaticResolver::default(),
        Duration::from_secs(2),
    );
    let origin = format!("http://127.0.0.1:{port}");
    let (served, response) = exchange(&h, &get(&origin, &format!("127.0.0.1:{port}"))).await;
    assert_eq!(served, Served::Forwarded);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("ok"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(h.asked.load(Ordering::SeqCst), 1);
    let sent = String::from_utf8(seen.lock().await.clone()).unwrap();
    assert_eq!(
        sent,
        format!(
            "GET /v1/x HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\naccept: */*\r\nconnection: close\r\n\r\n"
        )
    );
}

/// A node's refusal is the guest's refusal, and nothing is sent.
#[tokio::test]
async fn a_denied_request_is_not_performed() {
    let (port, hits, _) = fixture().await;
    let h = harness(
        Node::Deny(DenyReason::NotGranted),
        StaticResolver::default(),
        Duration::from_secs(2),
    );
    let origin = format!("http://127.0.0.1:{port}");
    let (served, response) = exchange(&h, &get(&origin, &format!("127.0.0.1:{port}"))).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::Denied(DenyReason::NotGranted))
    );
    assert_eq!(refusal_of(&response), Some("denied_not_granted"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// **A-19: no decision answer means deny** (ADR 0014 §7). A node that never
/// answers, and one that closes the channel, each refuse with their own
/// reason; the upstream is never contacted; and the poisoned channel refuses
/// the next request too rather than reading a late reply as its answer.
#[tokio::test]
async fn no_answer_from_the_node_is_a_denial() {
    let (port, hits, _) = fixture().await;
    let origin = format!("http://127.0.0.1:{port}");
    let req = get(&origin, &format!("127.0.0.1:{port}"));

    let silent = harness(
        Node::Silent,
        StaticResolver::default(),
        Duration::from_millis(200),
    );
    let (served, response) = exchange(&silent, &req).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::HostUnavailable(HostUnavailable::Timeout))
    );
    assert_eq!(refusal_of(&response), Some("host_unavailable_timeout"));
    let (served, _) = exchange(&silent, &req).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::HostUnavailable(HostUnavailable::Poisoned))
    );

    let closed = harness(
        Node::Close,
        StaticResolver::default(),
        Duration::from_secs(2),
    );
    let (served, _) = exchange(&closed, &req).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::HostUnavailable(HostUnavailable::Closed))
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no answer, no request");
}

/// **A-19: a private or metadata resolution is refused** (ADR 0015 §3). The
/// node allows every request here, so only the proxy's address rule stands
/// between a name and the address it resolves to. The fixture listens on
/// loopback, so with the rule removed the first request reaches it.
#[tokio::test]
async fn a_private_or_metadata_resolution_is_refused() {
    let (port, hits, _) = fixture().await;
    let resolver = StaticResolver::default()
        .with("rebound.example", &[IpAddr::V4(Ipv4Addr::LOCALHOST)])
        .with("internal.example", &["10.0.0.7".parse().unwrap()])
        .with("metadata.example", &["169.254.169.254".parse().unwrap()])
        .with("pool.example", &["10.200.0.1".parse().unwrap()])
        .with(
            "mixed.example",
            &[
                "93.184.215.14".parse().unwrap(),
                "169.254.169.254".parse().unwrap(),
            ],
        );
    let h = harness(Node::Allow, resolver, Duration::from_secs(2));
    for (name, why) in [
        ("rebound.example", Refusal::PrivateAddress),
        ("internal.example", Refusal::PrivateAddress),
        ("metadata.example", Refusal::ForbiddenAddress),
        ("pool.example", Refusal::ForbiddenAddress),
        ("mixed.example", Refusal::ForbiddenAddress),
    ] {
        let host = format!("{name}:{port}");
        let (served, response) = exchange(&h, &get(&format!("http://{host}"), &host)).await;
        assert_eq!(served, Served::Refused(why), "{name}");
        assert_eq!(refusal_of(&response), Some(why.code()), "{name}");
    }
    // Literals: the metadata address and the node floor are refused even
    // when written, and even when the node allowed them.
    for literal in ["169.254.169.254", "10.200.0.1"] {
        let host = format!("{literal}:{port}");
        let (served, _) = exchange(&h, &get(&format!("http://{host}"), &host)).await;
        assert_eq!(
            served,
            Served::Refused(Refusal::ForbiddenAddress),
            "{literal}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// **A-19: a malformed, HTTP/2 or upgrade request is refused**, before the
/// node is asked and before anything is sent (ADR 0015 §4).
#[tokio::test]
async fn malformed_http2_and_upgrade_requests_are_refused_before_anyone_is_asked() {
    let (port, hits, _) = fixture().await;
    let h = harness(
        Node::Allow,
        StaticResolver::default(),
        Duration::from_secs(2),
    );
    let o = format!("127.0.0.1:{port}");
    for (raw, why) in [
        (
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_string(),
            Refusal::Http2,
        ),
        (
            format!(
                "GET http://{o}/ HTTP/1.1\r\nHost: {o}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            ),
            Refusal::Upgrade,
        ),
        (
            format!(
                "GET http://{o}/ HTTP/1.1\r\nHost: {o}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\r\n"
            ),
            Refusal::Upgrade,
        ),
        (
            format!("CONNECT {o} HTTP/1.1\r\nHost: {o}\r\n\r\n"),
            Refusal::Connect,
        ),
        // A raw TLS ClientHello, sent without a CONNECT: not HTTP.
        (
            "\u{16}\u{3}\u{1}\u{0}\u{5}hello".to_string(),
            Refusal::Malformed,
        ),
        (
            format!("GET /v1/x HTTP/1.1\r\nHost: {o}\r\n\r\n"),
            Refusal::NotAbsoluteForm,
        ),
        (
            format!(
                "POST http://{o}/ HTTP/1.1\r\nHost: {o}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
            Refusal::TransferEncoding,
        ),
        (
            format!(
                "POST http://{o}/ HTTP/1.1\r\nHost: {o}\r\nContent-Length: 1\r\n\r\nxGET http://{o}/ HTTP/1.1\r\n\r\n"
            ),
            Refusal::Malformed,
        ),
    ] {
        let (served, response) = exchange(&h, raw.as_bytes()).await;
        assert_eq!(served, Served::Refused(why), "{raw:?}");
        assert_eq!(refusal_of(&response), Some(why.code()), "{raw:?}");
    }
    assert_eq!(
        h.asked.load(Ordering::SeqCst),
        0,
        "the node was never asked"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// ADR 0015 §10: the 65th concurrent connection is refused with its own
/// reason.
#[tokio::test]
async fn connections_past_the_limit_are_refused() {
    let h = Arc::new(harness(
        Node::Silent,
        StaticResolver::default(),
        Duration::from_secs(5),
    ));
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let (guest, proxy_side) = tokio::io::duplex(1024);
        let h = Arc::clone(&h);
        held.push(guest);
        tokio::spawn(async move { h.proxy.connection(proxy_side).await });
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (served, response) = exchange(&h, b"GET http://a.example/ HTTP/1.1\r\n\r\n").await;
    assert_eq!(served, Served::Refused(Refusal::TooManyConnections));
    assert_eq!(refusal_of(&response), Some("too_many_connections"));
    drop(held);
}
