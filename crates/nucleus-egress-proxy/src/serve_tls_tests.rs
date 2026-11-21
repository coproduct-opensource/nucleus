//! E3: a terminated `CONNECT`, end to end in-process, against a stand-in node
//! and a real rustls client. Every case checks the journal's kernel verdict,
//! which is the `TlsTermination.step` outcome `TlsTerminationExtracted.lean`
//! proves the code computes.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use nucleus_decision_protocol::host::DecisionLedger;
use nucleus_decision_protocol::{GuestFrame, HostFrame, LEN_PREFIX, Verdict, body_len};
use rustls::RootCertStore;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UnixStream;

use super::*;
use crate::refusal::REFUSAL_HEADER;
use crate::resolve::StaticResolver;
use crate::tls::{PodCa, Termination, now_unix, test_ca};

const FAR: u64 = 4_000_000_000;

/// A stand-in node that allows every `Decide` and counts them.
fn allowing_node(end: UnixStream, asked: Arc<AtomicUsize>) {
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
                subject,
                args_digest,
                ..
            } = GuestFrame::decode_body(&body).unwrap()
            else {
                panic!("the proxy sends only Decide");
            };
            assert!(
                subject.as_str().starts_with("GET https://api.test:443/"),
                "{}",
                subject.as_str()
            );
            asked.fetch_add(1, Ordering::SeqCst);
            let verdict = Verdict::Allowed {
                decision_id: ledger.allow(args_digest).unwrap(),
            };
            let reply = HostFrame::Verdict { seq, verdict }.encode().unwrap();
            end.write_all(&reply).await.unwrap();
        }
    });
}

struct Rig {
    proxy: Arc<Proxy<UnixStream, StaticResolver>>,
    asked: Arc<AtomicUsize>,
    ca_cert: Vec<u8>,
}

/// A proxy whose pod CA permits exactly `api.test` until `not_after`.
fn rig(not_after: u64) -> Rig {
    let (cert, key) = test_ca::mint(&["api.test"], not_after);
    let ca = PodCa::from_bundle(&PodCa::to_bundle(&cert, &key)).unwrap();
    let termination = Termination::new(ca, RootCertStore::empty(), now_unix).unwrap();
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    allowing_node(node_end, Arc::clone(&asked));
    let resolver = StaticResolver::default().with("api.test", &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let proxy = Proxy::new(
        SharedDecider::new(proxy_end, Duration::from_secs(2)),
        resolver,
        vec!["169.254.0.0/16".parse().unwrap()],
    )
    .with_tls(termination);
    Rig {
        proxy: Arc::new(proxy),
        asked,
        ca_cert: cert,
    }
}

fn client(trust: &[u8], alpn: &[&[u8]]) -> tokio_rustls::TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(trust.to_vec())).unwrap();
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// The guest's side: `CONNECT authority`, then TLS for `sni` trusting
/// `trust`, then `request` (Host already in it). Returns what the proxy
/// concluded, and either the response read inside TLS or the handshake error.
async fn guest(
    r: &Rig,
    authority: &str,
    sni: &str,
    trust: &[u8],
    alpn: &[&[u8]],
    request: &str,
) -> (Served, Result<String, String>) {
    let (mut g, proxy_side) = tokio::io::duplex(1 << 20);
    let proxy = Arc::clone(&r.proxy);
    let served = tokio::spawn(async move { proxy.connection(proxy_side).await });
    g.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut established = [0u8; 39];
    g.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection established\r\n\r\n");
    let outcome = tls_exchange(g, sni, trust, alpn, request).await;
    (served.await.unwrap(), outcome)
}

async fn tls_exchange(
    g: DuplexStream,
    sni: &str,
    trust: &[u8],
    alpn: &[&[u8]],
    request: &str,
) -> Result<String, String> {
    let name = ServerName::try_from(sni.to_string()).unwrap();
    let mut tls = client(trust, alpn)
        .connect(name, g)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(p) = tls.get_ref().1.alpn_protocol() {
        assert_ne!(p, b"h2", "the proxy never offers h2");
    }
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn refusal_of(response: &str) -> Option<&str> {
    response
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{REFUSAL_HEADER}: ")))
}

const GET_API: &str = "GET /v1/x HTTP/1.1\r\nHost: api.test\r\nAccept: */*\r\n\r\n";

/// A permitted name is terminated, its request reaches the node's decision
/// (as `https://api.test:443/…`), and only then the address rule applies:
/// `api.test` resolves to loopback here, which a name may not reach.
#[tokio::test]
async fn a_permitted_name_is_decided() {
    let r = rig(FAR);
    let ca = r.ca_cert.clone();
    let (served, out) = guest(&r, "api.test:443", "api.test", &ca, &[b"http/1.1"], GET_API).await;
    let response = out.unwrap();
    assert_eq!(r.asked.load(Ordering::SeqCst), 1, "the node was asked");
    assert_eq!(refusal_of(&response), Some("private_address"), "{response}");
    assert_eq!(served, Served::Refused(Refusal::PrivateAddress));
    let journal = r.proxy.tls_journal();
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].sni.as_deref(), Some("api.test"));
    assert_eq!(journal[0].verdict, TlsVerdict::Decided);
    assert_eq!(r.proxy.tls.as_ref().unwrap().minter.minted(), 1);
}

/// A name outside the CA's constraints: no leaf is minted, the handshake
/// fails, the node is never asked.
#[tokio::test]
async fn a_name_outside_the_constraints_is_refused_and_no_leaf_is_minted() {
    let r = rig(FAR);
    let ca = r.ca_cert.clone();
    let get = "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n";
    let (served, out) = guest(&r, "other.test:443", "other.test", &ca, &[b"http/1.1"], get).await;
    assert!(out.is_err(), "the handshake must fail");
    assert_eq!(served, Served::Refused(Refusal::TlsNameNotPermitted));
    assert_eq!(r.proxy.tls.as_ref().unwrap().minter.minted(), 0);
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
    let j = r.proxy.tls_journal();
    assert_eq!(j[0].verdict, TlsVerdict::RefusedNameNotPermitted);
    assert_eq!(j[0].sni.as_deref(), Some("other.test"));
}

/// A client that trusts another CA (pinned, or another pod's) rejects the
/// leaf: refused as `client_rejected_interception`, with its name, never
/// tunnelled.
#[tokio::test]
async fn a_client_trusting_another_ca_is_refused_and_recorded() {
    let r = rig(FAR);
    let (other, _) = test_ca::mint(&["api.test"], FAR);
    let (served, out) = guest(
        &r,
        "api.test:443",
        "api.test",
        &other,
        &[b"http/1.1"],
        GET_API,
    )
    .await;
    assert!(out.is_err(), "the client must reject the leaf");
    assert_eq!(served, Served::Refused(Refusal::ClientRejectedInterception));
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
    let j = r.proxy.tls_journal();
    assert_eq!(j[0].verdict, TlsVerdict::RefusedClientRejected);
    assert_eq!(j[0].sni.as_deref(), Some("api.test"));
}

/// Domain fronting: the TLS name is permitted, the `Host` header names
/// another origin. Refused inside TLS; the node is never asked.
#[tokio::test]
async fn sni_and_host_that_differ_are_fronting() {
    let r = rig(FAR);
    let ca = r.ca_cert.clone();
    let fronted = "GET /v1/x HTTP/1.1\r\nHost: other.test\r\n\r\n";
    let (served, out) = guest(&r, "api.test:443", "api.test", &ca, &[b"http/1.1"], fronted).await;
    assert_eq!(refusal_of(&out.unwrap()), Some("fronting"));
    assert_eq!(served, Served::Refused(Refusal::Fronting));
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
    assert_eq!(
        r.proxy.tls_journal()[0].verdict,
        TlsVerdict::RefusedFronting
    );
}

/// The `CONNECT` authority is part of the same agreement: a tunnel opened
/// for one name and spoken to as another is fronting too.
#[tokio::test]
async fn a_connect_authority_that_differs_from_the_tls_name_is_fronting() {
    let (cert, key) = test_ca::mint(&["api.test", "other.test"], FAR);
    let ca = PodCa::from_bundle(&PodCa::to_bundle(&cert, &key)).unwrap();
    let mut r = rig(FAR);
    r.ca_cert = cert.clone();
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    allowing_node(node_end, Arc::clone(&r.asked));
    r.proxy = Arc::new(
        Proxy::new(
            SharedDecider::new(proxy_end, Duration::from_secs(2)),
            StaticResolver::default(),
            vec![],
        )
        .with_tls(Termination::new(ca, RootCertStore::empty(), now_unix).unwrap()),
    );
    let (served, _) = guest(
        &r,
        "other.test:443",
        "api.test",
        &cert,
        &[b"http/1.1"],
        GET_API,
    )
    .await;
    assert_eq!(served, Served::Refused(Refusal::Fronting));
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
}

/// A CA past its deadline terminates nothing.
#[tokio::test]
async fn an_expired_ca_is_refused() {
    let r = rig(1_000);
    let ca = r.ca_cert.clone();
    let (served, out) = guest(&r, "api.test:443", "api.test", &ca, &[b"http/1.1"], GET_API).await;
    assert!(out.is_err());
    assert_eq!(served, Served::Refused(Refusal::TlsExpired));
    assert_eq!(r.proxy.tls.as_ref().unwrap().minter.minted(), 0);
    assert_eq!(r.proxy.tls_journal()[0].verdict, TlsVerdict::RefusedExpired);
}

/// A client that offers only h2 gets no h2: the proxy offers http/1.1 alone,
/// so the handshake fails rather than negotiating a protocol whose requests
/// this parser cannot read.
#[tokio::test]
async fn an_h2_only_client_gets_no_h2() {
    let r = rig(FAR);
    let ca = r.ca_cert.clone();
    let (served, out) = guest(&r, "api.test:443", "api.test", &ca, &[b"h2"], GET_API).await;
    assert!(out.is_err(), "no protocol in common: the handshake fails");
    assert!(matches!(served, Served::Refused(_)));
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
}

/// After `CONNECT`, bytes that are not a ClientHello are refused: no raw
/// tunnels.
#[tokio::test]
async fn a_connect_that_does_not_speak_tls_is_refused() {
    let r = rig(FAR);
    let (mut g, proxy_side) = tokio::io::duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    let served = tokio::spawn(async move { proxy.connection(proxy_side).await });
    g.write_all(b"CONNECT api.test:443 HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = g.read_to_end(&mut out).await;
    assert_eq!(served.await.unwrap(), Served::Refused(Refusal::NotTls));
    assert!(r.proxy.tls_journal().is_empty());
}

/// Without a pod CA, `CONNECT` is refused exactly as in E2.
#[tokio::test]
async fn without_a_ca_connect_is_refused_as_before() {
    let (proxy_end, _node) = UnixStream::pair().unwrap();
    let proxy = Proxy::new(
        SharedDecider::new(proxy_end, Duration::from_secs(2)),
        StaticResolver::default(),
        vec![],
    );
    let (mut g, proxy_side) = tokio::io::duplex(1 << 16);
    g.write_all(b"CONNECT api.test:443 HTTP/1.1\r\nHost: api.test:443\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        proxy.connection(proxy_side).await,
        Served::Refused(Refusal::Connect)
    );
}

/// The upstream TLS client verifies the upstream against the configured
/// roots and the decided name: trusted root and right name connect; the
/// webpki roots (which do not hold the test CA) and a wrong name do not.
#[tokio::test]
async fn the_upstream_client_verifies_roots_and_name() {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = CertificateParams::new(vec!["up.test".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let a = acceptor.clone();
            tokio::spawn(async move {
                let _ = a.accept(s).await;
            });
        }
    });
    let (ca_cert, ca_key) = test_ca::mint(&["api.test"], FAR);
    let pod = || PodCa::from_bundle(&PodCa::to_bundle(&ca_cert, &ca_key)).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let trusting = Termination::new(pod(), roots, now_unix).unwrap();
    let webpki = Termination::new(pod(), Termination::webpki(), now_unix).unwrap();

    let tcp = || TcpStream::connect(addr);
    assert!(
        upstream_tls(tcp().await.unwrap(), "up.test", &trusting)
            .await
            .is_ok()
    );
    assert_eq!(
        upstream_tls(tcp().await.unwrap(), "up.test", &webpki)
            .await
            .err(),
        Some(Refusal::UpstreamUnreachable)
    );
    assert_eq!(
        upstream_tls(tcp().await.unwrap(), "elsewhere.test", &trusting)
            .await
            .err(),
        Some(Refusal::UpstreamUnreachable)
    );
}
