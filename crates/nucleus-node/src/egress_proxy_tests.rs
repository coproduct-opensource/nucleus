//! The egress proxy composed with the node's decision service, host side:
//! the real proxy (`nucleus_egress_proxy::serve::Proxy`) over a real
//! socketpair to the real `EgressDecider`, with the operator's routes from a
//! registry file, a real `PodPolicy`, and its durable host-signed journal.
//! No guest: the request is written where the guest's vsock connection would
//! arrive (ADR 0015 E2).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use nucleus_decision_protocol::{ArgsDigest, GuestFrame, Operation, Seq, Subject};
use nucleus_egress_proxy::Refusal;
use nucleus_egress_proxy::decision::SharedDecider;
use nucleus_egress_proxy::resolve::StaticResolver;
use nucleus_egress_proxy::serve::{Proxy, Served};
use nucleus_spec::host_effect::{LOG_FILE, SignedAuthorization};
use portcullis::kernel::Kernel;
use portcullis::{CapabilityLevel, PermissionLattice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};

use super::*;
use crate::host_decide::evidence::Evidence;
use crate::upstreams::UpstreamRegistry;

/// An upstream that counts the connections it accepts and answers `200 ok`.
async fn fixture() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let (mut c, _) = listener.accept().await.unwrap();
            h.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 8192];
            let _ = c.read(&mut buf).await;
            let _ = c
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await;
        }
    });
    (port, hits)
}

fn registry(port: u16) -> Arc<EgressRoutes> {
    let toml = format!(
        r#"
[[egress]]
name    = "fixture"
origin  = "http://127.0.0.1:{port}"
methods = ["GET"]
paths   = ["/v1/*", "/static/**"]
call_charge_micro_usd = 0
"#
    );
    Arc::clone(UpstreamRegistry::from_toml_str(&toml).unwrap().egress())
}

struct Composed {
    proxy: Proxy<UnixStream, StaticResolver>,
    journal: tempfile::TempDir,
}

/// The node's decision service for one pod, and the proxy wired to it.
fn compose(routes: Arc<EgressRoutes>, lattice: PermissionLattice) -> Composed {
    let journal = tempfile::tempdir().unwrap();
    let pod = Uuid::new_v4();
    let evidence = Evidence::create(
        pod,
        journal.path(),
        Arc::new(SigningKey::from_bytes(&[9; 32])),
    )
    .unwrap();
    let policy = PodPolicy::new(Kernel::new(lattice), evidence);
    let decider = EgressDecider::new(pod, routes, policy, 1);
    let (proxy_end, node_end) = UnixStream::pair().unwrap();
    tokio::spawn(async move {
        let _ = serve_decisions(node_end, decider).await;
    });
    let floor = crate::net::NODE_DENY_FLOOR
        .iter()
        .map(|n| ipnet::IpNet::V4(*n))
        .collect();
    Composed {
        proxy: Proxy::new(
            SharedDecider::new(proxy_end, Duration::from_secs(2)),
            StaticResolver::default(),
            floor,
        ),
        journal,
    }
}

impl Composed {
    async fn send(&self, raw: &str) -> (Served, String) {
        let (mut guest, proxy_side) = tokio::io::duplex(1 << 16);
        guest.write_all(raw.as_bytes()).await.unwrap();
        let served = self.proxy.connection(proxy_side).await;
        let mut out = Vec::new();
        guest.read_to_end(&mut out).await.unwrap();
        (served, String::from_utf8_lossy(&out).into_owned())
    }

    fn journaled(&self) -> Vec<SignedAuthorization> {
        std::fs::read_to_string(self.journal.path().join(LOG_FILE))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn get(port: u16, path: &str) -> String {
    format!("GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
}

/// ADR 0015 E2's definition of done, the allow half: an in-registry request
/// is decided by the pod's policy, performed, and journaled host-signed.
#[tokio::test]
async fn an_in_registry_request_is_decided_performed_and_journaled() {
    let (port, hits) = fixture().await;
    let node = compose(registry(port), PermissionLattice::permissive());
    let (served, response) = node.send(&get(port, "/v1/items")).await;
    assert_eq!(served, Served::Forwarded, "{response}");
    assert!(response.ends_with("ok"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let records = node.journaled();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].authorization.subject,
        format!("http://127.0.0.1:{port}/v1/items")
    );
    assert_eq!(records[0].authorization.operation, "web_fetch");
}

/// **A-19: a request to an unregistered upstream is refused.** The pod's
/// policy would allow it (permissive), and the proxy would reach it (a
/// loopback literal); only the operator's registry stands in the way.
#[tokio::test]
async fn a_request_to_an_unregistered_upstream_is_refused() {
    let (port, _) = fixture().await;
    let (other, other_hits) = fixture().await;
    let node = compose(registry(port), PermissionLattice::permissive());
    let (served, _) = node.send(&get(other, "/v1/items")).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::Denied(DenyReason::NotRegistered))
    );
    assert_eq!(other_hits.load(Ordering::SeqCst), 0);
    assert!(node.journaled().is_empty(), "a refusal authorizes nothing");
}

/// **A-19: a refused method or path is refused**, by the registered entry's
/// own rules, before the pod's policy is asked.
#[tokio::test]
async fn a_refused_method_or_path_is_refused() {
    let (port, hits) = fixture().await;
    let node = compose(registry(port), PermissionLattice::permissive());
    for raw in [
        format!(
            "POST http://127.0.0.1:{port}/v1/items HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Content-Length: 2\r\n\r\nhi"
        ),
        get(port, "/admin"),
        get(port, "/v1/items/deeper"),
        get(port, "/v1/"),
    ] {
        let (served, _) = node.send(&raw).await;
        assert_eq!(
            served,
            Served::Refused(Refusal::Denied(DenyReason::RouteRefused)),
            "{raw:?}"
        );
    }
    let (served, _) = node.send(&get(port, "/static/a/b/c.css")).await;
    assert_eq!(served, Served::Forwarded, "a final ** admits any rest");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// The route is necessary, not sufficient: a registered request the pod's
/// policy does not grant is refused (G-1: the pod policy decides).
#[tokio::test]
async fn the_pod_policy_decides_a_registered_request() {
    let (port, hits) = fixture().await;
    let mut lattice = PermissionLattice::permissive();
    lattice.capabilities.web_fetch = CapabilityLevel::Never;
    let node = compose(registry(port), lattice);
    let (served, _) = node.send(&get(port, "/v1/items")).await;
    assert_eq!(
        served,
        Served::Refused(Refusal::Denied(DenyReason::NotGranted))
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A frame the proxy could not honestly have written closes the channel,
/// which the proxy reads as no answer.
#[test]
fn a_forged_frame_closes_the_channel() {
    let pod = Uuid::new_v4();
    let decider = || {
        EgressDecider::new(
            pod,
            Arc::new(EgressRoutes::none()),
            crate::host_decide::test_policy(PermissionLattice::permissive()),
            1,
        )
    };
    let text = "GET http://a.example:80/x\nheaders=\nbody=0:\
                e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let subject = Subject::new(text).unwrap();
    let frame = |op, digest| GuestFrame::Decide {
        seq: Seq::FIRST,
        op,
        subject: subject.clone(),
        args_digest: digest,
    };
    let honest = summary::digest(text);
    assert!(matches!(
        decider().step(frame(Operation::WebFetch, ArgsDigest::new([0; 32])), 1),
        Err(Close::DigestMismatch)
    ));
    assert!(matches!(
        decider().step(frame(Operation::ReadFiles, honest), 1),
        Err(Close::WrongOperation)
    ));
    let sloppy = text.replace(":80/", "/");
    assert!(matches!(
        decider().step(
            GuestFrame::Decide {
                seq: Seq::FIRST,
                op: Operation::WebFetch,
                subject: Subject::new(sloppy.clone()).unwrap(),
                args_digest: summary::digest(&sloppy),
            },
            1
        ),
        Err(Close::Summary(_))
    ));
    // And the honest frame is answered: here, not registered.
    let (_, decided) = decider()
        .step(frame(Operation::WebFetch, honest), 1)
        .unwrap();
    assert!(matches!(
        decided,
        Decided::Refused {
            reason: DenyReason::NotRegistered,
            detail: _,
        }
    ));
}

#[test]
fn the_registry_refuses_what_it_cannot_mean() {
    let entry = |origin: &str, methods: &str, paths: &str, charge: &str| {
        format!(
            "[[egress]]\nname = \"e\"\norigin = \"{origin}\"\nmethods = {methods}\n\
             paths = {paths}\n{charge}"
        )
    };
    let ok = entry(
        "http://a.example",
        "[\"GET\"]",
        "[\"/x\"]",
        "call_charge_micro_usd = 0",
    );
    assert!(UpstreamRegistry::from_toml_str(&ok).is_ok());
    for bad in [
        entry(
            "https://a.example",
            "[\"GET\"]",
            "[\"/x\"]",
            "call_charge_micro_usd = 0",
        ),
        entry(
            "http://a.example",
            "[]",
            "[\"/x\"]",
            "call_charge_micro_usd = 0",
        ),
        entry(
            "http://a.example",
            "[\"GET\"]",
            "[]",
            "call_charge_micro_usd = 0",
        ),
        entry(
            "http://a.example",
            "[\"TRACE\"]",
            "[\"/x\"]",
            "call_charge_micro_usd = 0",
        ),
        entry(
            "http://a.example",
            "[\"GET\"]",
            "[\"x\"]",
            "call_charge_micro_usd = 0",
        ),
        entry(
            "http://a.example",
            "[\"GET\"]",
            "[\"/a/../b\"]",
            "call_charge_micro_usd = 0",
        ),
        entry(
            "http://a.example",
            "[\"GET\"]",
            "[\"/a*\"]",
            "call_charge_micro_usd = 0",
        ),
        entry("http://a.example", "[\"GET\"]", "[\"/x\"]", ""),
        format!(
            "{ok}\n{}",
            entry(
                "http://a.example:80",
                "[\"GET\"]",
                "[\"/y\"]",
                "call_charge_micro_usd = 0"
            )
            .replace("name = \"e\"", "name = \"f\"")
        ),
    ] {
        assert!(UpstreamRegistry::from_toml_str(&bad).is_err(), "{bad}");
    }
}

#[test]
fn path_patterns_match_segment_by_segment() {
    let p = |s| PathPattern::parse(s).unwrap();
    assert!(p("/").matches("/"));
    assert!(!p("/").matches("/a"));
    assert!(p("/v1/*").matches("/v1/a"));
    assert!(!p("/v1/*").matches("/v1/"));
    assert!(!p("/v1/*").matches("/v1/a/b"));
    assert!(p("/v1/**").matches("/v1"));
    assert!(p("/v1/**").matches("/v1/a/b"));
    assert!(!p("/v1/**").matches("/v2/a"));
    assert!(p("/**").matches("/anything/at/all"));
    assert!(!p("/V1").matches("/v1"), "literals are exact");
}

/// The real binary, spawned the way the node spawns it, end to end over the
/// socket Firecracker would connect to. Root only (the namespace and the
/// drop), so it is ignored by default and run on a Linux builder with
/// `NUCLEUS_EGRESS_PROXY_TEST_BIN` naming a built `nucleus-egress-proxy`.
///
/// What it shows: the node's confinement takes (the node's own `verify`
/// passed, and the proxy's inside check and Landlock let it serve); the
/// decision channel works across the process boundary (an unregistered
/// origin is `denied_not_registered`, decided by the node); and the proxy's
/// fresh namespace has no route out: an ALLOWED request to the node's own
/// loopback fixture never arrives, because the proxy's loopback is its own.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root and NUCLEUS_EGRESS_PROXY_TEST_BIN"]
async fn the_real_proxy_runs_confined_with_no_route_out() {
    let binary = PathBuf::from(
        std::env::var("NUCLEUS_EGRESS_PROXY_TEST_BIN").expect("NUCLEUS_EGRESS_PROXY_TEST_BIN"),
    );
    let dir = tempfile::tempdir().unwrap();
    let (port, hits) = fixture().await;
    let pod = Uuid::new_v4();
    let evidence =
        Evidence::create(pod, dir.path(), Arc::new(SigningKey::from_bytes(&[9; 32]))).unwrap();
    let policy = PodPolicy::new(Kernel::new(PermissionLattice::permissive()), evidence);
    let vsock = dir.path().join("vsock.sock");
    let proxy = EgressProxy::start(Launch {
        binary: &binary,
        vsock_path: &vsock,
        pod_dir: dir.path(),
        jail_owner: None,
        run_as: (65534, 65534),
        decider: EgressDecider::new(pod, registry(port), policy, 1),
    })
    .await
    .expect("the proxy starts confined");
    let socket =
        crate::guest_socket::listener_path(&vsock, nucleus_ifc_kernel::VsockListener::EgressProxy);
    let ask = |raw: String| {
        let socket = socket.clone();
        async move {
            let mut s = UnixStream::connect(&socket).await.unwrap();
            s.write_all(raw.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).await.unwrap();
            String::from_utf8_lossy(&out).into_owned()
        }
    };
    let refusal = |r: &str| {
        r.lines()
            .find_map(|l| l.strip_prefix("x-nucleus-egress-refusal: "))
            .map(str::to_string)
    };
    let (other, _) = fixture().await;
    let r = ask(get(other, "/v1/items")).await;
    assert_eq!(refusal(&r).as_deref(), Some("denied_not_registered"), "{r}");
    let r = ask("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".into()).await;
    assert_eq!(refusal(&r).as_deref(), Some("http2"), "{r}");
    let r = ask(get(port, "/v1/items")).await;
    assert_eq!(refusal(&r).as_deref(), Some("upstream_unreachable"), "{r}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "nothing left the proxy's namespace"
    );
    let log = std::fs::read_to_string(dir.path().join(PROXY_LOG)).unwrap();
    assert!(log.contains("egress proxy confined and serving"), "{log}");
    proxy.shutdown().await;
}
