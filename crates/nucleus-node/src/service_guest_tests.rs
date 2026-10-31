use super::*;

use std::cell::{Cell, RefCell};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener};

const CONSOLE: &str = r#"
[[service]]
name = "console"
spec = "/etc/nucleus/services/console.json"
volume = { size_mib = 20480 }
ingress = [{ listen = "0.0.0.0:443", guest_port = 8443 }]
restart = { policy = "always", initial_secs = 2, max_secs = 120, max_restarts_per_hour = 20 }
"#;

fn spec(json: &str) -> nucleus_spec::PodSpec {
    serde_json::from_str(json).expect("spec parses")
}

/// A service spec as the operator would write it: no network section, a vsock section.
fn console_spec() -> nucleus_spec::PodSpec {
    spec(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"},"vsock":{"guest_cid":3,"port":5005}}}"#,
    )
}

fn console() -> ServiceName {
    ServiceName::new("console").unwrap()
}

#[test]
fn the_console_entry_parses_and_its_volume_is_derived_under_the_state_dir() {
    let reg = ServiceRegistry::from_toml_str(CONSOLE).expect("parses");
    let plan = reg
        .plan(&console(), &console_spec(), Path::new("/var/lib/nucleus"))
        .expect("declared")
        .expect("admitted");
    assert_eq!(
        plan.volume().map(ServiceVolume::host_path),
        Some(Path::new("/var/lib/nucleus/services/console/volume.img"))
    );
    assert_eq!(plan.volume().map(ServiceVolume::size_mib), Some(20480));
    assert_eq!(
        plan.ingress(),
        &[IngressEntry {
            listen: "0.0.0.0:443".parse().unwrap(),
            guest_port: 8443
        }]
    );
    assert!(matches!(plan.restart(), RestartPolicy::Always(_)));
    assert_eq!(plan.name(), &console());
    assert_eq!(reg.services().len(), 1);
}

#[test]
fn an_undeclared_service_has_no_plan() {
    let reg = ServiceRegistry::from_toml_str(CONSOLE).unwrap();
    let other = ServiceName::new("agent-1").unwrap();
    assert!(reg.plan(&other, &console_spec(), Path::new("/s")).is_none());
}

/// Each refusal, driven by changing one thing in the console entry.
#[test]
fn the_registry_refuses_each_malformed_entry() {
    let cases: &[(&str, &str, &str)] = &[
        ("name = \"console\"", "name = \"../etc\"", "service name"),
        ("name = \"console\"", "name = \"Console\"", "service name"),
        (
            "spec = \"/etc/nucleus/services/console.json\"",
            "spec = \"console.json\"",
            "absolute",
        ),
        ("size_mib = 20480", "size_mib = 0", "above 0"),
        ("size_mib = 20480", "size_mib = 2097152", "is above"),
        ("0.0.0.0:443", "0.0.0.0:0", "port 0"),
        ("guest_port = 8443", "guest_port = 0", "reserved"),
        (
            "initial_secs = 2",
            "initial_secs = 500",
            "initial_secs <= max_secs",
        ),
        (
            "max_restarts_per_hour = 20",
            "max_restarts_per_hour = 0",
            "max_restarts_per_hour > 0",
        ),
        (
            "policy = \"always\"",
            "policy = \"never\"",
            "takes no backoff",
        ),
        (
            "policy = \"always\"",
            "policy = \"sometimes\"",
            "unknown variant",
        ),
        (
            "volume = {",
            "volume = { path = \"/etc/shadow\", ",
            "unknown field",
        ),
    ];
    for (from, to, want) in cases {
        let text = CONSOLE.replacen(from, to, 1);
        assert_ne!(text, CONSOLE, "the case {to:?} changed nothing");
        let err = ServiceRegistry::from_toml_str(&text).expect_err(to);
        assert!(err.contains(want), "{to:?}: {err}");
    }
}

/// The volume path cannot be written by the operator at all, only derived: `path` is an
/// unknown field (above), and the name's charset keeps the derived path under the root.
#[test]
fn a_derived_volume_path_never_leaves_the_state_dir() {
    for name in ["a", "console", "agent-0123456789abcdef", "z-9"] {
        let n = ServiceName::new(name).unwrap();
        let p = volume_path(Path::new("/var/lib/nucleus"), &n);
        assert!(
            p.starts_with("/var/lib/nucleus/services/"),
            "{}",
            p.display()
        );
        assert!(!p.components().any(|c| c == std::path::Component::ParentDir));
    }
}

#[test]
fn every_port_the_node_reserves_is_refused_as_an_ingress_guest_port() {
    for l in nucleus_ifc_kernel::VsockListener::ALL {
        let text = CONSOLE.replacen(
            "guest_port = 8443",
            &format!("guest_port = {}", l.port()),
            1,
        );
        let err = ServiceRegistry::from_toml_str(&text).expect_err("reserved");
        assert!(err.contains("reserved"), "{l:?}: {err}");
    }
}

#[test]
fn one_listen_address_cannot_be_claimed_by_two_services() {
    let two = format!(
        "{CONSOLE}\n{}",
        CONSOLE.replacen("\"console\"", "\"console-b\"", 1)
    );
    let err = ServiceRegistry::from_toml_str(&two).expect_err("claimed twice");
    assert!(err.contains("claimed twice"), "{err}");
    let dup = format!("{CONSOLE}\n{CONSOLE}");
    assert!(
        ServiceRegistry::from_toml_str(&dup)
            .unwrap_err()
            .contains("defined twice")
    );
}

// ----- No NIC, for ordinary pods and for service guests ---------------------------------------

/// An ordinary pod with no network policy gets no NIC: the netns is still made and default-
/// denied, and no `NetPlan` (so no tap) is allocated. Unchanged by this module, and pinned here
/// because a service guest must keep it.
#[test]
fn an_ordinary_pod_still_has_no_nic() {
    let ordinary = spec(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#,
    );
    let plan = crate::net::NetnsPlan::decide(true, ordinary.spec.network.as_ref());
    assert!(plan.create_netns && plan.apply_default_deny);
    assert!(
        !plan.allocate_net_plan,
        "an ordinary pod was given a NetPlan"
    );
}

/// A service guest's spec may not carry a network policy, so the composition that decides a NIC
/// sees exactly what it sees for an ordinary pod: no plan, no tap. Ingress is VSOCK.
#[test]
fn a_service_guest_has_no_nic_and_a_spec_asking_for_one_is_refused() {
    let reg = ServiceRegistry::from_toml_str(CONSOLE).unwrap();
    let admitted = console_spec();
    reg.plan(&console(), &admitted, Path::new("/s"))
        .unwrap()
        .expect("admitted");
    let netns = crate::net::NetnsPlan::decide(true, admitted.spec.network.as_ref());
    assert!(!netns.allocate_net_plan);

    let with_network = spec(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"},"vsock":{"guest_cid":3,"port":5005},"network":{"allow":["10.0.0.0/8"],"deny":[]}}}"#,
    );
    // Non-vacuity: this spec WOULD get a NIC as an ordinary pod.
    assert!(
        crate::net::NetnsPlan::decide(true, with_network.spec.network.as_ref()).allocate_net_plan
    );
    let err = reg
        .plan(&console(), &with_network, Path::new("/s"))
        .unwrap()
        .expect_err("a service spec with a network policy");
    assert!(err.contains("network policy"), "{err}");
}

#[test]
fn ingress_needs_vsock_and_cannot_reuse_the_specs_own_port() {
    let reg = ServiceRegistry::from_toml_str(CONSOLE).unwrap();
    let no_vsock = spec(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#,
    );
    assert!(
        reg.plan(&console(), &no_vsock, Path::new("/s"))
            .unwrap()
            .unwrap_err()
            .contains("vsock section")
    );
    let same_port = spec(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"},"vsock":{"guest_cid":3,"port":8443}}}"#,
    );
    assert!(
        reg.plan(&console(), &same_port, Path::new("/s"))
            .unwrap()
            .unwrap_err()
            .contains("own vsock port")
    );
}

// ----- Ingress rides VSOCK ---------------------------------------------------------------------

/// Firecracker's host-side VSOCK multiplexer, as the bridge sees it, recording which guest port
/// each host-initiated connection asked for.
async fn recording_mux(path: &Path) -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let listener = UnixListener::bind(path).expect("mux binds");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut line = Vec::new();
                let mut b = [0u8; 1];
                while s.read(&mut b).await.unwrap_or(0) == 1 {
                    line.push(b[0]);
                    if b[0] == b'\n' {
                        break;
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&line).into_owned());
                if s.write_all(b"OK 1073741824\n").await.is_err() {
                    return;
                }
                let mut buf = [0u8; 64];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    rx
}

#[tokio::test]
async fn ingress_carries_a_host_connection_to_the_guest_port_over_vsock() {
    let dir = tempfile::tempdir().unwrap();
    let uds = dir.path().join("vsock.sock");
    let mut connects = recording_mux(&uds).await;
    let plan = ServicePlan {
        name: console(),
        volume: None,
        ingress: vec![IngressEntry {
            listen: "127.0.0.1:0".parse().unwrap(),
            guest_port: 8443,
        }],
        restart: RestartPolicy::Never,
    };
    let bridges = start_ingress(&plan, &uds).await.expect("ingress starts");
    assert_eq!(bridges.len(), 1);
    let mut c = TcpStream::connect(bridges[0].listen_addr()).await.unwrap();
    c.write_all(b"ClientHello").await.unwrap();
    let mut got = [0u8; 11];
    c.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ClientHello", "bytes pass through untouched");
    assert_eq!(connects.recv().await.as_deref(), Some("CONNECT 8443\n"));
    for b in bridges {
        b.shutdown().await;
    }
}

#[tokio::test]
async fn ingress_is_all_or_none() {
    let dir = tempfile::tempdir().unwrap();
    let uds = dir.path().join("vsock.sock");
    let _connects = recording_mux(&uds).await;
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = taken.local_addr().unwrap();
    let free = {
        // IPv6 loopback: a port space the rest of the suite does not bind in, so nothing else
        // takes this port between its release and the rebind below.
        let l = std::net::TcpListener::bind("[::1]:0").unwrap();
        l.local_addr().unwrap()
    };
    let plan = ServicePlan {
        name: console(),
        volume: None,
        ingress: vec![
            IngressEntry {
                listen: free,
                guest_port: 8443,
            },
            IngressEntry {
                listen: busy,
                guest_port: 8080,
            },
        ],
        restart: RestartPolicy::Never,
    };
    assert!(start_ingress(&plan, &uds).await.is_err());
    // The first listener was dropped unserved, so its address binds again at once.
    std::net::TcpListener::bind(free).expect("the first listener was released");
}

/// On metal: a real Firecracker VMM's VSOCK multiplexer accepts a host-initiated ingress
/// connection for a port its guest listens on. Needs a running guest that listens on VSOCK.
///
/// On the host, with a nucleus pod running whose guest listens on vsock port 8443:
/// ```text
/// NUCLEUS_E2E_VSOCK_UDS=/srv/jailer/firecracker/<pod-id>/root/vsock.sock \
/// NUCLEUS_E2E_GUEST_PORT=8443 \
///   cargo test -p nucleus-node --bin nucleus-node \
///   service_guest::tests::ingress_reaches_a_real_firecracker_guest -- --ignored --exact
/// ```
#[tokio::test]
#[ignore = "needs a running Firecracker guest on metal; see the doc comment for the command"]
async fn ingress_reaches_a_real_firecracker_guest() {
    let uds = PathBuf::from(std::env::var("NUCLEUS_E2E_VSOCK_UDS").expect("NUCLEUS_E2E_VSOCK_UDS"));
    let port: u32 = std::env::var("NUCLEUS_E2E_GUEST_PORT")
        .expect("NUCLEUS_E2E_GUEST_PORT")
        .parse()
        .expect("a port");
    let plan = ServicePlan {
        name: console(),
        volume: None,
        ingress: vec![IngressEntry {
            listen: "127.0.0.1:0".parse().unwrap(),
            guest_port: port,
        }],
        restart: RestartPolicy::Never,
    };
    let bridges = start_ingress(&plan, &uds).await.expect("ingress starts");
    let mut c = TcpStream::connect(bridges[0].listen_addr()).await.unwrap();
    c.write_all(b"GET /health HTTP/1.0\r\n\r\n").await.unwrap();
    let mut first = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), c.read_exact(&mut first))
        .await
        .expect("the guest answered within 10 s")
        .expect("read");
    for b in bridges {
        b.shutdown().await;
    }
}

// ----- Restart --------------------------------------------------------------------------------

fn backoff(per_hour: u32) -> Backoff {
    Backoff {
        initial: Duration::from_secs(2),
        max: Duration::from_secs(30),
        max_restarts_per_hour: per_hour,
    }
}

#[test]
fn failures_back_off_doubling_to_the_cap() {
    let p = RestartPolicy::Always(backoff(1000));
    let waits: Vec<_> = (0..6)
        .map(|f| p.decide(ExitKind::Failed, Duration::from_secs(10_000), &[], f))
        .collect();
    let secs = [2, 4, 8, 16, 30, 30];
    for (w, s) in waits.iter().zip(secs) {
        assert_eq!(w, &RestartDecision::RestartAfter(Duration::from_secs(s)));
    }
    // No overflow at absurd failure counts.
    assert_eq!(
        p.decide(ExitKind::Failed, Duration::ZERO, &[], u32::MAX),
        RestartDecision::RestartAfter(Duration::from_secs(30))
    );
}

#[test]
fn on_failure_and_never_stop_where_they_say() {
    let on = RestartPolicy::OnFailure(backoff(10));
    assert_eq!(
        on.decide(ExitKind::Clean, Duration::ZERO, &[], 0),
        RestartDecision::Stop
    );
    assert!(matches!(
        on.decide(ExitKind::Failed, Duration::ZERO, &[], 0),
        RestartDecision::RestartAfter(_)
    ));
    for e in [ExitKind::Clean, ExitKind::Failed] {
        assert_eq!(
            RestartPolicy::Never.decide(e, Duration::ZERO, &[], 0),
            RestartDecision::Stop
        );
    }
    // `Always` relaunches a clean exit too, after the initial wait.
    assert_eq!(
        RestartPolicy::Always(backoff(10)).decide(ExitKind::Clean, Duration::ZERO, &[], 5),
        RestartDecision::RestartAfter(Duration::from_secs(2))
    );
}

#[test]
fn a_crash_loop_gives_up_and_old_restarts_do_not_count() {
    let p = RestartPolicy::Always(backoff(3));
    let now = Duration::from_secs(10_000);
    let recent = [
        now - Duration::from_secs(10),
        now - Duration::from_secs(20),
        now - Duration::from_secs(30),
    ];
    assert!(matches!(
        p.decide(ExitKind::Failed, now, &recent, 2),
        RestartDecision::GiveUp { .. }
    ));
    let old = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(3),
    ];
    assert!(matches!(
        p.decide(ExitKind::Failed, now, &old, 2),
        RestartDecision::RestartAfter(_)
    ));
}

/// A launcher whose every life ends the same way, on a fake clock advanced only by waits.
struct Fake {
    exit: ExitKind,
    clock: Cell<Duration>,
    lives: RefCell<Vec<Duration>>,
}

impl ServiceLauncher for Fake {
    async fn run_once(&self, _plan: &ServicePlan) -> ExitKind {
        self.lives.borrow_mut().push(self.clock.get());
        self.exit
    }
    async fn wait(&self, d: Duration) {
        self.clock.set(self.clock.get() + d);
    }
    fn now(&self) -> Duration {
        self.clock.get()
    }
}

fn plan_with(restart: RestartPolicy) -> ServicePlan {
    ServicePlan {
        name: console(),
        volume: None,
        ingress: Vec::new(),
        restart,
    }
}

#[tokio::test]
async fn the_supervisor_relaunches_until_a_crash_loop_then_gives_up() {
    let f = Fake {
        exit: ExitKind::Failed,
        clock: Cell::new(Duration::from_secs(1)),
        lives: RefCell::new(Vec::new()),
    };
    let (end, lives) = Supervisor::new(&f, plan_with(RestartPolicy::Always(backoff(3))))
        .run()
        .await;
    assert!(matches!(end, SupervisorEnd::GaveUp(_)), "{end:?}");
    assert_eq!(
        lives, 4,
        "three relaunches, then the fourth failure gives up"
    );
    let starts = f.lives.borrow().clone();
    let gaps: Vec<u64> = starts.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
    assert_eq!(gaps, [2, 4, 8], "each relaunch waited its backoff");
}

#[tokio::test]
async fn the_supervisor_stops_after_a_clean_exit_on_failure_policy() {
    let f = Fake {
        exit: ExitKind::Clean,
        clock: Cell::new(Duration::ZERO),
        lives: RefCell::new(Vec::new()),
    };
    let (end, lives) = Supervisor::new(&f, plan_with(RestartPolicy::OnFailure(backoff(3))))
        .run()
        .await;
    assert_eq!((end, lives), (SupervisorEnd::Stopped, 1));
}

/// A service guest's upstreams are its jobs' (`job_grant`); a spec naming them too is refused.
#[test]
fn a_service_spec_naming_credentialed_upstreams_is_refused() {
    let reg = ServiceRegistry::from_toml_str(CONSOLE).unwrap();
    let with_upstream = spec(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"},"vsock":{"guest_cid":3,"port":5005},"credentialed_egress":[{"name":"coding-model","upstream":"https://model.example/","header":"authorization"}]}}"#,
    );
    assert_eq!(
        with_upstream.spec.credentialed_egress.len(),
        1,
        "non-vacuous"
    );
    let err = reg
        .plan(&console(), &with_upstream, Path::new("/s"))
        .unwrap()
        .expect_err("a service spec naming upstreams");
    assert!(err.contains("credentialed upstreams"), "{err}");
}
