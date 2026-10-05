//! The fault-injection matrix for #2579.
//!
//! A launch fails at some site with some set of resources held. `run` is the launch's only exit,
//! so the set held at a failure is all that distinguishes one site from another. Every subset of
//! the handle's resources is therefore acquired for real — a killing child, a cgroup leaf, a jail
//! directory, a network allocation, two TCP listeners, a launch slot — and the body fails. Every
//! one of them must then be observably released. Covering every subset, rather than the prefixes
//! of today's acquisition order, keeps the matrix true when the order changes.
//!
//! What this does not observe: `ip netns list` and `iptables-save` on a real host. Network release
//! here runs the real recycle logic (`net/cleanup.rs`) against an inventory that reports absence;
//! the host commands need a KVM host and are left to the live evidence.
use super::*;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Records which namespaces were released, and recycles plans through the real lease logic.
struct RecordingNet {
    released: Mutex<Vec<String>>,
}

static NET: RecordingNet = RecordingNet {
    released: Mutex::new(Vec::new()),
};

#[tonic::async_trait]
impl NetRelease for RecordingNet {
    async fn network(&self, plan: &mut net::NetPlan) -> Result<(), ApiError> {
        self.released.lock().unwrap().push(plan.netns.clone());
        net::cleanup_network_observed_absent(plan).await
    }
    async fn namespace(&self, name: &str) -> Result<(), ApiError> {
        self.released.lock().unwrap().push(name.to_string());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Permit,
    Netns,
    Network,
    Dns,
    Jail,
    Vmm,
    Cgroup,
    Bridge,
    Proxy,
}

const SLOTS: [Slot; 9] = [
    Slot::Permit,
    Slot::Netns,
    Slot::Network,
    Slot::Dns,
    Slot::Jail,
    Slot::Vmm,
    Slot::Cgroup,
    Slot::Bridge,
    Slot::Proxy,
];

/// What a case acquired, so its release can be observed.
#[derive(Default)]
struct Acquired {
    netns: Option<String>,
    network_index: Option<usize>,
    pids: Vec<u32>,
    dirs: Vec<std::path::PathBuf>,
    listeners: Vec<Witnessed>,
}

/// A listener and the case-owned socket it forwards to. A free port can be taken by another
/// test's server at once, so "the port still answers" is not evidence; a connection arriving at
/// THIS case's sink is.
struct Witnessed {
    addr: std::net::SocketAddr,
    sink: Sink,
}

enum Sink {
    /// The vsock bridge dials its Firecracker socket path for every accepted connection.
    Unix(tokio::net::UnixListener),
    /// The signed proxy forwards every request to its target.
    Tcp(tokio::net::TcpListener),
}

impl Witnessed {
    async fn still_serving(&self) -> bool {
        use tokio::io::AsyncWriteExt;
        let Ok(mut stream) = tokio::net::TcpStream::connect(self.addr).await else {
            return false;
        };
        let _ = stream
            .write_all(b"GET / HTTP/1.1\r\nhost: probe\r\n\r\n")
            .await;
        let reached = async {
            match &self.sink {
                Sink::Unix(sink) => sink.accept().await.is_ok(),
                Sink::Tcp(sink) => sink.accept().await.is_ok(),
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), reached)
            .await
            .unwrap_or(false)
    }
}

struct Case {
    pool: Arc<Semaphore>,
    allocator: net::NetworkAllocator,
    dir: tempfile::TempDir,
    acquired: Acquired,
}

fn sleeper() -> Child {
    tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .expect("spawn sleep")
}

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run kill")
        .success()
}

impl Case {
    fn new() -> Self {
        Self {
            pool: Arc::new(Semaphore::new(1)),
            allocator: net::NetworkAllocator::new(),
            dir: tempfile::tempdir().unwrap(),
            acquired: Acquired::default(),
        }
    }

    fn handle(&self, slots: &[Slot]) -> LaunchResources {
        let permit = slots
            .contains(&Slot::Permit)
            .then(|| self.pool.clone().try_acquire_owned().unwrap());
        LaunchResources::new(permit, &NET)
    }

    /// Acquire one real resource into the handle, in the launch's own order.
    async fn acquire(&mut self, res: &mut LaunchResources, slot: Slot) {
        let a = &mut self.acquired;
        match slot {
            Slot::Permit => {} // taken by `LaunchResources::new`, as the launch does
            Slot::Netns => {
                let name = format!("nuc-{}", &Uuid::new_v4().simple().to_string()[..8]);
                res.hold_netns(name.clone());
                a.netns = Some(name);
            }
            Slot::Network => {
                let name = a.netns.clone().unwrap_or_else(|| {
                    format!("nuc-{}", &Uuid::new_v4().simple().to_string()[..8])
                });
                let plan = self
                    .allocator
                    .allocate(Uuid::new_v4(), name.clone())
                    .unwrap();
                a.network_index = Some(plan.index());
                res.hold_network(plan);
                a.netns = Some(name);
            }
            Slot::Dns => {
                let child = sleeper();
                a.pids.push(child.id().unwrap());
                res.hold_dns(net::DnsProxyState {
                    child,
                    entries: Vec::new(),
                });
            }
            Slot::Jail => {
                let layout = firecracker_config::JailLayout::new(
                    &self.dir.path().join("jail"),
                    std::path::Path::new("/usr/bin/firecracker"),
                    &Uuid::new_v4().to_string(),
                );
                std::fs::create_dir_all(&layout.jail_root).unwrap();
                a.dirs
                    .push(layout.jail_root.parent().unwrap().to_path_buf());
                res.hold_jail(layout);
            }
            Slot::Vmm => {
                let child = sleeper();
                a.pids.push(child.id().unwrap());
                res.hold_vmm(child);
            }
            Slot::Cgroup => {
                let leaf = self
                    .dir
                    .path()
                    .join("cgroup")
                    .join(Uuid::new_v4().to_string());
                res.hold_cgroup(cgroup::Placement::create(&leaf).await.unwrap());
                a.dirs.push(leaf);
            }
            Slot::Bridge => {
                let uds = self.dir.path().join("v.sock");
                let sink = Sink::Unix(tokio::net::UnixListener::bind(&uds).unwrap());
                let bridge = vsock_bridge::VsockBridge::start(uds, 1).await.unwrap();
                let addr = bridge.listen_addr();
                a.listeners.push(Witnessed { addr, sink });
                res.hold_bridge(bridge);
            }
            Slot::Proxy => {
                let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let to = target.local_addr().unwrap();
                let proxy = signed_proxy::SignedProxy::start(to, Arc::new(vec![7; 32]), None, None)
                    .await
                    .unwrap();
                let addr = proxy.listen_addr();
                a.listeners.push(Witnessed {
                    addr,
                    sink: Sink::Tcp(target),
                });
                res.hold_proxy(proxy);
            }
        }
    }

    /// Everything this case acquired is gone. Returns what was not.
    async fn leaks(&self) -> Vec<String> {
        let a = &self.acquired;
        let mut leaks = Vec::new();
        if self.pool.available_permits() != 1 {
            leaks.push("launch slot".to_string());
        }
        if let Some(name) = &a.netns
            && !NET.released.lock().unwrap().contains(name)
        {
            leaks.push(format!("namespace {name}"));
        }
        if let Some(index) = a.network_index {
            let next = self
                .allocator
                .allocate(Uuid::new_v4(), "probe".into())
                .unwrap();
            if next.index() != index {
                leaks.push(format!("network index {index}"));
            }
        }
        leaks.extend(
            a.pids
                .iter()
                .filter(|p| alive(**p))
                .map(|p| format!("pid {p}")),
        );
        leaks.extend(
            a.dirs
                .iter()
                .filter(|d| d.exists())
                .map(|d| format!("dir {}", d.display())),
        );
        for listener in &a.listeners {
            if listener.still_serving().await {
                leaks.push(format!("listener {}", listener.addr));
            }
        }
        leaks
    }
}

/// Every subset of the handle's resources, held at a failure, is released by `run`.
#[tokio::test]
async fn a_failure_with_any_set_of_resources_held_releases_all_of_them() {
    let mut failures = Vec::new();
    for mask in 0u32..(1 << SLOTS.len()) {
        let held: Vec<Slot> = SLOTS
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, slot)| *slot)
            .collect();
        let mut case = Case::new();
        let res = case.handle(&held);
        let outcome = res
            .run(async |res: &mut LaunchResources| {
                for slot in &held {
                    case.acquire(res, *slot).await;
                }
                Err::<(), _>(ApiError::Driver("injected".into()))
            })
            .await;
        assert!(
            matches!(&outcome, Err(ApiError::Driver(m)) if m == "injected"),
            "the injected error is the one returned"
        );
        let leaks = case.leaks().await;
        if !leaks.is_empty() {
            failures.push(format!("{held:?}: leaked {leaks:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Non-vacuity, and the success arm: a committed launch releases nothing — the pod owns it all.
#[tokio::test]
async fn a_committed_launch_hands_every_resource_on() {
    let mut case = Case::new();
    let res = case.handle(&SLOTS);
    let (value, committed) = res
        .run(async |res: &mut LaunchResources| {
            for slot in SLOTS {
                case.acquire(res, slot).await;
            }
            Ok(7)
        })
        .await
        .unwrap();
    assert_eq!(value, 7);
    let leaks = case.leaks().await;
    // Every observation can see a held resource, or the matrix above proves nothing.
    for (held, count) in [
        ("launch slot", 1),
        ("namespace", 1),
        ("network index", 1),
        ("pid", 2),
        ("dir", 2),
        ("listener", 2),
    ] {
        assert_eq!(
            leaks.iter().filter(|l| l.starts_with(held)).count(),
            count,
            "{held} still held by the committed pod: {leaks:?}"
        );
    }
    let Committed {
        permit,
        netns,
        mut net_plan,
        dns,
        jail,
        vmm,
        cgroup,
        bridge,
        proxy,
    } = committed;
    // Release by hand, as `StoppedVm::cleanup` would.
    drop((permit, netns, dns, vmm, cgroup));
    if let Some(plan) = net_plan.as_mut() {
        net::cleanup_network_observed_absent(plan).await.unwrap();
    }
    if let Some(jail) = jail {
        firecracker_config::cleanup_jail(&jail);
    }
    bridge.unwrap().shutdown().await;
    proxy.unwrap().shutdown().await;
}

/// A body that succeeds without a VMM registered nothing that runs: refused, and released.
#[tokio::test]
async fn success_without_a_vmm_is_refused_and_released() {
    let mut case = Case::new();
    let held = [Slot::Permit, Slot::Netns, Slot::Jail];
    let res = case.handle(&held);
    let outcome = res
        .run(async |res: &mut LaunchResources| {
            for slot in held {
                case.acquire(res, slot).await;
            }
            Ok(())
        })
        .await;
    assert!(outcome.is_err());
    assert_eq!(case.leaks().await, Vec::<String>::new());
}

/// The background release a dropped handle owes still releases everything.
#[tokio::test]
async fn background_release_releases_everything() {
    let mut case = Case::new();
    let mut res = case.handle(&SLOTS);
    for slot in SLOTS {
        case.acquire(&mut res, slot).await;
    }
    res.release_in_background();
    drop(res); // empty now: no panic
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let leaks = case.leaks().await;
        if leaks.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "background release left {leaks:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A handle dropped while holding something is a bypassed exit, and in tests it says so.
#[tokio::test]
#[should_panic(expected = "route the exit through run")]
async fn dropping_a_handle_that_holds_something_panics_in_tests() {
    let mut case = Case::new();
    let mut res = case.handle(&[]);
    case.acquire(&mut res, Slot::Jail).await;
    drop(res);
}

/// An empty handle has nothing to release and drops quietly.
#[test]
fn an_empty_handle_drops_quietly() {
    drop(LaunchResources::new(None, &NET));
}

/// With no runtime to release on, a dropped handle still releases what it can synchronously —
/// here the jail directory — before the test-build panic.
#[test]
fn without_a_runtime_a_dropped_handle_releases_synchronously() {
    let dir = tempfile::tempdir().unwrap();
    let layout = firecracker_config::JailLayout::new(
        dir.path(),
        std::path::Path::new("/usr/bin/firecracker"),
        "pod",
    );
    std::fs::create_dir_all(&layout.jail_root).unwrap();
    let jail = layout.jail_root.parent().unwrap().to_path_buf();
    let mut res = LaunchResources::new(None, &NET);
    res.hold_jail(layout);
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(res)));
    assert!(dropped.is_err(), "an unconsumed handle panics in tests");
    assert!(!jail.exists(), "the jail was released before the panic");
}
