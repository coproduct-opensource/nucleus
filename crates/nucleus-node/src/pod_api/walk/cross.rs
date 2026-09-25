//! Which HOST commands commute with which GUEST commands, on one pod.
//!
//! The pod census (`census.rs`) and the guest census
//! (`workload_api_vsock/walk/census.rs`) each measure one surface, and neither can
//! see the other: the pod census never has a guest doing anything, and the guest
//! census never cancels its pod. This measures the faces BETWEEN them.
//!
//! # The universe
//!
//! One pod `P` with a real [`WorkloadApiVsockBridge`](crate::workload_api_vsock::WorkloadApiVsockBridge)
//! on a real Unix socket and a real identity (registered, certificate cached), held
//! in a [`FirecrackerPod`](crate::FirecrackerPod) — so a cancel runs the Firecracker
//! driver's own teardown, `cleanup_identity` included, not a restatement of it. The
//! VMM is a sleep process; there is no jail and no network plan. `P` has one child
//! `K`. Runs start from `K` running or cancelled, and `P`'s broker one-shot served
//! or not (4 states).
//!
//! The guest's connection to the bridge is opened before any letter, as a real
//! guest's is: the tool-proxy holds one open for the pod's life. Letters:
//!
//! - host: the operator cancels `P`, cancels `K`, creates a child of `P`, lists;
//! - guest, on the open connection: `PING`, `FETCH_SVID`, `FETCH_BROKER_SECRET`,
//!   `POD_LIST`; and on a FRESH connection: `PING`, `FETCH_SVID`.
//!
//! # The law this exists for
//!
//! **Cancel is a barrier.** Once the host has cancelled `P`, the guest is served
//! nothing — on any connection, including one it opened before. Found by this
//! census's first spike: the bridge's shutdown stopped ACCEPTING, but connections
//! already accepted were never told, so a guest holding one was served its caller
//! token, broker secret and pod list after `cancel_pod` had returned, and a
//! `FETCH_SVID` minted a fresh certificate for the identity `release_pod` had just
//! forgotten — re-caching it, with nothing left to forget it again. On Firecracker
//! the window is teardown itself: the bridge is shut first and the VMM killed last,
//! after proxy, DNS and network cleanup, with the guest running throughout.
//!
//! # The declaration
//!
//! [`declared_hollow`] derives the cross faces from each letter's [`footprint`]
//! (`effect_footprint`): a face is hollow exactly when one letter writes what the
//! other reads. Every guest letter reads `P`'s liveness — its scope — so the barrier
//! is a consequence, and `POD_LIST` also reads what `P` is shown (`K`'s liveness,
//! `P`'s children). Guest letters write only what no host letter here reads — the
//! one-shot latch and the certificate cache, which are checked in the record instead.
//!
//! Only cross faces are asserted. Host×host is the pod census's; guest×guest is the
//! guest census's; declaring them again here would be a second decider for each.
//!
//! # What this does not reach
//!
//! A real VMM (whose death closes the guest's end); the broker listener, DNS proxy
//! and network teardown that sit inside the window; the snapshot decision on the cross
//! axis. Concurrency is reached only by the race tests at the bottom — `FETCH_SVID`
//! hammered through a cancel, a mint in flight when one starts, and `SHIP_RECEIPT`
//! mid-ship, stalled, and racing on several connections — not by the census, whose
//! letters are sequential. The receipt tests found that concurrent ships tore the
//! collected log (two writes per receipt); `mediation_receipt_collector` has the fix
//! and its own test.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

use super::*;
use crate::effect_footprint::{self, Footprint};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Host {
    CancelP,
    CancelK,
    CreateUnderP,
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Command {
    Ping,
    FetchSvid,
    FetchBrokerSecret,
    PodList,
}

impl Command {
    fn wire(self) -> &'static str {
        match self {
            Command::Ping => "PING",
            Command::FetchSvid => "FETCH_SVID",
            Command::FetchBrokerSecret => "FETCH_BROKER_SECRET",
            Command::PodList => "POD_LIST",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Conn {
    /// The connection the guest opened before any letter.
    Open,
    /// A connection made for this letter.
    Fresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Letter {
    Host(Host),
    Guest(Conn, Command),
}

const HOST: [Host; 4] = [Host::CancelP, Host::CancelK, Host::CreateUnderP, Host::List];
const GUEST: [(Conn, Command); 6] = [
    (Conn::Open, Command::Ping),
    (Conn::Open, Command::FetchSvid),
    (Conn::Open, Command::FetchBrokerSecret),
    (Conn::Open, Command::PodList),
    (Conn::Fresh, Command::Ping),
    (Conn::Fresh, Command::FetchSvid),
];

/// What a letter was told.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// The guest got a reply that is not an error. Contents are not compared: a
    /// certificate differs between mints and says nothing about order.
    Served,
    /// The guest's pod list, in role terms.
    Listed(Vec<(String, bool)>),
    Refused(String),
    /// The connection was closed, or could not be made.
    Gone,
    /// No reply and no close within the bound: a hang is its own finding.
    Hung,
    HostOk,
    HostNotFound,
    HostListed(Vec<(String, bool)>),
    Other(String),
}

/// The host's state, in role terms.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    registry: Vec<(String, bool)>,
    /// Whether `P`'s certificate is in the node's cache.
    p_certificate_cached: bool,
    broker_served: bool,
    personalized: bool,
}

struct Run {
    st: NodeState,
    manager: crate::identity::IdentityManager,
    identity: nucleus_identity::Identity,
    p: Uuid,
    k: Uuid,
    socket: std::path::PathBuf,
    /// Where `SHIP_RECEIPT` bodies are collected for `P`.
    receipt_dir: std::path::PathBuf,
    open: Option<(BufReader<OwnedReadHalf>, OwnedWriteHalf)>,
    broker_served: Arc<AtomicBool>,
    personalized: Arc<AtomicBool>,
    _dir: tempfile::TempDir,
}

impl Run {
    async fn new(k_cancelled: bool, broker_already_served: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let manager =
            crate::identity::IdentityManager::new("cross.local", Duration::from_secs(3600))
                .expect("identity manager");
        let p = Uuid::new_v4();
        let identity = manager.pod_identity(p);
        manager.register_pod(p.to_string(), identity.clone()).await;
        manager
            .prefetch_certificate(&identity)
            .await
            .expect("certificate");

        let broker_served = Arc::new(AtomicBool::new(broker_already_served));
        let personalized = Arc::new(AtomicBool::new(false));
        // Every field named (E-1): a new kind of material is a decision for this
        // census, not a silent default.
        let material = crate::workload_api_vsock::PodMaterial {
            task_token: None,
            pod_certificate: None,
            caller_token: Some("test-token-123".into()),
            dlc_admission: None,
            broker_secret: Some("test-broker-secret".into()),
            broker_port: 0,
            broker_secret_served: Arc::clone(&broker_served),
            audit_creds: None,
            audit_creds_served: Arc::default(),
            pod_spec_yaml: None,
            mediation_signing_key: None,
            mediation_spiffe_id: None,
            at_snapshot_barrier: Arc::default(),
            personalized: Arc::clone(&personalized),
            mediation_key_served: Arc::default(),
            receipt_dir: Some(dir.path().join("p")),
            pod_registry: st.pods.clone(),
        };
        let bridge = crate::workload_api_vsock::WorkloadApiVsockBridge::start(
            dir.path().join("vsock.sock"),
            15012,
            p,
            manager.clone(),
            material,
            None,
        )
        .await
        .expect("bridge");
        let socket = bridge.socket_path().to_path_buf();

        let child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("a child spawns");
        let firecracker = crate::FirecrackerPod {
            pod_dir: dir.path().to_path_buf(),
            jail: Mutex::new(None),
            child: Arc::new(Mutex::new(child)),
            bridge: Mutex::new(None),
            signed_proxy: Mutex::new(None),
            permit: Mutex::new(None),
            net_plan: Mutex::new(None),
            netns: Mutex::new(None),
            dns_proxy: Mutex::new(None),
            drift_monitor: Mutex::new(None),
            drift_stop: Arc::default(),
            network_allocator: st.network_allocator.clone(),
            identity: Some(identity.clone()),
            identity_registry_key: Some(p.to_string()),
            identity_manager: Some(manager.clone()),
            workload_api_bridge: Mutex::new(Some(bridge)),
            broker: Mutex::new(None),
            snapshot: None,
        };
        let mut spec: nucleus_spec::PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                .expect("minimal spec");
        spec.spec.work_dir = dir.path().to_path_buf();
        st.pods.lock().await.insert(
            p,
            Arc::new(crate::PodHandle {
                id: p,
                spec,
                created_at: 1_757_000_000,
                log_path: dir.path().join("pod.log"),
                proxy_addr: Mutex::new(None),
                driver_state: crate::DriverState::Firecracker(Box::new(firecracker)),
                parent_pod_id: None,
                posture_stamp: None,
                owner: None,
            }),
        );
        let k = register(&st, Some(p)).await;
        if k_cancelled {
            let _ = cancel_pod(
                State(st.clone()),
                Extension(crate::pod_api::Caller::Operator),
                AxumPath(k),
            )
            .await;
        }

        let (r, w) = UnixStream::connect(&socket)
            .await
            .expect("the guest connects before anything happens")
            .into_split();
        Run {
            st,
            manager,
            identity,
            p,
            k,
            socket,
            receipt_dir: dir.path().join("p"),
            open: Some((BufReader::new(r), w)),
            broker_served,
            personalized,
            _dir: dir,
        }
    }

    fn label(&self, id: Uuid) -> String {
        if id == self.p {
            "P".into()
        } else if id == self.k {
            "K".into()
        } else {
            "new".into()
        }
    }

    async fn registry(&self) -> Vec<(String, bool)> {
        let mut out: Vec<(String, bool)> = collect_pod_infos(&self.st, None)
            .await
            .iter()
            .map(|i| (self.label(i.id), matches!(i.state, PodState::Running)))
            .collect();
        out.sort();
        out
    }

    async fn ask(&mut self, conn: Conn, command: Command) -> Seen {
        let reply = match conn {
            Conn::Open => match self.open.as_mut() {
                Some((r, w)) => exchange(r, w, command).await,
                None => Err(Seen::Gone),
            },
            Conn::Fresh => match UnixStream::connect(&self.socket).await {
                Ok(stream) => {
                    let (r, mut w) = stream.into_split();
                    exchange(&mut BufReader::new(r), &mut w, command).await
                }
                Err(_) => Err(Seen::Gone),
            },
        };
        let line = match reply {
            Ok(line) => line,
            Err(seen) => {
                if conn == Conn::Open && seen == Seen::Gone {
                    self.open = None;
                }
                return seen;
            }
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            return Seen::Other(line);
        };
        if let Some(e) = value.get("error") {
            return Seen::Refused(e.to_string());
        }
        match (command, value.as_array()) {
            (Command::PodList, Some(rows)) => {
                let mut listed: Vec<(String, bool)> = rows
                    .iter()
                    .map(|row| {
                        let id = row
                            .get("id")
                            .and_then(|v| v.as_str())
                            .and_then(|s| Uuid::parse_str(s).ok())
                            .unwrap_or_else(Uuid::nil);
                        let running = row.get("state").and_then(|v| v.as_str()) == Some("running");
                        (self.label(id), running)
                    })
                    .collect();
                listed.sort();
                Seen::Listed(listed)
            }
            (Command::PodList, None) => Seen::Other(line),
            (Command::Ping | Command::FetchSvid | Command::FetchBrokerSecret, _) => Seen::Served,
        }
    }

    async fn step(&mut self, letter: Letter) -> Seen {
        match letter {
            Letter::Host(Host::CancelP) | Letter::Host(Host::CancelK) => {
                let id = if letter == Letter::Host(Host::CancelP) {
                    self.p
                } else {
                    self.k
                };
                match cancel_pod(
                    State(self.st.clone()),
                    Extension(crate::pod_api::Caller::Operator),
                    AxumPath(id),
                )
                .await
                {
                    Ok(_) => Seen::HostOk,
                    Err(ApiError::NotFound) => Seen::HostNotFound,
                    Err(e) => Seen::Other(e.to_string()),
                }
            }
            Letter::Host(Host::CreateUnderP) => {
                let _ = register(&self.st, Some(self.p)).await;
                Seen::HostOk
            }
            Letter::Host(Host::List) => Seen::HostListed(self.registry().await),
            Letter::Guest(conn, command) => self.ask(conn, command).await,
        }
    }

    async fn finish(self) -> Record {
        let record = Record {
            registry: self.registry().await,
            p_certificate_cached: self
                .manager
                .secret_manager()
                .cached_identities()
                .await
                .contains(&self.identity),
            broker_served: self.broker_served.load(Ordering::SeqCst),
            personalized: self.personalized.load(Ordering::SeqCst),
        };
        drop(self.open);
        for (_, h) in self.st.pods.lock().await.iter() {
            let _ = h.cancel().await;
        }
        record
    }
}

/// One command, one reply line — or how the connection failed to give one.
async fn exchange(
    r: &mut BufReader<OwnedReadHalf>,
    w: &mut OwnedWriteHalf,
    command: Command,
) -> Result<String, Seen> {
    let frame = format!("{}\n", command.wire());
    if w.write_all(frame.as_bytes()).await.is_err() || w.flush().await.is_err() {
        return Err(Seen::Gone);
    }
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(2), r.read_line(&mut line)).await {
        Ok(Ok(0)) | Ok(Err(_)) => Err(Seen::Gone),
        Ok(Ok(_)) => Ok(line),
        Err(_) => Err(Seen::Hung),
    }
}

async fn run(k_cancelled: bool, broker_served: bool, letters: &[Letter]) -> (Vec<Seen>, Record) {
    let mut run = Run::new(k_cancelled, broker_served).await;
    let mut seen = Vec::with_capacity(letters.len());
    for &l in letters {
        seen.push(run.step(l).await);
    }
    (seen, run.finish().await)
}

/// What the host holds about `P`, as resources a letter reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Resource {
    /// Whether `P` is running. Every guest letter is scoped to it.
    LiveP,
    /// Whether `K` is running.
    LiveK,
    /// The pods created under `P`.
    ChildrenOfP,
    /// `P`'s certificate in the node's cache.
    CertCacheP,
    /// `P`'s broker one-shot.
    BrokerServed,
}

/// Each letter's footprint.
///
/// **The barrier is a read.** A guest letter is only valid while `P` lives, so every
/// one reads `LiveP`, and a cancel of `P` writes it: that is the whole of "cancel is
/// a barrier", and it is why every guest letter is hollow against `CancelP` without
/// a rule saying so. `POD_LIST` also reads what `P` is shown: `K`'s liveness and
/// `P`'s children.
fn footprint(letter: Letter) -> Footprint<Resource> {
    match letter {
        Letter::Host(Host::CancelP) => Footprint::pure().set(Resource::LiveP),
        Letter::Host(Host::CancelK) => Footprint::pure().set(Resource::LiveK),
        Letter::Host(Host::CreateUnderP) => Footprint::pure().update(Resource::ChildrenOfP),
        Letter::Host(Host::List) => Footprint::pure()
            .read(Resource::LiveP)
            .read(Resource::LiveK)
            .read(Resource::ChildrenOfP),
        Letter::Guest(_, command) => {
            let scoped = Footprint::pure().read(Resource::LiveP);
            match command {
                Command::Ping => scoped,
                Command::FetchSvid => scoped.update(Resource::CertCacheP),
                Command::FetchBrokerSecret => scoped.update(Resource::BrokerServed),
                Command::PodList => scoped.read(Resource::LiveK).read(Resource::ChildrenOfP),
            }
        }
    }
}

/// The cross faces, DERIVED from the footprints (see `effect_footprint`). Letters are
/// ordered hosts first, so every cross face comes out as (host, guest).
fn declared_hollow() -> BTreeSet<(Host, (Conn, Command))> {
    let letters: Vec<Letter> = HOST
        .iter()
        .map(|h| Letter::Host(*h))
        .chain(GUEST.iter().map(|(c, g)| Letter::Guest(*c, *g)))
        .collect();
    effect_footprint::hollow_faces(&letters, footprint)
        .into_iter()
        .filter_map(|face| match face {
            (Letter::Host(h), Letter::Guest(c, g)) => Some((h, (c, g))),
            (Letter::Host(_) | Letter::Guest(..), _) => None,
        })
        .collect()
}

/// Whether host letter `h` ends the scope guest letter `g` depends on: it writes a
/// liveness `g` is scoped to. The barrier assertion below runs for exactly these
/// pairs, derived rather than listed.
fn ends_scope_of(h: Host, g: (Conn, Command)) -> bool {
    // `P` is the pod whose guest these letters come from; `K`'s liveness is data a
    // listing shows, not a scope.
    // Against a footprint touching only `LiveP`, a conflict is exactly "writes it"
    // (for the host) and "reads it" (for the guest).
    footprint(Letter::Host(h)).conflicts_with(&Footprint::pure().read(Resource::LiveP))
        && Footprint::pure()
            .set(Resource::LiveP)
            .conflicts_with(&footprint(Letter::Guest(g.0, g.1)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_is_a_barrier_and_the_cross_faces_are_the_declared_ones() {
    let starts = [(false, false), (false, true), (true, false), (true, true)];
    let mut hollow: BTreeMap<(Host, (Conn, Command)), String> = BTreeMap::new();
    let mut served_after_cancel: Vec<String> = Vec::new();
    let mut leaked: Vec<String> = Vec::new();
    let mut hung: Vec<String> = Vec::new();
    let mut guest_served = 0usize;
    let mut checks = 0usize;

    for &(k_cancelled, broker) in &starts {
        for &h in &HOST {
            for &(conn, command) in &GUEST {
                let (a, b) = (Letter::Host(h), Letter::Guest(conn, command));
                let (hg_seen, hg) = run(k_cancelled, broker, &[a, b]).await;
                let (gh_seen, gh) = run(k_cancelled, broker, &[b, a]).await;
                checks += 1;
                let at = format!("K cancelled={k_cancelled}, broker served={broker}");

                for s in hg_seen.iter().chain(&gh_seen) {
                    if *s == Seen::Hung {
                        hung.push(format!("{h:?} / {conn:?} {command:?} ({at})"));
                    }
                    if matches!(s, Seen::Served | Seen::Listed(_)) {
                        guest_served += 1;
                    }
                }
                // The law, stated directly and not only as a face: after a cancel
                // of P, the guest is told nothing but that it is gone, and P's
                // certificate is not in the cache.
                if ends_scope_of(h, (conn, command)) {
                    if hg_seen[1] != Seen::Gone {
                        served_after_cancel
                            .push(format!("{conn:?} {command:?} got {:?} ({at})", hg_seen[1]));
                    }
                    if hg.p_certificate_cached || gh.p_certificate_cached {
                        leaked.push(format!("{conn:?} {command:?} ({at})"));
                    }
                }

                let why = if hg_seen[0] != gh_seen[1] {
                    Some(format!(
                        "host {h:?} answered {:?} first, {:?} second",
                        hg_seen[0], gh_seen[1]
                    ))
                } else if hg_seen[1] != gh_seen[0] {
                    Some(format!(
                        "guest answered {:?} first, {:?} second",
                        gh_seen[0], hg_seen[1]
                    ))
                } else if hg != gh {
                    Some(format!("records differ: {hg:?} vs {gh:?}"))
                } else {
                    None
                };
                if let Some(why) = why {
                    hollow
                        .entry((h, (conn, command)))
                        .or_insert_with(|| format!("{at}: {why}"));
                }
            }
        }
    }

    eprintln!(
        "cross census: {} host x {} guest letters, {checks} checks from {} states; hollow {}",
        HOST.len(),
        GUEST.len(),
        starts.len(),
        hollow.len()
    );
    for ((h, g), why) in &hollow {
        eprintln!("  hollow  {h:?} ; {g:?}  —  {why}");
    }

    assert!(hung.is_empty(), "a guest letter hung: {hung:?}");
    // Non-vacuity: the barrier assertion ran for the pairs the footprints scope.
    let scoped = HOST
        .iter()
        .flat_map(|h| GUEST.iter().map(move |g| (*h, *g)))
        .filter(|(h, g)| ends_scope_of(*h, *g))
        .count();
    assert!(
        scoped > 0,
        "no host letter ends any guest letter's scope: the barrier checked nothing"
    );
    // Non-vacuity: a guest that is never served makes every face look like a barrier.
    assert!(
        guest_served > 0,
        "the guest was never served: the census measured nothing"
    );
    assert!(
        served_after_cancel.is_empty(),
        "the guest was served after its pod was cancelled: {served_after_cancel:?}"
    );
    assert!(
        leaked.is_empty(),
        "P's certificate is cached after P was cancelled: {leaked:?}"
    );

    let measured: BTreeSet<_> = hollow.keys().copied().collect();
    let declared = declared_hollow();
    let undeclared: Vec<_> = measured.difference(&declared).collect();
    let stale: Vec<_> = declared.difference(&measured).collect();
    assert!(
        undeclared.is_empty() && stale.is_empty(),
        "hollow cross faces the rules do not imply: {undeclared:?}; implied faces that filled: {stale:?}"
    );
}

/// The census runs letters one after another, so it never has a guest acting
/// DURING teardown — which is where the window actually is. Here the guest sends
/// `FETCH_SVID` in a tight loop on its open connection while the host cancels.
/// However the two interleave, `P`'s certificate must not be cached once
/// `cancel_pod` returns, and nothing may be served on the connection after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_fetching_during_cancel_leaves_no_certificate() {
    const TRIALS: usize = 40;
    let mut leaked = 0usize;
    let mut served_after = 0usize;
    let mut served_during = 0usize;
    for _ in 0..TRIALS {
        let mut run = Run::new(false, false).await;
        let (mut r, mut w) = run.open.take().expect("the open connection");
        let done = Arc::new(AtomicBool::new(false));
        let guest_done = Arc::clone(&done);
        let guest = tokio::spawn(async move {
            let (mut before, mut after) = (0usize, 0usize);
            loop {
                let cancelled = guest_done.load(Ordering::SeqCst);
                match exchange(&mut r, &mut w, Command::FetchSvid).await {
                    Ok(line) if !line.contains("\"error\"") => {
                        if cancelled {
                            after += 1;
                        } else {
                            before += 1;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            (before, after)
        });
        // Let the guest get going, so cancel lands mid-stream rather than first.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let _ = cancel_pod(
            State(run.st.clone()),
            Extension(crate::pod_api::Caller::Operator),
            AxumPath(run.p),
        )
        .await;
        done.store(true, Ordering::SeqCst);
        let cached = run
            .manager
            .secret_manager()
            .cached_identities()
            .await
            .contains(&run.identity);
        let (before, after) = tokio::time::timeout(Duration::from_secs(5), guest)
            .await
            .expect("the guest's connection was closed by cancel")
            .expect("guest task");
        leaked += usize::from(cached);
        served_during += before;
        served_after += after;
        let _ = run.finish().await;
    }
    eprintln!(
        "cancel race: {TRIALS} trials, {served_during} SVIDs served before cancel returned, \
         {served_after} after, {leaked} certificates left cached"
    );
    // Non-vacuity: the guest must actually have been fetching when cancel landed.
    assert!(served_during > 0, "the guest never fetched: nothing raced");
    assert_eq!(served_after, 0, "served after cancel returned");
    assert_eq!(leaked, 0, "a cancelled pod's certificate is still cached");
}

/// The drain, specifically. A `FETCH_SVID` served from the cache cannot leak — the
/// certificate is still there until `release_pod` forgets it — so the hammering test
/// above does not need the bridge to WAIT for its connections. A MINT does: with the
/// certificate not cached, a frame already being served when cancel starts is signing
/// a new one, and if shutdown returns before it finishes, `release_pod` forgets
/// nothing and the mint lands afterwards. Here every trial starts uncached and cancel
/// is issued the moment the guest's frame is on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mint_in_flight_at_cancel_is_waited_for() {
    // The leak without the drain lands in ~2% of trials, so 60 would miss it about a
    // quarter of the time; at 300 a miss is ~0.15%. With the drain it is 0, not rare.
    const TRIALS: usize = 300;
    let mut leaked = 0usize;
    let mut minted_during_cancel = 0usize;
    for _ in 0..TRIALS {
        let mut run = Run::new(false, false).await;
        run.manager.forget_certificate(&run.identity).await;
        let (mut r, mut w) = run.open.take().expect("the open connection");
        w.write_all(b"FETCH_SVID\n").await.expect("frame written");
        w.flush().await.expect("frame flushed");
        let _ = cancel_pod(
            State(run.st.clone()),
            Extension(crate::pod_api::Caller::Operator),
            AxumPath(run.p),
        )
        .await;
        let cached = run
            .manager
            .secret_manager()
            .cached_identities()
            .await
            .contains(&run.identity);
        let mut line = String::new();
        let got = tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line))
            .await
            .expect("cancel closed the connection");
        if matches!(got, Ok(n) if n > 0) && !line.contains("\"error\"") {
            minted_during_cancel += 1;
        }
        leaked += usize::from(cached);
        drop(w);
        let _ = run.finish().await;
    }
    eprintln!(
        "mint race: {TRIALS} trials, {minted_during_cancel} mints served during cancel, \
         {leaked} certificates left cached"
    );
    // Non-vacuity: the mint must actually have been in flight when cancel ran.
    assert!(
        minted_during_cancel > 0,
        "no mint was in flight: nothing raced"
    );
    assert_eq!(
        leaked, 0,
        "a mint in flight at cancel left the certificate cached"
    );
}

// ---------------------------------------------------------------------------
// Receipts at teardown: the other half of the barrier.
//
// The barrier says nothing NEW is served once cancel begins. This says what was
// already accepted is still recorded — whole or not at all. The drain in the bridge
// exists for it ("a receipt mid-ship is collected, not truncated"); these are what
// make that sentence a checked claim rather than a comment.
// ---------------------------------------------------------------------------

/// A receipt body that parses as JSON, big enough that a torn write would show.
fn receipt_body(tag: usize) -> String {
    format!(
        r#"{{"schema_version":1,"verdict":"allow","tag":{tag},"pad":"{}"}}"#,
        "x".repeat(2048)
    )
}

/// Every collected line for `P`, and whether each is a whole receipt.
fn collected(run: &Run) -> Vec<Result<serde_json::Value, String>> {
    let path = crate::mediation_receipt_collector::receipt_log_path(&run.receipt_dir);
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).map_err(|_| l.chars().take(80).collect())
        })
        .collect()
}

async fn cancel_p(run: &Run) -> Duration {
    let started = std::time::Instant::now();
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        cancel_pod(
            State(run.st.clone()),
            Extension(crate::pod_api::Caller::Operator),
            AxumPath(run.p),
        ),
    )
    .await;
    assert!(
        r.is_ok(),
        "cancel hung on a guest mid-receipt: the drain has no bound"
    );
    started.elapsed()
}

/// The command frame is read and the body is half-sent when cancel begins; the rest
/// arrives inside the drain window. The receipt must be collected whole and acked,
/// and cancel must have waited for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receipt_mid_ship_at_cancel_is_collected_whole() {
    let mut run = Run::new(false, false).await;
    let (mut r, mut w) = run.open.take().expect("the open connection");
    let body = receipt_body(1);
    let (head, tail) = body.split_at(body.len() / 2);
    w.write_all(b"SHIP_RECEIPT\n").await.expect("command");
    w.write_all(head.as_bytes()).await.expect("half the body");
    w.flush().await.expect("flush");
    // Let the bridge read the command frame and block in the body.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let tail = tail.to_string();
    let guest = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = w.write_all(tail.as_bytes()).await;
        let _ = w.write_all(b"\n").await;
        let _ = w.flush().await;
        let mut line = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line)).await;
        line
    });
    let took = cancel_p(&run).await;
    let reply = guest.await.expect("guest task");

    let lines = collected(&run);
    assert_eq!(
        lines.len(),
        1,
        "exactly the one receipt is collected: {lines:?}"
    );
    assert!(
        matches!(&lines[0], Ok(v) if v.get("tag") == Some(&serde_json::json!(1))),
        "the collected receipt is whole: {lines:?}"
    );
    assert!(
        reply.contains("collected"),
        "the guest was not told its receipt was collected: {reply:?}"
    );
    assert!(
        took >= Duration::from_millis(250),
        "cancel returned in {took:?}, before the receipt it was draining arrived"
    );
    let _ = run.finish().await;
}

/// The guest stalls inside the body and never finishes. Cancel must not wait for it
/// past the bound, nothing may be collected, and no torn line may be left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receipt_stalled_at_cancel_is_dropped_whole_and_cancel_is_bounded() {
    let mut run = Run::new(false, false).await;
    let (mut r, mut w) = run.open.take().expect("the open connection");
    let body = receipt_body(2);
    w.write_all(b"SHIP_RECEIPT\n").await.expect("command");
    w.write_all(&body.as_bytes()[..body.len() / 2])
        .await
        .expect("half the body");
    w.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let took = cancel_p(&run).await;
    assert!(
        took < Duration::from_secs(5),
        "cancel took {took:?} on a stalled guest"
    );
    let mut line = String::new();
    let got = tokio::time::timeout(Duration::from_secs(2), r.read_line(&mut line)).await;
    assert!(
        matches!(got, Ok(Ok(0)) | Ok(Err(_))),
        "the stalled guest's connection is still open after cancel: {got:?} {line:?}"
    );
    let lines = collected(&run);
    assert!(
        lines.is_empty(),
        "a stalled receipt left something behind: {lines:?}"
    );
    drop(w);
    let _ = run.finish().await;
}

/// Receipts shipped on several connections while cancel lands: whatever was
/// collected is whole, every ack names a receipt that was collected, and nothing is
/// collected that was sent after cancel returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receipts_racing_cancel_are_whole_and_every_ack_is_true() {
    const TRIALS: usize = 20;
    const CONNECTIONS: usize = 4;
    let mut collected_during = 0usize;
    for trial in 0..TRIALS {
        let run = Run::new(false, false).await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut guests = Vec::new();
        for c in 0..CONNECTIONS {
            let socket = run.socket.clone();
            let cancelled = Arc::clone(&cancelled);
            guests.push(tokio::spawn(async move {
                let mut acked = Vec::new();
                let mut sent_after = Vec::new();
                let Ok(stream) = UnixStream::connect(&socket).await else {
                    return (acked, sent_after);
                };
                let (r, mut w) = stream.into_split();
                let mut r = BufReader::new(r);
                for i in 0.. {
                    let tag = trial * 1_000_000 + c * 10_000 + i;
                    let after = cancelled.load(Ordering::SeqCst);
                    let frame = format!("SHIP_RECEIPT\n{}\n", receipt_body(tag));
                    if w.write_all(frame.as_bytes()).await.is_err() {
                        break;
                    }
                    if after {
                        sent_after.push(tag);
                    }
                    let mut line = String::new();
                    match tokio::time::timeout(Duration::from_secs(3), r.read_line(&mut line)).await
                    {
                        Ok(Ok(n)) if n > 0 && line.contains("collected") => acked.push(tag),
                        _ => break,
                    }
                }
                (acked, sent_after)
            }));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        let _ = cancel_p(&run).await;
        cancelled.store(true, Ordering::SeqCst);

        let mut acked = BTreeSet::new();
        let mut sent_after = BTreeSet::new();
        for g in guests {
            let (a, s) = tokio::time::timeout(Duration::from_secs(10), g)
                .await
                .expect("a guest outlived cancel")
                .expect("guest task");
            acked.extend(a);
            sent_after.extend(s);
        }
        let lines = collected(&run);
        let torn: Vec<&String> = lines.iter().filter_map(|l| l.as_ref().err()).collect();
        assert!(
            torn.is_empty(),
            "torn receipt lines were collected: {torn:?}"
        );
        let tags: BTreeSet<usize> = lines
            .iter()
            .filter_map(|l| l.as_ref().ok()?.get("tag")?.as_u64())
            .map(|t| usize::try_from(t).expect("tag fits"))
            .collect();
        let lost: Vec<&usize> = acked.difference(&tags).collect();
        assert!(lost.is_empty(), "acked but not collected: {lost:?}");
        let late: Vec<&usize> = sent_after.intersection(&tags).collect();
        assert!(
            late.is_empty(),
            "collected though sent after cancel returned: {late:?}"
        );
        collected_during += tags.len();
        let _ = run.finish().await;
    }
    eprintln!(
        "receipt race: {TRIALS} trials x {CONNECTIONS} connections, {collected_during} receipts collected"
    );
    assert!(
        collected_during > 0,
        "no receipt was shipped: nothing raced"
    );
}
