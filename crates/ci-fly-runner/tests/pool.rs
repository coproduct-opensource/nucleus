//! What the pool does with the world it finds, and the two orderings that lose a job.
//!
//! Every test here is a pass over a fake forge and a fake substrate: the same calls the real ones
//! make, recorded, so what is asserted is what would be sent.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ci_fly_runner::api::{Error, Forge, Registration, Run, Substrate};
use ci_fly_runner::reconcile::{Manager, Settings};
use ci_fly_runner::{
    Action, Demand, Guest, Job, Machine, PoolSpec, Runner, Snapshot, parse_pools, plan,
};
use serde_json::{Value, json};

// ── Fakes ───────────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct FakeForge {
    runs: Vec<Run>,
    jobs: BTreeMap<u64, Vec<Job>>,
    runners: Mutex<Vec<Runner>>,
    next_runner: Mutex<u64>,
    registered: Mutex<Vec<(String, String, u64)>>,
    removed: Mutex<Vec<u64>>,
}

impl Forge for FakeForge {
    fn active_runs(&self, _limit: usize) -> Result<Vec<Run>, Error> {
        Ok(self.runs.clone())
    }
    fn jobs(&self, run: u64) -> Result<Vec<Job>, Error> {
        Ok(self.jobs.get(&run).cloned().unwrap_or_default())
    }
    fn runners(&self) -> Result<Vec<Runner>, Error> {
        Ok(self.runners.lock().unwrap().clone())
    }
    fn register(&self, label: &str, name: &str) -> Result<Registration, Error> {
        let mut next = self.next_runner.lock().unwrap();
        *next += 1;
        self.registered
            .lock()
            .unwrap()
            .push((label.to_string(), name.to_string(), *next));
        Ok(Registration {
            id: *next,
            encoded: format!("JIT-{next}"),
        })
    }
    fn remove_runner(&self, id: u64) -> Result<(), Error> {
        self.removed.lock().unwrap().push(id);
        self.runners.lock().unwrap().retain(|r| r.id != id);
        Ok(())
    }
}

#[derive(Default)]
struct FakeSubstrate {
    machines: Mutex<Vec<Machine>>,
    created: Mutex<Vec<(String, Value)>>,
    updated: Mutex<Vec<(String, Value)>>,
    started: Mutex<Vec<String>>,
    waited: Mutex<Vec<(String, String)>>,
    destroyed: Mutex<Vec<String>>,
    start_fails: bool,
    /// The substrate answers every config rewrite "at capacity", as Fly does when the
    /// organization is at its machine cap.
    at_capacity: bool,
    /// How long the substrate takes to settle after a configuration rewrite.
    settle: std::time::Duration,
}

impl Substrate for FakeSubstrate {
    fn machines(&self) -> Result<Vec<Machine>, Error> {
        Ok(self.machines.lock().unwrap().clone())
    }
    fn create(&self, name: &str, _region: &str, config: &Value) -> Result<Machine, Error> {
        self.created
            .lock()
            .unwrap()
            .push((name.to_string(), config.clone()));
        let machine = machine(&format!("id-{name}"), name, "created", config.clone(), 0);
        self.machines.lock().unwrap().push(machine.clone());
        Ok(machine)
    }
    fn update(&self, id: &str, config: &Value) -> Result<(), Error> {
        if self.at_capacity {
            return Err(Error::Status {
                method: "POST",
                path: "/apps/a/machines/x".into(),
                code: 422,
            });
        }
        self.updated
            .lock()
            .unwrap()
            .push((id.to_string(), config.clone()));
        Ok(())
    }
    fn wait_for(&self, id: &str, state: &str, _timeout_s: u64) -> Result<(), Error> {
        std::thread::sleep(self.settle);
        self.waited
            .lock()
            .unwrap()
            .push((id.to_string(), state.to_string()));
        Ok(())
    }
    fn start(&self, id: &str) -> Result<(), Error> {
        if self.start_fails {
            return Err(Error::Status {
                method: "POST",
                path: "/apps/a/machines/x/start".into(),
                code: 500,
            });
        }
        self.started.lock().unwrap().push(id.to_string());
        Ok(())
    }
    fn destroy(&self, id: &str) -> Result<(), Error> {
        self.destroyed.lock().unwrap().push(id.to_string());
        Ok(())
    }
}

// ── Builders ────────────────────────────────────────────────────────────────────────────────

fn pool(label: &str, size: usize, standby: usize) -> PoolSpec {
    PoolSpec {
        label: label.into(),
        guest: Guest {
            cpu_kind: "shared".into(),
            cpus: 2,
            memory_mb: 4096,
        },
        size,
        standby,
        volumes: vec![],
        env: BTreeMap::new(),
        requires_volume: false,
    }
}

fn machine(id: &str, name: &str, state: &str, config: Value, stopped_ms_ago: i64) -> Machine {
    let mut config = config;
    if config.get("metadata").is_none() {
        config["metadata"] = json!({"managed_by": "nucleus-fly-runner"});
    }
    let events = if stopped_ms_ago > 0 {
        json!([{"type": "exit", "status": "stopped", "timestamp": NOW_MS - stopped_ms_ago}])
    } else {
        json!([])
    };
    serde_json::from_value(json!({
        "id": id, "name": name, "state": state, "config": config, "events": events,
    }))
    .unwrap()
}

const NOW: u64 = 1_800_000_000;
const NOW_MS: i64 = 1_800_000_000_000;

fn pooled(label: &str, index: usize, state: &str, stopped_secs_ago: i64) -> Machine {
    machine(
        &format!("id-{label}-{index}"),
        &format!("{label}-{index}"),
        state,
        json!({"metadata": {"managed_by": "nucleus-fly-runner", "pool": label, "index": index.to_string()}}),
        stopped_secs_ago * 1000,
    )
}

fn runner(id: u64, name: &str, status: &str, busy: bool) -> Runner {
    serde_json::from_value(json!({"id": id, "name": name, "status": status, "busy": busy})).unwrap()
}

fn snapshot(machines: Vec<Machine>, runners: Vec<Runner>, demand: &[(&str, usize)]) -> Snapshot {
    Snapshot {
        machines,
        runners,
        demand: Demand(
            demand
                .iter()
                .map(|(l, n)| ((*l).to_string(), *n))
                .collect::<BTreeMap<_, _>>(),
        ),
        issued: BTreeMap::new(),
        warming_limit: 4,
        shrink_by: 0,
        now_secs: NOW,
        idle_secs: 1800,
    }
}

// ── Configuration ───────────────────────────────────────────────────────────────────────────

#[test]
fn pools_are_validated() {
    let good = r#"[{"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4096},
                    "size":2,"standby":1,"volumes":["a","b"]}]"#;
    assert_eq!(parse_pools(good).unwrap().len(), 1);

    for (bad, why) in [
        ("[]", "empty"),
        (
            r#"[{"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4},"size":2,"standby":3}]"#,
            "standby above size",
        ),
        (
            r#"[{"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4},"size":1,"standby":1,"volumes":["a","b"]}]"#,
            "more volumes than machines",
        ),
        (
            r#"[{"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4},"size":2,"standby":1,"volumes":["a","a"]}]"#,
            "the same volume twice",
        ),
        (
            r#"[{"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4},"size":1,"standby":0},
                {"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4},"size":1,"standby":0}]"#,
            "two pools with one label",
        ),
        (
            r#"[{"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4},"size":1}]"#,
            "no standby",
        ),
        (
            r#"[{"label":"p","guest":{"cpu_kind":"shared","cpus":2,"memory_mb":4},"size":1,"standby":0,"stanby":2}]"#,
            "a misspelled key",
        ),
    ] {
        assert!(parse_pools(bad).is_err(), "accepted {why}: {bad}");
    }
}

// ── Demand ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn queued_jobs_with_a_pool_label_count_whatever_the_event_and_only_once() {
    let forge = FakeForge {
        runs: vec![
            Run {
                id: 1,
                created_at: "2026-09-09T01:00:00Z".into(),
            },
            Run {
                id: 2,
                created_at: "2026-09-09T02:00:00Z".into(),
            },
        ],
        jobs: BTreeMap::from([
            (
                1,
                vec![
                    job(10, "queued", &["self-hosted", "build"]),
                    job(11, "in_progress", &["build"]),
                    job(12, "queued", &["ubuntu-latest"]),
                ],
            ),
            (
                2,
                vec![job(13, "queued", &["build"]), job(10, "queued", &["build"])],
            ),
        ]),
        ..FakeForge::default()
    };
    let manager = Manager::new(
        forge,
        FakeSubstrate::default(),
        vec![pool("build", 2, 0), pool("gate", 2, 0)],
        Settings {
            image: "img@sha256:aa".into(),
            ..Settings::default()
        },
    );
    let demand = manager.demand().unwrap();
    // 10 and 13 queued; 11 is running, 12 is another label, and 10 seen twice is one job.
    assert_eq!(demand.get("build"), 2);
    assert_eq!(demand.get("gate"), 0);
}

fn job(id: u64, status: &str, labels: &[&str]) -> Job {
    serde_json::from_value(json!({"id": id, "status": status, "labels": labels})).unwrap()
}

// ── Planning ────────────────────────────────────────────────────────────────────────────────

#[test]
fn demand_starts_stopped_machines_before_creating_new_ones() {
    let actions = plan(
        &[pool("build", 4, 0)],
        &snapshot(
            vec![pooled("build", 0, "stopped", 60)],
            vec![],
            &[("build", 2)],
        ),
    );
    assert_eq!(
        actions,
        vec![
            Action::Launch {
                pool: "build".into(),
                id: "id-build-0".into(),
                name: "build-0".into()
            },
            Action::Create {
                pool: "build".into(),
                index: 1
            },
        ]
    );
}

#[test]
fn the_pool_never_exceeds_its_size() {
    let actions = plan(
        &[pool("build", 2, 0)],
        &snapshot(vec![], vec![], &[("build", 9)]),
    );
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, Action::Create { .. }))
            .count(),
        2
    );
}

#[test]
fn a_live_machine_and_an_idle_registered_runner_each_cover_one_queued_job() {
    let actions = plan(
        &[pool("build", 4, 0)],
        &snapshot(
            vec![
                pooled("build", 0, "started", 0),
                pooled("build", 1, "stopped", 60),
            ],
            vec![runner(7, "build-2-123", "online", false)],
            &[("build", 2)],
        ),
    );
    // One job is covered by the started machine, the other by the idle runner: nothing to do.
    assert_eq!(actions, vec![]);
}

#[test]
fn standby_is_warmed_without_demand_and_surplus_idle_machines_retire() {
    let actions = plan(
        &[pool("gate", 4, 1)],
        &snapshot(vec![], vec![], &[("gate", 0)]),
    );
    assert_eq!(
        actions,
        vec![Action::Create {
            pool: "gate".into(),
            index: 0
        }]
    );

    let retiring = plan(
        &[pool("gate", 4, 1)],
        &snapshot(
            vec![
                pooled("gate", 0, "stopped", 60),   // young: kept
                pooled("gate", 1, "stopped", 4000), // old and surplus: retired
                pooled("gate", 2, "stopped", 5000), // old and surplus: retired
            ],
            vec![],
            &[("gate", 0)],
        ),
    );
    assert_eq!(
        retiring,
        vec![
            Action::Retire {
                pool: "gate".into(),
                id: "id-gate-2".into(),
                name: "gate-2".into()
            },
            Action::Retire {
                pool: "gate".into(),
                id: "id-gate-1".into(),
                name: "gate-1".into()
            },
        ]
    );
}

/// The first ordering that loses a job. Every machine has been stopped past the idle period —
/// which is what "the pool has been quiet since last night" looks like — and demand arrives. A
/// loop that launches against a machine list and then retires against the same list destroys the
/// machine it has just handed a registration to.
#[test]
fn a_machine_launched_this_pass_is_never_also_retired() {
    let idle_all_night = vec![
        pooled("build", 0, "stopped", 40_000),
        pooled("build", 1, "stopped", 39_000),
        pooled("build", 2, "stopped", 38_000),
        pooled("build", 3, "stopped", 37_000),
    ];
    let actions = plan(
        &[pool("build", 4, 2)],
        &snapshot(idle_all_night, vec![], &[("build", 2)]),
    );
    let launched: Vec<&String> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Launch { id, .. } => Some(id),
            _ => None,
        })
        .collect();
    let retired: Vec<&String> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Retire { id, .. } => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(launched.len(), 2, "{actions:?}");
    for id in &launched {
        assert!(
            !retired.contains(id),
            "{id} was launched and retired: {actions:?}"
        );
    }
    // The two that were not launched are exactly standby, so nothing is surplus.
    assert!(retired.is_empty(), "{actions:?}");
}

/// The second ordering that loses a job. A registration is `offline` from the moment it is
/// created until its guest boots and connects — seconds — and the reap runs in the same pass that
/// created it. A rule that reads "offline and not busy" as orphaned deletes every registration it
/// issues, and no job ever runs.
#[test]
fn a_registration_whose_machine_is_coming_up_is_not_an_orphan() {
    let mut booting = pooled("build", 0, "starting", 0);
    booting.config["metadata"]["github_runner_id"] = json!("77");
    let mut state = snapshot(
        vec![booting],
        vec![runner(77, "build-0-1800000000", "offline", false)],
        &[("build", 0)],
    );
    state.issued.insert(77, NOW - 5);
    assert_eq!(plan(&[pool("build", 4, 0)], &state), vec![]);
}

#[test]
fn a_registration_this_manager_never_issued_or_long_past_its_grace_is_removed() {
    // Its machine is stopped: the boot happened, or never will, and the registration is stale.
    let mut state = snapshot(
        vec![pooled("build", 0, "stopped", 60)],
        vec![
            runner(77, "build-0-1", "offline", false),
            runner(78, "build-1-1", "offline", true), // busy: never touched
            runner(79, "other-0-1", "offline", false), // not ours
        ],
        &[("build", 0)],
    );
    state.issued.insert(77, NOW - 10_000);
    let actions = plan(&[pool("build", 4, 1)], &state);
    assert_eq!(
        actions,
        vec![Action::RemoveRunner {
            id: 77,
            name: "build-0-1".into()
        }]
    );
}

#[test]
fn a_machine_the_manager_does_not_own_is_never_touched() {
    let stranger = machine(
        "id-x",
        "build-0",
        "stopped",
        json!({"metadata": {"pool": "build"}}),
        60_000,
    );
    assert!(!stranger.is_managed());
}

// ── Applying ────────────────────────────────────────────────────────────────────────────────

fn manager(
    forge: FakeForge,
    substrate: FakeSubstrate,
    pools: Vec<PoolSpec>,
) -> Manager<FakeForge, FakeSubstrate> {
    Manager::new(
        forge,
        substrate,
        pools,
        Settings {
            image: "registry.invalid/runner@sha256:aa".into(),
            ..Settings::default()
        },
    )
}

fn one_queued(label: &str) -> FakeForge {
    FakeForge {
        runs: vec![Run {
            id: 1,
            created_at: "2026-09-09T01:00:00Z".into(),
        }],
        jobs: BTreeMap::from([(1, vec![job(10, "queued", &[label])])]),
        ..FakeForge::default()
    }
}

#[test]
fn a_launch_writes_one_job_configuration_and_starts_the_machine() {
    let substrate = FakeSubstrate {
        machines: Mutex::new(vec![pooled("build", 0, "stopped", 60)]),
        ..FakeSubstrate::default()
    };
    let m = manager(one_queued("build"), substrate, vec![pool("build", 4, 0)]);
    let report = m.tick(NOW).unwrap();
    assert_eq!(report.launched, 1);
    assert!(report.failures.is_empty(), "{:?}", report.failures);

    let updated = m.substrate.updated.lock().unwrap();
    let (id, config) = updated.first().expect("the machine was reconfigured");
    assert_eq!(id, "id-build-0");
    assert_eq!(config["files"][0]["guest_path"], "/run/runner-jit");
    assert_eq!(config["metadata"]["github_runner_id"], "1");
    // The registration is the only credential the worker is handed.
    let rendered = config.to_string();
    assert!(!rendered.contains("GITHUB_TOKEN") && !rendered.contains("FLY_API_TOKEN"));
    assert_eq!(
        *m.substrate.started.lock().unwrap(),
        vec!["id-build-0".to_string()]
    );
    // And the manager knows it issued it, so the next pass does not reap it.
    assert_eq!(m.ledger().get(&1), Some(&NOW));
}

#[test]
fn a_created_machine_is_created_unbooted_with_the_volume_of_its_index_and_booted_later() {
    let mut spec = pool("build", 2, 0);
    spec.volumes = vec!["vol_a".into(), "vol_b".into()];
    let m = manager(one_queued("build"), FakeSubstrate::default(), vec![spec]);
    let report = m.tick(NOW).unwrap();
    assert_eq!(report.created, 1);
    let created = m.substrate.created.lock().unwrap();
    let (name, config) = created.first().unwrap();
    assert_eq!(name, "build-0");
    assert_eq!(config["mounts"][0]["volume"], "vol_a");
    assert_eq!(config["image"], "registry.invalid/runner@sha256:aa");
    // Not started in the pass that created it: that start races the machine's placement, and the
    // substrate answers 412 — which is exactly how six machines were left unbootable on the first
    // live run. Nothing is registered for it either.
    assert!(m.substrate.started.lock().unwrap().is_empty());
    assert!(m.substrate.updated.lock().unwrap().is_empty());
    assert!(m.forge.registered.lock().unwrap().is_empty());
    drop(created);

    // The next pass boots it. The job is still queued, so it boots WITH the registration — a
    // cold boot that takes the job, pulling the image on the way — rather than warming first and
    // making the job wait two passes. (Warming a cold machine there is no demand for is the
    // other test.)
    let report = m.tick(NOW + 20).unwrap();
    assert_eq!(report.launched, 1);
    assert_eq!(
        *m.substrate.started.lock().unwrap(),
        vec!["id-build-0".to_string()]
    );
    assert_eq!(m.forge.registered.lock().unwrap().len(), 1);
}

/// A machine that has never booted covers no queued job, and a planner that reads it as live
/// leaves it in `created` for good — which is what happened on the first live pass.
/// A pool may hold fewer volumes than machines: the ones with a volume get a disk for the build
/// directory, the rest run on the root filesystem. Requiring one volume each is what pinned the
/// build pool to eight while gate machines idled.
#[test]
fn a_pool_may_have_fewer_volumes_than_machines_and_the_rest_mount_nothing() {
    let pools = parse_pools(
        r#"[{"label":"build","guest":{"cpu_kind":"performance","cpus":8,"memory_mb":32768},
             "size":4,"standby":4,"volumes":["vol_a","vol_b"]}]"#,
    )
    .unwrap();
    let p = &pools[0];
    assert_eq!(
        p.base_config("i@sha256:a", 0)["mounts"][0]["volume"],
        "vol_a"
    );
    assert_eq!(
        p.base_config("i@sha256:a", 1)["mounts"][0]["volume"],
        "vol_b"
    );
    assert!(p.base_config("i@sha256:a", 2).get("mounts").is_none());
    assert!(p.base_config("i@sha256:a", 3).get("mounts").is_none());
}

/// A pool that compiles must not hold a machine without a volume: the root filesystem is about
/// 8 GB TOTAL on this substrate, `cargo test --all-features` fills it, and the failure is a
/// linker bus error and `ENOSPC` on four required checks — which ejects the merge-queue entry.
#[test]
fn a_pool_that_requires_volumes_may_not_outnumber_them() {
    let bad = r#"[{"label":"build","guest":{"cpu_kind":"performance","cpus":8,"memory_mb":32768},
                   "size":12,"standby":12,"volumes":["a","b"],"requires_volume":true}]"#;
    assert!(
        parse_pools(bad).is_err(),
        "accepted a compiling pool with 2 volumes for 12 machines"
    );

    let ok = r#"[{"label":"build","guest":{"cpu_kind":"performance","cpus":8,"memory_mb":32768},
                  "size":2,"standby":2,"volumes":["a","b"],"requires_volume":true}]"#;
    assert!(parse_pools(ok).is_ok());

    // A pool that does not compile may still run on the root filesystem alone.
    let gate = r#"[{"label":"gate","guest":{"cpu_kind":"shared","cpus":8,"memory_mb":16384},
                    "size":24,"standby":24}]"#;
    assert!(parse_pools(gate).is_ok());
}

#[test]
fn a_never_booted_machine_is_startable_not_live() {
    let cold = pooled("build", 0, "created", 0);
    assert!(cold.is_cold() && !cold.is_live() && !cold.is_warm());

    let actions = plan(
        &[pool("build", 4, 0)],
        &snapshot(vec![cold], vec![], &[("build", 1)]),
    );
    // It takes the job itself rather than being ignored while a second machine is created.
    assert_eq!(
        actions,
        vec![Action::Launch {
            pool: "build".into(),
            id: "id-build-0".into(),
            name: "build-0".into()
        }]
    );
}

#[test]
fn a_warm_machine_is_preferred_over_a_cold_one_and_the_cold_one_is_booted_anyway() {
    let actions = plan(
        &[pool("build", 4, 0)],
        &snapshot(
            vec![
                pooled("build", 0, "created", 0),
                pooled("build", 1, "stopped", 60),
            ],
            vec![],
            &[("build", 1)],
        ),
    );
    assert_eq!(
        actions,
        vec![
            // The warm one takes the job: a start is a second, a cold boot is an image pull.
            Action::Launch {
                pool: "build".into(),
                id: "id-build-1".into(),
                name: "build-1".into()
            },
            // And the cold one is booted once so it is warm for the next job.
            Action::Warm {
                pool: "build".into(),
                id: "id-build-0".into(),
                name: "build-0".into()
            },
        ]
    );
}

#[test]
fn a_failed_start_removes_the_registration_it_had_issued() {
    let substrate = FakeSubstrate {
        machines: Mutex::new(vec![pooled("build", 0, "stopped", 60)]),
        start_fails: true,
        ..FakeSubstrate::default()
    };
    let m = manager(one_queued("build"), substrate, vec![pool("build", 4, 0)]);
    let report = m.tick(NOW).unwrap();
    assert_eq!(report.launched, 0);
    assert_eq!(report.failures.len(), 1);
    // Otherwise an idle registered runner would be counted as covering the job forever.
    assert_eq!(*m.forge.removed.lock().unwrap(), vec![1]);
    assert!(m.ledger().is_empty());
}

/// Launching is a registration plus three substrate calls plus the settle wait, and the settle
/// wait alone is seconds. Serialized, a burst of launches spends more time waiting its turn than
/// booting — which is most of the queue time the profile showed. They are independent, and the
/// planner already guarantees one action per machine, so they run at once.
#[test]
fn launches_in_one_pass_do_not_wait_for_each_other() {
    let slow = FakeSubstrate {
        machines: Mutex::new(
            (0..8)
                .map(|i| pooled("build", i, "stopped", 60))
                .collect::<Vec<_>>(),
        ),
        settle: std::time::Duration::from_millis(300),
        ..FakeSubstrate::default()
    };
    let forge = FakeForge {
        runs: vec![Run {
            id: 1,
            created_at: "2026-09-09T01:00:00Z".into(),
        }],
        jobs: BTreeMap::from([(
            1,
            (0..8)
                .map(|i| job(10 + i, "queued", &["build"]))
                .collect::<Vec<_>>(),
        )]),
        ..FakeForge::default()
    };
    let m = manager(forge, slow, vec![pool("build", 8, 0)]);
    let started = std::time::Instant::now();
    let report = m.tick(NOW).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(report.launched, 8, "{:?}", report.failures);
    // Serialized that is 2.4s; concurrent it is one settle plus overhead. The bound is loose on
    // purpose — what is being pinned is "not eight times one wait", not a wall-clock figure.
    assert!(
        elapsed < std::time::Duration::from_millis(1200),
        "eight launches took {elapsed:?}: they are serialized"
    );
}

/// The deadlock this exists to break. A pool sized to the organization's machine cap cannot start
/// anything: writing a boot's registration is an update, an update needs a free slot, so every
/// launch is refused — and because no job is taken, no machine ever stops, so nothing frees a
/// slot. The refusal is the live path refuting the declared budget, so the pool gives a machine
/// back at once, ignoring `standby` and the idle period, and stops creating until it has.
#[test]
fn a_substrate_at_capacity_makes_the_pool_give_a_machine_back() {
    let full = FakeSubstrate {
        machines: Mutex::new(vec![
            pooled("build", 0, "stopped", 30),
            pooled("build", 1, "stopped", 60),
        ]),
        at_capacity: true,
        ..FakeSubstrate::default()
    };
    let m = manager(one_queued("build"), full, vec![pool("build", 4, 2)]);

    // Pass one: the launch is refused, and the manager records what the substrate would not give.
    let report = m.tick(NOW).unwrap();
    assert_eq!(report.launched, 0);
    assert_eq!(
        m.shrink_owed(),
        1,
        "the refusal was not recognised as capacity"
    );
    assert!(m.substrate.destroyed.lock().unwrap().is_empty());

    // Pass two: a machine is given back even though both are inside `standby` and neither has
    // been idle anywhere near the retirement period — and nothing is created to take the slot.
    let report = m.tick(NOW + 30).unwrap();
    assert_eq!(report.retired, 1, "no machine was given back: {report:?}");
    assert_eq!(report.created, 0, "created a machine while at capacity");
    assert_eq!(
        *m.substrate.destroyed.lock().unwrap(),
        vec!["id-build-1".to_string()],
        "the longest-idle machine is the one given back"
    );
    assert_eq!(m.shrink_owed(), 0);
}

/// The pool holds machines above a pool's declared size whenever a size is lowered — they are
/// retired on the idle period, not at once — so checking the DECLARED size at startup does not
/// keep the organization under its machine cap. A pass counts what it can actually see, and
/// gives the excess back before it asks for anything.
#[test]
fn a_pass_over_the_machine_budget_gives_machines_back_before_asking_for_any() {
    let over = FakeSubstrate {
        machines: Mutex::new(
            (0..6i64)
                .map(|i| pooled("build", usize::try_from(i).unwrap(), "stopped", 30 + i))
                .collect::<Vec<_>>(),
        ),
        ..FakeSubstrate::default()
    };
    let m = Manager::new(
        one_queued("build"),
        over,
        vec![pool("build", 8, 8)],
        Settings {
            image: "i@sha256:a".into(),
            launch_concurrency: 2,
            // 6 held + 2 in flight + 3 elsewhere + 1 manager = 12, against 10.
            machine_budget: Some(10),
            machines_elsewhere: 3,
            ..Settings::default()
        },
    );
    let report = m.tick(NOW).unwrap();
    assert_eq!(
        report.retired, 2,
        "did not give the excess back: {report:?}"
    );
    assert_eq!(report.created, 0, "created while over the budget");
    assert_eq!(m.shrink_owed(), 0);
}

#[test]
fn a_pass_that_cannot_read_the_world_changes_nothing() {
    struct Broken;
    impl Forge for Broken {
        fn active_runs(&self, _: usize) -> Result<Vec<Run>, Error> {
            Err(Error::Unreachable {
                path: "/repos/o/r/actions/runs".into(),
                cause: "connection reset".into(),
            })
        }
        fn jobs(&self, _: u64) -> Result<Vec<Job>, Error> {
            unreachable!()
        }
        fn runners(&self) -> Result<Vec<Runner>, Error> {
            unreachable!()
        }
        fn register(&self, _: &str, _: &str) -> Result<Registration, Error> {
            unreachable!()
        }
        fn remove_runner(&self, _: u64) -> Result<(), Error> {
            unreachable!()
        }
    }
    let m = Manager::new(
        Broken,
        FakeSubstrate::default(),
        vec![pool("build", 4, 1)],
        Settings {
            image: "i@sha256:a".into(),
            ..Settings::default()
        },
    );
    assert!(m.tick(NOW).is_err());
    assert!(m.substrate.created.lock().unwrap().is_empty());
    assert!(m.substrate.destroyed.lock().unwrap().is_empty());
}

/// Every boot pulls the whole rootfs over one shared uplink. Rolling the fleet onto a 2.5 GB image
/// put 21 machines in `starting` at once with zero unpack failures — six minutes of stampede, not
/// a fault. A pass may only put so many machines on the wire, and machines already pulling count.
#[test]
fn only_so_many_machines_may_pull_an_image_at_once() {
    let cold: Vec<_> = (0..10).map(|i| pooled("gate", i, "created", 0)).collect();

    let warming = plan(
        &[pool("gate", 10, 10)],
        &Snapshot {
            warming_limit: 3,
            ..snapshot(cold.clone(), vec![], &[("gate", 0)])
        },
    );
    assert_eq!(
        warming.len(),
        3,
        "ten cold machines, a limit of three: {warming:#?}"
    );
    assert!(warming.iter().all(|a| matches!(a, Action::Warm { .. })));

    // Two are already on the wire, so this pass may only put one more there.
    let mut mixed = cold.clone();
    mixed[0] = pooled("gate", 0, "starting", 0);
    mixed[1] = pooled("gate", 1, "starting", 0);
    let alongside = plan(
        &[pool("gate", 10, 10)],
        &Snapshot {
            warming_limit: 3,
            ..snapshot(mixed, vec![], &[("gate", 0)])
        },
    );
    assert_eq!(
        alongside.len(),
        1,
        "two already pulling against a limit of three: {alongside:#?}"
    );
}

/// **The pool's occupancy, reported because the log is not a history.**
///
/// `ci/fly-runner/README.md` says this manager's log shows every start, warm-up and retirement,
/// and it does — but `fly logs` is a TAIL. It keeps the recent past, its lines carry no timestamp
/// of their own, and its per-machine lines say what the manager DID rather than what the pool
/// WAS. A plan to answer "why does a pool of sixteen deliver two concurrent jobs" by parsing that
/// log would have built a brittle reader of an unversioned format over a window already gone.
///
/// The manager reads the whole machine list every pass anyway, to plan over it. The census is
/// that same observation carried out — taken from the snapshot the pass PLANNED over, so the
/// numbers and the decisions they explain cannot disagree.
#[test]
fn every_pass_reports_the_state_the_substrate_had_every_machine_in() {
    let substrate = FakeSubstrate {
        machines: Mutex::new(vec![
            pooled("build", 0, "stopped", 60),
            pooled("build", 1, "stopped", 60),
            pooled("build", 2, "stopped", 60),
        ]),
        ..FakeSubstrate::default()
    };
    let m = manager(one_queued("build"), substrate, vec![pool("build", 4, 0)]);
    let report = m.tick(NOW).unwrap();

    let mut seen: Vec<(String, String)> = report
        .workers
        .iter()
        .map(|w| (w.machine.clone(), w.state.clone()))
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("id-build-0".to_string(), "stopped".to_string()),
            ("id-build-1".to_string(), "stopped".to_string()),
            ("id-build-2".to_string(), "stopped".to_string()),
        ],
        "one row per managed machine, in the substrate's own words"
    );
    assert!(
        report.workers.iter().all(|w| w.pool == "build"),
        "and each says which pool it answers for: {:?}",
        report.workers
    );
    // The census is of the world the pass PLANNED over, so it does NOT show the effect of the
    // pass's own launch: `id-build-0` is still `stopped` here and started by the time the pass
    // returns. That is deliberate — a census read afterwards would be a second observation of
    // the substrate, and nothing could line it up against what this pass decided.
    assert_eq!(
        *m.substrate.started.lock().unwrap(),
        vec!["id-build-0".to_string()],
        "the pass started a machine the census still calls stopped"
    );
    assert_eq!(report.workers.len(), 3);
}

/// **Fly's own state strings, unmapped — added because the test above did not hold this.**
/// That fleet is all `stopped`, so renaming `started` to `busy` in the census changed nothing
/// and the claim was carried by a comment. A pool with a machine the substrate calls `started`
/// is the case, and it is the whole question: why is a pool whose machines are STARTED not
/// running jobs? Mapping the word here would put this manager's vocabulary between a reader and
/// the API that decides.
#[test]
fn the_census_uses_the_substrates_word_for_a_state_and_never_its_own() {
    let substrate = FakeSubstrate {
        machines: Mutex::new(vec![
            pooled("build", 0, "started", 60),
            pooled("build", 1, "starting", 60),
            pooled("build", 2, "stopped", 60),
        ]),
        ..FakeSubstrate::default()
    };
    let m = manager(FakeForge::default(), substrate, vec![pool("build", 4, 0)]);
    let mut states: Vec<String> = m
        .tick(NOW)
        .unwrap()
        .workers
        .iter()
        .map(|w| w.state.clone())
        .collect();
    states.sort();
    assert_eq!(states, vec!["started", "starting", "stopped"]);
}
