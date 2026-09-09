//! A warm, bounded pool of microVMs that run this repository's CI jobs.
//!
//! Why a pool and not one machine per job: a machine that finished a job and STOPPED keeps its
//! root filesystem on its host, so starting it again takes about a second and pulls nothing.
//! Creating a machine pulls the image every time (tens of seconds for a Rust image) and, for a
//! build worker, would separate the job from its cache volume. So every pool is a fixed set of
//! machines that cycle stopped → started → stopped, one job per start, a fresh one-job JIT
//! runner registration written into the machine before each start.
//!
//! Administrative credentials (a forge token that can register runners, a substrate token for
//! the worker app) live in the manager and never in a worker: a worker receives exactly one JIT
//! registration, good for one job, and nothing else.
//!
//! The shape here is a **pure planner over a snapshot** ([`plan`]) and an apply pass that is the
//! only thing making calls. That is not decoration: the two ways a reconciler like this loses a
//! job are both ordering bugs that a planner cannot express —
//!
//! * retiring a machine that this same pass just handed a job to (the machine list is a
//!   snapshot; a `launch` does not mutate it), and
//! * reaping a registration this same pass just created, because a runner is `offline` until its
//!   guest boots and connects.
//!
//! [`plan`] emits at most one action per machine and never retires a machine it launched, and an
//! orphan is defined against the machines that claim it and an issuance ledger, so neither is
//! reachable. Both are pinned by tests.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{Value, json};

pub mod api;
pub mod reconcile;

/// Written into every machine this manager owns, so a machine created by hand in the same app is
/// never touched.
pub const MANAGED_BY: &str = "nucleus-fly-runner";

/// Where a boot's one-job runner registration is written before the machine is started. A boot
/// that does not find one is a warm-up: it exits at once, image now cached on that host.
pub const JIT_PATH: &str = "/run/runner-jit";

/// How long a registration this manager issued is left alone before it can be read as orphaned.
/// A JIT runner is `offline` from the moment it is registered until its guest boots and connects,
/// which is seconds — and the reap runs in the same pass that issued it.
pub const ORPHAN_GRACE_SECS: u64 = 300;

/// Machine states in which a machine is running, or about to run, its job: it covers a queued job
/// and it is not a candidate to be started or retired.
///
/// `created` is deliberately NOT here. A machine created with `skip_launch` has never booted: it
/// covers nothing, and a planner that reads it as live never touches it again — six machines sat
/// in `created` forever the first time this ran against the real API.
pub const LIVE_STATES: [&str; 4] = ["starting", "started", "stopping", "replacing"];

/// A machine that has never booted. It is startable, like a stopped one, but its image is not on
/// its host yet, so a job that takes it waits for the pull: warm machines are used first.
pub const NEVER_BOOTED: &str = "created";

// ── Configuration ───────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    pub cpu_kind: String,
    pub cpus: u32,
    pub memory_mb: u32,
}

/// One pool: a label jobs are routed to, and the fixed set of machines that serve it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolSpec {
    /// The `runs-on` label, and the prefix of every machine and runner name in the pool.
    pub label: String,
    pub guest: Guest,
    /// How many machines the pool holds at most. Nothing autoscales past it.
    pub size: usize,
    /// How many stopped-and-warm machines to keep regardless of demand; the rest are destroyed
    /// after the idle period and re-created when demand returns.
    pub standby: usize,
    /// Volume ids, mounted at `/data`, assigned to machine indexes in order. FEWER than `size` is
    /// allowed and is the normal state: on Fly a machine's root filesystem is its only disk and is
    /// capped at 8 GB, so a volume is what gives a compile job room — but a volume is also the
    /// only thing in this pool that costs money while idle ($0.15/GB-month), and pinning `size` to
    /// the volume count is what left sixteen idle gate machines next to forty-seven queued build
    /// jobs. Machines past the end of this list run on the root filesystem alone.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Extra environment for the worker (e.g. the build job count).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Parse and validate the pool set. Every rejection here is a configuration mistake that would
/// otherwise show up as a lost job hours later.
pub fn parse_pools(source: &str) -> Result<Vec<PoolSpec>, String> {
    let pools: Vec<PoolSpec> =
        serde_json::from_str(source).map_err(|e| format!("POOLS is not a pool list: {e}"))?;
    if pools.is_empty() {
        return Err("POOLS is empty".into());
    }
    let mut labels = BTreeSet::new();
    for pool in &pools {
        if pool.label.is_empty() {
            return Err("a pool has an empty label".into());
        }
        if !labels.insert(pool.label.as_str()) {
            return Err(format!("{}: pool labels must be distinct", pool.label));
        }
        if pool.size == 0 {
            return Err(format!("{}: size must be at least 1", pool.label));
        }
        if pool.standby > pool.size {
            return Err(format!("{}: standby must be within 0..size", pool.label));
        }
        if pool.volumes.len() > pool.size {
            return Err(format!(
                "{}: {} volumes for {} machines — the extra ones would never be mounted",
                pool.label,
                pool.volumes.len(),
                pool.size
            ));
        }
        let distinct: BTreeSet<&String> = pool.volumes.iter().collect();
        if distinct.len() != pool.volumes.len() {
            return Err(format!("{}: volumes must be distinct", pool.label));
        }
    }
    Ok(pools)
}

impl PoolSpec {
    pub fn machine_name(&self, index: usize) -> String {
        format!("{}-{index}", self.label)
    }

    /// The machine configuration for one index: image, guest, this pool's environment, and the
    /// cache volume this index owns. `restart: no` is what makes one boot one job — the runner
    /// exits after its job and the machine stops instead of coming back up.
    pub fn base_config(&self, image: &str, index: usize) -> Value {
        let mut config = json!({
            "image": image,
            "guest": {
                "cpu_kind": self.guest.cpu_kind,
                "cpus": self.guest.cpus,
                "memory_mb": self.guest.memory_mb,
            },
            "env": self.env,
            "init": {},
            "restart": {"policy": "no"},
            "auto_destroy": false,
            "metadata": {
                "managed_by": MANAGED_BY,
                "pool": self.label,
                "index": index.to_string(),
            },
        });
        if let Some(volume) = self.volumes.get(index) {
            config["mounts"] = json!([{"volume": volume, "path": "/data"}]);
        }
        config
    }
}

// ── The world as one pass sees it ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Event {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub status: String,
    /// Milliseconds since the epoch, as the machines API reports it.
    #[serde(default)]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Machine {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub state: String,
    /// Kept as the API returned it: a launch edits two fields of this and sends it back, and a
    /// typed round trip would silently drop whatever this manager does not model.
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub events: Vec<Event>,
}

impl Machine {
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.config.get("metadata")?.get(key)?.as_str()
    }

    pub fn pool(&self) -> Option<&str> {
        self.metadata("pool")
    }

    pub fn is_managed(&self) -> bool {
        self.metadata("managed_by") == Some(MANAGED_BY)
    }

    /// The registration handed to this machine's current boot, if any.
    pub fn runner_id(&self) -> Option<u64> {
        self.metadata("github_runner_id")?.parse().ok()
    }

    pub fn is_live(&self) -> bool {
        LIVE_STATES.contains(&self.state.as_str())
    }

    /// Stopped after a boot: the image is on this host and a start is about a second.
    pub fn is_warm(&self) -> bool {
        self.state == "stopped"
    }

    /// Created and never booted: startable, but the first boot pulls the image.
    pub fn is_cold(&self) -> bool {
        self.state == NEVER_BOOTED
    }

    /// Seconds since this machine stopped, from its most recent stop event; 0 when unknown, which
    /// keeps an unreadable machine out of the retirement set rather than in it.
    pub fn stopped_secs(&self, now_secs: u64) -> u64 {
        for event in &self.events {
            if event.kind == "exit" || event.status == "stopped" {
                let stopped_at = event.timestamp / 1000;
                return u64::try_from(i64::try_from(now_secs).unwrap_or(i64::MAX) - stopped_at)
                    .unwrap_or(0);
            }
        }
        0
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Runner {
    pub id: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub busy: bool,
}

impl Runner {
    pub fn is_idle_online(&self) -> bool {
        self.status == "online" && !self.busy
    }

    pub fn belongs_to(&self, label: &str) -> bool {
        self.name.starts_with(&format!("{label}-"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub id: u64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

/// Queued jobs per label, deduplicated by job id: a pull request's clippy is as real as a merge
/// group's, and the same job seen in two pages is one job.
pub fn tally<'a>(jobs: impl IntoIterator<Item = &'a Job>, labels: &[String]) -> Demand {
    let mut seen: BTreeMap<String, BTreeSet<u64>> = labels
        .iter()
        .map(|l| (l.clone(), BTreeSet::new()))
        .collect();
    for job in jobs {
        if job.status != "queued" {
            continue;
        }
        for label in &job.labels {
            if let Some(ids) = seen.get_mut(label) {
                ids.insert(job.id);
            }
        }
    }
    Demand(seen.into_iter().map(|(l, ids)| (l, ids.len())).collect())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Demand(pub BTreeMap<String, usize>);

impl Demand {
    pub fn get(&self, label: &str) -> usize {
        self.0.get(label).copied().unwrap_or(0)
    }
}

/// Everything one pass reads, read once. A planner over this cannot act on a machine list it has
/// already invalidated, because it never performs the actions it plans.
pub struct Snapshot {
    /// Machines this manager owns (already filtered by [`Machine::is_managed`]).
    pub machines: Vec<Machine>,
    pub runners: Vec<Runner>,
    pub demand: Demand,
    /// Registrations this manager has issued, and when (seconds since the epoch). A registration
    /// this process did not issue is absent, and treated as old.
    pub issued: BTreeMap<u64, u64>,
    pub now_secs: u64,
    /// How long a stopped machine above `standby` lives before it is retired.
    pub idle_secs: u64,
    /// How many machines the pool must give back RIGHT NOW because the substrate refused one for
    /// capacity. Retiring these ignores the idle period: the pool is deadlocked until a slot is
    /// free, and waiting thirty minutes to free it is waiting thirty minutes to run anything.
    pub shrink_by: usize,
}

// ── The plan ────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Give a stopped machine one job's registration and start it.
    Launch {
        pool: String,
        id: String,
        name: String,
    },
    /// Create a machine at this index, stopped and unbooted. The boot is a separate action on a
    /// later pass: starting a machine the same pass that created it races its placement, and the
    /// substrate answers 412.
    Create { pool: String, index: usize },
    /// Boot a never-booted machine with no registration, so its image lands on its host and every
    /// later start is warm. It exits at once.
    Warm {
        pool: String,
        id: String,
        name: String,
    },
    /// Destroy a stopped machine above `standby` that has been idle past the period.
    Retire {
        pool: String,
        id: String,
        name: String,
    },
    /// Remove a registration whose machine never took the job.
    RemoveRunner { id: u64, name: String },
}

/// What this pass should do. Every machine appears in at most one action, and a machine that is
/// launched here is never also retired here — the property that a mutate-as-you-go loop cannot
/// state, and the one that loses jobs the first time a pool comes back from idle.
pub fn plan(pools: &[PoolSpec], snapshot: &Snapshot) -> Vec<Action> {
    let mut actions = Vec::new();
    let mut claimed: BTreeSet<&str> = BTreeSet::new();
    let mut shrink_remaining = snapshot.shrink_by;

    for pool in pools {
        let mine: Vec<&Machine> = snapshot
            .machines
            .iter()
            .filter(|m| m.pool() == Some(pool.label.as_str()))
            .collect();
        let idle_online = snapshot
            .runners
            .iter()
            .filter(|r| r.belongs_to(&pool.label) && r.is_idle_online())
            .count();
        let live = mine.iter().filter(|m| m.is_live()).count();
        let warm: Vec<&&Machine> = mine.iter().filter(|m| m.is_warm()).collect();
        let cold: Vec<&&Machine> = mine.iter().filter(|m| m.is_cold()).collect();

        // A queued job is already covered by a machine that is up, or by a registered runner
        // sitting idle: both will take it within seconds without anything started here.
        let mut needed = snapshot
            .demand
            .get(&pool.label)
            .saturating_sub(idle_online)
            .saturating_sub(live);

        // Warm machines first — a start is about a second; a cold one pulls the image first.
        for machine in warm.iter().chain(cold.iter()) {
            if needed == 0 {
                break;
            }
            claimed.insert(&machine.id);
            actions.push(Action::Launch {
                pool: pool.label.clone(),
                id: machine.id.clone(),
                name: machine.name.clone(),
            });
            needed -= 1;
        }

        // Every machine that has never booted and did not just take a job is booted once with no
        // registration: until it has, it is a machine whose first job waits for an image pull.
        for machine in &cold {
            if !claimed.contains(machine.id.as_str()) {
                actions.push(Action::Warm {
                    pool: pool.label.clone(),
                    id: machine.id.clone(),
                    name: machine.name.clone(),
                });
            }
        }

        let existing: BTreeSet<&str> = mine.iter().map(|m| m.name.as_str()).collect();
        let mut planned: BTreeSet<usize> = BTreeSet::new();
        // Creating while the substrate is refusing for capacity would take back the slot the
        // retirement below is giving up, and the pool would stay deadlocked.
        let may_create = snapshot.shrink_by == 0;
        for index in 0..pool.size {
            if needed == 0 || !may_create {
                break;
            }
            if !existing.contains(pool.machine_name(index).as_str()) {
                actions.push(Action::Create {
                    pool: pool.label.clone(),
                    index,
                });
                planned.insert(index);
                // A created machine warms rather than taking this job — it takes one on the next
                // pass, a poll apart. Counting it here is what stops one queued job from creating
                // the whole pool.
                needed -= 1;
            }
        }

        // Retire, from the machines still warm after this pass's launches, longest-idle first.
        let mut by_age: Vec<&&Machine> = warm
            .iter()
            .filter(|m| !claimed.contains(m.id.as_str()))
            .copied()
            .collect();
        by_age.sort_by_key(|m| std::cmp::Reverse(m.stopped_secs(snapshot.now_secs)));

        // First, whatever the substrate says the pool cannot have. This ignores `standby` and the
        // idle period on purpose: a pool at the organization's machine cap cannot start ANY job,
        // because writing a boot's registration is an update and an update needs a free slot. It
        // gives one back so the next pass can run.
        let mut given_back = 0;
        while given_back < shrink_remaining && given_back < by_age.len() {
            let machine = by_age[given_back];
            actions.push(Action::Retire {
                pool: pool.label.clone(),
                id: machine.id.clone(),
                name: machine.name.clone(),
            });
            given_back += 1;
        }
        shrink_remaining -= given_back;

        // Then the ordinary surplus above `standby`, once it has been idle long enough.
        let rest = &by_age[given_back..];
        let surplus = rest.len().saturating_sub(pool.standby);
        for machine in rest.iter().take(surplus) {
            if machine.stopped_secs(snapshot.now_secs) > snapshot.idle_secs {
                actions.push(Action::Retire {
                    pool: pool.label.clone(),
                    id: machine.id.clone(),
                    name: machine.name.clone(),
                });
            }
        }

        // Keep `standby` machines warm even with no demand, so the first job of the day is warm.
        let mut warm_or_busy = mine.len() + planned.len();
        for index in 0..pool.size {
            if warm_or_busy >= pool.standby || !may_create {
                break;
            }
            if !existing.contains(pool.machine_name(index).as_str()) && !planned.contains(&index) {
                actions.push(Action::Create {
                    pool: pool.label.clone(),
                    index,
                });
                planned.insert(index);
                warm_or_busy += 1;
            }
        }
    }

    actions.extend(orphans(pools, snapshot));
    actions
}

/// A registration whose machine never took its job. Three things have to hold, and the first two
/// are what keep this pass from reaping what it just issued: a runner is `offline` from
/// registration until its guest boots and connects.
fn orphans(pools: &[PoolSpec], snapshot: &Snapshot) -> Vec<Action> {
    let live_claims: BTreeSet<u64> = snapshot
        .machines
        .iter()
        .filter(|m| m.is_live())
        .filter_map(Machine::runner_id)
        .collect();
    snapshot
        .runners
        .iter()
        .filter(|runner| pools.iter().any(|p| runner.belongs_to(&p.label)))
        .filter(|runner| runner.status == "offline" && !runner.busy)
        // Not claimed by a machine that is up or coming up.
        .filter(|runner| !live_claims.contains(&runner.id))
        // Issued long enough ago that "offline" means failed rather than booting. A registration
        // this process did not issue (a restart, an earlier manager) is absent and so is old.
        .filter(|runner| {
            snapshot
                .issued
                .get(&runner.id)
                .is_none_or(|at| snapshot.now_secs.saturating_sub(*at) >= ORPHAN_GRACE_SECS)
        })
        .map(|runner| Action::RemoveRunner {
            id: runner.id,
            name: runner.name.clone(),
        })
        .collect()
}

/// The machine configuration for one boot: the pool's base configuration with this job's
/// registration written in as a file, and the registration's id recorded in the metadata so the
/// next pass can tell "booting" from "never took the job".
pub fn launch_config(base: &Value, jit: &str, runner_id: u64) -> Value {
    use base64::Engine as _;
    let mut config = base.clone();
    config["files"] = json!([{
        "guest_path": JIT_PATH,
        "raw_value": base64::engine::general_purpose::STANDARD.encode(jit),
    }]);
    config["metadata"]["github_runner_id"] = json!(runner_id.to_string());
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_launch_carries_one_registration_and_never_a_credential() {
        let pool = PoolSpec {
            label: "p".into(),
            guest: Guest {
                cpu_kind: "shared".into(),
                cpus: 2,
                memory_mb: 4096,
            },
            size: 1,
            standby: 0,
            volumes: vec![],
            env: BTreeMap::new(),
        };
        let config = launch_config(&pool.base_config("img@sha256:aa", 0), "JIT-BLOB", 7);
        let rendered = serde_json::to_string(&config).unwrap();
        assert_eq!(config["files"][0]["guest_path"], JIT_PATH);
        assert_eq!(config["files"][0]["raw_value"], "SklULUJMT0I=");
        assert_eq!(config["metadata"]["github_runner_id"], "7");
        // The one job's registration is the only credential in a worker's configuration.
        assert_eq!(rendered.matches("raw_value").count(), 1);
        assert!(!rendered.contains("TOKEN"));
    }

    #[test]
    fn a_pool_with_a_volume_per_machine_mounts_the_one_its_index_owns() {
        let pool = PoolSpec {
            label: "build".into(),
            guest: Guest {
                cpu_kind: "performance".into(),
                cpus: 8,
                memory_mb: 32768,
            },
            size: 2,
            standby: 1,
            volumes: vec!["vol_a".into(), "vol_b".into()],
            env: BTreeMap::from([("CARGO_BUILD_JOBS".into(), "8".into())]),
        };
        assert_eq!(
            pool.base_config("i@sha256:a", 1)["mounts"][0]["volume"],
            "vol_b"
        );
        assert_eq!(
            pool.base_config("i@sha256:a", 0)["mounts"][0]["path"],
            "/data"
        );
        assert_eq!(pool.base_config("i@sha256:a", 0)["restart"]["policy"], "no");
        assert_eq!(
            pool.base_config("i@sha256:a", 0)["env"]["CARGO_BUILD_JOBS"],
            "8"
        );
    }
}
