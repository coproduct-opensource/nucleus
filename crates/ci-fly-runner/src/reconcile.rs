//! One pass: read the world, plan over it, apply the plan.
//!
//! Applying is best-effort per action. A pool whose start failed must not stop the other pool
//! from being served, and a pass that gave up halfway would leave the registration it had just
//! issued behind — so every failure is recorded and the pass continues.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::api::{Error, Forge, Substrate};
use crate::{Action, Demand, PoolSpec, Snapshot, launch_config, plan, tally};

/// How long an issuance stays in the ledger. Long enough that a slow boot is never read as an
/// orphan, short enough that the ledger is bounded by the pass rate, not by uptime.
const LEDGER_SECS: u64 = 3600;

/// How long to wait for a machine to settle after its configuration is rewritten. Generous: the
/// alternative to waiting is a 412 and a job that is never taken.
const WAIT_SECS: u64 = 60;

/// How many launches may be in flight at once.
///
/// This is not a politeness limit. Writing a boot's registration into a machine is an UPDATE, and
/// the substrate satisfies an update by replacing the machine — which needs a free slot under the
/// organization's machine cap. A pool sized close to that cap therefore cannot start anything:
/// every update answers 422 "reached its machine limit", so no job is taken, so no machine ever
/// stops, so nothing frees a slot. The pool deadlocks with every machine warm and the queue full,
/// and the only clue is a status code. Launches are bounded so a pass can never ask for more
/// headroom than the deployment was sized to leave.
pub const DEFAULT_LAUNCH_CONCURRENCY: usize = 6;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub demand: Vec<(String, usize)>,
    pub launched: usize,
    pub created: usize,
    pub warmed: usize,
    pub retired: usize,
    pub runners_removed: usize,
    /// What did not happen, and why. Never a response body.
    pub failures: Vec<String>,
}

/// Everything about a deployment that is not the pools or the two APIs.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The worker image, pinned by digest.
    pub image: String,
    pub region: String,
    /// How many recent runs a pass scans for queued jobs.
    pub lookback: usize,
    /// How long a stopped machine above `standby` lives before it is retired.
    pub idle_secs: u64,
    /// Launches in flight at once; see [`DEFAULT_LAUNCH_CONCURRENCY`].
    pub launch_concurrency: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            image: String::new(),
            region: "iad".into(),
            lookback: 25,
            idle_secs: 1800,
            launch_concurrency: DEFAULT_LAUNCH_CONCURRENCY,
        }
    }
}

pub struct Manager<F: Forge, S: Substrate> {
    pub forge: F,
    pub substrate: S,
    pub pools: Vec<PoolSpec>,
    pub settings: Settings,
    /// Registrations this process issued, and when. Bounds how "offline" is read: within the
    /// grace period it means booting, after it means the machine never took the job.
    ///
    /// How many machines the substrate has refused to let this pool have. Raised when a call is
    /// answered "at capacity" — the live path refuting the declared budget — and spent by the
    /// retirements the next pass plans. Without it the pool sits deadlocked: every update needs a
    /// free slot, no job is taken, no machine stops, nothing frees one.
    shrink: Mutex<usize>,
    /// Behind a lock because launches run concurrently: they are independent, each costs a
    /// registration plus three substrate calls plus the settle wait, and run one after another a
    /// burst of twenty spends a minute of queue time on nothing but its own serialization.
    issued: Mutex<BTreeMap<u64, u64>>,
}

impl<F: Forge + Sync, S: Substrate + Sync> Manager<F, S> {
    pub fn new(forge: F, substrate: S, pools: Vec<PoolSpec>, settings: Settings) -> Self {
        let settings = Settings {
            launch_concurrency: settings.launch_concurrency.max(1),
            ..settings
        };
        Self {
            forge,
            substrate,
            pools,
            settings,
            shrink: Mutex::new(0),
            issued: Mutex::new(BTreeMap::new()),
        }
    }

    fn labels(&self) -> Vec<String> {
        self.pools.iter().map(|p| p.label.clone()).collect()
    }

    /// Queued jobs per pool label, across every event and workflow. Reading the runs first and
    /// their jobs second is what keeps a pass to a handful of calls; the conditional cache makes
    /// the unchanged ones free.
    pub fn demand(&self) -> Result<Demand, Error> {
        let mut jobs = Vec::new();
        for run in self.forge.active_runs(self.settings.lookback)? {
            jobs.extend(self.forge.jobs(run.id)?);
        }
        Ok(tally(jobs.iter(), &self.labels()))
    }

    fn shrink_lock(&self) -> std::sync::MutexGuard<'_, usize> {
        self.shrink.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What the substrate has refused. Read by the tests that pin the self-heal.
    pub fn shrink_owed(&self) -> usize {
        *self.shrink_lock()
    }

    /// One machine at a time. A pass can see many refusals — every launch in it asks for the same
    /// slot — and counting them all would shrink the pool by the size of the burst for a shortage
    /// of one. The debt is therefore at most one outstanding: the pool gives a machine back,
    /// tries again next pass, and converges on the size the substrate will actually allow.
    fn note_capacity_refusal(&self, what: &str) {
        let mut owed = self.shrink_lock();
        if *owed == 0 {
            *owed = 1;
            println!(
                "the declared machine budget is wrong: the substrate refused {what} at capacity; \
                 giving one machine back so there is a free slot to start jobs with"
            );
        }
    }

    fn ledger_lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, u64>> {
        // A poisoned ledger would stop every later pass; the map holds no invariant worth
        // failing for, so a panicking launch thread does not take the pool down with it.
        self.issued.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn tick(&self, now_secs: u64) -> Result<Report, Error> {
        let demand = self.demand()?;
        let machines = self
            .substrate
            .machines()?
            .into_iter()
            .filter(crate::Machine::is_managed)
            .collect();
        let snapshot = Snapshot {
            machines,
            runners: self.forge.runners()?,
            demand,
            issued: self.ledger_lock().clone(),
            now_secs,
            idle_secs: self.settings.idle_secs,
            shrink_by: *self.shrink_lock(),
        };
        let actions = plan(&self.pools, &snapshot);
        let mut report = Report {
            demand: snapshot
                .demand
                .0
                .iter()
                .map(|(l, n)| (l.clone(), *n))
                .collect(),
            ..Report::default()
        };
        // Launches are independent of each other and of everything else in the plan: the planner
        // has already guaranteed one action per machine. Run them at once.
        let (launches, rest): (Vec<Action>, Vec<Action>) = actions
            .into_iter()
            .partition(|a| matches!(a, Action::Launch { .. }));
        let mut outcomes: Vec<Result<(), String>> = Vec::with_capacity(launches.len());
        for batch in launches.chunks(self.settings.launch_concurrency) {
            outcomes.extend(std::thread::scope(|scope| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|action| {
                        let snapshot = &snapshot;
                        scope.spawn(move || self.act(action, snapshot, now_secs))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err("a launch panicked".to_string()))
                    })
                    .collect::<Vec<_>>()
            }));
        }
        for outcome in outcomes {
            match outcome {
                Ok(()) => report.launched += 1,
                Err(failure) => report.failures.push(failure),
            }
        }
        for action in rest {
            match self.act(&action, &snapshot, now_secs) {
                Ok(()) => match action {
                    Action::Create { .. } => report.created += 1,
                    Action::Warm { .. } => report.warmed += 1,
                    Action::Retire { .. } => {
                        report.retired += 1;
                        // A machine given back is a slot the substrate no longer owes us.
                        let mut owed = self.shrink_lock();
                        *owed = owed.saturating_sub(1);
                    }
                    Action::RemoveRunner { .. } => report.runners_removed += 1,
                    Action::Launch { .. } => unreachable!("launches were partitioned out"),
                },
                Err(failure) => report.failures.push(failure),
            }
        }
        self.ledger_lock()
            .retain(|_, at| now_secs.saturating_sub(*at) < LEDGER_SECS);
        Ok(report)
    }

    fn act(&self, action: &Action, snapshot: &Snapshot, now_secs: u64) -> Result<(), String> {
        match action {
            Action::Launch { pool, id, name } => {
                let machine = snapshot
                    .machines
                    .iter()
                    .find(|m| &m.id == id)
                    .ok_or_else(|| format!("{pool}: {name} vanished before it was started"))?;
                let runner_name = format!("{name}-{now_secs}");
                let registration = self
                    .forge
                    .register(pool, &runner_name)
                    .map_err(|e| format!("{pool}: register {runner_name}: {e}"))?;
                // The ledger entry goes in BEFORE the machine calls: if the process dies between
                // them, the next pass must still see this registration as one it issued.
                self.ledger_lock().insert(registration.id, now_secs);
                let config = launch_config(&machine.config, &registration.encoded, registration.id);
                let started = self
                    .substrate
                    .update(id, &config)
                    // The update rewrites the machine; it is not startable until it has settled
                    // back to stopped, and a start before then is answered 412.
                    .and_then(|()| self.substrate.wait_for(id, "stopped", WAIT_SECS))
                    .and_then(|()| self.substrate.start(id));
                if let Err(ref e) = started
                    && e.is_at_capacity()
                {
                    self.note_capacity_refusal(name);
                }
                if let Err(e) = started {
                    // The machine will not take the job, so the registration must not outlive
                    // the attempt: an idle registered runner would be counted as covering demand.
                    let _ = self.forge.remove_runner(registration.id);
                    self.ledger_lock().remove(&registration.id);
                    return Err(format!("{pool}: start {name}: {e}"));
                }
                println!("{pool}: started {name} as runner {}", registration.id);
                Ok(())
            }
            Action::Create { pool, index } => {
                let spec = self
                    .pools
                    .iter()
                    .find(|p| &p.label == pool)
                    .ok_or_else(|| format!("{pool}: no such pool"))?;
                let name = spec.machine_name(*index);
                let config = spec.base_config(&self.settings.image, *index);
                let machine = self
                    .substrate
                    .create(&name, &self.settings.region, &config)
                    .map_err(|e| {
                        if e.is_at_capacity() {
                            self.note_capacity_refusal(&name);
                        }
                        format!("{pool}: create {name}: {e}")
                    })?;
                // Not started here: a start issued in the same pass as the create races the
                // machine's placement and is answered 412. The next pass boots it.
                println!("{pool}: created {name} ({})", machine.id);
                Ok(())
            }
            Action::Warm { pool, id, name } => {
                // One boot with no registration: the image lands on this host and the machine
                // exits at once. Every later start is warm.
                self.substrate
                    .start(id)
                    .map_err(|e| format!("{pool}: warm {name}: {e}"))?;
                println!("{pool}: warming {name}");
                Ok(())
            }
            Action::Retire { pool, id, name } => {
                self.substrate
                    .destroy(id)
                    .map_err(|e| format!("{pool}: retire {name}: {e}"))?;
                println!("{pool}: retired idle {name}");
                Ok(())
            }
            Action::RemoveRunner { id, name } => {
                self.forge
                    .remove_runner(*id)
                    .map_err(|e| format!("remove orphaned runner {name}: {e}"))?;
                self.ledger_lock().remove(id);
                println!("removed orphaned runner {name}");
                Ok(())
            }
        }
    }

    /// Registrations this process has issued and not yet retired. Read by the smoke path and by
    /// the tests that pin the grace period.
    pub fn ledger(&self) -> BTreeMap<u64, u64> {
        self.ledger_lock().clone()
    }
}
