//! One pass: read the world, plan over it, apply the plan.
//!
//! Applying is best-effort per action. A pool whose start failed must not stop the other pool
//! from being served, and a pass that gave up halfway would leave the registration it had just
//! issued behind — so every failure is recorded and the pass continues.

use std::collections::BTreeMap;

use crate::api::{Error, Forge, Substrate};
use crate::{Action, Demand, PoolSpec, Snapshot, launch_config, plan, tally};

/// How long an issuance stays in the ledger. Long enough that a slow boot is never read as an
/// orphan, short enough that the ledger is bounded by the pass rate, not by uptime.
const LEDGER_SECS: u64 = 3600;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub demand: Vec<(String, usize)>,
    pub launched: usize,
    pub created: usize,
    pub retired: usize,
    pub runners_removed: usize,
    /// What did not happen, and why. Never a response body.
    pub failures: Vec<String>,
}

pub struct Manager<F: Forge, S: Substrate> {
    pub forge: F,
    pub substrate: S,
    pub pools: Vec<PoolSpec>,
    pub image: String,
    pub region: String,
    pub lookback: usize,
    pub idle_secs: u64,
    /// Registrations this process issued, and when. Bounds how "offline" is read: within the
    /// grace period it means booting, after it means the machine never took the job.
    issued: BTreeMap<u64, u64>,
}

impl<F: Forge, S: Substrate> Manager<F, S> {
    pub fn new(
        forge: F,
        substrate: S,
        pools: Vec<PoolSpec>,
        image: String,
        region: String,
        lookback: usize,
        idle_secs: u64,
    ) -> Self {
        Self {
            forge,
            substrate,
            pools,
            image,
            region,
            lookback,
            idle_secs,
            issued: BTreeMap::new(),
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
        for run in self.forge.active_runs(self.lookback)? {
            jobs.extend(self.forge.jobs(run.id)?);
        }
        Ok(tally(jobs.iter(), &self.labels()))
    }

    pub fn tick(&mut self, now_secs: u64) -> Result<Report, Error> {
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
            issued: self.issued.clone(),
            now_secs,
            idle_secs: self.idle_secs,
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
        for action in actions {
            if let Err(failure) = self.act(&action, &snapshot, now_secs, &mut report) {
                report.failures.push(failure);
            }
        }
        self.issued
            .retain(|_, at| now_secs.saturating_sub(*at) < LEDGER_SECS);
        Ok(report)
    }

    fn act(
        &mut self,
        action: &Action,
        snapshot: &Snapshot,
        now_secs: u64,
        report: &mut Report,
    ) -> Result<(), String> {
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
                self.issued.insert(registration.id, now_secs);
                let config = launch_config(&machine.config, &registration.encoded, registration.id);
                let started = self
                    .substrate
                    .update(id, &config)
                    .and_then(|()| self.substrate.start(id));
                if let Err(e) = started {
                    // The machine will not take the job, so the registration must not outlive
                    // the attempt: an idle registered runner would be counted as covering demand.
                    let _ = self.forge.remove_runner(registration.id);
                    self.issued.remove(&registration.id);
                    return Err(format!("{pool}: start {name}: {e}"));
                }
                report.launched += 1;
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
                let config = spec.base_config(&self.image, *index);
                let machine = self
                    .substrate
                    .create(&name, &self.region, &config)
                    .map_err(|e| format!("{pool}: create {name}: {e}"))?;
                // One boot with no registration: the image lands on this host and the machine
                // stops. Every later start is warm.
                self.substrate
                    .start(&machine.id)
                    .map_err(|e| format!("{pool}: warm {name}: {e}"))?;
                report.created += 1;
                println!("{pool}: created {name} ({}), warming", machine.id);
                Ok(())
            }
            Action::Retire { pool, id, name } => {
                self.substrate
                    .destroy(id)
                    .map_err(|e| format!("{pool}: retire {name}: {e}"))?;
                report.retired += 1;
                println!("{pool}: retired idle {name}");
                Ok(())
            }
            Action::RemoveRunner { id, name } => {
                self.forge
                    .remove_runner(*id)
                    .map_err(|e| format!("remove orphaned runner {name}: {e}"))?;
                self.issued.remove(id);
                report.runners_removed += 1;
                println!("removed orphaned runner {name}");
                Ok(())
            }
        }
    }

    /// Registrations this process has issued and not yet retired. Read by the smoke path and by
    /// the tests that pin the grace period.
    pub fn ledger(&self) -> &BTreeMap<u64, u64> {
        &self.issued
    }
}
