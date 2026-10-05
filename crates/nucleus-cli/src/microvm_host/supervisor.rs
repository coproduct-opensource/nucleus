//! Keep the host container alive, within a budget, and say so every time.
//!
//! Apple's Virtualization.framework can assert on a nested guest's exit, and
//! the Lima builder that shares the layer dies about every 13 microVM boots
//! (#3010). The spike measured 0 deaths in about 140 boots here, but that is
//! not evidence the crash cannot happen. So the host is supervised:
//!
//! - [`Supervisor::tick`] looks once and returns what it saw as
//!   [`HostEvent`]s: `Healthy`, or `Died` followed by `Restarted` or
//!   `RestartFailed`.
//! - Restarts are capped by a [`RestartBudget`], 3 per 10 minutes, so a host
//!   that dies on every start is surfaced rather than restarted forever.
//! - Every event except `Healthy` is appended to an audit log, one JSON line
//!   per event, with `nucleus_jsonl`'s single atomic write (ADR 0007 G-1).
//! - A restart takes the same lock as creation, so two supervisors (or a
//!   supervisor and `ensure_ready`) never race a `container start`.
//! - `container start` runs under the lifecycle deadline, because a wedged
//!   `container` service stalled every call for 40 minutes in the spike.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::container_cli::ContainerCli;
use super::lifecycle::{self, HostConfig, HostLock, HostState, Refusal};

/// Why the supervisor considers the host dead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum DeathCause {
    /// `container list` reports it stopped.
    Stopped,
    /// It is gone from `container list`.
    Vanished,
    /// It runs, and its node does not answer.
    Unhealthy { detail: String },
    /// `container list` could not be read, so its state is unknown. Not
    /// restarted: a restart would queue behind the same wedged service.
    Unobservable { detail: String },
    /// It is no longer the container this build runs.
    Stale { detail: String },
}

/// What one supervision step saw or did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HostEvent {
    Healthy,
    Died {
        #[serde(flatten)]
        cause: DeathCause,
    },
    Restarted {
        /// From the restart decision to a healthy node.
        took_ms: u128,
    },
    RestartFailed {
        reason: String,
        /// True when the budget, not the restart itself, stopped it.
        budget_exhausted: bool,
    },
}

/// How many restarts are allowed in how long.
#[derive(Debug, Clone)]
pub struct RestartBudget {
    max: usize,
    window: Duration,
    spent: VecDeque<Instant>,
}

impl RestartBudget {
    /// 3 restarts per 10 minutes.
    pub fn standard() -> Self {
        Self::new(3, Duration::from_secs(10 * 60))
    }

    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            spent: VecDeque::new(),
        }
    }

    /// Spend one restart at `now`, or refuse when `max` were already spent
    /// inside the window ending at `now`.
    pub fn try_spend(&mut self, now: Instant) -> bool {
        while self
            .spent
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= self.window)
        {
            self.spent.pop_front();
        }
        if self.spent.len() >= self.max {
            return false;
        }
        self.spent.push_back(now);
        true
    }
}

/// One line of the audit log.
#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    at: String,
    container: &'a str,
    #[serde(flatten)]
    event: &'a HostEvent,
}

/// Supervises one host.
pub struct Supervisor {
    cli: ContainerCli,
    cfg: HostConfig,
    budget: RestartBudget,
    audit: PathBuf,
}

impl Supervisor {
    pub fn new(cli: ContainerCli, cfg: HostConfig) -> Self {
        let audit = cfg.state_dir.join("host-events.jsonl");
        Self {
            cli,
            cfg,
            budget: RestartBudget::standard(),
            audit,
        }
    }

    /// The audit log's path.
    pub fn audit_log(&self) -> &std::path::Path {
        &self.audit
    }

    /// Look once, restart if the host died and the budget allows, and return
    /// the events in order. Every event but `Healthy` is audited before this
    /// returns; an audit write failure is logged, not swallowed into success.
    pub fn tick(&mut self) -> Vec<HostEvent> {
        let events = self.step(Instant::now());
        for e in events.iter().filter(|e| **e != HostEvent::Healthy) {
            self.record(e);
        }
        events
    }

    fn step(&mut self, now: Instant) -> Vec<HostEvent> {
        let cause = match lifecycle::observe_state(&self.cli, &self.cfg) {
            Err(e) => {
                return vec![HostEvent::Died {
                    cause: DeathCause::Unobservable {
                        detail: e.to_string(),
                    },
                }];
            }
            Ok(HostState::Running(owned, ports)) => {
                match lifecycle::wait_host_healthy(
                    &self.cli,
                    &owned,
                    &ports,
                    &self.cfg,
                    Duration::from_secs(5),
                ) {
                    Ok(_) => return vec![HostEvent::Healthy],
                    Err(e) => DeathCause::Unhealthy {
                        detail: e.to_string(),
                    },
                }
            }
            Ok(HostState::Stopped(_)) => DeathCause::Stopped,
            Ok(HostState::Absent) => DeathCause::Vanished,
            Ok(HostState::Stale { reason }) => DeathCause::Stale {
                detail: format!("{reason:?}"),
            },
        };
        let died = HostEvent::Died { cause };
        if !self.budget.try_spend(now) {
            return vec![
                died,
                HostEvent::RestartFailed {
                    reason: "3 restarts in 10 minutes already; the host keeps dying".into(),
                    budget_exhausted: true,
                },
            ];
        }
        let started = Instant::now();
        let restarted = match self.restart() {
            Ok(()) => HostEvent::Restarted {
                took_ms: started.elapsed().as_millis(),
            },
            Err(e) => HostEvent::RestartFailed {
                reason: e.to_string(),
                budget_exhausted: false,
            },
        };
        vec![died, restarted]
    }

    /// Under the host lock, bring the host back and wait for health.
    fn restart(&self) -> Result<(), Refusal> {
        let lock = HostLock::acquire(&self.cfg.state_dir, self.cfg.ready_timeout)?;
        match lifecycle::observe_state(&self.cli, &self.cfg)? {
            HostState::Stopped(owned) => {
                let out = self.cli.start(&owned);
                if !out.succeeded() {
                    return Err(Refusal::Cli {
                        action: "start",
                        outcome: out.describe(),
                    });
                }
            }
            HostState::Running(..) => {}
            HostState::Absent | HostState::Stale { .. } => {
                // Recreating needs the full path, which also re-probes and
                // takes this same lock itself.
                drop(lock);
                return lifecycle::ensure_ready(&self.cli, &self.cfg).map(|_host| ());
            }
        }
        match lifecycle::observe_state(&self.cli, &self.cfg)? {
            HostState::Running(owned, ports) => lifecycle::wait_host_healthy(
                &self.cli,
                &owned,
                &ports,
                &self.cfg,
                self.cfg.ready_timeout,
            )
            .map(|_| ()),
            other => Err(Refusal::Cli {
                action: "start",
                outcome: format!("left the host {other:?}"),
            }),
        }
    }

    fn record(&self, event: &HostEvent) {
        let rec = AuditRecord {
            at: chrono::Utc::now().to_rfc3339(),
            container: self.cfg.names.container,
            event,
        };
        let line = match serde_json::to_string(&rec) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "could not serialise a host event");
                return;
            }
        };
        if let Err(e) = nucleus_jsonl::append_line_synced(&self.audit, &line) {
            tracing::error!(error = %e, path = %self.audit.display(), "could not audit a host event");
        }
        tracing::warn!(container = self.cfg.names.container, %line, "microVM host event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn three_restarts_fit_in_ten_minutes_and_a_fourth_does_not() {
        let t0 = Instant::now();
        let mut b = RestartBudget::standard();
        assert!(b.try_spend(at(t0, 0)));
        assert!(b.try_spend(at(t0, 60)));
        assert!(b.try_spend(at(t0, 120)));
        assert!(
            !b.try_spend(at(t0, 180)),
            "a fourth restart inside the window"
        );
        assert!(
            !b.try_spend(at(t0, 599)),
            "still inside the first restart's window"
        );
    }

    #[test]
    fn the_budget_refills_as_restarts_age_out() {
        let t0 = Instant::now();
        let mut b = RestartBudget::standard();
        for s in [0, 60, 120] {
            assert!(b.try_spend(at(t0, s)));
        }
        // The first restart leaves the window at 600 s; one slot frees.
        assert!(b.try_spend(at(t0, 600)));
        assert!(!b.try_spend(at(t0, 601)));
        // By 720 s the 60 s and 120 s restarts have aged out too.
        assert!(b.try_spend(at(t0, 720)));
        assert!(b.try_spend(at(t0, 721)));
        assert!(!b.try_spend(at(t0, 722)));
    }

    #[test]
    fn a_refused_restart_is_not_spent() {
        let t0 = Instant::now();
        let mut b = RestartBudget::new(1, Duration::from_secs(10));
        assert!(b.try_spend(at(t0, 0)));
        for s in 1..10 {
            assert!(!b.try_spend(at(t0, s)));
        }
        assert!(
            b.try_spend(at(t0, 10)),
            "refusals must not extend the window"
        );
    }

    #[test]
    fn events_serialise_to_one_flat_record() {
        let e = HostEvent::Died {
            cause: DeathCause::Unhealthy {
                detail: "HTTP 503".into(),
            },
        };
        let rec = AuditRecord {
            at: "2026-09-29T00:00:00Z".into(),
            container: "nucleus-dev-microvm-host",
            event: &e,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&rec).expect("ser")).expect("json");
        assert_eq!(v["event"], "died");
        assert_eq!(v["cause"], "unhealthy");
        assert_eq!(v["detail"], "HTTP 503");
        assert_eq!(v["container"], "nucleus-dev-microvm-host");
    }

    /// A supervisor whose `container` is a wedged program: the look times out
    /// (it does not hang), the host is `Unobservable`, and no restart is
    /// attempted or budgeted.
    #[test]
    fn an_unobservable_host_is_reported_not_restarted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = HostConfig {
            names: nucleus_spec::microvm_host::HostNames::DEV,
            image: "nucleus-dev-microvm-host:local".into(),
            kernel: dir.path().join("Image"),
            state_dir: dir.path().to_path_buf(),
            cpus: 1,
            memory: "1g".into(),
            trust_domain: "nucleus.local".into(),
            ready_timeout: Duration::from_secs(1),
            connection: crate::microvm_host::lifecycle::Connection::PublishedLoopback,
        };
        // `false` exits 1 at once: `container list` "failed".
        let mut s = Supervisor::new(ContainerCli::at(PathBuf::from("/usr/bin/false")), cfg);
        let events = s.tick();
        assert!(
            matches!(
                events.as_slice(),
                [HostEvent::Died {
                    cause: DeathCause::Unobservable { .. }
                }]
            ),
            "{events:?}"
        );
        assert!(s.budget.spent.is_empty());
        let log = std::fs::read_to_string(s.audit_log()).expect("audited");
        assert_eq!(log.lines().count(), 1);
        assert!(log.contains("\"unobservable\""));
    }
}
