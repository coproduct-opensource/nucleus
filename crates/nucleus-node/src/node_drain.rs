//! Stop the node on SIGTERM/SIGINT by draining its pods through their own teardown (#3204).
//!
//! # The defect this closes
//!
//! The node installed no signal handler. SIGTERM took the default action, so the process died
//! without running a single teardown, and every pod's VMM, jail, netns, host veth, host iptables
//! rules and dnsmasq outlived it. `kill_on_drop` on the VMM child never fired: it needs the
//! owning handle to be DROPPED inside a live runtime, and a signal-killed process drops nothing.
//!
//! # The order, and why it is this order
//!
//! 1. **Stop admitting.** [`Intake::close`] refuses every new launch and then waits for the
//!    launches already past the gate to register. Without the wait, a launch that passed the gate
//!    just before the drain read the registry would register AFTER it, and run with no node.
//!    "Stop accepting" is not "stop serving": a listener's shutdown leaves its accepted
//!    connections running, so the gate is on the launch path, not the socket.
//! 2. **Tear down every registered pod through its normal teardown** — the same `cancel` an
//!    operator's request runs — so receipts are preserved and a lifecycle record is written.
//! 3. **Report what actually happened.** The drain succeeds only when the intake quiesced and
//!    every pod is confirmed stopped. Anything else is an error naming the stragglers, and the
//!    node exits non-zero (ADR 0007 A-2: a drain that could not confirm is not a drain that
//!    succeeded).
//!
//! # Stragglers
//!
//! The drain is bounded by [`DRAIN_DEADLINE`], which sits under systemd's default 90 s stop
//! timeout. A pod whose teardown does not finish in time is reported by id and left. The process
//! then exits; whatever it still held is SIGKILLed with it or stranded, and the next start's
//! reclaim (`jail_reclaim`) finds a stranded VMM by its jail's cgroup and kills it before the
//! node serves anything.

use std::{collections::HashSet, sync::Arc, time::Duration};

use tokio::sync::{Mutex, RwLock, RwLockReadGuard};
use uuid::Uuid;

use crate::{ApiError, NodeState, PodHandle, PodState, lifecycle};

/// How long a drain may take, end to end, before it reports stragglers instead of waiting.
pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

/// The signal that started a shutdown. Closed: only these two are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopSignal {
    Terminate,
    Interrupt,
}

impl StopSignal {
    fn name(self) -> &'static str {
        match self {
            StopSignal::Terminate => "SIGTERM",
            StopSignal::Interrupt => "SIGINT",
        }
    }
}

/// SIGTERM and SIGINT, installed once. Installing replaces the default action (terminate), so
/// this is created before the node serves anything: a signal that arrives during startup is
/// queued and drained, not fatal.
pub(crate) struct Signals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    pub(crate) fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    pub(crate) async fn recv(&mut self) -> StopSignal {
        tokio::select! {
            _ = self.terminate.recv() => StopSignal::Terminate,
            _ = self.interrupt.recv() => StopSignal::Interrupt,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    Open,
    Closed,
}

/// The launch gate. Every launch holds a read guard from before its first side effect until its
/// pod is registered (or it has failed); [`Intake::close`] takes the write side, so it returns
/// only once no launch is between the gate and the registry.
#[derive(Clone, Debug)]
pub(crate) struct Intake(Arc<RwLock<Gate>>);

/// Held by one launch for its whole duration. Dropping it is what lets a drain proceed.
pub(crate) struct Admitted<'a> {
    _gate: RwLockReadGuard<'a, Gate>,
}

/// What closing the intake observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntakeClosed {
    /// Closed, and no launch was in flight when the registry was read.
    Quiesced,
    /// The deadline passed with launches still in flight. They were admitted before the close
    /// and may register a pod after the drain read the registry.
    LaunchesInFlight,
}

impl Intake {
    /// An open gate. Written by hand, not derived: the only constructor says which end it is.
    pub(crate) fn open() -> Self {
        Self(Arc::new(RwLock::new(Gate::Open)))
    }

    /// Admit one launch, or refuse it because the node is draining.
    pub(crate) async fn admit(&self) -> Result<Admitted<'_>, ApiError> {
        let guard = self.0.read().await;
        match *guard {
            Gate::Open => Ok(Admitted { _gate: guard }),
            Gate::Closed => Err(ApiError::SupervisorUnavailable(
                "the node is shutting down and admits no new pods".into(),
            )),
        }
    }

    /// Refuse new launches, then wait (until `deadline`) for admitted ones to finish.
    ///
    /// The refusal is immediate either way: tokio's `RwLock` is fair, so once the write is
    /// queued every later `admit` waits behind it and then reads `Closed`. If the deadline passes
    /// first, a separate flag would be needed to refuse while launches are still running — so the
    /// close is written through the first write guard it gets, and until then `admit` simply
    /// waits, which a launch's own deadline bounds.
    pub(crate) async fn close(&self, deadline: tokio::time::Instant) -> IntakeClosed {
        match tokio::time::timeout_at(deadline, self.0.write()).await {
            Ok(mut gate) => {
                *gate = Gate::Closed;
                IntakeClosed::Quiesced
            }
            Err(_elapsed) => {
                // Close it anyway once the in-flight launches release it, so no launch admitted
                // after this point can start: the waiting writer already holds every new reader.
                let gate = self.0.clone();
                tokio::spawn(async move { *gate.write().await = Gate::Closed });
                IntakeClosed::LaunchesInFlight
            }
        }
    }
}

/// What the drain did to one pod. Every arm is a different fact, and only two are success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PodDrain {
    /// It was running, and its teardown confirmed the VMM stopped and its resources released.
    Stopped,
    /// It had exited and not been reaped; its teardown released what it held.
    Released,
    /// It had exited and the reaper had already released it. Nothing to do.
    AlreadyReaped,
    /// Its teardown returned an error. Its resources are retained, not released.
    Failed(String),
    /// Its teardown did not finish before the drain's deadline.
    TimedOut,
}

impl PodDrain {
    fn confirmed(&self) -> bool {
        match self {
            PodDrain::Stopped | PodDrain::Released | PodDrain::AlreadyReaped => true,
            PodDrain::Failed(_) | PodDrain::TimedOut => false,
        }
    }
}

/// Everything a drain observed, so its verdict is computed from facts rather than asserted.
#[derive(Debug)]
pub(crate) struct DrainReport {
    pub(crate) signal: StopSignal,
    pub(crate) intake: IntakeClosed,
    pub(crate) pods: Vec<(Uuid, PodDrain)>,
}

impl DrainReport {
    /// `Ok` only when the intake quiesced and every pod is confirmed released.
    pub(crate) fn verdict(&self) -> Result<usize, ApiError> {
        let stragglers: Vec<String> = self
            .pods
            .iter()
            .filter(|(_, outcome)| !outcome.confirmed())
            .map(|(id, outcome)| format!("{id}: {outcome:?}"))
            .collect();
        match (self.intake, stragglers.is_empty()) {
            (IntakeClosed::Quiesced, true) => Ok(self.pods.len()),
            (IntakeClosed::Quiesced, false) => Err(ApiError::Driver(format!(
                "{} drain left {} pod(s) unconfirmed: {}",
                self.signal.name(),
                stragglers.len(),
                stragglers.join("; ")
            ))),
            (IntakeClosed::LaunchesInFlight, _) => Err(ApiError::Driver(format!(
                "{} drain hit its deadline with launches in flight; unconfirmed pods: [{}]",
                self.signal.name(),
                stragglers.join("; ")
            ))),
        }
    }
}

/// The reaper's record of the pods it has released, shared so a drain does not release one twice
/// (a second `pod_exited`/`pod_drained` entry and a second authority release). The reaper holds
/// the lock for a whole pass, so taking it also waits out a pass in progress.
pub(crate) type Reaped = Arc<Mutex<HashSet<Uuid>>>;

/// Stop admitting, tear every pod down, and report. Never returns early on one pod's failure.
pub(crate) async fn drain(
    state: &NodeState,
    reaped: &Reaped,
    signal: StopSignal,
    budget: Duration,
) -> DrainReport {
    let deadline = tokio::time::Instant::now() + budget;
    let intake = state.intake.close(deadline).await;
    // Hold the reaper's set for the rest of the drain: no pass can run concurrently with it.
    let mut reaped = tokio::time::timeout_at(deadline, reaped.lock()).await.ok();
    let pods: Vec<Arc<PodHandle>> = state.pods.lock().await.values().cloned().collect();
    tracing::info!(
        signal = signal.name(),
        pods = pods.len(),
        ?intake,
        "draining the node: no new pods are admitted"
    );
    let mut tasks = tokio::task::JoinSet::new();
    for pod in &pods {
        let pod = pod.clone();
        let already = reaped.as_ref().map(|set| set.contains(&pod.id));
        tasks.spawn(async move {
            let outcome = match tokio::time::timeout_at(deadline, one(&pod, already, signal)).await
            {
                Ok(outcome) => outcome,
                Err(_elapsed) => PodDrain::TimedOut,
            };
            (pod.id, outcome)
        });
    }
    let mut outcomes = Vec::with_capacity(pods.len());
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => tracing::error!(%error, "drain: a teardown task panicked"),
        }
    }
    // A teardown that panicked has no outcome; it is still a pod, and still unconfirmed.
    for pod in &pods {
        if !outcomes.iter().any(|(id, _)| *id == pod.id) {
            outcomes.push((pod.id, PodDrain::Failed("teardown task panicked".into())));
        }
    }
    for (id, outcome) in &outcomes {
        match outcome {
            PodDrain::Stopped | PodDrain::Released => {
                if let Some(set) = reaped.as_mut() {
                    set.insert(*id);
                }
                state.authority.release_child(*id).await;
            }
            PodDrain::AlreadyReaped => {}
            PodDrain::Failed(error) => {
                tracing::error!(pod = %id, %error, "drain: teardown failed; resources retained")
            }
            PodDrain::TimedOut => {
                tracing::error!(pod = %id, "drain: teardown did not finish before the deadline")
            }
        }
    }
    DrainReport {
        signal,
        intake,
        pods: outcomes,
    }
}

/// One pod's teardown, chosen by its observed state. `already` is `None` when the reaper's
/// record could not be read in time: the pod is then torn down, which is idempotent, rather than
/// assumed released.
async fn one(pod: &PodHandle, already: Option<bool>, signal: StopSignal) -> PodDrain {
    let observed = pod.status().await;
    let (result, outcome, detail) = match &observed {
        PodState::Running => (
            pod.cancel().await,
            PodDrain::Stopped,
            format!("node shutdown ({}): stopped a running pod", signal.name()),
        ),
        PodState::Exited { code: _ } | PodState::Error { message: _ } => {
            if already == Some(true) {
                return PodDrain::AlreadyReaped;
            }
            (
                pod.cleanup_after_exit().await,
                PodDrain::Released,
                format!(
                    "node shutdown ({}): released an exited pod ({observed:?})",
                    signal.name()
                ),
            )
        }
    };
    match result {
        Ok(()) => {
            let pod_dir = pod.log_path.parent().unwrap_or(std::path::Path::new("."));
            lifecycle::write_lifecycle_audit(pod_dir, "pod_drained", &pod.id.to_string(), &detail)
                .await;
            outcome
        }
        Err(error) => PodDrain::Failed(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_closed_intake_refuses_and_close_waits_for_admitted_launches() {
        let intake = Intake::open();
        let admitted = intake.admit().await.expect("open admits");
        let closing = {
            let intake = intake.clone();
            tokio::spawn(async move {
                intake
                    .close(tokio::time::Instant::now() + Duration::from_secs(5))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !closing.is_finished(),
            "close must wait for the launch that was admitted before it"
        );
        drop(admitted);
        assert_eq!(closing.await.unwrap(), IntakeClosed::Quiesced);
        assert!(matches!(
            intake.admit().await,
            Err(ApiError::SupervisorUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn a_launch_still_in_flight_at_the_deadline_is_reported_not_hidden() {
        let intake = Intake::open();
        let admitted = intake.admit().await.unwrap();
        let closed = intake
            .close(tokio::time::Instant::now() + Duration::from_millis(20))
            .await;
        assert_eq!(closed, IntakeClosed::LaunchesInFlight);
        drop(admitted);
        // The close still lands once the launch is done: nothing is admitted afterwards.
        tokio::time::timeout(Duration::from_secs(2), async {
            while intake.admit().await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the intake closes once the in-flight launch finishes");
    }

    #[test]
    fn the_verdict_succeeds_only_on_a_quiesced_intake_and_every_pod_confirmed() {
        let id = Uuid::new_v4();
        let report = |intake, outcome: PodDrain| DrainReport {
            signal: StopSignal::Terminate,
            intake,
            pods: vec![(id, outcome)],
        };
        for ok in [
            PodDrain::Stopped,
            PodDrain::Released,
            PodDrain::AlreadyReaped,
        ] {
            assert_eq!(report(IntakeClosed::Quiesced, ok).verdict().unwrap(), 1);
        }
        for bad in [PodDrain::Failed("busy".into()), PodDrain::TimedOut] {
            let error = report(IntakeClosed::Quiesced, bad).verdict().unwrap_err();
            assert!(error.to_string().contains(&id.to_string()), "{error}");
        }
        assert!(
            report(IntakeClosed::LaunchesInFlight, PodDrain::Stopped)
                .verdict()
                .is_err(),
            "a launch that may register after the drain read the registry is not a clean drain"
        );
        let empty = DrainReport {
            signal: StopSignal::Interrupt,
            intake: IntakeClosed::Quiesced,
            pods: Vec::new(),
        };
        assert_eq!(empty.verdict().unwrap(), 0);
    }
}

#[cfg(all(test, feature = "local-driver"))]
mod drain_tests {
    use super::*;

    /// End to end over the real registry, teardown and lifecycle log: a running pod is stopped,
    /// recorded, released from its authority, and a launch after the drain is refused.
    #[tokio::test]
    async fn a_drain_stops_every_running_pod_records_it_and_closes_admission() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&dir);
        state.node_capacity = crate::node_capacity::Capacity::new(640, 4);
        let first = crate::pod_api::handler_tests::register(&state, None).await;
        let second = crate::pod_api::handler_tests::register(&state, None).await;
        for id in [first, second] {
            let pod = crate::pod_api::get_pod(&state, id).await.unwrap();
            assert!(matches!(pod.status().await, PodState::Running));
        }
        let reaped = Reaped::default();
        let report = drain(&state, &reaped, StopSignal::Terminate, DRAIN_DEADLINE).await;
        assert_eq!(report.verdict().unwrap(), 2, "{report:?}");
        for id in [first, second] {
            let pod = crate::pod_api::get_pod(&state, id).await.unwrap();
            assert!(
                matches!(pod.status().await, PodState::Exited { .. }),
                "a drained pod's process must have stopped"
            );
            assert!(reaped.lock().await.contains(&id));
        }
        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        let drained = log
            .lines()
            .filter(|l| l.contains("\"pod_drained\""))
            .count();
        assert_eq!(drained, 2, "one drain record per pod: {log}");
        assert!(matches!(
            state.intake.admit().await,
            Err(ApiError::SupervisorUnavailable(_))
        ));

        // A second drain finds nothing left to do and writes nothing.
        let again = drain(&state, &reaped, StopSignal::Terminate, DRAIN_DEADLINE).await;
        assert!(
            again
                .pods
                .iter()
                .all(|(_, outcome)| *outcome == PodDrain::AlreadyReaped)
        );
        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert_eq!(
            log.lines()
                .filter(|l| l.contains("\"pod_drained\""))
                .count(),
            2
        );
    }
}
