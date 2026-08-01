//! Runtime verification over the decision stream.
//!
//! # Why a monitor rather than another test
//!
//! Every wiring defect this codebase produced had the same shape: a verification
//! artifact attached to a *code shape* while the property was about an
//! *execution*. A test asserts a function returns X and is silent on whether it
//! is called. A lint asserts a path has a property and is silent when it cannot
//! see the path. Four times running, a test passed with the live call deleted.
//!
//! A monitor cannot fail that way. It observes what actually happened, so
//! "the handler never called this" is not something it can miss — the record
//! simply is not in the stream, and the absence is the finding.
//!
//! This is standard runtime verification (the Linux kernel ships an RV
//! subsystem; SpecMon does it for security protocols). What makes it cheap here
//! is that the trace already exists: `record_kernel_decision` has emitted one
//! record per kernel decision since #2127, and every terminal outcome is
//! recorded too. Nothing new has to be produced. This is the missing consumer.
//!
//! # What it is NOT
//!
//! * **Not a replacement for static checks.** A monitor only ever sees executed
//!   paths. An unmediated branch nobody took is invisible to it and visible to
//!   the `mediated` lint. The two cover different halves and neither subsumes
//!   the other.
//! * **Not fail-closed, yet.** Violations are recorded and exposed, not denied.
//!   Making a monitor refuse traffic is a real policy change and belongs behind
//!   its own flag, after the violation rate on real workloads is known. Shipping
//!   it fail-closed on day one would be the same mistake as a gate whose first
//!   run is green: nobody knows what it does yet.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::capability::Operation;
use crate::verdict_sink::{SinkError, VerdictContext, VerdictOutcome, VerdictSink};

/// A property of the decision stream that was violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// A terminal outcome was recorded for an operation with no preceding
    /// kernel decision. The effect happened; nothing authorised it on the
    /// record. This is the unmediated-effect defect, observed rather than
    /// statically inferred.
    OutcomeWithoutDecision {
        /// The operation whose effect was recorded unauthorised.
        operation: Operation,
    },
    /// Consecutive records disagree about the permission state: one record's
    /// `post_permissions_hash` is not the next one's `pre_permissions_hash`.
    /// Permissions changed outside the recorded path.
    PermissionDiscontinuity {
        /// The previous record's `post_permissions_hash`.
        expected: String,
        /// The next record's `pre_permissions_hash`, which should have matched.
        found: String,
    },
    /// The exposure count went DOWN. Exposure is a monotone ratchet; a decrease
    /// means it was reset by something that left no record.
    ExposureRegressed {
        /// The exposure count before.
        from: u8,
        /// The lower count observed after.
        to: u8,
    },
}

#[derive(Default)]
struct State {
    /// Operations for which a kernel decision has been seen and no terminal
    /// outcome yet.
    awaiting_outcome: BTreeSet<Operation>,
    last_post_hash: Option<String>,
    last_exposure: Option<u8>,
}

/// Wraps a sink and checks stream properties as records flow through it.
///
/// A wrapper rather than a parallel consumer on purpose: it sees exactly the
/// records the real sink sees, so it cannot drift out of sync with the thing it
/// is monitoring — which is the failure this whole exercise is about.
pub struct TraceMonitor {
    inner: Arc<dyn VerdictSink>,
    state: Mutex<State>,
    violations: Mutex<Vec<Violation>>,
}

impl TraceMonitor {
    /// Wrap a sink so the stream flowing through it is checked.
    pub fn new(inner: Arc<dyn VerdictSink>) -> Self {
        Self {
            inner,
            state: Mutex::new(State::default()),
            violations: Mutex::new(Vec::new()),
        }
    }

    /// Everything the monitor has observed to be wrong.
    pub fn violations(&self) -> Vec<Violation> {
        self.violations.lock().expect("monitor lock").clone()
    }

    fn flag(&self, v: Violation) {
        tracing::warn!(violation = ?v, "decision-stream property violated");
        self.violations.lock().expect("monitor lock").push(v);
    }

    /// A record carrying `decision_sequence` is a KERNEL DECISION (#2127);
    /// anything else is a terminal outcome recorded by a handler.
    fn is_kernel_decision(ctx: &VerdictContext) -> bool {
        ctx.extensions.contains_key("decision_sequence")
    }

    fn check(&self, ctx: &VerdictContext) {
        let mut st = self.state.lock().expect("monitor lock");

        // ── permission continuity ──────────────────────────────────────────
        if let (Some(prev), Some(pre)) = (
            st.last_post_hash.clone(),
            ctx.extensions.get("pre_permissions_hash"),
        ) {
            if &prev != pre {
                drop(st);
                self.flag(Violation::PermissionDiscontinuity {
                    expected: prev,
                    found: pre.clone(),
                });
                st = self.state.lock().expect("monitor lock");
            }
        }
        if let Some(post) = ctx.extensions.get("post_permissions_hash") {
            st.last_post_hash = Some(post.clone());
        }

        // ── exposure is a ratchet ──────────────────────────────────────────
        if let Some(now) = ctx
            .extensions
            .get("exposure_post")
            .and_then(|v| v.parse::<u8>().ok())
        {
            if let Some(before) = st.last_exposure {
                if now < before {
                    drop(st);
                    self.flag(Violation::ExposureRegressed {
                        from: before,
                        to: now,
                    });
                    st = self.state.lock().expect("monitor lock");
                }
            }
            st.last_exposure = Some(now);
        }

        // ── mediation: an outcome needs a decision before it ────────────────
        if Self::is_kernel_decision(ctx) {
            // Only an ALLOW leads to an effect; a refusal ends the story.
            if matches!(ctx.outcome, VerdictOutcome::Allow) {
                st.awaiting_outcome.insert(ctx.operation);
            }
        } else if matches!(ctx.outcome, VerdictOutcome::Allow)
            && !st.awaiting_outcome.remove(&ctx.operation)
        {
            // Only an ALLOWED outcome implies an effect occurred. A refusal
            // recorded with no preceding decision is CORRECT and common: several
            // handlers reject on input validation before ever consulting the
            // kernel (`validate_path`, main.rs:2582/2724), and nothing happened.
            // Flagging those would have made the monitor's first deployment
            // noise, which is how a real signal gets ignored.
            drop(st);
            self.flag(Violation::OutcomeWithoutDecision {
                operation: ctx.operation,
            });
        } else {
            // A refusal consumes any pending authorisation: the decision allowed
            // it, the handler declined to proceed. Not a violation, but the
            // authorisation is spent either way.
            st.awaiting_outcome.remove(&ctx.operation);
        }
    }
}

impl VerdictSink for TraceMonitor {
    fn record(&self, ctx: VerdictContext) -> Result<(), SinkError> {
        self.check(&ctx);
        // Delegate unchanged. The monitor observes; it does not decide. Making
        // it refuse is a separate, flagged change.
        self.inner.record(ctx)
    }

    fn preflight(&self, operation: Operation) -> Result<(), SinkError> {
        self.inner.preflight(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict_sink::ActorIdentity;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct NullSink;
    impl VerdictSink for NullSink {
        fn record(&self, _ctx: VerdictContext) -> Result<(), SinkError> {
            Ok(())
        }
        fn preflight(&self, _op: Operation) -> Result<(), SinkError> {
            Ok(())
        }
    }

    fn monitor() -> TraceMonitor {
        TraceMonitor::new(Arc::new(NullSink))
    }

    fn decision(op: Operation, pre: &str, post: &str, exposure: u8) -> VerdictContext {
        let mut extensions = BTreeMap::new();
        extensions.insert("decision_sequence".into(), "1".into());
        extensions.insert("pre_permissions_hash".into(), pre.into());
        extensions.insert("post_permissions_hash".into(), post.into());
        extensions.insert("exposure_post".into(), exposure.to_string());
        VerdictContext {
            operation: op,
            subject: "s".into(),
            outcome: VerdictOutcome::Allow,
            actor: ActorIdentity::Unknown,
            policy_rule: None,
            extensions,
        }
    }

    fn outcome(op: Operation) -> VerdictContext {
        VerdictContext {
            operation: op,
            subject: "s".into(),
            outcome: VerdictOutcome::Allow,
            actor: ActorIdentity::Unknown,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }
    }

    /// A well-formed trace produces no findings. Without this the monitor could
    /// flag everything and the tests below would still pass.
    #[test]
    fn a_well_formed_trace_is_clean() {
        let m = monitor();
        m.record(decision(Operation::ReadFiles, "h0", "h1", 1))
            .unwrap();
        m.record(outcome(Operation::ReadFiles)).unwrap();
        m.record(decision(Operation::WriteFiles, "h1", "h2", 2))
            .unwrap();
        m.record(outcome(Operation::WriteFiles)).unwrap();
        assert!(m.violations().is_empty(), "{:?}", m.violations());
    }

    /// **The defect this exists to catch.** An effect recorded with nothing
    /// authorising it — the unmediated path, observed rather than inferred.
    #[test]
    fn an_outcome_with_no_decision_is_flagged() {
        let m = monitor();
        m.record(outcome(Operation::RunBash)).unwrap();
        assert_eq!(
            m.violations(),
            vec![Violation::OutcomeWithoutDecision {
                operation: Operation::RunBash
            }]
        );
    }

    /// A decision authorises ONE outcome. A second effect on the same authority
    /// is unmediated too — this is the linearity the `Authority` type enforces
    /// at compile time, checked here against what actually ran.
    #[test]
    fn a_second_outcome_on_one_decision_is_flagged() {
        let m = monitor();
        m.record(decision(Operation::WriteFiles, "h0", "h1", 1))
            .unwrap();
        m.record(outcome(Operation::WriteFiles)).unwrap();
        m.record(outcome(Operation::WriteFiles)).unwrap();
        assert_eq!(m.violations().len(), 1, "{:?}", m.violations());
    }

    /// **The false positive that would have made deployment noise.** Handlers
    /// reject on input validation BEFORE consulting the kernel, recording a
    /// refusal with no preceding decision. Nothing happened, so nothing is
    /// wrong — and a monitor that cried wolf here would be ignored by the time
    /// it saw something real.
    #[test]
    fn a_refusal_with_no_decision_is_not_a_violation() {
        let m = monitor();
        let mut rejected = outcome(Operation::ReadFiles);
        rejected.outcome = VerdictOutcome::Deny {
            reason: "validation: bad path".into(),
        };
        m.record(rejected).unwrap();
        assert!(m.violations().is_empty(), "{:?}", m.violations());
    }

    /// Permissions changed outside the recorded path.
    #[test]
    fn a_permission_discontinuity_is_flagged() {
        let m = monitor();
        m.record(decision(Operation::ReadFiles, "h0", "h1", 1))
            .unwrap();
        m.record(decision(Operation::ReadFiles, "SOMETHING_ELSE", "h2", 1))
            .unwrap();
        assert!(
            m.violations()
                .iter()
                .any(|v| matches!(v, Violation::PermissionDiscontinuity { .. })),
            "{:?}",
            m.violations()
        );
    }

    /// Exposure is a monotone ratchet; a decrease means an unrecorded reset.
    #[test]
    fn an_exposure_regression_is_flagged() {
        let m = monitor();
        m.record(decision(Operation::ReadFiles, "h0", "h1", 3))
            .unwrap();
        m.record(decision(Operation::ReadFiles, "h1", "h2", 1))
            .unwrap();
        assert!(
            m.violations()
                .iter()
                .any(|v| matches!(v, Violation::ExposureRegressed { from: 3, to: 1 })),
            "{:?}",
            m.violations()
        );
    }

    /// A REFUSAL authorises nothing, so no outcome should follow it — and if one
    /// does, that is an effect which happened despite being denied.
    #[test]
    fn an_outcome_after_a_refusal_is_flagged() {
        let m = monitor();
        let mut denied = decision(Operation::WriteFiles, "h0", "h1", 1);
        denied.outcome = VerdictOutcome::Deny {
            reason: "ifc".into(),
        };
        m.record(denied).unwrap();
        m.record(outcome(Operation::WriteFiles)).unwrap();
        assert_eq!(
            m.violations(),
            vec![Violation::OutcomeWithoutDecision {
                operation: Operation::WriteFiles
            }]
        );
    }

    /// The monitor must not swallow the sink's behaviour: a locked inner sink
    /// still refuses through the wrapper.
    #[test]
    fn the_wrapper_delegates_refusals() {
        struct LockedSink;
        impl VerdictSink for LockedSink {
            fn record(&self, _c: VerdictContext) -> Result<(), SinkError> {
                Err(SinkError::Locked)
            }
            fn preflight(&self, _o: Operation) -> Result<(), SinkError> {
                Err(SinkError::Locked)
            }
        }
        let m = TraceMonitor::new(Arc::new(LockedSink));
        assert!(m.record(outcome(Operation::ReadFiles)).is_err());
        assert!(m.preflight(Operation::ReadFiles).is_err());
    }
}
