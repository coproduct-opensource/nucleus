//! Information-flow control gate for the kernel (most-paranoid #1/#3).
//!
//! Extracted from `kernel.rs` to keep that file under the line ratchet. Provides
//! the fail-closed gate consulted at the top of
//! [`Kernel::decide_term_with_flow`](super::Kernel::decide_term_with_flow):
//!
//! - **Poison gate (#3):** if an upstream `observe()` dropped a node, the
//!   session's taint state is unprovable, so EVERY operation is denied until a
//!   human-authorized cleanse.
//! - **Egress gate (#1633 / #4):** once adversarial (web) content is in the
//!   session, OR the session's confidentiality ceiling exceeds what a sink may
//!   emit, outbound actions are denied to prevent exfiltration.

use super::{Decision, DecisionToken, DenyReason, Kernel, Verdict};
use crate::exposure_core;
use crate::exposure_core::EgressAggregates;
use crate::ActionTerm;
use crate::CapabilityLevel;
use crate::Operation;

/// The sinks a taint may be held at rather than refused: those whose only way
/// out of a pod is an effect the host performs after an operator approves
/// that exact request by its digest (a push, a pull request). Every other
/// outbound operation — a file write, a shell, a sub-agent — has no approval
/// that can bind what it does, so it keeps the abort-only rule, and
/// [`Kernel::decide_effect_with_flow`] decides it exactly as
/// [`Kernel::decide_term_with_flow`] does. That is what lets the host decide
/// every shadowed guest call with the effect decider and still agree with the
/// guest's tool calls.
const ACTION_BOUND_SINKS: [Operation; 2] = [Operation::GitPush, Operation::CreatePr];

/// What a decision does with an action whose every check passes but whose
/// session carries an integrity taint. Private to the kernel: the only way to
/// ask for a hold is [`Kernel::decide_effect_with_flow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TaintExit {
    /// The IFC gate has already run; nothing is held.
    Closed,
    /// Hold it as `RequiresApproval`, which no count of pre-granted approvals
    /// can discharge: only an approval of this one action can (#3255).
    ActionBoundApproval,
}

/// The kernel held this action for approval because the session carries an
/// integrity taint, and for no other reason. Minted only by
/// [`Kernel::decide_effect_with_flow`]; neither `Clone` nor constructible
/// outside the kernel, so a record of a declassification is always backed by
/// the decision that called for one (ADR 0007 C-1).
///
/// Evidence, not a right: it authorizes nothing, and no `#[must_use]` here
/// pretends otherwise. The right is the operator's approval, which is one-shot
/// and expires, and which the host consumes by value with this hold.
#[derive(Debug, PartialEq, Eq)]
pub struct TaintHold {
    operation: Operation,
}

impl TaintHold {
    /// The sink the tainted session's data would reach.
    pub fn operation(&self) -> Operation {
        self.operation
    }
}

/// [`Kernel::decide_effect_with_flow`]'s answer: the decision, its token when
/// allowed, and the taint hold when it was held for one.
#[derive(Debug)]
pub struct EffectDecision {
    /// The recorded decision.
    pub decision: Decision,
    /// `Some` only when the verdict is `Allow`.
    pub token: Option<DecisionToken>,
    /// `Some` only when the verdict is `RequiresApproval` because of a taint.
    pub hold: Option<TaintHold>,
}

/// Clock-free verdict used by the live gate. Environment policy is an explicit
/// input; decision recording remains in `Kernel::ifc_flow_gate`.
fn ifc_flow_gate<F: EgressAggregates + ?Sized>(
    flow: &F,
    operation: Operation,
    graded: bool,
) -> exposure_core::EgressDisposition {
    if flow.is_poisoned() {
        return exposure_core::EgressDisposition::Poisoned;
    }
    exposure_core::ifc_egress_disposition(flow, operation, Kernel::node_kind_for(operation), graded)
}

impl Kernel {
    /// Extract source and artifact labels for policy rule evaluation.
    ///
    /// Reads the cached flow label (derived from graph state). When flow
    /// control is enabled, uses the cache as both source and artifact label.
    /// Otherwise returns empty sources and a bottom label (which causes
    /// source predicates to be vacuously true and artifact predicates to
    /// match permissively).
    pub(super) fn policy_flow_labels(
        &self,
    ) -> (Vec<portcullis_core::IFCLabel>, portcullis_core::IFCLabel) {
        if let Some(ref label) = self.flow_label {
            // Cached label (derived from graph): use as both source and artifact.
            (vec![*label], *label)
        } else {
            // No flow control — use bottom label (most permissive).
            let now = chrono::Utc::now().timestamp() as u64;
            let bottom = portcullis_core::IFCLabel::user_prompt(now);
            (vec![], bottom)
        }
    }

    /// Map an Operation to the most appropriate FlowNode kind.
    /// (Moved here from `kernel.rs` for the line ratchet; used by the IFC gate
    /// below and by `decide`'s intrinsic-label path.)
    pub(super) fn node_kind_for(op: Operation) -> portcullis_core::flow::NodeKind {
        use portcullis_core::flow::NodeKind;
        match op {
            Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
                NodeKind::FileRead
            }
            Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
            Operation::WriteFiles | Operation::EditFiles => NodeKind::OutboundAction,
            Operation::RunBash
            | Operation::GitCommit
            | Operation::GitPush
            | Operation::CreatePr
            | Operation::ManagePods
            | Operation::SpawnAgent => NodeKind::OutboundAction,
        }
    }

    /// Consult the session flow tracker. Returns `Some(deny_decision)` if the
    /// IFC gate denies the action, or `None` to fall through to the normal
    /// decision path. `flow == None` ⇒ always `None` (backward compatible).
    pub(super) fn ifc_flow_gate<F: EgressAggregates + ?Sized>(
        &mut self,
        term: &ActionTerm,
        flow: Option<&F>,
    ) -> Option<(Decision, Option<DecisionToken>)> {
        let flow = flow?;
        let operation = term.operation();

        match ifc_flow_gate(flow, operation, Self::graded_taint_enabled()).render(operation) {
            exposure_core::EgressVerdict::Deny(detail) => {
                tracing::warn!(
                    ?operation,
                    subject = term.subject(),
                    %detail,
                    "IFC denied action"
                );
                Some(self.ifc_deny(term.clone(), detail))
            }
            exposure_core::EgressVerdict::RequireApproval(detail) => {
                tracing::info!(
                    ?operation,
                    subject = term.subject(),
                    %detail,
                    "IFC deferred outbound action to human approval"
                );
                Some(self.ifc_requires_approval(term.clone(), detail))
            }
            exposure_core::EgressVerdict::Pass => None,
        }
    }

    /// [`Self::decide_term_with_flow`] for an effect that is performed only
    /// after an operator approves that one request by its digest — a push the
    /// host performs, say (#3255).
    ///
    /// The one difference: a push or pull request ([`ACTION_BOUND_SINKS`])
    /// refused ONLY for an integrity taint, under a profile whose capability
    /// for it is not `Never`, is held
    /// as `RequiresApproval` (with a [`TaintHold`]) instead of refused. Every
    /// other check still runs and still refuses — capability, path, egress
    /// policy, sink scope, Cedar — so a hold is never wider than what the
    /// profile grants a clean session. Poison and a confidentiality ceiling
    /// above the sink still refuse; under `Never` the decision is exactly
    /// [`Self::decide_term_with_flow`]'s. The guest's broker submission and the
    /// host's effect authorization both call this, so they cannot disagree
    /// about which flows have an exit (ADR 0007 G-1).
    ///
    /// The hold is APPA's recoverable information-flow control ("Recoverable
    /// Information-Flow Control for Real-World LLM Agents", arXiv 2607.24625):
    /// abort-only IFC with a human-approved, policy-governed exit.
    pub fn decide_effect_with_flow<F: EgressAggregates + ?Sized>(
        &mut self,
        term: ActionTerm,
        flow: Option<&F>,
    ) -> EffectDecision {
        let operation = term.operation();
        let held = ACTION_BOUND_SINKS.contains(&operation)
            && flow.is_some_and(|flow| {
                !flow.is_poisoned()
                    && exposure_core::action_bound_egress_disposition(
                        flow,
                        operation,
                        Self::node_kind_for(operation),
                    ) == exposure_core::EgressDisposition::TaintedApproval
            })
            && self.effective.capabilities.level_for(operation) != CapabilityLevel::Never;
        if !held {
            let (decision, token) = self.decide_term_with_flow(term, flow);
            return EffectDecision {
                decision,
                token,
                hold: None,
            };
        }
        tracing::info!(
            ?operation,
            subject = term.subject(),
            "IFC held a tainted outbound action for an approval of that action"
        );
        let (decision, token) = self.decide_term_past_flow(term, TaintExit::ActionBoundApproval);
        let hold = match decision.verdict {
            Verdict::RequiresApproval => Some(TaintHold { operation }),
            Verdict::Allow | Verdict::Deny(_) => None,
        };
        EffectDecision {
            decision,
            token,
            hold,
        }
    }

    /// Everything [`Self::decide_term_with_flow`] runs after its IFC gate.
    pub(super) fn decide_term_past_flow(
        &mut self,
        term: ActionTerm,
        exit: TaintExit,
    ) -> (Decision, Option<DecisionToken>) {
        // DLC-D verified admission (`kernel::dlc`): deny-narrowing, inert
        // until `set_dlc_admission` provisions credentials.
        #[cfg(feature = "dlc")]
        if let Some(denied) = self.dlc_admission_gate(&term) {
            return denied;
        }

        // Only the Cedar consult below uses `operation`; bind it under the same
        // cfg so non-cedar feature combos don't trip `-D unused-variables`.
        #[cfg(feature = "cedar")]
        let operation = term.operation();

        // Cedar policy consult (#1634): after the IFC check, if a Cedar policy is
        // loaded, deny any operation Cedar does not `permit`. Uses the session's
        // current flow label (integrity/authority/confidentiality) as context.
        // No policy loaded ⇒ skipped entirely (default-on feature is inert here).
        #[cfg(feature = "cedar")]
        if let Some(ref cedar) = self.cedar_evaluator {
            let label = self.flow_label.unwrap_or_else(|| {
                portcullis_core::IFCLabel::user_prompt(chrono::Utc::now().timestamp() as u64)
            });
            let subject = term.subject().to_string();
            let result = cedar.evaluate(
                &self.session_id.to_string(),
                operation,
                &subject,
                label.integrity,
                label.authority,
                label.confidentiality,
            );
            if !result.is_allowed() {
                let pre_hash = self.effective.checksum();
                let pre_exposure_count = self.exposure.count();
                let contributed_label = exposure_core::classify_operation(operation);
                let detail = if result.reasons.is_empty() {
                    "no matching Cedar `permit` rule (default deny)".to_string()
                } else {
                    result.reasons.join(", ")
                };
                tracing::warn!(?operation, subject, %detail, "Cedar denied operation");
                let (mut decision, token) = self.record_with_exposure(
                    operation,
                    &subject,
                    Verdict::Deny(DenyReason::CedarDenied { detail }),
                    &pre_hash,
                    pre_exposure_count,
                    contributed_label,
                    false,
                    false,
                );
                decision.action_term = Some(term.clone());
                if let Some(last) = self.trace.last_mut() {
                    last.action_term = Some(term);
                }
                return (decision, token);
            }
        }

        self.decide_term_held(term, exit)
    }

    /// Whether the graded taint response (Option C) is enabled.
    ///
    /// Default OFF. Read from the environment at each decision rather than
    /// cached, so flipping it is a config change with no restart and rolling it
    /// back is the same — this is the only switch here that can permit something
    /// previously refused, so it stays as reversible as possible.
    fn graded_taint_enabled() -> bool {
        std::env::var("NUCLEUS_GRADED_TAINT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Shared IFC deferral path: records a `RequiresApproval` decision so the
    /// operation can be unblocked through `/v1/approve` (nonce-checked,
    /// expiry-bounded) instead of dying at an opaque refusal — and so the
    /// deferral lands in the Article 12 record as Article 14 human oversight.
    fn ifc_requires_approval(
        &mut self,
        term: ActionTerm,
        _detail: String,
    ) -> (Decision, Option<DecisionToken>) {
        let operation = term.operation();
        let subject = term.subject().to_string();
        let pre_hash = self.effective.checksum();
        let pre_exposure_count = self.exposure.count();
        let contributed_label = exposure_core::classify_operation(operation);
        let (mut decision, token) = self.record_with_exposure(
            operation,
            &subject,
            Verdict::RequiresApproval,
            &pre_hash,
            pre_exposure_count,
            contributed_label,
            false,
            // This IS a dynamic gate: the deferral is caused by accumulated
            // session state, not by a static obligation in the lattice.
            true,
        );
        decision.action_term = Some(term.clone());
        if let Some(last) = self.trace.last_mut() {
            last.action_term = Some(term);
        }
        (decision, token)
    }

    /// Shared IFC denial path: records a `Deny(IfcUnsafe { detail })` decision
    /// with exposure accounting and stamps the action term onto the decision and
    /// the trace entry.
    fn ifc_deny(&mut self, term: ActionTerm, detail: String) -> (Decision, Option<DecisionToken>) {
        let operation = term.operation();
        let subject = term.subject().to_string();
        let pre_hash = self.effective.checksum();
        let pre_exposure_count = self.exposure.count();
        let contributed_label = exposure_core::classify_operation(operation);
        let (mut decision, token) = self.record_with_exposure(
            operation,
            &subject,
            Verdict::Deny(DenyReason::IfcUnsafe { detail }),
            &pre_hash,
            pre_exposure_count,
            contributed_label,
            false,
            false,
        );
        decision.action_term = Some(term.clone());
        if let Some(last) = self.trace.last_mut() {
            last.action_term = Some(term);
        }
        (decision, token)
    }
}

#[cfg(test)]
mod effect_hold_tests {
    use super::*;
    use crate::flow_graph::FlowGraph;
    use crate::PermissionLattice;
    use portcullis_core::flow::NodeKind;

    const REMOTE: &str = "https://forge.invalid/org/repo.git/git-receive-pack";

    fn graph(kinds: &[NodeKind]) -> FlowGraph {
        let mut g = FlowGraph::new();
        for kind in kinds {
            g.insert_observation(*kind, &[], 1).unwrap();
        }
        g
    }

    fn term() -> ActionTerm {
        ActionTerm::from_operation(Operation::GitPush, REMOTE)
    }

    fn push(policy: PermissionLattice, flow: &FlowGraph) -> EffectDecision {
        Kernel::new(policy).decide_effect_with_flow(term(), Some(flow))
    }

    /// The governed exit: a push from a session that read untrusted content
    /// is held for approval — never allowed, never refused outright.
    #[test]
    fn a_tainted_push_is_held_not_refused() {
        let tainted = graph(&[NodeKind::WebContent]);
        let held = push(PermissionLattice::permissive(), &tainted);
        assert_eq!(held.decision.verdict, Verdict::RequiresApproval);
        assert!(held.token.is_none());
        assert_eq!(held.hold.map(|h| h.operation()), Some(Operation::GitPush));
        // The flow rule itself is unchanged: the abort-only entry still refuses.
        let (refused, _) = Kernel::new(PermissionLattice::permissive())
            .decide_term_with_flow(term(), Some(&tainted));
        assert!(matches!(
            refused.verdict,
            Verdict::Deny(DenyReason::IfcUnsafe { .. })
        ));
    }

    /// A clean session is decided exactly as before.
    #[test]
    fn a_clean_push_is_unchanged() {
        let clean = FlowGraph::new();
        let effect = push(PermissionLattice::permissive(), &clean);
        let (plain, _) = Kernel::new(PermissionLattice::permissive())
            .decide_term_with_flow(term(), Some(&clean));
        assert_eq!(effect.decision.verdict, plain.verdict);
        assert!(effect.hold.is_none(), "nothing to declassify");
    }

    /// Under `Never` there is no exit: the refusal is the flow refusal it was.
    #[test]
    fn under_never_a_tainted_push_stays_refused() {
        let mut never = PermissionLattice::permissive();
        never.capabilities.git_push = CapabilityLevel::Never;
        let refused = push(never, &graph(&[NodeKind::WebContent]));
        assert!(matches!(
            refused.decision.verdict,
            Verdict::Deny(DenyReason::IfcUnsafe { .. })
        ));
        assert!(refused.hold.is_none());
    }

    /// Only the integrity taint is held. A secret-bearing session, a poisoned
    /// one, and a push some other check refuses all stay refused.
    #[test]
    fn confidentiality_poison_and_other_refusals_are_never_held() {
        let secret = push(
            PermissionLattice::permissive(),
            &graph(&[NodeKind::WebContent, NodeKind::Secret]),
        );
        assert!(secret.decision.verdict.is_denied());
        assert!(secret.hold.is_none());
        let mut poisoned = graph(&[NodeKind::WebContent]);
        poisoned.poison();
        assert!(push(PermissionLattice::permissive(), &poisoned)
            .decision
            .verdict
            .is_denied());
        let mut broke = PermissionLattice::permissive();
        broke.budget.max_cost_usd = rust_decimal::Decimal::ZERO;
        let refused = push(broke, &graph(&[NodeKind::WebContent]));
        assert!(matches!(
            refused.decision.verdict,
            Verdict::Deny(DenyReason::BudgetExhausted { .. })
        ));
        assert!(refused.hold.is_none());
    }

    /// Every other operation is decided exactly as the abort-only entry
    /// decides it: no approval can bind a file write or a shell.
    #[test]
    fn only_action_bound_sinks_are_ever_held() {
        let tainted = graph(&[NodeKind::WebContent]);
        for op in Operation::ALL {
            let mut a = Kernel::new(PermissionLattice::permissive());
            let mut b = Kernel::new(PermissionLattice::permissive());
            let effect =
                a.decide_effect_with_flow(ActionTerm::from_operation(op, "s"), Some(&tainted));
            let (plain, _) =
                b.decide_term_with_flow(ActionTerm::from_operation(op, "s"), Some(&tainted));
            if ACTION_BOUND_SINKS.contains(&op) {
                assert_eq!(effect.decision.verdict, Verdict::RequiresApproval, "{op:?}");
                assert!(plain.verdict.is_denied(), "{op:?}");
            } else {
                assert_eq!(effect.decision.verdict, plain.verdict, "{op:?}");
                assert!(effect.hold.is_none(), "{op:?}");
            }
        }
    }

    /// A count of pre-granted approvals is not an approval of THIS action, so
    /// it never discharges a taint hold.
    #[test]
    fn pre_granted_approvals_do_not_discharge_a_hold() {
        let mut kernel = Kernel::new(PermissionLattice::permissive());
        kernel.grant_approval(Operation::GitPush, 8);
        let tainted = graph(&[NodeKind::WebContent]);
        for _ in 0..2 {
            let held = kernel.decide_effect_with_flow(term(), Some(&tainted));
            assert_eq!(held.decision.verdict, Verdict::RequiresApproval);
            assert!(held.token.is_none());
        }
    }
}

#[cfg(kani)]
mod flow_gate_proofs {
    use super::*;
    use portcullis_core::{ifc_api::SafetyCheck, ConfLevel};

    struct Labels {
        poisoned: bool,
        tainted: bool,
        confidentiality: ConfLevel,
    }

    impl EgressAggregates for Labels {
        fn is_poisoned(&self) -> bool {
            self.poisoned
        }
        fn is_tainted(&self) -> bool {
            self.tainted
        }
        fn session_exfiltration_check(&self, cap: ConfLevel) -> SafetyCheck {
            if self.confidentiality > cap {
                SafetyCheck::ConfidentialityViolation {
                    data_conf: self.confidentiality,
                    sink_max_conf: cap,
                }
            } else {
                SafetyCheck::Safe
            }
        }
    }

    /// Default (ungraded) IFC policy: poison always rejects, outbound taint
    /// rejects, and external sinks cannot carry a secret session ceiling.
    #[kani::proof]
    #[kani::unwind(16)]
    fn proof_ifc_flow_gate_rejects_iff_forbidden() {
        let index: u8 = kani::any();
        kani::assume((index as usize) < Operation::ALL.len());
        let op = Operation::ALL[index as usize];
        let conf: u8 = kani::any();
        kani::assume(conf < 3);
        let labels = Labels {
            poisoned: kani::any(),
            tainted: kani::any(),
            confidentiality: match conf {
                0 => ConfLevel::Public,
                1 => ConfLevel::Internal,
                _ => ConfLevel::Secret,
            },
        };
        let outbound = !matches!(
            op,
            Operation::ReadFiles
                | Operation::GlobSearch
                | Operation::GrepSearch
                | Operation::WebFetch
                | Operation::WebSearch
        );
        let external = matches!(
            op,
            Operation::GitPush
                | Operation::CreatePr
                | Operation::SpawnAgent
                | Operation::ManagePods
                | Operation::WebFetch
                | Operation::WebSearch
        );
        let forbidden = labels.poisoned
            || (outbound && labels.tainted)
            || (external && labels.confidentiality == ConfLevel::Secret);
        let verdict = ifc_flow_gate(&labels, op, false);
        assert_eq!(
            matches!(
                verdict,
                exposure_core::EgressDisposition::Poisoned
                    | exposure_core::EgressDisposition::Tainted
                    | exposure_core::EgressDisposition::Confidentiality
            ),
            forbidden
        );
        assert!(!matches!(
            verdict,
            exposure_core::EgressDisposition::TaintedApproval
        ));
        kani::cover!(forbidden, "forbidden labels reach denial");
        kani::cover!(!forbidden, "permitted labels reach fallthrough");
    }
}
