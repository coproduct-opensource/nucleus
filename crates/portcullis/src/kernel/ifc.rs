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
use crate::Operation;

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
