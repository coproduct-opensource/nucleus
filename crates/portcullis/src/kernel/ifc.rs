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

use portcullis_core::ifc_api::FlowTracker;

use super::{Decision, DecisionToken, DenyReason, Kernel, Verdict};
use crate::exposure_core;
use crate::ActionTerm;

impl Kernel {
    /// Consult the session flow tracker. Returns `Some(deny_decision)` if the
    /// IFC gate denies the action, or `None` to fall through to the normal
    /// decision path. `flow == None` ⇒ always `None` (backward compatible).
    pub(super) fn ifc_flow_gate(
        &mut self,
        term: &ActionTerm,
        flow: Option<&FlowTracker>,
    ) -> Option<(Decision, Option<DecisionToken>)> {
        let flow = flow?;
        let operation = term.operation();

        // Fail-closed poison gate (#3): a dropped observation makes the taint
        // state unprovable, so deny EVERY operation (not just outbound).
        if flow.is_poisoned() {
            tracing::warn!(
                ?operation,
                subject = term.subject(),
                "IFC denied: session poisoned (a flow observation was dropped)"
            );
            return Some(
                self.ifc_deny(
                    term.clone(),
                    "session poisoned: an information-flow observation was dropped; \
                 failing closed to prevent untracked taint"
                        .to_string(),
                ),
            );
        }

        // Egress gate (#1633 / most-paranoid #4): deny outbound operations when
        // the session is integrity-tainted OR its confidentiality ceiling exceeds
        // what the sink may emit (secret exfiltration). The combined
        // integrity+confidentiality check lives in `exposure_core`.
        let kind = Kernel::node_kind_for(operation);
        if let Some(detail) = exposure_core::ifc_egress_denial(flow, operation, kind) {
            tracing::warn!(
                ?operation,
                subject = term.subject(),
                %detail,
                "IFC denied outbound action"
            );
            return Some(self.ifc_deny(term.clone(), detail));
        }

        None
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
