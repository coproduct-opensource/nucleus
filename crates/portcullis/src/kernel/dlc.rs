//! DLC-D verified-admission gate for the kernel (feature `dlc`).
//!
//! Extracted from `kernel.rs` to keep that file under the line ratchet, in the
//! same shape as [`super::Kernel::decide_term_with_flow`]'s other consults: the
//! IFC gate (`kernel::ifc`) and the Cedar consult. Default-inert — a kernel
//! with no [`DlcAdmission`](crate::says_admission::DlcAdmission) provisioned
//! behaves exactly as before; once provisioned via
//! [`Kernel::set_dlc_admission`], every operation additionally requires a
//! valid issuer-signed says-credential for exactly that operation, decided by
//! DLC-D's proof-carrying PEP (fail-closed; see the `says_admission` module
//! docs for the trust boundary and the credential namespace).

use super::{Decision, DecisionToken, DenyReason, Kernel, Verdict};
use crate::exposure_core;
use crate::says_admission::DlcAdmission;
use crate::ActionTerm;

impl Kernel {
    /// Provision DLC-D admission: after this call, every decision through
    /// [`Kernel::decide_term_with_flow`](Kernel::decide_term_with_flow)
    /// additionally requires an issuer-signed credential for the operation
    /// (deny-narrowing — this can only refuse what the lattice/IFC/Cedar
    /// layers would otherwise allow, never widen).
    pub fn set_dlc_admission(&mut self, admission: DlcAdmission) {
        self.dlc_admission = Some(admission);
    }

    /// Consult the provisioned admission state. `None` when unprovisioned or
    /// admitted; `Some(deny_decision)` when the credential check refuses.
    pub(super) fn dlc_admission_gate(
        &mut self,
        term: &ActionTerm,
    ) -> Option<(Decision, Option<DecisionToken>)> {
        let admission = self.dlc_admission.as_ref()?;
        let operation = term.operation();
        let op_name = operation.to_string();
        let verdict = admission.decide_operation(&op_name);
        if verdict.is_admit() {
            return None;
        }
        let detail = match verdict {
            dlc_d::admission::Decision::Deny(reason) => reason.to_string(),
            dlc_d::admission::Decision::Admit => unreachable!("is_admit checked above"),
        };
        tracing::warn!(
            ?operation,
            subject = term.subject(),
            %detail,
            "DLC-D admission denied operation"
        );
        let pre_hash = self.effective.checksum();
        let pre_exposure_count = self.exposure.count();
        let contributed_label = exposure_core::classify_operation(operation);
        let subject = term.subject().to_string();
        let (mut decision, token) = self.record_with_exposure(
            operation,
            &subject,
            Verdict::Deny(DenyReason::DlcAdmissionDenied { detail }),
            &pre_hash,
            pre_exposure_count,
            contributed_label,
            false,
            false,
        );
        decision.action_term = Some(term.clone());
        if let Some(last) = self.trace.last_mut() {
            last.action_term = Some(term.clone());
        }
        Some((decision, token))
    }
}
