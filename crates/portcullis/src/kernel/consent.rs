//! Two-phase consent for [`Kernel::decide`](super::Kernel::decide) (#3443).
//!
//! A decision can be held for a person's consent at more than one step: a
//! policy rule (step 3d), a lattice obligation (step 7), and the dynamic
//! exposure gate. Each of those used to SPEND a pre-granted approval the
//! moment it found one, and the decision then went on to run checks that can
//! refuse — path, command, sink scope, the action-bound hold, the exposure
//! gate. A refused operation left the person's consent spent and the effect
//! unperformed.
//!
//! So consent is collected in two phases:
//!
//! 1. [`Kernel::reserve`] LOOKS. It records which gate asked and reports
//!    whether the approvals on file cover every gate asked so far. It spends
//!    nothing.
//! 2. [`Kernel::record_allow`] is the only place a decision becomes `Allow`,
//!    and it takes the [`ConsentDraw`] BY VALUE (ADR 0007 C-4) and spends it
//!    in one step. A refusal never reaches it, so it drops the draw, and a
//!    dropped draw spends nothing.
//!
//! The contract the gates share:
//!
//! - **One question, one approval.** A policy rule and a lattice obligation
//!   both ask "does the policy say a person must approve this operation?".
//!   Asked twice, it is still one consent and spends one approval.
//! - **The exposure gate is its own question.** A static approval says the
//!   operation may happen. It does not say the operation may complete the
//!   uninhabitable state. An exfil the gate holds needs a second approval,
//!   so an obligated exfil inside the uninhabitable state needs two.
//!
//! Extracted from `kernel.rs` for the line ratchet, as a child module so it can
//! reach the kernel's private fields.

use super::{Decision, DecisionToken, Kernel, Verdict};
use crate::exposure_core;
use crate::guard::ExposureLabel;
use crate::Operation;

/// A step that holds an operation for a person's consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConsentGate {
    /// The policy says a person must approve this operation: a policy rule
    /// (step 3d) or a lattice obligation (step 7). One question, however many
    /// steps ask it.
    Policy,
    /// The dynamic exposure gate: this exfil would complete, or runs inside,
    /// the uninhabitable state.
    Exposure,
}

/// The approvals a decision has found on file and not yet spent.
///
/// Neither `Clone` nor `Copy`, and spent only by value through
/// [`Kernel::record_allow`]. There is no other way to decrement the kernel's
/// approvals during a decision, so "spent only on `Allow`" is a property of
/// the call graph rather than of every early return remembering it.
#[derive(Debug)]
pub(super) struct ConsentDraw {
    operation: Operation,
    policy: bool,
    exposure: bool,
}

impl ConsentDraw {
    /// Nothing asked yet.
    pub(super) fn new(operation: Operation) -> Self {
        Self {
            operation,
            policy: false,
            exposure: false,
        }
    }

    /// How many approvals this draw spends: one per distinct gate that asked.
    fn units(&self) -> u32 {
        u32::from(self.policy) + u32::from(self.exposure)
    }
}

impl Kernel {
    /// Phase one: `gate` asks for consent on `draw`'s operation.
    ///
    /// Returns whether the approvals on file cover every gate the draw now
    /// names. Spends nothing.
    pub(super) fn reserve(&self, draw: &mut ConsentDraw, gate: ConsentGate) -> bool {
        match gate {
            ConsentGate::Policy => draw.policy = true,
            ConsentGate::Exposure => draw.exposure = true,
        }
        let on_file = self.approvals.get(&draw.operation).copied().unwrap_or(0);
        on_file >= draw.units()
    }

    /// Phase two, and the decision's only `Allow`: spend `draw`, record the
    /// operation's exposure, and record the decision.
    pub(super) fn record_allow(
        &mut self,
        draw: ConsentDraw,
        subject: &str,
        pre_hash: &str,
        pre_exposure_count: u8,
        contributed_label: Option<ExposureLabel>,
        dynamic_gate_applied: bool,
    ) -> (Decision, Option<DecisionToken>) {
        let operation = draw.operation;
        let units = draw.units();
        if units > 0 {
            // `reserve` saw at least `units` on file, and nothing between it
            // and here grants or spends (the kernel is `&mut self` throughout).
            if let Some(count) = self.approvals.get_mut(&operation) {
                *count = count.saturating_sub(units);
            }
        }
        let pre_complete = self.exposure.is_uninhabitable();
        self.exposure = exposure_core::apply_record(&self.exposure, operation);
        let newly_completed = !pre_complete && self.exposure.is_uninhabitable();
        self.record_with_exposure(
            operation,
            subject,
            Verdict::Allow,
            pre_hash,
            pre_exposure_count,
            contributed_label,
            newly_completed,
            dynamic_gate_applied,
        )
    }
}
