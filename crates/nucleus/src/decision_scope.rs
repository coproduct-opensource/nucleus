//! The decision must be about the operation being performed — in every profile.
//!
//! Thirty call sites in `command.rs` and `sandbox.rs` carried this check as
//!
//! ```ignore
//! debug_assert_eq!(decision.operation(), op, "DecisionToken operation mismatch");
//! ```
//!
//! `debug_assert_eq!` compiles to nothing when `debug_assertions` is off, which
//! is every release build — so in a shipped binary a `DecisionToken` minted for
//! `ReadFiles` and handed to a `RunBash` entry point was accepted exactly as
//! readily as the right one. The two paths were indistinguishable at the call
//! site (ADR 0007 I-3: the error path and the allow path may not share an exit
//! status), and the `decision` parameter had no consumer at all there
//! (ADR 0007 B-5: a declaration with no consumer is a defect).
//!
//! In a debug build it was not much better: `debug_assert_eq!` **panics**. A
//! mismatched token aborted the process rather than refusing the operation, so
//! neither profile did the thing a reference monitor is supposed to do.
//!
//! Thirty copies of one rule is also thirty chances for one of them to drift
//! (ADR 0007 G-1: if a fact is written twice, delete one; D-2: a safety-critical
//! check is not replicated per call site). This is the one copy.
//!
//! # What this does and does not claim
//!
//! This is a **defence in depth**, not the primary gate. The authority spend is
//! the enforcement: `Authority::spend_on` binds a discharged bundle to the
//! concrete act, and `Sandbox::spend_as` refuses an authority earned for a
//! different operation. What this adds is that the *decision the reference
//! monitor made upstream* is also about the operation now being performed, so a
//! caller cannot present a decision about one act while spending an authority
//! for another.

use portcullis::Operation;

use crate::error::NucleusError;

/// Refuse a decision that was made about a different operation.
///
/// Returns [`NucleusError::ScopeMismatch`] — the same class the authority spend
/// uses for "earned for a different action", because that is what this is.
///
/// Checked in every profile. That is the whole point; see the module docs.
pub(crate) fn require_decision_for(
    decision_op: Operation,
    performing: Operation,
) -> Result<(), NucleusError> {
    if decision_op == performing {
        return Ok(());
    }
    Err(NucleusError::ScopeMismatch {
        reason: format!("decision authorises {decision_op:?}, this effect is {performing:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_decision_is_accepted() {
        assert!(require_decision_for(Operation::RunBash, Operation::RunBash).is_ok());
    }

    /// THE regression. Under `debug_assert_eq!` this case PANICKED in a debug
    /// build and was SILENTLY ACCEPTED in a release one. It is now a refusal in
    /// both.
    #[test]
    fn a_decision_about_another_operation_is_refused() {
        let err = require_decision_for(Operation::ReadFiles, Operation::RunBash)
            .expect_err("a decision about ReadFiles must not authorise RunBash");
        assert!(
            matches!(err, NucleusError::ScopeMismatch { .. }),
            "a decision for the wrong operation is a scope mismatch, got {err:?}"
        );
    }

    /// The message has to name BOTH sides, or it sends the reader to inspect
    /// the wrong one. `15e3530f`'s lesson (ADR 0007 A-4) in a smaller place.
    #[test]
    fn the_refusal_names_what_was_held_and_what_was_attempted() {
        let err = require_decision_for(Operation::ReadFiles, Operation::RunBash)
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("ReadFiles"), "{msg}");
        assert!(msg.contains("RunBash"), "{msg}");
    }

    /// Non-vacuity: the refusal test above would pass against a function that
    /// refused everything. Every operation must authorise itself.
    #[test]
    fn every_operation_authorises_itself() {
        for op in Operation::ALL {
            assert!(
                require_decision_for(op, op).is_ok(),
                "{op:?} must authorise itself"
            );
        }
    }
}
