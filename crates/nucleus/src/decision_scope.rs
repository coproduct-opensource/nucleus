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

use crate::error::NucleusError;

/// Refuse a decision that was made about a different operation.
///
/// Returns [`NucleusError::ScopeMismatch`] — the same class the authority spend
/// uses for "earned for a different action", because that is what this is.
///
/// Checked in every profile. That is the whole point; see the module docs.
/// A refused redeem becomes a scope mismatch.
///
/// Both variants are the same kind of failure to a caller — the decision does
/// not authorise this effect — and the message says which kind it was.
///
/// # Why this module is now three lines
///
/// It used to hold `require_decision_for`, which compared two `Operation`s and
/// consulted no state, and callers were trusted to also compare permissions.
/// They mostly did not: 24 of the 30 redeem sites in this crate checked the
/// operation and nothing else, so a decision taken under one policy was
/// redeemable under any other at every one of them.
///
/// The check now lives on the token as [`portcullis::kernel::DecisionToken::redeem`],
/// which takes `self` by value and requires both the operation and the
/// permissions in force. `DecisionToken::operation` is `pub(crate)` to
/// portcullis, so there is no other way to read what a token authorises — a new
/// effect method cannot forget, because there is nothing else to call.
impl From<portcullis::kernel::RedeemError> for NucleusError {
    fn from(e: portcullis::kernel::RedeemError) -> Self {
        Self::ScopeMismatch {
            reason: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::Operation;
    use portcullis::kernel::RedeemError;

    /// THE regression, preserved. This check used to be
    /// `debug_assert_eq!(decision.operation(), op, ..)`, which compiles to
    /// nothing when `debug_assertions` is off — every release build — so a
    /// `DecisionToken` minted for `ReadFiles` and handed to a `RunBash` entry
    /// point was accepted exactly as readily as the right one.
    ///
    /// It is now a refusal in both profiles, and it is no longer a call site's
    /// job to remember: `DecisionToken::redeem` is the only way to read a token.
    /// The property lives with `redeem` in portcullis; this pins that the
    /// refusal still arrives here as a `ScopeMismatch` rather than being
    /// swallowed.
    #[test]
    fn a_refused_redeem_arrives_as_a_scope_mismatch() {
        let scope = NucleusError::from(RedeemError::ScopeMismatch {
            authorised: Operation::ReadFiles,
            performing: Operation::RunBash,
        });
        assert!(matches!(scope, NucleusError::ScopeMismatch { .. }));
        assert!(scope.to_string().contains("ReadFiles"), "{scope}");
        assert!(scope.to_string().contains("RunBash"), "{scope}");

        let stale = NucleusError::from(RedeemError::StalePermissions {
            decided_under: "aaaaaaaabbbb".to_string(),
            executing_under: "ccccccccdddd".to_string(),
        });
        assert!(matches!(stale, NucleusError::ScopeMismatch { .. }));
        let msg = stale.to_string();
        assert!(
            msg.contains("aaaaaaaa"),
            "names what it was decided under: {msg}"
        );
        assert!(
            msg.contains("cccccccc"),
            "and what it would run under: {msg}"
        );
        assert!(msg.contains("change of policy"), "{msg}");
    }
}
