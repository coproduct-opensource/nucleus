//! Pure decision kernel for taint-based guard logic.
//!
//! These functions contain the core decision logic extracted from
//! [`GradedTaintGuard`](crate::guard::GradedTaintGuard) as pure,
//! side-effect-free functions. No `RwLock`, no `sha2`, no I/O — just
//! the boolean decision math.
//!
//! ## Verified Shared Core
//!
//! The Verus proofs in `portcullis-verified` verify executable spec
//! functions (`exec_guard_check`, `exec_apply_event`, etc.) that are
//! structurally identical to these production functions. The CI
//! conformance tests in `verus_conformance.rs` exhaustively verify
//! that these production functions agree with the Verus exec functions
//! on all inputs — establishing a structural bisimulation between the
//! verified model and the production code.
//!
//! This is the closest we can get to seL4-style refinement without
//! running the full portcullis dependency tree through Verus's modified
//! rustc (which doesn't support `sha2`, `ring`, `regex`, etc.).

use crate::capability::Operation;
use crate::guard::{TaintLabel, TaintSet};

/// Classify an operation into its taint label.
///
/// Pure mirror of [`operation_taint`](crate::guard::operation_taint).
/// Maps each operation to the trifecta leg it contributes to.
///
/// Verus equivalent: `operation_taint_label(op: nat) -> nat`
///   - 0 = PrivateData, 1 = UntrustedContent, 2 = ExfilVector, 3 = Neutral
#[inline]
pub fn classify_operation(op: Operation) -> Option<TaintLabel> {
    match op {
        // Leg 1: Private data access
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            Some(TaintLabel::PrivateData)
        }
        // Leg 2: Untrusted content ingestion
        Operation::WebFetch | Operation::WebSearch => Some(TaintLabel::UntrustedContent),
        // Leg 3: Exfiltration vectors
        Operation::RunBash | Operation::GitPush | Operation::CreatePr => {
            Some(TaintLabel::ExfilVector)
        }
        // Neutral operations (no taint contribution)
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::GitCommit
        | Operation::ManagePods => None,
    }
}

/// Project what the taint set WOULD be if this operation executes.
///
/// RunBash is treated as **omnibus**: it conservatively projects both
/// `PrivateData` and `ExfilVector` because bash can read arbitrary
/// files (`cat /etc/passwd`) AND exfiltrate data (`curl`).
///
/// Verus equivalent: the projection arm of `guard_would_deny(obs, taint, op)`
#[inline]
pub fn project_taint(current: &TaintSet, operation: Operation) -> TaintSet {
    if operation == Operation::RunBash {
        // RunBash is omnibus: projects PrivateData + ExfilVector
        current
            .union(&TaintSet::singleton(TaintLabel::PrivateData))
            .union(&TaintSet::singleton(TaintLabel::ExfilVector))
    } else if let Some(label) = classify_operation(operation) {
        current.union(&TaintSet::singleton(label))
    } else {
        current.clone()
    }
}

/// Pure denial decision: should this operation be denied?
///
/// This is the extracted decision kernel from `GradedTaintGuard::check()`.
/// It returns `true` if the operation should be denied.
///
/// The logic:
///   1. Project taint (what would the taint be after this op?)
///   2. If projected taint is trifecta-complete AND the operation
///      requires approval under trifecta constraint → **deny**
///
/// Verus equivalent: `guard_would_deny(obs, taint, op) -> bool`
#[inline]
pub fn should_deny(
    current: &TaintSet,
    operation: Operation,
    requires_approval: bool,
    trifecta_constraint: bool,
) -> bool {
    if !trifecta_constraint {
        return false;
    }
    let projected = project_taint(current, operation);
    projected.is_trifecta_complete() && requires_approval
}

/// Apply a successful operation's taint to the accumulator.
///
/// Returns the new taint set after recording this operation.
/// Only non-neutral operations modify the taint.
///
/// Note: RunBash records ONLY ExfilVector (its actual taint label),
/// NOT the omnibus projection. The omnibus projection is conservative
/// over-approximation used in `project_taint`/`should_deny` for
/// safety. The record reflects what actually happened.
///
/// Verus equivalent: `apply_event_taint(taint, McpEvent{op, succeeded: true})`
#[inline]
pub fn apply_record(current: &TaintSet, operation: Operation) -> TaintSet {
    if let Some(label) = classify_operation(operation) {
        current.union(&TaintSet::singleton(label))
    } else {
        current.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_operation_coverage() {
        // Every operation variant maps to something
        let ops = [
            (Operation::ReadFiles, Some(TaintLabel::PrivateData)),
            (Operation::WriteFiles, None),
            (Operation::EditFiles, None),
            (Operation::RunBash, Some(TaintLabel::ExfilVector)),
            (Operation::GlobSearch, Some(TaintLabel::PrivateData)),
            (Operation::GrepSearch, Some(TaintLabel::PrivateData)),
            (Operation::WebSearch, Some(TaintLabel::UntrustedContent)),
            (Operation::WebFetch, Some(TaintLabel::UntrustedContent)),
            (Operation::GitCommit, None),
            (Operation::GitPush, Some(TaintLabel::ExfilVector)),
            (Operation::CreatePr, Some(TaintLabel::ExfilVector)),
            (Operation::ManagePods, None),
        ];
        for (op, expected) in ops {
            assert_eq!(classify_operation(op), expected, "mismatch for {:?}", op);
        }
    }

    #[test]
    fn test_project_taint_runbash_omnibus() {
        let empty = TaintSet::empty();
        let projected = project_taint(&empty, Operation::RunBash);
        assert!(projected.contains(TaintLabel::PrivateData));
        assert!(projected.contains(TaintLabel::ExfilVector));
        assert!(!projected.contains(TaintLabel::UntrustedContent));
    }

    #[test]
    fn test_project_taint_normal_op() {
        let empty = TaintSet::empty();
        let projected = project_taint(&empty, Operation::ReadFiles);
        assert!(projected.contains(TaintLabel::PrivateData));
        assert!(!projected.contains(TaintLabel::UntrustedContent));
        assert!(!projected.contains(TaintLabel::ExfilVector));
    }

    #[test]
    fn test_project_taint_neutral_op() {
        let taint = TaintSet::singleton(TaintLabel::PrivateData);
        let projected = project_taint(&taint, Operation::WriteFiles);
        assert_eq!(projected, taint);
    }

    #[test]
    fn test_should_deny_trifecta_complete() {
        let taint = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent));
        // GitPush would complete the trifecta
        assert!(should_deny(&taint, Operation::GitPush, true, true));
    }

    #[test]
    fn test_should_deny_no_approval() {
        let taint = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent));
        // Even if trifecta would complete, no approval required → allow
        assert!(!should_deny(&taint, Operation::GitPush, false, true));
    }

    #[test]
    fn test_should_deny_constraint_disabled() {
        let taint = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent));
        // Trifecta constraint disabled → always allow
        assert!(!should_deny(&taint, Operation::GitPush, true, false));
    }

    #[test]
    fn test_apply_record_does_not_omnibus() {
        let empty = TaintSet::empty();
        let recorded = apply_record(&empty, Operation::RunBash);
        // Record only adds ExfilVector, NOT the omnibus PrivateData
        assert!(recorded.contains(TaintLabel::ExfilVector));
        assert!(!recorded.contains(TaintLabel::PrivateData));
    }

    #[test]
    fn test_apply_record_neutral() {
        let taint = TaintSet::singleton(TaintLabel::PrivateData);
        let recorded = apply_record(&taint, Operation::WriteFiles);
        assert_eq!(recorded, taint);
    }
}
