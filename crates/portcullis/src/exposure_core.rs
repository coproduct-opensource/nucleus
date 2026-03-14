//! Pure decision kernel for exposure-based guard logic.
//!
//! These functions contain the core decision logic extracted from
//! [`GradedExposureGuard`](crate::guard::GradedExposureGuard) as pure,
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
use crate::guard::{ExposureLabel, ExposureSet};

/// Classify an operation into its exposure label.
///
/// Pure mirror of [`operation_exposure`](crate::guard::operation_exposure).
/// Maps each operation to the exposure leg it contributes to.
///
/// Verus equivalent: `operation_exposure_label(op: nat) -> nat`
///   - 0 = PrivateData, 1 = UntrustedContent, 2 = ExfilVector, 3 = Neutral
#[inline]
pub fn classify_operation(op: Operation) -> Option<ExposureLabel> {
    match op {
        // Leg 1: Private data access
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            Some(ExposureLabel::PrivateData)
        }
        // Leg 2: Untrusted content ingestion
        Operation::WebFetch | Operation::WebSearch => Some(ExposureLabel::UntrustedContent),
        // Leg 3: Exfiltration vectors
        Operation::RunBash | Operation::GitPush | Operation::CreatePr => {
            Some(ExposureLabel::ExfilVector)
        }
        // Neutral operations (no exposure contribution)
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::GitCommit
        | Operation::ManagePods => None,
    }
}

/// Project what the exposure set WOULD be if this operation executes.
///
/// RunBash is treated as **omnibus**: it conservatively projects both
/// `PrivateData` and `ExfilVector` because bash can read arbitrary
/// files (`cat /etc/passwd`) AND exfiltrate data (`curl`).
///
/// Verus equivalent: the projection arm of `guard_would_deny(obs, exposure, op)`
#[inline]
pub fn project_exposure(current: &ExposureSet, operation: Operation) -> ExposureSet {
    if operation == Operation::RunBash {
        // RunBash is omnibus: projects PrivateData + ExfilVector
        current
            .union(&ExposureSet::singleton(ExposureLabel::PrivateData))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector))
    } else if let Some(label) = classify_operation(operation) {
        current.union(&ExposureSet::singleton(label))
    } else {
        current.clone()
    }
}

/// Pure denial decision: should this operation be denied?
///
/// This is the extracted decision kernel from `GradedExposureGuard::check()`.
/// It returns `true` if the operation should be denied.
///
/// The logic:
///   1. Project exposure (what would the exposure be after this op?)
///   2. If projected exposure is uninhabitable AND the operation
///      requires approval under uninhabitable_state constraint → **deny**
///
/// Verus equivalent: `guard_would_deny(obs, exposure, op) -> bool`
#[inline]
pub fn should_deny(
    current: &ExposureSet,
    operation: Operation,
    requires_approval: bool,
    uninhabitable_constraint: bool,
) -> bool {
    if !uninhabitable_constraint {
        return false;
    }
    let projected = project_exposure(current, operation);
    projected.is_uninhabitable() && requires_approval
}

/// Apply a successful operation's exposure to the accumulator.
///
/// Returns the new exposure set after recording this operation.
/// Only non-neutral operations modify the exposure.
///
/// Note: RunBash records ONLY ExfilVector (its actual exposure label),
/// NOT the omnibus projection. The omnibus projection is conservative
/// over-approximation used in `project_exposure`/`should_deny` for
/// safety. The record reflects what actually happened.
///
/// Verus equivalent: `apply_event_exposure(exposure, McpEvent{op, succeeded: true})`
#[inline]
pub fn apply_record(current: &ExposureSet, operation: Operation) -> ExposureSet {
    if let Some(label) = classify_operation(operation) {
        current.union(&ExposureSet::singleton(label))
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
            (Operation::ReadFiles, Some(ExposureLabel::PrivateData)),
            (Operation::WriteFiles, None),
            (Operation::EditFiles, None),
            (Operation::RunBash, Some(ExposureLabel::ExfilVector)),
            (Operation::GlobSearch, Some(ExposureLabel::PrivateData)),
            (Operation::GrepSearch, Some(ExposureLabel::PrivateData)),
            (Operation::WebSearch, Some(ExposureLabel::UntrustedContent)),
            (Operation::WebFetch, Some(ExposureLabel::UntrustedContent)),
            (Operation::GitCommit, None),
            (Operation::GitPush, Some(ExposureLabel::ExfilVector)),
            (Operation::CreatePr, Some(ExposureLabel::ExfilVector)),
            (Operation::ManagePods, None),
        ];
        for (op, expected) in ops {
            assert_eq!(classify_operation(op), expected, "mismatch for {:?}", op);
        }
    }

    #[test]
    fn test_project_exposure_runbash_omnibus() {
        let empty = ExposureSet::empty();
        let projected = project_exposure(&empty, Operation::RunBash);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(projected.contains(ExposureLabel::ExfilVector));
        assert!(!projected.contains(ExposureLabel::UntrustedContent));
    }

    #[test]
    fn test_project_exposure_normal_op() {
        let empty = ExposureSet::empty();
        let projected = project_exposure(&empty, Operation::ReadFiles);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(!projected.contains(ExposureLabel::UntrustedContent));
        assert!(!projected.contains(ExposureLabel::ExfilVector));
    }

    #[test]
    fn test_project_exposure_neutral_op() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData);
        let projected = project_exposure(&exposure, Operation::WriteFiles);
        assert_eq!(projected, exposure);
    }

    #[test]
    fn test_should_deny_uninhabitable_complete() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        // GitPush would complete the uninhabitable_state
        assert!(should_deny(&exposure, Operation::GitPush, true, true));
    }

    #[test]
    fn test_should_deny_no_approval() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        // Even if uninhabitable_state would complete, no approval required → allow
        assert!(!should_deny(&exposure, Operation::GitPush, false, true));
    }

    #[test]
    fn test_should_deny_constraint_disabled() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        //  UninhabitableState constraint disabled → always allow
        assert!(!should_deny(&exposure, Operation::GitPush, true, false));
    }

    #[test]
    fn test_apply_record_does_not_omnibus() {
        let empty = ExposureSet::empty();
        let recorded = apply_record(&empty, Operation::RunBash);
        // Record only adds ExfilVector, NOT the omnibus PrivateData
        assert!(recorded.contains(ExposureLabel::ExfilVector));
        assert!(!recorded.contains(ExposureLabel::PrivateData));
    }

    #[test]
    fn test_apply_record_neutral() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData);
        let recorded = apply_record(&exposure, Operation::WriteFiles);
        assert_eq!(recorded, exposure);
    }
}
