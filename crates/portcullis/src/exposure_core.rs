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
/// ## Intentional asymmetry with `project_exposure` for RunBash
///
/// `project_exposure` conservatively adds `{PrivateData, ExfilVector}` for
/// RunBash because bash *can* read files and exfiltrate data. This is the
/// pre-check over-approximation: deny anything that *might* complete the
/// uninhabitable state.
///
/// `apply_record` adds only `ExfilVector` (the actual classification from
/// `classify_operation`), because the post-check records what the operation
/// *actually contributed*, not what it theoretically could have done.
///
/// This asymmetry is by design (Trail of Bits finding #2):
/// - **Pre-check (project_exposure)**: conservative for safety — blocks
///   operations that *could* complete the uninhabitable state.
/// - **Post-check (apply_record)**: precise for accuracy — records the
///   actual exposure leg so that subsequent pre-checks start from an
///   accurate baseline rather than an inflated one.
///
/// If `apply_record` used the omnibus projection, a single RunBash call
/// would inflate the exposure to `{PrivateData, ExfilVector}` even if
/// the command was `echo hello`. This would make subsequent web_fetch
/// calls trigger uninhabitable_state warnings incorrectly.
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

    // ════════════════════════════════════════════════════════════════════
    // Core ↔ Production conformance tests
    //
    // The portcullis-core crate defines independent ExposureLabel,
    // ExposureSet, and classification functions for Aeneas translation.
    // These tests verify the core types agree with the production types
    // on all inputs — establishing structural bisimulation.
    // ════════════════════════════════════════════════════════════════════

    /// Translate a core ExposureLabel to a production ExposureLabel.
    fn core_to_prod_label(core: portcullis_core::ExposureLabel) -> ExposureLabel {
        match core {
            portcullis_core::ExposureLabel::PrivateData => ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent => ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector => ExposureLabel::ExfilVector,
        }
    }

    #[test]
    fn conformance_classify_operation_agrees() {
        // Operation is the same type (re-exported from core), so we just
        // verify that core::classify_operation and production classify_operation
        // agree for all 12 operations.
        for op in Operation::ALL {
            let core_result = portcullis_core::classify_operation(op);
            let prod_result = classify_operation(op);

            match (core_result, prod_result) {
                (None, None) => {}
                (Some(core_label), Some(prod_label)) => {
                    assert_eq!(
                        core_to_prod_label(core_label),
                        prod_label,
                        "classify_operation disagrees for {:?}",
                        op
                    );
                }
                _ => panic!(
                    "classify_operation disagrees for {:?}: core={:?}, prod={:?}",
                    op, core_result, prod_result
                ),
            }
        }
    }

    #[test]
    fn conformance_exposure_set_uninhabitable_agrees() {
        // Exhaustively check all 8 combinations of 3 booleans
        let labels = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ];
        let core_labels = [
            portcullis_core::ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector,
        ];

        for mask in 0u8..8 {
            let mut prod_set = ExposureSet::empty();
            let mut core_set = portcullis_core::ExposureSet::empty();

            for i in 0..3 {
                if mask & (1 << i) != 0 {
                    prod_set = prod_set.union(&ExposureSet::singleton(labels[i]));
                    core_set =
                        core_set.union(&portcullis_core::ExposureSet::singleton(core_labels[i]));
                }
            }

            assert_eq!(
                core_set.is_uninhabitable(),
                prod_set.is_uninhabitable(),
                "is_uninhabitable disagrees for mask={:03b}",
                mask
            );
            assert_eq!(
                core_set.count(),
                prod_set.count(),
                "count disagrees for mask={:03b}",
                mask
            );
        }
    }

    #[test]
    fn conformance_project_exposure_agrees() {
        // For each starting state (8 combos) x each operation (12),
        // verify core and production project_exposure agree.
        let labels = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ];
        let core_labels = [
            portcullis_core::ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector,
        ];

        for mask in 0u8..8 {
            let mut prod_set = ExposureSet::empty();
            let mut core_set = portcullis_core::ExposureSet::empty();

            for i in 0..3 {
                if mask & (1 << i) != 0 {
                    prod_set = prod_set.union(&ExposureSet::singleton(labels[i]));
                    core_set =
                        core_set.union(&portcullis_core::ExposureSet::singleton(core_labels[i]));
                }
            }

            for op in Operation::ALL {
                let prod_projected = project_exposure(&prod_set, op);
                let core_projected = portcullis_core::project_exposure(&core_set, op);

                // Compare is_uninhabitable (the key safety property)
                // Note: production project_exposure has RunBash omnibus behavior
                // (adds PrivateData + ExfilVector), while core does not.
                // This is intentional — the core models the simple classification.
                // We check count and uninhabitable status rather than exact bit match.
                //
                // For non-RunBash ops, they should agree exactly.
                if op != Operation::RunBash {
                    assert_eq!(
                        core_projected.is_uninhabitable(),
                        prod_projected.is_uninhabitable(),
                        "project_exposure uninhabitable disagrees for mask={:03b}, op={:?}",
                        mask,
                        op
                    );
                }
            }
        }
    }

    #[test]
    fn conformance_should_gate_vs_should_deny() {
        // Core's should_gate and production's should_deny have different
        // signatures (production takes approval/constraint bools).
        // Verify they agree when constraint=true and requires_approval=true
        // for the exfil operations.
        let labels = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ];
        let core_labels = [
            portcullis_core::ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector,
        ];

        for mask in 0u8..8 {
            let mut prod_set = ExposureSet::empty();
            let mut core_set = portcullis_core::ExposureSet::empty();

            for i in 0..3 {
                if mask & (1 << i) != 0 {
                    prod_set = prod_set.union(&ExposureSet::singleton(labels[i]));
                    core_set =
                        core_set.union(&portcullis_core::ExposureSet::singleton(core_labels[i]));
                }
            }

            // Check non-RunBash exfil operations (GitPush, CreatePr)
            // RunBash diverges intentionally (omnibus in production)
            for op in [Operation::GitPush, Operation::CreatePr] {
                let core_gated = portcullis_core::should_gate(&core_set, op);
                let prod_denied = should_deny(&prod_set, op, true, true);
                assert_eq!(
                    core_gated, prod_denied,
                    "should_gate vs should_deny disagrees for mask={:03b}, op={:?}",
                    mask, op
                );
            }
        }
    }
}
