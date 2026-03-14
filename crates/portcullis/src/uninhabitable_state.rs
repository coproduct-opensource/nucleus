//! Parameterized constraint system for dangerous exposure combinations.
//!
//! The uninhabitable_state (PrivateData + UntrustedContent + ExfilVector) is the
//! first and permanent constraint. This module generalizes the concept to
//! arbitrary dangerous combinations of core and extension exposure labels.
//!
//! ## Mathematical Structure
//!
//! Each `UninhabitableState` is a deflationary nucleus on the permission lattice:
//! it only adds obligations, never removes them. The `ConstraintNucleus`
//! composes multiple combos via fixed-point iteration — the result is itself
//! a nucleus (composition of deflationary endomorphisms is deflationary).
//!
//! ## Proof Obligations for New Combos
//!
//! When adding a new `UninhabitableState`, the implementor must demonstrate:
//! 1. The combo's nucleus is deflationary (only adds obligations)
//! 2. It composes with the uninhabitable_state via the fixed-point iteration
//! 3. Property tests pass for the combo (template provided in tests)

use std::collections::BTreeSet;

use crate::capability::{Obligations, Operation, StateRisk};
use crate::guard::{ExposureLabel, ExposureSet, ExtensionExposureLabel};

/// A dangerous combination of exposure labels.
///
/// When all `required_core_labels` AND `required_ext_labels` are present in
/// a session's exposure set, the `mitigation` obligations are imposed.
///
/// The uninhabitable_state is combo #0, always present, CANNOT be removed.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UninhabitableState {
    /// Human-readable name for this combination.
    pub name: String,
    /// Core exposure labels required to trigger this combo.
    pub required_core_labels: BTreeSet<CoreExposureRequirement>,
    /// Extension exposure labels required to trigger this combo.
    pub required_ext_labels: BTreeSet<ExtensionExposureLabel>,
    /// Obligations added when this combo is triggered.
    pub mitigation: Obligations,
    /// Risk grade when triggered.
    pub risk_grade: StateRisk,
}

/// Core exposure label requirements, mapping to the 3 verified labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CoreExposureRequirement {
    /// Requires PrivateData exposure.
    PrivateData,
    /// Requires UntrustedContent exposure.
    UntrustedContent,
    /// Requires ExfilVector exposure.
    ExfilVector,
}

impl CoreExposureRequirement {
    /// Convert to the corresponding ExposureLabel.
    pub fn to_label(self) -> ExposureLabel {
        match self {
            CoreExposureRequirement::PrivateData => ExposureLabel::PrivateData,
            CoreExposureRequirement::UntrustedContent => ExposureLabel::UntrustedContent,
            CoreExposureRequirement::ExfilVector => ExposureLabel::ExfilVector,
        }
    }
}

impl UninhabitableState {
    /// Check if this combo is triggered by the given exposure set.
    pub fn is_triggered(&self, exposure: &ExposureSet) -> bool {
        let core_met = self
            .required_core_labels
            .iter()
            .all(|req| exposure.contains(req.to_label()));
        #[cfg(not(kani))]
        let ext_met = self
            .required_ext_labels
            .iter()
            .all(|label| exposure.contains_extension(label));
        #[cfg(kani)]
        let ext_met = true;
        core_met && ext_met
    }

    /// The canonical uninhabitable_state combo. Always slot 0 in `ConstraintNucleus`.
    pub fn canonical() -> Self {
        let mut required_core = BTreeSet::new();
        required_core.insert(CoreExposureRequirement::PrivateData);
        required_core.insert(CoreExposureRequirement::UntrustedContent);
        required_core.insert(CoreExposureRequirement::ExfilVector);

        let mut mitigation = Obligations::for_operation(Operation::GitPush);
        mitigation.insert(Operation::CreatePr);
        mitigation.insert(Operation::RunBash);

        Self {
            name: "uninhabitable-state".to_string(),
            required_core_labels: required_core,
            required_ext_labels: BTreeSet::new(),
            mitigation,
            risk_grade: StateRisk::Uninhabitable,
        }
    }
}

/// The constraint nucleus: uninhabitable_state + additional dangerous combos.
///
/// The uninhabitable_state is always slot 0 and cannot be removed. Additional combos
/// are applied in order after the uninhabitable_state. Each combo is deflationary:
/// it only adds obligations, never removes them.
#[derive(Debug, Clone)]
pub struct ConstraintNucleus {
    /// Slot 0: the uninhabitable_state. Always present. Verified.
    uninhabitable_state: UninhabitableState,
    /// Additional dangerous combinations (tested, not verified).
    additional: Vec<UninhabitableState>,
}

impl Default for ConstraintNucleus {
    fn default() -> Self {
        Self {
            uninhabitable_state: UninhabitableState::canonical(),
            additional: Vec::new(),
        }
    }
}

impl ConstraintNucleus {
    /// Create a new constraint nucleus with only the uninhabitable_state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an additional dangerous combination.
    ///
    /// Returns `&mut Self` for chaining.
    pub fn with_combo(mut self, combo: UninhabitableState) -> Self {
        self.additional.push(combo);
        self
    }

    /// Add an additional dangerous combination by reference.
    pub fn add_combo(&mut self, combo: UninhabitableState) {
        self.additional.push(combo);
    }

    /// Apply all constraints to the given exposure set. Returns accumulated obligations.
    ///
    ///  UninhabitableState first, then additional combos. Each is deflationary:
    /// only adds obligations, never removes.
    pub fn apply(&self, exposure: &ExposureSet) -> Obligations {
        let mut obligations = Obligations::default();

        // Slot 0: the uninhabitable_state (always)
        if self.uninhabitable_state.is_triggered(exposure) {
            obligations = obligations.union(&self.uninhabitable_state.mitigation);
        }

        // Additional combos
        for combo in &self.additional {
            if combo.is_triggered(exposure) {
                obligations = obligations.union(&combo.mitigation);
            }
        }

        obligations
    }

    /// Return a reference to the uninhabitable_state combo.
    pub fn uninhabitable_state(&self) -> &UninhabitableState {
        &self.uninhabitable_state
    }

    /// Return all additional combos.
    pub fn additional(&self) -> &[UninhabitableState] {
        &self.additional
    }

    /// Total number of constraints (uninhabitable_state + additional).
    pub fn len(&self) -> usize {
        1 + self.additional.len()
    }

    /// Always false — the uninhabitable_state is always present.
    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uninhabitable_combo_triggered() {
        let combo = UninhabitableState::canonical();
        let full = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
        assert!(combo.is_triggered(&full));
    }

    #[test]
    fn test_uninhabitable_combo_not_triggered_partial() {
        let combo = UninhabitableState::canonical();
        let partial = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        assert!(!combo.is_triggered(&partial));
    }

    #[test]
    fn test_uninhabitable_combo_not_triggered_empty() {
        let combo = UninhabitableState::canonical();
        assert!(!combo.is_triggered(&ExposureSet::empty()));
    }

    #[test]
    fn test_extension_combo_triggered() {
        let mut required_ext = BTreeSet::new();
        required_ext.insert(ExtensionExposureLabel::new("code_execution"));

        let combo = UninhabitableState {
            name: "code-exec-with-private-data".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreExposureRequirement::PrivateData);
                s
            },
            required_ext_labels: required_ext,
            mitigation: Obligations::for_operation(Operation::RunBash),
            risk_grade: StateRisk::Medium,
        };

        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData).union(
            &ExposureSet::extension_singleton(ExtensionExposureLabel::new("code_execution")),
        );
        assert!(combo.is_triggered(&exposure));
    }

    #[test]
    fn test_extension_combo_not_triggered_missing_ext() {
        let mut required_ext = BTreeSet::new();
        required_ext.insert(ExtensionExposureLabel::new("code_execution"));

        let combo = UninhabitableState {
            name: "code-exec-with-private-data".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreExposureRequirement::PrivateData);
                s
            },
            required_ext_labels: required_ext,
            mitigation: Obligations::for_operation(Operation::RunBash),
            risk_grade: StateRisk::Medium,
        };

        // Has core label but missing extension label
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData);
        assert!(!combo.is_triggered(&exposure));
    }

    #[test]
    fn test_constraint_nucleus_default_has_uninhabitable() {
        let nucleus = ConstraintNucleus::new();
        assert_eq!(nucleus.len(), 1);
        assert!(!nucleus.is_empty());
        assert_eq!(nucleus.uninhabitable_state().name, "uninhabitable-state");
    }

    #[test]
    fn test_constraint_nucleus_apply_uninhabitable() {
        let nucleus = ConstraintNucleus::new();
        let full = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));

        let obligations = nucleus.apply(&full);
        assert!(obligations.requires(Operation::GitPush));
        assert!(obligations.requires(Operation::CreatePr));
        assert!(obligations.requires(Operation::RunBash));
    }

    #[test]
    fn test_constraint_nucleus_apply_no_exposure() {
        let nucleus = ConstraintNucleus::new();
        let obligations = nucleus.apply(&ExposureSet::empty());
        assert!(obligations.is_empty());
    }

    #[test]
    fn test_constraint_nucleus_with_additional_combo() {
        let ext_combo = UninhabitableState {
            name: "data-plus-exec".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreExposureRequirement::PrivateData);
                s
            },
            required_ext_labels: {
                let mut s = BTreeSet::new();
                s.insert(ExtensionExposureLabel::new("code_execution"));
                s
            },
            mitigation: Obligations::for_operation(Operation::RunBash),
            risk_grade: StateRisk::Medium,
        };

        let nucleus = ConstraintNucleus::new().with_combo(ext_combo);
        assert_eq!(nucleus.len(), 2);

        // Trigger only the extension combo, not the uninhabitable_state
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData).union(
            &ExposureSet::extension_singleton(ExtensionExposureLabel::new("code_execution")),
        );

        let obligations = nucleus.apply(&exposure);
        assert!(obligations.requires(Operation::RunBash));
        // GitPush NOT required because uninhabitable_state wasn't triggered
        assert!(!obligations.requires(Operation::GitPush));
    }

    #[test]
    fn test_deflationary_property() {
        // Adding a combo can only add obligations, never remove them.
        let nucleus_base = ConstraintNucleus::new();
        let nucleus_extended = ConstraintNucleus::new().with_combo(UninhabitableState {
            name: "extra".to_string(),
            required_core_labels: {
                let mut s = BTreeSet::new();
                s.insert(CoreExposureRequirement::PrivateData);
                s.insert(CoreExposureRequirement::UntrustedContent);
                s
            },
            required_ext_labels: BTreeSet::new(),
            mitigation: Obligations::for_operation(Operation::WebFetch),
            risk_grade: StateRisk::Medium,
        });

        // For any exposure set, extended obligations are a superset of base obligations
        let test_exposures = vec![
            ExposureSet::empty(),
            ExposureSet::singleton(ExposureLabel::PrivateData),
            ExposureSet::singleton(ExposureLabel::PrivateData)
                .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent)),
            ExposureSet::singleton(ExposureLabel::PrivateData)
                .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
                .union(&ExposureSet::singleton(ExposureLabel::ExfilVector)),
        ];

        for exposure in &test_exposures {
            let base = nucleus_base.apply(exposure);
            let extended = nucleus_extended.apply(exposure);
            // Every base obligation must also be in extended
            for op in &base.approvals {
                assert!(
                    extended.approvals.contains(op),
                    "Deflationary violation: base has {:?} but extended doesn't for exposure {}",
                    op,
                    exposure
                );
            }
        }
    }
}
