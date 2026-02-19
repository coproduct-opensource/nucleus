//! Heyting algebra for intuitionistic implication in permissions.
//!
//! A **Heyting algebra** is a bounded distributive lattice with an implication
//! operation `→` satisfying the adjunction:
//!
//! ```text
//! (c ∧ a) ≤ b  ⟺  c ≤ (a → b)
//! ```
//!
//! This adjunction is the categorical formulation of the deduction theorem in
//! intuitionistic logic: "from c and a we can derive b" iff "from c alone we
//! can derive that a implies b".
//!
//! # Security Applications
//!
//! - **Conditional Permissions**: "If you have capability A, you can derive capability B"
//! - **Policy Entailment**: Check if one policy logically implies another
//! - **Delegation Reasoning**: Compute what a delegatee can request given delegator's caps
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::heyting::HeytingAlgebra;
//! use lattice_guard::{CapabilityLattice, CapabilityLevel};
//!
//! let a = CapabilityLattice {
//!     read_files: CapabilityLevel::LowRisk,
//!     ..CapabilityLattice::restrictive()
//! };
//!
//! let b = CapabilityLattice {
//!     read_files: CapabilityLevel::Always,
//!     ..CapabilityLattice::restrictive()
//! };
//!
//! // a → b: what's needed to go from a to b
//! let implication = a.implies(&b);
//!
//! // The adjunction: (c ∧ a) ≤ b iff c ≤ (a → b)
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityLattice, CapabilityLevel};
use crate::frame::{BoundedLattice, DistributiveLattice, Lattice};

/// A Heyting algebra: a bounded distributive lattice with implication.
///
/// The key property is the **adjunction**:
/// ```text
/// (c ∧ a) ≤ b  ⟺  c ≤ (a → b)
/// ```
///
/// Equivalently, `a → b` is the largest element x such that `(x ∧ a) ≤ b`.
///
/// # Intuitionistic Logic Interpretation
///
/// - `a → b`: "a implies b" (if a then b)
/// - `¬a = a → ⊥`: pseudo-complement (intuitionistic negation)
/// - Unlike Boolean algebras, `a ∨ ¬a` may not equal ⊤
pub trait HeytingAlgebra: BoundedLattice + DistributiveLattice {
    /// Heyting implication: the largest x such that `(x ∧ a) ≤ b`.
    ///
    /// # Properties
    ///
    /// - `a → a = ⊤` (identity)
    /// - `a → (b → a) = ⊤` (weakening)
    /// - `(a → (b → c)) → ((a → b) → (a → c)) = ⊤` (distribution)
    /// - `⊤ → a = a` (modus ponens with truth)
    fn implies(&self, other: &Self) -> Self;

    /// Pseudo-complement (intuitionistic negation): `a → ⊥`.
    ///
    /// In a Heyting algebra, `¬a` is the largest element disjoint from `a`.
    /// Note: `a ∧ ¬a = ⊥` but `a ∨ ¬a` may not equal `⊤`.
    fn pseudo_complement(&self) -> Self {
        self.implies(&Self::bottom())
    }

    /// Check if this element implies another (entailment).
    ///
    /// Returns true if `self → other = ⊤`.
    fn entails(&self, other: &Self) -> bool {
        self.implies(other) == Self::top()
    }

    /// Bi-implication: `(a → b) ∧ (b → a)`.
    ///
    /// Returns `⊤` iff `a = b`.
    fn biimplies(&self, other: &Self) -> Self {
        self.implies(other).meet(&other.implies(self))
    }
}

/// Compute implication for capability levels.
///
/// For a total order `Never < LowRisk < Always`:
/// - `a → b = ⊤` if `a ≤ b` (implication is trivially true)
/// - `a → b = b` if `a > b` (need to be at level b to satisfy)
fn level_implies(a: CapabilityLevel, b: CapabilityLevel) -> CapabilityLevel {
    if a <= b {
        CapabilityLevel::Always // Top - trivially true
    } else {
        b // The implication requires at most this level
    }
}

impl Lattice for CapabilityLattice {
    fn meet(&self, other: &Self) -> Self {
        CapabilityLattice::meet(self, other)
    }

    fn join(&self, other: &Self) -> Self {
        CapabilityLattice::join(self, other)
    }

    fn leq(&self, other: &Self) -> bool {
        CapabilityLattice::leq(self, other)
    }
}

impl BoundedLattice for CapabilityLattice {
    fn top() -> Self {
        CapabilityLattice::permissive()
    }

    fn bottom() -> Self {
        Self {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
        }
    }
}

impl DistributiveLattice for CapabilityLattice {}

impl HeytingAlgebra for CapabilityLattice {
    fn implies(&self, other: &Self) -> Self {
        // For a product of total orders, implication is computed pointwise
        Self {
            read_files: level_implies(self.read_files, other.read_files),
            write_files: level_implies(self.write_files, other.write_files),
            edit_files: level_implies(self.edit_files, other.edit_files),
            run_bash: level_implies(self.run_bash, other.run_bash),
            glob_search: level_implies(self.glob_search, other.glob_search),
            grep_search: level_implies(self.grep_search, other.grep_search),
            web_search: level_implies(self.web_search, other.web_search),
            web_fetch: level_implies(self.web_fetch, other.web_fetch),
            git_commit: level_implies(self.git_commit, other.git_commit),
            git_push: level_implies(self.git_push, other.git_push),
            create_pr: level_implies(self.create_pr, other.create_pr),
            manage_pods: level_implies(self.manage_pods, other.manage_pods),
        }
    }
}

/// A conditional permission rule using Heyting implication.
///
/// Represents "if condition then consequence" at the permission level.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConditionalPermission<L: HeytingAlgebra> {
    /// The antecedent (condition)
    pub condition: L,
    /// The consequent (what follows if condition is met)
    pub consequence: L,
    /// Human-readable description
    pub description: String,
}

impl<L: HeytingAlgebra> ConditionalPermission<L> {
    /// Create a new conditional permission rule.
    pub fn new(condition: L, consequence: L, description: impl Into<String>) -> Self {
        Self {
            condition,
            consequence,
            description: description.into(),
        }
    }

    /// Compute the implication as a lattice element.
    pub fn as_implication(&self) -> L {
        self.condition.implies(&self.consequence)
    }

    /// Check if a given permission satisfies this conditional rule.
    ///
    /// A permission `p` satisfies `condition → consequence` if:
    /// `p ≤ (condition → consequence)`
    pub fn is_satisfied_by(&self, perms: &L) -> bool {
        perms.leq(&self.as_implication())
    }

    /// Apply modus ponens: if we have the condition, derive the consequence.
    ///
    /// Given permission `p`, if `p ≥ condition`, return `p ∧ consequence`.
    pub fn apply(&self, perms: &L) -> Option<L> {
        if self.condition.leq(perms) {
            Some(perms.meet(&self.consequence))
        } else {
            None
        }
    }
}

/// Check if one permission set entails another.
///
/// `a` entails `b` if having permission `a` logically implies having permission `b`.
/// This is computed as `a → b = ⊤`.
pub fn entails<L: HeytingAlgebra>(a: &L, b: &L) -> bool {
    a.entails(b)
}

/// Compute the "gap" between two permission sets.
///
/// The gap is what's needed to upgrade from `current` to `target`.
/// Mathematically: `current → target`.
pub fn permission_gap<L: HeytingAlgebra>(current: &L, target: &L) -> L {
    current.implies(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heyting_adjunction() {
        // The key property: (c ∧ a) ≤ b  ⟺  c ≤ (a → b)

        let a = CapabilityLattice {
            read_files: CapabilityLevel::LowRisk,
            write_files: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };

        let b = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Never,
            ..CapabilityLattice::bottom()
        };

        let c = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };

        let implication = a.implies(&b);

        // Check the adjunction
        let lhs = c.meet(&a).leq(&b);
        let rhs = c.leq(&implication);

        assert_eq!(lhs, rhs, "Heyting adjunction must hold");
    }

    #[test]
    fn test_identity_implies_top() {
        // a → a = ⊤
        let a = CapabilityLattice::default();
        let result = a.implies(&a);
        assert_eq!(result, CapabilityLattice::top());
    }

    #[test]
    fn test_top_implies_identity() {
        // ⊤ → a = a
        let a = CapabilityLattice {
            read_files: CapabilityLevel::LowRisk,
            web_fetch: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };

        let result = CapabilityLattice::top().implies(&a);
        assert_eq!(result, a);
    }

    #[test]
    fn test_bottom_implies_anything() {
        // ⊥ → a = ⊤ (ex falso quodlibet)
        let a = CapabilityLattice::default();
        let result = CapabilityLattice::bottom().implies(&a);
        assert_eq!(result, CapabilityLattice::top());
    }

    #[test]
    fn test_level_implication_trivial() {
        // If a ≤ b, then a → b = ⊤
        assert_eq!(
            level_implies(CapabilityLevel::Never, CapabilityLevel::Always),
            CapabilityLevel::Always
        );
        assert_eq!(
            level_implies(CapabilityLevel::LowRisk, CapabilityLevel::Always),
            CapabilityLevel::Always
        );
    }

    #[test]
    fn test_level_implication_nontrivial() {
        // If a > b, then a → b = b
        assert_eq!(
            level_implies(CapabilityLevel::Always, CapabilityLevel::LowRisk),
            CapabilityLevel::LowRisk
        );
        assert_eq!(
            level_implies(CapabilityLevel::Always, CapabilityLevel::Never),
            CapabilityLevel::Never
        );
    }

    #[test]
    fn test_pseudo_complement() {
        // ¬a = a → ⊥
        let a = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };

        let neg_a = a.pseudo_complement();

        // a ∧ ¬a should be ⊥
        let intersection = a.meet(&neg_a);
        assert!(intersection.leq(&CapabilityLattice::bottom()));
    }

    #[test]
    fn test_entailment() {
        // In Heyting algebra, a entails b means a → b = ⊤ (i.e., a ≤ b)
        // So restrictive (bottom) entails anything, and top is only entailed by itself

        let permissive = CapabilityLattice::permissive();
        let restrictive = CapabilityLattice::bottom();

        // bottom entails anything (⊥ → a = ⊤)
        assert!(entails(&restrictive, &permissive));

        // permissive does NOT entail restrictive (⊤ → ⊥ = ⊥ ≠ ⊤)
        assert!(!entails(&permissive, &restrictive));

        // anything entails itself
        assert!(entails(&permissive, &permissive));
        assert!(entails(&restrictive, &restrictive));
    }

    #[test]
    fn test_permission_gap() {
        // Gap is the implication current → target
        // If current ≤ target for a field, gap = Always (trivially satisfied)
        // If current > target for a field, gap = target (need to drop to target level)

        let current = CapabilityLattice {
            read_files: CapabilityLevel::LowRisk, // LowRisk < Always
            write_files: CapabilityLevel::Never,  // Never < LowRisk
            ..CapabilityLattice::bottom()
        };

        let target = CapabilityLattice {
            read_files: CapabilityLevel::Always,   // current < target
            write_files: CapabilityLevel::LowRisk, // current < target
            ..CapabilityLattice::bottom()
        };

        let gap = permission_gap(&current, &target);

        // Since current ≤ target for both fields, gap should be ⊤ for those fields
        assert_eq!(gap.read_files, CapabilityLevel::Always);
        assert_eq!(gap.write_files, CapabilityLevel::Always);

        // Test the other direction: when current > target
        let higher = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };
        let lower = CapabilityLattice {
            read_files: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };

        let gap2 = permission_gap(&higher, &lower);
        // higher > lower, so gap = lower level
        assert_eq!(gap2.read_files, CapabilityLevel::LowRisk);
    }

    #[test]
    fn test_conditional_permission() {
        // Rule: if you have read access, you can also have glob search
        let condition = CapabilityLattice {
            read_files: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };

        let consequence = CapabilityLattice {
            glob_search: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };

        let rule =
            ConditionalPermission::new(condition, consequence, "Read access implies glob search");

        // A permission with read access should be able to apply the rule
        let perms_with_read = CapabilityLattice {
            read_files: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };

        let result = rule.apply(&perms_with_read);
        assert!(result.is_some());

        // A permission without read access cannot apply the rule
        let perms_without_read = CapabilityLattice::bottom();
        let result = rule.apply(&perms_without_read);
        assert!(result.is_none());
    }

    #[test]
    fn test_biimplication() {
        let a = CapabilityLattice::default();
        let b = CapabilityLattice::default();

        // a ↔ a = ⊤
        let biimpl = a.biimplies(&b);
        assert_eq!(biimpl, CapabilityLattice::top());
    }

    #[test]
    fn test_capability_gap_for_weakening() {
        // Gap from restrictive to permissive - should be non-trivial
        let floor = CapabilityLattice::bottom();
        let ceiling = CapabilityLattice::permissive();

        let gap = permission_gap(&floor, &ceiling);

        // floor → ceiling should be ceiling (since floor is bottom)
        // Actually, ⊥ → anything = ⊤ (ex falso quodlibet)
        // But for our cost computation we care about floor < ceiling
        assert_eq!(gap, CapabilityLattice::top());
    }
}
