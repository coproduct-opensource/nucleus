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
//! use portcullis::heyting::HeytingAlgebra;
//! use portcullis::{CapabilityLattice, CapabilityLevel};
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
///
/// # Sparse representation and `leq_himp`
///
/// For types that use a sparse map (e.g., `BTreeMap`) to represent dimensions,
/// the absent-key semantic differs between regular lattice values and implication
/// results:
///
/// - Regular lattice (capability set): absent key → `⊥` (fail-closed, security default)
/// - Implication result `a → b`: absent key → `⊤` (correct: `level_implies(⊥,⊥) = ⊤`)
///
/// Because `leq()` uses the fail-closed `⊥` default for absent RHS keys, comparing
/// `c ≤ (a → b)` with `c.leq(&a.implies(&b))` produces wrong answers when `c`
/// contains keys absent from both `a` and `b`. Use `c.leq_himp(&a.implies(&b))`
/// (provided by this trait) for all adjunction checks.
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

    /// Compare `self ≤ himp` where `himp` is a Heyting implication result.
    ///
    /// This is the correct comparison for the adjunction `c ≤ (a → b)`. It
    /// differs from `leq()` for sparse representations: absent keys in the
    /// implication result should default to `⊤` (always satisfied), not `⊥`
    /// (fail-closed). The default implementation delegates to `leq()`, which
    /// is correct for dense/total representations where `implies()` always
    /// produces a fully-populated result. Override for sparse representations.
    fn leq_himp(&self, himp: &Self) -> bool {
        self.leq(himp)
    }

    /// Pseudo-complement (intuitionistic negation): `a → ⊥`.
    ///
    /// In a Heyting algebra, `¬a` is the largest element disjoint from `a`.
    /// Note: `a ∧ ¬a = ⊥` but `a ∨ ¬a` may not equal `⊤`.
    fn pseudo_complement(&self) -> Self {
        self.implies(&Self::bottom())
    }

    /// Check if this element implies another (entailment).
    ///
    /// Returns true if `self → other = ⊤`, equivalently `self ≤ other`.
    ///
    /// The default implementation uses `leq()` directly rather than
    /// `self.implies(other) == Self::top()` to avoid false negatives when
    /// `implies()` stores explicit `⊤` entries that `top()` omits (a known
    /// issue in sparse BTreeMap representations where `top()` has empty maps
    /// but `implies()` may store `Always` entries for explicit extension keys).
    fn entails(&self, other: &Self) -> bool {
        self.leq(other)
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
pub(crate) fn level_implies(a: CapabilityLevel, b: CapabilityLevel) -> CapabilityLevel {
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
            #[cfg(not(kani))]
            extensions: std::collections::BTreeMap::new(),
        }
    }
}

impl DistributiveLattice for CapabilityLattice {}

impl HeytingAlgebra for CapabilityLattice {
    fn implies(&self, other: &Self) -> Self {
        // For a product of total orders, implication is computed pointwise.
        // Extension dimensions are included to preserve the Heyting adjunction:
        //   (c ∧ a) ≤ b  ⟺  c ≤ (a ⇨ b)
        // Dropping extensions from the result would break this adjunction for any
        // lattice with non-empty extension capabilities (fail-closed default is Never,
        // which is strictly smaller than the correct pointwise implication value).
        //
        // Storage convention: absent key in the result = Always (the mathematically
        // correct default for an implication result, since level_implies(Never,Never)
        // = Always). We therefore store only entries where the result is NOT Always
        // (i.e., the non-trivial restrictions). This way the result map stays compact
        // and callers using `leq_himp()` get the correct Always default.
        #[cfg(not(kani))]
        let ext = {
            let mut ext = std::collections::BTreeMap::new();
            for key in self.extensions.keys().chain(other.extensions.keys()) {
                let a = self.extension_level(key);
                let b = other.extension_level(key);
                let v = level_implies(a, b);
                // Only store non-Always entries: absent key in the implies result
                // is semantically Always (see leq_himp). Always entries are the
                // trivially-satisfied case and need not be stored.
                if v != CapabilityLevel::Always {
                    ext.insert(key.clone(), v);
                }
            }
            ext
        };

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
            #[cfg(not(kani))]
            extensions: ext,
        }
    }

    /// Compare `self ≤ himp` where `himp` is the result of a Heyting implication.
    ///
    /// The sparse BTreeMap convention for implication results is:
    ///   **absent key = `Always`** (not `Never`)
    ///
    /// Because `level_implies(Never, Never) = Always`, any key absent from both
    /// operands of `a.implies(b)` would be `Always` in a dense representation.
    /// The sparse result omits `Always` entries, so `leq()` (which uses `Never`
    /// as the fail-closed default for absent RHS keys) gives the wrong answer.
    /// This method uses `Always` as the absent-key default for `himp`.
    ///
    /// Use this for all adjunction checks: `c.leq_himp(&a.implies(&b))`.
    /// Use `leq()` for regular policy enforcement (`requested.leq(&allowed)`).
    #[cfg(not(kani))]
    fn leq_himp(&self, himp: &Self) -> bool {
        // Core 12 fields: same as regular leq (fully stored, no sparse issue)
        let core_leq = self.read_files <= himp.read_files
            && self.write_files <= himp.write_files
            && self.edit_files <= himp.edit_files
            && self.run_bash <= himp.run_bash
            && self.glob_search <= himp.glob_search
            && self.grep_search <= himp.grep_search
            && self.web_search <= himp.web_search
            && self.web_fetch <= himp.web_fetch
            && self.git_commit <= himp.git_commit
            && self.git_push <= himp.git_push
            && self.create_pr <= himp.create_pr
            && self.manage_pods <= himp.manage_pods;

        if !core_leq {
            return false;
        }

        // Extension check with Always-default for absent himp keys.
        // The implies-result convention: absent = Always (trivially satisfied).
        // Only fail if himp explicitly restricts a key below self's level.
        for (key, &self_level) in &self.extensions {
            // Key absent in himp = Always (implication default).
            // self_level ≤ Always is always true.
            if let Some(&himp_level) = himp.extensions.get(key) {
                if self_level > himp_level {
                    return false;
                }
            }
        }
        // Keys in himp not in self: self[K] = Never ≤ himp[K], always true.
        true
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
    ///
    /// Uses `leq_himp()` rather than `leq()` so that extension keys absent from
    /// the implication result are treated as `Always` (the correct mathematical
    /// default) rather than `Never` (the fail-closed security default used by
    /// `leq()` for regular capability comparisons).
    pub fn is_satisfied_by(&self, perms: &L) -> bool {
        perms.leq_himp(&self.as_implication())
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

        // Check the adjunction — use leq_himp() (not leq()) because implies() uses
        // the sparse absent=Always convention for extension keys; leq() would apply
        // the Never default instead. For these core-field-only lattices leq() and
        // leq_himp() are equivalent, but leq_himp() is the correct pattern.
        let lhs = c.meet(&a).leq(&b);
        let rhs = c.leq_himp(&implication);

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

    /// Concrete regression for the bug reported in the gap analysis:
    /// a.extensions = {X: Never}, b.extensions = {X: LowRisk}, c.extensions = {X: LowRisk}
    ///
    /// `level_implies(Never, LowRisk) = Always` (since Never ≤ LowRisk). The implies
    /// result now stores only non-Always entries (absent = Always convention), so K is
    /// ABSENT from `a.implies(b)`. `leq_himp()` treats the absent key as Always, so
    /// `c[K] = LowRisk ≤ Always` and the adjunction holds.
    #[cfg(not(kani))]
    #[test]
    fn test_heyting_adjunction_extensions_regression() {
        use crate::capability::ExtensionOperation;
        use std::collections::BTreeMap;

        let ext_op = ExtensionOperation::new("custom_op");

        let a = CapabilityLattice {
            extensions: {
                let mut m = BTreeMap::new();
                m.insert(ext_op.clone(), CapabilityLevel::Never);
                m
            },
            ..CapabilityLattice::bottom()
        };

        let b = CapabilityLattice {
            extensions: {
                let mut m = BTreeMap::new();
                m.insert(ext_op.clone(), CapabilityLevel::LowRisk);
                m
            },
            ..CapabilityLattice::bottom()
        };

        let c = CapabilityLattice {
            extensions: {
                let mut m = BTreeMap::new();
                m.insert(ext_op.clone(), CapabilityLevel::LowRisk);
                m
            },
            ..CapabilityLattice::bottom()
        };

        // level_implies(Never, LowRisk) = Always.
        // The new convention: absent key in implies result = Always.
        // So K is NOT stored in the result (omitting Always entries keeps the map compact).
        let implication = a.implies(&b);
        assert!(
            !implication.extensions.contains_key(&ext_op),
            "level_implies(Never, LowRisk) = Always; Always entries are omitted (absent = Always convention)"
        );

        // leq_himp correctly interprets absent key in implication as Always:
        // c[K] = LowRisk ≤ Always (absent-key default) = true
        assert!(
            c.leq_himp(&implication),
            "leq_himp: c[K]=LowRisk ≤ absent key in implication = Always"
        );

        // Full adjunction check via leq_himp: (c ∧ a) ≤ b  ↔  c ≤ (a ⇨ b)
        let lhs = c.meet(&a).leq(&b);
        let rhs = c.leq_himp(&implication);
        assert_eq!(
            lhs, rhs,
            "Heyting adjunction must hold for extension dimensions via leq_himp"
        );
    }

    /// Exhaustive adjunction check over all (a, b, c) triples with one extension dimension.
    ///
    /// Tests all 27 triples (3 levels × 3 levels × 3 levels) where the extension key is
    /// EXPLICITLY PRESENT in all three lattices. Also tests the sparse case where K is
    /// absent from a and b but present in c. All cases use `leq_himp()` for the RHS
    /// comparison (the correct method for adjunction checks).
    #[cfg(not(kani))]
    #[test]
    fn test_heyting_adjunction_extensions_exhaustive() {
        use crate::capability::ExtensionOperation;
        use std::collections::BTreeMap;

        let ext_op = ExtensionOperation::new("ext_dim");
        let levels = [
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];

        for &a_ext in &levels {
            for &b_ext in &levels {
                for &c_ext in &levels {
                    // Always store the key explicitly (even Never) so implies() can
                    // iterate over it and compute the correct pointwise result.
                    let make_explicit = |level: CapabilityLevel| -> CapabilityLattice {
                        let mut m = BTreeMap::new();
                        m.insert(ext_op.clone(), level);
                        CapabilityLattice {
                            extensions: m,
                            ..CapabilityLattice::bottom()
                        }
                    };

                    let a = make_explicit(a_ext);
                    let b = make_explicit(b_ext);
                    let c = make_explicit(c_ext);

                    let lhs = c.meet(&a).leq(&b);
                    // Use leq_himp() for the RHS: the correct comparison against an
                    // implication result (absent key = Always, not Never).
                    let rhs = c.leq_himp(&a.implies(&b));

                    assert_eq!(
                        lhs, rhs,
                        "Adjunction failed for a={:?} b={:?} c={:?}",
                        a_ext, b_ext, c_ext
                    );
                }
            }
        }

        // Sparse case: K absent from a and b, present in c. All 3 levels for c.
        for &c_ext in &levels {
            let a_sparse = CapabilityLattice {
                extensions: BTreeMap::new(),
                ..CapabilityLattice::bottom()
            };
            let b_sparse = CapabilityLattice {
                extensions: BTreeMap::new(),
                ..CapabilityLattice::bottom()
            };
            let c_sparse = {
                let mut m = BTreeMap::new();
                m.insert(ext_op.clone(), c_ext);
                CapabilityLattice {
                    extensions: m,
                    ..CapabilityLattice::bottom()
                }
            };

            let lhs = c_sparse.meet(&a_sparse).leq(&b_sparse);
            let rhs = c_sparse.leq_himp(&a_sparse.implies(&b_sparse));
            assert_eq!(
                lhs, rhs,
                "Sparse adjunction failed for c_ext={:?} (a,b have no entry for K)",
                c_ext
            );
        }
    }

    /// Verifies the adjunction holds for the "sparse key" scenario using `leq_himp()`.
    ///
    /// When `c` has extension key K but neither `a` nor `b` mention K, the implication
    /// `a.implies(b)` correctly omits an entry for K (since `level_implies(Never, Never)
    /// = Always` and Always is the absent-key default for implication results). Using
    /// `leq_himp()` — which treats absent keys in the RHS as `Always` — the adjunction
    /// holds:
    ///
    ///   LHS: `(c ∧ a)[K] = min(LowRisk, Never) = Never ≤ Never = true`
    ///   RHS: `c[K] = LowRisk ≤ Always = (a ⇨ b)[K] (absent = Always default) = true`
    ///
    /// Contrast with `leq()`: `leq()` uses `Never` as the absent-key default (the
    /// fail-closed security default for regular capability enforcement), so
    /// `c.leq(&a.implies(&b))` returns false for this case. `leq()` is CORRECT for
    /// policy enforcement (`requested.leq(&allowed)`) but WRONG for adjunction checks.
    /// Always use `leq_himp()` when comparing against an implication result.
    #[cfg(not(kani))]
    #[test]
    fn test_heyting_adjunction_extensions_sparse_leq_himp() {
        use crate::capability::ExtensionOperation;
        use std::collections::BTreeMap;

        let ext_op = ExtensionOperation::new("unknown_to_a_and_b");

        // c knows about ext_op; a and b do not (sparse "absent = Never")
        let a = CapabilityLattice {
            extensions: BTreeMap::new(),
            ..CapabilityLattice::bottom()
        };
        let b = CapabilityLattice {
            extensions: BTreeMap::new(),
            ..CapabilityLattice::bottom()
        };
        let c = CapabilityLattice {
            extensions: {
                let mut m = BTreeMap::new();
                m.insert(ext_op.clone(), CapabilityLevel::LowRisk);
                m
            },
            ..CapabilityLattice::bottom()
        };

        // LHS: (c ∧ a)[K] = min(LowRisk, Never) = Never ≤ Never = true
        let lhs = c.meet(&a).leq(&b);
        assert!(lhs, "LHS must be true: min(LowRisk,Never)=Never ≤ Never");

        // The implication result omits K (both a and b have no entry for K).
        // Absent key in implies result = Always (the correct implication default).
        let implication = a.implies(&b);
        assert!(
            !implication.extensions.contains_key(&ext_op),
            "Key absent from both operands should be absent from implies result \
             (absent = Always by convention)"
        );

        // RHS via leq_himp: treats absent key in implication result as Always.
        // c[K] = LowRisk ≤ Always = true. Adjunction holds.
        let rhs_himp = c.leq_himp(&implication);
        assert!(
            rhs_himp,
            "Adjunction must hold via leq_himp: c[K]=LowRisk ≤ Always (absent-key default)"
        );
        assert_eq!(
            lhs, rhs_himp,
            "Heyting adjunction (c ∧ a) ≤ b ↔ c ≤ (a ⇨ b) must hold via leq_himp"
        );

        // Document: leq() gives wrong answer here (Never default, not Always).
        // This is intentional: leq() is the security-correct method for policy
        // enforcement where absent key = "operation not permitted".
        let rhs_leq = c.leq(&implication);
        assert!(
            !rhs_leq,
            "leq() uses Never default for absent keys — correct for security enforcement, \
             wrong for adjunction checks; use leq_himp() for adjunction checks"
        );

        // Confirm: level_implies(Never, Never) = Always
        assert_eq!(
            level_implies(CapabilityLevel::Never, CapabilityLevel::Never),
            CapabilityLevel::Always,
            "level_implies(Never, Never) = Always (the correct absent-key default)"
        );
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
