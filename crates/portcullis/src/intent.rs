//! Work intent lattice for predicting code region impact.
//!
//! A `WorkIntent` describes what kind of work an agent intends to perform
//! and which files it expects to touch. Intents form a **distributive lattice**
//! under scope containment, isomorphic to the `CodeRegion` lattice:
//!
//! ```text
//! Ordering:  i1 ≤ i2  iff  i1.scope ⊆ i2.scope
//! Meet (∧):  intersection of scope sets
//! Join (∨):  union of scope sets
//! Bottom (⊥): empty scope (no work)
//! Top (⊤):   sentinel representing "any modification"
//! ```
//!
//! # Galois Connection
//!
//! The pair `(alpha, gamma)` between `WorkIntent` and `CodeRegion` forms a
//! Galois connection when both are powerset lattices over the same string
//! universe (file paths):
//!
//! ```text
//! alpha(intent) = CodeRegion with intent.scope as files
//! gamma(region) = WorkIntent with region.files as scope
//!
//! Adjunction: alpha(i) ≤ r  ⟺  i ≤ gamma(r)
//!             (scope ⊆ files ⟺ scope ⊆ files)
//! ```
//!
//! This is the identity embedding — trivially correct. Learned expansions
//! (co-occurrence, type patterns) are applied as pre-processing before alpha,
//! inflating the scope conservatively.

use std::collections::BTreeSet;

use crate::frame::{BoundedLattice, Lattice};
use crate::region::CodeRegion;

/// Sentinel value stored in `scope` to represent "any modification" (⊤).
const TOP_SENTINEL: &str = "**";

/// A work intent: an abstract description of what work an agent will perform.
///
/// The `scope` field contains file paths or directory prefixes that the intent
/// expects to touch. The `kind` field is informational and does **not** affect
/// the lattice ordering — this is critical for preserving the Galois adjunction.
#[derive(Debug, Clone)]
pub struct WorkIntent {
    /// Repository identifier (owner, repo).
    pub repo: (String, String),
    /// Scope tags: file paths, directory prefixes, or semantic markers.
    /// Empty = bottom (no work). Contains `"**"` = top (any modification).
    pub scope: BTreeSet<String>,
    /// The kind of work (informational, not part of lattice ordering).
    pub kind: IntentKind,
}

/// Equality is defined only on `(repo, scope)` — `kind` is informational
/// and excluded to preserve lattice laws. Without this, `meet(a, a)` would
/// not equal `a` because `meet` resets `kind` to `General`.
impl PartialEq for WorkIntent {
    fn eq(&self, other: &Self) -> bool {
        self.repo == other.repo && self.scope == other.scope
    }
}

impl Eq for WorkIntent {}

/// The kind of work being performed.
///
/// Used by the impact predictor to refine file predictions, but does **not**
/// affect the lattice ordering. This separation is essential: if `IntentKind`
/// participated in ordering, the Galois adjunction with `CodeRegion` would break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentKind {
    /// Fix a bug — touches files around the reported location.
    BugFix,
    /// Refactor — touches the specified module and its dependents.
    Refactor,
    /// Add a new feature — may create new files, touches related modules.
    Feature,
    /// Code review — read-only intent (alpha maps to bottom).
    Review,
    /// Documentation — touches docs/ and related source files.
    Documentation,
    /// CI/CD — touches workflow files and build configs.
    CiCd,
    /// Testing — touches test files and the modules under test.
    Testing,
    /// General — no structural hint.
    General,
}

impl WorkIntent {
    /// Create an intent with specific scope tags and kind.
    pub fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        scope: BTreeSet<String>,
        kind: IntentKind,
    ) -> Self {
        Self {
            repo: (owner.into(), repo.into()),
            scope,
            kind,
        }
    }

    /// Create an empty intent (bottom) — no work.
    pub fn empty(owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            repo: (owner.into(), repo.into()),
            scope: BTreeSet::new(),
            kind: IntentKind::General,
        }
    }

    /// Create a universal intent (top) — may touch anything.
    pub fn all(owner: impl Into<String>, repo: impl Into<String>) -> Self {
        let mut scope = BTreeSet::new();
        scope.insert(TOP_SENTINEL.to_string());
        Self {
            repo: (owner.into(), repo.into()),
            scope,
            kind: IntentKind::General,
        }
    }

    /// Create an intent from a list of file paths.
    pub fn from_files(
        owner: impl Into<String>,
        repo: impl Into<String>,
        paths: impl IntoIterator<Item = impl Into<String>>,
        kind: IntentKind,
    ) -> Self {
        Self {
            repo: (owner.into(), repo.into()),
            scope: paths.into_iter().map(|p| p.into()).collect(),
            kind,
        }
    }

    /// Returns true if this intent represents "any modification" (⊤).
    pub fn is_top(&self) -> bool {
        self.scope.contains(TOP_SENTINEL)
    }

    /// Returns true if this intent is empty (⊥).
    pub fn is_bottom(&self) -> bool {
        self.scope.is_empty()
    }

    /// Number of scope tags (0 for bottom, usize::MAX for top).
    pub fn scope_count(&self) -> usize {
        if self.is_top() {
            usize::MAX
        } else {
            self.scope.len()
        }
    }

    /// Convert this intent to a `CodeRegion` via the identity embedding (alpha).
    ///
    /// This is the pure Galois alpha function: scope tags become file paths.
    pub fn to_region(&self) -> CodeRegion {
        if self.is_top() {
            return CodeRegion::all(&self.repo.0, &self.repo.1);
        }
        if self.is_bottom() {
            return CodeRegion::empty(&self.repo.0, &self.repo.1);
        }
        CodeRegion::new(&self.repo.0, &self.repo.1, self.scope.clone())
    }

    /// Create an intent from a `CodeRegion` via the identity embedding (gamma).
    ///
    /// This is the pure Galois gamma function: file paths become scope tags.
    pub fn from_region(region: &CodeRegion) -> Self {
        if region.is_top() {
            return Self::all(&region.repo.0, &region.repo.1);
        }
        if region.is_bottom() {
            return Self::empty(&region.repo.0, &region.repo.1);
        }
        Self {
            repo: region.repo.clone(),
            scope: region.files.clone(),
            kind: IntentKind::General,
        }
    }
}

impl Lattice for WorkIntent {
    /// Meet (∧) = intersection of scope sets.
    ///
    /// - `⊤ ∧ x = x` (top is identity)
    /// - `⊥ ∧ x = ⊥` (bottom is annihilator)
    /// - Different repos → ⊥
    fn meet(&self, other: &Self) -> Self {
        if self.repo != other.repo {
            return Self::empty("", "");
        }
        if self.is_top() {
            return other.clone();
        }
        if other.is_top() {
            return self.clone();
        }
        let scope: BTreeSet<String> = self.scope.intersection(&other.scope).cloned().collect();
        Self {
            repo: self.repo.clone(),
            scope,
            kind: IntentKind::General,
        }
    }

    /// Join (∨) = union of scope sets.
    ///
    /// - `⊤ ∨ x = ⊤` (top is annihilator)
    /// - `⊥ ∨ x = x` (bottom is identity)
    /// - Different repos → ⊤ (conservative)
    fn join(&self, other: &Self) -> Self {
        if self.repo != other.repo {
            return Self::all(&self.repo.0, &self.repo.1);
        }
        if self.is_top() || other.is_top() {
            return Self::all(&self.repo.0, &self.repo.1);
        }
        let scope: BTreeSet<String> = self.scope.union(&other.scope).cloned().collect();
        Self {
            repo: self.repo.clone(),
            scope,
            kind: IntentKind::General,
        }
    }

    /// Partial order: `a ≤ b` iff `a.scope ⊆ b.scope`.
    fn leq(&self, other: &Self) -> bool {
        if self.repo != other.repo {
            return self.is_bottom();
        }
        if other.is_top() {
            return true;
        }
        if self.is_top() {
            return other.is_top();
        }
        self.scope.is_subset(&other.scope)
    }
}

impl BoundedLattice for WorkIntent {
    /// Top (⊤): any modification.
    fn top() -> Self {
        Self::all("*", "*")
    }

    /// Bottom (⊥): no work.
    fn bottom() -> Self {
        Self::empty("*", "*")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::galois::GaloisConnection;

    fn sample_intents() -> Vec<WorkIntent> {
        vec![
            WorkIntent::empty("o", "r"),
            WorkIntent::from_files("o", "r", ["src/main.rs"], IntentKind::BugFix),
            WorkIntent::from_files("o", "r", ["src/lib.rs"], IntentKind::Refactor),
            WorkIntent::from_files("o", "r", ["src/main.rs", "src/lib.rs"], IntentKind::Feature),
            WorkIntent::from_files(
                "o",
                "r",
                ["src/main.rs", "src/lib.rs", "Cargo.toml"],
                IntentKind::General,
            ),
            WorkIntent::all("o", "r"),
        ]
    }

    fn sample_regions() -> Vec<CodeRegion> {
        vec![
            CodeRegion::empty("o", "r"),
            CodeRegion::from_files("o", "r", ["src/main.rs"]),
            CodeRegion::from_files("o", "r", ["src/lib.rs"]),
            CodeRegion::from_files("o", "r", ["src/main.rs", "src/lib.rs"]),
            CodeRegion::from_files("o", "r", ["src/main.rs", "src/lib.rs", "Cargo.toml"]),
            CodeRegion::all("o", "r"),
        ]
    }

    // ── Lattice laws ──────────────────────────────────────────────────

    #[test]
    fn test_meet_commutativity() {
        for a in sample_intents() {
            for b in sample_intents() {
                assert_eq!(a.meet(&b), b.meet(&a), "meet must be commutative");
            }
        }
    }

    #[test]
    fn test_join_commutativity() {
        for a in sample_intents() {
            for b in sample_intents() {
                assert_eq!(a.join(&b), b.join(&a), "join must be commutative");
            }
        }
    }

    #[test]
    fn test_meet_associativity() {
        let samples = sample_intents();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    assert_eq!(
                        a.meet(&b.meet(c)),
                        a.meet(b).meet(c),
                        "meet must be associative"
                    );
                }
            }
        }
    }

    #[test]
    fn test_join_associativity() {
        let samples = sample_intents();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    assert_eq!(
                        a.join(&b.join(c)),
                        a.join(b).join(c),
                        "join must be associative"
                    );
                }
            }
        }
    }

    #[test]
    fn test_idempotence() {
        for a in sample_intents() {
            assert_eq!(a.meet(&a), a, "meet must be idempotent");
            assert_eq!(a.join(&a), a, "join must be idempotent");
        }
    }

    #[test]
    fn test_absorption() {
        for a in sample_intents() {
            for b in sample_intents() {
                assert_eq!(a.meet(&a.join(&b)), a, "absorption: a ∧ (a ∨ b) = a");
                assert_eq!(a.join(&a.meet(&b)), a, "absorption: a ∨ (a ∧ b) = a");
            }
        }
    }

    #[test]
    fn test_distributivity() {
        let samples = sample_intents();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    let lhs = a.meet(&b.join(c));
                    let rhs = a.meet(b).join(&a.meet(c));
                    assert_eq!(lhs, rhs, "meet must distribute over join");

                    let lhs = a.join(&b.meet(c));
                    let rhs = a.join(b).meet(&a.join(c));
                    assert_eq!(lhs, rhs, "join must distribute over meet");
                }
            }
        }
    }

    // ── Bounded lattice laws ──────────────────────────────────────────

    #[test]
    fn test_top_is_meet_identity() {
        let top = WorkIntent::all("o", "r");
        for a in sample_intents() {
            assert_eq!(a.meet(&top), a, "a ∧ ⊤ = a");
        }
    }

    #[test]
    fn test_bottom_is_join_identity() {
        let bot = WorkIntent::empty("o", "r");
        for a in sample_intents() {
            assert_eq!(a.join(&bot), a, "a ∨ ⊥ = a");
        }
    }

    #[test]
    fn test_bottom_is_meet_annihilator() {
        let bot = WorkIntent::empty("o", "r");
        for a in sample_intents() {
            assert_eq!(a.meet(&bot), bot, "a ∧ ⊥ = ⊥");
        }
    }

    #[test]
    fn test_top_is_join_annihilator() {
        let top = WorkIntent::all("o", "r");
        for a in sample_intents() {
            assert_eq!(a.join(&top), top, "a ∨ ⊤ = ⊤");
        }
    }

    // ── Partial order ─────────────────────────────────────────────────

    #[test]
    fn test_leq_consistent_with_meet() {
        for a in sample_intents() {
            for b in sample_intents() {
                assert_eq!(
                    a.leq(&b),
                    a.meet(&b) == a,
                    "leq must be consistent with meet: a={a:?}, b={b:?}"
                );
            }
        }
    }

    #[test]
    fn test_bottom_leq_everything() {
        let bot = WorkIntent::empty("o", "r");
        for a in sample_intents() {
            assert!(bot.leq(&a), "⊥ ≤ a for all a");
        }
    }

    #[test]
    fn test_everything_leq_top() {
        let top = WorkIntent::all("o", "r");
        for a in sample_intents() {
            assert!(a.leq(&top), "a ≤ ⊤ for all a");
        }
    }

    // ── Galois connection (identity embedding) ────────────────────────

    fn identity_connection() -> GaloisConnection<WorkIntent, CodeRegion> {
        GaloisConnection::new(
            |intent: &WorkIntent| intent.to_region(),
            |region: &CodeRegion| WorkIntent::from_region(region),
        )
    }

    #[test]
    fn test_adjunction_exhaustive() {
        let conn = identity_connection();
        for i in sample_intents() {
            for r in sample_regions() {
                assert!(
                    conn.verify(&i, &r),
                    "adjunction violated: alpha({i:?}) ≤ {r:?} ⟺ {i:?} ≤ gamma({r:?})"
                );
            }
        }
    }

    #[test]
    fn test_adjunction_verified_construction() {
        let samples: Vec<(WorkIntent, CodeRegion)> =
            sample_intents().into_iter().zip(sample_regions()).collect();

        let conn = GaloisConnection::new_verified(
            |intent: &WorkIntent| intent.to_region(),
            |region: &CodeRegion| WorkIntent::from_region(region),
            &samples,
        );
        assert!(conn.is_ok(), "identity embedding must satisfy adjunction");
    }

    #[test]
    fn test_closure_is_inflationary() {
        let conn = identity_connection();
        for i in sample_intents() {
            let closed = conn.closure(&i);
            assert!(i.leq(&closed), "closure must be inflationary: i ≤ γ(α(i))");
        }
    }

    #[test]
    fn test_kernel_is_deflationary() {
        let conn = identity_connection();
        for r in sample_regions() {
            let kerneled = conn.kernel(&r);
            assert!(kerneled.leq(&r), "kernel must be deflationary: α(γ(r)) ≤ r");
        }
    }

    #[test]
    fn test_to_region_round_trip() {
        let intent =
            WorkIntent::from_files("o", "r", ["src/main.rs", "src/lib.rs"], IntentKind::BugFix);
        let region = intent.to_region();
        let back = WorkIntent::from_region(&region);

        // Scope is preserved, kind is reset to General
        assert_eq!(intent.scope, back.scope);
        assert_eq!(back.kind, IntentKind::General);
    }

    #[test]
    fn test_review_intent_maps_to_bottom_region() {
        let review = WorkIntent::empty("o", "r");
        let region = review.to_region();
        assert!(region.is_bottom(), "empty intent maps to bottom region");
    }

    #[test]
    fn test_top_intent_maps_to_top_region() {
        let all = WorkIntent::all("o", "r");
        let region = all.to_region();
        assert!(region.is_top(), "top intent maps to top region");
    }

    #[test]
    fn test_different_repos_meet_is_bottom() {
        let a = WorkIntent::from_files("o", "r1", ["src/main.rs"], IntentKind::General);
        let b = WorkIntent::from_files("o", "r2", ["src/main.rs"], IntentKind::General);
        assert!(a.meet(&b).is_bottom(), "different repos meet = bottom");
    }
}
