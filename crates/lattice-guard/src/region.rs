//! Code region lattice for coordinating concurrent agent modifications.
//!
//! A `CodeRegion` represents a set of file paths within a repository.
//! Regions form a **distributive lattice** under set containment:
//!
//! ```text
//! Ordering:  r1 ≤ r2  iff  r1.files ⊆ r2.files
//! Meet (∧):  intersection of file sets (overlap between claims)
//! Join (∨):  union of file sets (combined claim)
//! Bottom (⊥): empty set (no files)
//! Top (⊤):   sentinel representing "all files"
//! ```
//!
//! # Key theorem
//!
//! Two agents' claims conflict iff `meet(claim_a, claim_b) ≠ ⊥`.
//!
//! This gives a lattice-theoretic oracle for safe parallelism:
//! when the meet is bottom, agents touch disjoint file sets and can
//! proceed concurrently without conflicts.

use std::collections::BTreeSet;

use crate::frame::{BoundedLattice, Lattice};

/// Sentinel value stored in `files` to represent "all files" (⊤).
const TOP_SENTINEL: &str = "**";

/// A code region: a set of file paths within a repository.
///
/// Implements the `Lattice` and `BoundedLattice` traits from `frame.rs`.
/// Meet = intersection, join = union, bottom = empty, top = `{"**"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRegion {
    /// Repository identifier (owner, repo).
    pub repo: (String, String),
    /// Materialized file paths in this region.
    /// Empty = bottom (no files). Contains `"**"` = top (all files).
    pub files: BTreeSet<String>,
}

impl CodeRegion {
    /// Create a region with specific files.
    pub fn new(owner: impl Into<String>, repo: impl Into<String>, files: BTreeSet<String>) -> Self {
        Self {
            repo: (owner.into(), repo.into()),
            files,
        }
    }

    /// Create an empty region (bottom) for a repo.
    pub fn empty(owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            repo: (owner.into(), repo.into()),
            files: BTreeSet::new(),
        }
    }

    /// Create a region covering all files (top) for a repo.
    pub fn all(owner: impl Into<String>, repo: impl Into<String>) -> Self {
        let mut files = BTreeSet::new();
        files.insert(TOP_SENTINEL.to_string());
        Self {
            repo: (owner.into(), repo.into()),
            files,
        }
    }

    /// Create a region from a list of file paths.
    pub fn from_files(
        owner: impl Into<String>,
        repo: impl Into<String>,
        paths: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            repo: (owner.into(), repo.into()),
            files: paths.into_iter().map(|p| p.into()).collect(),
        }
    }

    /// Returns true if this region represents "all files" (⊤).
    pub fn is_top(&self) -> bool {
        self.files.contains(TOP_SENTINEL)
    }

    /// Returns true if this region is empty (⊥).
    pub fn is_bottom(&self) -> bool {
        self.files.is_empty()
    }

    /// Number of files in this region (0 for bottom, usize::MAX for top).
    pub fn file_count(&self) -> usize {
        if self.is_top() {
            usize::MAX
        } else {
            self.files.len()
        }
    }

    /// Returns the set of overlapping files between two regions.
    pub fn overlap(&self, other: &Self) -> BTreeSet<String> {
        if self.repo != other.repo {
            return BTreeSet::new();
        }
        self.meet(other).files
    }
}

impl Lattice for CodeRegion {
    /// Meet (∧) = intersection of file sets.
    ///
    /// - `⊤ ∧ x = x` (top is identity)
    /// - `⊥ ∧ x = ⊥` (bottom is annihilator)
    /// - Different repos → ⊥ (no overlap across repos)
    fn meet(&self, other: &Self) -> Self {
        // Different repos have no overlap
        if self.repo != other.repo {
            return Self::empty("", "");
        }

        // Top is identity for meet
        if self.is_top() {
            return other.clone();
        }
        if other.is_top() {
            return self.clone();
        }

        // Intersection of file sets
        let files: BTreeSet<String> = self.files.intersection(&other.files).cloned().collect();

        Self {
            repo: self.repo.clone(),
            files,
        }
    }

    /// Join (∨) = union of file sets.
    ///
    /// - `⊤ ∨ x = ⊤` (top is annihilator)
    /// - `⊥ ∨ x = x` (bottom is identity)
    /// - Different repos → join contains both (modeled as top for simplicity)
    fn join(&self, other: &Self) -> Self {
        // Different repos: join is top (conservative)
        if self.repo != other.repo {
            return Self::all(&self.repo.0, &self.repo.1);
        }

        // Top is annihilator for join
        if self.is_top() || other.is_top() {
            return Self::all(&self.repo.0, &self.repo.1);
        }

        // Union of file sets
        let files: BTreeSet<String> = self.files.union(&other.files).cloned().collect();

        Self {
            repo: self.repo.clone(),
            files,
        }
    }

    /// Partial order: `a ≤ b` iff `a ∧ b = a` (i.e., a.files ⊆ b.files).
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
        self.files.is_subset(&other.files)
    }
}

impl BoundedLattice for CodeRegion {
    /// Top (⊤): all files in the repository.
    fn top() -> Self {
        Self::all("*", "*")
    }

    /// Bottom (⊥): empty set.
    fn bottom() -> Self {
        Self::empty("*", "*")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for a in sample_regions() {
            for b in sample_regions() {
                assert_eq!(a.meet(&b), b.meet(&a), "meet must be commutative");
            }
        }
    }

    #[test]
    fn test_join_commutativity() {
        for a in sample_regions() {
            for b in sample_regions() {
                assert_eq!(a.join(&b), b.join(&a), "join must be commutative");
            }
        }
    }

    #[test]
    fn test_meet_associativity() {
        let samples = sample_regions();
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
        let samples = sample_regions();
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
        for a in sample_regions() {
            assert_eq!(a.meet(&a), a, "meet must be idempotent");
            assert_eq!(a.join(&a), a, "join must be idempotent");
        }
    }

    #[test]
    fn test_absorption() {
        for a in sample_regions() {
            for b in sample_regions() {
                // a ∧ (a ∨ b) = a
                assert_eq!(a.meet(&a.join(&b)), a, "absorption: a ∧ (a ∨ b) = a");
                // a ∨ (a ∧ b) = a
                assert_eq!(a.join(&a.meet(&b)), a, "absorption: a ∨ (a ∧ b) = a");
            }
        }
    }

    #[test]
    fn test_distributivity() {
        let samples = sample_regions();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    // a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)
                    let lhs = a.meet(&b.join(c));
                    let rhs = a.meet(b).join(&a.meet(c));
                    assert_eq!(lhs, rhs, "meet must distribute over join");

                    // a ∨ (b ∧ c) = (a ∨ b) ∧ (a ∨ c)
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
        let top = CodeRegion::all("o", "r");
        for a in sample_regions() {
            assert_eq!(a.meet(&top), a, "a ∧ ⊤ = a");
        }
    }

    #[test]
    fn test_bottom_is_join_identity() {
        let bot = CodeRegion::empty("o", "r");
        for a in sample_regions() {
            assert_eq!(a.join(&bot), a, "a ∨ ⊥ = a");
        }
    }

    #[test]
    fn test_bottom_is_meet_annihilator() {
        let bot = CodeRegion::empty("o", "r");
        for a in sample_regions() {
            assert_eq!(a.meet(&bot), bot, "a ∧ ⊥ = ⊥");
        }
    }

    #[test]
    fn test_top_is_join_annihilator() {
        let top = CodeRegion::all("o", "r");
        for a in sample_regions() {
            assert_eq!(a.join(&top), top, "a ∨ ⊤ = ⊤");
        }
    }

    // ── Partial order ─────────────────────────────────────────────────

    #[test]
    fn test_leq_consistent_with_meet() {
        for a in sample_regions() {
            for b in sample_regions() {
                // a ≤ b iff a ∧ b = a
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
        let bot = CodeRegion::empty("o", "r");
        for a in sample_regions() {
            assert!(bot.leq(&a), "⊥ ≤ a for all a");
        }
    }

    #[test]
    fn test_everything_leq_top() {
        let top = CodeRegion::all("o", "r");
        for a in sample_regions() {
            assert!(a.leq(&top), "a ≤ ⊤ for all a");
        }
    }

    // ── Domain-specific tests ─────────────────────────────────────────

    #[test]
    fn test_conflict_detection_via_meet() {
        let agent_a = CodeRegion::from_files("co", "gt", ["src/bridge.rs", "src/config.rs"]);
        let agent_b = CodeRegion::from_files("co", "gt", ["src/bridge.rs", "src/main.rs"]);

        let overlap = agent_a.meet(&agent_b);
        assert!(
            !overlap.is_bottom(),
            "agents touching same file must conflict"
        );
        assert_eq!(overlap.files.len(), 1);
        assert!(overlap.files.contains("src/bridge.rs"));
    }

    #[test]
    fn test_no_conflict_disjoint_files() {
        let agent_a = CodeRegion::from_files("co", "gt", ["src/config.rs"]);
        let agent_b = CodeRegion::from_files("co", "gt", ["src/main.rs"]);

        let overlap = agent_a.meet(&agent_b);
        assert!(
            overlap.is_bottom(),
            "agents touching different files must not conflict"
        );
    }

    #[test]
    fn test_no_conflict_different_repos() {
        let agent_a = CodeRegion::from_files("co", "repo-a", ["src/main.rs"]);
        let agent_b = CodeRegion::from_files("co", "repo-b", ["src/main.rs"]);

        let overlap = agent_a.meet(&agent_b);
        assert!(
            overlap.is_bottom(),
            "same file in different repos must not conflict"
        );
    }

    #[test]
    fn test_top_conflicts_with_everything() {
        let top = CodeRegion::all("co", "gt");
        let specific = CodeRegion::from_files("co", "gt", ["src/main.rs"]);

        let overlap = top.meet(&specific);
        assert!(
            !overlap.is_bottom(),
            "top must conflict with any non-bottom region"
        );
        assert_eq!(overlap, specific);
    }

    #[test]
    fn test_combined_claim_via_join() {
        let claim_a = CodeRegion::from_files("co", "gt", ["src/a.rs"]);
        let claim_b = CodeRegion::from_files("co", "gt", ["src/b.rs"]);

        let combined = claim_a.join(&claim_b);
        assert!(combined.files.contains("src/a.rs"));
        assert!(combined.files.contains("src/b.rs"));
        assert_eq!(combined.file_count(), 2);
    }

    #[test]
    fn test_overlap_helper() {
        let a = CodeRegion::from_files("co", "gt", ["x.rs", "y.rs"]);
        let b = CodeRegion::from_files("co", "gt", ["y.rs", "z.rs"]);

        let common = a.overlap(&b);
        assert_eq!(common.len(), 1);
        assert!(common.contains("y.rs"));
    }
}
