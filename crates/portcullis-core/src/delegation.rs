//! Delegation plane — sealed tokens with scope, expiry, and sink ceilings.
//!
//! Extends the capability-lattice delegation model with structured constraints
//! that enforce narrowing at every delegation step:
//!
//! - **Scope**: Which file paths, repositories, and sink classes the delegate
//!   may access. A child's scope must be a subset of its parent's.
//! - **Depth**: Maximum further sub-delegations allowed. Decremented at each
//!   delegation step; zero means the delegate cannot delegate further.
//! - **Expiry**: Unix timestamp after which the delegation is invalid. A child's
//!   expiry cannot exceed its parent's.
//!
//! # Narrowing invariant
//!
//! Delegation is monotone-attenuating: every child constraint is at most as
//! permissive as its parent on every dimension. [`DelegationConstraints::narrow`]
//! enforces this by intersecting scopes and taking the minimum of numeric bounds.

use crate::SinkClass;

/// Scope restrictions for a delegation — which resources the delegate may touch.
///
/// All fields use allowlist semantics: an empty list means nothing is allowed
/// in that dimension. A child scope must be a subset of its parent scope on
/// every dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DelegationScope {
    /// Glob-style path patterns the delegate may access (e.g., `"src/**"`).
    /// Empty = no file access allowed.
    pub allowed_paths: Vec<String>,
    /// Sink classes the delegate is permitted to use.
    /// Empty = no side effects allowed (read-only).
    pub allowed_sinks: Vec<SinkClass>,
    /// Repository identifiers the delegate may operate on (e.g., `"org/repo"`).
    /// Empty = no repository access allowed.
    pub allowed_repos: Vec<String>,
}

impl DelegationScope {
    /// An empty scope that permits nothing.
    pub fn empty() -> Self {
        Self {
            allowed_paths: Vec::new(),
            allowed_sinks: Vec::new(),
            allowed_repos: Vec::new(),
        }
    }

    /// A maximally permissive scope (all sink classes, wildcard path/repo).
    pub fn unrestricted() -> Self {
        Self {
            allowed_paths: vec!["**".to_string()],
            allowed_sinks: SinkClass::ALL.to_vec(),
            allowed_repos: vec!["*".to_string()],
        }
    }

    /// Returns true if `self` is a subset of `parent` on every dimension.
    ///
    /// Subset means: every element in `self.allowed_X` must appear in
    /// `parent.allowed_X`. This is a simple containment check — glob
    /// pattern subsumption (e.g., `"src/lib.rs"` ⊆ `"src/**"`) is NOT
    /// evaluated here; the caller must expand globs before comparison
    /// or use literal paths.
    pub fn is_subset_of(&self, parent: &DelegationScope) -> bool {
        let paths_ok = self
            .allowed_paths
            .iter()
            .all(|p| parent.allowed_paths.contains(p));
        let sinks_ok = self
            .allowed_sinks
            .iter()
            .all(|s| parent.allowed_sinks.contains(s));
        let repos_ok = self
            .allowed_repos
            .iter()
            .all(|r| parent.allowed_repos.contains(r));
        paths_ok && sinks_ok && repos_ok
    }

    /// Intersect this scope with `other`, producing the narrowest scope
    /// that satisfies both. Each dimension retains only elements present
    /// in both scopes.
    pub fn intersect(&self, other: &DelegationScope) -> DelegationScope {
        DelegationScope {
            allowed_paths: self
                .allowed_paths
                .iter()
                .filter(|p| other.allowed_paths.contains(p))
                .cloned()
                .collect(),
            allowed_sinks: self
                .allowed_sinks
                .iter()
                .filter(|s| other.allowed_sinks.contains(s))
                .copied()
                .collect(),
            allowed_repos: self
                .allowed_repos
                .iter()
                .filter(|r| other.allowed_repos.contains(r))
                .cloned()
                .collect(),
        }
    }
}

/// Constraints on a delegation token: scope, depth limit, and expiry.
///
/// These are carried alongside (or embedded in) a `LatticeCertificate` to
/// restrict not just *what capabilities* a delegate has, but *where*, *when*,
/// and *how deeply* those capabilities may be exercised.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DelegationConstraints {
    /// Which resources and sinks the delegate may access.
    pub scope: DelegationScope,
    /// Maximum number of further sub-delegations allowed.
    /// 0 = the delegate cannot delegate to others.
    pub max_delegation_depth: u32,
    /// Unix timestamp (seconds) after which this delegation is invalid.
    pub expires_at: u64,
}

impl DelegationConstraints {
    /// Check whether the delegation is still valid at the given unix timestamp.
    pub fn is_valid(&self, now: u64) -> bool {
        now <= self.expires_at
    }

    /// Check whether the holder can delegate further at the given chain depth.
    ///
    /// `current_depth` is the number of delegation steps already taken
    /// (0 for the original principal, 1 for its first delegate, etc.).
    pub fn can_delegate_further(&self, current_depth: u32) -> bool {
        current_depth < self.max_delegation_depth
    }

    /// Create a narrower child constraint by intersecting scopes and taking
    /// the minimum of numeric bounds.
    ///
    /// Returns `None` if the requested child is not actually narrower than
    /// (or equal to) `self` — i.e., if narrowing would need to *widen* any
    /// dimension.
    pub fn narrow(&self, child: &DelegationConstraints) -> Option<DelegationConstraints> {
        // Child scope must be subset of parent scope
        if !child.scope.is_subset_of(&self.scope) {
            return None;
        }
        // Child expiry must not exceed parent expiry
        if child.expires_at > self.expires_at {
            return None;
        }
        // Child depth must not exceed parent depth
        if child.max_delegation_depth > self.max_delegation_depth {
            return None;
        }

        Some(DelegationConstraints {
            scope: self.scope.intersect(&child.scope),
            max_delegation_depth: self.max_delegation_depth.min(child.max_delegation_depth),
            expires_at: self.expires_at.min(child.expires_at),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC harnesses — delegation chain monotonicity
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_delegation_proofs {
    use super::*;

    /// Generate a symbolic SinkClass.
    fn any_sink_class() -> SinkClass {
        let v: u8 = kani::any();
        kani::assume((v as usize) < SinkClass::ALL.len());
        SinkClass::ALL[v as usize]
    }

    /// Generate a symbolic DelegationScope with bounded element counts
    /// for tractable verification (0-2 elements per dimension).
    fn any_scope() -> DelegationScope {
        let path_count: u8 = kani::any();
        kani::assume(path_count <= 2);
        let sink_count: u8 = kani::any();
        kani::assume(sink_count <= 2);

        // Use fixed path/repo strings for subset checking tractability
        let all_paths = ["src/**", "tests/**"];
        let all_repos = ["org/a", "org/b"];

        let mut paths = Vec::new();
        let mut repos = Vec::new();
        let mut sinks = Vec::new();

        // Bitmask selection for paths (2 bits)
        let path_mask: u8 = kani::any();
        kani::assume(path_mask <= 3);
        for i in 0..2u8 {
            if path_mask & (1 << i) != 0 {
                paths.push(all_paths[i as usize].to_string());
            }
        }

        // Bitmask selection for repos (2 bits)
        let repo_mask: u8 = kani::any();
        kani::assume(repo_mask <= 3);
        for i in 0..2u8 {
            if repo_mask & (1 << i) != 0 {
                repos.push(all_repos[i as usize].to_string());
            }
        }

        // Bitmask selection for sinks (use first 4 sink classes for tractability)
        let sink_mask: u8 = kani::any();
        kani::assume(sink_mask <= 15);
        let available_sinks = [
            SinkClass::WorkspaceWrite,
            SinkClass::GitCommit,
            SinkClass::BashExec,
            SinkClass::GitPush,
        ];
        for i in 0..4u8 {
            if sink_mask & (1 << i) != 0 {
                sinks.push(available_sinks[i as usize]);
            }
        }

        DelegationScope {
            allowed_paths: paths,
            allowed_sinks: sinks,
            allowed_repos: repos,
        }
    }

    /// Generate symbolic DelegationConstraints.
    fn any_constraints() -> DelegationConstraints {
        DelegationConstraints {
            scope: any_scope(),
            max_delegation_depth: kani::any::<u32>() % 8,
            expires_at: kani::any::<u64>(),
        }
    }

    /// **DEL1 — Single-step narrowing is monotone: child ≤ parent.**
    ///
    /// If `narrow()` succeeds, the result has:
    /// - scope that is a subset of the parent's scope
    /// - max_delegation_depth ≤ parent's depth
    /// - expires_at ≤ parent's expiry
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(5)]
    fn proof_narrow_monotone() {
        let parent = any_constraints();
        let child = any_constraints();

        if let Some(result) = parent.narrow(&child) {
            assert!(result.scope.is_subset_of(&parent.scope));
            assert!(result.max_delegation_depth <= parent.max_delegation_depth);
            assert!(result.expires_at <= parent.expires_at);
        }
    }

    /// **DEL2 — Two-step delegation chain: terminal ≤ initial.**
    ///
    /// For any root and two levels of delegation: if both narrowing steps
    /// succeed, the final constraints are at most as permissive as the root.
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(5)]
    fn proof_delegation_chain_monotone() {
        let root = any_constraints();
        let level1 = any_constraints();
        let level2 = any_constraints();

        if let Some(narrowed1) = root.narrow(&level1) {
            if let Some(narrowed2) = narrowed1.narrow(&level2) {
                // Terminal constraints must be ≤ root on every dimension
                assert!(narrowed2.scope.is_subset_of(&root.scope));
                assert!(narrowed2.max_delegation_depth <= root.max_delegation_depth);
                assert!(narrowed2.expires_at <= root.expires_at);
            }
        }
    }

    /// **DEL3 — Narrowing is idempotent: narrow(self) = self.**
    ///
    /// Narrowing a constraint set by itself always succeeds and returns
    /// an equivalent constraint set.
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(5)]
    fn proof_narrow_idempotent() {
        let c = any_constraints();
        let result = c.narrow(&c);
        assert!(result.is_some(), "narrowing by self must succeed");
        let result = result.unwrap();
        assert_eq!(result.max_delegation_depth, c.max_delegation_depth);
        assert_eq!(result.expires_at, c.expires_at);
        // Scope intersection with itself should preserve all elements
        assert!(result.scope.is_subset_of(&c.scope));
        assert!(c.scope.is_subset_of(&result.scope));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_scope() -> DelegationScope {
        DelegationScope {
            allowed_paths: vec!["src/**".to_string(), "tests/**".to_string()],
            allowed_sinks: vec![
                SinkClass::WorkspaceWrite,
                SinkClass::GitCommit,
                SinkClass::BashExec,
            ],
            allowed_repos: vec!["org/repo-a".to_string(), "org/repo-b".to_string()],
        }
    }

    fn child_scope() -> DelegationScope {
        DelegationScope {
            allowed_paths: vec!["src/**".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit],
            allowed_repos: vec!["org/repo-a".to_string()],
        }
    }

    // ── DelegationScope::is_subset_of ───────────────────────────────

    #[test]
    fn child_scope_is_subset_of_parent() {
        assert!(child_scope().is_subset_of(&parent_scope()));
    }

    #[test]
    fn parent_scope_is_not_subset_of_child() {
        assert!(!parent_scope().is_subset_of(&child_scope()));
    }

    #[test]
    fn scope_is_subset_of_itself() {
        assert!(parent_scope().is_subset_of(&parent_scope()));
    }

    #[test]
    fn empty_scope_is_subset_of_everything() {
        assert!(DelegationScope::empty().is_subset_of(&parent_scope()));
        assert!(DelegationScope::empty().is_subset_of(&DelegationScope::empty()));
    }

    #[test]
    fn non_empty_scope_is_not_subset_of_empty() {
        assert!(!parent_scope().is_subset_of(&DelegationScope::empty()));
    }

    #[test]
    fn disjoint_sinks_not_subset() {
        let scope = DelegationScope {
            allowed_paths: vec!["src/**".to_string()],
            allowed_sinks: vec![SinkClass::GitPush], // not in parent
            allowed_repos: vec!["org/repo-a".to_string()],
        };
        assert!(!scope.is_subset_of(&parent_scope()));
    }

    #[test]
    fn disjoint_repos_not_subset() {
        let scope = DelegationScope {
            allowed_paths: vec!["src/**".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite],
            allowed_repos: vec!["other/repo".to_string()], // not in parent
        };
        assert!(!scope.is_subset_of(&parent_scope()));
    }

    // ── DelegationScope::intersect ──────────────────────────────────

    #[test]
    fn intersect_retains_common_elements() {
        let result = parent_scope().intersect(&child_scope());
        assert_eq!(result.allowed_paths, vec!["src/**".to_string()]);
        assert_eq!(
            result.allowed_sinks,
            vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit]
        );
        assert_eq!(result.allowed_repos, vec!["org/repo-a".to_string()]);
    }

    #[test]
    fn intersect_with_empty_yields_empty() {
        let result = parent_scope().intersect(&DelegationScope::empty());
        assert!(result.allowed_paths.is_empty());
        assert!(result.allowed_sinks.is_empty());
        assert!(result.allowed_repos.is_empty());
    }

    // ── DelegationConstraints::is_valid ─────────────────────────────

    #[test]
    fn valid_before_expiry() {
        let c = DelegationConstraints {
            scope: child_scope(),
            max_delegation_depth: 2,
            expires_at: 1000,
        };
        assert!(c.is_valid(999));
        assert!(c.is_valid(1000)); // at expiry is still valid
        assert!(!c.is_valid(1001)); // past expiry
    }

    // ── DelegationConstraints::can_delegate_further ─────────────────

    #[test]
    fn delegation_depth_limits() {
        let c = DelegationConstraints {
            scope: child_scope(),
            max_delegation_depth: 2,
            expires_at: u64::MAX,
        };
        assert!(c.can_delegate_further(0));
        assert!(c.can_delegate_further(1));
        assert!(!c.can_delegate_further(2));
        assert!(!c.can_delegate_further(3));
    }

    #[test]
    fn zero_depth_cannot_delegate() {
        let c = DelegationConstraints {
            scope: child_scope(),
            max_delegation_depth: 0,
            expires_at: u64::MAX,
        };
        assert!(!c.can_delegate_further(0));
    }

    // ── DelegationConstraints::narrow ───────────────────────────────

    #[test]
    fn narrow_succeeds_for_valid_child() {
        let parent = DelegationConstraints {
            scope: parent_scope(),
            max_delegation_depth: 3,
            expires_at: 2000,
        };
        let requested = DelegationConstraints {
            scope: child_scope(),
            max_delegation_depth: 1,
            expires_at: 1500,
        };
        let result = parent.narrow(&requested).expect("should succeed");
        assert_eq!(result.max_delegation_depth, 1);
        assert_eq!(result.expires_at, 1500);
        assert_eq!(result.scope.allowed_paths, vec!["src/**".to_string()]);
        assert_eq!(
            result.scope.allowed_sinks,
            vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit]
        );
    }

    #[test]
    fn narrow_fails_if_child_scope_wider() {
        let parent = DelegationConstraints {
            scope: child_scope(), // narrower
            max_delegation_depth: 3,
            expires_at: 2000,
        };
        let requested = DelegationConstraints {
            scope: parent_scope(), // wider — violation
            max_delegation_depth: 1,
            expires_at: 1500,
        };
        assert!(parent.narrow(&requested).is_none());
    }

    #[test]
    fn narrow_fails_if_child_expiry_exceeds_parent() {
        let parent = DelegationConstraints {
            scope: parent_scope(),
            max_delegation_depth: 3,
            expires_at: 1000,
        };
        let requested = DelegationConstraints {
            scope: child_scope(),
            max_delegation_depth: 1,
            expires_at: 2000, // exceeds parent — violation
        };
        assert!(parent.narrow(&requested).is_none());
    }

    #[test]
    fn narrow_fails_if_child_depth_exceeds_parent() {
        let parent = DelegationConstraints {
            scope: parent_scope(),
            max_delegation_depth: 2,
            expires_at: 2000,
        };
        let requested = DelegationConstraints {
            scope: child_scope(),
            max_delegation_depth: 5, // exceeds parent — violation
            expires_at: 1500,
        };
        assert!(parent.narrow(&requested).is_none());
    }

    #[test]
    fn narrow_identity_succeeds() {
        let c = DelegationConstraints {
            scope: parent_scope(),
            max_delegation_depth: 3,
            expires_at: 2000,
        };
        let result = c.narrow(&c).expect("narrowing by self should succeed");
        assert_eq!(result.max_delegation_depth, 3);
        assert_eq!(result.expires_at, 2000);
        assert_eq!(result.scope, parent_scope());
    }

    #[test]
    fn narrow_to_empty_scope_succeeds() {
        let parent = DelegationConstraints {
            scope: parent_scope(),
            max_delegation_depth: 3,
            expires_at: 2000,
        };
        let requested = DelegationConstraints {
            scope: DelegationScope::empty(),
            max_delegation_depth: 0,
            expires_at: 500,
        };
        let result = parent
            .narrow(&requested)
            .expect("empty scope is always subset");
        assert!(result.scope.allowed_paths.is_empty());
        assert!(result.scope.allowed_sinks.is_empty());
        assert!(result.scope.allowed_repos.is_empty());
        assert_eq!(result.max_delegation_depth, 0);
        assert_eq!(result.expires_at, 500);
    }

    // ── Chained narrowing ───────────────────────────────────────────

    #[test]
    fn chained_narrowing_is_monotone() {
        // Root has all the paths/sinks/repos that children will request
        let root = DelegationConstraints {
            scope: parent_scope(),
            max_delegation_depth: 5,
            expires_at: 10_000,
        };
        let level1 = DelegationConstraints {
            scope: parent_scope(),
            max_delegation_depth: 3,
            expires_at: 5_000,
        };
        let level2 = DelegationConstraints {
            scope: child_scope(),
            max_delegation_depth: 1,
            expires_at: 3_000,
        };

        let narrowed1 = root.narrow(&level1).expect("level1 narrows root");
        let narrowed2 = narrowed1.narrow(&level2).expect("level2 narrows level1");

        // Final result should be the most restrictive
        assert_eq!(narrowed2.max_delegation_depth, 1);
        assert_eq!(narrowed2.expires_at, 3_000);
        assert!(narrowed2.scope.is_subset_of(&narrowed1.scope));
        assert!(narrowed1.scope.is_subset_of(&root.scope));
    }
}
