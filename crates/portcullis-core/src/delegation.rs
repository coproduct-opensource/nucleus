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

// ═══════════════════════════════════════════════════════════════════════════
// Glob matching — dependency-free, recursive byte-level matcher
// ═══════════════════════════════════════════════════════════════════════════

/// Returns `true` if `parent_pattern` glob-covers `child`.
///
/// Coverage means every concrete path matched by `child` is also matched by
/// `parent_pattern`. When `child` is a literal path (no glob characters),
/// this reduces to `path_glob_match(parent_pattern, child)`. When `child`
/// is itself a glob, we check structural subsumption: the parent must be
/// at least as broad as the child.
fn glob_covers(parent: &str, child: &str) -> bool {
    // Fast path: exact string equality.
    if parent == child {
        return true;
    }
    // If child has no glob characters, it's a literal — just match it.
    if !has_glob_chars(child) {
        return path_glob_match(parent, child);
    }
    // Child is also a glob. Check if parent structurally subsumes it.
    // A parent `**` or `**/X` always covers any child.
    if parent == "**" || parent == "**/*" {
        return true;
    }
    // If both share the same prefix before globs diverge, and the parent's
    // glob is at least as broad, the parent covers the child.
    // Strategy: split on `/` segments and compare pairwise.
    glob_subsumes_segments(parent, child)
}

/// Segment-by-segment glob subsumption check.
///
/// A parent segment covers a child segment if:
/// - parent segment is `**` (covers any number of child segments)
/// - parent segment is `*` and child segment is `*` or a literal
/// - parent segment equals child segment exactly
fn glob_subsumes_segments(parent: &str, child: &str) -> bool {
    let p_segs: Vec<&str> = parent.split('/').collect();
    let c_segs: Vec<&str> = child.split('/').collect();
    subsumes_inner(&p_segs, &c_segs)
}

fn subsumes_inner(parent: &[&str], child: &[&str]) -> bool {
    if parent.is_empty() {
        return child.is_empty();
    }
    if parent[0] == "**" {
        // `**` can consume zero or more child segments
        let rest = &parent[1..];
        for i in 0..=child.len() {
            if subsumes_inner(rest, &child[i..]) {
                return true;
            }
        }
        return false;
    }
    if child.is_empty() {
        return false;
    }
    // A parent `*` covers any single child segment (literal or `*`)
    if parent[0] == "*" && child[0] != "**" {
        return subsumes_inner(&parent[1..], &child[1..]);
    }
    // Exact segment match (handles literal = literal, `**` = `**`, etc.)
    if parent[0] == child[0] {
        return subsumes_inner(&parent[1..], &child[1..]);
    }
    false
}

/// Match a concrete path against a glob pattern.
///
/// Glob syntax:
/// - `*` matches any characters except `/`
/// - `**` matches any characters including `/` (zero or more path segments)
/// - All other characters match literally
///
/// This is a dependency-free recursive matcher operating on bytes.
pub fn path_glob_match(pattern: &str, path: &str) -> bool {
    match_inner(pattern.as_bytes(), path.as_bytes())
}

fn match_inner(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'*' {
        let rest = if pattern.len() > 2 && pattern[2] == b'/' {
            &pattern[3..] // skip `**/`
        } else {
            &pattern[2..] // bare `**` at end
        };
        // `**` matches zero or more characters including `/`
        for i in 0..=text.len() {
            if match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if pattern[0] == b'*' {
        // `*` matches zero or more non-`/` characters
        let rest = &pattern[1..];
        for i in 0..=text.len() {
            if i > 0 && text[i - 1] == b'/' {
                break;
            }
            if match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pattern[0] == text[0] {
        return match_inner(&pattern[1..], &text[1..]);
    }
    false
}

/// Returns true if the string contains glob metacharacters (`*`).
fn has_glob_chars(s: &str) -> bool {
    s.contains('*')
}

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
            allowed_repos: vec!["**".to_string()],
        }
    }

    /// Returns true if `self` is a subset of `parent` on every dimension.
    ///
    /// For paths and repos, each element in `self` must be *covered* by at
    /// least one element in `parent`. Coverage is determined by glob matching:
    /// a parent pattern like `"src/**"` covers child paths `"src/lib.rs"`,
    /// `"src/*"`, and `"src/foo/bar.rs"`.
    ///
    /// Glob syntax:
    /// - `*` matches any characters except `/` (single path segment)
    /// - `**` matches any characters including `/` (zero or more segments)
    /// - Literal characters match exactly
    pub fn is_subset_of(&self, parent: &DelegationScope) -> bool {
        let paths_ok = self.allowed_paths.iter().all(|child| {
            parent
                .allowed_paths
                .iter()
                .any(|parent_pat| glob_covers(parent_pat, child))
        });
        let sinks_ok = self
            .allowed_sinks
            .iter()
            .all(|s| parent.allowed_sinks.contains(s));
        let repos_ok = self.allowed_repos.iter().all(|child| {
            parent
                .allowed_repos
                .iter()
                .any(|parent_pat| glob_covers(parent_pat, child))
        });
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

    // ── path_glob_match ────────────────────────────────────────────

    #[test]
    fn glob_exact_match() {
        assert!(path_glob_match("src/lib.rs", "src/lib.rs"));
        assert!(!path_glob_match("src/lib.rs", "src/main.rs"));
    }

    #[test]
    fn glob_star_matches_single_segment() {
        assert!(path_glob_match("src/*", "src/lib.rs"));
        assert!(path_glob_match("src/*", "src/main.rs"));
        assert!(!path_glob_match("src/*", "src/foo/bar.rs"));
    }

    #[test]
    fn glob_double_star_matches_multiple_segments() {
        assert!(path_glob_match("src/**", "src/lib.rs"));
        assert!(path_glob_match("src/**", "src/foo/bar/baz.rs"));
        assert!(!path_glob_match("src/**", "tests/foo.rs"));
    }

    #[test]
    fn glob_double_star_slash_prefix() {
        assert!(path_glob_match("**/lib.rs", "src/lib.rs"));
        assert!(path_glob_match("**/lib.rs", "a/b/c/lib.rs"));
        assert!(path_glob_match("**/lib.rs", "lib.rs"));
    }

    #[test]
    fn glob_universal_patterns() {
        assert!(path_glob_match("**", "anything/at/all"));
        assert!(path_glob_match("**/*", "foo/bar"));
        assert!(path_glob_match("**", ""));
    }

    #[test]
    fn glob_no_match() {
        assert!(!path_glob_match("src/*", "tests/foo.rs"));
        assert!(!path_glob_match("src/**", "tests/foo.rs"));
    }

    // ── is_subset_of with globs ────────────────────────────────────

    #[test]
    fn literal_child_subset_of_glob_parent() {
        let parent = DelegationScope {
            allowed_paths: vec!["src/**".to_string()],
            allowed_sinks: SinkClass::ALL.to_vec(),
            allowed_repos: vec!["**".to_string()],
        };
        let child = DelegationScope {
            allowed_paths: vec!["src/lib.rs".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite],
            allowed_repos: vec!["org/repo".to_string()],
        };
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn star_child_subset_of_doublestar_parent() {
        let parent = DelegationScope {
            allowed_paths: vec!["src/**".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite],
            allowed_repos: vec!["**".to_string()],
        };
        let child = DelegationScope {
            allowed_paths: vec!["src/*".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite],
            allowed_repos: vec!["org/repo".to_string()],
        };
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn doublestar_child_not_subset_of_star_parent() {
        let parent = DelegationScope {
            allowed_paths: vec!["src/*".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite],
            allowed_repos: vec!["*".to_string()],
        };
        let child = DelegationScope {
            allowed_paths: vec!["src/**".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite],
            allowed_repos: vec!["org/repo".to_string()],
        };
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn narrow_succeeds_with_glob_parent_literal_child() {
        let parent = DelegationConstraints {
            scope: DelegationScope {
                allowed_paths: vec!["workspace/**".to_string()],
                allowed_sinks: vec![SinkClass::WorkspaceWrite],
                allowed_repos: vec!["org/*".to_string()],
            },
            max_delegation_depth: 3,
            expires_at: 2000,
        };
        let child = DelegationConstraints {
            scope: DelegationScope {
                allowed_paths: vec!["workspace/src/lib.rs".to_string()],
                allowed_sinks: vec![SinkClass::WorkspaceWrite],
                allowed_repos: vec!["org/repo".to_string()],
            },
            max_delegation_depth: 1,
            expires_at: 1500,
        };
        assert!(parent.narrow(&child).is_some());
    }

    #[test]
    fn unrestricted_parent_covers_any_child() {
        let parent = DelegationScope::unrestricted();
        let child = DelegationScope {
            allowed_paths: vec!["some/deep/path/file.rs".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite],
            allowed_repos: vec!["any/repo".to_string()],
        };
        assert!(child.is_subset_of(&parent));
    }
}
