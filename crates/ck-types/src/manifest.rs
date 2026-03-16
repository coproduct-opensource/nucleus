//! Policy manifest — canonical schema for constitutional invariants.
//!
//! The `PolicyManifest` is the source of truth for what a governed artifact
//! is allowed to do. Every amendment must ship a before/after manifest pair,
//! and the constitutional kernel checks that ordinary amendments do not
//! widen authority along any axis.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::digest::ArtifactDigest;

/// Canonical policy manifest for a governed artifact.
///
/// All collections use `BTreeSet` for deterministic serialization order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyManifest {
    pub version: u32,
    pub capabilities: CapabilitySet,
    pub io_surface: IoSurface,
    pub budget_bounds: BudgetBounds,
    pub proof_requirements: ProofRequirements,
    pub amendment_rules: AmendmentRules,
}

impl PolicyManifest {
    /// Compute a canonical BLAKE3 digest of this manifest.
    ///
    /// Uses deterministic JSON serialization (BTreeSet guarantees ordering).
    pub fn digest(&self) -> ArtifactDigest {
        let canonical = serde_json::to_vec(self).expect("PolicyManifest is always serializable");
        ArtifactDigest::from_bytes(&canonical)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CAPABILITY SET — product lattice over discrete axes
// ═══════════════════════════════════════════════════════════════════════════

/// Discrete capability axes. Each axis has a partial order where
/// "more entries = greater capability."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// Directories the artifact may read from.
    pub filesystem_read: BTreeSet<String>,
    /// Directories the artifact may write to.
    pub filesystem_write: BTreeSet<String>,
    /// Network domains the artifact may contact.
    pub network_allow: BTreeSet<String>,
    /// Tools the artifact may invoke.
    pub tools_allow: BTreeSet<String>,
    /// Secret classes the artifact may access.
    pub secret_classes: BTreeSet<String>,
    /// Maximum concurrent tasks.
    pub max_parallel_tasks: u32,
}

impl CapabilitySet {
    /// True if `self` is a subset of `other` on every axis.
    ///
    /// This is the partial order check for capability non-escalation:
    /// `Cap(A_{i+1}) ⊆ Cap(A_i)`.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.filesystem_read.is_subset(&other.filesystem_read)
            && self.filesystem_write.is_subset(&other.filesystem_write)
            && self.network_allow.is_subset(&other.network_allow)
            && self.tools_allow.is_subset(&other.tools_allow)
            && self.secret_classes.is_subset(&other.secret_classes)
            && self.max_parallel_tasks <= other.max_parallel_tasks
    }

    /// Returns the axes where `self` exceeds `other`.
    pub fn escalations_over(&self, other: &Self) -> Vec<String> {
        let mut escalations = Vec::new();
        let check = |name: &str, child: &BTreeSet<String>, parent: &BTreeSet<String>| {
            let excess: BTreeSet<_> = child.difference(parent).collect();
            if !excess.is_empty() {
                Some(format!(
                    "{}: +[{}]",
                    name,
                    excess.into_iter().cloned().collect::<Vec<_>>().join(", ")
                ))
            } else {
                None
            }
        };
        if let Some(e) = check(
            "filesystem_read",
            &self.filesystem_read,
            &other.filesystem_read,
        ) {
            escalations.push(e);
        }
        if let Some(e) = check(
            "filesystem_write",
            &self.filesystem_write,
            &other.filesystem_write,
        ) {
            escalations.push(e);
        }
        if let Some(e) = check("network_allow", &self.network_allow, &other.network_allow) {
            escalations.push(e);
        }
        if let Some(e) = check("tools_allow", &self.tools_allow, &other.tools_allow) {
            escalations.push(e);
        }
        if let Some(e) = check(
            "secret_classes",
            &self.secret_classes,
            &other.secret_classes,
        ) {
            escalations.push(e);
        }
        if self.max_parallel_tasks > other.max_parallel_tasks {
            escalations.push(format!(
                "max_parallel_tasks: {} > {}",
                self.max_parallel_tasks, other.max_parallel_tasks
            ));
        }
        escalations
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// I/O SURFACE
// ═══════════════════════════════════════════════════════════════════════════

/// Permitted I/O surface. May not widen under ordinary self-amendment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoSurface {
    /// Outbound network domains.
    pub outbound_domains: BTreeSet<String>,
    /// Local file roots (read + write combined).
    pub local_file_roots: BTreeSet<String>,
    /// Environment variables the artifact may read.
    pub env_vars_readable: BTreeSet<String>,
    /// Tool namespaces accessible.
    pub tool_namespaces: BTreeSet<String>,
    /// Repository write targets (owner/repo).
    pub repo_write_targets: BTreeSet<String>,
}

impl IoSurface {
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.outbound_domains.is_subset(&other.outbound_domains)
            && self.local_file_roots.is_subset(&other.local_file_roots)
            && self.env_vars_readable.is_subset(&other.env_vars_readable)
            && self.tool_namespaces.is_subset(&other.tool_namespaces)
            && self.repo_write_targets.is_subset(&other.repo_write_targets)
    }

    /// Returns the axes where `self` exceeds `other`.
    pub fn escalations_over(&self, other: &Self) -> Vec<String> {
        let mut escalations = Vec::new();
        let check = |name: &str, child: &BTreeSet<String>, parent: &BTreeSet<String>| {
            let excess: BTreeSet<_> = child.difference(parent).collect();
            if !excess.is_empty() {
                Some(format!(
                    "{}: +[{}]",
                    name,
                    excess.into_iter().cloned().collect::<Vec<_>>().join(", ")
                ))
            } else {
                None
            }
        };
        if let Some(e) = check(
            "outbound_domains",
            &self.outbound_domains,
            &other.outbound_domains,
        ) {
            escalations.push(e);
        }
        if let Some(e) = check(
            "local_file_roots",
            &self.local_file_roots,
            &other.local_file_roots,
        ) {
            escalations.push(e);
        }
        if let Some(e) = check(
            "env_vars_readable",
            &self.env_vars_readable,
            &other.env_vars_readable,
        ) {
            escalations.push(e);
        }
        if let Some(e) = check(
            "tool_namespaces",
            &self.tool_namespaces,
            &other.tool_namespaces,
        ) {
            escalations.push(e);
        }
        if let Some(e) = check(
            "repo_write_targets",
            &self.repo_write_targets,
            &other.repo_write_targets,
        ) {
            escalations.push(e);
        }
        escalations
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BUDGET BOUNDS
// ═══════════════════════════════════════════════════════════════════════════

/// Resource budget bounds. A descendant's bounds may not exceed its parent's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetBounds {
    pub max_tokens: u64,
    pub max_wall_ms: u64,
    pub max_cpu_ms: u64,
    pub max_memory_bytes: u64,
    pub max_network_calls: u64,
    pub max_files_touched: u64,
    pub max_dollar_spend_millicents: u64,
    pub max_patch_attempts: u32,
}

impl BudgetBounds {
    /// True if every bound in `self` is ≤ the corresponding bound in `other`.
    pub fn is_within(&self, other: &Self) -> bool {
        self.max_tokens <= other.max_tokens
            && self.max_wall_ms <= other.max_wall_ms
            && self.max_cpu_ms <= other.max_cpu_ms
            && self.max_memory_bytes <= other.max_memory_bytes
            && self.max_network_calls <= other.max_network_calls
            && self.max_files_touched <= other.max_files_touched
            && self.max_dollar_spend_millicents <= other.max_dollar_spend_millicents
            && self.max_patch_attempts <= other.max_patch_attempts
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF REQUIREMENTS — the anti-coup rule
// ═══════════════════════════════════════════════════════════════════════════

/// Required proof obligations. May not shrink under ordinary amendment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequirements {
    /// Checks required for config/eval patches (Class A).
    pub config_patch: BTreeSet<String>,
    /// Checks required for controller patches (Class B).
    pub controller_patch: BTreeSet<String>,
    /// Checks required for evaluator/meta patches (Class C).
    pub evaluator_patch: BTreeSet<String>,
}

impl ProofRequirements {
    /// True if `self` is at least as strict as `other` on every patch class.
    ///
    /// `ProofReq(A_{i+1}) ⊇ ProofReq(A_i)` — governance monotonicity.
    pub fn is_superset_of(&self, other: &Self) -> bool {
        self.config_patch.is_superset(&other.config_patch)
            && self.controller_patch.is_superset(&other.controller_patch)
            && self.evaluator_patch.is_superset(&other.evaluator_patch)
    }

    /// Returns checks that were dropped (present in `other` but not `self`).
    pub fn dropped_requirements(&self, other: &Self) -> Vec<String> {
        let mut dropped = Vec::new();
        for req in other.config_patch.difference(&self.config_patch) {
            dropped.push(format!("config_patch: -{}", req));
        }
        for req in other.controller_patch.difference(&self.controller_patch) {
            dropped.push(format!("controller_patch: -{}", req));
        }
        for req in other.evaluator_patch.difference(&self.evaluator_patch) {
            dropped.push(format!("evaluator_patch: -{}", req));
        }
        dropped
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AMENDMENT RULES
// ═══════════════════════════════════════════════════════════════════════════

/// Rules governing what ordinary self-amendment may touch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmendmentRules {
    /// Paths the agent may modify under ordinary self-amendment.
    pub may_modify: BTreeSet<String>,
    /// Paths that are never modifiable without constitutional amendment.
    pub may_not_modify: BTreeSet<String>,
    /// Require Cap(child) ⊆ Cap(parent).
    pub require_monotone_capabilities: bool,
    /// Require IO(child) ⊆ IO(parent).
    pub require_monotone_io: bool,
    /// Require ProofReq(child) ⊇ ProofReq(parent).
    pub require_monotone_proofreq: bool,
    /// Number of human signatures required for constitutional amendments.
    pub constitutional_human_signatures: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn base_capabilities() -> CapabilitySet {
        CapabilitySet {
            filesystem_read: ["/workspace/repo".into()].into(),
            filesystem_write: ["/workspace/repo".into(), "/workspace/artifacts".into()].into(),
            network_allow: ["api.github.com".into(), "crates.io".into()].into(),
            tools_allow: ["builder".into(), "tester".into(), "kani".into()].into(),
            secret_classes: BTreeSet::new(),
            max_parallel_tasks: 4,
        }
    }

    #[test]
    fn test_capability_subset_identical() {
        let cap = base_capabilities();
        assert!(cap.is_subset_of(&cap));
    }

    #[test]
    fn test_capability_subset_fewer_is_ok() {
        let parent = base_capabilities();
        let mut child = parent.clone();
        child.network_allow.remove("crates.io");
        child.max_parallel_tasks = 2;
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn test_capability_escalation_detected() {
        let parent = base_capabilities();
        let mut child = parent.clone();
        child.network_allow.insert("evil.com".into());
        assert!(!child.is_subset_of(&parent));

        let escalations = child.escalations_over(&parent);
        assert_eq!(escalations.len(), 1);
        assert!(escalations[0].contains("evil.com"));
    }

    #[test]
    fn test_capability_parallel_tasks_escalation() {
        let parent = base_capabilities();
        let mut child = parent.clone();
        child.max_parallel_tasks = 8;
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn test_budget_within() {
        let parent = BudgetBounds {
            max_tokens: 200_000,
            max_wall_ms: 1_800_000,
            max_cpu_ms: 1_200_000,
            max_memory_bytes: 4_000_000_000,
            max_network_calls: 200,
            max_files_touched: 50,
            max_dollar_spend_millicents: 500_000,
            max_patch_attempts: 3,
        };
        let child = BudgetBounds {
            max_tokens: 100_000,
            max_wall_ms: 900_000,
            ..parent.clone()
        };
        assert!(child.is_within(&parent));
    }

    #[test]
    fn test_budget_escalation() {
        let parent = BudgetBounds {
            max_tokens: 200_000,
            max_wall_ms: 1_800_000,
            max_cpu_ms: 1_200_000,
            max_memory_bytes: 4_000_000_000,
            max_network_calls: 200,
            max_files_touched: 50,
            max_dollar_spend_millicents: 500_000,
            max_patch_attempts: 3,
        };
        let child = BudgetBounds {
            max_tokens: 999_999,
            ..parent.clone()
        };
        assert!(!child.is_within(&parent));
    }

    #[test]
    fn test_proof_requirements_superset() {
        let parent = ProofRequirements {
            config_patch: ["build_pass".into(), "tests_pass".into()].into(),
            controller_patch: ["build_pass".into(), "kani_pass".into()].into(),
            evaluator_patch: ["build_pass".into()].into(),
        };
        let mut child = parent.clone();
        child.controller_patch.insert("replay_pass".into());
        assert!(child.is_superset_of(&parent)); // stricter = ok
    }

    #[test]
    fn test_proof_requirements_weakening_detected() {
        let parent = ProofRequirements {
            config_patch: ["build_pass".into(), "tests_pass".into()].into(),
            controller_patch: ["build_pass".into(), "kani_pass".into()].into(),
            evaluator_patch: ["build_pass".into()].into(),
        };
        let mut child = parent.clone();
        child.controller_patch.remove("kani_pass");
        assert!(!child.is_superset_of(&parent));

        let dropped = child.dropped_requirements(&parent);
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].contains("kani_pass"));
    }

    #[test]
    fn test_manifest_digest_deterministic() {
        let m = PolicyManifest {
            version: 1,
            capabilities: base_capabilities(),
            io_surface: IoSurface {
                outbound_domains: ["api.github.com".into()].into(),
                local_file_roots: ["/workspace".into()].into(),
                env_vars_readable: BTreeSet::new(),
                tool_namespaces: BTreeSet::new(),
                repo_write_targets: BTreeSet::new(),
            },
            budget_bounds: BudgetBounds {
                max_tokens: 200_000,
                max_wall_ms: 1_800_000,
                max_cpu_ms: 1_200_000,
                max_memory_bytes: 4_000_000_000,
                max_network_calls: 200,
                max_files_touched: 50,
                max_dollar_spend_millicents: 500_000,
                max_patch_attempts: 3,
            },
            proof_requirements: ProofRequirements {
                config_patch: ["build_pass".into()].into(),
                controller_patch: ["build_pass".into(), "kani_pass".into()].into(),
                evaluator_patch: ["build_pass".into()].into(),
            },
            amendment_rules: AmendmentRules {
                may_modify: ["controller_code".into()].into(),
                may_not_modify: ["kernel_checker".into()].into(),
                require_monotone_capabilities: true,
                require_monotone_io: true,
                require_monotone_proofreq: true,
                constitutional_human_signatures: 2,
            },
        };
        let d1 = m.digest();
        let d2 = m.digest();
        assert_eq!(d1, d2);
    }
}
