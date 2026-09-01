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

    /// Deserialize from a TOML string (e.g., `PolicyManifest.toml`).
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Serialize to a canonical TOML string.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("PolicyManifest is always serializable")
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

impl AmendmentRules {
    /// Returns the governance monotonicity flags that `self` (the CHILD) weakens
    /// relative to `parent`.
    ///
    /// A flag is WEAKENED iff it was `true` on the parent and `false` on the
    /// child (`parent = true && child = false`). Enabling a flag the parent did
    /// not require is fine; only DISABLING a required flag is a weakening.
    ///
    /// This is the anti-self-weakening / anti-coup check: it is consulted
    /// UNCONDITIONALLY by the kernel (never gated on any flag), because the
    /// whole point is to stop an amendment from disarming the very flags that
    /// would police the next amendment.
    ///
    /// SCOPE: the three boolean governance monotonicity flags —
    /// `require_monotone_{capabilities,io,proofreq}` — AND the numeric
    /// `constitutional_human_signatures` threshold, which may be raised but never
    /// lowered.
    ///
    /// The numeric axis was previously excluded and documented as a follow-up. It
    /// is a coup vector in its own right: an amendment that lowers the threshold
    /// from 2 to 0 disarms the human review that would police the NEXT
    /// constitutional amendment, which is exactly what this function exists to
    /// prevent. Boolean flags and a numeric threshold differ only in how disarming
    /// is spelled.
    ///
    /// Kept parity-exact with the Lean model (`Ck.Policy.rulesNonWeakening`, whose
    /// `sigs` field carries the same `parent ≤ child` obligation) and with the
    /// `policy_lean_parity` proptest.
    pub fn weakened_flags_over(&self, parent: &Self) -> Vec<String> {
        let mut weakened = Vec::new();
        let mut check = |name: &str, parent_flag: bool, child_flag: bool| {
            if parent_flag && !child_flag {
                weakened.push(format!("{}: true -> false", name));
            }
        };
        check(
            "require_monotone_capabilities",
            parent.require_monotone_capabilities,
            self.require_monotone_capabilities,
        );
        check(
            "require_monotone_io",
            parent.require_monotone_io,
            self.require_monotone_io,
        );
        check(
            "require_monotone_proofreq",
            parent.require_monotone_proofreq,
            self.require_monotone_proofreq,
        );

        // Numeric monotonicity: the threshold may RISE but never fall.
        if self.constitutional_human_signatures < parent.constitutional_human_signatures {
            weakened.push(format!(
                "constitutional_human_signatures: {} -> {}",
                parent.constitutional_human_signatures, self.constitutional_human_signatures
            ));
        }
        weakened
    }
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

    #[test]
    fn test_toml_roundtrip() {
        let original = PolicyManifest {
            version: 1,
            capabilities: base_capabilities(),
            io_surface: IoSurface {
                outbound_domains: ["api.github.com".into()].into(),
                local_file_roots: ["/workspace".into()].into(),
                env_vars_readable: ["HOME".into()].into(),
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
                config_patch: ["build_pass".into(), "tests_pass".into()].into(),
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

        let toml_str = original.to_toml();
        let parsed = PolicyManifest::from_toml(&toml_str).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_from_toml_rejects_invalid() {
        let result = PolicyManifest::from_toml("not valid toml {{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_toml_rejects_missing_fields() {
        let result = PolicyManifest::from_toml("[capabilities]\nmax_parallel_tasks = 4\n");
        assert!(result.is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBSET ⟺ NO-ESCALATION
// ═══════════════════════════════════════════════════════════════════════════

/// Two spellings of "the child does not escalate" live in this file:
///
///   * [`CapabilitySet::is_subset_of`] — a conjunction of `is_subset` per axis.
///     This is the PARTIAL ORDER, and it is what the Lean model and the Kani
///     harnesses reason about.
///   * [`CapabilitySet::escalations_over`] — a `difference()`-per-axis that
///     returns the offending axis NAMES. This is what `check_monotonicity`
///     actually calls, so it is what the running gate computes.
///
/// The gate's soundness argument silently assumes these agree. Nothing proved
/// it. They do agree today — but only because each function happens to list the
/// same axes, and that was an invariant no compiler or test enforced.
///
/// It is the same defect shape as the `constitutional_human_signatures`
/// threshold: an axis present in one enumeration and absent from another. A
/// drift bug waiting for the next field, not a bug in today's arithmetic. So
/// these tests check BOTH — agreement now, and a compile-time tripwire that
/// makes the next added axis impossible to wire into only one side.
#[cfg(test)]
mod subset_agrees_with_no_escalation {
    use super::*;

    /// Exhaustive destructuring with NO `..` rest pattern.
    ///
    /// This is the tripwire. Adding an axis to `CapabilitySet` stops this file
    /// COMPILING, here, in the module that owns the agreement property — which
    /// forces whoever adds it to decide how it appears in both functions rather
    /// than discovering later that the gate never looked at it.
    fn cap_axes(c: &CapabilitySet) -> (Vec<&BTreeSet<String>>, u32) {
        let CapabilitySet {
            filesystem_read,
            filesystem_write,
            network_allow,
            tools_allow,
            secret_classes,
            max_parallel_tasks,
        } = c;
        (
            vec![
                filesystem_read,
                filesystem_write,
                network_allow,
                tools_allow,
                secret_classes,
            ],
            *max_parallel_tasks,
        )
    }

    /// The same tripwire for the I/O surface.
    fn io_axes(s: &IoSurface) -> Vec<&BTreeSet<String>> {
        let IoSurface {
            outbound_domains,
            local_file_roots,
            env_vars_readable,
            tool_namespaces,
            repo_write_targets,
        } = s;
        vec![
            outbound_domains,
            local_file_roots,
            env_vars_readable,
            tool_namespaces,
            repo_write_targets,
        ]
    }

    /// The five capability axis names, in the order `escalations_over` reports
    /// them. Kept beside `cap_axes` so the destructuring guard covers both.
    const CAP_AXIS_NAMES: [&str; 5] = [
        "filesystem_read",
        "filesystem_write",
        "network_allow",
        "tools_allow",
        "secret_classes",
    ];

    const IO_AXIS_NAMES: [&str; 5] = [
        "outbound_domains",
        "local_file_roots",
        "env_vars_readable",
        "tool_namespaces",
        "repo_write_targets",
    ];

    /// `mask` selects a subset of the two-element universe {"a", "b"}.
    fn subset(mask: u8) -> BTreeSet<String> {
        let mut s = BTreeSet::new();
        if mask & 1 != 0 {
            s.insert("a".to_string());
        }
        if mask & 2 != 0 {
            s.insert("b".to_string());
        }
        s
    }

    fn cap(masks: [u8; 5], tasks: u32) -> CapabilitySet {
        CapabilitySet {
            filesystem_read: subset(masks[0]),
            filesystem_write: subset(masks[1]),
            network_allow: subset(masks[2]),
            tools_allow: subset(masks[3]),
            secret_classes: subset(masks[4]),
            max_parallel_tasks: tasks,
        }
    }

    fn io(masks: [u8; 5]) -> IoSurface {
        IoSurface {
            outbound_domains: subset(masks[0]),
            local_file_roots: subset(masks[1]),
            env_vars_readable: subset(masks[2]),
            tool_namespaces: subset(masks[3]),
            repo_write_targets: subset(masks[4]),
        }
    }

    fn bits(m: u8) -> [u8; 5] {
        [
            m & 1,
            (m >> 1) & 1,
            (m >> 2) & 1,
            (m >> 3) & 1,
            (m >> 4) & 1,
        ]
    }

    /// Per axis, EXHAUSTIVELY over the 4x4 subset pairs of a two-element
    /// universe: the two spellings agree. Every other axis is held equal, so a
    /// disagreement is attributable to the axis under test.
    #[test]
    fn capability_axes_agree_one_at_a_time() {
        for axis in 0..5usize {
            for cm in 0..4u8 {
                for pm in 0..4u8 {
                    let mut cmasks = [3u8; 5];
                    let mut pmasks = [3u8; 5];
                    cmasks[axis] = cm;
                    pmasks[axis] = pm;
                    let child = cap(cmasks, 1);
                    let parent = cap(pmasks, 1);

                    let subset_says = child.is_subset_of(&parent);
                    let escalations = child.escalations_over(&parent);
                    assert_eq!(
                        subset_says,
                        escalations.is_empty(),
                        "axis {} ({}): is_subset_of={} but escalations_over={:?}",
                        axis,
                        CAP_AXIS_NAMES[axis],
                        subset_says,
                        escalations
                    );

                    // Cross-axis discrimination: when THIS axis escalates, the
                    // report must name THIS axis and no other.
                    if !subset_says {
                        assert_eq!(escalations.len(), 1, "expected exactly one axis");
                        assert!(
                            escalations[0].starts_with(CAP_AXIS_NAMES[axis]),
                            "axis {} escalated but report says {:?}",
                            CAP_AXIS_NAMES[axis],
                            escalations
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn io_axes_agree_one_at_a_time() {
        for axis in 0..5usize {
            for cm in 0..4u8 {
                for pm in 0..4u8 {
                    let mut cmasks = [3u8; 5];
                    let mut pmasks = [3u8; 5];
                    cmasks[axis] = cm;
                    pmasks[axis] = pm;
                    let child = io(cmasks);
                    let parent = io(pmasks);

                    let subset_says = child.is_subset_of(&parent);
                    let escalations = child.escalations_over(&parent);
                    assert_eq!(
                        subset_says,
                        escalations.is_empty(),
                        "io axis {} ({}): is_subset_of={} but escalations_over={:?}",
                        axis,
                        IO_AXIS_NAMES[axis],
                        subset_says,
                        escalations
                    );
                    if !subset_says {
                        assert_eq!(escalations.len(), 1);
                        assert!(escalations[0].starts_with(IO_AXIS_NAMES[axis]));
                    }
                }
            }
        }
    }

    /// All 2^5 x 2^5 = 1024 patterns of WHICH axes escalate, over a one-element
    /// universe. One element is enough to separate "subset on this axis" from
    /// "not subset", which is all either function can observe — so this is
    /// exhaustive over the space the conjunction actually sees.
    #[test]
    fn every_pattern_of_escalating_axes_agrees() {
        for c in 0..32u8 {
            for p in 0..32u8 {
                let (cmasks, pmasks) = (bits(c), bits(p));
                let child = cap(cmasks, 1);
                let parent = cap(pmasks, 1);
                assert_eq!(
                    child.is_subset_of(&parent),
                    child.escalations_over(&parent).is_empty(),
                    "c={c:05b} p={p:05b}"
                );

                let ci = io(cmasks);
                let pi = io(pmasks);
                assert_eq!(
                    ci.is_subset_of(&pi),
                    ci.escalations_over(&pi).is_empty(),
                    "io c={c:05b} p={p:05b}"
                );

                // The number of reported axes is exactly the number that widened.
                let widened = (0..5).filter(|i| cmasks[*i] > pmasks[*i]).count();
                assert_eq!(child.escalations_over(&parent).len(), widened);
                assert_eq!(ci.escalations_over(&pi).len(), widened);
            }
        }
    }

    /// The numeric axis, exhaustively. `is_subset_of` uses `<=` and
    /// `escalations_over` uses `>`; those are complements only if both read the
    /// same field, which the destructuring guard above is what pins down.
    #[test]
    fn max_parallel_tasks_agrees() {
        for c in 0..8u32 {
            for p in 0..8u32 {
                let child = cap([0; 5], c);
                let parent = cap([0; 5], p);
                assert_eq!(
                    child.is_subset_of(&parent),
                    child.escalations_over(&parent).is_empty(),
                    "tasks {c} vs {p}"
                );
                if c > p {
                    let e = child.escalations_over(&parent);
                    assert_eq!(e.len(), 1);
                    assert!(e[0].starts_with("max_parallel_tasks"));
                }
            }
        }
    }

    /// Non-vacuity, the lesson of the axiom audit that never ran: a test whose
    /// verdict is carried by the absence of a failure must show it had
    /// something to fail on. Assert both outcomes actually occur.
    #[test]
    fn the_agreement_tests_see_both_verdicts() {
        let mut subsets = 0;
        let mut escalations = 0;
        for c in 0..32u8 {
            for p in 0..32u8 {
                if cap(bits(c), 1).is_subset_of(&cap(bits(p), 1)) {
                    subsets += 1;
                } else {
                    escalations += 1;
                }
            }
        }
        assert!(subsets > 0 && escalations > 0, "{subsets} / {escalations}");
        assert_eq!(subsets + escalations, 1024);
    }

    /// The destructuring guards are load-bearing, so keep them reachable: if
    /// either helper stops compiling, this test goes with it.
    #[test]
    fn axis_helpers_cover_every_field() {
        let probe_cap = cap([1, 1, 1, 1, 1], 7);
        let (sets, tasks) = cap_axes(&probe_cap);
        assert_eq!(sets.len(), CAP_AXIS_NAMES.len());
        assert_eq!(tasks, 7);
        let probe_io = io([1, 1, 1, 1, 1]);
        assert_eq!(io_axes(&probe_io).len(), IO_AXIS_NAMES.len());
    }
}
