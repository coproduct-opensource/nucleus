//! Pre-flight policy validation.
//!
//! Validates a policy manifest (or a parent→candidate transition) **before**
//! the caller builds a [`WitnessBundle`]. This lets orchestrators catch
//! structural or monotonicity violations early, without running builds, tests,
//! or Kani proofs first.
//!
//! # Usage
//!
//! ```
//! use ck_policy::preflight::{validate_structure, validate_candidate};
//! # use ck_types::manifest::*;
//! # use std::collections::BTreeSet;
//! # fn make_manifest() -> PolicyManifest {
//! #     PolicyManifest {
//! #         version: 1,
//! #         capabilities: CapabilitySet { filesystem_read: BTreeSet::new(), filesystem_write: BTreeSet::new(), network_allow: BTreeSet::new(), tools_allow: BTreeSet::new(), secret_classes: BTreeSet::new(), max_parallel_tasks: 1 },
//! #         io_surface: IoSurface { outbound_domains: BTreeSet::new(), local_file_roots: BTreeSet::new(), env_vars_readable: BTreeSet::new(), tool_namespaces: BTreeSet::new(), repo_write_targets: BTreeSet::new() },
//! #         budget_bounds: BudgetBounds { max_tokens: 1000, max_wall_ms: 1000, max_cpu_ms: 1000, max_memory_bytes: 1000, max_network_calls: 10, max_files_touched: 10, max_dollar_spend_millicents: 1000, max_patch_attempts: 1 },
//! #         proof_requirements: ProofRequirements { config_patch: BTreeSet::new(), controller_patch: BTreeSet::new(), evaluator_patch: BTreeSet::new() },
//! #         amendment_rules: AmendmentRules { may_modify: BTreeSet::new(), may_not_modify: BTreeSet::new(), require_monotone_capabilities: true, require_monotone_io: true, require_monotone_proofreq: true, constitutional_human_signatures: 1 },
//! #     }
//! # }
//!
//! let parent = make_manifest();
//! let candidate = make_manifest();
//!
//! // Check candidate is internally consistent.
//! let s = validate_structure(&candidate);
//! assert!(s.valid);
//!
//! // Check candidate does not escalate over parent.
//! let r = validate_candidate(&parent, &candidate);
//! assert!(r.valid);
//! ```

use ck_types::manifest::PolicyManifest;
use ck_types::ConstitutionalInvariant;

use crate::check_monotonicity;

// ═══════════════════════════════════════════════════════════════════════════
// Public types
// ═══════════════════════════════════════════════════════════════════════════

/// A single violation detected during pre-flight validation.
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub invariant: ConstitutionalInvariant,
    pub message: String,
}

/// Result of pre-flight policy validation.
#[derive(Debug, Clone)]
pub struct PreflightResult {
    pub valid: bool,
    pub violations: Vec<PolicyViolation>,
}

impl PreflightResult {
    pub fn ok() -> Self {
        PreflightResult {
            valid: true,
            violations: vec![],
        }
    }

    pub fn invalid(violations: Vec<PolicyViolation>) -> Self {
        PreflightResult {
            valid: false,
            violations,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public functions
// ═══════════════════════════════════════════════════════════════════════════

/// Validate that a single policy manifest is structurally well-formed.
///
/// Checks internal consistency of the manifest:
/// - `may_modify ∩ may_not_modify = ∅` (a path can't be both modifiable and locked)
/// - All budget bound fields are non-zero (a zero limit would halt all work)
///
/// This check does **not** require a parent manifest.
pub fn validate_structure(policy: &PolicyManifest) -> PreflightResult {
    let mut violations = Vec::new();

    // may_modify ∩ may_not_modify must be empty
    let overlap: Vec<_> = policy
        .amendment_rules
        .may_modify
        .intersection(&policy.amendment_rules.may_not_modify)
        .cloned()
        .collect();
    if !overlap.is_empty() {
        violations.push(PolicyViolation {
            invariant: ConstitutionalInvariant::BoundedTermination,
            message: format!(
                "may_modify ∩ may_not_modify is non-empty: [{}]",
                overlap.join(", ")
            ),
        });
    }

    // Budget bounds must all be non-zero
    let budget = &policy.budget_bounds;
    let zero_fields: Vec<&str> = [
        ("max_tokens", budget.max_tokens == 0),
        ("max_wall_ms", budget.max_wall_ms == 0),
        ("max_cpu_ms", budget.max_cpu_ms == 0),
        ("max_memory_bytes", budget.max_memory_bytes == 0),
        ("max_network_calls", budget.max_network_calls == 0),
        ("max_files_touched", budget.max_files_touched == 0),
        (
            "max_dollar_spend_millicents",
            budget.max_dollar_spend_millicents == 0,
        ),
        ("max_patch_attempts", budget.max_patch_attempts == 0),
    ]
    .iter()
    .filter_map(|(name, is_zero)| if *is_zero { Some(*name) } else { None })
    .collect();

    if !zero_fields.is_empty() {
        violations.push(PolicyViolation {
            invariant: ConstitutionalInvariant::ResourceBoundedness,
            message: format!(
                "budget bounds must be non-zero: [{}]",
                zero_fields.join(", ")
            ),
        });
    }

    if violations.is_empty() {
        PreflightResult::ok()
    } else {
        PreflightResult::invalid(violations)
    }
}

/// Validate that a candidate policy does not escalate capabilities over a parent.
///
/// Call this **before** building a [`WitnessBundle`] to catch violations early.
/// Internally reuses [`check_monotonicity`] — results are semantically identical
/// to what the kernel would see, just returned without needing digests or reports.
pub fn validate_candidate(parent: &PolicyManifest, candidate: &PolicyManifest) -> PreflightResult {
    let verdict = check_monotonicity(parent, candidate);
    if verdict.passed {
        return PreflightResult::ok();
    }

    let violations = verdict
        .diff
        .violated_invariants
        .iter()
        .map(|inv| {
            let message = match inv {
                ConstitutionalInvariant::CapabilityNonEscalation => format!(
                    "capability escalations: [{}]",
                    verdict.diff.capability_escalations.join(", ")
                ),
                ConstitutionalInvariant::IoConfinement => format!(
                    "I/O surface widened: [{}]",
                    verdict.diff.io_escalations.join(", ")
                ),
                ConstitutionalInvariant::ResourceBoundedness => format!(
                    "budget exceeded: [{}]",
                    verdict.diff.budget_escalations.join(", ")
                ),
                ConstitutionalInvariant::GovernanceMonotonicity => format!(
                    "proof requirements weakened: [{}]",
                    verdict.diff.proof_requirement_drops.join(", ")
                ),
                ConstitutionalInvariant::BoundedTermination => {
                    "bounded termination violated".into()
                }
            };
            PolicyViolation {
                invariant: *inv,
                message,
            }
        })
        .collect();

    PreflightResult::invalid(violations)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ck_types::manifest::*;
    use ck_types::ConstitutionalInvariant;

    use super::*;

    fn base_manifest() -> PolicyManifest {
        PolicyManifest {
            version: 1,
            capabilities: CapabilitySet {
                filesystem_read: ["/workspace".into()].into(),
                filesystem_write: ["/workspace".into()].into(),
                network_allow: ["api.github.com".into()].into(),
                tools_allow: ["builder".into(), "tester".into()].into(),
                secret_classes: BTreeSet::new(),
                max_parallel_tasks: 4,
            },
            io_surface: IoSurface {
                outbound_domains: ["api.github.com".into()].into(),
                local_file_roots: ["/workspace".into()].into(),
                env_vars_readable: ["HOME".into()].into(),
                tool_namespaces: BTreeSet::new(),
                repo_write_targets: ["org/repo".into()].into(),
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
                controller_patch: [
                    "build_pass".into(),
                    "tests_pass".into(),
                    "kani_pass".into(),
                ]
                .into(),
                evaluator_patch: ["build_pass".into(), "tests_pass".into()].into(),
            },
            amendment_rules: AmendmentRules {
                may_modify: ["controller_code".into()].into(),
                may_not_modify: ["kernel_checker".into()].into(),
                require_monotone_capabilities: true,
                require_monotone_io: true,
                require_monotone_proofreq: true,
                constitutional_human_signatures: 2,
            },
        }
    }

    // ── validate_candidate tests ──────────────────────────────────────────

    #[test]
    fn test_valid_unchanged_policy() {
        let m = base_manifest();
        let r = validate_candidate(&m, &m);
        assert!(r.valid, "Identical manifests must pass: {:?}", r.violations);
        assert!(r.violations.is_empty());
    }

    #[test]
    fn test_valid_tighter_policy() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.capabilities.network_allow.clear();
        candidate.budget_bounds.max_tokens = 100_000;
        candidate
            .proof_requirements
            .controller_patch
            .insert("replay_pass".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(r.valid, "Tighter candidate must pass: {:?}", r.violations);
    }

    #[test]
    fn test_network_escalation() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate
            .capabilities
            .network_allow
            .insert("evil.com".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::CapabilityNonEscalation));
        assert!(r
            .violations
            .iter()
            .any(|v| v.message.contains("evil.com")));
    }

    #[test]
    fn test_io_widening() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate
            .io_surface
            .outbound_domains
            .insert("exfiltrate.io".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::IoConfinement));
        assert!(r
            .violations
            .iter()
            .any(|v| v.message.contains("exfiltrate.io")));
    }

    #[test]
    fn test_budget_escalation() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.budget_bounds.max_dollar_spend_millicents = 999_999;
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::ResourceBoundedness));
    }

    #[test]
    fn test_proof_req_weakened() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate
            .proof_requirements
            .controller_patch
            .remove("kani_pass");
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::GovernanceMonotonicity));
        assert!(r
            .violations
            .iter()
            .any(|v| v.message.contains("kani_pass")));
    }

    #[test]
    fn test_multiple_violations() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate
            .capabilities
            .tools_allow
            .insert("rootkit".into());
        candidate.budget_bounds.max_tokens = 999_999;
        candidate
            .proof_requirements
            .config_patch
            .remove("tests_pass");
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert_eq!(r.violations.len(), 3, "Expected 3 violations, got: {:?}", r.violations);
    }

    // ── validate_structure tests ──────────────────────────────────────────

    #[test]
    fn test_validate_structure_well_formed() {
        let m = base_manifest();
        let r = validate_structure(&m);
        assert!(r.valid, "Base manifest must be well-formed: {:?}", r.violations);
    }

    #[test]
    fn test_validate_structure_may_overlap_guard() {
        let mut m = base_manifest();
        // Add the same path to both sets — overlap detected.
        m.amendment_rules.may_modify.insert("kernel_checker".into());
        let r = validate_structure(&m);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::BoundedTermination));
        assert!(r
            .violations
            .iter()
            .any(|v| v.message.contains("kernel_checker")));
    }

    #[test]
    fn test_validate_structure_zero_budget() {
        let mut m = base_manifest();
        m.budget_bounds.max_tokens = 0;
        let r = validate_structure(&m);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::ResourceBoundedness));
        assert!(r
            .violations
            .iter()
            .any(|v| v.message.contains("max_tokens")));
    }

    #[test]
    fn test_validate_structure_multiple_zero_budget_fields_single_violation() {
        let mut m = base_manifest();
        m.budget_bounds.max_tokens = 0;
        m.budget_bounds.max_wall_ms = 0;
        m.budget_bounds.max_memory_bytes = 0;
        let r = validate_structure(&m);
        assert!(!r.valid);
        // All zero fields reported in a single violation, not multiple.
        let resource_violations: Vec<_> = r
            .violations
            .iter()
            .filter(|v| v.invariant == ConstitutionalInvariant::ResourceBoundedness)
            .collect();
        assert_eq!(resource_violations.len(), 1, "Expected single ResourceBoundedness violation");
        let msg = &resource_violations[0].message;
        assert!(msg.contains("max_tokens"), "Missing max_tokens in: {}", msg);
        assert!(msg.contains("max_wall_ms"), "Missing max_wall_ms in: {}", msg);
        assert!(msg.contains("max_memory_bytes"), "Missing max_memory_bytes in: {}", msg);
    }

    #[test]
    fn test_validate_structure_both_violations() {
        let mut m = base_manifest();
        // Introduce overlap between may_modify and may_not_modify.
        m.amendment_rules.may_modify.insert("kernel_checker".into());
        // And zero out a budget field.
        m.budget_bounds.max_patch_attempts = 0;
        let r = validate_structure(&m);
        assert!(!r.valid);
        assert_eq!(r.violations.len(), 2, "Expected 2 violations, got: {:?}", r.violations);
        let invariants: Vec<_> = r.violations.iter().map(|v| v.invariant).collect();
        assert!(invariants.contains(&ConstitutionalInvariant::BoundedTermination));
        assert!(invariants.contains(&ConstitutionalInvariant::ResourceBoundedness));
    }

    // ── validate_candidate with monotonicity flags disabled ───────────────

    #[test]
    fn test_candidate_monotonicity_cap_disabled_allows_escalation() {
        let mut parent = base_manifest();
        parent.amendment_rules.require_monotone_capabilities = false;
        let mut candidate = parent.clone();
        candidate.capabilities.network_allow.insert("anywhere.com".into());
        candidate.capabilities.tools_allow.insert("rootkit".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(r.valid, "Cap escalation allowed when require_monotone_capabilities=false: {:?}", r.violations);
    }

    #[test]
    fn test_candidate_monotonicity_io_disabled_allows_widening() {
        let mut parent = base_manifest();
        parent.amendment_rules.require_monotone_io = false;
        let mut candidate = parent.clone();
        candidate.io_surface.outbound_domains.insert("exfil.io".into());
        candidate.io_surface.env_vars_readable.insert("SECRET_KEY".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(r.valid, "IO widening allowed when require_monotone_io=false: {:?}", r.violations);
    }

    #[test]
    fn test_candidate_monotonicity_proofreq_disabled_allows_weakening() {
        let mut parent = base_manifest();
        parent.amendment_rules.require_monotone_proofreq = false;
        let mut candidate = parent.clone();
        candidate.proof_requirements.controller_patch.clear();
        let r = validate_candidate(&parent, &candidate);
        assert!(r.valid, "Proof weakening allowed when require_monotone_proofreq=false: {:?}", r.violations);
    }

    #[test]
    fn test_candidate_budget_always_checked_even_when_monotonicity_disabled() {
        // All monotonicity flags off, but budget still enforced.
        let mut parent = base_manifest();
        parent.amendment_rules.require_monotone_capabilities = false;
        parent.amendment_rules.require_monotone_io = false;
        parent.amendment_rules.require_monotone_proofreq = false;

        let mut candidate = parent.clone();
        // Cap/IO/proofreq escalations are fine because flags are disabled.
        candidate.capabilities.network_allow.insert("anywhere.com".into());
        // But budget escalation must still fail.
        candidate.budget_bounds.max_tokens = 999_999_999;

        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid, "Budget escalation must fail regardless of monotonicity flags");
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::ResourceBoundedness));
    }

    // ── validate_candidate: specific capability axes ──────────────────────

    #[test]
    fn test_filesystem_read_escalation() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.capabilities.filesystem_read.insert("/etc/secrets".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::CapabilityNonEscalation));
        assert!(r
            .violations
            .iter()
            .any(|v| v.message.contains("/etc/secrets")));
    }

    #[test]
    fn test_max_parallel_tasks_escalation() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.capabilities.max_parallel_tasks = parent.capabilities.max_parallel_tasks + 1;
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::CapabilityNonEscalation));
    }

    #[test]
    fn test_secret_classes_escalation() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.capabilities.secret_classes.insert("prod-db-creds".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::CapabilityNonEscalation));
    }

    // ── validate_candidate: specific IO surface axes ─────────────────────

    #[test]
    fn test_local_file_roots_widening() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.io_surface.local_file_roots.insert("/host".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::IoConfinement));
        assert!(r
            .violations
            .iter()
            .any(|v| v.message.contains("/host")));
    }

    #[test]
    fn test_env_vars_readable_widening() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.io_surface.env_vars_readable.insert("AWS_SECRET_KEY".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::IoConfinement));
    }

    #[test]
    fn test_repo_write_targets_widening() {
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.io_surface.repo_write_targets.insert("attacker/stolen-repo".into());
        let r = validate_candidate(&parent, &candidate);
        assert!(!r.valid);
        assert!(r
            .violations
            .iter()
            .any(|v| v.invariant == ConstitutionalInvariant::IoConfinement));
    }

    // ── PreflightResult API ───────────────────────────────────────────────

    #[test]
    fn test_preflight_result_ok_invariants() {
        let r = PreflightResult::ok();
        assert!(r.valid);
        assert!(r.violations.is_empty());
    }

    #[test]
    fn test_preflight_result_invalid_sets_valid_false() {
        let v = PolicyViolation {
            invariant: ConstitutionalInvariant::CapabilityNonEscalation,
            message: "test".into(),
        };
        let r = PreflightResult::invalid(vec![v]);
        assert!(!r.valid);
        assert_eq!(r.violations.len(), 1);
    }

    // ── validate_structure vs validate_candidate independence ─────────────

    #[test]
    fn test_structure_check_ignores_monotonicity() {
        // A manifest with zero budget is structurally invalid even if it is
        // a valid child of its parent (tighter budget = fine monotonically).
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.budget_bounds.max_tokens = 0; // zero is invalid structurally

        // validate_structure catches it.
        let s = validate_structure(&candidate);
        assert!(!s.valid);

        // validate_candidate does NOT catch zero budget (monotonically it is tighter).
        let r = validate_candidate(&parent, &candidate);
        assert!(r.valid, "Zero budget is tighter (0 ≤ parent), so validate_candidate should pass");
    }

    #[test]
    fn test_candidate_check_ignores_structure_violations() {
        // Overlapping may_modify / may_not_modify is a structural issue,
        // but validate_candidate doesn't check structure — only monotonicity.
        let parent = base_manifest();
        let mut candidate = parent.clone();
        candidate.amendment_rules.may_modify.insert("kernel_checker".into()); // overlap

        let s = validate_structure(&candidate);
        assert!(!s.valid, "Overlap must be caught by validate_structure");

        let r = validate_candidate(&parent, &candidate);
        // Same overlap in both parent and candidate — monotonicity check is neutral.
        // The result depends on whether parent also has the overlap, but either way
        // validate_candidate should not introduce a GovernanceMonotonicity violation
        // solely because of the may_modify overlap (that is a structure concern).
        // Here parent doesn't have the overlap, but candidate's may_modify just grew —
        // that doesn't affect any monotonicity axis (may_modify is not checked there).
        assert!(r.valid, "Structural overlap should not trigger monotonicity failure");
    }
}
