//! Constitutional Kernel — monotonicity checker.
//!
//! Pure function that decides whether an ordinary amendment preserves
//! constitutional order. This is the core of the admission logic.
//!
//! The checker enforces four monotonicity invariants:
//! 1. Capability non-escalation: `Cap(child) ⊆ Cap(parent)`
//! 2. I/O confinement: `IO(child) ⊆ IO(parent)`
//! 3. Resource boundedness: `Budget(child) ≤ Budget(parent)`
//! 4. Governance monotonicity: `ProofReq(child) ⊇ ProofReq(parent)`

use ck_types::manifest::PolicyManifest;
use ck_types::witness::PolicyDiffReport;
use ck_types::ConstitutionalInvariant;

/// Result of checking an ordinary amendment for constitutional compliance.
#[derive(Debug, Clone)]
pub struct MonotonicityVerdict {
    pub passed: bool,
    pub diff: PolicyDiffReport,
}

/// Check whether an ordinary amendment from `parent` to `child` preserves
/// all constitutional monotonicity invariants.
///
/// This is a pure function — no I/O, no side effects. It compares two
/// policy manifests and reports any violations.
pub fn check_monotonicity(parent: &PolicyManifest, child: &PolicyManifest) -> MonotonicityVerdict {
    let mut violated = Vec::new();

    // 1. Capability non-escalation
    let cap_escalations = if parent.amendment_rules.require_monotone_capabilities {
        let e = child.capabilities.escalations_over(&parent.capabilities);
        if !e.is_empty() {
            violated.push(ConstitutionalInvariant::CapabilityNonEscalation);
        }
        e
    } else {
        vec![]
    };

    // 2. I/O confinement
    let io_escalations = if parent.amendment_rules.require_monotone_io {
        let e = child.io_surface.escalations_over(&parent.io_surface);
        if !e.is_empty() {
            violated.push(ConstitutionalInvariant::IoConfinement);
        }
        e
    } else {
        vec![]
    };

    // 3. Resource boundedness
    let budget_escalations = if !child.budget_bounds.is_within(&parent.budget_bounds) {
        violated.push(ConstitutionalInvariant::ResourceBoundedness);
        vec!["Budget bounds exceed parent".into()]
    } else {
        vec![]
    };

    // 4. Governance monotonicity (anti-coup)
    let proof_req_drops = if parent.amendment_rules.require_monotone_proofreq {
        let drops = child
            .proof_requirements
            .dropped_requirements(&parent.proof_requirements);
        if !drops.is_empty() {
            violated.push(ConstitutionalInvariant::GovernanceMonotonicity);
        }
        drops
    } else {
        vec![]
    };

    let diff = PolicyDiffReport {
        capability_escalations: cap_escalations,
        io_escalations,
        budget_escalations,
        proof_requirement_drops: proof_req_drops,
        violated_invariants: violated,
    };

    MonotonicityVerdict {
        passed: diff.is_clean(),
        diff,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ck_types::manifest::*;

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
                repo_write_targets: ["coproduct/nucleus".into()].into(),
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
                controller_patch: ["build_pass".into(), "tests_pass".into(), "kani_pass".into()]
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

    #[test]
    fn test_identical_manifests_pass() {
        let m = base_manifest();
        let v = check_monotonicity(&m, &m);
        assert!(v.passed);
        assert!(v.diff.is_clean());
    }

    #[test]
    fn test_tighter_child_passes() {
        let parent = base_manifest();
        let mut child = parent.clone();
        child.capabilities.network_allow.clear(); // fewer capabilities
        child.budget_bounds.max_tokens = 100_000; // tighter budget
        child
            .proof_requirements
            .controller_patch
            .insert("replay_pass".into()); // stricter checks
        let v = check_monotonicity(&parent, &child);
        assert!(v.passed, "Tighter child should pass: {:?}", v.diff);
    }

    #[test]
    fn test_capability_escalation_rejected() {
        let parent = base_manifest();
        let mut child = parent.clone();
        child.capabilities.network_allow.insert("evil.com".into());
        let v = check_monotonicity(&parent, &child);
        assert!(!v.passed);
        assert!(v
            .diff
            .violated_invariants
            .contains(&ConstitutionalInvariant::CapabilityNonEscalation));
        assert!(v.diff.capability_escalations[0].contains("evil.com"));
    }

    #[test]
    fn test_io_widening_rejected() {
        let parent = base_manifest();
        let mut child = parent.clone();
        child
            .io_surface
            .outbound_domains
            .insert("exfiltrate.io".into());
        let v = check_monotonicity(&parent, &child);
        assert!(!v.passed);
        assert!(v
            .diff
            .violated_invariants
            .contains(&ConstitutionalInvariant::IoConfinement));
        // Detailed escalation report should mention the specific domain
        assert!(
            v.diff
                .io_escalations
                .iter()
                .any(|e| e.contains("exfiltrate.io")),
            "Expected detailed I/O escalation report, got: {:?}",
            v.diff.io_escalations
        );
    }

    #[test]
    fn test_budget_escalation_rejected() {
        let parent = base_manifest();
        let mut child = parent.clone();
        child.budget_bounds.max_dollar_spend_millicents = 999_999;
        let v = check_monotonicity(&parent, &child);
        assert!(!v.passed);
        assert!(v
            .diff
            .violated_invariants
            .contains(&ConstitutionalInvariant::ResourceBoundedness));
    }

    #[test]
    fn test_proof_requirement_weakening_rejected() {
        let parent = base_manifest();
        let mut child = parent.clone();
        child
            .proof_requirements
            .controller_patch
            .remove("kani_pass");
        let v = check_monotonicity(&parent, &child);
        assert!(!v.passed);
        assert!(v
            .diff
            .violated_invariants
            .contains(&ConstitutionalInvariant::GovernanceMonotonicity));
        assert!(v.diff.proof_requirement_drops[0].contains("kani_pass"));
    }

    #[test]
    fn test_multiple_violations_all_reported() {
        let parent = base_manifest();
        let mut child = parent.clone();
        child.capabilities.tools_allow.insert("rootkit".into());
        child.budget_bounds.max_tokens = 999_999;
        child.proof_requirements.config_patch.remove("tests_pass");
        let v = check_monotonicity(&parent, &child);
        assert!(!v.passed);
        assert_eq!(v.diff.violated_invariants.len(), 3);
    }

    #[test]
    fn test_monotonicity_disabled_allows_escalation() {
        let mut parent = base_manifest();
        parent.amendment_rules.require_monotone_capabilities = false;
        parent.amendment_rules.require_monotone_io = false;
        parent.amendment_rules.require_monotone_proofreq = false;

        let mut child = parent.clone();
        child
            .capabilities
            .network_allow
            .insert("anywhere.com".into());
        child.proof_requirements.controller_patch.clear();

        // Budget is always checked (not optional)
        let v = check_monotonicity(&parent, &child);
        assert!(
            v.passed,
            "With monotonicity disabled, should pass: {:?}",
            v.diff
        );
    }

    // ── The amendment relation is a PREORDER (reflexive + transitive) ──────
    //
    // The example tests above check individual invariants on fixed manifests.
    // These prove the order-theoretic laws of `check_monotonicity` itself over
    // arbitrary capability sets — the laws a constitutional kernel's safety across
    // an amendment CHAIN depends on:
    //   * reflexive  — a manifest is always a valid amendment of itself.
    //   * transitive — if B is a valid amendment of A and C of B, then C is a
    //     valid amendment of A. Without this, an attacker could escalate
    //     GRADUALLY: A⊒B and B⊒C each pass while A⊒C would not (boiling-frog).
    use proptest::prelude::*;

    /// `base_manifest()` with its capability `filesystem_read` set to `caps`
    /// (every other field held equal, so only the capability invariant varies).
    fn manifest_with_caps(caps: BTreeSet<String>) -> PolicyManifest {
        let mut m = base_manifest();
        m.capabilities.filesystem_read = caps;
        m
    }

    fn as_set(items: &[String], keep: &[bool]) -> BTreeSet<String> {
        items
            .iter()
            .zip(keep)
            .filter(|(_, k)| **k)
            .map(|(s, _)| s.clone())
            .collect()
    }

    proptest! {
        /// Reflexivity: any manifest is a valid amendment of itself.
        #[test]
        fn amendment_is_reflexive(items in proptest::collection::vec("[a-z/]{1,4}", 0..6)) {
            let m = manifest_with_caps(items.into_iter().collect());
            prop_assert!(check_monotonicity(&m, &m).passed, "reflexivity failed");
        }

        /// Transitivity: build C ⊆ B ⊆ A by construction; each step is a valid
        /// amendment, and the composed A⊒C must be too (no gradual escalation).
        #[test]
        fn amendment_is_transitive(
            (items, keep_b, keep_c) in proptest::collection::vec("[a-z/]{1,4}", 0..6)
                .prop_flat_map(|items| {
                    let n = items.len();
                    (
                        Just(items),
                        proptest::collection::vec(any::<bool>(), n),
                        proptest::collection::vec(any::<bool>(), n),
                    )
                }),
        ) {
            let a: BTreeSet<String> = items.iter().cloned().collect();
            let b = as_set(&items, &keep_b);
            // C kept only where it's ALSO in B ⇒ C ⊆ B ⊆ A by construction.
            let cc: Vec<bool> = keep_b.iter().zip(&keep_c).map(|(b, c)| *b && *c).collect();
            let c = as_set(&items, &cc);

            let ma = manifest_with_caps(a);
            let mb = manifest_with_caps(b);
            let mc = manifest_with_caps(c);

            prop_assert!(check_monotonicity(&ma, &mb).passed, "step A⊒B failed");
            prop_assert!(check_monotonicity(&mb, &mc).passed, "step B⊒C failed");
            prop_assert!(
                check_monotonicity(&ma, &mc).passed,
                "TRANSITIVITY: A⊒B and B⊒C passed but A⊒C did not"
            );
        }
    }
}
