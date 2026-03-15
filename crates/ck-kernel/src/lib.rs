//! Constitutional Kernel — admission engine.
//!
//! The kernel is the smallest component that can reject self-serving
//! amendments even when the proposer is clever. It checks:
//! - structure (well-formed candidate, known parent)
//! - monotonicity (constitutional invariants preserved)
//! - evidence (witness bundle complete and valid)
//! - lineage (append atomically on acceptance)
//!
//! The kernel does NOT know about prompts, LLM reasoning, or task semantics.

mod lineage;

use ck_policy::check_monotonicity;
use ck_types::witness::LineageRecord;
use ck_types::{
    AdmissionDecision, ArtifactDigest, ConstitutionalInvariant, PatchClass, RejectionReason,
};
use tracing::{info, warn};

pub use lineage::LineageStore;

/// A candidate amendment submitted for admission.
pub struct CandidateAmendment {
    pub parent_digest: ArtifactDigest,
    pub candidate_digest: ArtifactDigest,
    pub patch_class: PatchClass,
    pub witness: ck_types::WitnessBundle,
}

/// The constitutional kernel admission engine.
///
/// Validates candidates against constitutional invariants and maintains
/// the accepted lineage. The kernel is intentionally simple — it checks
/// structure, monotonicity, evidence completeness, and appends lineage.
pub struct Kernel {
    lineage: LineageStore,
}

impl Kernel {
    /// Create a new kernel with an empty lineage.
    ///
    /// The genesis artifact is automatically admitted as the root.
    pub fn new(genesis_digest: ArtifactDigest) -> Self {
        let mut lineage = LineageStore::new();
        lineage.admit_genesis(genesis_digest);
        Self { lineage }
    }

    /// Submit a candidate amendment for admission.
    ///
    /// Returns `Accepted` with lineage record, or `Rejected` with reasons.
    pub fn admit(&mut self, candidate: CandidateAmendment) -> AdmissionDecision {
        let mut reasons = Vec::new();

        // 1. Parent must be known and admitted
        if !self.lineage.is_admitted(&candidate.parent_digest) {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::BoundedTermination,
                message: format!(
                    "Parent {} is not in the admitted lineage",
                    candidate.parent_digest
                ),
            });
            return AdmissionDecision::Rejected { reasons };
        }

        // 2. Patch class must be well-formed
        if candidate.patch_class == PatchClass::Constitutional {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                message: "Constitutional amendments cannot be self-merged; \
                          requires explicit higher-order authorization"
                    .into(),
            });
            return AdmissionDecision::Rejected { reasons };
        }

        // 3. Witness bundle structural completeness
        if let Err(missing) = candidate.witness.is_structurally_complete() {
            for m in missing {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::BoundedTermination,
                    message: format!("Witness incomplete: {}", m),
                });
            }
            return AdmissionDecision::Rejected { reasons };
        }

        // 4. Parent/candidate digests must match witness
        if candidate.witness.parent_digest != candidate.parent_digest {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::BoundedTermination,
                message: "Witness parent_digest does not match candidate parent_digest".into(),
            });
        }
        if candidate.witness.candidate_digest != candidate.candidate_digest {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::BoundedTermination,
                message: "Witness candidate_digest does not match candidate".into(),
            });
        }
        if !reasons.is_empty() {
            return AdmissionDecision::Rejected { reasons };
        }

        // 5. Monotonicity check (the constitutional contract)
        let verdict = check_monotonicity(
            &candidate.witness.policy_before,
            &candidate.witness.policy_after,
        );
        if !verdict.passed {
            for invariant in &verdict.diff.violated_invariants {
                let message = match invariant {
                    ConstitutionalInvariant::CapabilityNonEscalation => format!(
                        "Capability escalation: {:?}",
                        verdict.diff.capability_escalations
                    ),
                    ConstitutionalInvariant::IoConfinement => {
                        format!("I/O surface widened: {:?}", verdict.diff.io_escalations)
                    }
                    ConstitutionalInvariant::ResourceBoundedness => format!(
                        "Budget bounds exceeded: {:?}",
                        verdict.diff.budget_escalations
                    ),
                    ConstitutionalInvariant::GovernanceMonotonicity => format!(
                        "Proof requirements weakened: {:?}",
                        verdict.diff.proof_requirement_drops
                    ),
                    ConstitutionalInvariant::BoundedTermination => {
                        "Bounded termination violated".into()
                    }
                };
                reasons.push(RejectionReason {
                    invariant: *invariant,
                    message,
                });
            }
            warn!(
                parent = %candidate.parent_digest,
                candidate = %candidate.candidate_digest,
                violations = reasons.len(),
                "Amendment REJECTED — constitutional violation"
            );
            return AdmissionDecision::Rejected { reasons };
        }

        // 6. Check required verifier reports based on patch class
        let report_reasons = check_required_reports(&candidate);
        if !report_reasons.is_empty() {
            reasons.extend(report_reasons);
            return AdmissionDecision::Rejected { reasons };
        }

        // 7. All checks passed — admit
        let witness_digest = candidate.witness.digest();
        let record = self.lineage.append(
            candidate.parent_digest,
            candidate.candidate_digest.clone(),
            witness_digest.clone(),
            candidate.patch_class,
        );

        info!(
            sequence = record.sequence,
            candidate = %record.candidate_digest,
            patch_class = ?candidate.patch_class,
            "Amendment ADMITTED"
        );

        AdmissionDecision::Accepted {
            lineage_digest: record.candidate_digest,
            witness_digest,
        }
    }

    /// Number of admitted descendants in the lineage.
    pub fn lineage_length(&self) -> usize {
        self.lineage.len()
    }

    /// Check if a digest is in the admitted lineage.
    pub fn is_admitted(&self, digest: &ArtifactDigest) -> bool {
        self.lineage.is_admitted(digest)
    }

    /// Get the full lineage as an ordered list of records.
    pub fn lineage(&self) -> &[LineageRecord] {
        self.lineage.records()
    }
}

/// Check that required verification reports are present and passed.
fn check_required_reports(candidate: &CandidateAmendment) -> Vec<RejectionReason> {
    let mut reasons = Vec::new();
    let reports = &candidate.witness.reports;

    // Build report always required
    match &reports.build {
        Some(r) if !r.passed => {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::BoundedTermination,
                message: format!("Build failed: {}", r.summary),
            });
        }
        None => {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::BoundedTermination,
                message: "Build report missing".into(),
            });
        }
        _ => {}
    }

    // Test report always required
    match &reports.tests {
        Some(r) if !r.passed => {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::BoundedTermination,
                message: format!("Tests failed: {}", r.summary),
            });
        }
        None => {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::BoundedTermination,
                message: "Test report missing".into(),
            });
        }
        _ => {}
    }

    // Kani required for Controller and Evaluator patches
    if matches!(
        candidate.patch_class,
        PatchClass::Controller | PatchClass::Evaluator
    ) {
        match &reports.kani {
            Some(r) if !r.passed => {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::BoundedTermination,
                    message: format!("Kani verification failed: {}", r.summary),
                });
            }
            None => {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::BoundedTermination,
                    message: "Kani report required for controller/evaluator patches".into(),
                });
            }
            _ => {}
        }
    }

    reasons
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::Utc;
    use ck_types::manifest::*;
    use ck_types::witness::*;

    use super::*;

    fn test_manifest() -> ck_types::manifest::PolicyManifest {
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

    fn make_witness(
        parent: &ArtifactDigest,
        candidate: &ArtifactDigest,
        policy_after: PolicyManifest,
        build_pass: bool,
        test_pass: bool,
        kani_pass: Option<bool>,
    ) -> ck_types::WitnessBundle {
        let policy_before = test_manifest();
        ck_types::WitnessBundle {
            bundle_version: 1,
            parent_digest: parent.clone(),
            candidate_digest: candidate.clone(),
            patch_digest: ArtifactDigest::from_bytes(b"patch"),
            patch_class: PatchClass::Config,
            timestamp_utc: Utc::now(),
            toolchain: ToolchainInfo {
                container_digest: None,
                rustc_version: "1.85.0".into(),
                kani_version: Some("0.50.0".into()),
                kernel_version: "0.1.0".into(),
            },
            policy_before,
            policy_after,
            reports: VerificationReports {
                build: Some(ReportSummary {
                    passed: build_pass,
                    summary: if build_pass {
                        "OK".into()
                    } else {
                        "Build failed".into()
                    },
                    artifact_digest: None,
                }),
                tests: Some(ReportSummary {
                    passed: test_pass,
                    summary: if test_pass {
                        "OK".into()
                    } else {
                        "Tests failed".into()
                    },
                    artifact_digest: None,
                }),
                kani: kani_pass.map(|p| ReportSummary {
                    passed: p,
                    summary: if p { "OK".into() } else { "Kani failed".into() },
                    artifact_digest: None,
                }),
                policy_diff: None,
                replay: None,
                adversarial: None,
                termination: None,
                artifact_digests: BTreeMap::new(),
            },
            signatures: vec![BundleSignature {
                signer: "kernel-ci".into(),
                algorithm: "ed25519".into(),
                signature: "test-sig".into(),
            }],
        }
    }

    #[test]
    fn test_admit_valid_config_patch() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate_digest = ArtifactDigest::from_bytes(b"v2");
        let witness = make_witness(
            &genesis,
            &candidate_digest,
            test_manifest(),
            true,
            true,
            None,
        );

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate_digest.clone(),
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(matches!(result, AdmissionDecision::Accepted { .. }));
        assert_eq!(kernel.lineage_length(), 2); // genesis + v2
        assert!(kernel.is_admitted(&candidate_digest));
    }

    #[test]
    fn test_reject_unknown_parent() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis);

        let fake_parent = ArtifactDigest::from_bytes(b"fake");
        let candidate = ArtifactDigest::from_bytes(b"v2");
        let witness = make_witness(&fake_parent, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: fake_parent,
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(matches!(result, AdmissionDecision::Rejected { .. }));
    }

    #[test]
    fn test_reject_constitutional_self_merge() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"coup");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Constitutional,
            witness,
        });

        assert!(matches!(result, AdmissionDecision::Rejected { .. }));
        if let AdmissionDecision::Rejected { reasons } = result {
            assert!(reasons[0].message.contains("higher-order authorization"));
        }
    }

    #[test]
    fn test_reject_capability_escalation() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let mut escalated = test_manifest();
        escalated
            .capabilities
            .network_allow
            .insert("evil.com".into());

        let candidate = ArtifactDigest::from_bytes(b"evil");
        let witness = make_witness(&genesis, &candidate, escalated, true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(matches!(result, AdmissionDecision::Rejected { .. }));
        if let AdmissionDecision::Rejected { reasons } = result {
            assert!(reasons
                .iter()
                .any(|r| r.invariant == ConstitutionalInvariant::CapabilityNonEscalation));
        }
    }

    #[test]
    fn test_reject_failed_build() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"broken");
        let witness = make_witness(&genesis, &candidate, test_manifest(), false, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(matches!(result, AdmissionDecision::Rejected { .. }));
    }

    #[test]
    fn test_controller_patch_requires_kani() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"ctrl");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Controller,
            witness,
        });

        assert!(matches!(result, AdmissionDecision::Rejected { .. }));
        if let AdmissionDecision::Rejected { reasons } = result {
            assert!(reasons.iter().any(|r| r.message.contains("Kani")));
        }
    }

    #[test]
    fn test_controller_patch_with_kani_passes() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"ctrl-proven");
        let mut witness = make_witness(
            &genesis,
            &candidate,
            test_manifest(),
            true,
            true,
            Some(true),
        );
        witness.patch_class = PatchClass::Controller;

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Controller,
            witness,
        });

        assert!(matches!(result, AdmissionDecision::Accepted { .. }));
    }

    #[test]
    fn test_lineage_chain() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        // v1 descends from genesis
        let v1 = ArtifactDigest::from_bytes(b"v1");
        let w1 = make_witness(&genesis, &v1, test_manifest(), true, true, None);
        kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: v1.clone(),
            patch_class: PatchClass::Config,
            witness: w1,
        });

        // v2 descends from v1
        let v2 = ArtifactDigest::from_bytes(b"v2");
        let mut w2 = make_witness(&v1, &v2, test_manifest(), true, true, None);
        w2.policy_before = test_manifest(); // parent's policy
        kernel.admit(CandidateAmendment {
            parent_digest: v1.clone(),
            candidate_digest: v2.clone(),
            patch_class: PatchClass::Config,
            witness: w2,
        });

        assert_eq!(kernel.lineage_length(), 3); // genesis + v1 + v2
        assert!(kernel.is_admitted(&v1));
        assert!(kernel.is_admitted(&v2));

        let records = kernel.lineage();
        assert_eq!(records[1].parent_digest, records[0].candidate_digest);
        assert_eq!(records[2].parent_digest, records[1].candidate_digest);
    }

    #[test]
    fn test_digest_mismatch_rejected() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"v2");
        let wrong_parent = ArtifactDigest::from_bytes(b"wrong");
        // Witness claims different parent than the candidate submission
        let witness = make_witness(&wrong_parent, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis, // actual parent
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness, // witness says parent is "wrong"
        });

        assert!(matches!(result, AdmissionDecision::Rejected { .. }));
    }
}
