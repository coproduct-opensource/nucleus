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

mod kani;
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

/// Policy for how the kernel handles signature verification during admission.
///
/// Production deployments MUST use `Enforced`. `SkipForTesting` exists
/// only for unit tests that exercise non-signature admission logic.
/// There is no silent "off" mode — every kernel must make an explicit choice.
pub enum SignaturePolicy {
    /// Verify Ed25519 signatures on witness bundles. Reject if invalid.
    Enforced(ck_types::witness::SignatureVerifier),
    /// Skip signature verification entirely. Test mode only.
    ///
    /// Using this in production means ANY witness bundle will be accepted
    /// regardless of signatures. This is intentionally named to make
    /// accidental production use obvious in code review.
    SkipForTesting,
}

/// The constitutional kernel admission engine.
///
/// Validates candidates against constitutional invariants and maintains
/// the accepted lineage. The kernel is intentionally simple — it checks
/// structure, monotonicity, signatures, evidence completeness, and appends lineage.
pub struct Kernel {
    lineage: LineageStore,
    /// Signature verification policy. Production MUST use `Enforced`.
    signature_policy: SignaturePolicy,
    /// Maps candidate_digest → policy_after for admitted amendments.
    /// Used to verify that a new amendment's policy_before matches
    /// the parent's actual admitted policy (anti-forgery).
    admitted_policies: std::collections::HashMap<String, ck_types::manifest::PolicyManifest>,
}

impl Kernel {
    /// Create a new kernel with an empty lineage.
    ///
    /// The genesis artifact is automatically admitted as the root.
    /// If `git_commit_sha` is provided, it is stored on the genesis record
    /// so the verification bridge can create worktrees at the correct ref.
    pub fn new_with_sha(genesis_digest: ArtifactDigest, git_commit_sha: Option<String>) -> Self {
        let mut lineage = LineageStore::new();
        lineage.admit_genesis(genesis_digest, git_commit_sha);
        Self {
            lineage,
            signature_policy: SignaturePolicy::SkipForTesting,
            admitted_policies: std::collections::HashMap::new(),
        }
    }

    /// Create a new kernel with an empty lineage (no git SHA on genesis).
    pub fn new(genesis_digest: ArtifactDigest) -> Self {
        Self::new_with_sha(genesis_digest, None)
    }

    /// Restore a kernel from persisted lineage records.
    ///
    /// Rebuilds the in-memory lineage from a list of previously admitted
    /// records (e.g., loaded from a database). Records are replayed in
    /// order without re-running admission checks — the caller guarantees
    /// they were previously validated.
    ///
    /// The first record is treated as genesis. Returns an error if records
    /// are empty or if sequence numbers are not monotonically increasing.
    ///
    /// **Important**: Without `policy_snapshots`, the first amendment after
    /// restoration can forge `policy_before` because no policies are stored.
    /// Production kernels MUST call [`restore_with_policies`] instead, or
    /// supply snapshots here.
    pub fn restore(
        records: Vec<LineageRecord>,
        signature_policy: SignaturePolicy,
    ) -> Result<Self, String> {
        Self::restore_with_policies(records, signature_policy, std::collections::HashMap::new())
    }

    /// Restore a kernel from persisted lineage records and policy snapshots.
    ///
    /// `policy_snapshots` maps `candidate_digest` → `PolicyManifest` for each
    /// previously admitted amendment. This ensures the anti-forgery check on
    /// `policy_before` works correctly after restoration.
    pub fn restore_with_policies(
        records: Vec<LineageRecord>,
        signature_policy: SignaturePolicy,
        policy_snapshots: std::collections::HashMap<String, ck_types::manifest::PolicyManifest>,
    ) -> Result<Self, String> {
        if records.is_empty() {
            return Err("Cannot restore kernel from empty lineage".into());
        }
        let lineage = LineageStore::restore(records)?;
        Ok(Self {
            lineage,
            signature_policy,
            admitted_policies: policy_snapshots,
        })
    }

    /// Configure signature verification for admission.
    ///
    /// When called, `admit()` will cryptographically verify Ed25519 signatures
    /// on witness bundles before accepting them. Production kernels MUST
    /// call this — `SkipForTesting` is a test-mode-only convenience.
    pub fn with_signature_verifier(
        mut self,
        verifier: ck_types::witness::SignatureVerifier,
    ) -> Self {
        self.signature_policy = SignaturePolicy::Enforced(verifier);
        self
    }

    /// Submit a candidate amendment for admission.
    ///
    /// Returns `Accepted` with lineage record, or `Rejected` with reasons.
    /// `changed_files` is optional — when provided, may_not_modify rules are enforced.
    pub fn admit(&mut self, candidate: CandidateAmendment) -> AdmissionDecision {
        self.admit_with_files(candidate, &[])
    }

    /// Submit a candidate amendment with file-level amendment rule enforcement.
    pub fn admit_with_files(
        &mut self,
        candidate: CandidateAmendment,
        changed_files: &[String],
    ) -> AdmissionDecision {
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

        // 1.5. Dual-DAG enforcement: ordinary amendments must parent from
        //      the latest admitted node. This prevents out-of-band commits
        //      from silently becoming constitutional lineage ancestors.
        if let Some(latest) = self.lineage.latest_admitted_digest() {
            if candidate.parent_digest != latest {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                    message: format!(
                        "Ordinary amendment must parent from latest admitted node {}; got {}",
                        latest, candidate.parent_digest
                    ),
                });
                return AdmissionDecision::Rejected { reasons };
            }
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

        // 3.5. Cryptographic signature verification (fail-closed)
        match &self.signature_policy {
            SignaturePolicy::Enforced(verifier) => {
                if let Err(sig_errors) = verifier.verify(&candidate.witness) {
                    for e in sig_errors {
                        reasons.push(RejectionReason {
                            invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                            message: format!("Signature verification failed: {}", e),
                        });
                    }
                    return AdmissionDecision::Rejected { reasons };
                }
            }
            SignaturePolicy::SkipForTesting => {
                // Test mode: intentionally skip signature verification.
                // Production kernels MUST use SignaturePolicy::Enforced.
                #[cfg(not(test))]
                eprintln!(
                    "WARNING: ck-kernel signature verification DISABLED (SkipForTesting). \
                     Production deployments MUST call .with_signature_verifier(). \
                     Any witness bundle will be accepted without cryptographic proof."
                );
            }
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

        // 4.5. Policy continuity: witness.policy_before must match the parent's
        //      admitted policy. This prevents an attacker from lying about the
        //      parent's policy to smuggle in escalations.
        if let Some(parent_policy) = self.admitted_policies.get(candidate.parent_digest.as_str()) {
            if candidate.witness.policy_before != *parent_policy {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                    message:
                        "witness.policy_before does not match parent's admitted policy (forgery?)"
                            .into(),
                });
                return AdmissionDecision::Rejected { reasons };
            }
        }
        // If no stored policy (genesis or restored kernel), trust the witness.
        // Production kernels should restore policies alongside lineage records.

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

        // 5.5. Enforce may_modify / may_not_modify amendment rules
        if !changed_files.is_empty() {
            let rules = &candidate.witness.policy_after.amendment_rules;
            for file in changed_files {
                // Check may_not_modify: these paths are never allowed on ordinary path
                for forbidden in &rules.may_not_modify {
                    if file.contains(forbidden.as_str()) {
                        reasons.push(RejectionReason {
                            invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                            message: format!(
                                "File '{}' matches may_not_modify rule '{}'",
                                file, forbidden
                            ),
                        });
                    }
                }
            }
            if !reasons.is_empty() {
                return AdmissionDecision::Rejected { reasons };
            }
        }

        // 6. Check required verifier reports based on patch class
        let report_reasons = check_required_reports(&candidate);
        if !report_reasons.is_empty() {
            reasons.extend(report_reasons);
            return AdmissionDecision::Rejected { reasons };
        }

        // 7. All checks passed — admit
        let witness_digest = candidate.witness.digest();
        // Store the admitted policy for future policy_before verification
        self.admitted_policies.insert(
            candidate.candidate_digest.as_str().to_string(),
            candidate.witness.policy_after.clone(),
        );
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

    /// Import an external commit as a trusted base into the lineage.
    ///
    /// The parent must already be in the lineage (no disconnected islands).
    /// Returns the new lineage record with `AdmissionMode::Imported`.
    pub fn import_trusted_base(
        &mut self,
        parent_digest: ArtifactDigest,
        candidate_digest: ArtifactDigest,
        git_commit_sha: Option<String>,
    ) -> Result<LineageRecord, String> {
        if !self.lineage.is_admitted(&parent_digest) {
            return Err(format!(
                "Parent {} is not in the admitted lineage — cannot import disconnected artifact",
                parent_digest
            ));
        }
        Ok(self.lineage.import(
            parent_digest,
            candidate_digest,
            git_commit_sha.unwrap_or_default(),
        ))
    }

    /// Get the most recent lineage record.
    pub fn latest_record(&self) -> Option<&LineageRecord> {
        self.lineage.latest_record()
    }

    /// Submit a constitutional amendment for admission.
    ///
    /// Constitutional amendments change TCB files and require threshold
    /// human signatures with cryptographic verification. Unlike `admit()`,
    /// this method accepts `PatchClass::Constitutional` but enforces:
    /// - Signature count >= `required_signatures`
    /// - Each signature is cryptographically valid against the witness payload
    /// - Each signer identity is unique (no double-signing)
    ///
    /// `trusted_human_keys` maps identity → Ed25519 public key bytes.
    pub fn admit_constitutional(
        &mut self,
        candidate: CandidateAmendment,
        human_signatures: &[ck_types::witness::HumanSignature],
        required_signatures: u32,
        trusted_human_keys: &[(String, Vec<u8>)],
    ) -> AdmissionDecision {
        let mut reasons = Vec::new();

        // 1. Must be a Constitutional patch
        if candidate.patch_class != PatchClass::Constitutional {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                message: format!(
                    "admit_constitutional requires PatchClass::Constitutional, got {:?}",
                    candidate.patch_class
                ),
            });
            return AdmissionDecision::Rejected { reasons };
        }

        // 2. Parent must be known
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

        // 3. Parent must be latest (dual-DAG)
        if let Some(latest) = self.lineage.latest_admitted_digest() {
            if candidate.parent_digest != latest {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                    message: format!(
                        "Constitutional amendment must parent from latest: {} != {}",
                        latest, candidate.parent_digest
                    ),
                });
                return AdmissionDecision::Rejected { reasons };
            }
        }

        // 4. Human signature threshold + cryptographic verification
        let payload = candidate.witness.signing_payload();
        let mut verified_identities = std::collections::HashSet::new();

        for sig in human_signatures {
            // Find trusted key for this identity
            let trusted = trusted_human_keys
                .iter()
                .find(|(id, _)| id == &sig.identity);

            let Some((_, pub_key_bytes)) = trusted else {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                    message: format!("Human signer '{}' not in trusted key set", sig.identity),
                });
                continue;
            };

            // Verify Ed25519 signature
            let public_key =
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pub_key_bytes);
            if public_key.verify(&payload, &sig.signature).is_err() {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                    message: format!(
                        "Human signer '{}' Ed25519 signature verification failed",
                        sig.identity
                    ),
                });
                continue;
            }

            // Deduplicate — same identity cannot sign twice
            if !verified_identities.insert(&sig.identity) {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                    message: format!("Human signer '{}' signed more than once", sig.identity),
                });
                continue;
            }
        }

        let verified_count = verified_identities.len() as u32;
        if verified_count < required_signatures {
            reasons.push(RejectionReason {
                invariant: ConstitutionalInvariant::GovernanceMonotonicity,
                message: format!(
                    "Constitutional amendment requires {} verified human signatures, got {}",
                    required_signatures, verified_count
                ),
            });
            return AdmissionDecision::Rejected { reasons };
        }

        // 5. Witness structural completeness
        if let Err(missing) = candidate.witness.is_structurally_complete() {
            for m in missing {
                reasons.push(RejectionReason {
                    invariant: ConstitutionalInvariant::BoundedTermination,
                    message: format!("Witness incomplete: {}", m),
                });
            }
            return AdmissionDecision::Rejected { reasons };
        }

        // 6. Monotonicity still applies (constitutional amendments can
        //    relax rules but must do so explicitly — the diff is recorded)
        // NOTE: We intentionally do NOT enforce monotonicity for constitutional
        // amendments. The human signatures ARE the authorization to change rules.
        // The policy diff is still recorded in the witness for auditability.

        // 7. Admit with ConstitutionalAmendment mode
        let witness_digest = candidate.witness.digest();
        // Store the admitted policy for future policy_before verification.
        // Without this, the next amendment's anti-forgery check would find
        // no entry and skip verification — enabling policy_before forgery.
        self.admitted_policies.insert(
            candidate.candidate_digest.as_str().to_string(),
            candidate.witness.policy_after.clone(),
        );
        let record = self.lineage.append_constitutional(
            candidate.parent_digest,
            candidate.candidate_digest.clone(),
            witness_digest.clone(),
            candidate.patch_class,
        );

        info!(
            sequence = record.sequence,
            candidate = %record.candidate_digest,
            human_signatures = verified_count,
            "Constitutional amendment ADMITTED"
        );

        AdmissionDecision::Accepted {
            lineage_digest: record.candidate_digest,
            witness_digest,
        }
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
                sandbox: None,
                artifact_digests: BTreeMap::new(),
            },
            signatures: vec![BundleSignature {
                signer: "kernel-ci".into(),
                algorithm: "ed25519".into(),
                signature: "test-sig".into(),
                role: None,
            }],
            source_tree_digest: None,
            build_container_digest: None,
            manifest_digest_before: None,
            manifest_digest_after: None,
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

    fn human_keypair(seed: &[u8]) -> (ring::signature::Ed25519KeyPair, Vec<u8>) {
        use ring::signature::KeyPair;
        let seed_hash = ring::digest::digest(&ring::digest::SHA256, seed);
        let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed_hash.as_ref())
            .expect("valid seed");
        let pub_key = kp.public_key().as_ref().to_vec();
        (kp, pub_key)
    }

    fn sign_as_human(
        identity: &str,
        kp: &ring::signature::Ed25519KeyPair,
        witness: &WitnessBundle,
    ) -> HumanSignature {
        let payload = witness.signing_payload();
        let sig = kp.sign(&payload);
        HumanSignature {
            identity: identity.into(),
            signature: sig.as_ref().to_vec(),
            signed_at: Utc::now(),
        }
    }

    #[test]
    fn test_constitutional_amendment_with_verified_signatures() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"constitutional-v1");
        let witness = make_witness(
            &genesis,
            &candidate,
            test_manifest(),
            true,
            true,
            Some(true),
        );

        let (alice_kp, alice_pk) = human_keypair(b"alice-seed");
        let (bob_kp, bob_pk) = human_keypair(b"bob-seed");

        let sigs = vec![
            sign_as_human("alice@example.com", &alice_kp, &witness),
            sign_as_human("bob@example.com", &bob_kp, &witness),
        ];
        let trusted_keys = vec![
            ("alice@example.com".into(), alice_pk),
            ("bob@example.com".into(), bob_pk),
        ];

        let result = kernel.admit_constitutional(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate,
                patch_class: PatchClass::Constitutional,
                witness,
            },
            &sigs,
            2,
            &trusted_keys,
        );

        assert!(
            matches!(result, AdmissionDecision::Accepted { .. }),
            "Constitutional with 2/2 verified signatures should be accepted: {result:?}"
        );
        assert_eq!(kernel.lineage_length(), 2);
    }

    #[test]
    fn test_constitutional_rejects_forged_human_signature() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"constitutional-v1");
        let witness = make_witness(
            &genesis,
            &candidate,
            test_manifest(),
            true,
            true,
            Some(true),
        );

        let (_alice_kp, alice_pk) = human_keypair(b"alice-seed");
        let (attacker_kp, _) = human_keypair(b"attacker-seed");

        // Sign with attacker's key but claim alice's identity
        let forged = sign_as_human("alice@example.com", &attacker_kp, &witness);
        let trusted_keys = vec![("alice@example.com".into(), alice_pk)];

        let result = kernel.admit_constitutional(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate,
                patch_class: PatchClass::Constitutional,
                witness,
            },
            &[forged],
            1,
            &trusted_keys,
        );

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Forged human signature must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_constitutional_rejects_duplicate_signer() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"constitutional-v1");
        let witness = make_witness(
            &genesis,
            &candidate,
            test_manifest(),
            true,
            true,
            Some(true),
        );

        let (alice_kp, alice_pk) = human_keypair(b"alice-seed");

        // Same identity signs twice
        let sigs = vec![
            sign_as_human("alice@example.com", &alice_kp, &witness),
            sign_as_human("alice@example.com", &alice_kp, &witness),
        ];
        let trusted_keys = vec![("alice@example.com".into(), alice_pk)];

        let result = kernel.admit_constitutional(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate,
                patch_class: PatchClass::Constitutional,
                witness,
            },
            &sigs,
            2, // requires 2 distinct signers
            &trusted_keys,
        );

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Duplicate signer must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_constitutional_rejects_non_constitutional_class() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"v1");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit_constitutional(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate,
                patch_class: PatchClass::Config,
                witness,
            },
            &[],
            0,
            &[],
        );

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "admit_constitutional must require Constitutional class: {result:?}"
        );
    }

    #[test]
    fn test_may_not_modify_enforced() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"sneaky");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        // The test_manifest has may_not_modify: ["kernel_checker"]
        let changed = vec!["src/kernel_checker/mod.rs".to_string()];

        let result = kernel.admit_with_files(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate,
                patch_class: PatchClass::Config,
                witness,
            },
            &changed,
        );

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Modifying may_not_modify path must be rejected: {result:?}"
        );
        if let AdmissionDecision::Rejected { reasons } = result {
            assert!(
                reasons.iter().any(|r| r.message.contains("may_not_modify")),
                "Should cite may_not_modify: {reasons:?}"
            );
        }
    }

    #[test]
    fn test_admit_with_files_allows_safe_paths() {
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"safe");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        // These paths don't match any may_not_modify rules
        let changed = vec!["src/config/settings.rs".to_string()];

        let result = kernel.admit_with_files(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate,
                patch_class: PatchClass::Config,
                witness,
            },
            &changed,
        );

        assert!(
            matches!(result, AdmissionDecision::Accepted { .. }),
            "Safe paths should be accepted: {result:?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // SignaturePolicy tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_enforced_empty_keys_rejects_all() {
        // When Enforced with no trusted keys, SignatureVerifier::verify()
        // itself rejects (fail-closed). This simulates the production
        // failure mode when keyring is unavailable.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel =
            Kernel::new(genesis.clone()).with_signature_verifier(SignatureVerifier::new(vec![]));

        let candidate = ArtifactDigest::from_bytes(b"v2");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Enforced with no keys must reject: {result:?}"
        );
        if let AdmissionDecision::Rejected { reasons } = result {
            assert!(
                reasons
                    .iter()
                    .any(|r| r.message.contains("No trusted keys")),
                "Should mention missing keys: {reasons:?}"
            );
        }
    }

    #[test]
    fn test_skip_for_testing_admits_without_signatures() {
        // Documents that SkipForTesting allows unsigned witnesses.
        // This is the default for Kernel::new() — test mode only.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());
        // kernel.signature_policy is SkipForTesting by default

        let candidate = ArtifactDigest::from_bytes(b"v2");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(
            matches!(result, AdmissionDecision::Accepted { .. }),
            "SkipForTesting should admit: {result:?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Adversarial scenario tests — the coups we stop
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_adversarial_patch_laundering_rejected() {
        // Attack: Classify a Controller patch as Config to avoid kani proof requirement.
        // The patch modifies controller code but the class says Config.
        // Defense: admit_with_files checks changed_files against may_not_modify.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"laundered");
        let witness = make_witness(&genesis, &candidate, test_manifest(), true, true, None);

        // Claim it's Config but touch kernel_checker (in may_not_modify)
        let changed = vec!["kernel_checker/src/lib.rs".to_string()];
        let result = kernel.admit_with_files(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate,
                patch_class: PatchClass::Config,
                witness,
            },
            &changed,
        );

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Patch laundering must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_adversarial_replay_attack_rejected() {
        // Attack: Resubmit an already-admitted witness for a different candidate.
        // The witness has valid structure but points to a parent/candidate pair
        // that doesn't match the new submission.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        // First: admit v2 legitimately
        let v2 = ArtifactDigest::from_bytes(b"v2");
        let witness_v2 = make_witness(&genesis, &v2, test_manifest(), true, true, None);
        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis.clone(),
            candidate_digest: v2.clone(),
            patch_class: PatchClass::Config,
            witness: witness_v2.clone(),
        });
        assert!(matches!(result, AdmissionDecision::Accepted { .. }));

        // Attack: replay the v2 witness but claim it's for v3
        let v3 = ArtifactDigest::from_bytes(b"v3");
        let result = kernel.admit(CandidateAmendment {
            parent_digest: v2,
            candidate_digest: v3,
            patch_class: PatchClass::Config,
            witness: witness_v2, // reused! candidate_digest won't match
        });

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Replay attack must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_adversarial_lineage_tampering_detected() {
        // Attack: Submit an amendment claiming a parent that was never admitted.
        // This simulates lineage tampering — inserting a fake ancestor.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let fake_parent = ArtifactDigest::from_bytes(b"fake-injected-ancestor");
        let candidate = ArtifactDigest::from_bytes(b"candidate");
        let witness = make_witness(&fake_parent, &candidate, test_manifest(), true, true, None);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: fake_parent,
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Lineage tampering must be rejected: {result:?}"
        );
        assert_eq!(kernel.lineage_length(), 1, "Lineage must not grow");
    }

    #[test]
    fn test_adversarial_sandbox_relaxation_rejected() {
        // Attack: Widen io_surface (add exfiltration domain) while keeping
        // capabilities identical, hoping the monotonicity check misses it.
        // Defense: io_surface has its own monotonicity check.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let mut widened = test_manifest();
        widened
            .io_surface
            .outbound_domains
            .insert("exfiltrate.evil".into());

        let candidate = ArtifactDigest::from_bytes(b"widened");
        let witness = make_witness_with_policies(
            &genesis,
            &candidate,
            PatchClass::Config,
            &test_manifest(),
            &widened,
        );

        let result = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: candidate,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Sandbox relaxation must be rejected: {result:?}"
        );
        if let AdmissionDecision::Rejected { reasons } = result {
            assert!(
                reasons
                    .iter()
                    .any(|r| r.invariant == ConstitutionalInvariant::IoConfinement),
                "Must cite IoConfinement: {reasons:?}"
            );
        }
    }

    #[test]
    fn test_adversarial_policy_code_mismatch() {
        // Attack: Submit a patch where policy_after claims no change, but the
        // actual code widens authority. Since the kernel only sees the manifest,
        // the defense is that policy_before must match the parent's stored policy.
        // If the attacker lies about policy_before, it won't match the parent.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        // Legitimate v2 with specific policy
        let v2 = ArtifactDigest::from_bytes(b"v2");
        let witness = make_witness(&genesis, &v2, test_manifest(), true, true, None);
        let _ = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: v2.clone(),
            patch_class: PatchClass::Config,
            witness,
        });

        // Attack: v3 claims policy_before is a weaker policy than what v2 actually has.
        // This would let the attacker smuggle in an escalation.
        let mut fake_before = test_manifest();
        fake_before
            .capabilities
            .network_allow
            .insert("evil.com".into()); // lie: claim parent already had this
        let mut fake_after = fake_before.clone(); // "no change"
        fake_after
            .capabilities
            .network_allow
            .insert("evil.com".into());

        let v3 = ArtifactDigest::from_bytes(b"v3");
        let witness =
            make_witness_with_policies(&v2, &v3, PatchClass::Config, &fake_before, &fake_after);

        let result = kernel.admit(CandidateAmendment {
            parent_digest: v2,
            candidate_digest: v3,
            patch_class: PatchClass::Config,
            witness,
        });

        // The kernel checks policy_before against the stored parent policy.
        // If they don't match, the amendment is rejected.
        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Policy/code mismatch must be rejected: {result:?}"
        );
    }

    /// Helper: build witness with explicit before/after policies.
    fn make_witness_with_policies(
        parent: &ArtifactDigest,
        candidate: &ArtifactDigest,
        patch_class: PatchClass,
        policy_before: &PolicyManifest,
        policy_after: &PolicyManifest,
    ) -> WitnessBundle {
        use chrono::Utc;

        WitnessBundle {
            bundle_version: 1,
            parent_digest: parent.clone(),
            candidate_digest: candidate.clone(),
            patch_digest: ArtifactDigest::from_hex("abcd"),
            patch_class,
            timestamp_utc: Utc::now(),
            toolchain: ToolchainInfo {
                container_digest: None,
                rustc_version: "1.85.0".into(),
                kani_version: None,
                kernel_version: "0.1.0".into(),
            },
            policy_before: policy_before.clone(),
            policy_after: policy_after.clone(),
            reports: VerificationReports {
                build: Some(ReportSummary {
                    passed: true,
                    summary: "ok".into(),
                    artifact_digest: None,
                }),
                tests: Some(ReportSummary {
                    passed: true,
                    summary: "ok".into(),
                    artifact_digest: None,
                }),
                kani: None,
                policy_diff: None,
                replay: None,
                adversarial: None,
                termination: None,
                sandbox: None,
                artifact_digests: BTreeMap::new(),
            },
            signatures: vec![BundleSignature {
                signer: "ci".into(),
                algorithm: "ed25519".into(),
                signature: "sig".into(),
                role: None,
            }],
            source_tree_digest: None,
            build_container_digest: None,
            manifest_digest_before: None,
            manifest_digest_after: None,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Issue #835 — constitutional amendment must store admitted policy
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_constitutional_stores_admitted_policy() {
        // After a constitutional amendment is admitted, its policy must be
        // stored so the next amendment's anti-forgery check can compare.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        let candidate = ArtifactDigest::from_bytes(b"constitutional-v1");
        let mut tighter_policy = test_manifest();
        tighter_policy.capabilities.network_allow.clear(); // remove all network access

        let witness = make_witness_with_policies(
            &genesis,
            &candidate,
            PatchClass::Constitutional,
            &test_manifest(),
            &tighter_policy,
        );

        let (alice_kp, alice_pk) = human_keypair(b"alice-seed");
        let (bob_kp, bob_pk) = human_keypair(b"bob-seed");

        let sigs = vec![
            sign_as_human("alice@example.com", &alice_kp, &witness),
            sign_as_human("bob@example.com", &bob_kp, &witness),
        ];
        let trusted_keys = vec![
            ("alice@example.com".into(), alice_pk),
            ("bob@example.com".into(), bob_pk),
        ];

        let result = kernel.admit_constitutional(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: candidate.clone(),
                patch_class: PatchClass::Constitutional,
                witness,
            },
            &sigs,
            2,
            &trusted_keys,
        );
        assert!(
            matches!(result, AdmissionDecision::Accepted { .. }),
            "Constitutional amendment should be accepted: {result:?}"
        );

        // The admitted_policies map must now contain the constitutional amendment's policy.
        assert!(
            kernel.admitted_policies.contains_key(candidate.as_str()),
            "admitted_policies must contain the constitutional amendment's digest"
        );
        assert_eq!(
            kernel.admitted_policies[candidate.as_str()],
            tighter_policy,
            "Stored policy must match the constitutional amendment's policy_after"
        );
    }

    #[test]
    fn test_forgery_after_constitutional_amendment_rejected() {
        // Attack scenario from issue #835:
        // 1. Constitutional amendment tightens policy (removes network access)
        // 2. Attacker submits ordinary amendment claiming network access still present
        // 3. Must be REJECTED because admitted_policies now contains the tighter policy
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        // Step 1: Constitutional amendment removes network access
        let constitutional = ArtifactDigest::from_bytes(b"constitutional-tighten");
        let mut tighter_policy = test_manifest();
        tighter_policy.capabilities.network_allow.clear();
        tighter_policy.io_surface.outbound_domains.clear();

        let witness = make_witness_with_policies(
            &genesis,
            &constitutional,
            PatchClass::Constitutional,
            &test_manifest(),
            &tighter_policy,
        );

        let (alice_kp, alice_pk) = human_keypair(b"alice-seed");
        let (bob_kp, bob_pk) = human_keypair(b"bob-seed");

        let sigs = vec![
            sign_as_human("alice@example.com", &alice_kp, &witness),
            sign_as_human("bob@example.com", &bob_kp, &witness),
        ];
        let trusted_keys = vec![
            ("alice@example.com".into(), alice_pk),
            ("bob@example.com".into(), bob_pk),
        ];

        let result = kernel.admit_constitutional(
            CandidateAmendment {
                parent_digest: genesis,
                candidate_digest: constitutional.clone(),
                patch_class: PatchClass::Constitutional,
                witness,
            },
            &sigs,
            2,
            &trusted_keys,
        );
        assert!(matches!(result, AdmissionDecision::Accepted { .. }));

        // Step 2: Attacker forges policy_before to claim network was still present
        let attack = ArtifactDigest::from_bytes(b"attack-forgery");
        let forged_before = test_manifest(); // lies: claims parent had network access
        let forged_after = test_manifest(); // "maintains" the forged network access
        let witness = make_witness_with_policies(
            &constitutional,
            &attack,
            PatchClass::Config,
            &forged_before,
            &forged_after,
        );

        let result = kernel.admit(CandidateAmendment {
            parent_digest: constitutional,
            candidate_digest: attack,
            patch_class: PatchClass::Config,
            witness,
        });

        // Must be REJECTED: policy_before doesn't match what constitutional actually admitted
        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Forgery after constitutional amendment must be rejected: {result:?}"
        );
        if let AdmissionDecision::Rejected { reasons } = result {
            assert!(
                reasons.iter().any(|r| r.message.contains("forgery")),
                "Must cite forgery: {reasons:?}"
            );
        }
    }

    #[test]
    fn test_restore_with_policies_enables_anti_forgery() {
        // After restore with policy snapshots, the anti-forgery check works.
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        let mut kernel = Kernel::new(genesis.clone());

        // Admit v2 with normal policy
        let v2 = ArtifactDigest::from_bytes(b"v2");
        let witness = make_witness(&genesis, &v2, test_manifest(), true, true, None);
        let _ = kernel.admit(CandidateAmendment {
            parent_digest: genesis,
            candidate_digest: v2.clone(),
            patch_class: PatchClass::Config,
            witness,
        });

        // Simulate restore with policy snapshots
        let records = kernel.lineage().to_vec();
        let mut snapshots = std::collections::HashMap::new();
        snapshots.insert(v2.as_str().to_string(), test_manifest());

        let mut restored =
            Kernel::restore_with_policies(records, SignaturePolicy::SkipForTesting, snapshots)
                .expect("restore should succeed");

        // Now try a forgery against the restored kernel
        let v3 = ArtifactDigest::from_bytes(b"v3");
        let mut forged_before = test_manifest();
        forged_before
            .capabilities
            .network_allow
            .insert("evil.com".into());
        let witness = make_witness_with_policies(
            &v2,
            &v3,
            PatchClass::Config,
            &forged_before,
            &forged_before,
        );

        let result = restored.admit(CandidateAmendment {
            parent_digest: v2,
            candidate_digest: v3,
            patch_class: PatchClass::Config,
            witness,
        });

        assert!(
            matches!(result, AdmissionDecision::Rejected { .. }),
            "Forgery after restore must be rejected: {result:?}"
        );
    }
}
