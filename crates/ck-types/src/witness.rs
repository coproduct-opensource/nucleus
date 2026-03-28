//! Witness bundle — canonical evidence for amendment admission.
//!
//! Every accepted amendment emits a witness bundle containing all evidence
//! required by the constitutional kernel. The bundle is content-addressed
//! and cryptographically linked to its parent in the lineage.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::digest::ArtifactDigest;
use crate::manifest::PolicyManifest;
use crate::{ConstitutionalInvariant, PatchClass};

/// Canonical witness bundle for an amendment transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessBundle {
    pub bundle_version: u32,
    pub parent_digest: ArtifactDigest,
    pub candidate_digest: ArtifactDigest,
    pub patch_digest: ArtifactDigest,
    pub patch_class: PatchClass,
    pub timestamp_utc: DateTime<Utc>,
    pub toolchain: ToolchainInfo,
    pub policy_before: PolicyManifest,
    pub policy_after: PolicyManifest,
    pub reports: VerificationReports,
    pub signatures: Vec<BundleSignature>,
    /// BLAKE3 digest of the full source tree at the candidate commit.
    /// Binds the witness to the actual artifact, not just the commit SHA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tree_digest: Option<ArtifactDigest>,
    /// Digest of the build container image used for verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_container_digest: Option<ArtifactDigest>,
    /// BLAKE3 digest of the canonical policy_before manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_digest_before: Option<ArtifactDigest>,
    /// BLAKE3 digest of the canonical policy_after manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_digest_after: Option<ArtifactDigest>,
}

impl WitnessBundle {
    /// Compute a canonical BLAKE3 digest of this witness bundle.
    ///
    /// Excludes the `signatures` field from the digest input — signatures are
    /// computed OVER the digest, so including them would be circular. This uses
    /// the same cleared-signatures representation as `signing_payload()`.
    pub fn digest(&self) -> ArtifactDigest {
        let canonical = self.signing_payload();
        ArtifactDigest::from_bytes(&canonical)
    }

    /// Compute the canonical signing payload.
    ///
    /// This is the deterministic JSON serialization of the bundle with the
    /// `signatures` field set to an empty array. BTreeSet/BTreeMap ordering
    /// guarantees determinism.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut for_signing = self.clone();
        for_signing.signatures = vec![];
        serde_json::to_vec(&for_signing).expect("WitnessBundle is always serializable")
    }

    /// Check structural completeness: are all required fields present?
    pub fn is_structurally_complete(&self) -> Result<(), Vec<String>> {
        let mut missing = Vec::new();
        if self.bundle_version == 0 {
            missing.push("bundle_version must be > 0".into());
        }
        if self.signatures.is_empty() {
            missing.push("at least one signature required".into());
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

/// Verifies Ed25519 signatures on witness bundles.
///
/// Holds a set of trusted public keys keyed by signer name.
/// At least one valid signature from a trusted signer is required.
pub struct SignatureVerifier {
    /// Map of signer name → Ed25519 public key bytes (32 bytes).
    trusted_keys: Vec<(String, Vec<u8>)>,
    /// Roles that must be present for a bundle to be fully verified.
    /// If empty, any single valid signature suffices (legacy mode).
    required_roles: Vec<SignerRole>,
}

impl SignatureVerifier {
    /// Create a verifier with the given trusted public keys (legacy mode).
    pub fn new(trusted_keys: Vec<(String, Vec<u8>)>) -> Self {
        Self {
            trusted_keys,
            required_roles: vec![],
        }
    }

    /// Create a verifier that requires specific roles to be present.
    pub fn with_required_roles(
        trusted_keys: Vec<(String, Vec<u8>)>,
        required_roles: Vec<SignerRole>,
    ) -> Self {
        Self {
            trusted_keys,
            required_roles,
        }
    }

    /// Verify that the bundle has valid Ed25519 signatures.
    ///
    /// If `required_roles` is set, verifies that each required role has
    /// at least one valid signature. Otherwise, requires at least one
    /// valid signature from any trusted signer (legacy behavior).
    pub fn verify(&self, bundle: &WitnessBundle) -> Result<(), Vec<String>> {
        if self.trusted_keys.is_empty() {
            return Err(vec![
                "No trusted keys configured — rejecting (fail-closed)".to_string()
            ]);
        }

        let payload = bundle.signing_payload();
        let mut errors = Vec::new();
        let mut valid_roles = std::collections::HashSet::new();
        let mut valid_count = 0;
        // Track distinct public keys used for valid signatures.
        // Role separation requires distinct keys — one key can't satisfy multiple roles.
        let mut distinct_keys = std::collections::HashSet::<Vec<u8>>::new();

        for sig in &bundle.signatures {
            if sig.algorithm != "ed25519" {
                errors.push(format!(
                    "Signer '{}': unsupported algorithm '{}'",
                    sig.signer, sig.algorithm
                ));
                continue;
            }

            let trusted_key = self
                .trusted_keys
                .iter()
                .find(|(name, _)| name == &sig.signer);

            let Some((_, pub_key_bytes)) = trusted_key else {
                errors.push(format!("Signer '{}': not in trusted key set", sig.signer));
                continue;
            };

            let sig_bytes = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &sig.signature,
            ) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!(
                        "Signer '{}': base64 decode failed: {}",
                        sig.signer, e
                    ));
                    continue;
                }
            };

            let public_key =
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pub_key_bytes);

            match public_key.verify(&payload, &sig_bytes) {
                Ok(()) => {
                    valid_count += 1;
                    distinct_keys.insert(pub_key_bytes.clone());
                    if let Some(role) = sig.role {
                        valid_roles.insert(role);
                    }
                }
                Err(_) => {
                    errors.push(format!(
                        "Signer '{}': Ed25519 signature verification failed",
                        sig.signer
                    ));
                }
            }
        }

        // Check role requirements
        if !self.required_roles.is_empty() {
            let missing: Vec<_> = self
                .required_roles
                .iter()
                .filter(|r| !valid_roles.contains(r))
                .collect();
            if !missing.is_empty() {
                errors.push(format!("Missing required role signatures: {:?}", missing));
                return Err(errors);
            }

            // Distinct key check: a single key registered under multiple signer
            // names must not satisfy multiple required roles. The number of
            // distinct public keys must be >= the number of required roles.
            if distinct_keys.len() < self.required_roles.len() {
                errors.push(format!(
                    "Role separation violation: {} required roles but only {} distinct \
                     signing keys used. Each role must be signed by a different key.",
                    self.required_roles.len(),
                    distinct_keys.len()
                ));
                return Err(errors);
            }
        }

        if valid_count > 0 {
            Ok(())
        } else {
            errors.push("No valid signatures from trusted signers".into());
            Err(errors)
        }
    }
}

/// Pinned toolchain information for reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainInfo {
    pub container_digest: Option<String>,
    pub rustc_version: String,
    pub kani_version: Option<String>,
    pub kernel_version: String,
}

/// All verification reports attached to a witness bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReports {
    pub build: Option<ReportSummary>,
    pub tests: Option<ReportSummary>,
    pub kani: Option<ReportSummary>,
    pub policy_diff: Option<PolicyDiffReport>,
    pub replay: Option<ReportSummary>,
    pub adversarial: Option<ReportSummary>,
    pub termination: Option<ReportSummary>,
    /// Sandbox execution record — proves verification ran in confinement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxRecord>,
    /// Content-addressed references to full report artifacts.
    pub artifact_digests: BTreeMap<String, ArtifactDigest>,
}

/// Record of sandboxed execution for a verification run.
///
/// Proves that candidate verification ran inside an enforced sandbox
/// (Docker/Colima/Firecracker). Required by moonshot spec §11.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRecord {
    /// Digest of the container image used for verification.
    pub container_digest: Option<String>,
    /// BLAKE3 hash of the sandbox policy applied.
    pub policy_hash: Option<String>,
    /// Exit code of the sandboxed process.
    pub exit_code: i32,
    /// Peak memory usage in bytes.
    pub peak_memory_bytes: Option<u64>,
    /// Wall clock duration in milliseconds.
    pub wall_time_ms: u64,
    /// Whether the sandbox enforced network isolation.
    pub network_isolated: bool,
    /// BLAKE3 digest of the PolicyManifest enforced by the sandbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced_manifest_digest: Option<String>,
    /// Observed outbound network calls during sandbox execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_network_calls: Option<Vec<String>>,
    /// Observed filesystem writes during sandbox execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_fs_writes: Option<Vec<String>>,
    /// Violations detected: manifest constraint breaches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_violations: Option<Vec<String>>,
}

/// Summary of a verification report (pass/fail + details).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub passed: bool,
    pub summary: String,
    /// Full report stored externally, referenced by digest.
    pub artifact_digest: Option<ArtifactDigest>,
}

/// Result of comparing parent and candidate policy manifests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiffReport {
    pub capability_escalations: Vec<String>,
    pub io_escalations: Vec<String>,
    pub budget_escalations: Vec<String>,
    pub proof_requirement_drops: Vec<String>,
    pub violated_invariants: Vec<ConstitutionalInvariant>,
}

impl PolicyDiffReport {
    /// True if no constitutional invariants were violated.
    pub fn is_clean(&self) -> bool {
        self.violated_invariants.is_empty()
    }
}

/// Role of a witness bundle signer.
///
/// The moonshot spec requires 4 distinct signer roles to ensure no single
/// component can forge a complete witness. Each role signs at a different
/// pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    /// Signs after build verification passes.
    Build,
    /// Signs after formal proof (Kani) obligations are met.
    Proof,
    /// Signs after independent replay verification succeeds.
    Replay,
    /// Signs at kernel admission time — the final gate.
    Admission,
}

/// Cryptographic signature on the witness bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSignature {
    pub signer: String,
    pub algorithm: String,
    pub signature: String,
    /// The role this signature fulfills in the evidence pipeline.
    /// Legacy bundles may have `None` (pre-multi-role era).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<SignerRole>,
}

/// How an artifact entered the constitutional lineage.
///
/// The dual-DAG model (spec §10) distinguishes git ancestry from
/// constitutional ancestry. Each admission mode documents how and why
/// a node was added to the constitutional DAG.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionMode {
    /// Initial bootstrap — trusted by construction.
    Genesis,
    /// Ordinary self-amendment: passed kernel checks on the ordinary path.
    /// This is the normal admission mode for agent-generated patches.
    #[default]
    #[serde(alias = "admitted")]
    OrdinarySelfAmendment,
    /// External commit adopted as trusted base — weaker evidence.
    /// Used when `main` advances out-of-band.
    Imported,
    /// Constitutional amendment: changes to TCB files, requires human signatures.
    /// The kernel itself cannot issue this mode on the ordinary path.
    ConstitutionalAmendment,
    /// Human-signed bypass — external authority override.
    HumanOverride,
}

/// A record in the lineage store.
///
/// In the dual-DAG model, `parent_digest` tracks the constitutional parent
/// (latest admitted node), while `git_commit_sha` tracks git ancestry.
/// These may diverge when out-of-band commits advance `main`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageRecord {
    pub sequence: u64,
    /// The constitutional parent (latest admitted node at time of admission).
    pub parent_digest: ArtifactDigest,
    pub candidate_digest: ArtifactDigest,
    pub witness_digest: ArtifactDigest,
    pub patch_class: PatchClass,
    pub timestamp_utc: DateTime<Utc>,
    pub admitted: bool,
    #[serde(default)]
    pub admission_mode: AdmissionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit_sha: Option<String>,
}

/// A cryptographic signature from a human authority (spec §14).
///
/// Used in `admit_constitutional()` to verify that constitutional amendments
/// (Controller patches) have explicit human approval meeting the threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanSignature {
    /// Identity of the human signer (e.g., "admin@example.com").
    pub identity: String,
    /// Ed25519 signature over the witness bundle's signing payload.
    pub signature: Vec<u8>,
    /// Timestamp when the signature was produced.
    pub signed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::manifest::*;

    fn test_manifest() -> PolicyManifest {
        PolicyManifest {
            version: 1,
            capabilities: CapabilitySet {
                filesystem_read: ["/workspace".into()].into(),
                filesystem_write: ["/workspace".into()].into(),
                network_allow: BTreeSet::new(),
                tools_allow: ["builder".into()].into(),
                secret_classes: BTreeSet::new(),
                max_parallel_tasks: 2,
            },
            io_surface: IoSurface {
                outbound_domains: BTreeSet::new(),
                local_file_roots: ["/workspace".into()].into(),
                env_vars_readable: BTreeSet::new(),
                tool_namespaces: BTreeSet::new(),
                repo_write_targets: BTreeSet::new(),
            },
            budget_bounds: BudgetBounds {
                max_tokens: 100_000,
                max_wall_ms: 600_000,
                max_cpu_ms: 300_000,
                max_memory_bytes: 2_000_000_000,
                max_network_calls: 50,
                max_files_touched: 20,
                max_dollar_spend_millicents: 100_000,
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
        }
    }

    fn test_bundle() -> WitnessBundle {
        let manifest = test_manifest();
        WitnessBundle {
            bundle_version: 1,
            parent_digest: ArtifactDigest::from_bytes(b"parent"),
            candidate_digest: ArtifactDigest::from_bytes(b"candidate"),
            patch_digest: ArtifactDigest::from_bytes(b"patch"),
            patch_class: PatchClass::Controller,
            timestamp_utc: Utc::now(),
            toolchain: ToolchainInfo {
                container_digest: None,
                rustc_version: "1.85.0".into(),
                kani_version: Some("0.50.0".into()),
                kernel_version: "0.1.0".into(),
            },
            policy_before: manifest.clone(),
            policy_after: manifest,
            reports: VerificationReports {
                build: Some(ReportSummary {
                    passed: true,
                    summary: "Build succeeded".into(),
                    artifact_digest: None,
                }),
                tests: None,
                kani: None,
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
                signature: "deadbeef".into(),
                role: None,
            }],
            source_tree_digest: None,
            build_container_digest: None,
            manifest_digest_before: None,
            manifest_digest_after: None,
        }
    }

    #[test]
    fn test_bundle_digest_deterministic() {
        let b = test_bundle();
        let d1 = b.digest();
        let d2 = b.digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_bundle_structurally_complete() {
        let b = test_bundle();
        assert!(b.is_structurally_complete().is_ok());
    }

    #[test]
    fn test_bundle_missing_signature() {
        let mut b = test_bundle();
        b.signatures.clear();
        let err = b.is_structurally_complete().unwrap_err();
        assert!(err.iter().any(|e| e.contains("signature")));
    }

    #[test]
    fn test_bundle_zero_version() {
        let mut b = test_bundle();
        b.bundle_version = 0;
        let err = b.is_structurally_complete().unwrap_err();
        assert!(err.iter().any(|e| e.contains("version")));
    }

    #[test]
    fn test_policy_diff_clean() {
        let diff = PolicyDiffReport {
            capability_escalations: vec![],
            io_escalations: vec![],
            budget_escalations: vec![],
            proof_requirement_drops: vec![],
            violated_invariants: vec![],
        };
        assert!(diff.is_clean());
    }

    #[test]
    fn test_policy_diff_violation() {
        let diff = PolicyDiffReport {
            capability_escalations: vec!["network: +evil.com".into()],
            io_escalations: vec![],
            budget_escalations: vec![],
            proof_requirement_drops: vec![],
            violated_invariants: vec![ConstitutionalInvariant::CapabilityNonEscalation],
        };
        assert!(!diff.is_clean());
    }

    fn sign_bundle(
        bundle: &WitnessBundle,
        key_pair: &ring::signature::Ed25519KeyPair,
    ) -> BundleSignature {
        sign_bundle_with_role(bundle, key_pair, "test-ci", None)
    }

    fn sign_bundle_with_role(
        bundle: &WitnessBundle,
        key_pair: &ring::signature::Ed25519KeyPair,
        signer_name: &str,
        role: Option<SignerRole>,
    ) -> BundleSignature {
        use base64::Engine;
        let payload = bundle.signing_payload();
        let sig = key_pair.sign(&payload);
        BundleSignature {
            signer: signer_name.into(),
            algorithm: "ed25519".into(),
            signature: base64::engine::general_purpose::STANDARD.encode(sig.as_ref()),
            role,
        }
    }

    fn test_keypair() -> (ring::signature::Ed25519KeyPair, Vec<u8>) {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let seed = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(seed.as_ref()).unwrap();
        let pub_key = key_pair.public_key().as_ref().to_vec();
        (key_pair, pub_key)
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (key_pair, pub_key) = test_keypair();
        let mut bundle = test_bundle();
        bundle.signatures = vec![sign_bundle(&bundle, &key_pair)];

        let verifier = SignatureVerifier::new(vec![("test-ci".into(), pub_key)]);
        assert!(verifier.verify(&bundle).is_ok());
    }

    #[test]
    fn test_reject_tampered_bundle() {
        let (key_pair, pub_key) = test_keypair();
        let mut bundle = test_bundle();
        bundle.signatures = vec![sign_bundle(&bundle, &key_pair)];

        // Tamper with the bundle after signing
        bundle.bundle_version = 999;

        let verifier = SignatureVerifier::new(vec![("test-ci".into(), pub_key)]);
        assert!(verifier.verify(&bundle).is_err());
    }

    #[test]
    fn test_reject_wrong_key() {
        let (key_pair, _pub_key) = test_keypair();
        let (_other_pair, other_pub_key) = test_keypair();

        let mut bundle = test_bundle();
        bundle.signatures = vec![sign_bundle(&bundle, &key_pair)];

        // Verify with a different key
        let verifier = SignatureVerifier::new(vec![("test-ci".into(), other_pub_key)]);
        assert!(verifier.verify(&bundle).is_err());
    }

    #[test]
    fn test_reject_unsigned_algorithm_none() {
        let bundle = test_bundle(); // has algorithm: "ed25519" in test fixture
        let mut unsigned = bundle;
        unsigned.signatures = vec![BundleSignature {
            signer: "test".into(),
            algorithm: "none".into(),
            signature: "unsigned".into(),
            role: None,
        }];

        let (_, pub_key) = test_keypair();
        let verifier = SignatureVerifier::new(vec![("test".into(), pub_key)]);
        assert!(verifier.verify(&unsigned).is_err());
    }

    #[test]
    fn test_empty_trusted_keys_rejects_fail_closed() {
        let bundle = test_bundle();
        let verifier = SignatureVerifier::new(vec![]);
        let result = verifier.verify(&bundle);
        assert!(result.is_err(), "Empty keys must reject (fail-closed)");
        assert!(result.unwrap_err()[0].contains("No trusted keys"));
    }

    #[test]
    fn test_signing_payload_deterministic() {
        let bundle = test_bundle();
        let p1 = bundle.signing_payload();
        let p2 = bundle.signing_payload();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_signing_payload_excludes_signatures() {
        let mut bundle = test_bundle();
        let payload_with_sigs = bundle.signing_payload();
        bundle.signatures = vec![BundleSignature {
            signer: "extra".into(),
            algorithm: "ed25519".into(),
            signature: "deadbeef".into(),
            role: None,
        }];
        let payload_different_sigs = bundle.signing_payload();
        // Payload should be identical regardless of signatures content
        assert_eq!(payload_with_sigs, payload_different_sigs);
    }

    #[test]
    fn test_role_based_verification_requires_all_roles() {
        let (build_kp, build_pk) = test_keypair();
        let (admission_kp, admission_pk) = test_keypair();

        let mut bundle = test_bundle();
        bundle.signatures = vec![
            sign_bundle_with_role(
                &bundle,
                &build_kp,
                "build-verifier",
                Some(SignerRole::Build),
            ),
            sign_bundle_with_role(
                &bundle,
                &admission_kp,
                "admission-verifier",
                Some(SignerRole::Admission),
            ),
        ];

        let verifier = SignatureVerifier::with_required_roles(
            vec![
                ("build-verifier".into(), build_pk),
                ("admission-verifier".into(), admission_pk),
            ],
            vec![SignerRole::Build, SignerRole::Admission],
        );
        assert!(verifier.verify(&bundle).is_ok());
    }

    #[test]
    fn test_role_based_verification_rejects_missing_role() {
        let (build_kp, build_pk) = test_keypair();
        let (_admission_kp, admission_pk) = test_keypair();

        let mut bundle = test_bundle();
        // Only sign with Build role — Admission role is missing
        bundle.signatures = vec![sign_bundle_with_role(
            &bundle,
            &build_kp,
            "build-verifier",
            Some(SignerRole::Build),
        )];

        let verifier = SignatureVerifier::with_required_roles(
            vec![
                ("build-verifier".into(), build_pk),
                ("admission-verifier".into(), admission_pk),
            ],
            vec![SignerRole::Build, SignerRole::Admission],
        );
        let err = verifier.verify(&bundle).unwrap_err();
        assert!(err.iter().any(|e| e.contains("Missing required role")));
    }
}
