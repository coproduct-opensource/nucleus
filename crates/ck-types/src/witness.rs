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
}

impl WitnessBundle {
    /// Compute a canonical BLAKE3 digest of this witness bundle.
    pub fn digest(&self) -> ArtifactDigest {
        let canonical = serde_json::to_vec(self).expect("WitnessBundle is always serializable");
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
}

impl SignatureVerifier {
    /// Create a verifier with the given trusted public keys.
    pub fn new(trusted_keys: Vec<(String, Vec<u8>)>) -> Self {
        Self { trusted_keys }
    }

    /// Verify that the bundle has at least one valid Ed25519 signature
    /// from a trusted signer.
    pub fn verify(&self, bundle: &WitnessBundle) -> Result<(), Vec<String>> {
        if self.trusted_keys.is_empty() {
            return Ok(()); // no trusted keys configured = skip verification
        }

        let payload = bundle.signing_payload();
        let mut errors = Vec::new();
        let mut valid_count = 0;

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
                Ok(()) => valid_count += 1,
                Err(_) => {
                    errors.push(format!(
                        "Signer '{}': Ed25519 signature verification failed",
                        sig.signer
                    ));
                }
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
    /// Content-addressed references to full report artifacts.
    pub artifact_digests: BTreeMap<String, ArtifactDigest>,
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

/// Cryptographic signature on the witness bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSignature {
    pub signer: String,
    pub algorithm: String,
    pub signature: String,
}

/// A record in the lineage store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageRecord {
    pub sequence: u64,
    pub parent_digest: ArtifactDigest,
    pub candidate_digest: ArtifactDigest,
    pub witness_digest: ArtifactDigest,
    pub patch_class: PatchClass,
    pub timestamp_utc: DateTime<Utc>,
    pub admitted: bool,
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
                artifact_digests: BTreeMap::new(),
            },
            signatures: vec![BundleSignature {
                signer: "kernel-ci".into(),
                algorithm: "ed25519".into(),
                signature: "deadbeef".into(),
            }],
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
        use base64::Engine;
        let payload = bundle.signing_payload();
        let sig = key_pair.sign(&payload);
        BundleSignature {
            signer: "test-ci".into(),
            algorithm: "ed25519".into(),
            signature: base64::engine::general_purpose::STANDARD.encode(sig.as_ref()),
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
        }];

        let (_, pub_key) = test_keypair();
        let verifier = SignatureVerifier::new(vec![("test".into(), pub_key)]);
        assert!(verifier.verify(&unsigned).is_err());
    }

    #[test]
    fn test_empty_trusted_keys_skips_verification() {
        let bundle = test_bundle();
        let verifier = SignatureVerifier::new(vec![]);
        assert!(verifier.verify(&bundle).is_ok());
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
        }];
        let payload_different_sigs = bundle.signing_payload();
        // Payload should be identical regardless of signatures content
        assert_eq!(payload_with_sigs, payload_different_sigs);
    }
}
