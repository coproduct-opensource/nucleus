//! Manifest-amendment gate (most-paranoid #5).
//!
//! The pure, I/O-free decision used by the in-repo constitutional CI gate
//! (`cargo xtask policy-gate`) and by any runtime policy loader. It routes a
//! base→candidate [`PolicyManifest`] pair through the kernel's `admit` path so a
//! non-monotone or `may_not_modify`-violating amendment is REJECTED — closing
//! the audit gap that ck-kernel, though proven, was never actually invoked.
//!
//! Two modes:
//! - [`GateMode::Preflight`]: zero-config monotonicity + `may_not_modify` +
//!   structural/report admission, with signatures explicitly skipped (synthesizes
//!   a passing-report witness). This is what gates ordinary PRs today.
//! - [`GateMode::Admit`]: the fail-closed full decision — an `Enforced` verifier
//!   plus a real signed witness. Used once trust-root key material exists.

use std::collections::BTreeMap;

use chrono::Utc;
use ck_types::witness::{BundleSignature, ReportSummary, ToolchainInfo, VerificationReports};
use ck_types::{
    AdmissionDecision, ArtifactDigest, PatchClass, PolicyManifest, SignatureVerifier, WitnessBundle,
};

use crate::{CandidateAmendment, Kernel};

/// How the gate decides admission.
pub enum GateMode {
    /// Monotonicity + structural admission with signatures skipped. The gate
    /// synthesizes a complete, passing-report witness so the constitutional
    /// invariants (capability/IO/budget/proof-req monotonicity, anti-coup,
    /// `may_not_modify`) are all exercised without any key material.
    Preflight,
    /// Fail-closed full admission: a real `Enforced` verifier and a signed
    /// witness bundle. Rejects unless the witness is signed by a trusted key.
    Admit {
        /// Trusted-key verifier (empty ⇒ rejects everything, fail-closed).
        verifier: SignatureVerifier,
        /// The signed witness bundle carrying `policy_before`/`policy_after`.
        witness: Box<WitnessBundle>,
    },
}

/// Result of [`gate_manifest_amendment`].
pub struct GateOutcome {
    /// The kernel's admission decision.
    pub decision: AdmissionDecision,
}

impl GateOutcome {
    /// Whether the amendment was accepted.
    pub fn accepted(&self) -> bool {
        matches!(self.decision, AdmissionDecision::Accepted { .. })
    }
}

/// Gate a `PolicyManifest` amendment through the constitutional kernel.
///
/// Returns the kernel's [`AdmissionDecision`]. `changed_files` is the list of
/// repository paths changed by the amendment (checked against the parent's
/// `may_not_modify` rules).
pub fn gate_manifest_amendment(
    parent: &PolicyManifest,
    candidate: &PolicyManifest,
    changed_files: &[String],
    mode: GateMode,
) -> GateOutcome {
    let parent_digest = parent.digest();
    let candidate_digest = candidate.digest();

    let (mut kernel, candidate_amendment) = match mode {
        GateMode::Preflight => {
            let witness = synth_witness(parent, candidate, &parent_digest, &candidate_digest);
            // Genesis = parent; Preflight deliberately skips signatures.
            let kernel = Kernel::new(parent_digest.clone()).with_skip_for_testing();
            let cand = CandidateAmendment {
                parent_digest,
                candidate_digest,
                patch_class: PatchClass::Config,
                witness,
            };
            (kernel, cand)
        }
        GateMode::Admit { verifier, witness } => {
            let patch_class = witness.patch_class;
            let kernel = Kernel::new(parent_digest.clone()).with_signature_verifier(verifier);
            let cand = CandidateAmendment {
                parent_digest,
                candidate_digest,
                patch_class,
                witness: *witness,
            };
            (kernel, cand)
        }
    };

    let decision = kernel.admit_with_files(candidate_amendment, changed_files);
    GateOutcome { decision }
}

/// Build a structurally-complete, passing-report witness for `Preflight`.
///
/// `PatchClass::Config` so no Kani report is required; `build`/`tests` reports
/// are present and passing (required by the kernel's report check). The
/// `signatures` are placeholder — Preflight runs under `SkipForTesting`, so they
/// are never verified.
fn synth_witness(
    parent: &PolicyManifest,
    candidate: &PolicyManifest,
    parent_digest: &ArtifactDigest,
    candidate_digest: &ArtifactDigest,
) -> WitnessBundle {
    let pass = |s: &str| {
        Some(ReportSummary {
            passed: true,
            summary: s.to_string(),
            artifact_digest: None,
        })
    };
    WitnessBundle {
        bundle_version: 1,
        parent_digest: parent_digest.clone(),
        candidate_digest: candidate_digest.clone(),
        patch_digest: candidate_digest.clone(),
        patch_class: PatchClass::Config,
        timestamp_utc: Utc::now(),
        toolchain: ToolchainInfo {
            container_digest: None,
            rustc_version: env!("CARGO_PKG_VERSION").to_string(),
            kani_version: None,
            kernel_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        policy_before: parent.clone(),
        policy_after: candidate.clone(),
        reports: VerificationReports {
            build: pass("preflight: not run (monotonicity gate)"),
            tests: pass("preflight: not run (monotonicity gate)"),
            kani: None,
            policy_diff: None,
            replay: None,
            adversarial: None,
            termination: None,
            sandbox: None,
            artifact_digests: BTreeMap::new(),
        },
        signatures: vec![BundleSignature {
            signer: "preflight".to_string(),
            algorithm: "none".to_string(),
            signature: String::new(),
            role: None,
        }],
        source_tree_digest: None,
        build_container_digest: None,
        manifest_digest_before: None,
        manifest_digest_after: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PolicyManifest {
        let toml = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../PolicyManifest.toml"
        ))
        .expect("read root PolicyManifest.toml");
        PolicyManifest::from_toml(&toml).expect("root PolicyManifest.toml parses")
    }

    #[test]
    fn identity_amendment_is_monotone_and_accepted() {
        let m = base();
        let out = gate_manifest_amendment(&m, &m, &[], GateMode::Preflight);
        assert!(
            out.accepted(),
            "identity must be accepted, got {:?}",
            out.decision
        );
    }

    #[test]
    fn capability_escalation_is_rejected() {
        let parent = base();
        let mut candidate = parent.clone();
        // Widen the network allow-list: a capability escalation.
        candidate
            .capabilities
            .network_allow
            .insert("evil.example.com".to_string());
        let out = gate_manifest_amendment(&parent, &candidate, &[], GateMode::Preflight);
        assert!(
            !out.accepted(),
            "capability escalation must be rejected, got {:?}",
            out.decision
        );
    }

    #[test]
    fn modifying_protected_file_is_rejected() {
        let m = base();
        // PolicyManifest.toml is in the root manifest's may_not_modify set.
        let out = gate_manifest_amendment(
            &m,
            &m,
            &["PolicyManifest.toml".to_string()],
            GateMode::Preflight,
        );
        assert!(
            !out.accepted(),
            "touching a may_not_modify path must be rejected, got {:?}",
            out.decision
        );
    }

    #[cfg(feature = "test-harness")]
    #[test]
    fn admit_mode_empty_verifier_rejects_fail_closed() {
        let m = base();
        let parent_digest = m.digest();
        let candidate_digest = m.digest();
        let witness = synth_witness(&m, &m, &parent_digest, &candidate_digest);
        let out = gate_manifest_amendment(
            &m,
            &m,
            &[],
            GateMode::Admit {
                verifier: SignatureVerifier::new(Vec::new()),
                witness: Box::new(witness),
            },
        );
        assert!(
            !out.accepted(),
            "Admit with no trusted keys must reject (fail-closed), got {:?}",
            out.decision
        );
    }

    #[cfg(feature = "test-harness")]
    #[test]
    fn admit_mode_signed_witness_is_accepted() {
        use crate::test_harness::TestKeyring;
        let m = base();
        let parent_digest = m.digest();
        let candidate_digest = m.digest();
        let mut witness = synth_witness(&m, &m, &parent_digest, &candidate_digest);
        let keyring = TestKeyring::new(&["kernel-ci"]);
        witness.signatures = keyring.sign_all(&witness);
        let out = gate_manifest_amendment(
            &m,
            &m,
            &[],
            GateMode::Admit {
                verifier: keyring.verifier(),
                witness: Box::new(witness),
            },
        );
        assert!(
            out.accepted(),
            "Admit with a signed witness must be accepted, got {:?}",
            out.decision
        );
    }
}
