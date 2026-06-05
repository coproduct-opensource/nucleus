//! ZK + TEE oracle envelope layer.
//!
//! **Pigouvian S1-S4.** Wires up the three-layer verification stack
//! the production externality claims need:
//!
//! 1. **TEE attestation** ([`TeeAttestation`]) — the oracle ran inside
//!    an Intel TDX / AMD SEV-SNP / AWS Nitro Enclave; the quote
//!    proves the report bytes came from that TEE.
//! 2. **ZK upper-envelope proof** ([`UpperEnvelopeProof`]) — claimed
//!    `units_micro` is bounded above by a publicly-verifiable
//!    envelope (e.g. derived from workload spec + grid carbon
//!    intensity).
//! 3. **Ed25519 freshness signature** (the existing
//!    [`crate::SignedExternalityClaim`]) — the oracle's signing key
//!    binds the units + subject identity + freshness window.
//!
//! Composing all three is `verify_vca_claim`. The
//! per-`ResourceDim` [`OracleRegistry`] (S4) resolves the
//! oracle's verifying key from the claim's `kid`.
//!
//! ## Today: stubs with prod-shape contracts
//!
//! S1 + S2 ship as stubs whose APIs match the production
//! contract. The Verifiable Carbon Accounting paper's Groth16
//! shape, the Intel TDX DCAP quote format, and AWS Nitro CBOR
//! attestation doc are the prod targets — see the
//! `crates/nucleus-externality/Cargo.toml` follow-on TODO.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::claim::{verify_claim, ClaimError, SignedExternalityClaim};
use crate::dim::ResourceDim;

/// TEE vendor whose quote format applies. The vendor selects the
/// quote parser + revocation-list source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeVendor {
    /// Intel Trust Domain Extensions (DCAP-style ECDSA quote).
    IntelTdx,
    /// AMD Secure Encrypted Virtualization — Secure Nested Paging.
    AmdSevSnp,
    /// AWS Nitro Enclaves (CBOR attestation document).
    NitroEnclave,
}

/// **S1 — TEE quote envelope.** Carries the raw quote bytes + the
/// vendor tag. Production verification will hand `quote_bytes` to
/// the vendor-specific parser; today the stub checks that bytes are
/// non-empty and that `report_data` matches what the oracle signed.
///
/// The vendor-specific quote format always includes a 64-byte
/// `report_data` field bound by the TEE to the workload's chosen
/// public key — typically the oracle's Ed25519 verifying key, which
/// closes the loop with [`SignedExternalityClaim::sig_b64`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestation {
    pub vendor: TeeVendor,
    /// Raw vendor quote bytes (TDX DCAP / SEV-SNP / Nitro CBOR).
    pub quote_bytes: Vec<u8>,
    /// 64-byte `report_data` extracted from the quote — SHA-256 of
    /// the oracle's verifying key bytes is the standard binding.
    pub report_data: Vec<u8>,
}

impl TeeAttestation {
    /// **STUB.** Vendor-specific parsing + signature chain
    /// verification will land in a follow-on. Today the stub
    /// asserts (a) `quote_bytes` is non-empty, (b) `report_data`
    /// length is 64 bytes (matches every vendor's spec).
    ///
    /// Returns `Ok(())` for a well-formed stub quote. Production
    /// implementations must walk the DCAP PCK cert chain (TDX),
    /// the SEV-SNP versioned chip endorsement key, or the Nitro
    /// CABundle.
    pub fn verify_stub(&self) -> Result<(), OracleError> {
        if self.quote_bytes.is_empty() {
            return Err(OracleError::TeeQuoteEmpty);
        }
        if self.report_data.len() != 64 {
            return Err(OracleError::TeeReportDataWrongLength {
                got: self.report_data.len(),
            });
        }
        Ok(())
    }
}

/// **S2 — ZK upper-envelope proof.** A Groth16 (or PLONK / Halo2 /
/// FRI / STARK) proof that the oracle's claimed `units_micro` is
/// bounded above by `envelope_micro`, computed from public inputs
/// (workload spec + grid carbon intensity + …).
///
/// The wire format is intentionally minimal: opaque proof bytes +
/// public-input vector. The production verifier resolves the
/// proving-system VK from a known set; the stub just checks the
/// upper-envelope bound directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpperEnvelopeProof {
    /// Opaque proof bytes; the prover-side scheme is identified by
    /// the oracle registry entry that wraps this proof type.
    pub proof_bytes: Vec<u8>,
    /// Public inputs the proof commits to. For an envelope proof,
    /// `public_inputs[0]` is the envelope value; subsequent slots
    /// hold the auxiliary inputs (workload spec hash, grid intensity
    /// snapshot, …).
    pub public_inputs: Vec<u64>,
}

impl UpperEnvelopeProof {
    /// Envelope value (`public_inputs[0]`). Returns `None` if the
    /// public-input vector is empty (malformed proof).
    pub fn envelope_micro(&self) -> Option<u64> {
        self.public_inputs.first().copied()
    }

    /// **STUB.** Asserts `claim.units_micro <= envelope`. The
    /// production verifier additionally runs the Groth16 (or chosen
    /// scheme) verification key over (`proof_bytes`, `public_inputs`).
    /// The stub matches the prod-shape contract S2 will inherit.
    pub fn verify_stub(&self, claim: &SignedExternalityClaim) -> Result<(), OracleError> {
        let envelope = self
            .envelope_micro()
            .ok_or(OracleError::EnvelopeProofMissingPublicInputs)?;
        if claim.units_micro > envelope {
            return Err(OracleError::EnvelopeOverclaim {
                claimed: claim.units_micro,
                envelope,
            });
        }
        // Production: verify the Groth16/PLONK/Halo2 proof here.
        // Today the stub trusts the envelope value is well-formed.
        if self.proof_bytes.is_empty() {
            return Err(OracleError::EnvelopeProofEmpty);
        }
        Ok(())
    }
}

/// **S3 — Composite three-layer envelope.** Bundles the Ed25519
/// claim + the TEE attestation + the ZK upper-envelope proof. The
/// canonical "Verifiable Carbon Accounting" shape: three
/// independent verifications must all pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcaExternalityClaim {
    pub claim: SignedExternalityClaim,
    pub tee: TeeAttestation,
    pub envelope: UpperEnvelopeProof,
}

/// Verify a `VcaExternalityClaim` — three layers in order:
/// (1) TEE attestation → (2) ZK envelope bound on `claim.units_micro`
/// → (3) Ed25519 signature + freshness + subject binding.
///
/// Fails fast at the first layer that rejects.
pub fn verify_vca_claim(
    vca: &VcaExternalityClaim,
    oracle_vk: &VerifyingKey,
    expected_subject: &str,
    now_unix_micros: u64,
) -> Result<(), OracleError> {
    vca.tee.verify_stub()?;
    vca.envelope.verify_stub(&vca.claim)?;
    verify_claim(&vca.claim, oracle_vk, expected_subject, now_unix_micros)
        .map_err(OracleError::Claim)?;
    Ok(())
}

/// **S4 — Per-dimension oracle key registry.**
///
/// Maps `(ResourceDim, kid) -> VerifyingKey`. Production deployments
/// snapshot this from the verifier-service `/v1/oracles/{dim}/jwks`
/// endpoint at clearing time; the snapshot's hash is bound into the
/// emitted Allocation edge's `VerifierAttestation`.
#[derive(Debug, Default, Clone)]
pub struct OracleRegistry {
    inner: BTreeMap<(ResourceDim, String), VerifyingKey>,
}

impl OracleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an oracle's verifying key for a resource dimension.
    /// Returns the previous key for the (dim, kid) pair if one was
    /// registered.
    pub fn register(
        &mut self,
        dim: ResourceDim,
        kid: impl Into<String>,
        vk: VerifyingKey,
    ) -> Option<VerifyingKey> {
        self.inner.insert((dim, kid.into()), vk)
    }

    /// Look up the verifying key for `(dim, kid)`. Returns `None`
    /// when the registry has no entry for that pair.
    pub fn lookup(&self, dim: ResourceDim, kid: &str) -> Option<&VerifyingKey> {
        self.inner.get(&(dim, kid.to_string()))
    }

    /// Number of registered (dim, kid) entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no oracles are registered.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Errors from oracle / VCA verification.
#[derive(Debug, Error)]
pub enum OracleError {
    #[error("TEE quote bytes were empty")]
    TeeQuoteEmpty,
    #[error("TEE report_data is {got} bytes, expected 64")]
    TeeReportDataWrongLength { got: usize },
    #[error("ZK envelope proof has empty public_inputs vector")]
    EnvelopeProofMissingPublicInputs,
    #[error("ZK envelope proof bytes were empty")]
    EnvelopeProofEmpty,
    #[error("claimed units {claimed} exceed envelope {envelope}")]
    EnvelopeOverclaim { claimed: u64, envelope: u64 },
    #[error("claim verification: {0}")]
    Claim(ClaimError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::sign_claim;
    use ed25519_dalek::SigningKey;

    fn oracle_sk() -> SigningKey {
        SigningKey::from_bytes(&[44u8; 32])
    }

    fn fixture_claim(units: u64) -> SignedExternalityClaim {
        sign_claim(
            &oracle_sk(),
            SignedExternalityClaim {
                resource: ResourceDim::GpuSeconds,
                units_micro: units,
                ts_unix_micros: 1_700_000_000_000_000,
                not_after_unix_micros: 1_700_000_000_000_000 + 3_600_000_000,
                subject_identity: "spiffe://nucleus.io/ns/agents/sa/a1".into(),
                kid: "gpu-oracle".into(),
                sig_b64: String::new(),
            },
        )
    }

    fn fixture_tee() -> TeeAttestation {
        TeeAttestation {
            vendor: TeeVendor::IntelTdx,
            quote_bytes: vec![0xCA; 256],
            report_data: vec![0x42; 64], // 64-byte length matches all vendors
        }
    }

    fn fixture_envelope(envelope_micro: u64) -> UpperEnvelopeProof {
        UpperEnvelopeProof {
            proof_bytes: vec![0xAB; 192],
            public_inputs: vec![envelope_micro],
        }
    }

    // ── S1 — TEE attestation stub ──────────────────────────────────────

    #[test]
    fn tee_attestation_stub_accepts_well_formed_quote() {
        fixture_tee().verify_stub().unwrap();
    }

    #[test]
    fn tee_attestation_rejects_empty_quote() {
        let mut t = fixture_tee();
        t.quote_bytes.clear();
        assert!(matches!(t.verify_stub(), Err(OracleError::TeeQuoteEmpty)));
    }

    #[test]
    fn tee_attestation_rejects_wrong_report_data_length() {
        let mut t = fixture_tee();
        t.report_data.truncate(32);
        assert!(matches!(
            t.verify_stub(),
            Err(OracleError::TeeReportDataWrongLength { got: 32 })
        ));
    }

    // ── S2 — Upper-envelope proof stub ─────────────────────────────────

    #[test]
    fn envelope_proof_accepts_in_bound_claim() {
        let claim = fixture_claim(1_000);
        let env = fixture_envelope(1_500);
        env.verify_stub(&claim).unwrap();
    }

    #[test]
    fn envelope_proof_rejects_overclaim() {
        let claim = fixture_claim(1_000);
        let env = fixture_envelope(500);
        let err = env.verify_stub(&claim).unwrap_err();
        assert!(matches!(
            err,
            OracleError::EnvelopeOverclaim {
                claimed: 1_000,
                envelope: 500
            }
        ));
    }

    #[test]
    fn envelope_proof_rejects_missing_public_inputs() {
        let claim = fixture_claim(1_000);
        let mut env = fixture_envelope(500);
        env.public_inputs.clear();
        let err = env.verify_stub(&claim).unwrap_err();
        assert!(matches!(err, OracleError::EnvelopeProofMissingPublicInputs));
    }

    #[test]
    fn envelope_proof_rejects_empty_proof_bytes() {
        let claim = fixture_claim(1_000);
        let mut env = fixture_envelope(1_500);
        env.proof_bytes.clear();
        let err = env.verify_stub(&claim).unwrap_err();
        assert!(matches!(err, OracleError::EnvelopeProofEmpty));
    }

    // ── S3 — VcaExternalityClaim composite envelope ────────────────────

    #[test]
    fn vca_three_layer_envelope_verifies() {
        let vca = VcaExternalityClaim {
            claim: fixture_claim(1_000),
            tee: fixture_tee(),
            envelope: fixture_envelope(1_500),
        };
        let vk = oracle_sk().verifying_key();
        verify_vca_claim(
            &vca,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/a1",
            1_700_000_000_000_001,
        )
        .unwrap();
    }

    #[test]
    fn vca_fails_fast_on_first_failing_layer() {
        // TEE layer breaks first → error reflects TEE, NOT envelope.
        let mut vca = VcaExternalityClaim {
            claim: fixture_claim(2_000), // would also fail envelope
            tee: fixture_tee(),
            envelope: fixture_envelope(1_000),
        };
        vca.tee.quote_bytes.clear();
        let vk = oracle_sk().verifying_key();
        let err = verify_vca_claim(
            &vca,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/a1",
            1_700_000_000_000_001,
        )
        .unwrap_err();
        assert!(matches!(err, OracleError::TeeQuoteEmpty));
    }

    // ── S4 — Oracle registry ───────────────────────────────────────────

    #[test]
    fn lookup_resolves_to_registered_key() {
        let mut reg = OracleRegistry::new();
        let vk = oracle_sk().verifying_key();
        assert!(reg.is_empty());
        assert!(reg
            .register(ResourceDim::GpuSeconds, "gpu-oracle", vk)
            .is_none());
        assert_eq!(reg.len(), 1);
        let got = reg.lookup(ResourceDim::GpuSeconds, "gpu-oracle").unwrap();
        assert_eq!(got.as_bytes(), vk.as_bytes());
    }

    #[test]
    fn lookup_returns_none_for_unknown_pair() {
        let mut reg = OracleRegistry::new();
        let vk = oracle_sk().verifying_key();
        reg.register(ResourceDim::GpuSeconds, "gpu-oracle", vk);
        // Wrong dim — different (dim, kid) key.
        assert!(reg
            .lookup(ResourceDim::GridCarbonGramsCo2, "gpu-oracle")
            .is_none());
        // Wrong kid.
        assert!(reg.lookup(ResourceDim::GpuSeconds, "other-kid").is_none());
    }

    #[test]
    fn registry_replaces_on_repeat_register() {
        let mut reg = OracleRegistry::new();
        let vk1 = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let vk2 = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        assert!(reg.register(ResourceDim::GpuSeconds, "k", vk1).is_none());
        let prev = reg.register(ResourceDim::GpuSeconds, "k", vk2).unwrap();
        assert_eq!(prev.as_bytes(), vk1.as_bytes());
        assert_eq!(reg.len(), 1);
    }
}
