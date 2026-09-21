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

use crate::assurance::{AssuranceRung, assess_rung};
use crate::claim::{ClaimError, SignedExternalityClaim, verify_claim};
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

/// Sealing token. Private, so every witness below has a private constructor
/// (ADR 0007 C-1) and can be minted only inside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seal;

/// Traits whose implementations must live in this crate. The witness a verifier
/// returns is THIS crate's claim about what was checked, so this crate decides
/// what may make one. A downstream verifier arrives by landing here, not by
/// implementing an open trait and minting its own evidence.
mod sealed {
    pub trait Sealed {}
}

/// Evidence that the claim's Ed25519 signature verified — fresh, and bound to
/// the expected subject and resource. Minted only by [`verify_claim_witnessed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureVerified {
    _seal: Seal,
}

/// Evidence that a TEE quote was verified against a vendor trust chain.
///
/// NOT obtainable from a shape check: [`QuoteWellFormed`] is a different type,
/// and `assess_rung` takes this one. That is the whole repair — the two were
/// the same `bool` on 2026-09-21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeeAttested {
    _seal: Seal,
}

/// Evidence that a quote is STRUCTURALLY well formed: non-empty, and
/// `report_data` the 64 bytes every vendor specifies. It establishes nothing
/// about provenance, which is why it cannot reach a rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteWellFormed {
    _seal: Seal,
}

/// Evidence that a zk upper-envelope proof was verified against a verification
/// key AND bounds the claim's `units_micro`.
///
/// Not obtainable from [`EnvelopeSelfDeclared`], which is what checking a claim
/// against its own `public_inputs[0]` establishes: the prover chose that number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeBounded {
    _seal: Seal,
}

/// Evidence that `units_micro` is within the bound the PROVER supplied. A
/// consistency check on the proof's own public inputs, and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeSelfDeclared {
    _seal: Seal,
}

/// Evidence of a multi-source dispute window that elapsed unchallenged.
/// Supplied by the aggregation layer, never by a single claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disputed {
    _seal: Seal,
}

impl Disputed {
    /// Minted by the aggregation layer once its window has elapsed. Takes the
    /// count of independent corroborating sources so the constructor cannot be
    /// called on no evidence at all.
    ///
    /// # Errors
    ///
    /// [`OracleError::DisputeNeedsTwoSources`] below two sources.
    pub fn from_elapsed_window(independent_sources: usize) -> Result<Self, OracleError> {
        if independent_sources < 2 {
            return Err(OracleError::DisputeNeedsTwoSources {
                got: independent_sources,
            });
        }
        Ok(Self { _seal: Seal })
    }
}

/// Test-only mints. `#[cfg(test)]`, so they do not ship: the production path
/// has exactly one route to each witness, which is the checker for its layer.
/// Without these the crate could not test `assess_rung` at all, and a rung
/// table nobody exercises is the vacuity this change exists to remove.
#[cfg(test)]
impl SignatureVerified {
    pub(crate) fn for_test() -> Self {
        Self { _seal: Seal }
    }
}

#[cfg(test)]
impl TeeAttested {
    pub(crate) fn for_test() -> Self {
        Self { _seal: Seal }
    }
}

#[cfg(test)]
impl EnvelopeBounded {
    pub(crate) fn for_test() -> Self {
        Self { _seal: Seal }
    }
}

#[cfg(test)]
impl Disputed {
    pub(crate) fn for_test() -> Self {
        Self { _seal: Seal }
    }
}

/// A verifier for vendor TEE quotes.
///
/// **There is no implementation in this crate, and that is the point.** The
/// stub it replaces returned `Ok` for any non-empty byte string and fed the
/// assurance rung; a fail-closed trait with no default means a caller must
/// name a real verifier, and until one exists `verify_vca_claim` cannot be
/// called at all (#2504).
pub trait TeeQuoteVerifier: sealed::Sealed {
    /// Verify `att` and mint the attestation witness.
    ///
    /// Named `verify_quote` rather than `verify` so neither a reader nor
    /// `scripts/check-verify-strict.sh` can mistake it for a dalek leaf call.
    /// That gate watches every file mentioning `ed25519_dalek` for a
    /// two-argument `.verify(`, and it was right to flag the first draft of
    /// this trait.
    ///
    /// # Errors
    ///
    /// Whatever the vendor chain check rejects.
    fn verify_quote(&self, att: &TeeAttestation) -> Result<TeeAttested, OracleError>;
}

/// A verifier for zk upper-envelope proofs. Same shape, same reason (#2505),
/// and the sharper of the two: the bound the stub compared against was chosen
/// by the prover.
pub trait EnvelopeVerifier: sealed::Sealed {
    /// Verify `proof` against its verification key and bound `claim`.
    ///
    /// Two arguments, so the name matters for the same reason as
    /// `verify_quote`: a bare two-argument `.verify(` in this file reads
    /// exactly like the dalek call the strict-verify gate forbids.
    ///
    /// # Errors
    ///
    /// Whatever the proving-system check rejects.
    fn verify_envelope(
        &self,
        proof: &UpperEnvelopeProof,
        claim: &SignedExternalityClaim,
    ) -> Result<EnvelopeBounded, OracleError>;
}

impl TeeAttestation {
    /// A STRUCTURAL check: `quote_bytes` non-empty, and `report_data` the 64
    /// bytes every vendor specifies. It establishes nothing about provenance.
    ///
    /// Deliberately NOT a [`TeeQuoteVerifier`], and it returns
    /// [`QuoteWellFormed`] rather than [`TeeAttested`], so it cannot be passed
    /// where an attestation is wanted. Under its old name `verify_stub` it was
    /// called unconditionally by `verify_vca_claim` and its `Ok` became
    /// `tee_ok = true`: a one-byte quote reached rung R2 and, beside the
    /// envelope stub, R4. Real verification walks the DCAP PCK chain (TDX), the
    /// SEV-SNP versioned chip endorsement key, or the Nitro CABundle.
    ///
    /// # Errors
    ///
    /// [`OracleError::TeeQuoteEmpty`] or
    /// [`OracleError::TeeReportDataWrongLength`].
    pub fn check_shape(&self) -> Result<QuoteWellFormed, OracleError> {
        if self.quote_bytes.is_empty() {
            return Err(OracleError::TeeQuoteEmpty);
        }
        if self.report_data.len() != 64 {
            return Err(OracleError::TeeReportDataWrongLength {
                got: self.report_data.len(),
            });
        }
        Ok(QuoteWellFormed { _seal: Seal })
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

    /// Asserts `claim.units_micro <= envelope` — where `envelope` is
    /// `public_inputs[0]`, **which the prover supplied**. So this compares the
    /// claim against a number the claimant chose, and `proof_bytes` is never
    /// checked against anything.
    ///
    /// It returns [`EnvelopeSelfDeclared`] for that reason, not
    /// [`EnvelopeBounded`], and cannot reach a rung. Under its old name
    /// `verify_stub` a one-byte proof declaring `u64::MAX` passed it and
    /// `assess_rung` read the `Ok` as `zk_envelope_ok = true`. The real
    /// verifier runs the proving system's verification key over
    /// (`proof_bytes`, `public_inputs`).
    ///
    /// # Errors
    ///
    /// [`OracleError::EnvelopeProofMissingPublicInputs`],
    /// [`OracleError::EnvelopeOverclaim`] or
    /// [`OracleError::EnvelopeProofEmpty`].
    pub fn check_self_declared_bound(
        &self,
        claim: &SignedExternalityClaim,
    ) -> Result<EnvelopeSelfDeclared, OracleError> {
        let envelope = self
            .envelope_micro()
            .ok_or(OracleError::EnvelopeProofMissingPublicInputs)?;
        if claim.units_micro > envelope {
            return Err(OracleError::EnvelopeOverclaim {
                claimed: claim.units_micro,
                envelope,
            });
        }
        if self.proof_bytes.is_empty() {
            return Err(OracleError::EnvelopeProofEmpty);
        }
        Ok(EnvelopeSelfDeclared { _seal: Seal })
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

/// Verify the claim's signature and mint the [`SignatureVerified`] witness.
///
/// The only way to obtain that witness, which is what makes it evidence
/// rather than a parameter (ADR 0007 C-2).
///
/// # Errors
///
/// [`OracleError::Claim`] if the signature, freshness or subject binding fails.
pub fn verify_claim_witnessed(
    claim: &SignedExternalityClaim,
    oracle_vk: &VerifyingKey,
    expected_subject: &str,
    now_unix_micros: u64,
) -> Result<SignatureVerified, OracleError> {
    verify_claim(claim, oracle_vk, expected_subject, now_unix_micros)
        .map_err(OracleError::Claim)?;
    Ok(SignatureVerified { _seal: Seal })
}

/// Verify a `VcaExternalityClaim` — three layers, and return the witness each
/// one minted.
///
/// The verifiers are PARAMETERS because there is no default: a caller must name
/// what checks a vendor quote and what checks a proof. Before #2504/#2505 both
/// were stubs called unconditionally, so every caller got the strongest rung
/// for free.
///
/// Fails fast at the first layer that rejects.
///
/// # Errors
///
/// Whichever layer rejects first: the TEE verifier, the envelope verifier, or
/// [`OracleError::Claim`] for the signature.
pub fn verify_vca_claim<T, E>(
    vca: &VcaExternalityClaim,
    oracle_vk: &VerifyingKey,
    expected_subject: &str,
    now_unix_micros: u64,
    tee_verifier: &T,
    envelope_verifier: &E,
) -> Result<(SignatureVerified, TeeAttested, EnvelopeBounded), OracleError>
where
    T: TeeQuoteVerifier,
    E: EnvelopeVerifier,
{
    let tee = tee_verifier.verify_quote(&vca.tee)?;
    let envelope = envelope_verifier.verify_envelope(&vca.envelope, &vca.claim)?;
    let signature =
        verify_claim_witnessed(&vca.claim, oracle_vk, expected_subject, now_unix_micros)?;
    Ok((signature, tee, envelope))
}

/// Verify a `VcaExternalityClaim` AND report the [`AssuranceRung`] it achieved.
///
/// The rung is derived from the witnesses the layers minted, so R4 is
/// unreachable without a real envelope verifier and R2 without a real quote
/// verifier. The line this replaces read
/// `assess_rung(/* signature_ok */ true, /* tee_ok */ true, …)` — four
/// constants, and two of them stood for shape checks.
///
/// Multi-source dispute (R3) stays `None`: it is a property of an aggregation
/// over several claims, and a single claim cannot witness it.
///
/// # Errors
///
/// As [`verify_vca_claim`]. A failing layer returns the error rather than a
/// rung, so an unverified claim never reports one.
pub fn verify_vca_claim_rung<T, E>(
    vca: &VcaExternalityClaim,
    oracle_vk: &VerifyingKey,
    expected_subject: &str,
    now_unix_micros: u64,
    tee_verifier: &T,
    envelope_verifier: &E,
) -> Result<AssuranceRung, OracleError>
where
    T: TeeQuoteVerifier,
    E: EnvelopeVerifier,
{
    let (signature, tee, envelope) = verify_vca_claim(
        vca,
        oracle_vk,
        expected_subject,
        now_unix_micros,
        tee_verifier,
        envelope_verifier,
    )?;
    Ok(assess_rung(&signature, Some(&tee), None, Some(&envelope)))
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
    /// A dispute window with fewer than two independent sources corroborates
    /// nothing; `Disputed` refuses rather than witnessing a majority of one.
    #[error("multi-source dispute needs >= 2 independent sources, got {got}")]
    DisputeNeedsTwoSources { got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::sign_claim;
    use ed25519_dalek::SigningKey;

    /// Stands in for a real vendor-chain verifier. Exists only under
    /// `cfg(test)`: PRODUCTION SHIPS NO IMPLEMENTATION, which is the
    /// fail-closed property #2504 asked for. A caller in production cannot
    /// call `verify_vca_claim` until someone writes a real one.
    struct AcceptingTee;
    impl super::sealed::Sealed for AcceptingTee {}
    impl TeeQuoteVerifier for AcceptingTee {
        fn verify_quote(&self, _att: &TeeAttestation) -> Result<TeeAttested, OracleError> {
            Ok(TeeAttested::for_test())
        }
    }

    /// The same for the envelope layer (#2505).
    struct AcceptingEnvelope;
    impl super::sealed::Sealed for AcceptingEnvelope {}
    impl EnvelopeVerifier for AcceptingEnvelope {
        fn verify_envelope(
            &self,
            _proof: &UpperEnvelopeProof,
            _claim: &SignedExternalityClaim,
        ) -> Result<EnvelopeBounded, OracleError> {
            Ok(EnvelopeBounded::for_test())
        }
    }

    /// The same for the envelope layer, so a rejection there is reachable too.
    struct RefusingEnvelope;
    impl super::sealed::Sealed for RefusingEnvelope {}
    impl EnvelopeVerifier for RefusingEnvelope {
        fn verify_envelope(
            &self,
            _proof: &UpperEnvelopeProof,
            _claim: &SignedExternalityClaim,
        ) -> Result<EnvelopeBounded, OracleError> {
            Err(OracleError::EnvelopeProofEmpty)
        }
    }

    /// A verifier that refuses, so a rejection at the TEE layer is reachable
    /// in a test and the accepting pair above is not the only shape exercised.
    struct RefusingTee;
    impl super::sealed::Sealed for RefusingTee {}
    impl TeeQuoteVerifier for RefusingTee {
        fn verify_quote(&self, _att: &TeeAttestation) -> Result<TeeAttested, OracleError> {
            Err(OracleError::TeeQuoteEmpty)
        }
    }

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
        fixture_tee().check_shape().unwrap();
    }

    #[test]
    fn tee_attestation_rejects_empty_quote() {
        let mut t = fixture_tee();
        t.quote_bytes.clear();
        assert!(matches!(t.check_shape(), Err(OracleError::TeeQuoteEmpty)));
    }

    #[test]
    fn tee_attestation_rejects_wrong_report_data_length() {
        let mut t = fixture_tee();
        t.report_data.truncate(32);
        assert!(matches!(
            t.check_shape(),
            Err(OracleError::TeeReportDataWrongLength { got: 32 })
        ));
    }

    // ── S2 — Upper-envelope proof stub ─────────────────────────────────

    #[test]
    fn envelope_proof_accepts_in_bound_claim() {
        let claim = fixture_claim(1_000);
        let env = fixture_envelope(1_500);
        env.check_self_declared_bound(&claim).unwrap();
    }

    #[test]
    fn envelope_proof_rejects_overclaim() {
        let claim = fixture_claim(1_000);
        let env = fixture_envelope(500);
        let err = env.check_self_declared_bound(&claim).unwrap_err();
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
        let err = env.check_self_declared_bound(&claim).unwrap_err();
        assert!(matches!(err, OracleError::EnvelopeProofMissingPublicInputs));
    }

    #[test]
    fn envelope_proof_rejects_empty_proof_bytes() {
        let claim = fixture_claim(1_000);
        let mut env = fixture_envelope(1_500);
        env.proof_bytes.clear();
        let err = env.check_self_declared_bound(&claim).unwrap_err();
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
            &AcceptingTee,
            &AcceptingEnvelope,
        )
        .unwrap();
    }

    #[test]
    fn full_vca_derives_rung_r4() {
        let vca = VcaExternalityClaim {
            claim: fixture_claim(1_000),
            tee: fixture_tee(),
            envelope: fixture_envelope(1_500),
        };
        let vk = oracle_sk().verifying_key();
        let rung = verify_vca_claim_rung(
            &vca,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/a1",
            1_700_000_000_000_001,
            &AcceptingTee,
            &AcceptingEnvelope,
        )
        .unwrap();
        assert_eq!(rung, AssuranceRung::ZkUpperEnvelope);
    }

    /// A refused layer yields an ERROR, never a rung. Driven by a refusing
    /// verifier rather than by an over-claim, because the over-claim check is
    /// now `check_self_declared_bound` — a shape check that mints no witness
    /// and so cannot be what decides a rung.
    #[test]
    fn rung_not_reported_for_failed_verification() {
        let vca = VcaExternalityClaim {
            claim: fixture_claim(1_000),
            tee: fixture_tee(),
            envelope: fixture_envelope(1_500),
        };
        let vk = oracle_sk().verifying_key();
        assert!(
            verify_vca_claim_rung(
                &vca,
                &vk,
                "spiffe://nucleus.io/ns/agents/sa/a1",
                1_700_000_000_000_001,
                &AcceptingTee,
                &RefusingEnvelope,
            )
            .is_err(),
            "a refused envelope layer must not report a rung"
        );
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
        // BOTH verifiers refuse; the TEE layer runs first, so its error is the
        // one returned. The ordering is the property, not the message.
        let err = verify_vca_claim(
            &vca,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/a1",
            1_700_000_000_000_001,
            &RefusingTee,
            &RefusingEnvelope,
        )
        .unwrap_err();
        assert!(
            matches!(err, OracleError::TeeQuoteEmpty),
            "expected the TEE layer's error, got {err:?}"
        );
    }

    /// **The measurement from 2026-09-21, and what it earns now.**
    ///
    /// A one-byte TEE quote with 64 zero bytes of `report_data`, and a
    /// one-byte "proof" whose self-declared bound is `u64::MAX`. Both SHAPE
    /// checks still pass — they are honest about what they check — and under
    /// the old names both returned `Ok`, which `assess_rung` read as
    /// `tee_ok = true, zk_envelope_ok = true` and turned into R4.
    ///
    /// The repair is in the types: `check_shape` yields `QuoteWellFormed` and
    /// `check_self_declared_bound` yields `EnvelopeSelfDeclared`, and
    /// `assess_rung` takes neither. That is a compile-time fact, so this test
    /// does not pretend to observe it at runtime (ADR 0007 D-3: a
    /// `compile_fail` doctest is not a substitute for a type). What it does
    /// show is the consequence — with no witness beyond the signature, the
    /// same claim earns R1.
    #[test]
    fn the_forged_claim_passes_both_shape_checks_and_earns_r1() {
        let att = TeeAttestation {
            vendor: TeeVendor::IntelTdx,
            quote_bytes: vec![0x00],
            report_data: vec![0x00; 64],
        };
        let env = UpperEnvelopeProof {
            proof_bytes: vec![0x00],
            public_inputs: vec![u64::MAX],
        };
        let claim = fixture_claim(1_000);

        let _shape: QuoteWellFormed = att.check_shape().expect("a one-byte quote IS well formed");
        let _bound: EnvelopeSelfDeclared = env
            .check_self_declared_bound(&claim)
            .expect("the prover's own bound IS satisfied");

        let sig = SignatureVerified::for_test();
        assert_eq!(
            crate::assess_rung(&sig, None, None, None),
            AssuranceRung::OracleSigned,
            "a signature and two shape checks earn R1, not R4"
        );
    }

    /// A dispute window cannot be witnessed by a majority of one.
    #[test]
    fn a_dispute_needs_two_independent_sources() {
        assert!(matches!(
            Disputed::from_elapsed_window(1),
            Err(OracleError::DisputeNeedsTwoSources { got: 1 })
        ));
        assert!(Disputed::from_elapsed_window(2).is_ok());
    }

    // ── S4 — Oracle registry ───────────────────────────────────────────

    #[test]
    fn lookup_resolves_to_registered_key() {
        let mut reg = OracleRegistry::new();
        let vk = oracle_sk().verifying_key();
        assert!(reg.is_empty());
        assert!(
            reg.register(ResourceDim::GpuSeconds, "gpu-oracle", vk)
                .is_none()
        );
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
        assert!(
            reg.lookup(ResourceDim::GridCarbonGramsCo2, "gpu-oracle")
                .is_none()
        );
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
