//! The assurance rung as a **verification output** — never a field a record
//! carries, never a value a caller supplies (#2518).
//!
//! Before this module, [`crate::AccumulationManifest`] had a
//! `pub assurance_rung: AssuranceRung`: whoever signed the manifest wrote the
//! rung, and every reader took it. The signature bound the rung to the signer,
//! which made a lie *attributable*, not *impossible* — a signer that wrote
//! `ZkUpperEnvelope` over a claim no envelope verifier had seen produced a
//! manifest that verified and read as the top rung.
//!
//! Now the rung exists only as a [`VerifiedRung`]:
//!
//! - its fields are private and it has no public constructor, no `Default` and
//!   no `Deserialize` (ADR 0007 C-1, B-1). The one function that mints it is
//!   [`verify_rung_evidence`], which re-runs every layer's verifier over the
//!   [`RungEvidence`] and hands the resulting witnesses to
//!   [`nucleus_externality::assess_rung`];
//! - it records the digest of the evidence it was derived from, so a manifest
//!   built from it commits to *that* evidence ([`RungEvidence::digest`]) and a
//!   relying party re-derives the rung from the same bytes rather than reading
//!   one (ADR 0007 F: derive, never restate).
//!
//! # What the evidence can reach, and why
//!
//! The signature layer is mandatory: an unverified claim yields an error, never
//! a rung, so `SelfReported` is not a `VerifiedRung` at all. The TEE and
//! envelope layers are credited **only** through a verifier the caller names —
//! [`nucleus_externality::TeeQuoteVerifier`] / [`nucleus_externality::EnvelopeVerifier`]
//! are sealed and this workspace ships no implementation of either (#2504,
//! #2505). So with fail-closed defaults (`None`, `None`) the highest reachable
//! rung is `OracleSigned`, whatever quote or proof bytes the evidence carries.
//! The dispute layer (R3) is never credited: a single claim cannot witness a
//! multi-source window.
//!
//! A caller cannot construct one:
//!
//! ```compile_fail,E0451
//! use nucleus_externality::AssuranceRung;
//! use nucleus_witness_olog::VerifiedRung;
//! // Private fields: the struct literal is refused.
//! let _forged = VerifiedRung { rung: AssuranceRung::ZkUpperEnvelope, evidence_digest: [0u8; 32] };
//! ```
//!
//! nor deserialize one:
//!
//! ```compile_fail,E0277
//! use nucleus_witness_olog::VerifiedRung;
//! // `VerifiedRung: Deserialize` does not hold.
//! let _forged: VerifiedRung =
//!     serde_json::from_str(r#"{"rung":"zk_upper_envelope","evidence_digest":[]}"#).unwrap();
//! ```

use nucleus_externality::{
    AssuranceRung, EnvelopeVerifier, OracleError, SignedExternalityClaim, TeeAttestation,
    TeeQuoteVerifier, TeeVendor, UpperEnvelopeProof, assess_rung, canonical_claim_bytes,
    verify_claim_witnessed,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::manifest::push_field;

/// Domain prefix for [`RungEvidence::digest`]. Versioned so a later evidence
/// shape cannot collide with this one.
pub const RUNG_EVIDENCE_DOMAIN: &[u8] = b"nucleus/witness-olog/rung-evidence/v1\0";

/// The per-layer evidence a rung is derived FROM. Plain data: holding it proves
/// nothing until [`verify_rung_evidence`] has run each layer's verifier over it.
///
/// Carrying a `tee` or `envelope` earns nothing by itself — those bytes were the
/// forgery surface on 2026-09-21 — and is credited only when the matching
/// verifier is supplied and accepts them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RungEvidence {
    /// The oracle-signed claim. Its signature is the mandatory first layer.
    pub claim: SignedExternalityClaim,
    /// A TEE quote, if the oracle produced one.
    pub tee: Option<TeeAttestation>,
    /// A zk upper-envelope proof, if the oracle produced one.
    pub envelope: Option<UpperEnvelopeProof>,
}

impl RungEvidence {
    /// Content address of the evidence: SHA-256 over domain-tagged,
    /// length-prefixed, integer-only bytes covering every field (the claim
    /// including its signature, and each optional layer with a presence tag).
    /// This is what [`crate::AccumulationManifest::rung_evidence_digest`]
    /// commits to.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(RUNG_EVIDENCE_DOMAIN);
        push_field(&mut out, &canonical_claim_bytes(&self.claim));
        push_field(&mut out, self.claim.sig_b64.as_bytes());
        match &self.tee {
            None => out.push(0),
            Some(att) => {
                out.push(1);
                out.push(match att.vendor {
                    TeeVendor::IntelTdx => 0,
                    TeeVendor::AmdSevSnp => 1,
                    TeeVendor::NitroEnclave => 2,
                });
                push_field(&mut out, &att.quote_bytes);
                push_field(&mut out, &att.report_data);
            }
        }
        match &self.envelope {
            None => out.push(0),
            Some(proof) => {
                out.push(1);
                push_field(&mut out, &proof.proof_bytes);
                let len = u32::try_from(proof.public_inputs.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&len.to_be_bytes());
                for x in &proof.public_inputs {
                    out.extend_from_slice(&x.to_be_bytes());
                }
            }
        }
        Sha256::digest(&out).into()
    }
}

/// An assurance rung that a verifier DERIVED, bound to the evidence it was
/// derived from.
///
/// No public constructor, no `Default`, no `Deserialize`: the only way to hold
/// one is to have run [`verify_rung_evidence`] (or to have been handed one by
/// code that did). APIs in this crate that need a rung take this type, so no
/// public API accepts a rung a caller chose. `Serialize` is kept for display
/// and receipts; a reader of that output gets a label, not a `VerifiedRung`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct VerifiedRung {
    rung: AssuranceRung,
    evidence_digest: [u8; 32],
}

impl VerifiedRung {
    /// The derived rung.
    #[must_use]
    pub fn rung(&self) -> AssuranceRung {
        self.rung
    }

    /// Digest ([`RungEvidence::digest`]) of the evidence this rung was derived from.
    #[must_use]
    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    /// Test-only mint, for exercising the functor and manifest at rungs no
    /// shipped verifier can reach. `cfg(test)` and crate-private: it does not
    /// exist in the library a downstream crate (or a doctest) links against.
    #[cfg(test)]
    pub(crate) fn for_test(rung: AssuranceRung, evidence_digest: [u8; 32]) -> Self {
        Self {
            rung,
            evidence_digest,
        }
    }
}

/// Which layer refused, and why. Each variant wraps that layer's own error —
/// never a blanket conversion (ADR 0007 A-3).
#[derive(Debug, Error)]
pub enum RungError {
    /// The claim's signature, freshness or subject binding failed. There is no
    /// rung for an unverified claim — not even `SelfReported`.
    #[error("signature layer: {0}")]
    Signature(OracleError),
    /// A TEE verifier was supplied and refused the evidence's quote.
    #[error("tee layer: {0}")]
    Tee(OracleError),
    /// An envelope verifier was supplied and refused the evidence's proof.
    #[error("envelope layer: {0}")]
    Envelope(OracleError),
}

/// Derive the rung `evidence` earns, by running each layer's verifier.
///
/// - **Signature** (mandatory): [`verify_claim_witnessed`] against `oracle_vk`,
///   `expected_subject` and `now_unix_micros`. Failure is an error.
/// - **TEE**: credited only when `tee_verifier` is `Some` AND the evidence has a
///   quote AND the verifier accepts it. A supplied verifier that refuses a
///   present quote is an error, not a silent fallback; an absent verifier or
///   absent quote is simply no credit.
/// - **Envelope**: the same, with `envelope_verifier`.
/// - **Dispute**: never credited here (a single claim cannot witness it).
///
/// With `None` for both verifiers — the fail-closed default, and the only
/// choice while no implementation ships — the result is at most `OracleSigned`.
///
/// # Errors
///
/// [`RungError`] naming the layer that refused.
pub fn verify_rung_evidence(
    evidence: &RungEvidence,
    oracle_vk: &ed25519_dalek::VerifyingKey,
    expected_subject: &str,
    now_unix_micros: u64,
    tee_verifier: Option<&dyn TeeQuoteVerifier>,
    envelope_verifier: Option<&dyn EnvelopeVerifier>,
) -> Result<VerifiedRung, RungError> {
    let signature = verify_claim_witnessed(
        &evidence.claim,
        oracle_vk,
        expected_subject,
        now_unix_micros,
    )
    .map_err(RungError::Signature)?;
    let tee = match (tee_verifier, &evidence.tee) {
        (Some(v), Some(att)) => Some(v.verify_quote(att).map_err(RungError::Tee)?),
        (Some(_), None) | (None, Some(_)) | (None, None) => None,
    };
    let envelope = match (envelope_verifier, &evidence.envelope) {
        (Some(v), Some(proof)) => Some(
            v.verify_envelope(proof, &evidence.claim)
                .map_err(RungError::Envelope)?,
        ),
        (Some(_), None) | (None, Some(_)) | (None, None) => None,
    };
    Ok(VerifiedRung {
        rung: assess_rung(&signature, tee.as_ref(), None, envelope.as_ref()),
        evidence_digest: evidence.digest(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nucleus_externality::{ResourceDim, sign_claim};

    pub(crate) const SUBJECT: &str = "spiffe://nucleus.local/ns/agents/sa/a1";
    pub(crate) const NOW: u64 = 1_700_000_000_000_000;

    pub(crate) fn oracle_sk() -> SigningKey {
        SigningKey::from_bytes(&[44u8; 32])
    }

    /// The 2026-09-21 forgery, as evidence: a validly signed claim beside a
    /// one-byte "quote" and a one-byte "proof" self-declaring `u64::MAX`.
    pub(crate) fn fabricated_evidence() -> RungEvidence {
        RungEvidence {
            claim: sign_claim(
                &oracle_sk(),
                SignedExternalityClaim {
                    resource: ResourceDim::GpuSeconds,
                    units_micro: 1_000,
                    ts_unix_micros: NOW,
                    not_after_unix_micros: NOW + 3_600_000_000,
                    subject_identity: SUBJECT.into(),
                    kid: "gpu-oracle".into(),
                    sig_b64: String::new(),
                },
            ),
            tee: Some(TeeAttestation {
                vendor: TeeVendor::IntelTdx,
                quote_bytes: vec![0x01],
                report_data: vec![0x42; 64],
            }),
            envelope: Some(UpperEnvelopeProof {
                proof_bytes: vec![0x01],
                public_inputs: vec![u64::MAX],
            }),
        }
    }

    /// Acceptance criterion of #2518: fabricated bytes cannot reach
    /// `ZkUpperEnvelope`; with fail-closed defaults the ceiling is
    /// `OracleSigned`. Every combination of present/absent fabricated layers
    /// is tried.
    #[test]
    fn fabricated_layers_cannot_reach_zk_upper_envelope() {
        let base = fabricated_evidence();
        for tee in [None, base.tee.clone()] {
            for envelope in [None, base.envelope.clone()] {
                let ev = RungEvidence {
                    claim: base.claim.clone(),
                    tee: tee.clone(),
                    envelope: envelope.clone(),
                };
                let got = verify_rung_evidence(
                    &ev,
                    &oracle_sk().verifying_key(),
                    SUBJECT,
                    NOW,
                    None,
                    None,
                )
                .expect("a validly signed claim verifies");
                assert_eq!(
                    got.rung(),
                    AssuranceRung::OracleSigned,
                    "fail-closed ceiling is OracleSigned (tee={}, envelope={})",
                    ev.tee.is_some(),
                    ev.envelope.is_some()
                );
                assert_ne!(got.rung(), AssuranceRung::ZkUpperEnvelope);
                assert_eq!(got.evidence_digest(), ev.digest());
            }
        }
    }

    #[test]
    fn an_unverified_claim_has_no_rung_at_all() {
        let ev = fabricated_evidence();
        let wrong = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(matches!(
            verify_rung_evidence(&ev, &wrong, SUBJECT, NOW, None, None),
            Err(RungError::Signature(_))
        ));
        assert!(matches!(
            verify_rung_evidence(
                &ev,
                &oracle_sk().verifying_key(),
                "spiffe://nucleus.local/ns/agents/sa/someone-else",
                NOW,
                None,
                None
            ),
            Err(RungError::Signature(_))
        ));
    }

    #[test]
    fn the_digest_covers_every_layer() {
        let ev = fabricated_evidence();
        let d = ev.digest();
        let mut no_tee = ev.clone();
        no_tee.tee = None;
        let mut other_inputs = ev.clone();
        other_inputs.envelope.as_mut().unwrap().public_inputs = vec![1];
        let mut other_sig = ev.clone();
        other_sig.claim.sig_b64.push('A');
        for changed in [no_tee, other_inputs, other_sig] {
            assert_ne!(changed.digest(), d);
        }
        assert_eq!(ev.digest(), d, "deterministic");
    }

    #[test]
    fn evidence_refuses_unknown_fields() {
        let mut v = serde_json::to_value(fabricated_evidence()).unwrap();
        v["rung"] = serde_json::json!("zk_upper_envelope");
        assert!(serde_json::from_value::<RungEvidence>(v).is_err());
    }
}
