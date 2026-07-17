//! Signed declassification — the headline gate.
//!
//! A record whose authority is `MayNotAuthorize` (adversarial / AI-derived) can
//! only be promoted into actionable, informing context through a
//! [`SignedDeclassify`]: a [`DeclassifyWitness`] cosigned by a **k-of-n** quorum
//! of trusted Ed25519 keys (the same threshold discipline as
//! `nucleus_envelope::cosignature_threshold` and the move-7 witness quorum),
//! gated through the monotone `DerivationClass` lattice so that **promotion does
//! not cleanse**: an `OpaqueExternal` / `AIDerived` ancestry survives promotion
//! (becomes `Mixed` / `HumanPromoted`, never `Deterministic`), and integrity is
//! raised only to `Untrusted` (usable/informing), never to `Trusted`.
//!
//! Fail-closed: a zero threshold is a configuration error, not "no witness
//! required" — it is rejected outright.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use portcullis_core::memory::{MemoryAuthority, MemoryLabel};
use portcullis_core::{DerivationClass, IntegLevel};
use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::recompute::RecomputeVerdict;
use crate::record::{MemoryDerivation, MemoryRecord};

/// Domain tag for declassify-witness signatures (separate from record hashing).
const WITNESS_DOMAIN: &[u8] = b"nucleus-provenance-memory/declassify-witness/v1\0";

/// The claim a witness cosigns: "I attest that record `record_hash` may be
/// promoted to `to_authority` with derivation class `to_derivation`, given the
/// recompute verdict `recompute_verdict`."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassifyWitness {
    /// Content hash of the record being declassified (binds the witness to it).
    pub record_hash: ContentHash,
    /// The recompute verdict the witness observed. For a deterministic record
    /// this MUST be [`RecomputeVerdict::Match`] for the gate to pass.
    pub recompute_verdict: RecomputeVerdict,
    /// Target authority (normally [`MemoryAuthority::MayInform`]).
    pub to_authority: MemoryAuthority,
    /// Target derivation class. Promoting an adversarial/AI-derived record
    /// requires [`DerivationClass::HumanPromoted`].
    pub to_derivation: DerivationClass,
}

impl DeclassifyWitness {
    /// Domain-tagged canonical bytes the quorum signs over.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WITNESS_DOMAIN.len() + 128);
        out.extend_from_slice(WITNESS_DOMAIN);
        serde_json::to_writer(&mut out, self).expect("witness serialization is infallible");
        out
    }

    /// Sign this witness with `key`, returning the `(verifying_key, signature)`
    /// pair to attach to a [`SignedDeclassify`]. (`SigningKey` is constructed by
    /// the caller — e.g. from a SPIRE-issued key — never generated here.)
    pub fn sign(&self, key: &SigningKey) -> ([u8; 32], Vec<u8>) {
        let sig = key.sign(&self.canonical_bytes());
        (key.verifying_key().to_bytes(), sig.to_bytes().to_vec())
    }
}

/// A [`DeclassifyWitness`] plus its cosignatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeclassify {
    /// The cosigned claim.
    pub witness: DeclassifyWitness,
    /// `(verifying_key_bytes, signature_bytes)` cosignature pairs.
    pub signatures: Vec<([u8; 32], Vec<u8>)>,
}

impl SignedDeclassify {
    /// Start a signed declassification with no cosignatures yet.
    pub fn new(witness: DeclassifyWitness) -> Self {
        Self {
            witness,
            signatures: Vec::new(),
        }
    }

    /// Attach a cosignature from `key`.
    pub fn cosign(mut self, key: &SigningKey) -> Self {
        self.signatures.push(self.witness.sign(key));
        self
    }
}

/// Why a declassification was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclassifyError {
    /// The threshold was zero — a misconfiguration that would mean "no witness
    /// required". Rejected fail-closed.
    #[error("declassify threshold must be >= 1 (zero would be fail-open)")]
    ThresholdTooLow,
    /// The witness is bound to a different record than the one presented.
    #[error("witness record_hash {witness} != record content hash {record}")]
    HashMismatch {
        /// Hash named in the witness.
        witness: String,
        /// Hash of the presented record.
        record: String,
    },
    /// Fewer than `need` distinct trusted keys cosigned.
    #[error("insufficient quorum: {got} distinct trusted cosignatures, need {need}")]
    InsufficientWitnesses {
        /// Distinct trusted cosignatures collected.
        got: usize,
        /// Threshold required.
        need: usize,
    },
    /// A deterministic record was presented but the witnessed recompute verdict
    /// was not [`RecomputeVerdict::Match`].
    #[error("deterministic record requires a Match recompute verdict to declassify")]
    RecomputeNotMatched,
    /// An adversarial / AI-derived record requires an explicit
    /// [`DerivationClass::HumanPromoted`] target to be declassified.
    #[error("adversarial/AI-derived record requires HumanPromoted declassification")]
    RequiresHumanPromotion,
}

/// **The declassification gate.** Given a record, a signed witness, the set of
/// trusted verifying keys, and a k-of-n `threshold`, return the *promoted*
/// [`MemoryLabel`] the record may carry at a sink — or a [`DeclassifyError`].
///
/// Checks, all fail-closed:
/// 1. `threshold >= 1` (zero is a misconfiguration);
/// 2. the witness binds to this exact record (`record_hash`);
/// 3. at least `threshold` **distinct trusted** keys cosigned the witness;
/// 4. a [`MemoryDerivation::Deterministic`] record's witnessed verdict is
///    [`RecomputeVerdict::Match`] (the value actually re-derives);
/// 5. a record whose current authority is [`MemoryAuthority::MayNotAuthorize`]
///    (adversarial / AI-derived) is promoted only with a
///    [`DerivationClass::HumanPromoted`] target.
///
/// The promoted label raises integrity to at most [`IntegLevel::Untrusted`]
/// (informing, never kernel-trusted), keeps confidentiality, and sets derivation
/// to `old.join(to_derivation)` — so ancestry is never laundered.
pub fn declassify(
    record: &MemoryRecord,
    signed: &SignedDeclassify,
    trusted_keys: &[[u8; 32]],
    threshold: usize,
) -> Result<MemoryLabel, DeclassifyError> {
    if threshold == 0 {
        return Err(DeclassifyError::ThresholdTooLow);
    }

    let record_hash = record.content_hash();
    if signed.witness.record_hash != record_hash {
        return Err(DeclassifyError::HashMismatch {
            witness: signed.witness.record_hash.to_hex(),
            record: record_hash.to_hex(),
        });
    }

    // Count DISTINCT trusted keys with a valid signature over the witness bytes.
    let trusted: BTreeSet<[u8; 32]> = trusted_keys.iter().copied().collect();
    let msg = signed.witness.canonical_bytes();
    let mut verified: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (pk_bytes, sig_bytes) in &signed.signatures {
        if !trusted.contains(pk_bytes) || verified.contains(pk_bytes) {
            continue;
        }
        let Ok(vk) = VerifyingKey::from_bytes(pk_bytes) else {
            continue;
        };
        let Ok(sig) = Signature::from_slice(sig_bytes) else {
            continue;
        };
        if vk.verify_strict(&msg, &sig).is_ok() {
            verified.insert(*pk_bytes);
        }
    }
    if verified.len() < threshold {
        return Err(DeclassifyError::InsufficientWitnesses {
            got: verified.len(),
            need: threshold,
        });
    }

    // Deterministic records must have re-derived (Match) per the witness.
    if matches!(record.derivation, MemoryDerivation::Deterministic { .. })
        && !signed.witness.recompute_verdict.is_match()
    {
        return Err(DeclassifyError::RecomputeNotMatched);
    }

    // Adversarial / AI-derived records need an explicit human promotion.
    if record.authority() == MemoryAuthority::MayNotAuthorize
        && signed.witness.to_derivation != DerivationClass::HumanPromoted
    {
        return Err(DeclassifyError::RequiresHumanPromotion);
    }

    // Build the promoted label: integrity raised only to Untrusted (informing,
    // never Trusted), confidentiality preserved, derivation = old.join(target)
    // so ancestry survives ("promotion does not cleanse").
    let promoted_integ = match record.label.integ_level() {
        IntegLevel::Trusted => IntegLevel::Trusted,
        _ => IntegLevel::Untrusted,
    };
    Ok(MemoryLabel::from_levels_with_derivation(
        record.label.conf_level(),
        promoted_integ,
        record.label.derivation.join(signed.witness.to_derivation),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompute::derive_label;
    use crate::record::MemoryDerivation;
    use nucleus_lineage::SourceClass;
    use portcullis_core::memory::SchemaType;
    use portcullis_core::ConfLevel;

    fn key(seed: u8) -> SigningKey {
        // from_bytes is decode-only — no CSPRNG (production keys come from SPIRE).
        SigningKey::from_bytes(&[seed; 32])
    }

    fn web_record() -> MemoryRecord {
        let d = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(b"evil-instruction"),
        };
        let label = derive_label(&d, &[]);
        MemoryRecord::new("evil-instruction", SchemaType::String, label, d)
    }

    fn human_witness(rec: &MemoryRecord) -> DeclassifyWitness {
        DeclassifyWitness {
            record_hash: rec.content_hash(),
            recompute_verdict: RecomputeVerdict::Match,
            to_authority: MemoryAuthority::MayInform,
            to_derivation: DerivationClass::HumanPromoted,
        }
    }

    #[test]
    fn quorum_met_promotes_adversarial_record() {
        let rec = web_record();
        assert_eq!(rec.authority(), MemoryAuthority::MayNotAuthorize);
        let trusted = [
            key(1).verifying_key().to_bytes(),
            key(2).verifying_key().to_bytes(),
        ];
        let signed = SignedDeclassify::new(human_witness(&rec))
            .cosign(&key(1))
            .cosign(&key(2));
        let label = declassify(&rec, &signed, &trusted, 2).unwrap();
        // Promoted to informing (Untrusted), but ancestry preserved (not Deterministic).
        assert_eq!(label.integ_level(), IntegLevel::Untrusted);
        assert_ne!(label.derivation, DerivationClass::Deterministic);
    }

    /// M-3 strong-binding regression (site: `declassify`, the
    /// `vk.verify_strict(&msg, &sig)` cosignature check). The Ed25519
    /// identity/neutral key (`[1, 0, ..., 0]`) with the identity-triple
    /// signature (R = identity encoding, s = 0) satisfies the COFACTORED
    /// verification equation for every message, so non-strict `verify()`
    /// ACCEPTS it — a forged threshold cosignature. `verify_strict()`
    /// rejects the small-order key. If the site is reverted to non-strict
    /// `vk.verify(...)`, assertion (ii) counts the forged key and the
    /// adversarial record is (wrongly) PROMOTED.
    #[test]
    fn small_order_key_is_rejected_by_verify_strict() {
        // (i) No regression: an honest 2-of-2 quorum still promotes.
        let rec = web_record();
        let honest_trusted = [
            key(1).verifying_key().to_bytes(),
            key(2).verifying_key().to_bytes(),
        ];
        let honest = SignedDeclassify::new(human_witness(&rec))
            .cosign(&key(1))
            .cosign(&key(2));
        declassify(&rec, &honest, &honest_trusted, 2)
            .expect("honest quorum must still promote through verify_strict");

        // (ii) Strong binding: the small-order identity key with the
        // identity-triple signature must NOT count as a valid witness.
        let mut id = [0u8; 32];
        id[0] = 1; // identity/neutral point encoding — a small-order key
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&id); // R = identity, s = 0
        let mut forged = SignedDeclassify::new(human_witness(&rec));
        forged.signatures.push((id, sig_bytes.to_vec()));
        // Trust the identity key and require just one witness: the only way
        // to reach the threshold is for the forged cosignature to verify.
        assert!(
            matches!(
                declassify(&rec, &forged, &[id], 1),
                Err(DeclassifyError::InsufficientWitnesses { got: 0, need: 1 })
            ),
            "small-order identity key must be REJECTED by verify_strict; a \
             revert to non-strict verify() would COUNT this forged cosignature \
             and promote an adversarial record"
        );
    }

    #[test]
    fn below_threshold_is_refused() {
        let rec = web_record();
        let trusted = [
            key(1).verifying_key().to_bytes(),
            key(2).verifying_key().to_bytes(),
        ];
        let signed = SignedDeclassify::new(human_witness(&rec)).cosign(&key(1));
        assert!(matches!(
            declassify(&rec, &signed, &trusted, 2),
            Err(DeclassifyError::InsufficientWitnesses { got: 1, need: 2 })
        ));
    }

    #[test]
    fn untrusted_signer_does_not_count() {
        let rec = web_record();
        let trusted = [key(1).verifying_key().to_bytes()];
        // key(9) is not trusted; only key(1) counts → 1 < 2.
        let signed = SignedDeclassify::new(human_witness(&rec))
            .cosign(&key(1))
            .cosign(&key(9));
        assert!(matches!(
            declassify(&rec, &signed, &trusted, 2),
            Err(DeclassifyError::InsufficientWitnesses { got: 1, need: 2 })
        ));
    }

    #[test]
    fn duplicate_signature_counts_once() {
        let rec = web_record();
        let trusted = [
            key(1).verifying_key().to_bytes(),
            key(2).verifying_key().to_bytes(),
        ];
        // key(1) signs twice; must count as one distinct witness.
        let signed = SignedDeclassify::new(human_witness(&rec))
            .cosign(&key(1))
            .cosign(&key(1));
        assert!(matches!(
            declassify(&rec, &signed, &trusted, 2),
            Err(DeclassifyError::InsufficientWitnesses { got: 1, need: 2 })
        ));
    }

    #[test]
    fn zero_threshold_is_fail_closed() {
        let rec = web_record();
        let signed = SignedDeclassify::new(human_witness(&rec));
        assert_eq!(
            declassify(&rec, &signed, &[], 0),
            Err(DeclassifyError::ThresholdTooLow)
        );
    }

    #[test]
    fn witness_for_other_record_is_rejected() {
        let rec = web_record();
        let trusted = [key(1).verifying_key().to_bytes()];
        let mut w = human_witness(&rec);
        w.record_hash = ContentHash::of_canonical_bytes(b"some-other-record");
        let signed = SignedDeclassify::new(w).cosign(&key(1));
        assert!(matches!(
            declassify(&rec, &signed, &trusted, 1),
            Err(DeclassifyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn adversarial_record_requires_human_promotion() {
        let rec = web_record();
        let trusted = [key(1).verifying_key().to_bytes()];
        let mut w = human_witness(&rec);
        w.to_derivation = DerivationClass::Deterministic; // not HumanPromoted
        let signed = SignedDeclassify::new(w).cosign(&key(1));
        assert!(matches!(
            declassify(&rec, &signed, &trusted, 1),
            Err(DeclassifyError::RequiresHumanPromotion)
        ));
    }

    #[test]
    fn tampered_witness_body_fails_signature() {
        let rec = web_record();
        let trusted = [key(1).verifying_key().to_bytes()];
        let mut signed = SignedDeclassify::new(human_witness(&rec)).cosign(&key(1));
        // Tamper the witness AFTER signing → signature no longer verifies.
        signed.witness.to_authority = MemoryAuthority::MayNotAuthorize;
        assert!(matches!(
            declassify(&rec, &signed, &trusted, 1),
            Err(DeclassifyError::InsufficientWitnesses { got: 0, need: 1 })
        ));
    }

    #[test]
    fn deterministic_record_requires_match_verdict() {
        // A deterministic record whose witness carries a non-Match verdict.
        let a = {
            let d = MemoryDerivation::RawIngest {
                source_class: SourceClass::LocalFile,
                source_hash: ContentHash::of_canonical_bytes(b"a"),
            };
            MemoryRecord::new("a", SchemaType::String, derive_label(&d, &[]), d)
        };
        let d = MemoryDerivation::Deterministic {
            input_hashes: vec![a.content_hash()],
            transform: crate::record::TransformId::new("id"),
        };
        let label = derive_label(&d, &[&a]);
        let rec = MemoryRecord::new("a", SchemaType::String, label, d);
        let trusted = [key(1).verifying_key().to_bytes()];
        let mut w = DeclassifyWitness {
            record_hash: rec.content_hash(),
            recompute_verdict: RecomputeVerdict::Invalid {
                reason: "did not recompute".into(),
            },
            to_authority: MemoryAuthority::MayInform,
            to_derivation: DerivationClass::HumanPromoted,
        };
        // ensure conf carries through unchanged
        let _ = ConfLevel::Public;
        let signed = SignedDeclassify::new(w.clone()).cosign(&key(1));
        assert!(matches!(
            declassify(&rec, &signed, &trusted, 1),
            Err(DeclassifyError::RecomputeNotMatched)
        ));
        // and with a Match verdict it passes
        w.recompute_verdict = RecomputeVerdict::Match;
        let signed_ok = SignedDeclassify::new(w).cosign(&key(1));
        assert!(declassify(&rec, &signed_ok, &trusted, 1).is_ok());
    }
}
