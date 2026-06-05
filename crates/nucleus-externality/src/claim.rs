//! Signed externality claim envelope.
//!
//! **Pigouvian P1/P2.** A `SignedExternalityClaim` is the wire-format
//! unit of externality reporting: oracle says "this call consumed N
//! micro-units of resource D at time T", signs it with Ed25519, and
//! the substrate verifies before letting the claim into the auction's
//! Pigouvian re-weighting step.
//!
//! ## Wire shape
//!
//! ```text
//! canonical = RESOURCE_DIM_DOMAIN
//!          || resource_dim.tag()
//!          || u64_be(units_micro)
//!          || u64_be(ts_unix_micros)
//!          || u64_be(not_after_unix_micros)
//!          || u32_be(kid.len()) || kid
//!          || u32_be(subject_identity.len()) || subject_identity
//! ```
//!
//! Subject identity is included so the claim is *bound* to a specific
//! agent / call SPIFFE-id — a hostile oracle can't sign a claim for
//! identity A and swap it onto a call from identity B (the
//! replay-vector E1's `Freshness` envelope defends against).
//!
//! The `not_after_unix_micros` field is in the signature, so an
//! oracle that pre-signs a 1-hour-valid claim can't have an attacker
//! replay it into a 1-week window — same pattern as D5's FX oracle.
//!
//! ## Integer-only
//!
//! All field types are integer; the Pigouvian re-weighting step
//! (R2) computes `λ_k * units_micro` in `u128` then saturates to
//! `u64` — no floats anywhere.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dim::{ResourceDim, RESOURCE_DIM_DOMAIN};

/// One signed externality claim from a designated oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExternalityClaim {
    /// Which resource dimension this claim is about.
    pub resource: ResourceDim,
    /// Integer units consumed (or in `KnowledgeSpillover`'s case,
    /// produced — that's the only positive-externality variant).
    pub units_micro: u64,
    /// Oracle-side issuance time, unix microseconds.
    pub ts_unix_micros: u64,
    /// Hard expiry: claim is invalid after this point. Replay defense.
    pub not_after_unix_micros: u64,
    /// SPIFFE-id (or other identity string) of the agent / call this
    /// claim attests about. Bound into the signature so a claim for
    /// A can't be moved onto a call from B.
    pub subject_identity: String,
    /// Oracle's signing key id (resolves to `VerifyingKey` via the
    /// per-dimension `OracleRegistry` in S4).
    pub kid: String,
    /// Ed25519 signature, base64-encoded.
    pub sig_b64: String,
}

/// Errors from constructing or verifying a claim.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClaimError {
    /// Signature did not verify under the supplied `oracle_vk`.
    #[error("signature did not verify: {0}")]
    SignatureInvalid(String),
    /// Signature bytes didn't base64-decode.
    #[error("sig_b64 base64 decode failed: {0}")]
    Base64(String),
    /// Decoded signature had the wrong length.
    #[error("signature is {got} bytes, expected 64")]
    WrongSignatureLength { got: usize },
    /// Claim expired at `not_after` before the supplied `now`.
    #[error("claim expired at {not_after} micros, called at {now} micros")]
    Expired { not_after: u64, now: u64 },
    /// Subject identity didn't match the caller-supplied expected
    /// identity. The replay-into-different-call defense.
    #[error("subject identity mismatch — claim is for {claimed}, expected {expected}")]
    SubjectIdentityMismatch { claimed: String, expected: String },
}

/// Canonical bytes the Ed25519 signature commits to. The format is
/// domain-tagged, length-prefixed, and integer-only. Mirrors the
/// pattern from `nucleus-reputation::freshness_signing_bytes`.
pub fn canonical_claim_bytes(c: &SignedExternalityClaim) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(RESOURCE_DIM_DOMAIN);
    let tag = c.resource.as_canonical_tag();
    out.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(&c.units_micro.to_be_bytes());
    out.extend_from_slice(&c.ts_unix_micros.to_be_bytes());
    out.extend_from_slice(&c.not_after_unix_micros.to_be_bytes());
    out.extend_from_slice(&(c.kid.len() as u32).to_be_bytes());
    out.extend_from_slice(c.kid.as_bytes());
    out.extend_from_slice(&(c.subject_identity.len() as u32).to_be_bytes());
    out.extend_from_slice(c.subject_identity.as_bytes());
    out
}

/// Sign an unsigned claim shell — fills in `sig_b64` from
/// `canonical_claim_bytes` under the supplied signing key.
pub fn sign_claim(sk: &SigningKey, mut claim: SignedExternalityClaim) -> SignedExternalityClaim {
    let sig: Signature = sk.sign(&canonical_claim_bytes(&claim));
    claim.sig_b64 = STANDARD.encode(sig.to_bytes());
    claim
}

/// Verify a claim under the supplied oracle verifying key + freshness
/// window + expected subject identity. Returns `Ok(())` only when
/// (a) signature verifies, (b) `not_after >= now`, and (c) the
/// claim's `subject_identity` matches `expected_subject`.
pub fn verify_claim(
    claim: &SignedExternalityClaim,
    oracle_vk: &VerifyingKey,
    expected_subject: &str,
    now_unix_micros: u64,
) -> Result<(), ClaimError> {
    // 1. Signature first — never touch claim contents before this.
    let sig_bytes = STANDARD
        .decode(&claim.sig_b64)
        .map_err(|e| ClaimError::Base64(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(ClaimError::WrongSignatureLength {
            got: sig_bytes.len(),
        });
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&buf);
    oracle_vk
        .verify(&canonical_claim_bytes(claim), &sig)
        .map_err(|e| ClaimError::SignatureInvalid(e.to_string()))?;

    // 2. Freshness window.
    if claim.not_after_unix_micros < now_unix_micros {
        return Err(ClaimError::Expired {
            not_after: claim.not_after_unix_micros,
            now: now_unix_micros,
        });
    }

    // 3. Subject identity binding — defense against the
    //    swap-claim-onto-different-call attack.
    if claim.subject_identity != expected_subject {
        return Err(ClaimError::SubjectIdentityMismatch {
            claimed: claim.subject_identity.clone(),
            expected: expected_subject.to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_oracle() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn fixture_claim() -> SignedExternalityClaim {
        let sk = fixture_oracle();
        sign_claim(
            &sk,
            SignedExternalityClaim {
                resource: ResourceDim::GridCarbonGramsCo2,
                units_micro: 1_500_000, // 1.5 grams CO₂
                ts_unix_micros: 1_700_000_000_000_000,
                not_after_unix_micros: 1_700_000_000_000_000 + 3_600_000_000,
                subject_identity: "spiffe://nucleus.io/ns/agents/sa/agent-1".to_string(),
                kid: "co2-oracle-key-1".to_string(),
                sig_b64: String::new(),
            },
        )
    }

    #[test]
    fn valid_signed_claim_verifies() {
        let vk = fixture_oracle().verifying_key();
        let c = fixture_claim();
        verify_claim(
            &c,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/agent-1",
            1_700_000_000_000_001,
        )
        .expect("fresh signed claim must verify");
    }

    #[test]
    fn tampered_units_fail_signature() {
        let vk = fixture_oracle().verifying_key();
        let mut c = fixture_claim();
        c.units_micro = 999_999_999; // forge bigger consumption claim
        let err = verify_claim(
            &c,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/agent-1",
            1_700_000_000_000_001,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimError::SignatureInvalid(_)));
    }

    #[test]
    fn expired_claim_rejected() {
        let vk = fixture_oracle().verifying_key();
        let c = fixture_claim();
        // call at 2× the not_after.
        let err = verify_claim(
            &c,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/agent-1",
            c.not_after_unix_micros + 1,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimError::Expired { .. }));
    }

    #[test]
    fn swap_claim_onto_different_subject_rejected() {
        // Replay vector: hostile gateway gets a valid claim for
        // agent-1 and attaches it to a call from agent-2.
        let vk = fixture_oracle().verifying_key();
        let c = fixture_claim();
        let err = verify_claim(
            &c,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/agent-2",
            1_700_000_000_000_001,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimError::SubjectIdentityMismatch { .. }));
    }

    #[test]
    fn rogue_oracle_key_rejected() {
        let bogus = SigningKey::from_bytes(&[99u8; 32]).verifying_key();
        let c = fixture_claim();
        let err = verify_claim(
            &c,
            &bogus,
            "spiffe://nucleus.io/ns/agents/sa/agent-1",
            1_700_000_000_000_001,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimError::SignatureInvalid(_)));
    }

    #[test]
    fn resource_dim_swap_breaks_signature() {
        let vk = fixture_oracle().verifying_key();
        let mut c = fixture_claim();
        // Swap GridCarbon → GpuSeconds; the tag participates in the
        // canonical bytes so the signature must fail.
        c.resource = ResourceDim::GpuSeconds;
        let err = verify_claim(
            &c,
            &vk,
            "spiffe://nucleus.io/ns/agents/sa/agent-1",
            1_700_000_000_000_001,
        )
        .unwrap_err();
        assert!(matches!(err, ClaimError::SignatureInvalid(_)));
    }

    #[test]
    fn round_trips_json() {
        let c = fixture_claim();
        let json = serde_json::to_string(&c).unwrap();
        let back: SignedExternalityClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let c1 = fixture_claim();
        let c2 = fixture_claim();
        assert_eq!(canonical_claim_bytes(&c1), canonical_claim_bytes(&c2));
    }

    #[test]
    fn canonical_bytes_change_under_field_flip() {
        let c = fixture_claim();
        let original = canonical_claim_bytes(&c);

        let mut c2 = c.clone();
        c2.units_micro += 1;
        assert_ne!(canonical_claim_bytes(&c2), original);

        let mut c3 = c.clone();
        c3.not_after_unix_micros += 1;
        assert_ne!(canonical_claim_bytes(&c3), original);

        let mut c4 = c.clone();
        c4.subject_identity.push('x');
        assert_ne!(canonical_claim_bytes(&c4), original);
    }
}
