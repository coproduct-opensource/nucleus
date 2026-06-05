//! Verify a [`SignedAgentCard`] against an OUT-OF-BAND-resolved key.
//!
//! This module is ALWAYS compiled (no feature gate) and is secret-free —
//! a browser/WASM verifier can use it without ever touching a private key.
//!
//! # The one rule that makes this safe
//!
//! The verification key comes ONLY from the caller's `resolved_key`
//! argument — a key the caller obtained out-of-band (DID resolution, a
//! pinned JWKS, an operator file). It is NEVER read from the card or from
//! any `kid` the signature advertises. A card verified against a key the
//! *attacker* supplied is "verified garbage": the math passes but it
//! proves nothing about who the agent is.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use nucleus_identity::JsonWebKey;

use crate::card::{AgentCard, SignedAgentCard};
use crate::jcs::canonicalize;
use crate::{Error, Result};

/// A card whose signature verified against the caller's out-of-band key.
///
/// Holding a `VerifiedCard` is the proof obligation: you may only call
/// [`Self::advertised_jwks`] (and thence build a TrustAnchor) once the
/// card's authenticity has been established.
#[derive(Debug, Clone)]
pub struct VerifiedCard {
    /// The verified identity document.
    pub card: AgentCard,
}

impl VerifiedCard {
    /// The JWKS the (now-verified) card advertises as authoritative for
    /// its provenance bundles. Feed this to
    /// [`crate::anchor::trust_anchor_from_card`].
    pub fn advertised_jwks(&self) -> &nucleus_lineage::Jwks {
        &self.card.trust_jwks
    }
}

/// Verify a [`SignedAgentCard`] using a key the caller resolved
/// out-of-band.
///
/// Steps:
///
/// 1. Take the FIRST signature.
/// 2. Recompute the JCS canonical bytes of `card` and the detached JWS
///    payload segment `base64url_nopad(JCS(card))`.
/// 3. Reconstruct the compact JWS `protected.payload.signature` and verify
///    it via [`nucleus_identity::did_crypto::jws_verify_es256`] against
///    `resolved_key`.
/// 4. Assert the payload `jws_verify_es256` returns equals JCS(card) — so
///    the signature is bound to *this* card, not some other payload.
/// 5. Reject if the card's advertised `trust_jwks` is empty or malformed
///    (an advertised-but-unusable JWKS can't anchor anything downstream).
///
/// # Errors
///
/// Returns [`Error`] on: no signatures, signature/JWS verification
/// failure, payload mismatch, or empty/malformed `trust_jwks`.
pub fn verify_card(signed: &SignedAgentCard, resolved_key: &JsonWebKey) -> Result<VerifiedCard> {
    // 1) First signature. Multiple signatures are allowed on the wire, but
    //    the trust decision is made against the caller's resolved key over
    //    the first one — we never iterate looking for "a kid that matches"
    //    because that would re-introduce card-controlled key selection.
    let sig = signed
        .signatures
        .first()
        .ok_or(Error::Verify("signed card has no signatures".to_string()))?;

    // 2) Canonicalize the card and form the detached JWS payload segment.
    let jcs_bytes = canonicalize(&signed.card)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&jcs_bytes);

    // 3) Reconstruct the COMPACT JWS string the detached signature implies:
    //    protected "." base64url(JCS(card)) "." signature.
    let compact = format!("{}.{}.{}", sig.protected, payload_b64, sig.signature);

    // 4) Verify against the OUT-OF-BAND-resolved key ONLY. Never the card's
    //    own material. `jws_verify_es256` returns the decoded payload.
    let recovered = nucleus_identity::did_crypto::jws_verify_es256(&compact, resolved_key)
        .map_err(|e| Error::Verify(format!("JWS verification failed: {e}")))?;

    // 5) Defense in depth: the recovered payload MUST equal the JCS we
    //    canonicalized. With the reconstruction above this is structurally
    //    guaranteed, but asserting it pins the contract so a future change
    //    to the JWS reconstruction can't silently verify a different
    //    payload than the card.
    if recovered != jcs_bytes {
        return Err(Error::Verify(
            "verified JWS payload does not equal the card's JCS bytes".to_string(),
        ));
    }

    // 6) Reject an unusable advertised JWKS up front. An empty or malformed
    //    trust_jwks can't anchor any bundle, so a card carrying one is
    //    useless for verify-before-you-act — fail loudly here rather than
    //    let the caller build a TrustAnchor that rejects everything.
    reject_unusable_jwks(&signed.card.trust_jwks)?;

    Ok(VerifiedCard {
        card: signed.card.clone(),
    })
}

/// Reject an empty or malformed advertised JWKS.
///
/// Malformed = a key entry that can't be turned into a verifying key
/// (caught by [`nucleus_lineage::Jwks::verifying_key`]).
fn reject_unusable_jwks(jwks: &nucleus_lineage::Jwks) -> Result<()> {
    if jwks.keys.is_empty() {
        return Err(Error::Verify(
            "card advertises an empty trust_jwks (anchors nothing)".to_string(),
        ));
    }
    for key in &jwks.keys {
        // verifying_key() validates kty/crv/alg and decodes `x`. Any error
        // means this advertised key is unusable as a trust anchor.
        jwks.verifying_key(&key.kid).map_err(|e| {
            Error::Verify(format!(
                "card advertises a malformed trust_jwks key (kid {:?}): {e}",
                key.kid
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::{AgentCard, AgentCardSignature, SignedAgentCard};

    fn ed25519_jwks() -> nucleus_lineage::Jwks {
        nucleus_lineage::Jwks {
            keys: vec![nucleus_lineage::Jwk {
                kty: "OKP".to_string(),
                crv: Some("Ed25519".to_string()),
                kid: "k1".to_string(),
                x: Some("AAAA_AAAAAA-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
                alg: Some("EdDSA".to_string()),
                use_: Some("sig".to_string()),
                not_before: None,
                not_after: None,
            }],
        }
    }

    fn card_with(jwks: nucleus_lineage::Jwks) -> AgentCard {
        AgentCard {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            did: "did:web:coder.prod.example.com".to_string(),
            security_schemes: serde_json::json!({}),
            supported_envelope_schema_versions: vec!["1".to_string()],
            jwks_uri: None,
            trust_jwks: jwks,
            runtime_guarantees: None,
        }
    }

    #[test]
    fn no_signatures_is_rejected() {
        let signed = SignedAgentCard {
            card: card_with(ed25519_jwks()),
            signatures: vec![],
        };
        let key = JsonWebKey::ec_p256("x", "y");
        let err = verify_card(&signed, &key).unwrap_err();
        assert!(matches!(err, Error::Verify(_)));
    }

    #[test]
    fn garbage_signature_is_rejected() {
        let signed = SignedAgentCard {
            card: card_with(ed25519_jwks()),
            signatures: vec![AgentCardSignature {
                protected: "eyJhbGciOiJFUzI1NiJ9".to_string(),
                signature: "bm90LWEtcmVhbC1zaWc".to_string(),
                header: None,
            }],
        };
        // A syntactically-valid P-256 JWK that did not sign this card.
        let key = JsonWebKey::ec_p256(
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        );
        let err = verify_card(&signed, &key).unwrap_err();
        assert!(matches!(err, Error::Verify(_)));
    }
}
