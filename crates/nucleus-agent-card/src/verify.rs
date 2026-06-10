//! Verify a signed [`AgentCard`] against an OUT-OF-BAND-resolved key
//! (A2A v1.0 §8.4.3).
//!
//! This module is ALWAYS compiled (no feature gate) and is secret-free —
//! a browser/WASM verifier can use it without ever touching a private key.
//!
//! # The one rule that makes this safe
//!
//! The verification key comes ONLY from the caller's `resolved_key`
//! argument — a key the caller obtained out-of-band (DID resolution, a
//! pinned JWKS, an operator file). It is NEVER read from the card or from
//! the `kid`/`jku` the signature's protected header advertises. §8.4.3
//! permits resolving the key "from a trusted key store" — that is the only
//! mode this verifier implements, because a card verified against a key the
//! *attacker* supplied is "verified garbage": the math passes but it
//! proves nothing about who the agent is.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::card::{AgentCard, NucleusClaims};
use crate::jcs::canonicalize;
use crate::jwk::JsonWebKey;
use crate::{Error, Result};

/// A card whose signature verified against the caller's out-of-band key,
/// together with its extracted [`NucleusClaims`].
///
/// Holding a `VerifiedCard` is the proof obligation: you may only call
/// [`Self::advertised_jwks`] (and thence build a TrustAnchor) once the
/// card's authenticity has been established.
#[derive(Debug, Clone)]
pub struct VerifiedCard {
    /// The verified identity document (v1.0 card, signatures included).
    pub card: AgentCard,

    /// The nucleus claims extracted from the card's
    /// [`NUCLEUS_EXTENSION_URI`](crate::card::NUCLEUS_EXTENSION_URI)
    /// extension — covered by the verified signature.
    pub claims: NucleusClaims,
}

impl VerifiedCard {
    /// The JWKS the (now-verified) card advertises as authoritative for
    /// its provenance bundles. Feed this to
    /// [`crate::anchor::trust_anchor_from_card`].
    pub fn advertised_jwks(&self) -> &nucleus_lineage::Jwks {
        &self.claims.trust_jwks
    }
}

/// Verify a signed [`AgentCard`] using a key the caller resolved
/// out-of-band, and extract its [`NucleusClaims`].
///
/// Steps (§8.4.3, with the nucleus trust model on top):
///
/// 1. Take the FIRST entry of the card's `signatures` array.
/// 2. Recompute the §8.4.1 canonical payload — the JCS bytes of the card
///    with `signatures` excluded — and the detached JWS payload segment
///    `base64url_nopad(JCS)`.
/// 3. Reconstruct the compact JWS `protected.payload.signature` and verify
///    it via the wasm-clean ES256 verifier in [`crate::jwk`] against
///    `resolved_key`.
/// 4. Assert the payload `jws_verify_es256` returns equals the canonical
///    bytes — so the signature is bound to *this* card, not some other
///    payload.
/// 5. Extract the [`NucleusClaims`] from the card's nucleus extension —
///    REQUIRED here: this verifier exists for the verify-before-you-act
///    flow, and a card with no claims (or a malformed claim set) cannot
///    anchor anything downstream.
/// 6. Reject if the claimed `trust_jwks` is empty or malformed (an
///    advertised-but-unusable JWKS can't anchor anything either).
///
/// # Errors
///
/// Returns [`Error`] on: no signatures, a protected header missing `kid`
/// (§8.4.2), signature/JWS verification failure, payload mismatch,
/// missing/malformed nucleus extension, or empty/malformed `trust_jwks`.
pub fn verify_card(card: &AgentCard, resolved_key: &JsonWebKey) -> Result<VerifiedCard> {
    // 1) First signature. Multiple signatures are allowed on the wire
    //    (§8.4.3, key rotation), but the trust decision is made against the
    //    caller's resolved key over the first one — we never iterate
    //    looking for "a kid that matches" because that would re-introduce
    //    card-controlled key selection.
    let sig = card
        .signatures
        .first()
        .ok_or(Error::Verify("card has no signatures".to_string()))?;

    // 1b) §8.4.2 format conformance: the protected header MUST carry `kid`
    //     (and `alg`, which jws_verify_es256 pins to ES256 below). We
    //     REQUIRE kid's presence without ever using its value for key
    //     selection — the verification key stays the caller's
    //     out-of-band-resolved one.
    require_kid(&sig.protected)?;

    // 2) Canonical payload (signatures excluded) + detached JWS segment.
    let jcs_bytes = canonicalize(card)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&jcs_bytes);

    // 3) Reconstruct the COMPACT JWS string the detached signature implies:
    //    protected "." base64url(JCS) "." signature.
    let compact = format!("{}.{}.{}", sig.protected, payload_b64, sig.signature);

    // 4) Verify against the OUT-OF-BAND-resolved key ONLY. Never the card's
    //    own material, never the protected header's kid/jku.
    //    `jws_verify_es256` (wasm-clean, pure-Rust p256 — see crate::jwk)
    //    returns the decoded payload.
    let recovered = crate::jwk::jws_verify_es256(&compact, resolved_key)
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

    // 6) Extract the nucleus claims — required for verify-before-you-act.
    let claims = card.nucleus_claims()?.ok_or_else(|| {
        Error::Verify(format!(
            "card does not declare the nucleus extension ({}) — nothing to anchor on",
            crate::card::NUCLEUS_EXTENSION_URI
        ))
    })?;

    // 7) Reject an unusable advertised JWKS up front. An empty or malformed
    //    trust_jwks can't anchor any bundle, so a card carrying one is
    //    useless for verify-before-you-act — fail loudly here rather than
    //    let the caller build a TrustAnchor that rejects everything.
    reject_unusable_jwks(&claims.trust_jwks)?;

    Ok(VerifiedCard {
        card: card.clone(),
        claims,
    })
}

/// §8.4.2: the JWS protected header MUST include `kid`. Presence-only —
/// the value is never used to resolve a key (see the trust model note on
/// [`verify_card`]).
fn require_kid(protected_b64: &str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(protected_b64)
        .map_err(|e| Error::Verify(format!("protected header is not valid base64url: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Verify(format!("protected header is not valid JSON: {e}")))?;
    match header.get("kid").and_then(serde_json::Value::as_str) {
        Some(kid) if !kid.is_empty() => Ok(()),
        Some(_) => Err(Error::Verify(
            "protected header carries an empty kid (\u{a7}8.4.2 requires a key id)".to_string(),
        )),
        None => Err(Error::Verify(
            "protected header is missing kid (\u{a7}8.4.2 requires it)".to_string(),
        )),
    }
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
    use crate::card::{
        AgentCapabilities, AgentCardSignature, AgentInterface, A2A_PROTOCOL_VERSION,
    };

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
            name: "Coder Agent".to_string(),
            description: "verify tests".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: "https://coder.prod.example.com/a2a/v1".to_string(),
                protocol_binding: "JSONRPC".to_string(),
                tenant: None,
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            }],
            provider: None,
            version: "1.0.0".to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities::default(),
            security_schemes: serde_json::Map::new(),
            security_requirements: vec![],
            default_input_modes: vec!["application/json".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![],
            signatures: vec![],
            icon_url: None,
        }
        .with_nucleus_claims(&NucleusClaims {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            did: "did:web:coder.prod.example.com".to_string(),
            supported_envelope_schema_versions: vec!["1".to_string()],
            jwks_uri: None,
            trust_jwks: jwks,
            runtime_guarantees: None,
        })
        .unwrap()
    }

    #[test]
    fn no_signatures_is_rejected() {
        let card = card_with(ed25519_jwks());
        let key = JsonWebKey::ec_p256("x", "y");
        let err = verify_card(&card, &key).unwrap_err();
        assert!(matches!(err, Error::Verify(_)));
    }

    #[test]
    fn garbage_signature_is_rejected() {
        let mut card = card_with(ed25519_jwks());
        card.signatures = vec![AgentCardSignature {
            protected: "eyJhbGciOiJFUzI1NiJ9".to_string(),
            signature: "bm90LWEtcmVhbC1zaWc".to_string(),
            header: None,
        }];
        // A syntactically-valid P-256 JWK that did not sign this card.
        let key = JsonWebKey::ec_p256(
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        );
        let err = verify_card(&card, &key).unwrap_err();
        assert!(matches!(err, Error::Verify(_)));
    }
}
