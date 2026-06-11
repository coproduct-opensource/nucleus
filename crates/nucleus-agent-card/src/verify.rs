//! Verify a signed [`AgentCard`] against an OUT-OF-BAND-resolved key
//! (A2A v1.0 §8.4.3).
//!
//! This module is ALWAYS compiled (no feature gate) and is secret-free —
//! a browser/WASM verifier can use it without ever touching a private key.
//!
//! # Two layers, kept apart
//!
//! 1. **§8.4.3 signature verification** — [`verify_card_signature`] /
//!    [`verify_card_signature_json`]. Pure spec: canonicalize the card
//!    minus its `signatures` member (§8.4.1), reconstruct each detached
//!    JWS, accept if ANY signature verifies against the caller's resolved
//!    key (§8.4.3 allows multiple signatures for key rotation). A validly
//!    signed *plain* A2A card — no nucleus extension, e.g. one produced by
//!    a2a-python — passes this layer.
//!
//! 2. **Nucleus claims policy** — layered on top by [`verify_card`] /
//!    [`verify_card_json`]: the card must carry the nucleus extension with
//!    well-formed claims and a usable `trust_jwks`, because the
//!    verify-before-you-act flow anchors bundles on them. Policy failures
//!    say so explicitly ("nucleus claims policy …") — they are NOT
//!    signature failures.
//!
//! # Verify the received document, not a re-serialization
//!
//! §8.4.3 steps 3–6 operate on "the received Agent Card". When the caller
//! holds the raw JSON it received, it should verify through
//! [`verify_card_json`] / [`verify_card_signature_json`], which
//! canonicalize the document AS RECEIVED (see
//! [`crate::jcs::canonicalize_received`]). Verifying a re-serialized typed
//! struct instead has two §8.4.3 violations: a member the struct does not
//! model is silently dropped, so (a) an attacker-injected unknown member
//! escapes the signature check (fail-open), and (b) a card legitimately
//! signed by a newer implementation over an unmodeled member can never
//! verify (fail-closed, contradicting the crate's forward-compat
//! documentation). The struct-input functions remain for callers who only
//! have a typed card — for them the struct IS the received artifact.
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

use crate::card::{AgentCard, AgentCardSignature, NucleusClaims};
use crate::jcs::canonicalize_received;
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

/// §8.4.3 signature verification ONLY, over a typed [`AgentCard`], using a
/// key the caller resolved out-of-band.
///
/// Steps (§8.4.3):
///
/// 1. Canonicalize the card minus its `signatures` member to the §8.4.1
///    JCS payload, and derive the detached JWS payload segment
///    `base64url_nopad(JCS)`.
/// 2. For EACH entry of the `signatures` array (the spec allows multiple
///    for key rotation / co-signing): require a non-empty `kid` in the
///    protected header (§8.4.2 format conformance — the value is never
///    used to select a key), reconstruct the compact JWS
///    `protected.payload.signature`, and verify it via the wasm-clean
///    ES256 verifier in [`crate::jwk`] against `resolved_key`.
/// 3. Succeed if ANY entry verifies. This introduces no card-controlled
///    key selection — every entry is checked against the same
///    caller-resolved key, and work is bounded by the array length.
///
/// No nucleus policy is applied: a validly signed plain A2A card (no
/// nucleus extension) passes. Layer [`verify_card`] /
/// [`verify_card_json`] on top when you need the claims.
///
/// Prefer [`verify_card_signature_json`] when you hold the raw received
/// document — see the module docs on verifying what was received.
///
/// # Errors
///
/// Returns [`Error::Verify`] on: no signatures, or no entry that both
/// carries a `kid` (§8.4.2) and verifies against `resolved_key`.
pub fn verify_card_signature(card: &AgentCard, resolved_key: &JsonWebKey) -> Result<()> {
    let received = serde_json::to_value(card).map_err(|e| Error::Canonicalize(e.to_string()))?;
    verify_card_signature_json(&received, resolved_key)
}

/// §8.4.3 signature verification ONLY, over the RECEIVED Agent Card
/// document (raw JSON), using a key the caller resolved out-of-band.
///
/// Canonicalization is [`canonicalize_received`]: remove the `signatures`
/// member (§8.4.1 rule 3), keep every other member exactly as received,
/// JCS-canonicalize — so the signature is checked over what was actually
/// received, unknown/unmodeled members included. Signature iteration and
/// the trust model are as in [`verify_card_signature`].
///
/// # Errors
///
/// Returns [`Error::Verify`] on: a `signatures` member that does not parse
/// as JWS entries, no signatures, or no entry that both carries a `kid`
/// (§8.4.2) and verifies against `resolved_key`; [`Error::Canonicalize`]
/// if the document is not a JSON object.
pub fn verify_card_signature_json(
    received: &serde_json::Value,
    resolved_key: &JsonWebKey,
) -> Result<()> {
    let signatures: Vec<AgentCardSignature> = match received.get("signatures") {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
            Error::Verify(format!(
                "the card's signatures member does not parse as AgentCardSignature entries: {e}"
            ))
        })?,
        None => Vec::new(),
    };

    let canonical = canonicalize_received(received)?;
    verify_any_signature(&signatures, &canonical, resolved_key)
}

/// Verify a signed [`AgentCard`] using a key the caller resolved
/// out-of-band, and extract its [`NucleusClaims`].
///
/// Two layers (see the module docs):
///
/// 1. Pure §8.4.3 signature verification — [`verify_card_signature`]:
///    JCS canonicalization minus `signatures`, detached-JWS verification
///    of EVERY signature entry against `resolved_key`, success if any
///    verifies.
/// 2. The nucleus claims policy: the card MUST declare the nucleus
///    extension with well-formed [`NucleusClaims`] — this function exists
///    for the verify-before-you-act flow, and a card with no claims
///    cannot anchor anything downstream — and the claimed `trust_jwks`
///    MUST be non-empty and well-formed (an advertised-but-unusable JWKS
///    can't anchor anything either).
///
/// Prefer [`verify_card_json`] when you hold the raw received document.
///
/// # Errors
///
/// Returns [`Error`] on: no signatures, a protected header missing `kid`
/// (§8.4.2), signature/JWS verification failure, payload mismatch (all
/// from layer 1), or — explicitly labelled as nucleus claims POLICY
/// failures, not signature failures — a missing/malformed nucleus
/// extension or an empty/malformed `trust_jwks` (layer 2).
pub fn verify_card(card: &AgentCard, resolved_key: &JsonWebKey) -> Result<VerifiedCard> {
    verify_card_signature(card, resolved_key)?;
    apply_nucleus_policy(card.clone())
}

/// Verify a signed Agent Card from the RAW JSON DOCUMENT the caller
/// received, using a key resolved out-of-band, and extract its
/// [`NucleusClaims`].
///
/// Same two layers as [`verify_card`], but layer 1 runs over the received
/// document via [`verify_card_signature_json`] — §8.4.3's "the received
/// Agent Card", so an attacker-injected unknown member is REJECTED (the
/// signature does not cover it) and a card legitimately signed by a newer
/// implementation over an unmodeled member still VERIFIES. Use this
/// whenever the card reached you as bytes/string (HTTP body, credential
/// field, well-known fetch).
///
/// # Errors
///
/// Returns [`Error`] on: invalid JSON, any layer-1 signature failure (see
/// [`verify_card_signature_json`]), a verified document that does not
/// parse as an A2A v1.0 [`AgentCard`], or a nucleus claims POLICY failure
/// (see [`verify_card`]).
pub fn verify_card_json(received_json: &str, resolved_key: &JsonWebKey) -> Result<VerifiedCard> {
    let received: serde_json::Value = serde_json::from_str(received_json)
        .map_err(|e| Error::Verify(format!("received Agent Card is not valid JSON: {e}")))?;
    verify_card_signature_json(&received, resolved_key)?;

    // The signature verified over the received bytes; now type the card.
    // Unknown members are ignored on parse (forward-compat) — they were
    // still covered by the signature check above.
    let card: AgentCard = serde_json::from_value(received).map_err(|e| {
        Error::Verify(format!(
            "signature verified, but the document does not parse as an A2A v1.0 AgentCard: {e}"
        ))
    })?;
    apply_nucleus_policy(card)
}

/// Layer 2: the nucleus claims policy. Only called AFTER the §8.4.3
/// signature verified — every rejection here is a POLICY decision about
/// what nucleus's verify-before-you-act flow can anchor on, and says so.
fn apply_nucleus_policy(card: AgentCard) -> Result<VerifiedCard> {
    // The nucleus claims are required for verify-before-you-act.
    let claims = card.nucleus_claims()?.ok_or_else(|| {
        Error::Verify(format!(
            "nucleus claims policy (the \u{a7}8.4.3 signature verified; this is not a \
             signature failure): card does not declare the nucleus extension ({}) — \
             nothing to anchor on",
            crate::card::NUCLEUS_EXTENSION_URI
        ))
    })?;

    // Reject an unusable advertised JWKS up front. An empty or malformed
    // trust_jwks can't anchor any bundle, so a card carrying one is
    // useless for verify-before-you-act — fail loudly here rather than
    // let the caller build a TrustAnchor that rejects everything.
    reject_unusable_jwks(&claims.trust_jwks).map_err(|e| {
        Error::Verify(format!(
            "nucleus claims policy (the \u{a7}8.4.3 signature verified; this is not a \
             signature failure): {e}"
        ))
    })?;

    Ok(VerifiedCard { card, claims })
}

/// §8.4.3 over the whole `signatures` array: succeed if ANY entry both
/// conforms to §8.4.2 (non-empty `kid`) and verifies against the caller's
/// resolved key. Multiple signatures exist for key rotation — a card
/// co-signed by an old and a new key must verify for a holder of EITHER
/// key, so a failing entry never masks a later valid one. Work is bounded
/// by the array length, and the key is always the caller's: iterating
/// entries introduces no card-controlled key selection.
fn verify_any_signature(
    signatures: &[AgentCardSignature],
    canonical: &[u8],
    resolved_key: &JsonWebKey,
) -> Result<()> {
    if signatures.is_empty() {
        return Err(Error::Verify("card has no signatures".to_string()));
    }

    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical);
    let mut failures: Vec<String> = Vec::with_capacity(signatures.len());
    for sig in signatures {
        match verify_one_signature(sig, canonical, &payload_b64, resolved_key) {
            Ok(()) => return Ok(()),
            Err(reason) => failures.push(reason),
        }
    }

    if failures.len() == 1 {
        return Err(Error::Verify(failures.remove(0)));
    }
    let detail: Vec<String> = failures
        .iter()
        .enumerate()
        .map(|(i, f)| format!("[{i}] {f}"))
        .collect();
    Err(Error::Verify(format!(
        "none of the card's {} signatures verified against the resolved key: {}",
        failures.len(),
        detail.join("; ")
    )))
}

/// One §8.4.3 signature entry against the caller's resolved key.
fn verify_one_signature(
    sig: &AgentCardSignature,
    canonical: &[u8],
    payload_b64: &str,
    resolved_key: &JsonWebKey,
) -> std::result::Result<(), String> {
    // §8.4.2 format conformance: the protected header MUST carry `kid`
    // (and `alg`, which jws_verify_es256 pins to ES256 below). We REQUIRE
    // kid's presence without ever using its value for key selection — the
    // verification key stays the caller's out-of-band-resolved one.
    require_kid(&sig.protected)?;

    // Reconstruct the COMPACT JWS string the detached signature implies:
    // protected "." base64url(JCS) "." signature.
    let compact = format!("{}.{}.{}", sig.protected, payload_b64, sig.signature);

    // Verify against the OUT-OF-BAND-resolved key ONLY. Never the card's
    // own material, never the protected header's kid/jku.
    // `jws_verify_es256` (wasm-clean, pure-Rust p256 — see crate::jwk)
    // returns the decoded payload.
    let recovered = crate::jwk::jws_verify_es256(&compact, resolved_key)
        .map_err(|e| format!("JWS verification failed: {e}"))?;

    // Defense in depth: the recovered payload MUST equal the canonical
    // bytes. With the reconstruction above this is structurally
    // guaranteed, but asserting it pins the contract so a future change
    // to the JWS reconstruction can't silently verify a different
    // payload than the card.
    if recovered != canonical {
        return Err("verified JWS payload does not equal the card's JCS bytes".to_string());
    }
    Ok(())
}

/// §8.4.2: the JWS protected header MUST include `kid`. Presence-only —
/// the value is never used to resolve a key (see the trust model note on
/// [`verify_card`]).
fn require_kid(protected_b64: &str) -> std::result::Result<(), String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(protected_b64)
        .map_err(|e| format!("protected header is not valid base64url: {e}"))?;
    let header: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("protected header is not valid JSON: {e}"))?;
    match header.get("kid").and_then(serde_json::Value::as_str) {
        Some(kid) if !kid.is_empty() => Ok(()),
        Some(_) => {
            Err("protected header carries an empty kid (\u{a7}8.4.2 requires a key id)".to_string())
        }
        None => Err("protected header is missing kid (\u{a7}8.4.2 requires it)".to_string()),
    }
}

/// Reject an empty or malformed advertised JWKS.
///
/// Malformed = a key entry that can't be turned into a verifying key
/// (caught by [`nucleus_lineage::Jwks::verifying_key`]).
fn reject_unusable_jwks(jwks: &nucleus_lineage::Jwks) -> std::result::Result<(), String> {
    if jwks.keys.is_empty() {
        return Err("card advertises an empty trust_jwks (anchors nothing)".to_string());
    }
    for key in &jwks.keys {
        // verifying_key() validates kty/crv/alg and decodes `x`. Any error
        // means this advertised key is unusable as a trust anchor.
        jwks.verifying_key(&key.kid).map_err(|e| {
            format!(
                "card advertises a malformed trust_jwks key (kid {:?}): {e}",
                key.kid
            )
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
            security_schemes: Default::default(),
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
    fn no_signatures_is_rejected_on_the_pure_signature_path_too() {
        let card = card_with(ed25519_jwks());
        let key = JsonWebKey::ec_p256("x", "y");
        let err = verify_card_signature(&card, &key).unwrap_err();
        assert!(format!("{err}").contains("no signatures"), "{err}");
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

    #[test]
    fn two_garbage_signatures_report_every_entrys_failure() {
        // Iterating the array must not silently report only one entry's
        // failure when several were tried.
        let mut card = card_with(ed25519_jwks());
        let entry = AgentCardSignature {
            protected: "eyJhbGciOiJFUzI1NiJ9".to_string(),
            signature: "bm90LWEtcmVhbC1zaWc".to_string(),
            header: None,
        };
        card.signatures = vec![entry.clone(), entry];
        let key = JsonWebKey::ec_p256(
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        );
        let err = verify_card(&card, &key).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("none of the card's 2 signatures"), "{msg}");
        assert!(msg.contains("[0]") && msg.contains("[1]"), "{msg}");
    }

    #[test]
    fn received_document_that_is_not_json_is_rejected() {
        let key = JsonWebKey::ec_p256("x", "y");
        let err = verify_card_json("not json at all", &key).unwrap_err();
        assert!(format!("{err}").contains("not valid JSON"), "{err}");
    }

    #[test]
    fn received_document_with_malformed_signatures_member_is_rejected() {
        let key = JsonWebKey::ec_p256("x", "y");
        let received = serde_json::json!({"name": "x", "signatures": "not-an-array"});
        let err = verify_card_signature_json(&received, &key).unwrap_err();
        assert!(
            format!("{err}").contains("does not parse as AgentCardSignature"),
            "{err}"
        );
    }
}
