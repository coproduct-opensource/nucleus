//! Sign an [`AgentCard`] per A2A v1.0 §8.4 (server/dev only).
//!
//! This module is behind the non-default `sign` feature. It needs a
//! private key and therefore MUST NOT be compiled into a WASM / browser
//! verifier — verification ([`crate::verify`]) is always available and
//! secret-free.
//!
//! The signature produced is a DETACHED RFC 7515 JWS over the §8.4.1
//! canonical payload (RFC 8785 JCS of the card with `signatures`
//! excluded), appended to the card's own `signatures` array — the v1.0
//! wire placement. The protected header carries `alg`, `typ: "JOSE"` and
//! `kid` as §8.4.2 requires.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::card::{AgentCard, AgentCardSignature};
use crate::jcs::canonicalize;
use crate::{Error, Result};

/// Sign an [`AgentCard`] with a PKCS#8-DER P-256 private key, appending a
/// detached ES256 JWS signature to the card's `signatures` array (§8.4).
///
/// The signature covers `base64url(protected) || "." || base64url(JCS(card
/// minus signatures))` per RFC 7515; the payload segment is omitted from
/// the wire form (detached) — a recipient reconstructs it from the card
/// they received. The protected header is
/// `{"alg":"ES256","typ":"JOSE","kid":<kid>}` per §8.4.2 (`alg` and `kid`
/// MUST be present; `typ` SHOULD be `"JOSE"`).
///
/// `kid` identifies the signing key for recipients who resolve keys from a
/// JWKS — but note the verify-side trust model: [`crate::verify_card`]
/// never selects a key by `kid`; the verification key is always the
/// caller's out-of-band-resolved key.
///
/// Signing is append-only: any signatures already on the card are kept
/// (§8.4.3 allows multiple signatures for key rotation / co-signing), and
/// the canonical payload excludes them all, so earlier signatures stay
/// valid.
///
/// # Errors
///
/// Returns [`Error`] if canonicalization fails, the key is invalid /
/// signing fails, or the underlying JWS is not the expected three-part
/// compact form.
pub fn sign_card(
    mut card: AgentCard,
    private_key_pkcs8_der: &[u8],
    kid: &str,
) -> Result<AgentCard> {
    // Canonicalize first — this is the exact byte string the verifier will
    // reconstruct and check against (signatures excluded, §8.4.1 rule 3).
    let jcs_bytes = canonicalize(&card)?;

    // §8.4.2 protected header: alg + kid REQUIRED, typ SHOULD be "JOSE".
    // serde_json::to_string escapes the kid correctly; the header bytes are
    // carried verbatim in `protected`, so key order here is irrelevant to
    // verification.
    let protected_header = serde_json::to_string(&serde_json::json!({
        "alg": "ES256",
        "typ": "JOSE",
        "kid": kid,
    }))
    .map_err(|e| Error::Sign(format!("serialize protected header: {e}")))?;

    // jws_sign_es256_with_protected_header produces a COMPACT
    // "header.payload.signature" JWS. We sign the JCS bytes, then strip the
    // payload to make the signature detached.
    let compact = nucleus_identity::did_crypto::jws_sign_es256_with_protected_header(
        &protected_header,
        &jcs_bytes,
        private_key_pkcs8_der,
    )
    .map_err(|e| Error::Sign(format!("ES256 signing failed: {e}")))?;

    let parts: Vec<&str> = compact.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(Error::Sign(format!(
            "expected a 3-part compact JWS, got {} part(s)",
            parts.len()
        )));
    }

    // Sanity-pin the detached payload to the canonical bytes we computed —
    // a drift here would produce signatures nobody can verify.
    debug_assert_eq!(parts[1], URL_SAFE_NO_PAD.encode(&jcs_bytes));

    // parts[0] = protected header, parts[1] = payload (DROPPED — detached),
    // parts[2] = signature.
    card.signatures.push(AgentCardSignature {
        protected: parts[0].to_string(),
        signature: parts[2].to_string(),
        header: None,
    });

    Ok(card)
}
