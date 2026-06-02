//! Sign an [`AgentCard`] into a [`SignedAgentCard`] (server/dev only).
//!
//! This module is behind the non-default `sign` feature. It needs a
//! private key and therefore MUST NOT be compiled into a WASM / browser
//! verifier — verification ([`crate::verify`]) is always available and
//! secret-free.
//!
//! The signature produced is a DETACHED RFC 7515 JWS-JSON over the JCS
//! canonicalization of the card: the payload segment is dropped, so the
//! recipient reconstructs it by canonicalizing the card they received.

use crate::card::{AgentCard, AgentCardSignature, SignedAgentCard};
use crate::jcs::canonicalize;
use crate::{Error, Result};

/// Sign an [`AgentCard`] with a PKCS#8-DER P-256 private key, producing a
/// [`SignedAgentCard`] with a single detached ES256 JWS-JSON signature.
///
/// The signature covers `base64url(protected) || "." || base64url(JCS(card))`
/// per RFC 7515, but the payload segment is omitted from the wire form
/// (detached). Header `alg` is `ES256`.
///
/// # Errors
///
/// Returns [`Error`] if canonicalization fails, the key is invalid /
/// signing fails, or the underlying JWS is not the expected three-part
/// compact form.
pub fn sign_card(card: AgentCard, private_key_pkcs8_der: &[u8]) -> Result<SignedAgentCard> {
    // Canonicalize first — this is the exact byte string the verifier will
    // reconstruct and check against.
    let jcs_bytes = canonicalize(&card)?;

    // jws_sign_es256 produces a COMPACT "header.payload.signature" JWS with
    // alg=ES256. We sign the JCS bytes, then strip the payload to make the
    // signature detached.
    let compact = nucleus_identity::did_crypto::jws_sign_es256(&jcs_bytes, private_key_pkcs8_der)
        .map_err(|e| Error::Sign(format!("ES256 signing failed: {e}")))?;

    let parts: Vec<&str> = compact.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(Error::Sign(format!(
            "expected a 3-part compact JWS, got {} part(s)",
            parts.len()
        )));
    }

    // parts[0] = protected header, parts[1] = payload (DROPPED — detached),
    // parts[2] = signature.
    let signature = AgentCardSignature {
        protected: parts[0].to_string(),
        signature: parts[2].to_string(),
        header: None,
    };

    Ok(SignedAgentCard {
        card,
        signatures: vec![signature],
    })
}
