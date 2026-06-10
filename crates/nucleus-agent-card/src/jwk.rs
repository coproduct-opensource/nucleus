//! Minimal JSON Web Key + wasm-clean ES256 detached-JWS verification.
//!
//! This lives here (rather than reusing `nucleus_identity::JsonWebKey` +
//! `did_crypto::jws_verify_es256`) so the ALWAYS-ON verify path carries no
//! native-only crypto: `nucleus-identity`'s closure (ring, tokio) does not
//! compile to `wasm32-unknown-unknown`, and the WASM verifier SDK consumes
//! [`crate::verify::verify_card`] directly. Verification here uses the
//! pure-Rust `p256` crate; the wire shape of [`JsonWebKey`] is identical to
//! `nucleus_identity::JsonWebKey`, so JWKs resolved out-of-band parse the
//! same on every target.
//!
//! The `sign` feature (server/dev only) still signs through
//! `nucleus_identity::did_crypto::jws_sign_es256` (ring). Sign↔verify
//! parity across the two backends is pinned by the round-trip tests in
//! `sign_verify_tests.rs`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A JSON Web Key carrying the out-of-band-resolved public key a caller
/// verifies a [`crate::SignedAgentCard`] against.
///
/// Wire-compatible with `nucleus_identity::JsonWebKey` — same field names
/// and optionality — but defined here so the verify path stays wasm-clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key type (e.g., `"EC"`, `"OKP"`).
    pub kty: String,

    /// Curve (e.g., `"P-256"`, `"Ed25519"`).
    pub crv: String,

    /// Public key X coordinate (base64url-encoded).
    pub x: String,

    /// Public key Y coordinate (base64url-encoded, EC keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Algorithm (e.g., `"ES256"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

impl JsonWebKey {
    /// Create a new EC P-256 JWK from base64url-encoded coordinates.
    pub fn ec_p256(x: impl Into<String>, y: impl Into<String>) -> Self {
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: x.into(),
            y: Some(y.into()),
            kid: None,
            alg: None,
        }
    }
}

/// Verify a compact ES256 JWS (`header.payload.signature`, all base64url)
/// against a P-256 [`JsonWebKey`], returning the decoded payload bytes.
///
/// Semantics mirror `nucleus_identity::did_crypto::jws_verify_es256`
/// exactly (same checks, same order): 3-part shape, `ES256` in the header,
/// EC/P-256 key type, uncompressed-point reconstruction from `x`/`y`,
/// fixed-width (r||s) signature, ECDSA-P256-SHA256 over
/// `header_b64.payload_b64`.
pub(crate) fn jws_verify_es256(jws: &str, public_key: &JsonWebKey) -> Result<Vec<u8>, String> {
    // Split the compact JWS into its three parts.
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("JWS must have exactly 3 dot-separated parts".to_string());
    }
    let [header_b64, payload_b64, sig_b64] = [parts[0], parts[1], parts[2]];

    // Validate the header declares ES256.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| format!("invalid base64url header: {e}"))?;
    let header_str = std::str::from_utf8(&header_bytes)
        .map_err(|e| format!("header is not valid UTF-8: {e}"))?;
    if !header_str.contains("\"ES256\"") {
        return Err(format!("unsupported JWS algorithm: {header_str}"));
    }

    // Reconstruct the public key from the JWK coordinates.
    if public_key.kty != "EC" || public_key.crv != "P-256" {
        return Err(format!(
            "unsupported key type: kty={}, crv={}",
            public_key.kty, public_key.crv
        ));
    }
    let y = public_key
        .y
        .as_deref()
        .ok_or_else(|| "EC P-256 JWK missing y coordinate".to_string())?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(&public_key.x)
        .map_err(|e| format!("invalid base64url x coordinate: {e}"))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| format!("invalid base64url y coordinate: {e}"))?;

    // Uncompressed SEC1 point: 0x04 || x || y. from_sec1_bytes validates the
    // point is on the curve.
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x_bytes);
    uncompressed.extend_from_slice(&y_bytes);
    let verifying_key = VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| format!("invalid EC P-256 public key: {e}"))?;

    // Decode the fixed-width (r||s) signature.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| format!("invalid base64url signature: {e}"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("invalid ECDSA signature encoding: {e}"))?;

    // The signed message is `header_b64.payload_b64`; the Verifier impl
    // hashes it with SHA-256 (ES256).
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "ECDSA signature verification failed".to_string())?;

    // Decode and return the payload.
    URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("invalid base64url payload: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_jws_shape() {
        let jwk = JsonWebKey::ec_p256("x", "y");
        assert!(jws_verify_es256("only.two", &jwk).is_err());
        assert!(jws_verify_es256("", &jwk).is_err());
    }

    #[test]
    fn rejects_non_es256_header() {
        let jwk = JsonWebKey::ec_p256("x", "y");
        // {"alg":"none"} base64url, with dummy payload + signature parts.
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let err = jws_verify_es256(&format!("{header}.cGF5bG9hZA.c2ln"), &jwk).unwrap_err();
        assert!(err.contains("unsupported JWS algorithm"), "got: {err}");
    }

    #[test]
    fn rejects_non_p256_key() {
        let jwk = JsonWebKey {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "AAAA".into(),
            y: None,
            kid: None,
            alg: None,
        };
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#);
        let err = jws_verify_es256(&format!("{header}.cGF5bG9hZA.c2ln"), &jwk).unwrap_err();
        assert!(err.contains("unsupported key type"), "got: {err}");
    }

    #[test]
    fn json_wire_shape_matches_identity_jwk() {
        // The serde shape must stay identical to nucleus_identity::JsonWebKey
        // so out-of-band-resolved JWKs parse the same on every target.
        let jwk = JsonWebKey::ec_p256("xxx", "yyy");
        let json = serde_json::to_value(&jwk).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": "xxx", "y": "yyy"})
        );
    }
}
