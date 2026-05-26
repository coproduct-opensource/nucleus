//! [`PayloadBinding`] — detached DSSE-style signature that ties the
//! [`crate::Bundle::payload`] bytes to the envelope it travels with.
//!
//! Closes the v1 documented limitation that the envelope chain
//! authenticates the lineage but not the payload bytes the customer
//! ultimately consumes. With a binding present, a verifier can detect
//! payload-only tampering even when every per-edge signature still
//! checks out.
//!
//! # Wire model
//!
//! Aligned with DSSE ("Dead Simple Signing Envelope", used by Sigstore,
//! in-toto, SLSA) — specifically its Pre-Authentication Encoding
//! (PAE), which avoids the JSON-canonicalization pitfalls that
//! plagued earlier schemes. PAE prefixes each field with its byte
//! length, so two distinct JSON formattings of the same value
//! produce the same signed bytes.
//!
//! The signed bytes are:
//!
//! ```text
//! PAE("DSSEv1", payload_type, sha256(canonical_payload) || envelope_head_hash || merkle_root_or_empty)
//! ```
//!
//! Where `canonical_payload` is the payload serialized via
//! `serde_json::to_vec` (deterministic per-field-order for objects
//! that derive `Serialize` — the producer and verifier must use the
//! same serializer; today both use serde_json's default).
//!
//! # Signing identity
//!
//! The binding signature comes from the producer's edge-signing key
//! (the same `EdgeSigner` that signs `LineageEdge` proofs). The
//! `keyid` in the binding looks up into the trust anchor's JWKS —
//! the same out-of-band trust path as everything else. No new key
//! material to distribute.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Detached binding signature over `(payload_hash, envelope_head_hash,
/// optional merkle_root)`. When present on a [`crate::Bundle`], it
/// proves the payload and envelope were assembled together by a
/// producer holding the key identified by `keyid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadBinding {
    /// DSSE-style content type tag. Default for nucleus bundles is
    /// `"application/vnd.nucleus.bundle+json"`. Verifiers MUST check
    /// this against an expected value before treating the signature
    /// as authoritative.
    pub payload_type: String,
    /// SHA-256 of `serde_json::to_vec(&payload)`, hex-encoded.
    pub payload_hash_hex: String,
    /// Hash of the envelope's chain head — matches
    /// [`crate::VerificationReport::head_edge_hash_hex`].
    pub envelope_head_hash_hex: String,
    /// **v2 binding extension.** When the bundle has a Merkle anchor,
    /// this is `Some(sth.root_hash_hex)`. When absent, the binding
    /// covers only the chain head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root_hex: Option<String>,
    /// JWS-style key id — the verifier looks this up in the trust
    /// anchor's JWKS (NOT the envelope's embedded JWKS — the latter
    /// is producer-controlled).
    pub keyid: String,
    /// Ed25519 signature over [`pae_bytes`].
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// Errors raised while building or verifying a [`PayloadBinding`].
#[derive(Debug, Error)]
pub enum BindingError {
    #[error("serializing payload for binding hash: {0}")]
    SerializePayload(#[from] serde_json::Error),
    #[error("hex decode failed for field {field}: {detail}")]
    HexDecode { field: &'static str, detail: String },
    #[error("recomputed payload hash {got} does not match binding {expected}")]
    PayloadHashMismatch { got: String, expected: String },
    #[error("recomputed envelope head hash {got} does not match binding {expected}")]
    EnvelopeHeadMismatch { got: String, expected: String },
    #[error("merkle root mismatch between binding ({expected}) and anchor ({got})")]
    MerkleRootMismatch { got: String, expected: String },
    #[error(
        "binding present but envelope has merkle_anchor — binding must include merkle_root_hex"
    )]
    BindingMissingMerkleRoot,
    #[error(
        "binding includes merkle_root_hex but envelope has no merkle_anchor; reject as malformed"
    )]
    BindingHasMerkleRootWithoutAnchor,
    #[error("binding keyid {keyid:?} not in trust anchor's JWKS")]
    UnknownKeyId { keyid: String },
    #[error("binding signature did not verify")]
    BadSignature,
    #[error("binding signature length {got} != 64 bytes (Ed25519)")]
    BadSignatureLength { got: usize },
}

/// DSSE Pre-Authentication Encoding. Per the spec:
///
/// ```text
/// PAE(type, body...) = "DSSEv1" SP LEN(type) SP type SP LEN(body[0]) SP body[0] ...
/// ```
///
/// We accept a `payload_type` plus N pre-hashed byte sequences. Length
/// prefixes are ASCII decimal followed by a space.
///
/// Note: callers should pass *hashes* of large fields rather than the
/// raw bytes, both because PAE expands every field into the message
/// and because we want the binding's bytes to be small.
pub fn pae_bytes(payload_type: &str, body_fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        64 + payload_type.len() + body_fields.iter().map(|f| f.len() + 16).sum::<usize>(),
    );
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    for field in body_fields {
        out.push(b' ');
        out.extend_from_slice(field.len().to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(field);
    }
    out
}

/// Compute the SHA-256 of `serde_json::to_vec(payload)` — the payload
/// hash field the binding covers.
pub fn payload_hash(payload: &serde_json::Value) -> Result<[u8; 32], BindingError> {
    let bytes = serde_json::to_vec(payload)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(h.finalize().into())
}

/// Build the byte string a binding signature covers, given the
/// pre-computed component hashes / strings.
pub fn signed_bytes(
    payload_type: &str,
    payload_hash_bytes: &[u8; 32],
    envelope_head_hash_bytes: &[u8; 32],
    merkle_root_bytes: Option<&[u8; 32]>,
) -> Vec<u8> {
    // Field 0: payload SHA-256
    // Field 1: envelope head hash
    // Field 2: merkle root (when present) — explicitly absent (zero-len) when not
    let merkle_field: &[u8] = merkle_root_bytes.map(|m| &m[..]).unwrap_or(&[]);
    pae_bytes(
        payload_type,
        &[payload_hash_bytes, envelope_head_hash_bytes, merkle_field],
    )
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// Default MIME-style content type for nucleus bundles.
pub const NUCLEUS_BUNDLE_PAYLOAD_TYPE: &str = "application/vnd.nucleus.bundle+json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_spec_for_simple_input() {
        // Hand-computed reference for DSSEv1 PAE.
        // type = "test", one body field = "hi"
        // → "DSSEv1 4 test 2 hi"
        let out = pae_bytes("test", &[b"hi"]);
        assert_eq!(&out, b"DSSEv1 4 test 2 hi");
    }

    #[test]
    fn pae_two_fields() {
        let out = pae_bytes("ct", &[b"aaa", b"bb"]);
        assert_eq!(&out, b"DSSEv1 2 ct 3 aaa 2 bb");
    }

    #[test]
    fn signed_bytes_changes_when_payload_changes() {
        let a = signed_bytes("t", &[0u8; 32], &[1u8; 32], None);
        let mut altered = [0u8; 32];
        altered[0] = 0xFF;
        let b = signed_bytes("t", &altered, &[1u8; 32], None);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_bytes_changes_when_envelope_changes() {
        let a = signed_bytes("t", &[0u8; 32], &[1u8; 32], None);
        let mut altered = [1u8; 32];
        altered[0] = 0xFF;
        let b = signed_bytes("t", &[0u8; 32], &altered, None);
        assert_ne!(a, b);
    }

    #[test]
    fn signed_bytes_changes_when_merkle_root_added() {
        let a = signed_bytes("t", &[0u8; 32], &[1u8; 32], None);
        let b = signed_bytes("t", &[0u8; 32], &[1u8; 32], Some(&[2u8; 32]));
        assert_ne!(a, b, "v1 and v2 bindings over same payload must differ");
    }

    #[test]
    fn payload_hash_is_stable() {
        let p = serde_json::json!({"x": 1, "y": "hello"});
        let h1 = payload_hash(&p).unwrap();
        let h2 = payload_hash(&p).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn payload_hash_differs_for_different_payloads() {
        let p1 = serde_json::json!({"x": 1});
        let p2 = serde_json::json!({"x": 2});
        assert_ne!(payload_hash(&p1).unwrap(), payload_hash(&p2).unwrap());
    }
}
