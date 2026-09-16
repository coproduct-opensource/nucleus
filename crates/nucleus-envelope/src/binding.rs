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
//! The signed bytes (schema version 2) are:
//!
//! ```text
//! PAE("DSSEv1", payload_type,
//!     sha256(JCS(payload)), envelope_head_hash, merkle_root_or_empty, JCS(meta))
//! ```
//!
//! `JCS` is RFC 8785, the canonicalization `nucleus-receipt` signs. Two
//! consequences, both deliberate:
//!
//! - key order and whitespace do not change the hash, in any build — plain
//!   `serde_json::to_vec` (schema version 1) followed
//!   `serde_json/preserve_order`, so a producer and a verifier built with
//!   different feature sets disagreed about the same payload;
//! - JSON numbers are compared as values: `1` and `1.0` are one number. An
//!   integer JCS cannot represent exactly (beyond ±2^53 − 1) is refused rather
//!   than hashed, because it would collide with its neighbours.
//!
//! `meta` is [`crate::EnvelopeMeta`] — `schema_version` and `created_at`,
//! which version 1 left unauthenticated.
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

use crate::bundle::EnvelopeMeta;

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
    /// SHA-256 of the payload's RFC 8785 canonical form, hex-encoded (see
    /// [`payload_hash`]).
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
    /// The payload holds an integer RFC 8785 cannot represent exactly, so its
    /// canonical form would collide with a neighbouring integer's.
    #[error("payload integer at {path:?} is beyond ±(2^53 − 1) and has no exact canonical form")]
    InexactInteger { path: String },
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

/// SHA-256 of the payload's RFC 8785 (JCS) canonical form — the payload
/// hash field the binding covers.
///
/// Canonical, so the hash does not depend on key order, on
/// `serde_json/preserve_order`, or on which binary serialized the payload.
///
/// **Refuses integers JCS cannot represent exactly.** JCS writes every number
/// as an IEEE-754 double, so `9007199254740993` and `9007199254740992`
/// canonicalize identically: a payload carrying either would verify with the
/// other substituted. Such a payload is refused rather than hashed.
pub fn payload_hash(payload: &serde_json::Value) -> Result<[u8; 32], BindingError> {
    if let Some(path) = nucleus_receipt::jcs_inexact_integer(payload) {
        return Err(BindingError::InexactInteger { path });
    }
    let bytes = serde_json_canonicalizer::to_vec(payload)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(h.finalize().into())
}

/// Build the byte string a binding signature covers, given the
/// pre-computed component hashes and the envelope metadata.
///
/// Schema version 2 added field 3, the RFC 8785 form of [`EnvelopeMeta`].
/// A version-1 signature covers three fields and cannot verify against these
/// bytes.
pub fn signed_bytes(
    payload_type: &str,
    payload_hash_bytes: &[u8; 32],
    envelope_head_hash_bytes: &[u8; 32],
    merkle_root_bytes: Option<&[u8; 32]>,
    meta: &EnvelopeMeta,
) -> Result<Vec<u8>, BindingError> {
    // Field 0: payload SHA-256 (over JCS)
    // Field 1: envelope head hash
    // Field 2: merkle root (when present) — explicitly absent (zero-len) when not
    // Field 3: JCS(meta) — schema_version and created_at
    let merkle_field: &[u8] = merkle_root_bytes.map(|m| &m[..]).unwrap_or(&[]);
    let meta_field = serde_json_canonicalizer::to_vec(meta)?;
    Ok(pae_bytes(
        payload_type,
        &[
            payload_hash_bytes,
            envelope_head_hash_bytes,
            merkle_field,
            &meta_field,
        ],
    ))
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
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

    fn meta() -> EnvelopeMeta {
        EnvelopeMeta {
            schema_version: crate::bundle::ENVELOPE_SCHEMA_VERSION,
            created_at: "2026-09-16T00:00:00.123456Z".parse().unwrap(),
        }
    }

    fn signed(
        payload: &[u8; 32],
        head: &[u8; 32],
        root: Option<&[u8; 32]>,
        m: &EnvelopeMeta,
    ) -> Vec<u8> {
        signed_bytes("t", payload, head, root, m).unwrap()
    }

    #[test]
    fn signed_bytes_changes_when_payload_changes() {
        let a = signed(&[0u8; 32], &[1u8; 32], None, &meta());
        let mut altered = [0u8; 32];
        altered[0] = 0xFF;
        let b = signed(&altered, &[1u8; 32], None, &meta());
        assert_ne!(a, b);
    }

    #[test]
    fn signed_bytes_changes_when_envelope_changes() {
        let a = signed(&[0u8; 32], &[1u8; 32], None, &meta());
        let mut altered = [1u8; 32];
        altered[0] = 0xFF;
        let b = signed(&[0u8; 32], &altered, None, &meta());
        assert_ne!(a, b);
    }

    #[test]
    fn signed_bytes_changes_when_merkle_root_added() {
        let a = signed(&[0u8; 32], &[1u8; 32], None, &meta());
        let b = signed(&[0u8; 32], &[1u8; 32], Some(&[2u8; 32]), &meta());
        assert_ne!(a, b, "anchored and unanchored bindings must differ");
    }

    /// Schema version 2: the metadata is signed, both of its fields.
    #[test]
    fn signed_bytes_change_when_either_meta_field_changes() {
        let base = signed(&[0u8; 32], &[1u8; 32], None, &meta());
        let mut older = meta();
        older.schema_version = 1;
        let mut later = meta();
        later.created_at += chrono::Duration::nanoseconds(1);
        assert_ne!(base, signed(&[0u8; 32], &[1u8; 32], None, &older));
        assert_ne!(base, signed(&[0u8; 32], &[1u8; 32], None, &later));
    }

    /// The hash is RFC 8785: key order on the wire does not reach it, even when
    /// `serde_json/preserve_order` keeps that order in the `Value`.
    #[test]
    fn payload_hash_ignores_key_order() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"b":{"y":1,"x":[2,{"q":0,"p":1}]},"a":true}"#).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(r#"{"a":true,"b":{"x":[2,{"p":1,"q":0}],"y":1}}"#).unwrap();
        assert_eq!(payload_hash(&a).unwrap(), payload_hash(&b).unwrap());
    }

    /// Pinned to the RFC 8785 bytes, so a regression shows in every build — not
    /// only in one where `preserve_order` happens to be unified on. `15.0` is where
    /// JCS (`15`) and `serde_json` (`15.0`) disagree even with sorted keys.
    #[test]
    fn payload_hash_is_sha256_of_the_rfc8785_bytes() {
        let p: serde_json::Value = serde_json::from_str(r#"{"z":15.0,"a":"x"}"#).unwrap();
        let expected: [u8; 32] = Sha256::digest(br#"{"a":"x","z":15}"#).into();
        assert_eq!(payload_hash(&p).unwrap(), expected);
    }

    /// Integers JCS would round to a neighbour are refused, not hashed:
    /// otherwise `2^53 + 1` would verify where the producer signed `2^53`.
    #[test]
    fn payload_hash_refuses_integers_without_an_exact_canonical_form() {
        let limit = nucleus_receipt::MAX_EXACT_JSON_INTEGER;
        let negative_limit = -(limit as i64);
        payload_hash(&serde_json::json!({"n": limit, "m": negative_limit}))
            .expect("±(2^53 − 1) is exact");
        for beyond in [
            serde_json::json!({"n": limit + 1}),
            serde_json::json!({"deep": [0, {"n": negative_limit - 1}]}),
            serde_json::json!(u64::MAX),
        ] {
            assert!(
                matches!(
                    payload_hash(&beyond),
                    Err(BindingError::InexactInteger { .. })
                ),
                "{beyond} must be refused"
            );
        }
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
