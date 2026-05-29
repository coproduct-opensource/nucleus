//! in-toto Statement v1 + DSSE Envelope export.
//!
//! Wraps a [`Bundle`] in the [in-toto v1 Statement][stmt] shape and
//! signs it inside a [DSSE Envelope][dsse] using the same Ed25519
//! signer that signs lineage edges. The result is consumable by
//! `slsa-verifier`, Sigstore's `cosign verify-attestation`, and any
//! other ecosystem tool that accepts a DSSE-wrapped in-toto
//! Statement.
//!
//! [stmt]: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
//! [dsse]: https://github.com/secure-systems-lab/dsse
//!
//! # Wire shape
//!
//! The [`Statement`] is:
//!
//! ```json
//! {
//!   "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [
//!     { "name": "nucleus-bundle-payload",
//!       "digest": { "sha256": "<hex>" } }
//!   ],
//!   "predicateType": "https://nucleus.coproduct.io/agent-provenance/v1",
//!   "predicate": { /* the bundle's Envelope verbatim */ }
//! }
//! ```
//!
//! The subject digest is SHA-256 over the canonicalized payload bytes
//! (same canonicalization [`canonical_bundle_hash`](crate::canonical_bundle_hash)
//! uses) so tampering with the payload breaks the in-toto attestation
//! _in addition to_ the inner envelope's per-edge proofs.
//!
//! The [`DsseEnvelope`] uses
//! `payloadType = "application/vnd.in-toto+json"` per DSSE +
//! in-toto convention; the signature covers the canonical
//! [PAE][pae] of `(payloadType, payload_bytes)`.
//!
//! [pae]: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use nucleus_lineage::{EdgeSigner, IssuerError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::binding::pae_bytes;
use crate::bundle::Bundle;

/// in-toto Statement v1 type URI.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Nucleus predicate type — namespaced under our domain, versioned.
/// Any consumer parsing the predicate field must dispatch on this
/// exact string (the in-toto spec forbids ambiguity).
pub const NUCLEUS_PREDICATE_TYPE: &str = "https://nucleus.coproduct.io/agent-provenance/v1";

/// DSSE payloadType for an in-toto Statement (the convention shared
/// by SLSA, Sigstore, and in-toto's reference implementation).
pub const DSSE_INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Subject artifact name used in the Statement subject list. Stable
/// so downstream consumers can pattern-match if they wish.
pub const NUCLEUS_SUBJECT_NAME: &str = "nucleus-bundle-payload";

/// in-toto v1 Statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    /// Always [`IN_TOTO_STATEMENT_TYPE`].
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// One or more software artifacts this attestation refers to.
    pub subject: Vec<ResourceDescriptor>,
    /// TypeURI identifying what the predicate means.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Predicate body — a `nucleus_envelope::Envelope` serialized as JSON.
    pub predicate: Value,
}

/// in-toto v1 ResourceDescriptor — a digest-anchored artifact name.
/// We populate only `name` + `digest`; other optional fields (URI,
/// content, mediaType, …) are omitted by `skip_serializing_if`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    /// Human-friendly artifact name.
    pub name: String,
    /// Digest map: algorithm → hex digest. Always includes "sha256".
    pub digest: BTreeMap<String, String>,
}

/// DSSE Envelope v1.0.0 — single-signature variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// MIME type of the inner payload. For in-toto wrapping this is
    /// always [`DSSE_INTOTO_PAYLOAD_TYPE`].
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded inner payload bytes.
    pub payload: String,
    /// One or more detached signatures over
    /// [`pae_bytes`](crate::binding::pae_bytes)`(payloadType, payload)`.
    pub signatures: Vec<DsseSignature>,
}

/// A single DSSE signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    /// JWS-style key id; verifiers look this up in the trust anchor's
    /// JWKS. Reuses the same `kid` namespace as the envelope's
    /// per-edge proofs.
    pub keyid: String,
    /// Base64-encoded signature bytes (Ed25519, so 64 bytes raw → 88
    /// base64 chars).
    pub sig: String,
}

/// Errors raised while building an in-toto Statement or DSSE Envelope.
#[derive(Debug, Error)]
pub enum InTotoError {
    /// Payload or envelope failed to serialize to canonical JSON.
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The supplied [`EdgeSigner`] failed to sign the PAE bytes.
    #[error("signer: {0}")]
    Signer(#[from] IssuerError),
}

impl Bundle {
    /// Build an in-toto v1 Statement for this bundle.
    ///
    /// The subject digest is SHA-256 over the canonicalized payload
    /// bytes (same canonicalization
    /// [`crate::canonical_bundle_hash`] uses). The predicate is the
    /// bundle's envelope serialized verbatim at
    /// [`NUCLEUS_PREDICATE_TYPE`].
    pub fn to_in_toto_statement(&self) -> Result<Statement, InTotoError> {
        let payload_bytes = serde_json::to_vec(&self.payload)?;
        let payload_hash = Sha256::digest(&payload_bytes);
        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_string(), hex::encode(payload_hash));
        let subject = ResourceDescriptor {
            name: NUCLEUS_SUBJECT_NAME.to_string(),
            digest,
        };
        let predicate = serde_json::to_value(&self.envelope)?;
        Ok(Statement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![subject],
            predicate_type: NUCLEUS_PREDICATE_TYPE.to_string(),
            predicate,
        })
    }

    /// Build a DSSE Envelope wrapping the in-toto Statement signed by
    /// `signer`. The signer is the same trait used to sign individual
    /// lineage edges, so callers reuse their existing key material —
    /// no new trust anchors to distribute.
    pub fn to_in_toto_dsse(&self, signer: &dyn EdgeSigner) -> Result<DsseEnvelope, InTotoError> {
        let statement = self.to_in_toto_statement()?;
        let statement_bytes = serde_json::to_vec(&statement)?;
        // DSSE PAE: "DSSEv1 <len(type)> <type> <len(payload)> <payload>"
        let pae = pae_bytes(DSSE_INTOTO_PAYLOAD_TYPE, &[&statement_bytes]);
        let signature = signer.sign(&pae)?;
        Ok(DsseEnvelope {
            payload_type: DSSE_INTOTO_PAYLOAD_TYPE.to_string(),
            payload: B64.encode(&statement_bytes),
            signatures: vec![DsseSignature {
                keyid: signer.kid().to_string(),
                sig: B64.encode(&signature),
            }],
        })
    }
}

/// Recover the in-toto Statement bytes from a DSSE Envelope. Useful
/// for verifiers that want to re-hash the payload as part of
/// signature verification.
pub fn dsse_payload_bytes(env: &DsseEnvelope) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(&env.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleBuilder;
    use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
    use nucleus_lineage::{CallSpiffeId, EdgeKind, InMemorySink, Jwks, LineageEdge, LineageSink};

    /// Toy signer for tests — wraps a SigningKey + kid.
    struct TestSigner {
        key: SigningKey,
        kid: String,
    }

    impl TestSigner {
        fn new() -> Self {
            let key = SigningKey::from_bytes(&[7u8; SECRET_KEY_LENGTH]);
            Self {
                key,
                kid: "test-key-1".to_string(),
            }
        }

        fn verifying_key(&self) -> VerifyingKey {
            self.key.verifying_key()
        }
    }

    impl EdgeSigner for TestSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IssuerError> {
            Ok(self.key.sign(message).to_bytes().to_vec())
        }

        fn kid(&self) -> &str {
            &self.kid
        }

        fn alg(&self) -> &str {
            "EdDSA"
        }
    }

    fn fixture_bundle() -> Bundle {
        let sink = InMemorySink::new();
        let pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap();
        sink.emit(LineageEdge::pod_admit(pod.clone())).unwrap();
        sink.emit(LineageEdge::from_parent(
            pod.derive_tool("Read", Some(b"hello")).unwrap(),
            pod.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        BundleBuilder::new(pod)
            .payload(serde_json::json!({"summary": "hi", "stats": {"bytes": 5}}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap()
    }

    // ── Statement shape ───────────────────────────────────────────

    #[test]
    fn statement_has_correct_type_uri() {
        let stmt = fixture_bundle().to_in_toto_statement().unwrap();
        assert_eq!(stmt.statement_type, "https://in-toto.io/Statement/v1");
    }

    #[test]
    fn statement_predicate_type_is_namespaced_and_versioned() {
        let stmt = fixture_bundle().to_in_toto_statement().unwrap();
        assert_eq!(
            stmt.predicate_type,
            "https://nucleus.coproduct.io/agent-provenance/v1"
        );
        assert!(stmt.predicate_type.starts_with("https://"));
        assert!(stmt.predicate_type.ends_with("/v1"));
    }

    #[test]
    fn statement_subject_digest_is_sha256_of_canonical_payload() {
        let bundle = fixture_bundle();
        let stmt = bundle.to_in_toto_statement().unwrap();
        let payload_bytes = serde_json::to_vec(&bundle.payload).unwrap();
        let expected = hex::encode(Sha256::digest(&payload_bytes));
        let actual = stmt.subject[0].digest.get("sha256").unwrap();
        assert_eq!(actual, &expected);
    }

    #[test]
    fn statement_subject_name_is_stable() {
        let stmt = fixture_bundle().to_in_toto_statement().unwrap();
        assert_eq!(stmt.subject[0].name, NUCLEUS_SUBJECT_NAME);
        assert_eq!(stmt.subject.len(), 1, "exactly one subject per bundle");
    }

    #[test]
    fn statement_predicate_round_trips_envelope() {
        let bundle = fixture_bundle();
        let stmt = bundle.to_in_toto_statement().unwrap();
        // Re-parse the predicate as Envelope and compare semantically.
        // We don't compare raw JSON strings because `to_value` sorts
        // map keys alphabetically while direct `to_string(&envelope)`
        // preserves struct order — irrelevant to the wire contract.
        let recovered: crate::Envelope = serde_json::from_value(stmt.predicate).unwrap();
        assert_eq!(recovered.session_root, bundle.envelope.session_root);
        assert_eq!(recovered.edges.len(), bundle.envelope.edges.len());
        assert_eq!(
            recovered.meta.schema_version,
            bundle.envelope.meta.schema_version
        );
    }

    #[test]
    fn distinct_payloads_yield_distinct_subject_digests() {
        let mut b1 = fixture_bundle();
        let mut b2 = fixture_bundle();
        b1.payload = serde_json::json!({"summary": "alpha"});
        b2.payload = serde_json::json!({"summary": "beta"});
        let s1 = b1.to_in_toto_statement().unwrap();
        let s2 = b2.to_in_toto_statement().unwrap();
        assert_ne!(
            s1.subject[0].digest.get("sha256"),
            s2.subject[0].digest.get("sha256")
        );
    }

    // ── DSSE Envelope ─────────────────────────────────────────────

    #[test]
    fn dsse_envelope_carries_correct_payload_type() {
        let signer = TestSigner::new();
        let env = fixture_bundle().to_in_toto_dsse(&signer).unwrap();
        assert_eq!(env.payload_type, "application/vnd.in-toto+json");
    }

    #[test]
    fn dsse_envelope_payload_decodes_to_statement() {
        let signer = TestSigner::new();
        let env = fixture_bundle().to_in_toto_dsse(&signer).unwrap();
        let payload_bytes = dsse_payload_bytes(&env).unwrap();
        let stmt: Statement = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(stmt.statement_type, IN_TOTO_STATEMENT_TYPE);
        assert_eq!(stmt.predicate_type, NUCLEUS_PREDICATE_TYPE);
    }

    #[test]
    fn dsse_signature_verifies_against_pae() {
        let signer = TestSigner::new();
        let env = fixture_bundle().to_in_toto_dsse(&signer).unwrap();
        let payload_bytes = dsse_payload_bytes(&env).unwrap();
        let pae = pae_bytes(DSSE_INTOTO_PAYLOAD_TYPE, &[&payload_bytes]);

        let sig_bytes = B64.decode(&env.signatures[0].sig).unwrap();
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .expect("Ed25519 sig must be 64 bytes");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        let vk = signer.verifying_key();
        ed25519_dalek::Verifier::verify(&vk, &pae, &signature)
            .expect("DSSE signature must verify against PAE(payloadType, payload)");
    }

    #[test]
    fn dsse_envelope_signature_has_correct_keyid() {
        let signer = TestSigner::new();
        let env = fixture_bundle().to_in_toto_dsse(&signer).unwrap();
        assert_eq!(env.signatures.len(), 1);
        assert_eq!(env.signatures[0].keyid, "test-key-1");
    }

    #[test]
    fn dsse_signature_is_64_bytes_raw_ed25519() {
        let signer = TestSigner::new();
        let env = fixture_bundle().to_in_toto_dsse(&signer).unwrap();
        let sig_bytes = B64.decode(&env.signatures[0].sig).unwrap();
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");
    }

    #[test]
    fn tampered_payload_breaks_signature() {
        let signer = TestSigner::new();
        let mut env = fixture_bundle().to_in_toto_dsse(&signer).unwrap();
        // Flip one byte of the base64 payload — decoded bytes change,
        // signature no longer covers them.
        let mut payload = B64.decode(&env.payload).unwrap();
        payload[0] ^= 0xff;
        env.payload = B64.encode(&payload);

        let payload_bytes = dsse_payload_bytes(&env).unwrap();
        let pae = pae_bytes(DSSE_INTOTO_PAYLOAD_TYPE, &[&payload_bytes]);
        let sig_bytes = B64.decode(&env.signatures[0].sig).unwrap();
        let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        let vk = signer.verifying_key();
        assert!(
            ed25519_dalek::Verifier::verify(&vk, &pae, &signature).is_err(),
            "tampered payload must invalidate signature"
        );
    }

    #[test]
    fn dsse_envelope_round_trips_through_json() {
        let signer = TestSigner::new();
        let env = fixture_bundle().to_in_toto_dsse(&signer).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let back: DsseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload_type, env.payload_type);
        assert_eq!(back.payload, env.payload);
        assert_eq!(back.signatures.len(), env.signatures.len());
        assert_eq!(back.signatures[0].keyid, env.signatures[0].keyid);
        assert_eq!(back.signatures[0].sig, env.signatures[0].sig);
    }
}
