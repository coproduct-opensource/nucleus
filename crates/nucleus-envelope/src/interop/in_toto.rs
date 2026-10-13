//! in-toto Statement v1 + DSSE Envelope export.
//!
//! Wraps a [`Bundle`] in the [in-toto v1 Statement][stmt] shape and
//! signs it inside a [DSSE Envelope][dsse] using the same Ed25519
//! signer that signs lineage edges. The result is consumable by
//! `cosign verify-blob-attestation` and any other ecosystem tool that
//! accepts a DSSE-wrapped in-toto Statement.
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
//!       "digest": { "sha256": "<hex of JCS(payload)>" } },
//!     { "name": "spiffe://<td>/…/derived/sha256:<hex>",
//!       "digest": { "sha256": "<hex of the artifact bytes>" } }
//!   ],
//!   "predicateType": "https://nucleus.coproduct.io/agent-provenance/v2",
//!   "predicate": {
//!     "aiGeneration": {
//!       "origin": "ai-agent-under-nucleus-enforcement",
//!       "agent": "spiffe://<td>/ns/<ns>/sa/<sa>",
//!       "modelProviders": ["<provider>", …]
//!     },
//!     "envelope": { /* the bundle's Envelope verbatim */ }
//!   }
//! }
//! ```
//!
//! # Subjects: what the session produced
//!
//! The first subject is the bundle payload, hashed as the RFC 8785 (JCS)
//! form the payload binding signs ([`crate::payload_hash`]) — one decider
//! for "the payload's digest", so a statement's subject does not depend on
//! which serde features a build unified.
//!
//! Every `ArtifactProduced` edge then contributes one subject, named by its
//! child SPIFFE id, whose digest is the artifact bytes' SHA-256 as the
//! lineage recorded it: the `/sha256:<hex>` suffix
//! [`CallSpiffeId::derive_artifact`](nucleus_lineage::CallSpiffeId::derive_artifact)
//! writes into the id, and/or the edge's `content_hash_hex`. Both are in the
//! edge's signed bytes. A consumer holding an output file hashes it and finds
//! the attestation whose subject carries that digest.
//!
//! An artifact edge that records **no** digest, or whose two digest fields
//! disagree, refuses the export ([`InTotoError::ArtifactWithoutDigest`],
//! [`InTotoError::ArtifactDigestConflict`]). Dropping it would publish an
//! attestation that reads as "these are the outputs" while silently omitting
//! one (A-1: "could not bind" is not "bound").
//!
//! # Predicate: the AI-generation marking
//!
//! [`AgentProvenance::ai_generation`] states, as a typed field, that the
//! subjects were produced by an AI agent session running under nucleus
//! enforcement ([`ContentOrigin`]), names the agent by its session-root
//! SPIFFE id, and lists the model providers the signed lineage names (read
//! from each `LlmCall` edge's signed child id, never from the unsigned
//! `EdgeKind::LlmCall::provider` — a disagreement between the two refuses the
//! export). An empty `modelProviders` means the signed lineage records no
//! model call, typically because the model ran outside the mediated path.
//!
//! For readers mapping this onto C2PA: `origin` corresponds to C2PA's
//! `digitalSourceType` value `trainedAlgorithmicMedia` (IPTC's term for
//! content created by a trained model). The mapping is documentation only;
//! this module emits no C2PA structure, and embedding a manifest into generated
//! media is the generating application's step.
//!
//! **v1 → v2.** Version 1 carried the envelope itself as the predicate and
//! named only the payload as a subject. The predicate's shape changed, so its
//! type URI did; there is no v1 emitter left.
//!
//! The export reads the bundle as given; it does not verify it. Verify the
//! bundle against an out-of-band trust anchor first — `nucleus
//! envelope-export` does, and refuses to attest a bundle that fails.
//!
//! The [`DsseEnvelope`] uses
//! `payloadType = "application/vnd.in-toto+json"` per DSSE +
//! in-toto convention; the signature covers the canonical
//! [PAE][pae] of `(payloadType, payload_bytes)`.
//!
//! [pae]: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use nucleus_lineage::{CallSpiffeId, EdgeKind, EdgeSigner, IssuerError, LineageEdge};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::binding::{BindingError, pae_bytes, payload_hash};
use crate::bundle::{Bundle, Envelope};

/// in-toto Statement v1 type URI.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Nucleus predicate type — namespaced under our domain, versioned.
/// Any consumer parsing the predicate field must dispatch on this
/// exact string (the in-toto spec forbids ambiguity). The body is an
/// [`AgentProvenance`].
pub const NUCLEUS_PREDICATE_TYPE: &str = "https://nucleus.coproduct.io/agent-provenance/v2";

/// DSSE payloadType for an in-toto Statement (the convention shared
/// by SLSA, Sigstore, and in-toto's reference implementation).
pub const DSSE_INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Subject artifact name for the bundle payload. Stable so downstream
/// consumers can pattern-match if they wish.
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
    /// Predicate body — an [`AgentProvenance`] for [`NUCLEUS_PREDICATE_TYPE`],
    /// a SLSA [`Provenance`](crate::Provenance) for the SLSA type.
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

impl ResourceDescriptor {
    fn sha256(name: &str, hex: &str) -> Self {
        Self {
            name: name.to_string(),
            digest: BTreeMap::from([("sha256".to_string(), hex.to_string())]),
        }
    }
}

/// The predicate body at [`NUCLEUS_PREDICATE_TYPE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentProvenance {
    /// The AI-generation marking: who produced the subjects, and under what.
    pub ai_generation: AiGeneration,
    /// The bundle's envelope, verbatim, so a reader can re-verify every
    /// edge the marking and the subjects were read from.
    pub envelope: Envelope,
}

/// Typed statement that the attested content is AI-generated.
///
/// Every field is read from the bundle; none is supplied by the exporter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AiGeneration {
    /// What produced the subjects.
    pub origin: ContentOrigin,
    /// The agent's identity: the session-root SPIFFE id every edge in the
    /// envelope derives from.
    pub agent: CallSpiffeId,
    /// Model providers named by the signed lineage's `LlmCall` edges,
    /// sorted and de-duplicated. Empty when the lineage records no model
    /// call.
    pub model_providers: Vec<String>,
}

/// Where attested content came from. A closed set: a consumer that meets a
/// value it does not know fails to parse rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentOrigin {
    /// Produced by an AI agent session whose effects nucleus mediated and
    /// whose lineage it signed. Corresponds to C2PA / IPTC
    /// `trainedAlgorithmicMedia` (see the module docs).
    #[serde(rename = "ai-agent-under-nucleus-enforcement")]
    AiAgentUnderNucleusEnforcement,
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
    /// The payload has no canonical digest (e.g. an integer JCS cannot
    /// represent exactly), so it cannot be named as a subject.
    #[error("payload digest: {0}")]
    PayloadDigest(#[from] BindingError),
    /// The supplied [`EdgeSigner`] failed to sign the PAE bytes.
    #[error("signer: {0}")]
    Signer(#[from] IssuerError),
    /// An `ArtifactProduced` edge records no content digest — neither a
    /// `/sha256:` id suffix nor a `content_hash_hex` — so the artifact
    /// cannot be named as a subject.
    #[error("artifact {child} records no content digest; it cannot be attested as an output")]
    ArtifactWithoutDigest { child: String },
    /// An `ArtifactProduced` edge's id suffix and `content_hash_hex` name
    /// different digests. Neither is chosen.
    #[error("artifact {child}: id digest {in_id} disagrees with content_hash_hex {in_field}")]
    ArtifactDigestConflict {
        child: String,
        in_id: String,
        in_field: String,
    },
    /// An `ArtifactProduced` edge's `content_hash_hex` is not a lowercase
    /// hex SHA-256.
    #[error("artifact {child}: content_hash_hex {value:?} is not a lowercase hex SHA-256")]
    MalformedArtifactDigest { child: String, value: String },
    /// An `LlmCall` edge's signed child id names no model provider.
    #[error("model call {child}: the signed id names no model provider")]
    ModelProviderUnsigned { child: String },
    /// An `LlmCall` edge's unsigned `provider` disagrees with the provider
    /// its signed child id names.
    #[error("model call {child}: kind names {in_kind:?} but the signed id names {in_id:?}")]
    ModelProviderConflict {
        child: String,
        in_kind: String,
        in_id: String,
    },
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The artifact digest an `ArtifactProduced` edge records. See the module
/// docs for why a missing or conflicting digest refuses.
fn artifact_digest(edge: &LineageEdge) -> Result<String, InTotoError> {
    let child = || edge.child.as_str().to_string();
    let in_field = match edge.content_hash_hex.as_deref() {
        Some(v) if is_sha256_hex(v) => Some(v),
        Some(v) => {
            return Err(InTotoError::MalformedArtifactDigest {
                child: child(),
                value: v.to_string(),
            });
        }
        None => None,
    };
    match (edge.child.content_hash_hex(), in_field) {
        (Some(id), Some(field)) if id == field => Ok(id.to_string()),
        (Some(id), Some(field)) => Err(InTotoError::ArtifactDigestConflict {
            child: child(),
            in_id: id.to_string(),
            in_field: field.to_string(),
        }),
        (Some(d), None) | (None, Some(d)) => Ok(d.to_string()),
        (None, None) => Err(InTotoError::ArtifactWithoutDigest { child: child() }),
    }
}

/// Sign `statement` into a single-signature DSSE envelope. The one place a
/// Statement becomes signed bytes, for every predicate type.
pub(crate) fn sign_statement(
    statement: &Statement,
    signer: &dyn EdgeSigner,
) -> Result<DsseEnvelope, InTotoError> {
    let statement_bytes = serde_json::to_vec(statement)?;
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

impl Bundle {
    /// The subjects every Statement exported from this bundle names: the
    /// payload, then one entry per `ArtifactProduced` edge (module docs).
    /// Shared by the nucleus and SLSA statements.
    pub fn statement_subjects(&self) -> Result<Vec<ResourceDescriptor>, InTotoError> {
        let mut subjects = vec![ResourceDescriptor::sha256(
            NUCLEUS_SUBJECT_NAME,
            &hex::encode(payload_hash(&self.payload)?),
        )];
        for edge in &self.envelope.edges {
            if matches!(edge.kind, EdgeKind::ArtifactProduced) {
                subjects.push(ResourceDescriptor::sha256(
                    edge.child.as_str(),
                    &artifact_digest(edge)?,
                ));
            }
        }
        Ok(subjects)
    }

    /// The AI-generation marking, read from the envelope (module docs).
    pub fn ai_generation(&self) -> Result<AiGeneration, InTotoError> {
        let mut providers = BTreeSet::new();
        for edge in &self.envelope.edges {
            if let EdgeKind::LlmCall { provider, .. } = &edge.kind {
                let child = || edge.child.as_str().to_string();
                let signed = edge
                    .child
                    .llm_provider()
                    .ok_or_else(|| InTotoError::ModelProviderUnsigned { child: child() })?;
                if signed != provider {
                    return Err(InTotoError::ModelProviderConflict {
                        child: child(),
                        in_kind: provider.clone(),
                        in_id: signed.to_string(),
                    });
                }
                providers.insert(signed.to_string());
            }
        }
        Ok(AiGeneration {
            origin: ContentOrigin::AiAgentUnderNucleusEnforcement,
            agent: self.envelope.session_root.clone(),
            model_providers: providers.into_iter().collect(),
        })
    }

    /// Build an in-toto v1 Statement for this bundle: the subjects of
    /// [`Self::statement_subjects`] and an [`AgentProvenance`] predicate
    /// at [`NUCLEUS_PREDICATE_TYPE`].
    pub fn to_in_toto_statement(&self) -> Result<Statement, InTotoError> {
        let predicate = AgentProvenance {
            ai_generation: self.ai_generation()?,
            envelope: self.envelope.clone(),
        };
        Ok(Statement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: self.statement_subjects()?,
            predicate_type: NUCLEUS_PREDICATE_TYPE.to_string(),
            predicate: serde_json::to_value(&predicate)?,
        })
    }

    /// Build a DSSE Envelope wrapping the in-toto Statement signed by
    /// `signer`. The signer is the same trait used to sign individual
    /// lineage edges, so callers reuse their existing key material —
    /// no new trust anchors to distribute.
    pub fn to_in_toto_dsse(&self, signer: &dyn EdgeSigner) -> Result<DsseEnvelope, InTotoError> {
        sign_statement(&self.to_in_toto_statement()?, signer)
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
    use ed25519_dalek::{SECRET_KEY_LENGTH, Signer as Ed25519Signer, SigningKey, VerifyingKey};
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
            "https://nucleus.coproduct.io/agent-provenance/v2"
        );
        assert!(stmt.predicate_type.starts_with("https://"));
        assert!(stmt.predicate_type.ends_with("/v2"));
    }

    #[test]
    fn statement_subject_digest_is_sha256_of_canonical_payload() {
        let bundle = fixture_bundle();
        let stmt = bundle.to_in_toto_statement().unwrap();
        // JCS, the decider the payload binding signs — not `to_vec`, whose
        // key order follows `serde_json/preserve_order` feature unification.
        let expected = hex::encode(crate::binding::payload_hash(&bundle.payload).unwrap());
        let actual = stmt.subject[0].digest.get("sha256").unwrap();
        assert_eq!(actual, &expected);
    }

    #[test]
    fn statement_subject_name_is_stable() {
        let stmt = fixture_bundle().to_in_toto_statement().unwrap();
        assert_eq!(stmt.subject[0].name, NUCLEUS_SUBJECT_NAME);
        // This fixture produces no artifact, so the payload is the only subject.
        assert_eq!(
            stmt.subject.len(),
            1,
            "payload subject only: no ArtifactProduced edge"
        );
    }

    #[test]
    fn statement_predicate_round_trips_envelope() {
        let bundle = fixture_bundle();
        let stmt = bundle.to_in_toto_statement().unwrap();
        // Re-parse the predicate as Envelope and compare semantically.
        // We don't compare raw JSON strings because `to_value` sorts
        // map keys alphabetically while direct `to_string(&envelope)`
        // preserves struct order — irrelevant to the wire contract.
        let predicate: AgentProvenance = serde_json::from_value(stmt.predicate).unwrap();
        assert_eq!(predicate.ai_generation, bundle.ai_generation().unwrap());
        let recovered = predicate.envelope;
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

    // ── Subjects and marking ─────────────────────────────────────

    #[test]
    fn a_malformed_artifact_content_field_refuses_export() {
        let pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap();
        let edge = LineageEdge::from_parent(
            pod.derive_tool("Write", None).unwrap(),
            pod,
            EdgeKind::ArtifactProduced,
        )
        .with_content_hash("ABCDEF");
        assert!(matches!(
            artifact_digest(&edge),
            Err(InTotoError::MalformedArtifactDigest { .. })
        ));
    }

    #[test]
    fn an_unknown_content_origin_does_not_parse() {
        let known: ContentOrigin =
            serde_json::from_str("\"ai-agent-under-nucleus-enforcement\"").unwrap();
        assert_eq!(known, ContentOrigin::AiAgentUnderNucleusEnforcement);
        assert!(serde_json::from_str::<ContentOrigin>("\"human\"").is_err());
    }

    #[test]
    fn a_session_with_no_model_call_names_no_provider() {
        // The fixture has a Read and no LlmCall: the marking still names the
        // agent, and says so honestly with an empty provider list.
        let bundle = fixture_bundle();
        let ai = bundle.ai_generation().unwrap();
        assert_eq!(ai.agent, bundle.envelope.session_root);
        assert!(ai.model_providers.is_empty());
    }
}
