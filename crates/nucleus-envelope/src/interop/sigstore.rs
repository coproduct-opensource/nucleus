//! [Sigstore Bundle v0.3][sb] wrapper around the in-toto/SLSA DSSE
//! envelope.
//!
//! [sb]: https://docs.sigstore.dev/about/bundle/
//!
//! A Sigstore Bundle is the on-the-wire container Sigstore-aware
//! verifiers (`cosign verify-attestation`, slsa-verifier, sigstore-go,
//! sigstore-python, sigstore-js, …) accept by default. Wrapping our
//! DSSE envelope makes nucleus bundles drop-in compatible with the
//! existing Sigstore tooling without any consumer-side changes.
//!
//! # What v1 of this adapter ships
//!
//! - `mediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"`
//!   (the current Bundle spec)
//! - DSSE envelope carried verbatim under `dsseEnvelope`
//! - `verificationMaterial.publicKey.hint` set to the DSSE signature's
//!   `keyid` — required by the spec when a key hint is present
//!   alongside a DSSE envelope
//! - Empty `tlogEntries` and no `timestampVerificationData`
//!
//! # What v2 of this adapter will add
//!
//! - `tlogEntries`: Rekor log inclusion proofs once we publish to the
//!   public verifier service (see task #69)
//! - `timestampVerificationData`: RFC 3161 timestamps from our
//!   witness federation cosignatures (see task #73)
//! - `x509CertificateChain`: Sigstore Fulcio-issued cert chain once
//!   the OIDC OP can mint Fulcio identities

use serde::{Deserialize, Serialize};

use crate::bundle::Bundle;
use crate::interop::in_toto::{DsseEnvelope, InTotoError};
use nucleus_lineage::EdgeSigner;

/// Sigstore Bundle v0.3 media type.
pub const SIGSTORE_BUNDLE_V03_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// Top-level [Sigstore Bundle][sb] object.
///
/// [sb]: https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreBundle {
    /// MIME type. Always [`SIGSTORE_BUNDLE_V03_MEDIA_TYPE`] in this
    /// adapter version.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Everything a verifier needs to validate the signature.
    #[serde(rename = "verificationMaterial")]
    pub verification_material: VerificationMaterial,
    /// The signed payload — a DSSE envelope wrapping the in-toto
    /// Statement (either generic agent-provenance or SLSA Provenance).
    #[serde(rename = "dsseEnvelope")]
    pub dsse_envelope: DsseEnvelope,
}

/// Sigstore VerificationMaterial — public key + optional log/timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMaterial {
    /// Public key identifier (hint). Per the spec, when the content
    /// is a DSSE envelope and a key hint is present, it MUST equal
    /// each signature's `keyid`.
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyIdentifier>,
    /// Rekor transparency log entries. Empty in v1; reserved for
    /// post-task-#69 wire-up.
    #[serde(rename = "tlogEntries", default, skip_serializing_if = "Vec::is_empty")]
    pub tlog_entries: Vec<serde_json::Value>,
    /// Optional RFC 3161 timestamps. None in v1.
    #[serde(
        rename = "timestampVerificationData",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp_verification_data: Option<TimestampVerificationData>,
}

/// Public-key hint — opaque string the verifier resolves against a
/// trust anchor. Aligned with the DSSE signature's `keyid`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyIdentifier {
    /// Hint string. For nucleus this is the JWS-style kid of the
    /// signing key — the same value the DSSE envelope carries.
    pub hint: String,
}

/// Container for RFC 3161 timestamps. v1: always empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampVerificationData {
    #[serde(rename = "rfc3161Timestamps", default)]
    pub rfc3161_timestamps: Vec<serde_json::Value>,
}

impl Bundle {
    /// Wrap the in-toto-statement DSSE envelope in a Sigstore Bundle
    /// v0.3. Predicate type is [`super::in_toto::NUCLEUS_PREDICATE_TYPE`].
    pub fn to_sigstore_bundle_intoto(
        &self,
        signer: &dyn EdgeSigner,
    ) -> Result<SigstoreBundle, InTotoError> {
        let dsse = self.to_in_toto_dsse(signer)?;
        Ok(wrap_dsse(dsse))
    }

    /// Wrap the SLSA Provenance DSSE envelope in a Sigstore Bundle
    /// v0.3. Predicate type is
    /// [`super::slsa::SLSA_PROVENANCE_V1_PREDICATE_TYPE`].
    pub fn to_sigstore_bundle_slsa(
        &self,
        signer: &dyn EdgeSigner,
    ) -> Result<SigstoreBundle, InTotoError> {
        let dsse = self.to_slsa_dsse(signer)?;
        Ok(wrap_dsse(dsse))
    }
}

/// Internal helper: wrap a DSSE envelope in a v1-shape Sigstore Bundle.
fn wrap_dsse(dsse: DsseEnvelope) -> SigstoreBundle {
    let hint = dsse
        .signatures
        .first()
        .map(|s| s.keyid.clone())
        .unwrap_or_default();
    SigstoreBundle {
        media_type: SIGSTORE_BUNDLE_V03_MEDIA_TYPE.to_string(),
        verification_material: VerificationMaterial {
            public_key: Some(PublicKeyIdentifier { hint }),
            tlog_entries: Vec::new(),
            timestamp_verification_data: None,
        },
        dsse_envelope: dsse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleBuilder;
    use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, SECRET_KEY_LENGTH};
    use nucleus_lineage::{
        CallSpiffeId, EdgeKind, InMemorySink, IssuerError, Jwks, LineageEdge, LineageSink,
    };

    struct TestSigner {
        key: SigningKey,
        kid: String,
    }

    impl TestSigner {
        fn new(kid: &str) -> Self {
            Self {
                key: SigningKey::from_bytes(&[13u8; SECRET_KEY_LENGTH]),
                kid: kid.to_string(),
            }
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
            pod.derive_tool("Read", Some(b"x")).unwrap(),
            pod.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        BundleBuilder::new(pod)
            .payload(serde_json::json!({"summary": "hi"}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap()
    }

    #[test]
    fn intoto_bundle_has_correct_media_type() {
        let signer = TestSigner::new("kid-intoto");
        let b = fixture_bundle().to_sigstore_bundle_intoto(&signer).unwrap();
        assert_eq!(
            b.media_type,
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );
    }

    #[test]
    fn slsa_bundle_has_correct_media_type() {
        let signer = TestSigner::new("kid-slsa");
        let b = fixture_bundle().to_sigstore_bundle_slsa(&signer).unwrap();
        assert_eq!(
            b.media_type,
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );
    }

    #[test]
    fn public_key_hint_matches_dsse_keyid() {
        let signer = TestSigner::new("must-match-this-kid");
        let b = fixture_bundle().to_sigstore_bundle_intoto(&signer).unwrap();
        let hint = &b.verification_material.public_key.as_ref().unwrap().hint;
        let kid = &b.dsse_envelope.signatures[0].keyid;
        assert_eq!(
            hint, kid,
            "Sigstore spec requires verification_material.publicKey.hint == dsse.signatures[*].keyid"
        );
        assert_eq!(hint, "must-match-this-kid");
    }

    #[test]
    fn v1_omits_tlog_and_timestamps() {
        let signer = TestSigner::new("kid");
        let b = fixture_bundle().to_sigstore_bundle_intoto(&signer).unwrap();
        assert!(
            b.verification_material.tlog_entries.is_empty(),
            "v1 of this adapter ships empty tlogEntries; populated in task #69"
        );
        assert!(
            b.verification_material
                .timestamp_verification_data
                .is_none(),
            "v1 ships no rfc3161 timestamps; populated in task #73"
        );
    }

    #[test]
    fn slsa_bundle_dsse_envelope_carries_slsa_statement() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let signer = TestSigner::new("kid");
        let b = fixture_bundle().to_sigstore_bundle_slsa(&signer).unwrap();
        let payload_bytes = B64.decode(&b.dsse_envelope.payload).unwrap();
        let stmt: crate::Statement = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(stmt.predicate_type, "https://slsa.dev/provenance/v1");
    }

    #[test]
    fn intoto_bundle_dsse_envelope_carries_nucleus_statement() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let signer = TestSigner::new("kid");
        let b = fixture_bundle().to_sigstore_bundle_intoto(&signer).unwrap();
        let payload_bytes = B64.decode(&b.dsse_envelope.payload).unwrap();
        let stmt: crate::Statement = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(
            stmt.predicate_type,
            "https://nucleus.coproduct.io/agent-provenance/v1"
        );
    }

    #[test]
    fn bundle_round_trips_through_json() {
        let signer = TestSigner::new("kid-roundtrip");
        let b = fixture_bundle().to_sigstore_bundle_intoto(&signer).unwrap();
        let json = serde_json::to_string(&b).unwrap();
        let back: SigstoreBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.media_type, b.media_type);
        assert_eq!(
            back.verification_material.public_key.unwrap().hint,
            b.verification_material.public_key.unwrap().hint
        );
        assert_eq!(back.dsse_envelope.signatures.len(), 1);
    }

    #[test]
    fn empty_signatures_dsse_yields_empty_hint() {
        // Defensive — shouldn't happen via our public API, but the
        // helper must not panic.
        let dsse = crate::interop::in_toto::DsseEnvelope {
            payload_type: "test".to_string(),
            payload: "test".to_string(),
            signatures: Vec::new(),
        };
        let wrapped = super::wrap_dsse(dsse);
        let hint = &wrapped.verification_material.public_key.unwrap().hint;
        assert_eq!(hint, "");
    }
}
