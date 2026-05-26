//! [`Bundle`] and [`Envelope`] — the on-wire types and their builder.

use chrono::{DateTime, Utc};
use nucleus_lineage::{CallSpiffeId, IdError, Jwks, LineageEdge, LineageSink, SignedTreeHead};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::extract;

/// Errors a [`BundleBuilder`] may surface.
#[derive(Debug, Error)]
pub enum BundleError {
    /// Subgraph extraction failed while reading the underlying sink.
    #[error("lineage sink error: {0}")]
    Sink(#[from] nucleus_lineage::SinkError),
    /// The session root SPIFFE id was invalid.
    #[error("invalid session root id: {0}")]
    InvalidId(#[from] IdError),
    /// No edges were found for the supplied session root. A bundle with an
    /// empty envelope is rarely useful and almost always indicates a bug,
    /// so the builder refuses by default.
    #[error("no lineage edges found under session root {0}")]
    EmptySession(String),
    /// Required builder field was not set before `build()`.
    #[error("missing required builder field: {0}")]
    MissingField(&'static str),
    /// Builder was configured with `require_signed()` but at least one
    /// session edge lacked a cryptographic `proof`. Surfaced at build
    /// time so producers learn early, instead of at the verifier.
    #[error("edge #{index} has no proof; require_signed() rejects mixed logs")]
    UnsignedEdge { index: usize },
}

/// A portable, self-contained provenance bundle.
///
/// `payload` is the agent's structured output (free-form JSON — typically
/// `{"stats": ..., "summary": ...}`). `envelope` is the IFC certificate
/// that lets anyone re-validate the payload's provenance without trusting
/// the producer's storage.
///
/// Wire format is JSON; field order is stable across serde versions. New
/// fields must be `#[serde(default)]` to preserve forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Agent payload — opaque JSON.
    pub payload: Value,
    /// Provenance envelope covering the payload's session.
    pub envelope: Envelope,
}

/// The provenance certificate accompanying a [`Bundle::payload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Pod / session root SPIFFE id — the URI prefix under which every
    /// edge in this envelope was emitted.
    pub session_root: CallSpiffeId,
    /// Session subgraph in linear chain order. Verification is performed
    /// in this order; each edge's `proof.prev_hash` must match the
    /// previous edge's `edge_content_hash`.
    pub edges: Vec<LineageEdge>,
    /// JSON Web Key Set covering every `proof.kid` that appears in
    /// `edges`. Embedded so a verifier needs no network calls.
    pub jwks: Jwks,
    /// Signed tree heads contemporaneous with this session (zero or more).
    /// In v1 these are *time attestations* — full Merkle inclusion proof
    /// binding `edges` to a `root_hash` is a v2 follow-up.
    #[serde(default)]
    pub checkpoints: Vec<SignedTreeHead>,
    /// Envelope metadata (creation time, schema version, …).
    pub meta: EnvelopeMeta,
}

/// Metadata about the envelope itself (not about the payload it covers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeMeta {
    /// Envelope schema version. Bump on any breaking change to the wire
    /// format; verifiers may refuse unknown versions.
    pub schema_version: u32,
    /// Wall-clock time the bundle was assembled.
    pub created_at: DateTime<Utc>,
}

/// Current envelope schema version. Verifiers should accept this and
/// reject (or migrate) anything newer than they understand.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

impl EnvelopeMeta {
    /// Default metadata stamped with the current time and current schema
    /// version.
    pub fn now() -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            created_at: Utc::now(),
        }
    }
}

/// Builder for [`Bundle`]. Required fields: `payload`, `sink`, `jwks`.
/// `checkpoints` is optional and defaults to empty.
pub struct BundleBuilder<'a> {
    session_root: CallSpiffeId,
    payload: Option<Value>,
    sink: Option<&'a dyn LineageSink>,
    jwks: Option<Jwks>,
    checkpoints: Vec<SignedTreeHead>,
    allow_empty: bool,
    require_signed: bool,
}

impl<'a> BundleBuilder<'a> {
    /// Begin a new bundle for the session rooted at `session_root`.
    pub fn new(session_root: CallSpiffeId) -> Self {
        Self {
            session_root,
            payload: None,
            sink: None,
            jwks: None,
            checkpoints: Vec::new(),
            allow_empty: false,
            require_signed: false,
        }
    }

    /// Set the agent-produced payload (free-form JSON).
    pub fn payload(mut self, payload: Value) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Source of lineage edges — typically the same sink the session
    /// wrote into.
    pub fn sink(mut self, sink: &'a dyn LineageSink) -> Self {
        self.sink = Some(sink);
        self
    }

    /// JSON Web Key Set covering every issuer that signed edges in this
    /// session. Required for the verifier to validate proofs offline.
    pub fn jwks(mut self, jwks: Jwks) -> Self {
        self.jwks = Some(jwks);
        self
    }

    /// Attach contemporaneous signed tree heads. Time attestations in v1.
    pub fn checkpoints(mut self, checkpoints: Vec<SignedTreeHead>) -> Self {
        self.checkpoints = checkpoints;
        self
    }

    /// Allow building a bundle whose envelope contains zero session
    /// edges. Off by default. The verifier will *also* reject empty
    /// envelopes unless [`crate::TrustAnchor::allow_empty`] is set —
    /// the builder permission does not override the verifier's.
    pub fn allow_empty(mut self) -> Self {
        self.allow_empty = true;
        self
    }

    /// Refuse to build if any edge in the session subgraph lacks a
    /// cryptographic `proof`. Surfaces the failure at packaging time
    /// rather than letting the verifier discover it later.
    pub fn require_signed(mut self) -> Self {
        self.require_signed = true;
        self
    }

    /// Assemble the [`Bundle`].
    pub fn build(self) -> Result<Bundle, BundleError> {
        let payload = self.payload.ok_or(BundleError::MissingField("payload"))?;
        let sink = self.sink.ok_or(BundleError::MissingField("sink"))?;
        let jwks = self.jwks.ok_or(BundleError::MissingField("jwks"))?;

        let subgraph = extract::extract_session_subgraph(&self.session_root, sink)?;
        if subgraph.edges.is_empty() && !self.allow_empty {
            return Err(BundleError::EmptySession(self.session_root.to_string()));
        }
        if self.require_signed {
            if let Some(index) = subgraph.edges.iter().position(|e| e.proof.is_none()) {
                return Err(BundleError::UnsignedEdge { index });
            }
        }

        Ok(Bundle {
            payload,
            envelope: Envelope {
                session_root: subgraph.root,
                edges: subgraph.edges,
                jwks,
                checkpoints: self.checkpoints,
                meta: EnvelopeMeta::now(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::{EdgeKind, InMemorySink};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
    }

    #[test]
    fn schema_version_constant_matches_default_meta() {
        let m = EnvelopeMeta::now();
        assert_eq!(m.schema_version, ENVELOPE_SCHEMA_VERSION);
    }

    #[test]
    fn builder_missing_payload_errors() {
        let sink = InMemorySink::new();
        let err = BundleBuilder::new(pod())
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::MissingField("payload")));
    }

    #[test]
    fn builder_missing_sink_errors() {
        let err = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::MissingField("sink")));
    }

    #[test]
    fn builder_missing_jwks_errors() {
        let sink = InMemorySink::new();
        let err = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::MissingField("jwks")));
    }

    #[test]
    fn builder_empty_session_errors_by_default() {
        let sink = InMemorySink::new();
        let err = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::EmptySession(_)));
    }

    #[test]
    fn builder_allow_empty_accepts_zero_edges() {
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({"stats": 0}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        assert!(bundle.envelope.edges.is_empty());
        assert_eq!(bundle.envelope.meta.schema_version, ENVELOPE_SCHEMA_VERSION);
    }

    #[test]
    fn bundle_round_trips_through_json() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        sink.emit(LineageEdge::from_parent(
            p.derive_tool("Read", Some(b"hello")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();

        let bundle = BundleBuilder::new(p)
            .payload(serde_json::json!({"summary": "hi", "stats": {"bytes": 5}}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        assert_eq!(bundle.envelope.edges.len(), 2);

        let json = serde_json::to_string(&bundle).unwrap();
        let back: Bundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope.edges.len(), 2);
        assert_eq!(back.envelope.session_root, bundle.envelope.session_root);
        assert_eq!(back.payload, bundle.payload);
    }
}
