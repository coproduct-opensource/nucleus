//! [`LineageEdge`] — one entry in the append-only lineage DAG.
//!
//! Each edge records a single act of derivation: a child identity (one or
//! more) [`CallSpiffeId`]s flowed into it. Edges are content-addressable
//! records; the in-memory and JSONL sinks both treat them as immutable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::id::CallSpiffeId;
use crate::proof::Proof;

/// What kind of derivation this edge represents.
///
/// `Other(String)` is reserved for forward-compatible kinds that callers
/// can introduce without modifying this enum. The string value is shown
/// verbatim in lineage output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EdgeKind {
    /// A pod was admitted and given a SPIFFE identity.
    PodAdmit,
    /// A tool call was issued (Bash, Read, Write, …).
    ToolCall { tool: String },
    /// An LLM call was issued. `direction` is typically "prompt" or "response".
    LlmCall { provider: String, direction: String },
    /// Output of a tool/LLM call became an addressable artifact.
    ArtifactProduced,
    /// Two or more parents were merged into one child (e.g. a deterministic
    /// transform that consumed multiple inputs).
    Merge,
    /// A document was retrieved into the agent's context (web fetch, RAG index
    /// hit, local file, or memory recall). Captures the *provenance* of
    /// retrieved content so poisoned sources can be traced after the fact —
    /// the blind spot exploited by RAG/memory-poisoning attacks (AgentPoison,
    /// eTAMP) where injected documents silently steer later actions.
    DocumentRetrieved {
        /// Where the document came from (URL, index id, file path, memory key).
        source_url: String,
        /// Content hash of the retrieved bytes (hex), pinning exactly what was
        /// ingested so a later poisoning can be matched to this retrieval.
        content_hash: String,
        /// When the retrieval happened.
        retrieval_ts: DateTime<Utc>,
        /// Trust class of the source.
        source_class: SourceClass,
    },
    /// Forward-compatible escape hatch. `name` is the caller-defined kind label.
    Other { name: String },
}

/// Trust class of a retrieved document's source. Drives downstream policy:
/// `Web` content is untrusted by default; `Memory`/`RagIndex` may be poisoned
/// across sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    /// Fetched from the open web (untrusted).
    Web,
    /// Retrieved from a RAG / vector index.
    RagIndex,
    /// Read from a local file.
    LocalFile,
    /// Recalled from persistent agent memory (cross-session poisoning surface).
    Memory,
}

/// A single immutable lineage record.
///
/// Wire format is serde-compatible JSON for the JSONL sink and for cross-
/// process interchange. Field ordering follows audit-event convention:
/// `child` first, then `parents`, then metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEdge {
    /// The derived identity this edge produced.
    pub child: CallSpiffeId,
    /// Source identities consumed to produce `child`. Most edges have one
    /// parent; merges have many. `PodAdmit` edges have zero.
    pub parents: Vec<CallSpiffeId>,
    /// Kind discriminator with kind-specific payload.
    #[serde(flatten)]
    pub kind: EdgeKind,
    /// Optional content hash of the derived value, in hex. When present this
    /// usually matches the `/sha256:…` suffix on `child`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_hex: Option<String>,
    /// Wall-clock timestamp at edge emission time.
    pub ts: DateTime<Utc>,
    /// Free-form attributes (cost, model name, file path, exit code, …).
    /// Kept lexicographically sorted via BTreeMap for stable serialization.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
    /// Cryptographic proof signed over the edge's canonical bytes (see
    /// [`crate::proof::canonical_edge_bytes`]). `None` for legacy / unsigned
    /// edges. Edges produced by this crate's current emitters are unsigned;
    /// signing lands when an [`crate::IdentityFetcher`] impl gains an
    /// `sign_edge` method (PR-D). Verifiers should reject `None` in strict
    /// mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl LineageEdge {
    /// Construct an edge from one parent.
    pub fn from_parent(child: CallSpiffeId, parent: CallSpiffeId, kind: EdgeKind) -> Self {
        Self {
            child,
            parents: vec![parent],
            kind,
            content_hash_hex: None,
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
        }
    }

    /// Construct a document-retrieval edge: `child` retrieved a document from
    /// `source_url` (content hash `content_hash`, trust class `source_class`).
    /// `parent` is the retrieving identity (the pod/call doing the fetch).
    pub fn document_retrieved(
        child: CallSpiffeId,
        parent: CallSpiffeId,
        source_url: impl Into<String>,
        content_hash: impl Into<String>,
        source_class: SourceClass,
    ) -> Self {
        let content_hash = content_hash.into();
        Self {
            child,
            parents: vec![parent],
            kind: EdgeKind::DocumentRetrieved {
                source_url: source_url.into(),
                content_hash: content_hash.clone(),
                retrieval_ts: Utc::now(),
                source_class,
            },
            content_hash_hex: Some(content_hash),
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
        }
    }

    /// Construct a pod-admission edge (no parents).
    pub fn pod_admit(pod: CallSpiffeId) -> Self {
        Self {
            child: pod,
            parents: Vec::new(),
            kind: EdgeKind::PodAdmit,
            content_hash_hex: None,
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
        }
    }

    /// Builder: attach a content-hash to this edge.
    pub fn with_content_hash(mut self, hex: impl Into<String>) -> Self {
        self.content_hash_hex = Some(hex.into());
        self
    }

    /// Builder: attach a single attribute.
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    /// Builder: attach a cryptographic proof.
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proof = Some(proof);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::CallSpiffeId;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    #[test]
    fn document_retrieved_round_trips_and_tags() {
        let p = pod();
        let child = p.derive_artifact(b"doc-bytes").unwrap();
        let edge = LineageEdge::document_retrieved(
            child,
            p,
            "https://docs.example.com/poisoned",
            "abc123",
            SourceClass::Web,
        );
        // Provenance fields are captured on the variant.
        match &edge.kind {
            EdgeKind::DocumentRetrieved {
                source_url,
                content_hash,
                source_class,
                ..
            } => {
                assert_eq!(source_url, "https://docs.example.com/poisoned");
                assert_eq!(content_hash, "abc123");
                assert_eq!(*source_class, SourceClass::Web);
            }
            other => panic!("expected DocumentRetrieved, got {other:?}"),
        }
        // serde round-trip via the JSONL wire format.
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"document_retrieved\""));
        assert!(json.contains("\"source_class\":\"web\""));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(back, edge);
    }

    #[test]
    fn pod_admit_has_no_parents() {
        let p = pod();
        let edge = LineageEdge::pod_admit(p.clone());
        assert!(edge.parents.is_empty());
        assert_eq!(edge.child, p);
        assert!(matches!(edge.kind, EdgeKind::PodAdmit));
    }

    #[test]
    fn tool_call_edge_round_trips_json() {
        let p = pod();
        let child = p.derive_tool("Bash", Some(b"ls -la")).unwrap();
        let hash = child.content_hash_hex().unwrap().to_string();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        )
        .with_content_hash(hash)
        .with_attr("cwd", "/tmp")
        .with_attr("exit_code", "0");

        let json = serde_json::to_string(&edge).unwrap();
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    #[test]
    fn llm_call_edge_carries_provider_and_direction() {
        let p = pod();
        let prompt = p.derive_llm("anthropic", "prompt", b"hi").unwrap();
        let edge = LineageEdge::from_parent(
            prompt,
            p,
            EdgeKind::LlmCall {
                provider: "anthropic".to_string(),
                direction: "prompt".to_string(),
            },
        );
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"llm_call\""));
        assert!(json.contains("\"provider\":\"anthropic\""));
        assert!(json.contains("\"direction\":\"prompt\""));
    }

    #[test]
    fn merge_edge_carries_multiple_parents() {
        let p = pod();
        let a = p.derive_tool("Read", Some(b"a")).unwrap();
        let b = p.derive_tool("Read", Some(b"b")).unwrap();
        let merged = p.derive_artifact(b"a+b").unwrap();
        let edge = LineageEdge {
            child: merged,
            parents: vec![a.clone(), b.clone()],
            kind: EdgeKind::Merge,
            content_hash_hex: None,
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
        };
        assert_eq!(edge.parents.len(), 2);
        assert!(matches!(edge.kind, EdgeKind::Merge));
    }

    #[test]
    fn empty_attrs_skipped_in_json() {
        let p = pod();
        let edge = LineageEdge::pod_admit(p);
        let json = serde_json::to_string(&edge).unwrap();
        assert!(!json.contains("attrs"));
    }
}
