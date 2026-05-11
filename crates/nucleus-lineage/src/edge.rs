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
    /// Forward-compatible escape hatch. `name` is the caller-defined kind label.
    Other { name: String },
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
