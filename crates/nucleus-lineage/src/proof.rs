//! Cryptographic proof carried alongside [`LineageEdge`] records.
//!
//! This module ships the **wire format** for proofs and the **canonical-bytes
//! computation** that proofs are signed over. Actual signing/verification
//! happens in the issuer impl (e.g. [`LocalIssuer`](crate::local_issuer)) and
//! in a future verifier — those land in PR-D.
//!
//! Today, [`LineageEdge::proof`] is `None` for every edge produced by this
//! crate (legacy/unsigned). This module exists so the wire format has a slot
//! for the cryptographic evidence — adding signing later does not require a
//! breaking change to the JSONL log format.
//!
//! # Canonical encoding
//!
//! [`canonical_edge_bytes`] returns the bytes a signer should sign and a
//! verifier should verify against. The encoding is deterministic:
//!
//! 1. `child` SPIFFE ID, NUL-separated
//! 2. `kind` discriminator (snake_case), NUL-separated
//! 3. parent SPIFFE IDs in given order, each NUL-separated
//! 4. content hash (32 zero bytes if absent)
//! 5. RFC3339 timestamp string, NUL-separated
//! 6. previous edge's content hash from the proof chain (32 zero bytes if absent)
//!
//! Field-bag attributes (`attrs`) are intentionally NOT covered — they are
//! free-form metadata; the signed surface is the structural lineage edge.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::edge::{EdgeKind, LineageEdge};

/// A cryptographic proof attached to a [`LineageEdge`].
///
/// `kid` and `alg` are JWS-style identifiers so a future JWKS-backed
/// verifier can pick the right verifying key + algorithm. `sig` is the raw
/// signature bytes over [`canonical_edge_bytes`]. `prev_hash` is the SHA-256
/// of the previous edge's canonical bytes, forming a hash chain.
///
/// Wire format is JSON-stable — add fields with `#[serde(default)]` only,
/// never remove or rename existing ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// JWS key id; resolves to a verifying key via the issuer's JWKS.
    pub kid: String,
    /// JWS algorithm string (e.g., "EdDSA"). String not enum so we don't
    /// pin the verifier to a specific JWT library.
    pub alg: String,
    /// Raw signature bytes over [`canonical_edge_bytes`].
    #[serde(with = "base64_bytes")]
    pub sig: Vec<u8>,
    /// SHA-256 of the previous edge's canonical bytes (hash chain). `None`
    /// for the first edge in a log.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_hash_hex"
    )]
    pub prev_hash: Option<[u8; 32]>,
}

impl Proof {
    /// Construct a Proof. Validation of the signature happens in the
    /// verifier — this constructor just builds the wire object.
    pub fn new(kid: impl Into<String>, alg: impl Into<String>, sig: Vec<u8>) -> Self {
        Self {
            kid: kid.into(),
            alg: alg.into(),
            sig,
            prev_hash: None,
        }
    }

    /// Builder: attach a previous-edge hash for chaining.
    pub fn with_prev_hash(mut self, prev_hash: [u8; 32]) -> Self {
        self.prev_hash = Some(prev_hash);
        self
    }
}

/// Compute the canonical bytes that a [`LineageEdge`]'s [`Proof`] is signed
/// over. Stable across calls. See module docs for the encoding rules.
pub fn canonical_edge_bytes(edge: &LineageEdge, prev_hash: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    let push_field = |out: &mut Vec<u8>, s: &str| {
        out.extend_from_slice(s.as_bytes());
        out.push(0); // NUL separator — never appears inside SPIFFE IDs (hardened parser)
    };

    push_field(&mut out, edge.child.as_str());
    push_field(&mut out, kind_tag(&edge.kind));
    for parent in &edge.parents {
        push_field(&mut out, parent.as_str());
    }
    // Empty marker between parents and the rest, so any future addition
    // of more parents doesn't shift the trailing bytes' meaning.
    out.push(0);

    if let Some(hex) = edge.content_hash_hex.as_deref() {
        out.extend_from_slice(hex.as_bytes());
    } else {
        out.extend_from_slice(&[0u8; 64]); // 64 zero ASCII bytes = "no content hash"
    }
    out.push(0);

    push_field(&mut out, &edge.ts.to_rfc3339());

    if let Some(h) = prev_hash {
        out.extend_from_slice(h);
    } else {
        out.extend_from_slice(&[0u8; 32]);
    }

    out
}

/// Compute the SHA-256 of an edge's canonical bytes — useful as a
/// `prev_hash` for the next edge in a chain.
pub fn edge_content_hash(edge: &LineageEdge, prev_hash: Option<&[u8; 32]>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical_edge_bytes(edge, prev_hash));
    h.finalize().into()
}

/// Stable string tag for an [`EdgeKind`]. Mirrors what serde would emit
/// for `#[serde(tag = "kind", rename_all = "snake_case")]`. Centralized so
/// the canonical encoding doesn't depend on serde's runtime.
fn kind_tag(kind: &EdgeKind) -> &'static str {
    match kind {
        EdgeKind::PodAdmit => "pod_admit",
        EdgeKind::ToolCall { .. } => "tool_call",
        EdgeKind::LlmCall { .. } => "llm_call",
        EdgeKind::ArtifactProduced => "artifact_produced",
        EdgeKind::Merge => "merge",
        EdgeKind::Other { .. } => "other",
    }
}

// ── serde helpers ───────────────────────────────────────────────────────

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

mod opt_hash_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes (64 hex chars), got {}",
                        bytes.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{EdgeKind, LineageEdge};
    use crate::id::CallSpiffeId;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    #[test]
    fn proof_round_trips_through_json() {
        let p = Proof::new("kid-abc", "EdDSA", vec![1, 2, 3, 4, 5]).with_prev_hash([0xAA; 32]);
        let json = serde_json::to_string(&p).unwrap();
        let back: Proof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn proof_skips_prev_hash_when_none() {
        let p = Proof::new("kid", "EdDSA", vec![1, 2, 3]);
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("prev_hash"));
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let p = pod();
        let child = p.derive_tool("Bash", Some(b"x")).unwrap();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let bytes1 = canonical_edge_bytes(&edge, None);
        let bytes2 = canonical_edge_bytes(&edge, None);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn canonical_bytes_change_if_child_changes() {
        let p = pod();
        let edge_a = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"a")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let edge_b = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"b")).unwrap(),
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        assert_ne!(
            canonical_edge_bytes(&edge_a, None),
            canonical_edge_bytes(&edge_b, None)
        );
    }

    #[test]
    fn canonical_bytes_change_if_prev_hash_changes() {
        let p = pod();
        let child = p.derive_tool("Bash", Some(b"x")).unwrap();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let bytes_none = canonical_edge_bytes(&edge, None);
        let bytes_some = canonical_edge_bytes(&edge, Some(&[0xAA; 32]));
        assert_ne!(bytes_none, bytes_some);
    }

    #[test]
    fn edge_content_hash_is_deterministic_and_32_bytes() {
        let p = pod();
        let child = p.derive_artifact(b"hello").unwrap();
        let edge = LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced);
        let h1 = edge_content_hash(&edge, None);
        let h2 = edge_content_hash(&edge, None);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn prev_hash_chains_via_canonical_bytes() {
        let p = pod();
        let edge1 = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"1")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let h1 = edge_content_hash(&edge1, None);

        let edge2 = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"2")).unwrap(),
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let h2_chained = edge_content_hash(&edge2, Some(&h1));
        let h2_unchained = edge_content_hash(&edge2, None);
        assert_ne!(h2_chained, h2_unchained, "chain must affect hash");
    }

    #[test]
    fn pod_admit_canonical_bytes_have_no_parents() {
        let edge = LineageEdge::pod_admit(pod());
        let bytes = canonical_edge_bytes(&edge, None);
        // child + kind tag should be present
        assert!(bytes
            .windows(7)
            .any(|w| w == b"agents/" || w == b"sa/code" || w.starts_with(b"spiffe:")));
    }
}
