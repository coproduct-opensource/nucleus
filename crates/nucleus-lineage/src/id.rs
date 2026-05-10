//! [`CallSpiffeId`] — a SPIFFE-format identity for an individual call or artifact.
//!
//! These IDs derive from a parent SPIFFE ID by appending a `/call/<uuid>/...`
//! segment. The leaf segment optionally carries a `/sha256:<hex>` suffix that
//! makes the ID content-addressed.
//!
//! `CallSpiffeId` does NOT validate the trust-domain prefix beyond requiring
//! `spiffe://<authority>/<path>`; it is structurally a wrapper around the
//! standard SPIFFE URI grammar with stricter constraints on the `/call/...`
//! suffix structure that this crate owns.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

/// Errors when constructing or parsing a [`CallSpiffeId`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdError {
    #[error("expected URI to start with `spiffe://`, got {0:?}")]
    NotSpiffe(String),
    #[error("missing trust domain authority in {0:?}")]
    MissingAuthority(String),
    #[error("missing path segment after trust domain in {0:?}")]
    MissingPath(String),
    #[error("invalid call uuid {0:?}: {1}")]
    InvalidCallUuid(String, uuid::Error),
    #[error("invalid sha256 suffix {0:?}: must be 64 lowercase hex chars")]
    InvalidContentHash(String),
    #[error("path component {0:?} is empty or contains only whitespace")]
    EmptyComponent(String),
    #[error("path component {0:?} contains a `/`; pass segments individually")]
    SlashInComponent(String),
}

/// A SPIFFE-format identity for a call, artifact, or derived value.
///
/// Stored as the canonical string form (`spiffe://...`) plus a parsed
/// breakdown of the call-specific suffix when present. Equality and hashing
/// are based on the canonical string.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CallSpiffeId(String);

impl CallSpiffeId {
    /// Construct from a raw SPIFFE URI string. Validates the scheme,
    /// authority, and any `/call/<uuid>/...` suffix's structure (call uuid
    /// well-formed; content-hash suffix is 64 hex chars when present).
    pub fn parse(uri: impl Into<String>) -> Result<Self, IdError> {
        let uri = uri.into();
        let rest = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| IdError::NotSpiffe(uri.clone()))?;
        let (authority, path) = rest
            .split_once('/')
            .ok_or_else(|| IdError::MissingPath(uri.clone()))?;
        if authority.is_empty() {
            return Err(IdError::MissingAuthority(uri.clone()));
        }
        if path.is_empty() {
            return Err(IdError::MissingPath(uri.clone()));
        }
        // Validate any /call/<uuid>/... suffix structure.
        if let Some(call_idx) = path.find("/call/").map(|i| i + 1) {
            let suffix = &path[call_idx..];
            let mut parts = suffix.split('/');
            let _call = parts.next(); // "call"
            let uuid_part = parts
                .next()
                .ok_or_else(|| IdError::InvalidCallUuid(suffix.to_string(), uuid_error()))?;
            Uuid::parse_str(uuid_part)
                .map_err(|e| IdError::InvalidCallUuid(uuid_part.to_string(), e))?;
            if let Some(hash_seg) = suffix.split('/').next_back() {
                if let Some(hex) = hash_seg.strip_prefix("sha256:") {
                    let valid = hex.len() == 64
                        && hex
                            .chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
                    if !valid {
                        return Err(IdError::InvalidContentHash(hex.to_string()));
                    }
                }
            }
        }
        Ok(Self(uri))
    }

    /// Construct a pod-root SPIFFE ID (no `/call/...` suffix).
    /// Validates that no path component is empty or contains a slash.
    pub fn pod(
        trust_domain: &str,
        namespace: &str,
        service_account: &str,
    ) -> Result<Self, IdError> {
        for c in [trust_domain, namespace, service_account] {
            check_segment(c)?;
        }
        Self::parse(format!(
            "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"
        ))
    }

    /// Derive a child ID for a tool call.
    ///
    /// The new path segment is `/call/<uuid>/tool/<tool>`. If `content` is
    /// `Some`, a `/sha256:<hex>` suffix is appended (content-addressed).
    pub fn derive_tool(&self, tool: &str, content: Option<&[u8]>) -> Result<Self, IdError> {
        check_segment(tool)?;
        let uuid = Uuid::new_v4();
        let mut path = format!("{}/call/{uuid}/tool/{tool}", self.0);
        if let Some(bytes) = content {
            path.push_str(&format!("/sha256:{}", hex_lower(&sha256(bytes))));
        }
        Self::parse(path)
    }

    /// Derive a child ID for an LLM call (input prompt or output response).
    ///
    /// `direction` is typically `"prompt"` or `"response"`. `content` is
    /// always required and content-addressed.
    pub fn derive_llm(
        &self,
        provider: &str,
        direction: &str,
        content: &[u8],
    ) -> Result<Self, IdError> {
        for c in [provider, direction] {
            check_segment(c)?;
        }
        let uuid = Uuid::new_v4();
        let path = format!(
            "{}/call/{uuid}/llm/{provider}/{direction}/sha256:{}",
            self.0,
            hex_lower(&sha256(content))
        );
        Self::parse(path)
    }

    /// Derive a child ID for a deterministically-derived artifact.
    ///
    /// The new segment is `/call/<uuid>/derived/sha256:<hex>`. The uuid
    /// distinguishes derivations of the same content from different parents
    /// (preserving the lineage edge); the content hash distinguishes
    /// content-different derivations from the same parent.
    pub fn derive_artifact(&self, content: &[u8]) -> Result<Self, IdError> {
        let uuid = Uuid::new_v4();
        let path = format!(
            "{}/call/{uuid}/derived/sha256:{}",
            self.0,
            hex_lower(&sha256(content))
        );
        Self::parse(path)
    }

    /// Return the canonical SPIFFE URI string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the immediate parent ID, if any. The parent is everything up
    /// to (but not including) the last `/call/<uuid>/...` segment that this
    /// ID added. For a pod ID with no call suffix, returns `None`.
    pub fn parent(&self) -> Option<Self> {
        let path_start = "spiffe://".len();
        let after_authority = self.0[path_start..].find('/').map(|i| path_start + i + 1)?;
        let path = &self.0[after_authority..];
        // Find every "/call/" occurrence; the parent is everything before
        // the LAST one.
        let last_call = path.rfind("/call/")?;
        let parent_path = &self.0[..after_authority + last_call];
        Self::parse(parent_path.to_string()).ok()
    }

    /// Extract the content-hash hex suffix if this ID is content-addressed.
    pub fn content_hash_hex(&self) -> Option<&str> {
        self.0
            .rsplit_once("/sha256:")
            .map(|(_, hex)| hex)
            .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
    }

    /// True if this ID has a `/call/...` suffix beyond the pod root.
    pub fn is_call(&self) -> bool {
        self.0.contains("/call/")
    }
}

impl fmt::Display for CallSpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CallSpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CallSpiffeId({})", self.0)
    }
}

impl FromStr for CallSpiffeId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s.to_string())
    }
}

fn check_segment(s: &str) -> Result<(), IdError> {
    if s.trim().is_empty() {
        return Err(IdError::EmptyComponent(s.to_string()));
    }
    if s.contains('/') {
        return Err(IdError::SlashInComponent(s.to_string()));
    }
    Ok(())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn hex_lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// Stand-in Uuid::Error used for "missing uuid" path; the underlying parse_str
// will produce a real one when content is present.
fn uuid_error() -> uuid::Error {
    Uuid::parse_str("").unwrap_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    #[test]
    fn pod_id_round_trips() {
        let p = pod();
        assert_eq!(p.as_str(), "spiffe://prod.example.com/ns/agents/sa/coder");
        assert!(!p.is_call());
        assert_eq!(p.parent(), None);
    }

    #[test]
    fn pod_rejects_empty_segment() {
        assert!(matches!(
            CallSpiffeId::pod("prod.example.com", "", "coder"),
            Err(IdError::EmptyComponent(_))
        ));
    }

    #[test]
    fn pod_rejects_slash_in_segment() {
        assert!(matches!(
            CallSpiffeId::pod("prod.example.com", "agents/sub", "coder"),
            Err(IdError::SlashInComponent(_))
        ));
    }

    #[test]
    fn parse_rejects_wrong_scheme() {
        assert!(matches!(
            CallSpiffeId::parse("https://prod.example.com/x"),
            Err(IdError::NotSpiffe(_))
        ));
    }

    #[test]
    fn parse_rejects_missing_path() {
        assert!(matches!(
            CallSpiffeId::parse("spiffe://prod.example.com"),
            Err(IdError::MissingPath(_))
        ));
    }

    #[test]
    fn derive_tool_appends_call_segment() {
        let p = pod();
        let child = p.derive_tool("Bash", None).unwrap();
        assert!(child.as_str().starts_with(p.as_str()));
        assert!(child.as_str().contains("/call/"));
        assert!(child.as_str().contains("/tool/Bash"));
        assert!(child.is_call());
        assert_eq!(child.parent().unwrap(), p);
    }

    #[test]
    fn derive_tool_with_content_is_content_addressed() {
        let p = pod();
        let a1 = p.derive_tool("Bash", Some(b"hello")).unwrap();
        assert!(a1
            .as_str()
            .ends_with(&format!("/sha256:{}", hex_lower(&sha256(b"hello")))));
        let hash = a1.content_hash_hex().unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hex_lower(&sha256(b"hello")));
    }

    #[test]
    fn derive_tool_different_content_distinct_ids() {
        let p = pod();
        let a = p.derive_tool("Bash", Some(b"hello")).unwrap();
        let b = p.derive_tool("Bash", Some(b"world")).unwrap();
        // Different content → different content-hash suffix (uuid also differs).
        assert_ne!(a.content_hash_hex(), b.content_hash_hex());
    }

    #[test]
    fn derive_llm_always_content_addressed() {
        let p = pod();
        let prompt = p.derive_llm("anthropic", "prompt", b"hi claude").unwrap();
        assert!(prompt.as_str().contains("/llm/anthropic/prompt/sha256:"));
        assert_eq!(
            prompt.content_hash_hex().unwrap(),
            hex_lower(&sha256(b"hi claude"))
        );
    }

    #[test]
    fn derive_artifact_appends_derived_segment() {
        let p = pod();
        let leaf = p.derive_artifact(b"output bytes").unwrap();
        assert!(leaf.as_str().contains("/derived/sha256:"));
        assert_eq!(
            leaf.content_hash_hex().unwrap(),
            hex_lower(&sha256(b"output bytes"))
        );
    }

    #[test]
    fn parent_walks_back_one_level() {
        let p = pod();
        let tool = p.derive_tool("Bash", Some(b"x")).unwrap();
        let derived = tool.derive_artifact(b"y").unwrap();
        assert_eq!(derived.parent().unwrap(), tool);
        assert_eq!(tool.parent().unwrap(), p);
        assert_eq!(p.parent(), None);
    }

    #[test]
    fn parse_rejects_uppercase_content_hash() {
        let bad = format!(
            "spiffe://prod.example.com/ns/agents/sa/coder/call/{}/derived/sha256:ABCDEF{}",
            Uuid::new_v4(),
            "0".repeat(58)
        );
        assert!(matches!(
            CallSpiffeId::parse(bad),
            Err(IdError::InvalidContentHash(_))
        ));
    }

    #[test]
    fn parse_rejects_short_content_hash() {
        let bad = format!(
            "spiffe://prod.example.com/ns/agents/sa/coder/call/{}/derived/sha256:abc",
            Uuid::new_v4()
        );
        assert!(matches!(
            CallSpiffeId::parse(bad),
            Err(IdError::InvalidContentHash(_))
        ));
    }

    #[test]
    fn parse_rejects_invalid_call_uuid() {
        let bad = "spiffe://prod.example.com/ns/agents/sa/coder/call/not-a-uuid/tool/Bash";
        assert!(matches!(
            CallSpiffeId::parse(bad),
            Err(IdError::InvalidCallUuid(_, _))
        ));
    }

    #[test]
    fn from_str_and_display_round_trip() {
        let p = pod();
        let s = p.to_string();
        let parsed: CallSpiffeId = s.parse().unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn serde_round_trip() {
        let p = pod();
        let derived = p.derive_artifact(b"x").unwrap();
        let json = serde_json::to_string(&derived).unwrap();
        let back: CallSpiffeId = serde_json::from_str(&json).unwrap();
        assert_eq!(derived, back);
    }
}
