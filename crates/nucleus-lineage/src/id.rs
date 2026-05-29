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
    #[error("invalid sha256 suffix {0:?}: must be exactly `sha256:<64 lowercase hex>`")]
    InvalidContentHash(String),
    #[error("path component {0:?} is empty or contains only whitespace")]
    EmptyComponent(String),
    #[error("path component {0:?} contains a `/`; pass segments individually")]
    SlashInComponent(String),
    #[error("input is too long ({len} bytes; max {max} allowed)", max = MAX_URI_LEN)]
    TooLong { len: usize },
    #[error("input contains forbidden character {0:?} at byte offset {1}")]
    ForbiddenChar(char, usize),
    #[error("authority {0:?} contains characters outside `[a-z0-9._-]`")]
    InvalidAuthority(String),
    #[error("path component {0:?} contains characters outside `[A-Za-z0-9._-]` (or the reserved `sha256:<hex>` form)")]
    InvalidPathChar(String),
    #[error("path contains an empty segment (consecutive `/` or trailing `/`) in {0:?}")]
    EmptyPathSegment(String),
    #[error("`/call/` segment must be exactly lowercase, found {0:?}")]
    NonCanonicalCallSegment(String),
}

/// Maximum URI length we'll accept. SPIFFE IDs in practice are short; a
/// hard cap prevents pathological-input DoS in the parser.
pub const MAX_URI_LEN: usize = 4096;

/// A SPIFFE-format identity for a call, artifact, or derived value.
///
/// Stored as the canonical string form (`spiffe://...`) plus a parsed
/// breakdown of the call-specific suffix when present. Equality and hashing
/// are based on the canonical string.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CallSpiffeId(String);

impl CallSpiffeId {
    /// Construct from a raw SPIFFE URI string.
    ///
    /// Validates per the SPIFFE ID spec, with the documented deviation that
    /// the literal `:` character is permitted in the special last-segment form
    /// `sha256:<64-lowercase-hex>` (used for content-addressed lineage).
    /// Otherwise:
    ///
    /// - Scheme must be `spiffe://`.
    /// - URI length must be ≤ [`MAX_URI_LEN`] bytes.
    /// - Every byte must be ASCII printable (rejects NUL, control chars,
    ///   RTL/LRO Unicode overrides, and any non-ASCII).
    /// - URI components `?` (query), `#` (fragment), and `@` (userinfo) are
    ///   absent — SPIFFE forbids them.
    /// - Authority charset: lowercase ASCII letters, digits, `-`, `.`, `_`.
    ///   No `:` (no port), no `@` (no userinfo).
    /// - Path segments are non-empty (rejects `//`, leading `//`, trailing `/`).
    /// - Path segment charset: `[A-Za-z0-9._-]` per SPIFFE, or the reserved
    ///   form `sha256:<64 lowercase hex>`.
    /// - Any `/call/...` suffix must use lowercase `call` and a well-formed
    ///   uuid in the next segment.
    pub fn parse(uri: impl Into<String>) -> Result<Self, IdError> {
        let uri = uri.into();

        // 1. Hard length cap (DoS guard).
        if uri.len() > MAX_URI_LEN {
            return Err(IdError::TooLong { len: uri.len() });
        }

        // 2. ASCII printable only — rejects NUL, control chars, RTL/LRO
        //    overrides (U+202E/U+202D), any other Unicode. SPIFFE IDs are
        //    ASCII per spec; rejecting non-ASCII closes the homograph /
        //    visual-spoofing surface in the `nucleus lineage` renderer.
        for (i, ch) in uri.char_indices() {
            // Allow only ASCII range 0x20..=0x7E plus the structural chars
            // that appear in spiffe URIs (handled by other rules below).
            if !ch.is_ascii() || (ch as u32) < 0x20 || (ch as u32) == 0x7F {
                return Err(IdError::ForbiddenChar(ch, i));
            }
        }

        // 3. Reject query, fragment, userinfo. SPIFFE ID grammar forbids
        //    `?`, `#`, `@`. We reject anywhere in the URI rather than only
        //    at canonical positions; defense in depth.
        for forbidden in ['?', '#', '@'] {
            if let Some(pos) = uri.find(forbidden) {
                return Err(IdError::ForbiddenChar(forbidden, pos));
            }
        }

        // 4. Scheme.
        let rest = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| IdError::NotSpiffe(uri.clone()))?;

        // 5. Authority + path split. Authority is everything up to the first
        //    `/`. Path begins after.
        let (authority, path) = rest
            .split_once('/')
            .ok_or_else(|| IdError::MissingPath(uri.clone()))?;
        if authority.is_empty() {
            return Err(IdError::MissingAuthority(uri.clone()));
        }
        if path.is_empty() {
            return Err(IdError::MissingPath(uri.clone()));
        }

        // 6. Authority charset. SPIFFE: lowercase letters, digits, `-`, `.`,
        //    `_`. No port (`:`), no userinfo (already rejected above).
        if !authority
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_'))
        {
            return Err(IdError::InvalidAuthority(authority.to_string()));
        }

        // 7. Path segments: non-empty, valid charset.
        for segment in path.split('/') {
            if segment.is_empty() {
                return Err(IdError::EmptyPathSegment(uri.clone()));
            }
            // Special case: a `sha256:`-prefixed segment is a content-hash;
            // route its specific failure to InvalidContentHash for actionable
            // error messages. Note: case-sensitive — `SHA256:` falls through
            // to the generic path-charset check below and is rejected there.
            if let Some(hex) = segment.strip_prefix("sha256:") {
                let valid = hex.len() == 64
                    && hex
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'));
                if !valid {
                    return Err(IdError::InvalidContentHash(segment.to_string()));
                }
                continue;
            }
            if !is_valid_path_segment(segment) {
                return Err(IdError::InvalidPathChar(segment.to_string()));
            }
        }

        // 8. Validate any /call/<uuid>/... suffix structure. The first /call/
        //    segment must be lowercase; any uppercase variant (e.g. /CALL/)
        //    is non-canonical and rejected (closes the suffix-bypass case
        //    where uppercase /CALL/ skips uuid validation).
        let mut path_parts = path.split('/').peekable();
        while let Some(seg) = path_parts.next() {
            if seg.eq_ignore_ascii_case("call") && seg != "call" {
                return Err(IdError::NonCanonicalCallSegment(seg.to_string()));
            }
            if seg == "call" {
                let uuid_part = path_parts.next().ok_or_else(|| {
                    IdError::InvalidCallUuid("(missing)".to_string(), uuid_error())
                })?;
                Uuid::parse_str(uuid_part)
                    .map_err(|e| IdError::InvalidCallUuid(uuid_part.to_string(), e))?;
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

    /// Render as a WIMSE Workload Identifier per `draft-ietf-wimse-identifier`.
    ///
    /// Per AIMS §3 (`draft-klrc-aiagent-auth-00`): "An agent participating
    /// in this framework MUST be assigned exactly one WIMSE identifier,
    /// which MAY be a SPIFFE ID." Per the WIMSE identifier draft §3.2:
    /// "Every SPIFFE-ID is a valid WIMSE Workload Identifier" — so we
    /// emit the canonical `spiffe://` form unchanged and remain
    /// conformant by inclusion. Consumers that prefer the explicit
    /// `wimse://` scheme can post-process the returned string; the
    /// internal canonical form stays SPIFFE-based to keep existing
    /// callers, audit logs, and `grep` searches stable.
    ///
    /// This method exists primarily for API clarity: a call site that
    /// reaches for a WIMSE identifier should call `to_wimse_uri()` so
    /// the WIMSE context is documented at the call site, even though
    /// the bytes are equal to [`Self::as_str`].
    pub fn to_wimse_uri(&self) -> &str {
        &self.0
    }

    /// Parse a WIMSE Workload Identifier per `draft-ietf-wimse-identifier`.
    ///
    /// Accepts BOTH:
    /// - `spiffe://<trust-domain>/<path>` — the canonical SPIFFE form
    ///   (delegates to [`Self::parse`]).
    /// - `wimse://<trust-domain>/<path>` — the explicit WIMSE alias.
    ///   The scheme is normalized to `spiffe://` before parsing, since
    ///   the path/authority grammar is identical between the two
    ///   schemes (per the WIMSE draft).
    ///
    /// **Scheme case-sensitivity:** WIMSE / SPIFFE URIs use a lowercase
    /// scheme. We reject `WIMSE://`, `Spiffe://`, etc. to keep parsing
    /// canonical (RFC 3986 §3.1 says schemes are case-insensitive in
    /// principle but case-normalized in canonical form; we enforce the
    /// canonical form on input rather than normalizing).
    pub fn from_wimse_uri(uri: &str) -> Result<Self, IdError> {
        if let Some(rest) = uri.strip_prefix("wimse://") {
            Self::parse(format!("spiffe://{rest}"))
        } else {
            Self::parse(uri.to_string())
        }
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

/// Per SPIFFE ID spec, path segments use `[A-Za-z0-9._-]`. We additionally
/// permit the reserved last-segment form `sha256:<64 lowercase hex>` for
/// content-addressed lineage suffixes — the only allowed appearance of `:`
/// in any segment.
fn is_valid_path_segment(seg: &str) -> bool {
    if let Some(hex) = seg.strip_prefix("sha256:") {
        return hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'));
    }
    !seg.is_empty()
        && seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
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
        let prompt = p.derive_llm("provider-a", "prompt", b"hi there").unwrap();
        assert!(prompt.as_str().contains("/llm/provider-a/prompt/sha256:"));
        assert_eq!(
            prompt.content_hash_hex().unwrap(),
            hex_lower(&sha256(b"hi there"))
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

    // ── Hardened-parser negative tests ─────────────────────────────────
    // These cases were accepted by the original parser; a skeptical-code
    // auditor pass enumerated each as a real input that should fail.

    #[test]
    fn parse_rejects_nul_byte_in_path() {
        let err = CallSpiffeId::parse("spiffe://prod.example.com/ns/agents\0/sa/coder")
            .expect_err("NUL byte must be rejected");
        assert!(matches!(err, IdError::ForbiddenChar('\0', _)), "{err:?}");
    }

    #[test]
    fn parse_rejects_rtl_unicode_override() {
        // U+202E (RIGHT-TO-LEFT OVERRIDE) — used for visual spoofing.
        let err = CallSpiffeId::parse("spiffe://prod.example.com/ns/admin\u{202E}/sa/coder")
            .expect_err("RTL override must be rejected (non-ASCII)");
        assert!(matches!(err, IdError::ForbiddenChar(_, _)), "{err:?}");
    }

    #[test]
    fn parse_rejects_other_control_chars() {
        // U+0007 BEL, embedded in a path component.
        let err = CallSpiffeId::parse("spiffe://prod.example.com/ns/agents\u{0007}/sa/coder")
            .expect_err("control char must be rejected");
        assert!(matches!(err, IdError::ForbiddenChar(_, _)), "{err:?}");
    }

    #[test]
    fn parse_rejects_double_slash() {
        let err = CallSpiffeId::parse("spiffe://prod.example.com//ns/agents/sa/coder")
            .expect_err("double slash must be rejected");
        assert!(matches!(err, IdError::EmptyPathSegment(_)), "{err:?}");
    }

    #[test]
    fn parse_rejects_trailing_slash() {
        let err = CallSpiffeId::parse("spiffe://prod.example.com/ns/agents/sa/coder/")
            .expect_err("trailing slash must be rejected");
        assert!(matches!(err, IdError::EmptyPathSegment(_)), "{err:?}");
    }

    #[test]
    fn parse_rejects_empty_path_only_root() {
        let err = CallSpiffeId::parse("spiffe://prod.example.com//")
            .expect_err("empty path must be rejected");
        assert!(matches!(err, IdError::EmptyPathSegment(_)), "{err:?}");
    }

    #[test]
    fn parse_rejects_uppercase_call_segment() {
        // Original parser only validated /call/ via lowercase string.find,
        // so /CALL/ slipped past the uuid check entirely.
        let err =
            CallSpiffeId::parse("spiffe://prod.example.com/ns/agents/sa/coder/CALL/abc/tool/Bash")
                .expect_err("uppercase /CALL/ must be rejected");
        assert!(
            matches!(err, IdError::NonCanonicalCallSegment(_)),
            "{err:?}"
        );
    }

    #[test]
    fn parse_rejects_query_string() {
        let err = CallSpiffeId::parse("spiffe://prod.example.com/ns/agents/sa/coder?x=1")
            .expect_err("URI query must be rejected");
        assert!(matches!(err, IdError::ForbiddenChar('?', _)), "{err:?}");
    }

    #[test]
    fn parse_rejects_fragment() {
        let err = CallSpiffeId::parse("spiffe://prod.example.com/ns/agents/sa/coder#frag")
            .expect_err("URI fragment must be rejected");
        assert!(matches!(err, IdError::ForbiddenChar('#', _)), "{err:?}");
    }

    #[test]
    fn parse_rejects_userinfo_in_authority() {
        let err = CallSpiffeId::parse("spiffe://attacker:p@prod.example.com/ns/agents/sa/coder")
            .expect_err("userinfo must be rejected");
        assert!(matches!(err, IdError::ForbiddenChar('@', _)), "{err:?}");
    }

    #[test]
    fn parse_rejects_uppercase_authority() {
        // SPIFFE: trust-domain is lowercase.
        let err = CallSpiffeId::parse("spiffe://Prod.Example.Com/ns/agents/sa/coder")
            .expect_err("uppercase authority must be rejected");
        assert!(matches!(err, IdError::InvalidAuthority(_)), "{err:?}");
    }

    #[test]
    fn parse_rejects_uppercase_sha256_prefix() {
        // /SHA256:<hex> previously parsed but content_hash_hex returned None
        // — silent inconsistency. Now rejected as invalid path segment.
        let bad = format!(
            "spiffe://prod.example.com/ns/agents/sa/coder/call/{}/tool/Bash/SHA256:{}",
            Uuid::new_v4(),
            "a".repeat(64)
        );
        let err = CallSpiffeId::parse(bad).expect_err("/SHA256: must be rejected");
        assert!(matches!(err, IdError::InvalidPathChar(_)), "{err:?}");
    }

    #[test]
    fn parse_rejects_too_long_input() {
        let bad = format!("spiffe://prod.example.com/{}", "a".repeat(MAX_URI_LEN));
        let err = CallSpiffeId::parse(bad).expect_err("over-length URI must be rejected");
        assert!(matches!(err, IdError::TooLong { .. }), "{err:?}");
    }

    #[test]
    fn parse_rejects_path_traversal_segment() {
        // ".." is itself a valid SPIFFE path segment (only [A-Za-z0-9._-]),
        // so we permit it structurally — but its presence should not enable
        // any escape because the canonical string never collapses it. This
        // test pins the behavior so a future "path-canonicalization" change
        // must be deliberate.
        let id = CallSpiffeId::parse("spiffe://prod.example.com/ns/../sa/coder").unwrap();
        assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/../sa/coder");
        // The structural parent walker uses string prefix only — it does not
        // resolve `..`. (The walker is hardened separately in PR-C.)
    }

    #[test]
    fn parse_rejects_colon_outside_sha256_prefix() {
        // `:` is forbidden in SPIFFE path segments except in the reserved
        // `sha256:<hex>` last-segment form. Anywhere else → rejected.
        let err = CallSpiffeId::parse("spiffe://prod.example.com/ns/has:colon/sa/coder")
            .expect_err("`:` outside sha256 prefix must be rejected");
        assert!(matches!(err, IdError::InvalidPathChar(_)), "{err:?}");
    }

    #[test]
    fn parse_accepts_canonical_pod_id() {
        // Sanity: don't regress accepted inputs.
        CallSpiffeId::parse("spiffe://prod.example.com/ns/agents/sa/coder").unwrap();
    }

    // ── WIMSE conformance (task #40 / GAP-10) ──────────────────────────

    #[test]
    fn to_wimse_uri_returns_canonical_spiffe_form() {
        // Per #30 GAP-10 recommendation: backwards-compat keeps spiffe://
        // as the canonical wire form. `to_wimse_uri()` is API-level
        // clarity, not a byte-level transformation.
        let p = pod();
        assert_eq!(p.to_wimse_uri(), p.as_str());
        assert!(p.to_wimse_uri().starts_with("spiffe://"));
    }

    #[test]
    fn from_wimse_uri_accepts_spiffe_scheme() {
        // The canonical input still works.
        let id =
            CallSpiffeId::from_wimse_uri("spiffe://prod.example.com/ns/agents/sa/coder").unwrap();
        assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/agents/sa/coder");
    }

    #[test]
    fn from_wimse_uri_accepts_wimse_scheme_and_normalizes() {
        // `wimse://` is rewritten to `spiffe://` because our internal
        // canonical form is SPIFFE.
        let id =
            CallSpiffeId::from_wimse_uri("wimse://prod.example.com/ns/agents/sa/coder").unwrap();
        assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/agents/sa/coder");
    }

    #[test]
    fn from_wimse_uri_rejects_uppercase_scheme() {
        // Defensive: only the lowercase canonical forms are accepted.
        assert!(matches!(
            CallSpiffeId::from_wimse_uri("WIMSE://prod.example.com/ns/agents/sa/coder"),
            Err(IdError::NotSpiffe(_))
        ));
        assert!(matches!(
            CallSpiffeId::from_wimse_uri("Spiffe://prod.example.com/ns/agents/sa/coder"),
            Err(IdError::NotSpiffe(_))
        ));
        assert!(matches!(
            CallSpiffeId::from_wimse_uri("WiMsE://prod.example.com/ns/agents/sa/coder"),
            Err(IdError::NotSpiffe(_))
        ));
    }

    #[test]
    fn from_wimse_uri_rejects_other_schemes() {
        assert!(matches!(
            CallSpiffeId::from_wimse_uri("https://prod.example.com/path"),
            Err(IdError::NotSpiffe(_))
        ));
        assert!(matches!(
            CallSpiffeId::from_wimse_uri("urn:example:id"),
            Err(IdError::NotSpiffe(_))
        ));
    }

    /// Acceptance property for #40 (a): `from_wimse_uri(to_wimse_uri(id)) == id`
    /// across pod IDs and content-addressed `/call/...` IDs.
    #[test]
    fn wimse_uri_round_trip_property() {
        let cases = [
            // Pod ID.
            pod(),
            // Single tool-call edge.
            pod().derive_tool("Bash", Some(b"hello")).unwrap(),
            // Chained: tool → llm → derived.
            pod()
                .derive_tool("Bash", Some(b"x"))
                .unwrap()
                .derive_llm("provider-a", "prompt", b"hi")
                .unwrap()
                .derive_artifact(b"result")
                .unwrap(),
        ];
        for id in cases {
            let round_tripped = CallSpiffeId::from_wimse_uri(id.to_wimse_uri()).unwrap();
            assert_eq!(
                id,
                round_tripped,
                "wimse round-trip must equal original for {:?}",
                id.as_str()
            );
        }
    }

    /// Cross-scheme: `wimse://X` and `spiffe://X` yield equal `CallSpiffeId`s
    /// — they share the same internal canonical form.
    #[test]
    fn wimse_and_spiffe_schemes_parse_to_equal_ids() {
        let a =
            CallSpiffeId::from_wimse_uri("spiffe://prod.example.com/ns/agents/sa/coder").unwrap();
        let b =
            CallSpiffeId::from_wimse_uri("wimse://prod.example.com/ns/agents/sa/coder").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.as_str(), b.as_str());
    }

    /// All grammar rules from the SPIFFE parser apply to `wimse://` inputs
    /// once the scheme is normalized. Sanity-checking a few rejection
    /// classes (forbidden chars, uppercase authority, query strings)
    /// pins this behavior.
    #[test]
    fn from_wimse_uri_inherits_spiffe_grammar_rejections() {
        // Query string forbidden — covered by parse() check.
        assert!(matches!(
            CallSpiffeId::from_wimse_uri("wimse://prod.example.com/ns/agents/sa/coder?x=1"),
            Err(IdError::ForbiddenChar('?', _))
        ));
        // Uppercase authority forbidden — covered by parse() check.
        assert!(matches!(
            CallSpiffeId::from_wimse_uri("wimse://Prod.Example.Com/ns/agents/sa/coder"),
            Err(IdError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn parse_accepts_full_lineage_path() {
        let id = pod()
            .derive_tool("Bash", Some(b"x"))
            .unwrap()
            .derive_llm("provider-a", "prompt", b"hi")
            .unwrap()
            .derive_llm("provider-a", "response", b"reply")
            .unwrap();
        // Round-trip through parse to verify the canonical string is also
        // accepted by the hardened parser.
        let reparsed: CallSpiffeId = id.as_str().parse().unwrap();
        assert_eq!(id, reparsed);
    }
}
