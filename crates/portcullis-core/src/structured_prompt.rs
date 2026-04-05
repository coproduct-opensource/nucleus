//! StructuredPrompt — control/data separation seam for CaMeL-style reasoning.
//!
//! The CaMeL research direction observes that prompt injection is fundamentally
//! a confusion between **control** (what the operator asked for) and **data**
//! (what was retrieved from untrusted sources). A structured prompt makes that
//! seam explicit:
//!
//! - `control_text`: operator-authored plan or task skeleton — trusted.
//! - `payloads`: attached retrieval blobs — potentially untrusted.
//!
//! This module does not implement a planner or an inference engine. It provides
//! the minimal type-level seam that lets upstream tooling label data at its
//! origin and downstream checks treat the labels as enforcement signals.
//!
//! ## Example
//!
//! ```rust
//! use portcullis_core::structured_prompt::{PayloadRef, PayloadSource, StructuredPrompt};
//!
//! let prompt = StructuredPrompt::new("summarize the release notes")
//!     .with_payload(PayloadRef::web_fetch(
//!         "https://example.com/release-notes",
//!         b"v1.2: added feature X, fixed bug Y",
//!     ));
//!
//! assert_eq!(prompt.payload_count(), 1);
//! assert!(!prompt.all_payloads_trusted());
//! assert!(prompt.audit_summary().contains("web_fetch"));
//! ```

use crate::{AuthorityLevel, ConfLevel, DerivationClass, IntegLevel};

// ═══════════════════════════════════════════════════════════════════════════
// PayloadSource
// ═══════════════════════════════════════════════════════════════════════════

/// The retrieval method that produced a payload.
///
/// Used for audit markers that distinguish trusted control from untrusted
/// retrieval content. The source is the coarsest provenance label — finer-
/// grained labels live in the IFC fields of [`PayloadRef`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadSource {
    /// Content fetched from a URL via `web_fetch`.
    WebFetch {
        /// The URL that was fetched.
        url: String,
    },
    /// Content returned by a `web_search` query.
    WebSearch {
        /// The query string used.
        query: String,
    },
    /// Content read from a local file path.
    FileRead {
        /// The file path.
        path: String,
    },
    /// Structured output from an MCP tool call.
    McpTool {
        /// The tool name.
        tool: String,
        /// The input arguments (stringified for audit).
        args_summary: String,
    },
    /// Explicitly trusted content (operator-authored or system config).
    Trusted {
        /// A short label identifying the trusted source.
        label: String,
    },
}

impl PayloadSource {
    /// The default IFC integrity level for this source.
    ///
    /// Web content is adversarial; MCP tool output is untrusted; operator
    /// content is trusted.
    pub fn default_integrity(&self) -> IntegLevel {
        match self {
            PayloadSource::WebFetch { .. } | PayloadSource::WebSearch { .. } => {
                IntegLevel::Adversarial
            }
            PayloadSource::McpTool { .. } => IntegLevel::Untrusted,
            PayloadSource::FileRead { .. } => IntegLevel::Untrusted,
            PayloadSource::Trusted { .. } => IntegLevel::Trusted,
        }
    }

    /// The default authority level for this source.
    ///
    /// Web content has no authority to steer the agent; trusted operator
    /// content has full directive authority.
    pub fn default_authority(&self) -> AuthorityLevel {
        match self {
            PayloadSource::WebFetch { .. } | PayloadSource::WebSearch { .. } => {
                AuthorityLevel::NoAuthority
            }
            PayloadSource::McpTool { .. } => AuthorityLevel::Informational,
            PayloadSource::FileRead { .. } => AuthorityLevel::Informational,
            PayloadSource::Trusted { .. } => AuthorityLevel::Directive,
        }
    }

    /// The default derivation class for this source.
    pub fn default_derivation(&self) -> DerivationClass {
        match self {
            PayloadSource::WebFetch { .. }
            | PayloadSource::WebSearch { .. }
            | PayloadSource::FileRead { .. }
            | PayloadSource::McpTool { .. } => DerivationClass::OpaqueExternal,
            PayloadSource::Trusted { .. } => DerivationClass::Deterministic,
        }
    }

    /// A short string identifier for use in audit output.
    pub fn audit_tag(&self) -> String {
        match self {
            PayloadSource::WebFetch { url } => format!("web_fetch:{}", truncate(url, 40)),
            PayloadSource::WebSearch { query } => format!("web_search:{}", truncate(query, 40)),
            PayloadSource::FileRead { path } => format!("file_read:{}", truncate(path, 40)),
            PayloadSource::McpTool { tool, .. } => format!("mcp_tool:{tool}"),
            PayloadSource::Trusted { label } => format!("trusted:{label}"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PayloadRef
// ═══════════════════════════════════════════════════════════════════════════

/// A reference to an untrusted (or partially trusted) content blob.
///
/// Carries the content bytes, its retrieval source, and IFC labels that
/// downstream policy checks can use to gate how the content is handled.
#[derive(Debug, Clone)]
pub struct PayloadRef {
    /// The raw content bytes from retrieval.
    pub content: Vec<u8>,
    /// Where the content came from.
    pub source: PayloadSource,
    /// Confidentiality label: how sensitive is this payload's content?
    pub conf_level: ConfLevel,
    /// Integrity label: how trustworthy is this payload's origin?
    pub integ_level: IntegLevel,
    /// Authority label: can this payload steer the agent?
    pub authority_level: AuthorityLevel,
    /// Derivation class: is this content AI-generated, deterministic, etc.?
    pub derivation: DerivationClass,
}

impl PayloadRef {
    /// Construct a payload from a `web_fetch` result.
    ///
    /// Defaults: `Public` confidentiality, `Adversarial` integrity,
    /// `NoAuthority`, `OpaqueExternal` derivation.
    pub fn web_fetch(url: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        let source = PayloadSource::WebFetch { url: url.into() };
        Self {
            content: content.into(),
            conf_level: ConfLevel::Public,
            integ_level: source.default_integrity(),
            authority_level: source.default_authority(),
            derivation: source.default_derivation(),
            source,
        }
    }

    /// Construct a payload from a `web_search` result.
    pub fn web_search(query: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        let source = PayloadSource::WebSearch {
            query: query.into(),
        };
        Self {
            content: content.into(),
            conf_level: ConfLevel::Public,
            integ_level: source.default_integrity(),
            authority_level: source.default_authority(),
            derivation: source.default_derivation(),
            source,
        }
    }

    /// Construct a payload from a local file read.
    pub fn file_read(path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        let source = PayloadSource::FileRead { path: path.into() };
        Self {
            content: content.into(),
            conf_level: ConfLevel::Internal,
            integ_level: source.default_integrity(),
            authority_level: source.default_authority(),
            derivation: source.default_derivation(),
            source,
        }
    }

    /// Construct a payload from an MCP tool result.
    pub fn mcp_tool(
        tool: impl Into<String>,
        args_summary: impl Into<String>,
        content: impl Into<Vec<u8>>,
    ) -> Self {
        let source = PayloadSource::McpTool {
            tool: tool.into(),
            args_summary: args_summary.into(),
        };
        Self {
            content: content.into(),
            conf_level: ConfLevel::Public,
            integ_level: source.default_integrity(),
            authority_level: source.default_authority(),
            derivation: source.default_derivation(),
            source,
        }
    }

    /// Override the confidentiality level.
    pub fn with_conf_level(mut self, level: ConfLevel) -> Self {
        self.conf_level = level;
        self
    }

    /// Override the integrity level.
    pub fn with_integ_level(mut self, level: IntegLevel) -> Self {
        self.integ_level = level;
        self
    }

    /// Whether this payload is safe to use in a directive context.
    ///
    /// A payload is "safe for control" only when its integrity is at least
    /// `Trusted` and its authority is at least `Directive`. Any web content
    /// or MCP output fails this check.
    pub fn is_safe_for_control(&self) -> bool {
        self.integ_level >= IntegLevel::Trusted && self.authority_level >= AuthorityLevel::Directive
    }

    /// Whether this payload may contain adversarially crafted content.
    pub fn is_adversarial(&self) -> bool {
        self.integ_level == IntegLevel::Adversarial
    }

    /// Size in bytes of the payload content.
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Whether the payload content is empty.
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// StructuredPrompt
// ═══════════════════════════════════════════════════════════════════════════

/// A structured prompt separating trusted control from untrusted payloads.
///
/// Exposes the minimal seam for control/data separation without requiring
/// a full planner or inference rewrite.
///
/// `control_text` is the operator-authored task skeleton — trusted, directive.
/// `payloads` are retrieved blobs — potentially adversarial, no authority.
///
/// See module documentation for usage.
#[derive(Debug, Clone)]
pub struct StructuredPrompt {
    /// Trusted operator-authored plan or task skeleton.
    ///
    /// This text may steer the agent. It comes from the operator/system,
    /// not from retrieval. Policy checks should treat it with `Directive`
    /// authority.
    pub control_text: String,
    /// Untrusted attachments or retrieved content blobs.
    ///
    /// Policy checks should gate whether individual payloads may influence
    /// control flow (they should not, by default).
    pub payloads: Vec<PayloadRef>,
}

impl StructuredPrompt {
    /// Create a new structured prompt from a trusted control text.
    ///
    /// Start with an empty payload list; attach payloads via [`with_payload`].
    pub fn new(control_text: impl Into<String>) -> Self {
        Self {
            control_text: control_text.into(),
            payloads: vec![],
        }
    }

    /// Attach a payload (builder pattern).
    pub fn with_payload(mut self, payload: PayloadRef) -> Self {
        self.payloads.push(payload);
        self
    }

    /// Number of attached payloads.
    pub fn payload_count(&self) -> usize {
        self.payloads.len()
    }

    /// Whether all payloads pass [`PayloadRef::is_safe_for_control`].
    ///
    /// Returns `true` if there are no payloads (vacuously safe).
    pub fn all_payloads_trusted(&self) -> bool {
        self.payloads.iter().all(|p| p.is_safe_for_control())
    }

    /// Whether any payload is adversarial.
    pub fn has_adversarial_payload(&self) -> bool {
        self.payloads.iter().any(|p| p.is_adversarial())
    }

    /// Total bytes across all payloads.
    pub fn total_payload_bytes(&self) -> usize {
        self.payloads.iter().map(|p| p.len()).sum()
    }

    /// The "worst" (least trusted) integrity level across all payloads.
    ///
    /// Returns `Trusted` if there are no payloads.
    pub fn min_payload_integrity(&self) -> IntegLevel {
        self.payloads
            .iter()
            .map(|p| p.integ_level)
            .min()
            .unwrap_or(IntegLevel::Trusted)
    }

    /// The "worst" (least trusted) authority level across all payloads.
    ///
    /// Returns `Directive` if there are no payloads.
    pub fn min_payload_authority(&self) -> AuthorityLevel {
        self.payloads
            .iter()
            .map(|p| p.authority_level)
            .min()
            .unwrap_or(AuthorityLevel::Directive)
    }

    /// Build an audit summary distinguishing trusted control from untrusted payloads.
    ///
    /// Returns a multi-line string suitable for appending to an audit log entry.
    pub fn audit_summary(&self) -> String {
        let mut out = format!(
            "StructuredPrompt: control_len={} payload_count={}",
            self.control_text.len(),
            self.payloads.len(),
        );
        for (i, p) in self.payloads.iter().enumerate() {
            out.push_str(&format!(
                "\n  payload[{i}] source={} integ={:?} auth={:?} deriv={:?} bytes={}",
                p.source.audit_tag(),
                p.integ_level,
                p.authority_level,
                p.derivation,
                p.len(),
            ));
        }
        if self.has_adversarial_payload() {
            out.push_str("\n  WARN: adversarial payload(s) present");
        }
        out
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        // Use char boundary-safe slicing to avoid panics on multi-byte UTF-8.
        s.char_indices().nth(max).map_or(s, |(i, _)| &s[..i])
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_fetch_defaults_to_adversarial() {
        let p = PayloadRef::web_fetch("https://example.com", b"content".to_vec());
        assert_eq!(p.integ_level, IntegLevel::Adversarial);
        assert_eq!(p.authority_level, AuthorityLevel::NoAuthority);
        assert!(p.is_adversarial());
        assert!(!p.is_safe_for_control());
    }

    #[test]
    fn web_search_defaults_to_adversarial() {
        let p = PayloadRef::web_search("rust tutorial", b"content".to_vec());
        assert_eq!(p.integ_level, IntegLevel::Adversarial);
        assert!(!p.is_safe_for_control());
    }

    #[test]
    fn mcp_tool_defaults_to_untrusted() {
        let p = PayloadRef::mcp_tool("fetch_pr", "pr_number=42", b"content".to_vec());
        assert_eq!(p.integ_level, IntegLevel::Untrusted);
        assert_eq!(p.authority_level, AuthorityLevel::Informational);
        assert!(!p.is_adversarial());
        assert!(!p.is_safe_for_control());
    }

    #[test]
    fn trusted_source_is_safe_for_control() {
        let source = PayloadSource::Trusted {
            label: "system_config".into(),
        };
        let p = PayloadRef {
            content: b"config data".to_vec(),
            conf_level: ConfLevel::Internal,
            integ_level: source.default_integrity(),
            authority_level: source.default_authority(),
            derivation: source.default_derivation(),
            source,
        };
        assert!(p.is_safe_for_control());
        assert!(!p.is_adversarial());
    }

    #[test]
    fn empty_prompt_is_vacuously_safe() {
        let prompt = StructuredPrompt::new("summarize the docs");
        assert!(prompt.all_payloads_trusted());
        assert!(!prompt.has_adversarial_payload());
        assert_eq!(prompt.total_payload_bytes(), 0);
        assert_eq!(prompt.min_payload_integrity(), IntegLevel::Trusted);
    }

    #[test]
    fn prompt_with_web_fetch_is_not_fully_trusted() {
        let prompt = StructuredPrompt::new("summarize the docs").with_payload(
            PayloadRef::web_fetch("https://example.com", b"docs".to_vec()),
        );
        assert!(!prompt.all_payloads_trusted());
        assert!(prompt.has_adversarial_payload());
        assert_eq!(prompt.min_payload_integrity(), IntegLevel::Adversarial);
    }

    #[test]
    fn prompt_payload_count() {
        let prompt = StructuredPrompt::new("research task")
            .with_payload(PayloadRef::web_fetch("https://a.com", b"a".to_vec()))
            .with_payload(PayloadRef::web_search("query", b"b".to_vec()));
        assert_eq!(prompt.payload_count(), 2);
        assert_eq!(prompt.total_payload_bytes(), 2);
    }

    #[test]
    fn audit_summary_contains_source_tags() {
        let prompt = StructuredPrompt::new("task")
            .with_payload(PayloadRef::web_fetch(
                "https://example.com/data",
                b"x".to_vec(),
            ))
            .with_payload(PayloadRef::mcp_tool("get_pr", "pr=1", b"y".to_vec()));
        let summary = prompt.audit_summary();
        assert!(summary.contains("web_fetch:"));
        assert!(summary.contains("mcp_tool:"));
        assert!(summary.contains("WARN: adversarial"));
    }

    #[test]
    fn audit_summary_no_warn_for_clean_payload() {
        let prompt = StructuredPrompt::new("task").with_payload(PayloadRef::mcp_tool(
            "fetch_pr",
            "pr=1",
            b"data".to_vec(),
        ));
        let summary = prompt.audit_summary();
        assert!(!summary.contains("WARN"));
    }

    #[test]
    fn payload_ref_with_overrides() {
        let p = PayloadRef::web_fetch("https://example.com", b"data".to_vec())
            .with_conf_level(ConfLevel::Secret)
            .with_integ_level(IntegLevel::Untrusted);
        assert_eq!(p.conf_level, ConfLevel::Secret);
        assert_eq!(p.integ_level, IntegLevel::Untrusted);
    }

    #[test]
    fn min_integrity_picks_worst() {
        let prompt = StructuredPrompt::new("task")
            .with_payload(PayloadRef::mcp_tool("t", "", b"a".to_vec())) // Untrusted
            .with_payload(PayloadRef::web_fetch("https://x.com", b"b".to_vec())); // Adversarial
        assert_eq!(prompt.min_payload_integrity(), IntegLevel::Adversarial);
    }

    // ── truncate UTF-8 safety (#1184) ────────────────────────────────────

    #[test]
    fn truncate_ascii_exact_limit() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_ascii_under_limit() {
        assert_eq!(truncate("hi", 10), "hi");
    }

    #[test]
    fn truncate_ascii_over_limit() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    #[test]
    fn truncate_multibyte_does_not_panic() {
        // Each '日' is 3 bytes; slicing at byte index 1 or 2 would panic.
        let s = "日本語テスト";
        let result = truncate(s, 2); // 2 chars = first 2 characters
        assert_eq!(result, "日本");
    }

    #[test]
    fn truncate_multibyte_at_char_boundary() {
        let s = "αβγδε"; // each char is 2 bytes
        assert_eq!(truncate(s, 3), "αβγ");
    }
}
