//! The model-level IFC **decision** over the inputs a call *declares* it will be
//! exposed to — the lethal-trifecta gate as a pure, deterministic function.
//!
//! This composes [`crate::FlowTracker`] (the same engine the rest of nucleus
//! uses) and turns a [`FlowDeclaration`] into an [`IfcVerdict`]. It is **homed
//! here** (rather than in `nucleus-verify-commerce`) precisely so it is
//! **wasm-safe and the single source of truth**: the `@nucleus/verify` recompute
//! SDK re-derives the verdict with the EXACT same code the production gate runs —
//! a recompute that can never drift from enforcement.
//!
//! # Honesty boundary
//!
//! A **model-level** decision over **declared** inputs — not an end-to-end proof
//! that exfiltration cannot happen. Coverage is the limit: an input the caller
//! never declares is one the lattice never sees, so [`IfcVerdict`] carries the
//! declared set verbatim for a verifier to judge coverage. Per-call (no
//! cross-session taint ratchet). Fails closed.

use crate::{FlowTracker, NodeKind};
use portcullis_core::ConfLevel;
use serde::{Deserialize, Serialize};

/// One declared data-flow input a call will be exposed to. The caller declares
/// every input; the gate maps each to its IFC lattice node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeclaredInput {
    /// Trusted, directive user prompt.
    UserPrompt,
    /// Adversarial public web content (indirect prompt-injection vector).
    WebContent,
    /// Untrusted MCP / tool response.
    ToolResponse,
    /// Private file contents.
    FileRead,
    /// An environment variable (potentially secret).
    EnvVar,
    /// A credential / API key.
    Secret,
    /// A row from a local database (internal, trusted).
    DatabaseRow,
    /// A memory entry recalled into context.
    MemoryRead,
    /// A structured HTTP/API response from an external service.
    HttpResponse,
}

impl DeclaredInput {
    fn node_kind(self) -> NodeKind {
        match self {
            DeclaredInput::UserPrompt => NodeKind::UserPrompt,
            DeclaredInput::WebContent => NodeKind::WebContent,
            DeclaredInput::ToolResponse => NodeKind::ToolResponse,
            DeclaredInput::FileRead => NodeKind::FileRead,
            DeclaredInput::EnvVar => NodeKind::EnvVar,
            DeclaredInput::Secret => NodeKind::Secret,
            DeclaredInput::DatabaseRow => NodeKind::DatabaseRow,
            DeclaredInput::MemoryRead => NodeKind::MemoryRead,
            DeclaredInput::HttpResponse => NodeKind::HTTPResponse,
        }
    }

    /// Stable wire token (matches the serde `snake_case` rename).
    pub fn token(self) -> &'static str {
        match self {
            DeclaredInput::UserPrompt => "user_prompt",
            DeclaredInput::WebContent => "web_content",
            DeclaredInput::ToolResponse => "tool_response",
            DeclaredInput::FileRead => "file_read",
            DeclaredInput::EnvVar => "env_var",
            DeclaredInput::Secret => "secret",
            DeclaredInput::DatabaseRow => "database_row",
            DeclaredInput::MemoryRead => "memory_read",
            DeclaredInput::HttpResponse => "http_response",
        }
    }

    /// Parse a wire token back to a [`DeclaredInput`] (inverse of [`Self::token`]).
    /// Used by the recompute path to rebuild a declaration from a receipt's
    /// `declared_inputs`.
    pub fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "user_prompt" => DeclaredInput::UserPrompt,
            "web_content" => DeclaredInput::WebContent,
            "tool_response" => DeclaredInput::ToolResponse,
            "file_read" => DeclaredInput::FileRead,
            "env_var" => DeclaredInput::EnvVar,
            "secret" => DeclaredInput::Secret,
            "database_row" => DeclaredInput::DatabaseRow,
            "memory_read" => DeclaredInput::MemoryRead,
            "http_response" => DeclaredInput::HttpResponse,
            _ => return None,
        })
    }
}

/// The declared data-flow surface of a call. The action is modelled as an
/// `OutboundAction` sink whose causal parents are the declared inputs, so the
/// gate sees the full lethal trifecta.
///
/// `sink_public` sets the sink's maximum confidentiality: `false` (default) =
/// delivered to an authenticated counterparty (`ConfLevel::Internal`); `true` =
/// publicly visible (`ConfLevel::Public`, tighter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDeclaration {
    /// Every input the handler will be exposed to.
    pub inputs: Vec<DeclaredInput>,
    /// Whether the action requires `Directive` authority (most do not).
    #[serde(default)]
    pub requires_authority: bool,
    /// Whether the response is publicly visible (vs. delivered to the
    /// authenticated counterparty). See the type docs.
    #[serde(default)]
    pub sink_public: bool,
}

impl FlowDeclaration {
    /// A declaration with the given inputs, no authority requirement, and a
    /// counterparty (non-public) sink.
    pub fn new(inputs: impl IntoIterator<Item = DeclaredInput>) -> Self {
        Self {
            inputs: inputs.into_iter().collect(),
            requires_authority: false,
            sink_public: false,
        }
    }

    /// Rebuild a declaration from wire tokens (e.g. a receipt's `declared_inputs`)
    /// plus the sink visibility. Unknown tokens are rejected (returns `None`) so
    /// the recompute fails closed on an unrecognised input rather than silently
    /// dropping it.
    pub fn from_tokens<'a>(
        tokens: impl IntoIterator<Item = &'a str>,
        requires_authority: bool,
        sink_public: bool,
    ) -> Option<Self> {
        let inputs = tokens
            .into_iter()
            .map(DeclaredInput::from_token)
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            inputs,
            requires_authority,
            sink_public,
        })
    }

    /// Mark the response as publicly visible (tightens confidentiality from
    /// `Internal` to `Public`).
    pub fn public_sink(mut self) -> Self {
        self.sink_public = true;
        self
    }

    /// Run the model-level IFC decision for this declaration. Fails closed.
    pub fn decide(&self) -> IfcVerdict {
        // Sorted, de-duplicated declared set for a deterministic, auditable
        // verdict (independent of declaration order).
        let mut declared: Vec<DeclaredInput> = self.inputs.clone();
        declared.sort();
        declared.dedup();
        let declared_tokens: Vec<String> = declared.iter().map(|i| i.token().to_string()).collect();

        let mut tracker = FlowTracker::new();
        let mut parents = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            match tracker.observe(input.node_kind()) {
                Ok(id) => parents.push(id),
                Err(e) => {
                    return IfcVerdict::deny(
                        format!("flow tracking error observing input: {e}"),
                        declared_tokens,
                    );
                }
            }
        }
        // The action is an outbound sink that may communicate externally.
        let sink = match tracker.observe_with_parents(NodeKind::OutboundAction, &parents) {
            Ok(id) => id,
            Err(e) => {
                return IfcVerdict::deny(
                    format!("flow tracking error observing sink: {e}"),
                    declared_tokens,
                );
            }
        };
        let sink_max_conf = if self.sink_public {
            ConfLevel::Public
        } else {
            ConfLevel::Internal
        };
        let check = tracker.check_exfiltration_safety(sink, self.requires_authority, sink_max_conf);
        if check.is_safe() {
            IfcVerdict::allow(declared_tokens)
        } else {
            IfcVerdict::deny(format!("{check:?}"), declared_tokens)
        }
    }
}

/// The result of the IFC gate. Serializable + deterministic so it can be folded
/// into a signed receipt and independently re-derived by a verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcVerdict {
    /// Whether the action is permitted by the model-level IFC decision.
    pub allow: bool,
    /// Human/audit reason (`SafetyCheck` debug form on deny, `"safe"` on allow).
    pub reason: String,
    /// The declared inputs the decision was made over, sorted + deduped. Carried
    /// verbatim so a verifier can judge **coverage**, not just the verdict.
    pub declared_inputs: Vec<String>,
}

impl IfcVerdict {
    fn allow(declared_inputs: Vec<String>) -> Self {
        Self {
            allow: true,
            reason: "safe".to_string(),
            declared_inputs,
        }
    }

    fn deny(reason: String, declared_inputs: Vec<String>) -> Self {
        Self {
            allow: false,
            reason,
            declared_inputs,
        }
    }

    /// `true` if the gate permits the action.
    pub fn is_allow(&self) -> bool {
        self.allow
    }

    /// Deterministic canonical string of the verdict, for the signed binding.
    /// NUL-separated; `allow` + the sorted declared set fully determine it (the
    /// `reason` is descriptive and intentionally excluded).
    pub fn canonical(&self) -> String {
        let mut s = String::new();
        s.push_str(if self.allow { "allow" } else { "deny" });
        s.push('\0');
        s.push_str(&self.declared_inputs.join(","));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_declaration_allows() {
        let v =
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]).decide();
        assert!(v.is_allow(), "clean flow must be allowed: {v:?}");
    }

    #[test]
    fn untrusted_content_to_action_is_denied() {
        let v =
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]).decide();
        assert!(!v.is_allow(), "adversarial ancestry must be denied: {v:?}");
    }

    #[test]
    fn secret_to_counterparty_is_denied() {
        let v = FlowDeclaration::new([DeclaredInput::Secret]).decide();
        assert!(!v.is_allow(), "secret→counterparty must be denied: {v:?}");
    }

    #[test]
    fn internal_to_counterparty_ok_but_public_denied() {
        let to_buyer = FlowDeclaration::new([DeclaredInput::DatabaseRow]).decide();
        assert!(to_buyer.is_allow());
        let to_public = FlowDeclaration::new([DeclaredInput::DatabaseRow])
            .public_sink()
            .decide();
        assert!(!to_public.is_allow());
    }

    #[test]
    fn declared_inputs_sorted_and_deduped() {
        let v = FlowDeclaration::new([
            DeclaredInput::WebContent,
            DeclaredInput::UserPrompt,
            DeclaredInput::WebContent,
        ])
        .decide();
        assert_eq!(v.declared_inputs, ["user_prompt", "web_content"]);
    }

    #[test]
    fn canonical_is_order_independent() {
        let a = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow])
            .decide()
            .canonical();
        let b = FlowDeclaration::new([DeclaredInput::DatabaseRow, DeclaredInput::UserPrompt])
            .decide()
            .canonical();
        assert_eq!(a, b);
    }

    #[test]
    fn token_round_trips() {
        for t in [
            "user_prompt",
            "web_content",
            "secret",
            "database_row",
            "http_response",
        ] {
            assert_eq!(DeclaredInput::from_token(t).unwrap().token(), t);
        }
        assert_eq!(DeclaredInput::from_token("nope"), None);
    }

    #[test]
    fn from_tokens_recomputes_same_verdict() {
        // The recompute path: rebuild from tokens → decide → same canonical.
        let orig = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]);
        let v1 = orig.decide();
        let rebuilt =
            FlowDeclaration::from_tokens(["user_prompt", "web_content"], false, false).unwrap();
        let v2 = rebuilt.decide();
        assert_eq!(v1.canonical(), v2.canonical());
        assert!(!v2.is_allow());
        // Unknown token fails closed.
        assert!(FlowDeclaration::from_tokens(["bogus"], false, false).is_none());
    }
}
