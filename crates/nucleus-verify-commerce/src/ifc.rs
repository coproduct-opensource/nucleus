//! The IFC gate: a model-level information-flow decision over the inputs a
//! paid call *declares* it will be exposed to.
//!
//! This composes [`nucleus_ifc`]'s Denning-lattice [`FlowTracker`] (the same
//! engine the rest of nucleus uses for the lethal trifecta) and turns a
//! [`FlowDeclaration`] into an [`IfcVerdict`]. The gate models the paid action
//! as an `OutboundAction` sink whose causal parents are the declared inputs,
//! then asks the tracker whether serving it would exfiltrate: untrusted content
//! reaching the action (integrity) **or** confidential data flowing to the
//! (public) sink (confidentiality).
//!
//! # Honesty boundary
//!
//! This is a **model-level** decision over **declared** inputs. It is not an
//! end-to-end proof that exfiltration cannot happen. The limiting factor is
//! **coverage**: the gate is exactly as good as the [`FlowDeclaration`] the
//! caller hands it — an input the caller never declares is an input the lattice
//! never sees. [`IfcVerdict`] therefore carries the declared input set verbatim
//! so a downstream verifier can judge coverage instead of trusting a bare
//! "allow". The decision is also **per-call**: each [`decide`] builds a fresh
//! tracker; the cross-call monotonic session-taint ratchet is not wired here.
//!
//! The gate **fails closed**: any internal flow-tracking error yields a *deny*.

use nucleus_ifc::{FlowTracker, NodeKind};
use portcullis_core::ConfLevel;
use serde::{Deserialize, Serialize};

/// One declared data-flow input a paid call will be exposed to. The caller
/// (gateway / planner) is responsible for declaring every input; the gate maps
/// each to its IFC lattice node kind.
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
    fn token(self) -> &'static str {
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
}

/// The declared data-flow surface of a paid call. The paid action is modelled
/// as an `OutboundAction` sink whose causal parents are the declared inputs, so
/// the gate sees the full lethal trifecta.
///
/// `sink_public` sets the sink's maximum confidentiality:
/// - `false` (default) — the response is delivered to the **authenticated
///   buyer** (a counterparty, `ConfLevel::Internal`). Internal data may be
///   served to the paying customer, but `Secret` data (credentials/PII) is
///   denied, and anything with adversarial integrity is denied. This is the
///   normal paid-API case.
/// - `true` — the response is **publicly** visible (`ConfLevel::Public`); then
///   any Internal-or-higher data reaching it is denied too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDeclaration {
    /// Every input the handler will be exposed to.
    pub inputs: Vec<DeclaredInput>,
    /// Whether the paid action requires `Directive` authority (most do not).
    #[serde(default)]
    pub requires_authority: bool,
    /// Whether the paid response is publicly visible (vs. delivered to the
    /// authenticated buyer). See the type docs.
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

    /// Mark the paid response as publicly visible (tightens the confidentiality
    /// sink from `Internal` to `Public`).
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
        // The paid action is an outbound sink that may communicate externally.
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
/// into the signed receipt and independently re-derived by a verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcVerdict {
    /// Whether the paid action is permitted by the model-level IFC decision.
    pub allow: bool,
    /// Human/audit reason (the `SafetyCheck` debug form on deny, `"safe"` on allow).
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

    /// `true` if the gate permits the paid action.
    pub fn is_allow(&self) -> bool {
        self.allow
    }

    /// Deterministic canonical string of the verdict, for the signed binding.
    /// NUL-separated; the components contain no NUL.
    pub fn canonical(&self) -> String {
        // reason is excluded from the canonical binding on purpose: the
        // security-relevant facts are the decision + the declared set; the
        // reason is descriptive. Including it would make the binding brittle to
        // wording. allow + sorted declared set fully determine the decision.
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
        // Trusted prompt + local DB row, no untrusted content, no secrets.
        let v =
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]).decide();
        assert!(v.is_allow(), "clean flow must be allowed: {v:?}");
    }

    #[test]
    fn untrusted_content_to_paid_action_is_denied() {
        // Web content (adversarial integrity) reaching the outbound paid action.
        let v =
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]).decide();
        assert!(!v.is_allow(), "adversarial ancestry must be denied: {v:?}");
    }

    #[test]
    fn secret_to_counterparty_is_denied() {
        // Secret (credentials/PII) must not flow even to the authenticated buyer.
        let v = FlowDeclaration::new([DeclaredInput::Secret]).decide();
        assert!(!v.is_allow(), "secret→counterparty must be denied: {v:?}");
    }

    #[test]
    fn internal_data_to_counterparty_is_allowed_but_to_public_is_denied() {
        // A DB row (Internal) to the paying buyer is fine…
        let to_buyer = FlowDeclaration::new([DeclaredInput::DatabaseRow]).decide();
        assert!(
            to_buyer.is_allow(),
            "internal→counterparty ok: {to_buyer:?}"
        );
        // …but not to a publicly-visible response.
        let to_public = FlowDeclaration::new([DeclaredInput::DatabaseRow])
            .public_sink()
            .decide();
        assert!(
            !to_public.is_allow(),
            "internal→public denied: {to_public:?}"
        );
    }

    #[test]
    fn declared_inputs_are_sorted_and_deduped_in_verdict() {
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
}
