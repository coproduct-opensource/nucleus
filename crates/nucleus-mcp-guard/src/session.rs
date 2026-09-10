//! Per-session taint tracking + lethal-trifecta detection.
//!
//! As an agent session runs, each tool **result** that is a [`ToolRole::Source`]
//! adds its data class to the accumulated taint set; each tool **call** that is a
//! [`ToolRole::Sink`] is an egress point, checked against the taint via the proven
//! [`nucleus_ifc`] lethal-trifecta decision. A denied verdict is a [`Finding`]:
//! the agent, at that moment, *can* exfiltrate (private data + untrusted content +
//! an external sink all co-occur).

use crate::classify::{Classifier, ToolRole};
use nucleus_ifc::{DeclaredInput, FlowDeclaration, IfcVerdict};
use serde::{Deserialize, Serialize};

/// One observed tool interaction (for the session log / artifact).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEvent {
    /// The MCP tool name.
    pub tool: String,
    /// How it was classified.
    pub role: ToolRole,
}

/// A flagged exfiltration risk: an egress sink reached while the session context
/// already holds the lethal trifecta. The embedded [`IfcVerdict`] is the proven
/// gate's output — `allow == false`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The sink tool whose call triggered the check.
    pub sink_tool: String,
    /// Whether the sink destination is publicly visible.
    pub public_sink: bool,
    /// The model-level IFC verdict (carries `reason` + `declared_inputs`).
    pub verdict: IfcVerdict,
}

/// Why a tool's metadata was refused.
///
/// Each variant is a distinct integrity failure, kept apart because they carry
/// different weight to a reader: [`Self::SchemaMutated`] is the rug-pull the
/// pinning exists to catch, while [`Self::Unadvertised`] can simply mean a
/// client called ahead of its first listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// A pinned tool's descriptor changed after approval — the rug-pull.
    SchemaMutated,
    /// A tool appeared in `tools/list` that no pin vouches for.
    NewToolAfterPinning,
    /// No signed manifest vouches for the tool.
    Unapproved,
    /// The tool is outside the compartment the pod's grant allows.
    WrongCompartment,
    /// The server announced its list changed and nothing has been re-vetted.
    StaleCatalogue,
    /// A call named a tool no `tools/list` ever advertised.
    Unadvertised,
}

impl RefusalKind {
    /// The short label used in the rendered report.
    pub fn label(self) -> &'static str {
        match self {
            Self::SchemaMutated => "rug-pull",
            Self::NewToolAfterPinning => "new tool after pinning",
            Self::Unapproved => "unapproved",
            Self::WrongCompartment => "wrong compartment",
            Self::StaleCatalogue => "stale catalogue",
            Self::Unadvertised => "unadvertised",
        }
    }
}

/// One refused piece of tool metadata.
///
/// Recorded so the finding survives past stderr: without this it reached the
/// operator's terminal and nothing else — not the exit code, not `--json` — so
/// a CI job wrapping a server that rug-pulled its schema went green (#2735).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataRefusal {
    /// The tool the refusal is about.
    pub tool: String,
    /// Which integrity check failed.
    pub kind: RefusalKind,
    /// The operator-facing explanation, as printed to stderr.
    pub reason: String,
}

/// Accumulates session taint and emits findings. Cheap to construct; one per
/// agent session.
#[derive(Debug, Default)]
pub struct SessionMonitor {
    classifier: Classifier,
    seen: Vec<DeclaredInput>,
    events: Vec<ToolEvent>,
    findings: Vec<Finding>,
    refusals: Vec<MetadataRefusal>,
}

impl SessionMonitor {
    /// New monitor with the given tool classifier.
    pub fn new(classifier: Classifier) -> Self {
        Self {
            classifier,
            ..Default::default()
        }
    }

    /// Observe an outbound tool **call**. Returns a [`Finding`] iff the tool is an
    /// egress sink AND the proven trifecta gate denies the egress given the taint
    /// accumulated so far.
    pub fn observe_call(&mut self, tool: &str) -> Option<Finding> {
        let role = self.classifier.classify(tool);
        self.events.push(ToolEvent {
            tool: tool.to_string(),
            role,
        });
        if let ToolRole::Sink { public } = role {
            let decl = FlowDeclaration::new(self.seen.clone());
            let decl = if public { decl.public_sink() } else { decl };
            let verdict = decl.decide();
            if !verdict.allow {
                let finding = Finding {
                    sink_tool: tool.to_string(),
                    public_sink: public,
                    verdict,
                };
                self.findings.push(finding.clone());
                return Some(finding);
            }
        }
        None
    }

    /// Observe a tool **result**. A [`ToolRole::Source`] adds its data class to the
    /// session taint (deduped).
    pub fn observe_result(&mut self, tool: &str) {
        if let ToolRole::Source { input } = self.classifier.classify(tool)
            && !self.seen.contains(&input)
        {
            self.seen.push(input);
        }
    }

    /// Record **untrusted tool metadata** — a `tools/list` entry that is not
    /// pinned, or whose schema mutated after pinning.
    ///
    /// MCP carries instructions and data in one channel, so a tool description
    /// has as much influence over the agent as the system prompt does. An
    /// unvouched-for description is therefore adversarial *ingest*, exactly like
    /// fetched web content, and is recorded as [`DeclaredInput::WebContent`] —
    /// the model-level counterpart of the kernel's
    /// `NodeKind::McpToolDescription`.
    ///
    /// Only *unapproved* metadata taints. A description pinned on first sight is
    /// trusted-on-first-use; if every server's `tools/list` tainted, the very
    /// first list would lock the session and the guard would be unusable.
    pub fn observe_untrusted_metadata(&mut self, tool: &str) {
        self.events.push(ToolEvent {
            tool: format!("{tool} (metadata)"),
            role: ToolRole::Source {
                input: DeclaredInput::WebContent,
            },
        });
        if !self.seen.contains(&DeclaredInput::WebContent) {
            self.seen.push(DeclaredInput::WebContent);
        }
    }

    /// Record a refusal of a tool's metadata: taint it exactly as
    /// [`Self::observe_untrusted_metadata`] does, and *keep* the refusal so it
    /// can reach the report, the exit code and `--json`.
    ///
    /// Prefer this over the bare taint call at every site that prints a refusal
    /// to stderr. Tainting alone is not enough: taint only changes the verdict
    /// if the session later reaches an egress sink, so a session that refused a
    /// rug-pull and then simply stopped left no machine-readable trace at all.
    pub fn observe_metadata_refusal(
        &mut self,
        tool: &str,
        kind: RefusalKind,
        reason: impl Into<String>,
    ) {
        self.observe_untrusted_metadata(tool);
        self.refusals.push(MetadataRefusal {
            tool: tool.to_string(),
            kind,
            reason: reason.into(),
        });
    }

    /// Convenience for offline replay: a full call+result interaction in order.
    pub fn observe_invocation(&mut self, tool: &str) -> Option<Finding> {
        let f = self.observe_call(tool);
        self.observe_result(tool);
        f
    }

    /// Every observed tool event, in order.
    pub fn events(&self) -> &[ToolEvent] {
        &self.events
    }

    /// All findings (egress points where exfiltration is possible).
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The accumulated taint set (data classes the agent has been exposed to).
    pub fn seen_inputs(&self) -> &[DeclaredInput] {
        &self.seen
    }

    /// Every refused piece of tool metadata, in order.
    pub fn refusals(&self) -> &[MetadataRefusal] {
        &self.refusals
    }

    /// `true` iff the agent reached at least one egress sink while holding the
    /// lethal trifecta.
    pub fn exfiltration_possible(&self) -> bool {
        !self.findings.is_empty()
    }

    /// `true` iff the server's tool metadata failed an integrity check at least
    /// once. Independent of [`Self::exfiltration_possible`]: a session can refuse
    /// a rug-pull without ever reaching a sink, and that is still not "OK".
    pub fn metadata_refused(&self) -> bool {
        !self.refusals.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::Classifier;

    #[test]
    fn benign_session_is_clean() {
        // Reads only public web, sends nothing externally → no trifecta.
        let mut m = SessionMonitor::new(Classifier::default());
        assert!(m.observe_invocation("web_search").is_none());
        assert!(m.observe_invocation("calculator").is_none());
        assert!(!m.exfiltration_possible());
    }

    #[test]
    fn exfil_session_is_flagged() {
        // Read a secret + ingest untrusted web content, then send an email out.
        let mut m = SessionMonitor::new(Classifier::default());
        assert!(m.observe_invocation("read_secret").is_none()); // private data in
        assert!(m.observe_invocation("fetch_url").is_none()); // untrusted content in
        let finding = m.observe_invocation("send_email"); // egress!
        assert!(finding.is_some(), "trifecta egress must be flagged");
        let f = finding.unwrap();
        assert!(!f.verdict.allow);
        assert_eq!(f.sink_tool, "send_email");
        assert!(m.exfiltration_possible());
    }

    #[test]
    fn egress_before_exposure_is_safe() {
        // Sending out BEFORE any private/untrusted data is in context is fine.
        let mut m = SessionMonitor::new(Classifier::default());
        assert!(m.observe_invocation("send_email").is_none());
        assert!(!m.exfiltration_possible());
    }
}
