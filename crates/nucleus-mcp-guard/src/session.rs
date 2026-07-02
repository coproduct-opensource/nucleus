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

/// Accumulates session taint and emits findings. Cheap to construct; one per
/// agent session.
#[derive(Debug, Default)]
pub struct SessionMonitor {
    classifier: Classifier,
    seen: Vec<DeclaredInput>,
    events: Vec<ToolEvent>,
    findings: Vec<Finding>,
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
        if let ToolRole::Source { input } = self.classifier.classify(tool) {
            if !self.seen.contains(&input) {
                self.seen.push(input);
            }
        }
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

    /// `true` iff the agent reached at least one egress sink while holding the
    /// lethal trifecta.
    pub fn exfiltration_possible(&self) -> bool {
        !self.findings.is_empty()
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
