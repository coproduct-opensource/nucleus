//! The session report — the artifact a developer sees.
//!
//! [`SessionReport::render`] produces the visceral, copy-pasteable headline
//! ("your agent CAN exfiltrate") plus the exact tool chain that proves it;
//! [`SessionReport::to_json`] gives the machine-readable form for CI / receipts.

use crate::session::{Finding, SessionMonitor, ToolEvent};
use serde::{Deserialize, Serialize};

/// A finished session's findings, serializable for CI artifacts and (later) for
/// folding into a signed, recomputable audit receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    /// `true` iff at least one egress sink was reached while holding the trifecta.
    pub exfiltration_possible: bool,
    /// Data classes (IFC tokens) the agent was exposed to, in order seen.
    pub inputs_seen: Vec<String>,
    /// Every observed tool event.
    pub events: Vec<ToolEvent>,
    /// The flagged egress points.
    pub findings: Vec<Finding>,
}

impl SessionReport {
    /// Build a report from a finished [`SessionMonitor`].
    pub fn from_monitor(m: &SessionMonitor) -> Self {
        Self {
            exfiltration_possible: m.exfiltration_possible(),
            inputs_seen: m
                .seen_inputs()
                .iter()
                .map(|i| i.token().to_string())
                .collect(),
            events: m.events().to_vec(),
            findings: m.findings().to_vec(),
        }
    }

    /// Machine-readable JSON (pretty).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// The human-facing artifact.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("== Trifecta Gate — MCP session report ==\n\n");
        s.push_str(&format!("Tools observed:        {}\n", self.events.len()));
        let seen = if self.inputs_seen.is_empty() {
            "(none)".to_string()
        } else {
            self.inputs_seen.join(", ")
        };
        s.push_str(&format!("Data classes in scope: {seen}\n"));
        s.push_str(&format!(
            "Egress points flagged: {}\n\n",
            self.findings.len()
        ));

        if self.exfiltration_possible {
            s.push_str("  /!\\  EXFILTRATION POSSIBLE\n");
            s.push_str("       This agent reached an external sink while holding the lethal\n");
            s.push_str("       trifecta (private data + untrusted content + outbound channel).\n");
            s.push_str("       A prompt-injection in the untrusted content can now leak the\n");
            s.push_str("       private data out. Verdict from the nucleus-ifc gate:\n\n");
            for f in &self.findings {
                let dest = if f.public_sink {
                    "public"
                } else {
                    "counterparty"
                };
                s.push_str(&format!(
                    "    - via `{}` ({dest}) over [{}]\n      reason: {}\n",
                    f.sink_tool,
                    f.verdict.declared_inputs.join(" + "),
                    f.verdict.reason,
                ));
            }
        } else {
            s.push_str("  OK   No lethal-trifecta egress detected in this session.\n");
            s.push_str("       (Observe-only: this reflects the tools actually exercised.)\n");
        }
        s
    }
}

/// Replay a recorded session (an ordered list of tool names) offline and report.
/// This is the zero-dependency way to produce the artifact without a live server.
pub fn analyze_session(tools: &[String], classifier: crate::classify::Classifier) -> SessionReport {
    let mut m = SessionMonitor::new(classifier);
    for t in tools {
        m.observe_invocation(t);
    }
    SessionReport::from_monitor(&m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::Classifier;

    #[test]
    fn exfil_report_renders_the_headline_and_chain() {
        let tools: Vec<String> = ["read_secret", "fetch_url", "send_email"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rep = analyze_session(&tools, Classifier::default());
        assert!(rep.exfiltration_possible);
        let out = rep.render();
        assert!(out.contains("EXFILTRATION POSSIBLE"), "got:\n{out}");
        assert!(out.contains("send_email"));
        // round-trips as JSON
        let j = rep.to_json();
        let back: SessionReport = serde_json::from_str(&j).unwrap();
        assert!(back.exfiltration_possible);
    }

    #[test]
    fn benign_report_is_clean() {
        let tools: Vec<String> = ["web_search", "calculator"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rep = analyze_session(&tools, Classifier::default());
        assert!(!rep.exfiltration_possible);
        assert!(rep.render().contains("No lethal-trifecta egress"));
    }
}
