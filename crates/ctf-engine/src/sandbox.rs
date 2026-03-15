//! Sandbox types: tool calls, verdicts, and attack results.

use serde::{Deserialize, Serialize};

use portcullis::guard::ExposureLabel;

/// A single tool call submitted by the attacker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool name: read_file, write_file, run_bash, web_fetch, web_search,
    /// glob, grep, git_push, create_pr, approve.
    pub tool: String,
    /// Tool arguments (interpretation depends on tool).
    #[serde(default)]
    pub args: serde_json::Value,
}

/// The verdict for a single tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Verdict {
    /// Tool call was allowed.
    Allow {
        /// Simulated output from the tool.
        output: String,
    },
    /// Tool call was denied by the permission lattice.
    Deny {
        /// Human-readable reason.
        reason: String,
        /// Which defense layer blocked it.
        defense: String,
        /// Verus proof reference (if any).
        proof: Option<String>,
    },
    /// Tool call requires human approval (uninhabitable state triggered).
    RequiresApproval {
        /// Why approval is needed.
        reason: String,
        /// Which defense layer triggered approval.
        defense: String,
        proof: Option<String>,
    },
    /// Tool is not available at this level.
    Unavailable { tool: String },
}

/// Result of a single step in the attack sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// The step number (0-indexed).
    pub step: usize,
    /// The tool call that was attempted.
    pub tool_call: ToolCall,
    /// The verdict.
    pub verdict: Verdict,
    /// Human-readable narrative explaining WHY this verdict was given,
    /// grounded in real-world incidents and CVEs.
    pub narrative: String,
    /// Exposure state AFTER this step (actual recorded state).
    pub exposure: ExposureState,
    /// What the exposure state WOULD be if this operation were allowed.
    /// Only present when a guard blocks preemptively.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projected_exposure: Option<ExposureState>,
    /// Exposure classification of this operation: "PrivateData", "UntrustedContent",
    /// "ExfilVector", or null for neutral/unknown operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_class: Option<String>,
    /// Permission level for this operation in the current profile:
    /// "Always", "LowRisk", "Never", or null for special tools like approve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_level: Option<String>,
}

/// Snapshot of the exposure accumulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureState {
    pub private_data: bool,
    pub untrusted_content: bool,
    pub exfil_vector: bool,
    pub is_uninhabitable: bool,
}

impl ExposureState {
    pub fn from_labels(labels: &[ExposureLabel]) -> Self {
        let private_data = labels.contains(&ExposureLabel::PrivateData);
        let untrusted_content = labels.contains(&ExposureLabel::UntrustedContent);
        let exfil_vector = labels.contains(&ExposureLabel::ExfilVector);
        Self {
            private_data,
            untrusted_content,
            exfil_vector,
            is_uninhabitable: private_data && untrusted_content && exfil_vector,
        }
    }

    pub fn empty() -> Self {
        Self {
            private_data: false,
            untrusted_content: false,
            exfil_vector: false,
            is_uninhabitable: false,
        }
    }
}

/// The complete result of running an attack sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Per-step results.
    pub steps: Vec<StepResult>,
    /// Was the flag successfully exfiltrated?
    pub flag_captured: bool,
    /// Which defense layers were activated during the attack.
    pub defenses_activated: Vec<String>,
    /// Score: higher = more defense layers triggered (the goal is understanding).
    pub score: u32,
    /// Final exposure state.
    pub final_exposure: ExposureState,
    /// Error message if the attack sequence was malformed.
    pub error: Option<String>,
    /// Human-readable explanation of how the score was computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_reason: Option<String>,
}

impl AttackResult {
    pub fn parse_error(msg: String) -> Self {
        Self {
            steps: vec![],
            flag_captured: false,
            defenses_activated: vec![],
            score: 0,
            final_exposure: ExposureState::empty(),
            error: Some(msg),
            score_reason: None,
        }
    }
}
