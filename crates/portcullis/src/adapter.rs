//! Platform adapters — I/O abstraction for cross-platform deployment.
//!
//! The verified decision core (`portcullis-core` + `Kernel`) is pure logic.
//! Platform adapters handle the I/O boundary:
//!
//! - **Hook adapter** (`HookAdapter`): stdin/stdout JSON for Claude Code hooks
//! - **CI adapter** (`CiAdapter`): GitHub Actions annotations + exit codes
//! - **Sidecar adapter** (`SidecarAdapter`): gRPC for k8s sidecar containers
//! - **MicroVM adapter** (`MicrovmAdapter`): vsock for Firecracker guests
//!
//! All adapters share the same `Kernel` — the decision logic is identical.
//! Only the I/O framing changes.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌──────────────┐
//! │ HookAdapter  │     │ CiAdapter    │
//! │ (stdin/out)  │     │ (annotations)│
//! └──────┬───────┘     └──────┬───────┘
//!        │                    │
//!        ▼                    ▼
//! ┌────────────────────────────────────┐
//! │         Kernel::decide()           │
//! │   (verified portcullis-core)       │
//! └────────────────────────────────────┘
//!        ▲                    ▲
//! ┌──────┴───────┐     ┌──────┴───────┐
//! │ SidecarAdapter│    │MicrovmAdapter │
//! │ (gRPC)       │     │ (vsock)      │
//! └──────────────┘     └──────────────┘
//! ```

use portcullis_core::Operation;

/// A tool call request from the platform.
#[derive(Debug, Clone)]
pub struct ToolRequest {
    /// Session identifier (stable across invocations).
    pub session_id: String,
    /// Tool name (e.g., "Bash", "Read", "mcp__server__tool").
    pub tool_name: String,
    /// Tool-specific parameters (opaque to the adapter).
    pub tool_input: String,
    /// Human-readable subject (file path, URL, command).
    pub subject: String,
}

/// The kernel's decision for a tool call.
#[derive(Debug, Clone)]
pub struct ToolDecision {
    /// "allow", "deny", or "ask"
    pub verdict: Verdict,
    /// Human-readable reason (for deny/ask).
    pub reason: Option<String>,
    /// Operation that was evaluated.
    pub operation: Operation,
    /// Exposure count after this decision.
    pub exposure_count: u32,
    /// Flow node ID (if flow graph enabled).
    pub flow_node_id: Option<u64>,
}

/// Decision verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Tool call is allowed.
    Allow,
    /// Tool call is denied (with reason).
    Deny,
    /// Tool call requires human approval.
    Ask,
}

/// Platform adapter trait — bridges the verified kernel with platform I/O.
///
/// Implementations handle:
/// 1. Reading tool call requests from the platform
/// 2. Passing them through `Kernel::decide()`
/// 3. Writing decisions back in the platform's format
/// 4. Managing session state persistence
pub trait PlatformAdapter {
    /// The platform-specific error type.
    type Error: std::fmt::Debug;

    /// Read a tool call request from the platform.
    fn read_request(&mut self) -> Result<ToolRequest, Self::Error>;

    /// Write a decision back to the platform.
    fn write_decision(&mut self, decision: &ToolDecision) -> Result<(), Self::Error>;

    /// Platform identifier (for logging/audit).
    fn platform_name(&self) -> &str;
}

/// Deployment mode — which platform adapter to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DeploymentMode {
    /// Claude Code PreToolUse hook (stdin/stdout JSON).
    Hook,
    /// GitHub Actions CI (annotations + exit codes).
    Ci,
    /// Kubernetes sidecar (gRPC).
    Sidecar,
    /// Firecracker microVM guest (vsock).
    Microvm,
}

impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeploymentMode::Hook => write!(f, "hook"),
            DeploymentMode::Ci => write!(f, "ci"),
            DeploymentMode::Sidecar => write!(f, "sidecar"),
            DeploymentMode::Microvm => write!(f, "microvm"),
        }
    }
}

impl DeploymentMode {
    /// Parse from string.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "hook" => Some(Self::Hook),
            "ci" => Some(Self::Ci),
            "sidecar" => Some(Self::Sidecar),
            "microvm" => Some(Self::Microvm),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_mode_roundtrip() {
        for mode in [
            DeploymentMode::Hook,
            DeploymentMode::Ci,
            DeploymentMode::Sidecar,
            DeploymentMode::Microvm,
        ] {
            assert_eq!(DeploymentMode::from_str_opt(&mode.to_string()), Some(mode));
        }
    }

    #[test]
    fn tool_request_construction() {
        let req = ToolRequest {
            session_id: "test-123".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: r#"{"command":"ls"}"#.to_string(),
            subject: "ls".to_string(),
        };
        assert_eq!(req.tool_name, "Bash");
        assert_eq!(req.session_id, "test-123");
    }

    #[test]
    fn verdict_equality() {
        assert_eq!(Verdict::Allow, Verdict::Allow);
        assert_ne!(Verdict::Allow, Verdict::Deny);
    }
}
