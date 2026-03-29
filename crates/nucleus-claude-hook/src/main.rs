//! Claude Code PreToolUse hook backed by the Nucleus verified permission kernel.
//!
//! Every tool call in Claude Code passes through this hook before execution.
//! The hook maps Claude Code tool names to the 12-operation permission lattice,
//! calls `Kernel::decide()` (backed by 297 Verus VCs, 62 Kani proofs, and
//! Lean 4 HeytingAlgebra), and returns allow/deny to Claude Code.
//!
//! # Installation
//!
//! ```bash
//! cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
//! ```
//!
//! # Configuration
//!
//! Add to `~/.claude/settings.json`:
//! ```json
//! {
//!   "hooks": {
//!     "PreToolUse": [{
//!       "matcher": "Bash|Read|Write|Edit|Glob|Grep|WebFetch|WebSearch",
//!       "hooks": [{ "type": "command", "command": "nucleus-claude-hook" }]
//!     }]
//!   }
//! }
//! ```
//!
//! # Environment Variables
//!
//! - `NUCLEUS_PROFILE`: Permission profile (default: `safe_pr_fixer`)
//!   Options: `read_only`, `code_review`, `edit_only`, `fix_issue`,
//!   `safe_pr_fixer`, `release`, `permissive`

use std::io::Read;
use std::path::PathBuf;

use portcullis::kernel::{Kernel, Verdict};
use portcullis::{Operation, PermissionLattice};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Claude Code hook protocol types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HookInput {
    session_id: String,
    tool_name: String,
    tool_input: serde_json::Value,
    #[allow(dead_code)]
    tool_use_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookOutput {
    hook_specific_output: HookSpecificOutput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput {
    hook_event_name: String,
    permission_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_context: Option<String>,
}

// ---------------------------------------------------------------------------
// Session state (persisted between hook invocations)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SessionState {
    profile: String,
    exposure_bits: u8,
    decision_count: u64,
}

fn session_path(session_id: &str) -> PathBuf {
    let tmp = std::env::temp_dir();
    tmp.join(format!("nucleus-hook-{session_id}.json"))
}

fn load_session(session_id: &str) -> Option<SessionState> {
    let path = session_path(session_id);
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_session(session_id: &str, state: &SessionState) {
    let path = session_path(session_id);
    if let Ok(data) = serde_json::to_string(state) {
        let _ = std::fs::write(path, data);
    }
}

// ---------------------------------------------------------------------------
// Tool name → Operation mapping
// ---------------------------------------------------------------------------

fn map_tool(tool_name: &str) -> Option<Operation> {
    match tool_name {
        "Bash" => Some(Operation::RunBash),
        "Read" => Some(Operation::ReadFiles),
        "Write" => Some(Operation::WriteFiles),
        "Edit" => Some(Operation::EditFiles),
        "Glob" => Some(Operation::GlobSearch),
        "Grep" => Some(Operation::GrepSearch),
        "WebFetch" => Some(Operation::WebFetch),
        "WebSearch" => Some(Operation::WebSearch),
        // Agent/subagent spawns don't do direct I/O — allow.
        "Agent" => None,
        // MCP tools have their own auth — allow by default.
        _ if tool_name.starts_with("mcp__") => None,
        // Unknown tools — let Claude Code's own permission system handle.
        _ => None,
    }
}

fn extract_subject(tool_name: &str, tool_input: &serde_json::Value) -> String {
    match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "Read" | "Write" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "Edit" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "Glob" => tool_input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("*")
            .to_string(),
        "Grep" => tool_input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "WebFetch" => tool_input
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "WebSearch" => tool_input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

fn resolve_profile(name: &str) -> PermissionLattice {
    match name {
        "read_only" | "read-only" => PermissionLattice::read_only(),
        "code_review" | "code-review" => PermissionLattice::code_review(),
        "edit_only" | "edit-only" => PermissionLattice::edit_only(),
        "fix_issue" | "fix-issue" => PermissionLattice::fix_issue(),
        "safe_pr_fixer" | "safe-pr-fixer" => PermissionLattice::safe_pr_fixer(),
        "release" => PermissionLattice::release(),
        "permissive" => PermissionLattice::permissive(),
        "restrictive" => PermissionLattice::restrictive(),
        "web_research" | "web-research" => PermissionLattice::web_research(),
        _ => {
            eprintln!("nucleus: unknown profile '{name}', using safe_pr_fixer");
            PermissionLattice::safe_pr_fixer()
        }
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn output_allow() -> HookOutput {
    HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "allow".to_string(),
            permission_decision_reason: None,
            additional_context: None,
        },
    }
}

fn output_deny(reason: &str) -> HookOutput {
    HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "deny".to_string(),
            permission_decision_reason: Some(reason.to_string()),
            additional_context: None,
        },
    }
}

fn output_ask(reason: &str, context: &str) -> HookOutput {
    HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "ask".to_string(),
            permission_decision_reason: Some(reason.to_string()),
            additional_context: Some(context.to_string()),
        },
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        // Can't read stdin — allow (fail open to avoid breaking Claude Code).
        let out = output_allow();
        let _ = serde_json::to_writer(std::io::stdout(), &out);
        return;
    }

    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => {
            // Malformed input — allow (fail open).
            let out = output_allow();
            let _ = serde_json::to_writer(std::io::stdout(), &out);
            return;
        }
    };

    // Map tool to operation. If unmapped, allow (not a gated tool).
    let operation = match map_tool(&hook_input.tool_name) {
        Some(op) => op,
        None => {
            let out = output_allow();
            let _ = serde_json::to_writer(std::io::stdout(), &out);
            return;
        }
    };

    let subject = extract_subject(&hook_input.tool_name, &hook_input.tool_input);
    let profile_name =
        std::env::var("NUCLEUS_PROFILE").unwrap_or_else(|_| "safe_pr_fixer".to_string());

    // Load or create session.
    let _session = load_session(&hook_input.session_id);
    let perms = resolve_profile(&profile_name);
    let mut kernel = Kernel::new(perms);

    // Make the decision.
    let decision = kernel.decide(operation, &subject);

    // Persist session state.
    let state = SessionState {
        profile: profile_name,
        exposure_bits: kernel.exposure().count(),
        decision_count: kernel.decision_count(),
    };
    save_session(&hook_input.session_id, &state);

    // Map verdict to Claude Code hook response.
    let out = match decision.verdict {
        Verdict::Allow => output_allow(),
        Verdict::Deny(ref reason) => {
            output_deny(&format!("Nucleus kernel denied {operation}: {reason:?}"))
        }
        Verdict::RequiresApproval => output_ask(
            &format!("Nucleus: {operation} requires approval"),
            &format!(
                "The nucleus permission kernel flagged this operation. \
                 Exposure state: {} legs active. Profile: {}.",
                kernel.exposure().count(),
                state.profile,
            ),
        ),
    };

    let _ = serde_json::to_writer(std::io::stdout(), &out);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_tool_all_claude_code_tools() {
        assert_eq!(map_tool("Bash"), Some(Operation::RunBash));
        assert_eq!(map_tool("Read"), Some(Operation::ReadFiles));
        assert_eq!(map_tool("Write"), Some(Operation::WriteFiles));
        assert_eq!(map_tool("Edit"), Some(Operation::EditFiles));
        assert_eq!(map_tool("Glob"), Some(Operation::GlobSearch));
        assert_eq!(map_tool("Grep"), Some(Operation::GrepSearch));
        assert_eq!(map_tool("WebFetch"), Some(Operation::WebFetch));
        assert_eq!(map_tool("WebSearch"), Some(Operation::WebSearch));
    }

    #[test]
    fn test_map_tool_passthrough() {
        assert_eq!(map_tool("Agent"), None);
        assert_eq!(map_tool("mcp__github__create_issue"), None);
        assert_eq!(map_tool("UnknownTool"), None);
    }

    #[test]
    fn test_extract_subject_bash() {
        let input = serde_json::json!({"command": "ls -la"});
        assert_eq!(extract_subject("Bash", &input), "ls -la");
    }

    #[test]
    fn test_extract_subject_read() {
        let input = serde_json::json!({"file_path": "/tmp/foo.rs"});
        assert_eq!(extract_subject("Read", &input), "/tmp/foo.rs");
    }

    #[test]
    fn test_extract_subject_web_fetch() {
        let input = serde_json::json!({"url": "https://example.com"});
        assert_eq!(extract_subject("WebFetch", &input), "https://example.com");
    }

    #[test]
    fn test_resolve_profile_defaults() {
        let perms = resolve_profile("safe_pr_fixer");
        assert_eq!(
            perms.capabilities.git_push,
            portcullis::CapabilityLevel::Never
        );

        let perms = resolve_profile("permissive");
        assert_eq!(
            perms.capabilities.git_push,
            portcullis::CapabilityLevel::Always
        );
    }

    #[test]
    fn test_kernel_allows_read_with_safe_pr_fixer() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        let decision = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(matches!(decision.verdict, Verdict::Allow));
    }

    #[test]
    fn test_kernel_denies_push_with_safe_pr_fixer() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        let decision = kernel.decide(Operation::GitPush, "origin/main");
        assert!(matches!(decision.verdict, Verdict::Deny(_)));
    }

    #[test]
    fn test_kernel_denies_bash_with_read_only() {
        let perms = PermissionLattice::read_only();
        let mut kernel = Kernel::new(perms);
        let decision = kernel.decide(Operation::RunBash, "ls -la");
        assert!(matches!(decision.verdict, Verdict::Deny(_)));
    }

    #[test]
    fn test_output_json_format() {
        let out = output_deny("test reason");
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"permissionDecision\":\"deny\""));
        assert!(json.contains("\"hookEventName\":\"PreToolUse\""));
    }
}
