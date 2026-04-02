//! Claude Code hook protocol types (PreToolUse wire format).
//!
//! These types define the JSON schema that Claude Code sends/receives for hook
//! invocations.  They are intentionally kept in a separate module so that
//! `main.rs` focuses on decision logic rather than serialization boilerplate.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Claude Code hook protocol types
// ---------------------------------------------------------------------------

/// Input from Claude Code (PreToolUse hook).
///
/// Claude Code sends snake_case fields: session_id, tool_name, tool_input, etc.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    /// Session identifier (stable across invocations).
    pub session_id: String,
    /// Hook event name (e.g., "PreToolUse", "PostToolUse", "SessionEnd").
    #[serde(default = "default_hook_event")]
    pub hook_event_name: String,
    /// Tool name as Claude Code reports it (empty for non-tool events).
    #[serde(default)]
    pub tool_name: String,
    /// Tool-specific parameters (JSON object).
    #[serde(default)]
    pub tool_input: serde_json::Value,
    /// Tool result (PostToolUse only — the tool's output).
    #[serde(default)]
    pub tool_result: Option<String>,
}

fn default_hook_event() -> String {
    "PreToolUse".to_string()
}

/// Output to Claude Code (PreToolUse hook protocol).
///
/// Claude Code expects: `{ "hookSpecificOutput": { "permissionDecision": "allow"|"deny"|"ask", ... } }`
/// See: <https://code.claude.com/docs/en/hooks>
#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput {
    /// Always "PreToolUse".
    hook_event_name: String,
    /// "allow", "deny", or "ask".
    permission_decision: String,
    /// Human-readable reason (shown to user on deny/ask, to Claude on deny).
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision_reason: Option<String>,
    /// Context added to Claude's prompt before the tool executes.
    /// Used to inform the model about its current security context.
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_context: Option<String>,
}

impl HookOutput {
    /// The permission decision string ("allow", "deny", or "ask").
    pub fn permission_decision(&self) -> &str {
        &self.hook_specific_output.permission_decision
    }

    /// Allow with optional security context injected into Claude's prompt.
    ///
    /// When `context` is Some, the string is set as `additionalContext` in the
    /// hook response. Claude Code prepends this to the model's context before
    /// the tool executes, informing the model of compartment restrictions and
    /// taint status (#842).
    pub fn allow_with_context(context: Option<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: None,
                additional_context: context,
            },
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(reason.into()),
                additional_context: None,
            },
        }
    }

    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: Some(reason.into()),
                additional_context: None,
            },
        }
    }
}
