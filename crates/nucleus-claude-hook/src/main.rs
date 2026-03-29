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
    /// Operations that were allowed — replayed on fresh Kernel to rebuild
    /// exposure state. This is necessary because each hook invocation is a
    /// separate process, but exposure must accumulate across the session.
    allowed_ops: Vec<(String, String)>, // (operation, subject)
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
// Subcommands
// ---------------------------------------------------------------------------

fn print_help() {
    eprintln!(
        "nucleus-claude-hook — formally verified permission kernel for Claude Code\n\
         \n\
         USAGE:\n\
         \x20 nucleus-claude-hook              (hook mode: reads JSON from stdin)\n\
         \x20 nucleus-claude-hook --setup      (configure Claude Code settings.json)\n\
         \x20 nucleus-claude-hook --status     (show active sessions and exposure)\n\
         \n\
         ENVIRONMENT:\n\
         \x20 NUCLEUS_PROFILE  Permission profile (default: safe_pr_fixer)\n\
         \x20                  Options: read_only, code_review, edit_only,\n\
         \x20                  fix_issue, safe_pr_fixer, release, permissive\n\
         \n\
         PROFILES:\n\
         \x20 read_only       Read + search only. No writes, no bash, no network.\n\
         \x20 code_review     Read + web research. No writes.\n\
         \x20 safe_pr_fixer   Write + edit + run + commit. No push, no PR. (default)\n\
         \x20 fix_issue       Full dev. Approval required for git push.\n\
         \x20 permissive      Everything allowed. Audit-only mode."
    );
}

fn setup_hook() {
    let settings_path = dirs_next::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .unwrap_or_else(|| PathBuf::from(".claude/settings.json"));

    // Read existing settings or create new.
    let mut settings: serde_json::Value = if settings_path.exists() {
        let data = std::fs::read_to_string(&settings_path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Check if hook is already configured.
    if let Some(hooks) = settings.get("hooks") {
        if let Some(pre) = hooks.get("PreToolUse") {
            let s = serde_json::to_string(pre).unwrap_or_default();
            if s.contains("nucleus-claude-hook") {
                eprintln!(
                    "nucleus: hook already configured in {}",
                    settings_path.display()
                );
                eprintln!(
                    "nucleus: current profile = {}",
                    std::env::var("NUCLEUS_PROFILE").unwrap_or_else(|_| "safe_pr_fixer".into())
                );
                return;
            }
        }
    }

    // Add the hook.
    let hook_config = serde_json::json!([{
        "matcher": "Bash|Read|Write|Edit|Glob|Grep|WebFetch|WebSearch",
        "hooks": [{ "type": "command", "command": "nucleus-claude-hook" }]
    }]);

    settings["hooks"]["PreToolUse"] = hook_config;

    // Ensure directory exists.
    if let Some(parent) = settings_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match std::fs::write(
        &settings_path,
        serde_json::to_string_pretty(&settings).unwrap_or_default(),
    ) {
        Ok(()) => {
            eprintln!("nucleus: hook configured in {}", settings_path.display());
            eprintln!(
                "nucleus: profile = {} (set NUCLEUS_PROFILE to change)",
                std::env::var("NUCLEUS_PROFILE").unwrap_or_else(|_| "safe_pr_fixer".into())
            );
            eprintln!("nucleus: restart Claude Code to activate");
        }
        Err(e) => {
            eprintln!("nucleus: failed to write {}: {e}", settings_path.display());
            std::process::exit(1);
        }
    }
}

fn show_status() {
    let profile = std::env::var("NUCLEUS_PROFILE").unwrap_or_else(|_| "safe_pr_fixer".into());
    eprintln!("nucleus-claude-hook status");
    eprintln!("  profile: {profile}");

    // Show active sessions.
    let tmp = std::env::temp_dir();
    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("nucleus-hook-") && name.ends_with(".json") {
                if let Ok(data) = std::fs::read_to_string(entry.path()) {
                    if let Ok(state) = serde_json::from_str::<SessionState>(&data) {
                        let session_id = name
                            .strip_prefix("nucleus-hook-")
                            .and_then(|s| s.strip_suffix(".json"))
                            .unwrap_or("?");
                        eprintln!(
                            "  session {session_id}: {} ops, profile={}",
                            state.allowed_ops.len(),
                            state.profile,
                        );
                        found = true;
                    }
                }
            }
        }
    }
    if !found {
        eprintln!("  no active sessions");
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Subcommands for setup and diagnostics.
    if args.len() > 1 {
        match args[1].as_str() {
            "--setup" => {
                setup_hook();
                return;
            }
            "--status" => {
                show_status();
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {}
        }
    }

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

    // Load or create session, then rebuild Kernel with accumulated exposure.
    let mut session = load_session(&hook_input.session_id).unwrap_or(SessionState {
        profile: profile_name.clone(),
        allowed_ops: Vec::new(),
    });
    let perms = resolve_profile(&profile_name);
    let mut kernel = Kernel::new(perms);

    // Replay previous allowed operations to rebuild exposure state.
    // This is the key to cross-invocation exposure tracking: each hook
    // invocation is a separate process, but exposure must accumulate.
    for (op_str, subj) in &session.allowed_ops {
        if let Ok(prev_op) = Operation::try_from(op_str.as_str()) {
            let _ = kernel.decide(prev_op, subj);
        }
    }

    // Make the actual decision with accumulated exposure.
    let decision = kernel.decide(operation, &subject);

    // If allowed, record this operation for future replay.
    if matches!(decision.verdict, Verdict::Allow) {
        session
            .allowed_ops
            .push((operation.to_string(), subject.clone()));
    }
    save_session(&hook_input.session_id, &session);

    // Log to stderr for visibility (Claude Code captures stderr).
    let exposure_count = kernel.exposure().count();
    eprintln!(
        "nucleus: {} {} → {:?} [exposure: {}/3, profile: {}]",
        operation, subject, decision.verdict, exposure_count, session.profile,
    );

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
                 Exposure state: {exposure_count}/3 legs active. Profile: {}.",
                session.profile,
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
