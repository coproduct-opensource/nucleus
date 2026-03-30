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
use portcullis_core::flow::NodeKind;
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
    /// Flow graph observations: (NodeKind discriminant, operation, subject).
    /// Replayed to rebuild the causal DAG across hook invocations.
    #[serde(default)]
    flow_observations: Vec<(u8, String, String)>,
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
/// Returns `None` only for the Agent meta-tool (orchestration, no side effects).
/// MCP tools (`mcp__<server>__<tool>`) are classified by their tool name suffix,
/// defaulting to RunBash (most restrictive) for unknown tools.
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
        // Agent is orchestration — no direct side effects
        "Agent" => None,
        // MCP tools: classify by tool name, fail-closed for unknown
        _ if name.starts_with("mcp__") => Some(classify_mcp_tool(name)),
        // Unknown tools: fail-closed (RunBash = most restrictive)
        _ => Some(Operation::RunBash),
    }
}

/// Classify an MCP tool by its name suffix.
///
/// MCP tool names follow `mcp__<server>__<tool>`. We extract the tool
/// portion and classify by known patterns. Unknown tools default to
/// RunBash (the most restrictive operation — requires Always capability
/// and contributes ExfilVector exposure).
fn classify_mcp_tool(name: &str) -> Operation {
    // Extract the tool name: mcp__server__tool_name → tool_name
    let tool = name
        .strip_prefix("mcp__")
        .and_then(|rest| rest.split("__").nth(1))
        .unwrap_or(name);

    // Classify by known tool patterns.
    // Order matters — more specific patterns before general ones.
    match tool {
        // Git PR tools (before "create" matches WriteFiles)
        t if t.contains("pull_request") || t.contains("pr_create") => Operation::CreatePr,
        // Git push/commit (before general patterns)
        t if t.contains("push") || t.contains("commit") || t.contains("merge") => {
            Operation::GitPush
        }
        // Exec/run tools (high priority — these are dangerous)
        t if t.contains("run")
            || t.contains("exec")
            || t.contains("shell")
            || t.contains("command")
            || t.contains("bash")
            || t.contains("terminal") =>
        {
            Operation::RunBash
        }
        // Web/fetch tools (before read, since "fetch" is network)
        t if t.contains("fetch")
            || t.contains("download")
            || t.contains("http")
            || t.contains("url")
            || t.contains("browse") =>
        {
            Operation::WebFetch
        }
        // Write-like tools
        t if t.contains("write")
            || t.contains("create")
            || t.contains("update")
            || t.contains("delete")
            || t.contains("put")
            || t.contains("set")
            || t.contains("insert")
            || t.contains("edit")
            || t.contains("modify") =>
        {
            Operation::WriteFiles
        }
        // Read-like tools
        t if t.contains("read")
            || t.contains("get")
            || t.contains("list")
            || t.contains("search")
            || t.contains("query")
            || t.contains("describe")
            || t.contains("request") =>
        {
            Operation::ReadFiles
        }
        // Search tools
        t if t.contains("grep") || t.contains("find") || t.contains("glob") => {
            Operation::GlobSearch
        }
        // Unknown MCP tool → fail-closed as RunBash (most restrictive)
        _ => Operation::RunBash,
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
        _ if tool_name.starts_with("mcp__") => {
            // For MCP tools, combine tool name + first string argument as subject
            let tool_part = tool_name.strip_prefix("mcp__").unwrap_or(tool_name);
            let arg = input
                .as_object()
                .and_then(|obj| obj.values().find_map(|v| v.as_str().map(|s| s.to_string())))
                .unwrap_or_default();
            if arg.is_empty() {
                tool_part.to_string()
            } else {
                format!("{tool_part}: {arg}")
            }
        }
        _ => "(unknown)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Flow label classification
// ---------------------------------------------------------------------------

/// Map an Operation to the NodeKind that represents its data contribution.
///
/// After an allowed operation executes, its result enters the session as
/// an observation of this kind. This determines the IFC label assigned
/// to the data: web content gets Adversarial/NoAuthority, file reads get
/// Internal/Trusted, etc.
fn operation_to_node_kind(op: Operation) -> NodeKind {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => NodeKind::FileRead,
        Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
        Operation::WriteFiles | Operation::EditFiles => NodeKind::OutboundAction,
        Operation::RunBash => NodeKind::OutboundAction,
        Operation::GitCommit | Operation::GitPush | Operation::CreatePr => NodeKind::OutboundAction,
        Operation::ManagePods => NodeKind::OutboundAction,
    }
}

/// Convert a NodeKind to a u8 discriminant for serialization.
fn node_kind_to_u8(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::UserPrompt => 0,
        NodeKind::ToolResponse => 1,
        NodeKind::WebContent => 2,
        NodeKind::MemoryRead => 3,
        NodeKind::MemoryWrite => 4,
        NodeKind::FileRead => 5,
        NodeKind::EnvVar => 6,
        NodeKind::ModelPlan => 7,
        NodeKind::Secret => 8,
        NodeKind::OutboundAction => 9,
    }
}

/// Convert a u8 discriminant back to NodeKind.
fn u8_to_node_kind(v: u8) -> NodeKind {
    match v {
        0 => NodeKind::UserPrompt,
        1 => NodeKind::ToolResponse,
        2 => NodeKind::WebContent,
        3 => NodeKind::MemoryRead,
        4 => NodeKind::MemoryWrite,
        5 => NodeKind::FileRead,
        6 => NodeKind::EnvVar,
        7 => NodeKind::ModelPlan,
        8 => NodeKind::Secret,
        _ => NodeKind::OutboundAction,
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
    kernel.enable_flow_graph();

    // Replay previous operations to rebuild exposure state AND flow graph.
    // Each allowed op is: 1) replayed in the flat kernel for exposure,
    // 2) observed in the flow graph as a data node.
    let mut last_node_id: Option<u64> = None;
    for (op_str, subj) in &session.allowed_ops {
        if let Ok(op) = Operation::try_from(op_str.as_str()) {
            kernel.decide(op, subj);
        }
    }
    for &(kind_u8, ref _op_str, ref _subj) in &session.flow_observations {
        let kind = u8_to_node_kind(kind_u8);
        let parents: Vec<u64> = last_node_id.into_iter().collect();
        if let Ok(id) = kernel.observe(kind, &parents) {
            last_node_id = Some(id);
        }
    }

    // Make the actual decision using the causal DAG.
    // The current operation's parents are the last observation in the chain.
    let parents: Vec<u64> = last_node_id.into_iter().collect();
    let (decision, _token) = kernel.decide_with_parents(operation, &subject, &parents);
    let exposure_count = decision.exposure_transition.post_count;

    let output = match decision.verdict {
        Verdict::Allow => {
            // Persist: operation will execute — track in both exposure and flow graph
            session
                .allowed_ops
                .push((operation.to_string(), subject.clone()));
            let obs_kind = operation_to_node_kind(operation);
            session.flow_observations.push((
                node_kind_to_u8(obs_kind),
                operation.to_string(),
                subject.clone(),
            ));
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
            let obs_kind = operation_to_node_kind(operation);
            session.flow_observations.push((
                node_kind_to_u8(obs_kind),
                operation.to_string(),
                subject.clone(),
            ));
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
    let flow_node = decision
        .flow_node_id
        .map(|id| format!(", flow_node: {id}"))
        .unwrap_or_default();
    eprintln!(
        "nucleus: {operation} {subject} -> {verdict_str} [exposure: {exposure_count}/3, profile: {profile_name}{flow_node}]"
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
        // Only Agent is passthrough — no side effects, just orchestration
        assert_eq!(map_tool("Agent"), None);
    }

    #[test]
    fn test_mcp_tools_are_gated() {
        // MCP tools must NOT be passthrough — they go through kernel
        assert!(map_tool("mcp__server__read_file").is_some());
        assert!(map_tool("mcp__github__create_issue").is_some());
        assert!(map_tool("mcp__unknown__unknown_tool").is_some());
    }

    #[test]
    fn test_mcp_tool_classification() {
        // Read-like
        assert_eq!(map_tool("mcp__fs__read_file"), Some(Operation::ReadFiles));
        assert_eq!(map_tool("mcp__db__get_record"), Some(Operation::ReadFiles));
        assert_eq!(map_tool("mcp__api__list_items"), Some(Operation::ReadFiles));
        // Write-like
        assert_eq!(map_tool("mcp__fs__write_file"), Some(Operation::WriteFiles));
        assert_eq!(
            map_tool("mcp__db__create_record"),
            Some(Operation::WriteFiles)
        );
        assert_eq!(
            map_tool("mcp__db__delete_item"),
            Some(Operation::WriteFiles)
        );
        // Web/fetch
        assert_eq!(map_tool("mcp__http__fetch_url"), Some(Operation::WebFetch));
        // Exec
        assert_eq!(
            map_tool("mcp__shell__run_command"),
            Some(Operation::RunBash)
        );
        assert_eq!(map_tool("mcp__term__exec_script"), Some(Operation::RunBash));
        // Git
        assert_eq!(map_tool("mcp__git__push_branch"), Some(Operation::GitPush));
        assert_eq!(map_tool("mcp__gh__pull_request"), Some(Operation::CreatePr));
        // Unknown → fail-closed as RunBash
        assert_eq!(map_tool("mcp__evil__pwn"), Some(Operation::RunBash));
    }

    #[test]
    fn test_unknown_tools_fail_closed() {
        // Unknown non-MCP tools also fail-closed
        assert_eq!(map_tool("UnknownTool"), Some(Operation::RunBash));
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

    #[test]
    fn test_flow_graph_blocks_web_tainted_write() {
        // With flow graph enabled, web_fetch taints the session so that
        // subsequent writes are blocked by flow control (authority escalation).
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        // Observe web content
        let web_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

        // Write depending on web content — blocked by flow control
        let (d, _) =
            kernel.decide_with_parents(Operation::WriteFiles, "/workspace/tainted.rs", &[web_id]);
        assert!(
            d.verdict.is_denied(),
            "Web-tainted write should be denied by flow control, got {:?}",
            d.verdict
        );
        assert!(d.flow_node_id.is_some());
    }

    #[test]
    fn test_flow_graph_allows_clean_write() {
        // Clean file read → write should be allowed
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let file_id = kernel.observe(NodeKind::FileRead, &[]).unwrap();

        let (d, _) =
            kernel.decide_with_parents(Operation::WriteFiles, "/workspace/clean.rs", &[file_id]);
        assert!(
            d.verdict.is_allowed(),
            "Clean-parented write should be allowed, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_operation_to_node_kind() {
        assert!(matches!(
            operation_to_node_kind(Operation::ReadFiles),
            NodeKind::FileRead
        ));
        assert!(matches!(
            operation_to_node_kind(Operation::WebFetch),
            NodeKind::WebContent
        ));
        assert!(matches!(
            operation_to_node_kind(Operation::WriteFiles),
            NodeKind::OutboundAction
        ));
        assert!(matches!(
            operation_to_node_kind(Operation::RunBash),
            NodeKind::OutboundAction
        ));
    }

    #[test]
    fn test_node_kind_roundtrip() {
        for i in 0..10u8 {
            let kind = u8_to_node_kind(i);
            assert_eq!(node_kind_to_u8(kind), i);
        }
    }
}
