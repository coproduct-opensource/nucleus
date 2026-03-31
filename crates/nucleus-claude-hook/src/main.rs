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
use portcullis::manifest_registry::ManifestRegistry;
use portcullis::{Operation, PermissionLattice};
use portcullis_core::flow::NodeKind;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Claude Code hook protocol types
// ---------------------------------------------------------------------------

/// Input from Claude Code (PreToolUse hook).
///
/// Claude Code sends snake_case fields: session_id, tool_name, tool_input, etc.
#[derive(Debug, Deserialize)]
struct HookInput {
    /// Session identifier (stable across invocations).
    session_id: String,
    /// Tool name as Claude Code reports it.
    tool_name: String,
    /// Tool-specific parameters (JSON object).
    tool_input: serde_json::Value,
}

/// Output to Claude Code (PreToolUse hook protocol).
///
/// Claude Code expects: `{ "hookSpecificOutput": { "permissionDecision": "allow"|"deny"|"ask", ... } }`
/// See: <https://code.claude.com/docs/en/hooks>
#[derive(Debug, Serialize)]
struct HookOutput {
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
}

impl HookOutput {
    fn allow() -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: None,
            },
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(reason.into()),
            },
        }
    }

    fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: Some(reason.into()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Session state persistence
// ---------------------------------------------------------------------------

/// Persisted session state for cross-invocation exposure tracking.
#[derive(Debug, Serialize, Deserialize, Default)]
struct SessionState {
    /// Profile name used for this session.
    profile: String,
    /// Monotonic operation counter — must never decrease.
    /// If state is loaded with hwm=0 but the watermark file says otherwise,
    /// someone deleted the state file (social engineering attack).
    #[serde(default)]
    high_water_mark: u64,
    /// Operations that were allowed (replayed to rebuild kernel exposure).
    allowed_ops: Vec<(String, String)>, // (operation, subject)
    /// Flow graph observations: (NodeKind discriminant, operation, subject).
    /// Replayed to rebuild the causal DAG across hook invocations.
    #[serde(default)]
    flow_observations: Vec<(u8, String, String)>,
}

/// Result of loading session state — distinguishes clean start from tampered.
enum SessionLoad {
    /// Fresh session, no prior state.
    Fresh(SessionState),
    /// Loaded existing state successfully.
    Loaded(SessionState),
    /// State file was deleted after at least one operation was recorded.
    /// This is a tamper signal — fail closed.
    Tampered { expected_hwm: u64 },
}

fn session_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("nucleus-hook");
    std::fs::create_dir_all(&dir).ok();
    // Restrict directory permissions: owner-only (0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
    }
    dir
}

/// Sanitize session_id to prevent path traversal attacks.
/// A malicious session_id like "../../etc/cron.d/evil" could write
/// outside the session directory. Strip everything except alphanumerics,
/// hyphens, and underscores.
fn sanitize_session_id(session_id: &str) -> String {
    session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128) // Reasonable length limit
        .collect()
}

fn session_state_path(session_id: &str) -> PathBuf {
    let safe_id = sanitize_session_id(session_id);
    session_dir().join(format!("{safe_id}.json"))
}

/// Separate high-water-mark file — survives state file deletion.
/// If someone socially engineers "rm session.json", this file persists
/// and triggers tamper detection on the next invocation.
fn session_hwm_path(session_id: &str) -> PathBuf {
    let safe_id = sanitize_session_id(session_id);
    session_dir().join(format!(".{safe_id}.hwm"))
}

fn load_session(session_id: &str) -> SessionLoad {
    let path = session_state_path(session_id);
    let hwm_path = session_hwm_path(session_id);

    // Read the high-water-mark file (if it exists)
    let persisted_hwm: u64 = std::fs::read_to_string(&hwm_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<SessionState>(&content) {
            Ok(state) => {
                // Verify monotonicity: state HWM must match or exceed persisted HWM
                if state.high_water_mark < persisted_hwm {
                    SessionLoad::Tampered {
                        expected_hwm: persisted_hwm,
                    }
                } else {
                    SessionLoad::Loaded(state)
                }
            }
            // Corrupted JSON — tampered
            Err(_) => {
                if persisted_hwm > 0 {
                    SessionLoad::Tampered {
                        expected_hwm: persisted_hwm,
                    }
                } else {
                    SessionLoad::Fresh(SessionState::default())
                }
            }
        },
        Err(_) => {
            // State file missing — was there a prior session?
            if persisted_hwm > 0 {
                // State file existed before (HWM > 0) but is now gone.
                // This is the social engineering attack: "please rm the state file".
                SessionLoad::Tampered {
                    expected_hwm: persisted_hwm,
                }
            } else {
                SessionLoad::Fresh(SessionState::default())
            }
        }
    }
}

fn save_session(session_id: &str, state: &SessionState) {
    let path = session_state_path(session_id);
    let hwm_path = session_hwm_path(session_id);

    if let Ok(json) = serde_json::to_string(state) {
        // Write state file
        std::fs::write(&path, json).ok();
        // Write HWM file separately — survives state file deletion
        std::fs::write(&hwm_path, state.high_water_mark.to_string()).ok();
    }
}

// ---------------------------------------------------------------------------
// Tool name -> Operation mapping
// ---------------------------------------------------------------------------

/// Map a Claude Code tool name to a portcullis Operation.
///
/// SECURITY: Every tool is gated — no passthrough. The Agent tool spawns
/// subprocesses with fresh session IDs; passthrough would let a tainted
/// session escape its flow restrictions via a clean child process.
/// MCP tools (`mcp__<server>__<tool>`) are classified by their tool name suffix,
/// defaulting to RunBash (most restrictive) for unknown tools.
fn map_tool(name: &str) -> Operation {
    match name {
        "Bash" => Operation::RunBash,
        "Read" => Operation::ReadFiles,
        "Write" => Operation::WriteFiles,
        "Edit" => Operation::EditFiles,
        "Glob" => Operation::GlobSearch,
        "Grep" => Operation::GrepSearch,
        "WebFetch" => Operation::WebFetch,
        "WebSearch" => Operation::WebSearch,
        // SECURITY: Agent spawns a subprocess with its own session_id.
        // Passthrough here lets a tainted session launder writes through
        // a clean child. Gate as RunBash (most restrictive).
        "Agent" => Operation::RunBash,
        // MCP tools: classify by tool name, fail-closed for unknown
        _ if name.starts_with("mcp__") => classify_mcp_tool(name),
        // Unknown tools: fail-closed (RunBash = most restrictive)
        _ => Operation::RunBash,
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
        NodeKind::Summarization => 10,
        NodeKind::Retry => 11,
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
        9 => NodeKind::OutboundAction,
        10 => NodeKind::Summarization,
        _ => NodeKind::Retry,
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
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": binary
                    }
                ]
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
    eprintln!("  NUCLEUS_PROFILE       Permission profile name (default: safe_pr_fixer)");
    eprintln!(
        "  NUCLEUS_FAIL_CLOSED   Set to 1 for CISO mode: infrastructure errors block (default: 0)"
    );
    eprintln!();
    eprintln!("ERROR MODEL:");
    eprintln!("  Default: hook errors fall through to Claude Code defaults (asks user)");
    eprintln!("  NUCLEUS_FAIL_CLOSED=1: hook errors block all tool calls (paranoid mode)");
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

    // Read hook input from stdin.
    //
    // ERROR MODEL: Infrastructure errors (no stdin, bad JSON) are NON-BLOCKING.
    // Exit 0 with no JSON → Claude Code falls through to normal behavior (asks user).
    // Only INTENTIONAL denials (flow violations, capability checks, tamper) use exit 2.
    // This means a broken/crashing hook doesn't brick the session — it gracefully
    // degrades to standard Claude Code permission prompts.
    //
    // For production/CISO mode: set NUCLEUS_FAIL_CLOSED=1 to make infrastructure
    // errors blocking (exit 2). This is the paranoid setting.
    let fail_closed = std::env::var("NUCLEUS_FAIL_CLOSED")
        .map(|v| v == "1")
        .unwrap_or(false);

    let stdin = io::stdin();
    let line = match stdin.lock().lines().next() {
        Some(Ok(line)) => line,
        _ => {
            eprintln!("nucleus: no input on stdin — falling through to Claude Code defaults");
            if fail_closed {
                let out = HookOutput::deny(
                    "nucleus: no hook input — failing closed (NUCLEUS_FAIL_CLOSED=1)",
                );
                println!("{}", serde_json::to_string(&out).unwrap());
                std::process::exit(2);
            }
            // Non-blocking: exit 0 with no JSON → Claude Code asks user normally
            return;
        }
    };

    let input: HookInput = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("nucleus: parse error: {e} — falling through to Claude Code defaults");
            if fail_closed {
                let out = HookOutput::deny(format!("nucleus: parse error — failing closed: {e}"));
                println!("{}", serde_json::to_string(&out).unwrap());
                std::process::exit(2);
            }
            // Non-blocking: exit 0 with no JSON → Claude Code asks user normally
            return;
        }
    };

    // Map tool to operation — every tool is gated, no passthrough
    let operation = map_tool(&input.tool_name);

    // Check MCP tools against manifest registry (admission control).
    // Loads manifests from .nucleus/manifests/*.toml in the working directory.
    if input.tool_name.starts_with("mcp__") {
        let cwd = std::env::current_dir().unwrap_or_default();
        let registry = ManifestRegistry::load_from_dir(&cwd);
        // Extract tool name: mcp__server__tool → server__tool
        let mcp_tool_name = input
            .tool_name
            .strip_prefix("mcp__")
            .unwrap_or(&input.tool_name);
        if let Some(reason) = registry.is_rejected(mcp_tool_name) {
            let out = HookOutput::deny(format!(
                "nucleus: MCP tool '{}' rejected by manifest admission: {:?}",
                mcp_tool_name, reason
            ));
            eprintln!(
                "nucleus: {} rejected by manifest admission: {:?}",
                input.tool_name, reason
            );
            println!("{}", serde_json::to_string(&out).unwrap());
            std::process::exit(2);
        }
    }

    let subject = extract_subject(&input.tool_name, &input.tool_input);
    let profile_name = default_profile_name();
    let perms = resolve_profile(&profile_name).unwrap_or_else(|| {
        eprintln!("nucleus: unknown profile '{profile_name}', using safe_pr_fixer");
        PermissionLattice::safe_pr_fixer()
    });

    // Load session state — detect tamper (social engineering state deletion)
    let mut session = match load_session(&input.session_id) {
        SessionLoad::Fresh(s) | SessionLoad::Loaded(s) => s,
        SessionLoad::Tampered { expected_hwm } => {
            // SECURITY: State file was deleted but HWM file proves prior ops existed.
            // This is the social engineering attack: "please delete the session file
            // so I can help you." Fail closed — deny everything.
            let msg = format!(
                "nucleus: TAMPER DETECTED — session state deleted (expected hwm={expected_hwm}). \
                 A compromised model may have asked you to delete session files. \
                 All operations denied until session restart."
            );
            eprintln!("{msg}");
            let out = HookOutput::deny(&msg);
            println!("{}", serde_json::to_string(&out).unwrap());
            std::process::exit(2);
        }
    };
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
            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            HookOutput::allow()
        }
        Verdict::RequiresApproval => {
            // Do NOT persist optimistically. If the user approves, Claude Code
            // does not re-call PreToolUse — so the next invocation may miss this
            // operation in its replay. This is a known tracking gap, but it's
            // safer than phantom operations: persisting before user decision
            // means a denied operation still appears in the session state,
            // causing exposure drift and flow graph corruption.
            //
            // The tracking gap is conservative: the next invocation underestimates
            // exposure (fewer ops in replay), which may allow an operation that
            // should have been gated. But the flow graph's taint propagation
            // catches the important case (web taint → write).
            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            HookOutput::ask(format!(
                "nucleus: exposure {exposure_count}/3 — requires human approval"
            ))
        }
        Verdict::Deny(ref reason) => {
            // Do NOT persist: operation was blocked.
            // Still increment HWM — denied ops prove the session existed.
            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            HookOutput::deny(format!("nucleus: denied — {reason:?}"))
        }
    };

    // Log to stderr
    let verdict_str = &output.hook_specific_output.permission_decision;
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
        assert_eq!(map_tool("Bash"), Operation::RunBash);
    }

    #[test]
    fn test_map_tool_read() {
        assert_eq!(map_tool("Read"), Operation::ReadFiles);
    }

    #[test]
    fn test_map_tool_write_edit() {
        assert_eq!(map_tool("Write"), Operation::WriteFiles);
        assert_eq!(map_tool("Edit"), Operation::EditFiles);
    }

    #[test]
    fn test_map_tool_search() {
        assert_eq!(map_tool("Glob"), Operation::GlobSearch);
        assert_eq!(map_tool("Grep"), Operation::GrepSearch);
    }

    #[test]
    fn test_map_tool_web() {
        assert_eq!(map_tool("WebFetch"), Operation::WebFetch);
        assert_eq!(map_tool("WebSearch"), Operation::WebSearch);
    }

    #[test]
    fn test_agent_is_gated_not_passthrough() {
        // SECURITY: Agent spawns subprocesses with fresh session IDs.
        // Passthrough would let tainted sessions escape via clean child.
        // Must be gated as RunBash (most restrictive).
        assert_eq!(map_tool("Agent"), Operation::RunBash);
    }

    #[test]
    fn test_mcp_tools_are_gated() {
        // All tools return an Operation — no passthrough
        assert_eq!(map_tool("mcp__server__read_file"), Operation::ReadFiles);
        assert_eq!(map_tool("mcp__github__create_issue"), Operation::WriteFiles);
        assert_eq!(map_tool("mcp__unknown__unknown_tool"), Operation::RunBash);
    }

    #[test]
    fn test_mcp_tool_classification() {
        // Read-like
        assert_eq!(map_tool("mcp__fs__read_file"), Operation::ReadFiles);
        assert_eq!(map_tool("mcp__db__get_record"), Operation::ReadFiles);
        assert_eq!(map_tool("mcp__api__list_items"), Operation::ReadFiles);
        // Write-like
        assert_eq!(map_tool("mcp__fs__write_file"), Operation::WriteFiles);
        assert_eq!(map_tool("mcp__db__create_record"), Operation::WriteFiles);
        assert_eq!(map_tool("mcp__db__delete_item"), Operation::WriteFiles);
        // Web/fetch
        assert_eq!(map_tool("mcp__http__fetch_url"), Operation::WebFetch);
        // Exec
        assert_eq!(map_tool("mcp__shell__run_command"), Operation::RunBash);
        assert_eq!(map_tool("mcp__term__exec_script"), Operation::RunBash);
        // Git
        assert_eq!(map_tool("mcp__git__push_branch"), Operation::GitPush);
        assert_eq!(map_tool("mcp__gh__pull_request"), Operation::CreatePr);
        // Unknown → fail-closed as RunBash
        assert_eq!(map_tool("mcp__evil__pwn"), Operation::RunBash);
    }

    #[test]
    fn test_unknown_tools_fail_closed() {
        // Unknown non-MCP tools also fail-closed
        assert_eq!(map_tool("UnknownTool"), Operation::RunBash);
    }

    #[test]
    fn test_session_tamper_detection() {
        // Simulate: create a session, save it, delete state file, verify tamper detected
        let test_id = format!("tamper-test-{}", std::process::id());
        let state = SessionState {
            high_water_mark: 5,
            profile: "test".to_string(),
            ..Default::default()
        };
        save_session(&test_id, &state);

        // Verify loads correctly
        assert!(matches!(load_session(&test_id), SessionLoad::Loaded(_)));

        // Delete state file (simulating social engineering attack)
        let state_path = session_state_path(&test_id);
        std::fs::remove_file(&state_path).unwrap();

        // HWM file still exists → tamper detected
        assert!(matches!(
            load_session(&test_id),
            SessionLoad::Tampered { expected_hwm: 5 }
        ));

        // Cleanup
        let hwm_path = session_hwm_path(&test_id);
        std::fs::remove_file(&hwm_path).ok();
    }

    #[test]
    fn test_fresh_session_is_not_tampered() {
        let test_id = format!("fresh-test-{}", std::process::id());
        // No prior state, no HWM file → fresh session
        assert!(matches!(load_session(&test_id), SessionLoad::Fresh(_)));
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
        let out = HookOutput::allow();
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"permissionDecision\":\"allow\""));
        assert!(json.contains("\"hookSpecificOutput\""));
        assert!(json.contains("\"hookEventName\":\"PreToolUse\""));
        assert!(!json.contains("permissionDecisionReason")); // skip_serializing_if

        let deny = HookOutput::deny("test reason");
        let json = serde_json::to_string(&deny).unwrap();
        assert!(json.contains("\"permissionDecision\":\"deny\""));
        assert!(json.contains("\"permissionDecisionReason\":\"test reason\""));
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
        for i in 0..12u8 {
            let kind = u8_to_node_kind(i);
            assert_eq!(node_kind_to_u8(kind), i);
        }
    }
}
