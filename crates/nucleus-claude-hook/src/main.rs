//! Claude Code PreToolUse hook backed by the Nucleus verified permission kernel.
//!
//! This binary reads JSON from stdin (Claude Code hook protocol), runs the
//! operation through `portcullis::kernel::Kernel`, and writes JSON to stdout.
//!
//! Session state is persisted to a JSON file under `/tmp/` so that exposure
//! tracking accumulates across hook invocations within the same session.

use std::io::{self, BufRead, Write};

use portcullis::kernel::{Kernel, Verdict};
use portcullis::manifest_registry::ManifestRegistry;
use portcullis::receipt_sign::{receipt_hash, sign_receipt};
use portcullis::{Operation, PermissionLattice};
use portcullis_core::flow::NodeKind;
use portcullis_core::receipt::build_receipt;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde::Serialize;

mod protocol;
mod session;

use protocol::{HookInput, HookOutput};
use session::{
    compartment_file_path, gc_stale_sessions, generate_compartment_token, keyed_compartment_name,
    load_session, resolve_compartment, run_gc, sanitize_session_id, save_session, session_dir,
    session_hwm_path, session_state_path, SessionLoad, SessionState,
    MANIFEST_VIOLATION_REVOKE_THRESHOLD, SESSION_GC_TTL_SECS,
};

// Session state, persistence, compartments, and GC are in session.rs.

// ---------------------------------------------------------------------------
// Receipt persistence — append-only JSONL audit trail
// ---------------------------------------------------------------------------

/// Serializable receipt entry for the JSONL audit file.
#[derive(Serialize)]
struct ReceiptEntry {
    /// Unix timestamp
    timestamp: u64,
    /// Operation name
    operation: String,
    /// Subject (file path, URL, command, etc.)
    subject: String,
    /// "allow", "deny", or "ask"
    verdict: String,
    /// Flow rule that fired (for denials)
    rule: String,
    /// Action node label
    action_label: String,
    /// Causal ancestors (node kind + label summary)
    ancestors: Vec<String>,
    /// Ed25519 signature (hex)
    signature: String,
    /// Previous receipt hash (hex) — chain link
    prev_hash: String,
    /// This receipt's hash (hex) — for the next receipt's prev_hash
    receipt_hash: String,
    /// Parent agent's session ID (if this is a child session)
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_session_id: Option<String>,
    /// Parent agent's chain hash at spawn time (if child session)
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_chain_hash: Option<String>,
    /// Active compartment when this decision was made
    #[serde(skip_serializing_if = "Option::is_none")]
    compartment: Option<String>,
    /// Previous compartment (if this entry records a transition)
    #[serde(skip_serializing_if = "Option::is_none")]
    compartment_transition_from: Option<String>,
}

/// Persist a signed receipt to `.nucleus/receipts/<session-id>.jsonl`.
///
/// Append-only JSONL — one receipt per line. Creates the directory
/// and file if they don't exist. Failures are silent (audit is
/// best-effort, not on the critical path).
fn persist_receipt(
    session_id: &str,
    receipt: &portcullis_core::receipt::FlowReceipt,
    operation: Operation,
    subject: &str,
    parent_session_id: &Option<String>,
    parent_chain_hash: &Option<String>,
    compartment: Option<&str>,
) {
    let safe_id = sanitize_session_id(session_id);
    let receipts_dir = session_dir().join("receipts");
    std::fs::create_dir_all(&receipts_dir).ok();
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    let entry = ReceiptEntry {
        timestamp: receipt.created_at(),
        operation: operation.to_string(),
        subject: subject.to_string(),
        verdict: format!("{:?}", receipt.verdict()),
        rule: receipt.rule_name().to_string(),
        action_label: format!(
            "conf={:?} integ={:?} auth={:?}",
            receipt.action().label.confidentiality,
            receipt.action().label.integrity,
            receipt.action().label.authority,
        ),
        ancestors: receipt
            .ancestors()
            .iter()
            .map(|a| {
                format!(
                    "{:?} conf={:?} integ={:?} auth={:?}",
                    a.kind, a.label.confidentiality, a.label.integrity, a.label.authority,
                )
            })
            .collect(),
        signature: hex::encode(receipt.signature_bytes()),
        prev_hash: hex::encode(receipt.prev_hash()),
        receipt_hash: hex::encode(receipt_hash(receipt)),
        parent_session_id: parent_session_id.clone(),
        parent_chain_hash: parent_chain_hash.clone(),
        compartment: compartment.map(|s| s.to_string()),
        compartment_transition_from: None,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            writeln!(file, "{json}").ok();
        }
    }
}

/// Emit a synthetic receipt for a compartment transition.
fn persist_transition_receipt(session_id: &str, from: Option<&str>, to: &str, direction: &str) {
    let safe_id = sanitize_session_id(session_id);
    let receipts_dir = session_dir().join("receipts");
    std::fs::create_dir_all(&receipts_dir).ok();
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entry = ReceiptEntry {
        timestamp: now,
        operation: "compartment_transition".to_string(),
        subject: format!("{} -> {} ({direction})", from.unwrap_or("none"), to),
        verdict: "Allow".to_string(),
        rule: "compartment_transition".to_string(),
        action_label: String::new(),
        ancestors: vec![],
        signature: String::new(),
        prev_hash: String::new(),
        receipt_hash: String::new(),
        parent_session_id: None,
        parent_chain_hash: None,
        compartment: Some(to.to_string()),
        compartment_transition_from: from.map(|s| s.to_string()),
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            writeln!(file, "{json}").ok();
        }
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
        // Classified as SpawnAgent so the kernel can gate agent spawning
        // independently from bash execution.
        "Agent" => Operation::SpawnAgent,
        // MCP tools: classify by tool name, fail-closed for unknown
        _ if name.starts_with("mcp__") => classify_mcp_tool(name),
        // Unknown tools: fail-closed (RunBash = most restrictive)
        _ => Operation::RunBash,
    }
}

/// Classify an MCP tool using its manifest capabilities (if available),
/// falling back to name-based heuristics (#490).
///
/// The manifest is the authoritative source — it declares what operations
/// the tool actually performs. Name-based classification is a fallback
/// with known ambiguity issues (e.g., "search_and_create").
fn classify_mcp_tool(name: &str) -> Operation {
    // Try manifest-based classification first
    let mcp_tool_name = name
        .strip_prefix("mcp__")
        .and_then(|rest| rest.split("__").nth(1))
        .unwrap_or(name);

    let cwd = std::env::current_dir().unwrap_or_default();
    let registry = portcullis::manifest_registry::ManifestRegistry::load_from_dir(&cwd);
    if let Some(manifest) = registry.get(mcp_tool_name) {
        // Use the first declared capability as the classification.
        // If the manifest declares multiple capabilities, the most
        // restrictive one wins (fail-conservative).
        if let Some(op) = manifest.capabilities.first() {
            return *op;
        }
    } else if registry.admitted_count() > 0 {
        // Registry has manifests but not for this tool — log a warning
        // so users know this tool is using the less-secure heuristic path.
        eprintln!(
            "nucleus: MCP tool '{}' has no manifest — using name-based classification (less secure). \
             Add a manifest in .nucleus/manifests/",
            mcp_tool_name
        );
    }

    classify_mcp_tool_by_name(name)
}

/// Classify an MCP tool by its name suffix (fallback).
///
/// MCP tool names follow `mcp__<server>__<tool>`. We extract the tool
/// portion and classify by known patterns. Unknown tools default to
/// RunBash (the most restrictive operation — requires Always capability
/// and contributes ExfilVector exposure).
fn classify_mcp_tool_by_name(name: &str) -> Operation {
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
/// Format a denial reason as a human-readable message for Claude Code users.
///
/// Instead of raw Rust Debug output like `FlowViolation { rule: "AuthorityEscalation" }`,
/// produce actionable messages like "Blocked: this write depends on web content."
fn format_denial_for_user(
    reason: &portcullis::kernel::DenyReason,
    operation: Operation,
    compartment: Option<&str>,
) -> String {
    use portcullis::kernel::DenyReason;

    let comp_hint = compartment
        .map(|c| format!(" (compartment: {c})"))
        .unwrap_or_default();

    match reason {
        DenyReason::InsufficientCapability => {
            let fix = match compartment {
                Some("research") => "\n  How to fix:\n  \
                    - Switch to 'draft' compartment (enables writes) or 'execute' (enables bash)\n  \
                    - Or change the profile to allow this operation in .nucleus/policy.toml",
                Some("draft") if operation == Operation::RunBash => "\n  How to fix:\n  \
                    - Switch to 'execute' compartment to run commands\n  \
                    - Draft compartment only allows read + write (no execution)",
                Some("draft") if matches!(operation, Operation::WebFetch | Operation::WebSearch) => {
                    "\n  How to fix:\n  \
                    - Switch to 'research' compartment for web access\n  \
                    - Draft compartment blocks web to prevent taint"
                }
                _ => "\n  How to fix:\n  \
                    - Change the profile's capability for this operation in .nucleus/policy.toml\n  \
                    - Or use a more permissive profile: NUCLEUS_PROFILE=permissive",
            };
            format!("Blocked: {operation} is not allowed in the current profile{comp_hint}.{fix}")
        }
        DenyReason::FlowViolation { rule, .. } => {
            let (explanation, fix) = if rule.contains("AuthorityEscalation") {
                (
                    "This operation depends on web content (adversarial/untrusted). \
                     Web-influenced data cannot steer writes, execution, or git operations.",
                    if compartment.is_some() {
                        "\n  How to fix:\n  \
                        - Switch to 'draft' compartment (resets the flow graph, clears taint)\n  \
                        - Or use separate sessions: research in one, code in another"
                    } else {
                        "\n  How to fix:\n  \
                        - Restart Claude Code to clear the taint and try again\n  \
                        - Or use separate sessions: research in one, code in another\n  \
                        - Or enable compartments: NUCLEUS_COMPARTMENT=research"
                    },
                )
            } else if rule.contains("Exfiltration") {
                (
                    "This operation would exfiltrate secret data to an external sink.",
                    "\n  How to fix:\n  \
                    - Avoid mixing secret file reads with network operations in the same session\n  \
                    - Or declassify the data if it's not actually secret",
                )
            } else if rule.contains("IntegrityViolation") {
                (
                    "This operation would use untrusted data in a trusted-only context.",
                    "\n  How to fix:\n  \
                    - Validate or re-derive the data from a trusted source\n  \
                    - Or switch compartments to reset the flow graph",
                )
            } else {
                (
                    "Information flow policy prevents this operation.",
                    "\n  How to fix:\n  \
                    - Restart the session or switch compartments to clear taint",
                )
            };
            format!("Blocked: {explanation}{comp_hint}{fix}")
        }
        DenyReason::CommandBlocked { command } => {
            let short_cmd = if command.len() > 60 {
                format!("{}...", &command[..57])
            } else {
                command.clone()
            };
            format!(
                "Blocked: command '{short_cmd}' is not allowed by the command policy{comp_hint}.\n  \
                How to fix:\n  \
                - Add the command to the allowlist in .nucleus/policy.toml under [profile.commands]\n  \
                - Or use a more permissive profile"
            )
        }
        DenyReason::PathBlocked { path } => {
            format!(
                "Blocked: access to '{path}' is restricted by path policy{comp_hint}.\n  \
                How to fix:\n  \
                - Add the path to [profile.paths.allowed] in .nucleus/policy.toml\n  \
                - Or remove it from [profile.paths.blocked]"
            )
        }
        DenyReason::BudgetExhausted { remaining_usd } => {
            format!(
                "Blocked: budget exhausted (remaining: ${remaining_usd}).\n  \
                How to fix:\n  \
                - Increase max_cost_usd in .nucleus/policy.toml\n  \
                - Or start a new session with a fresh budget"
            )
        }
        DenyReason::TimeExpired { expired_at } => {
            format!(
                "Blocked: session expired at {expired_at}.\n  \
                How to fix:\n  \
                - Start a new session (restart Claude Code)\n  \
                - Or increase duration_hours in .nucleus/policy.toml"
            )
        }
        DenyReason::IsolationInsufficient { required, actual } => {
            format!(
                "Blocked: requires {required} isolation but running in {actual}.\n  \
                How to fix:\n  \
                - Run in a container (Docker/Colima) or Firecracker microVM\n  \
                - Or lower the minimum isolation in the policy"
            )
        }
        DenyReason::IsolationGated { dimension } => {
            format!(
                "Blocked: {dimension} is not available in the current isolation level.\n  \
                How to fix:\n  \
                - Run in a higher isolation environment (container or microVM)"
            )
        }
    }
}

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
        Operation::SpawnAgent => NodeKind::OutboundAction,
    }
}

/// Classify the output of a completed tool into its appropriate NodeKind.
///
/// This is different from `operation_to_node_kind()` which classifies the
/// _action_ of invoking the tool. Here we classify the _result_:
/// - Web tools produce WebContent (adversarial) — the output IS web content
/// - File read tools produce ToolResponse — the output is data the model will use
/// - Outbound actions produce ToolResponse — the result (e.g., "file written") is metadata
///
/// The critical distinction: a WebFetch action is an OutboundAction in the
/// pre-tool observation, but its OUTPUT is WebContent (adversarial). This
/// ensures that subsequent actions depending on web results get tainted (#593).
fn classify_tool_output(op: Operation) -> NodeKind {
    match op {
        // Web tool outputs ARE web content — adversarial taint propagates
        Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
        // File read outputs are file content — trusted category
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => NodeKind::FileRead,
        // Everything else: generic tool response (model category)
        _ => NodeKind::ToolResponse,
    }
}

/// Truncate a string for storage/display, preserving valid UTF-8 boundaries.
fn truncate_subject(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a valid UTF-8 boundary at or before max_len - 3
        let end = s
            .char_indices()
            .take_while(|(i, _)| *i <= max_len.saturating_sub(3))
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!("{}...", &s[..end])
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

// ---------------------------------------------------------------------------
// DAG parent assignment — category-based leaf tracking
// ---------------------------------------------------------------------------

/// Tracks the most recent flow graph node ID for each source category.
///
/// Instead of a linear chain (where every node depends on the previous one),
/// we maintain leaf nodes by category. This means independent branches
/// (e.g., file reads vs web fetches) don't cross-contaminate — only nodes
/// that actually depend on a source category inherit its taint.
///
/// Categories:
/// - `trusted`: FileRead, UserPrompt, EnvVar, MemoryRead — internal, trusted data
/// - `adversarial`: WebContent — untrusted, potentially attacker-controlled
/// - `action`: OutboundAction, MemoryWrite — side effects (writes, bash, git)
/// - `model`: ModelPlan, ToolResponse — model-generated content
#[derive(Debug, Default)]
struct LeafTracker {
    trusted: Vec<u64>,
    adversarial: Vec<u64>,
    action: Vec<u64>,
    model: Vec<u64>,
}

impl LeafTracker {
    /// Record a new node, replacing the leaf for its category.
    fn record(&mut self, kind: NodeKind, node_id: u64) {
        let leaves = match kind {
            NodeKind::FileRead | NodeKind::UserPrompt | NodeKind::EnvVar | NodeKind::MemoryRead => {
                &mut self.trusted
            }
            NodeKind::WebContent => &mut self.adversarial,
            NodeKind::OutboundAction | NodeKind::MemoryWrite => &mut self.action,
            NodeKind::ModelPlan
            | NodeKind::ToolResponse
            | NodeKind::Secret
            | NodeKind::Summarization
            | NodeKind::Retry => &mut self.model,
        };
        // Keep only the most recent leaf per category
        *leaves = vec![node_id];
    }

    /// Get parents for a new observation based on its NodeKind.
    ///
    /// Source observations (FileRead, WebContent) have no parents from other
    /// categories — they're independent input branches entering the session.
    ///
    /// Action observations (OutboundAction) depend on ALL current source
    /// leaves — the action may have been influenced by any data in the session.
    /// This is the conservative choice: if web content exists anywhere in the
    /// session, actions inherit its taint. But if no web content has been
    /// fetched, actions only depend on trusted sources.
    fn parents_for(&self, kind: NodeKind) -> Vec<u64> {
        match kind {
            // Source nodes: independent entry points, no cross-category parents.
            // A file read doesn't depend on web content.
            // A web fetch doesn't depend on prior file reads.
            NodeKind::FileRead | NodeKind::UserPrompt | NodeKind::EnvVar | NodeKind::MemoryRead => {
                // Source-only: previous trusted node (for ordering) but no adversarial parent
                self.trusted.clone()
            }
            NodeKind::WebContent => {
                // Web content enters independently
                self.adversarial.clone()
            }
            // Actions depend on ALL sources — the model may have used any of them.
            // This is where taint propagation happens: if adversarial leaves exist,
            // the action inherits adversarial labels.
            NodeKind::OutboundAction | NodeKind::MemoryWrite => {
                let mut parents = Vec::new();
                parents.extend_from_slice(&self.trusted);
                parents.extend_from_slice(&self.adversarial);
                parents.extend_from_slice(&self.model);
                // Include prior action for ordering
                parents.extend_from_slice(&self.action);
                parents
            }
            // Model/tool responses depend on all sources (model synthesizes from inputs)
            NodeKind::ModelPlan
            | NodeKind::ToolResponse
            | NodeKind::Secret
            | NodeKind::Summarization
            | NodeKind::Retry => {
                let mut parents = Vec::new();
                parents.extend_from_slice(&self.trusted);
                parents.extend_from_slice(&self.adversarial);
                parents.extend_from_slice(&self.model);
                parents
            }
        }
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

/// Load config from `.nucleus/config.toml` (#550).
///
/// Example config.toml:
/// ```toml
/// profile = "safe_pr_fixer"
/// compartment = "research"
/// fail_closed = false
/// require_manifests = true
/// ```
///
/// Priority: env var > config file > default.
fn load_config_file() -> std::collections::HashMap<String, String> {
    let mut config = std::collections::HashMap::new();

    let config_paths = [
        std::env::current_dir()
            .ok()
            .map(|d| d.join(".nucleus").join("config.toml")),
        dirs_next::home_dir().map(|d| d.join(".nucleus").join("config.toml")),
    ];

    for path in config_paths.iter().flatten() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(table) = content.parse::<toml::Table>() {
                for (key, value) in &table {
                    if let Some(s) = value.as_str() {
                        config.insert(key.clone(), s.to_string());
                    } else if let Some(b) = value.as_bool() {
                        config.insert(key.clone(), if b { "1" } else { "0" }.to_string());
                    }
                }
            }
            break;
        }
    }

    config
}

fn default_profile_name() -> String {
    // Check env var first, then config file, then default
    if let Ok(p) = std::env::var("NUCLEUS_PROFILE") {
        return p;
    }
    let config = load_config_file();
    if let Some(p) = config.get("profile") {
        return p.clone();
    }
    "safe_pr_fixer".to_string()
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

const PROFILE_DESCRIPTIONS: &[(&str, &str)] = &[
    ("read_only", "Read + search only, no writes or execution"),
    ("code_review", "Read + search, no writes (PR review)"),
    ("edit_only", "Read + write, no execution or web"),
    ("fix_issue", "Read + write + bash + web, no push"),
    (
        "safe_pr_fixer",
        "Full dev workflow, no git push/PR (DEFAULT)",
    ),
    ("release", "Full access including git push and PR creation"),
    (
        "permissive",
        "All capabilities, audit-only (no enforcement)",
    ),
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

    // Set up PreToolUse hook — PRESERVE existing hooks (#546)
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let hooks_obj = hooks.as_object_mut().unwrap();

    let nucleus_entry = serde_json::json!({
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": binary
            }
        ]
    });

    if let Some(existing) = hooks_obj.get_mut("PreToolUse") {
        if let Some(arr) = existing.as_array_mut() {
            // Check if nucleus is already configured
            let already_present = arr.iter().any(|entry| {
                entry
                    .get("hooks")
                    .and_then(|h| h.as_array())
                    .map(|hooks| {
                        hooks.iter().any(|h| {
                            h.get("command")
                                .and_then(|c| c.as_str())
                                .map(|s| s.contains("nucleus-claude-hook"))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            });

            if already_present {
                // Update the existing nucleus entry's command path
                for entry in arr.iter_mut() {
                    if let Some(hooks) = entry.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                        for hook in hooks.iter_mut() {
                            if hook
                                .get("command")
                                .and_then(|c| c.as_str())
                                .map(|s| s.contains("nucleus-claude-hook"))
                                .unwrap_or(false)
                            {
                                hook.as_object_mut()
                                    .unwrap()
                                    .insert("command".to_string(), serde_json::json!(binary));
                            }
                        }
                    }
                }
                eprintln!("nucleus: updated existing hook path");
            } else {
                // Append — preserve existing hooks
                arr.push(nucleus_entry);
                eprintln!(
                    "nucleus: added nucleus hook (preserved {} existing hook(s))",
                    arr.len() - 1
                );
            }
        } else {
            // PreToolUse exists but isn't an array — replace
            hooks_obj.insert("PreToolUse".to_string(), serde_json::json!([nucleus_entry]));
        }
    } else {
        // No existing PreToolUse — create fresh
        hooks_obj.insert("PreToolUse".to_string(), serde_json::json!([nucleus_entry]));
    }

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
        println!("nucleus: no active sessions");
        return;
    }
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();

    if entries.is_empty() {
        println!("nucleus: no active sessions");
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
                let comp = state.active_compartment.as_deref().unwrap_or("none");
                println!(
                    "  {name}  profile={:<16} compartment={:<12} ops={}",
                    state.profile,
                    comp,
                    state.allowed_ops.len()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// --help
// ---------------------------------------------------------------------------

fn show_receipts(session_id: &str) {
    let safe_id = sanitize_session_id(session_id);
    let receipts_dir = session_dir().join("receipts");
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    if !path.exists() {
        println!("No receipts found for session '{session_id}'");
        return;
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to read receipts: {e}");
            return;
        }
    };

    let mut count = 0u32;
    let mut allowed = 0u32;
    let mut denied = 0u32;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            let op = entry["operation"].as_str().unwrap_or("?");
            let subject = entry["subject"].as_str().unwrap_or("?");
            let verdict = entry["verdict"].as_str().unwrap_or("?");
            let comp = entry["compartment"].as_str().unwrap_or("");

            let icon = if verdict.contains("Deny") {
                denied += 1;
                "\x1b[31m\u{2717}\x1b[0m"
            } else {
                allowed += 1;
                "\x1b[32m\u{2713}\x1b[0m"
            };

            let comp_tag = if comp.is_empty() {
                String::new()
            } else {
                format!(" [{comp}]")
            };

            let short = if subject.len() > 50 {
                format!("{}...", &subject[..47])
            } else {
                subject.to_string()
            };

            println!("  {icon} {op:<25} {short}{comp_tag}");
            count += 1;
        }
    }

    println!();
    println!("Total: {count} receipts ({allowed} allowed, {denied} denied)");
    println!("Chain file: {}", path.display());
}

fn run_smoke_test() {
    use std::process::Command;

    println!("nucleus smoke test — verifying hook works correctly\n");

    let binary = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "nucleus-claude-hook".to_string());

    let session_id = format!("smoke-test-{}", std::process::id());
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Test 1: Read should be allowed
    let input1 = format!(
        r#"{{"session_id":"{session_id}","tool_name":"Read","tool_input":{{"file_path":"/etc/hostname"}}}}"#
    );
    let out1 = Command::new(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input1.as_bytes())?;
            child.wait_with_output()
        });

    match out1 {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"allow\"") {
                println!("  \x1b[32m\u{2713}\x1b[0m Read file → allowed");
                passed += 1;
            } else {
                println!(
                    "  \x1b[31m\u{2717}\x1b[0m Read file → unexpected: {}",
                    stdout.trim()
                );
                failed += 1;
            }
        }
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!(
                "  \x1b[31m\u{2717}\x1b[0m Read file → failed (exit {}): {}",
                output.status,
                stdout.trim()
            );
            failed += 1;
        }
        Err(e) => {
            println!("  \x1b[31m\u{2717}\x1b[0m Read file → error: {e}");
            failed += 1;
        }
    }

    // Test 2: WebFetch should be allowed (but taints)
    let input2 = format!(
        r#"{{"session_id":"{session_id}","tool_name":"WebFetch","tool_input":{{"url":"https://example.com"}}}}"#
    );
    let out2 = Command::new(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input2.as_bytes())?;
            child.wait_with_output()
        });

    match out2 {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"allow\"") {
                println!("  \x1b[32m\u{2713}\x1b[0m WebFetch → allowed (session tainted)");
                passed += 1;
            } else {
                println!(
                    "  \x1b[31m\u{2717}\x1b[0m WebFetch → unexpected: {}",
                    stdout.trim()
                );
                failed += 1;
            }
        }
        _ => {
            println!("  \x1b[31m\u{2717}\x1b[0m WebFetch → failed");
            failed += 1;
        }
    }

    // Test 3: Write after web fetch should be DENIED
    let input3 = format!(
        r#"{{"session_id":"{session_id}","tool_name":"Write","tool_input":{{"file_path":"/tmp/test","content":"x"}}}}"#
    );
    let out3 = Command::new(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input3.as_bytes())?;
            child.wait_with_output()
        });

    match out3 {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"deny\"") {
                println!(
                    "  \x1b[32m\u{2713}\x1b[0m Write after taint → denied (flow control working!)"
                );
                passed += 1;
            } else {
                println!(
                    "  \x1b[31m\u{2717}\x1b[0m Write after taint → should be denied but got: {}",
                    stdout.trim()
                );
                failed += 1;
            }
        }
        Err(e) => {
            // Exit code 2 = deny, which is correct
            println!("  \x1b[32m\u{2713}\x1b[0m Write after taint → denied (exit 2)");
            let _ = e;
            passed += 1;
        }
    }

    // Clean up smoke test session
    let state_path = session_state_path(&session_id);
    let hwm_path = session_hwm_path(&session_id);
    std::fs::remove_file(&state_path).ok();
    std::fs::remove_file(&hwm_path).ok();
    let receipts_dir = session_dir().join("receipts");
    let receipt_path = receipts_dir.join(format!("{}.jsonl", sanitize_session_id(&session_id)));
    std::fs::remove_file(&receipt_path).ok();

    println!();
    if failed == 0 {
        println!(
            "\x1b[32m{passed}/{} tests passed — hook is working correctly.\x1b[0m",
            passed + failed
        );
    } else {
        println!(
            "\x1b[31m{passed}/{} tests passed, {failed} failed.\x1b[0m",
            passed + failed
        );
        std::process::exit(1);
    }
}

fn run_init() {
    let config_dir = std::path::Path::new(".nucleus");
    let config_path = config_dir.join("config.toml");

    if config_path.exists() {
        println!("  \x1b[33m!\x1b[0m .nucleus/config.toml already exists");
        println!("    Edit it directly or delete to regenerate.");
        return;
    }

    std::fs::create_dir_all(config_dir).ok();

    let config = r#"# Nucleus security configuration
# See: nucleus-claude-hook --help

# Permission profile (run --show-profile <name> to preview)
profile = "safe_pr_fixer"

# Compartment (research/draft/execute/breakglass)
# compartment = "research"

# Deny MCP tools without manifests in .nucleus/manifests/
require_manifests = false

# Block all tool calls on hook infrastructure errors
fail_closed = false
"#;

    match std::fs::write(&config_path, config) {
        Ok(()) => {
            println!("  \x1b[32m\u{2713}\x1b[0m Created .nucleus/config.toml");
            println!();
            println!("  Next steps:");
            println!("    1. Edit .nucleus/config.toml to customize");
            println!("    2. Run nucleus-claude-hook --doctor to verify");
            println!("    3. Restart Claude Code");
        }
        Err(e) => {
            println!("  \x1b[31m\u{2717}\x1b[0m Failed to create config: {e}");
        }
    }

    // Also create manifests dir
    let manifests_dir = config_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir).ok();
    println!("  \x1b[32m\u{2713}\x1b[0m Created .nucleus/manifests/");
}

fn run_uninstall() {
    println!("Removing nucleus-claude-hook from Claude Code...\n");

    // 1. Remove hook from settings.json
    if let Some(home) = dirs_next::home_dir() {
        let settings_path = home.join(".claude").join("settings.json");
        if settings_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&settings_path) {
                if let Ok(mut settings) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
                        if let Some(pre_tool) = hooks.get_mut("PreToolUse") {
                            if let Some(arr) = pre_tool.as_array_mut() {
                                let before = arr.len();
                                arr.retain(|entry| {
                                    !entry
                                        .get("hooks")
                                        .and_then(|h| h.as_array())
                                        .map(|hooks| {
                                            hooks.iter().any(|h| {
                                                h.get("command")
                                                    .and_then(|c| c.as_str())
                                                    .map(|s| s.contains("nucleus-claude-hook"))
                                                    .unwrap_or(false)
                                            })
                                        })
                                        .unwrap_or(false)
                                });
                                if arr.len() < before {
                                    if arr.is_empty() {
                                        hooks.remove("PreToolUse");
                                    }
                                    if let Ok(json) = serde_json::to_string_pretty(&settings) {
                                        std::fs::write(&settings_path, json).ok();
                                    }
                                    println!(
                                        "  \x1b[32m\u{2713}\x1b[0m Removed hook from {}",
                                        settings_path.display()
                                    );
                                } else {
                                    println!("  - Hook not found in {}", settings_path.display());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Clean up session state
    let sess_dir = session_dir();
    if sess_dir.exists() {
        let count = std::fs::read_dir(&sess_dir).map(|e| e.count()).unwrap_or(0);
        if count > 0 {
            println!(
                "  \x1b[33m!\x1b[0m Session data at {} ({count} files)",
                sess_dir.display()
            );
            println!("    Remove with: rm -rf {}", sess_dir.display());
        }
    }

    println!("\n  To remove the binary:");
    println!("    cargo uninstall nucleus-claude-hook");
    println!("\n  Restart Claude Code to deactivate.");
}

fn run_doctor() {
    let mut ok = true;

    // 1. Check settings.json
    let home = dirs_next::home_dir();
    let settings_path = home
        .as_ref()
        .map(|h| h.join(".claude").join("settings.json"));

    if let Some(ref path) = settings_path {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if content.contains("nucleus-claude-hook") {
                    println!(
                        "\x1b[32m\u{2713}\x1b[0m Hook configured in {}",
                        path.display()
                    );
                } else {
                    println!(
                        "\x1b[31m\u{2717}\x1b[0m Hook NOT configured in {} — run --setup",
                        path.display()
                    );
                    ok = false;
                }
            }
        } else {
            println!(
                "\x1b[31m\u{2717}\x1b[0m Settings file not found: {} — run --setup",
                path.display()
            );
            ok = false;
        }
    }

    // 2. Check session directory
    let sess_dir = session_dir();
    if sess_dir.exists() {
        let count = std::fs::read_dir(&sess_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        println!(
            "\x1b[32m\u{2713}\x1b[0m Session directory: {} ({count} files)",
            sess_dir.display()
        );
    } else {
        println!("\x1b[33m-\x1b[0m Session directory not yet created (first run pending)");
    }

    // 3. Check profile
    let profile = default_profile_name();
    if resolve_profile(&profile).is_some() {
        println!("\x1b[32m\u{2713}\x1b[0m Active profile: {profile}");
    } else {
        println!(
            "\x1b[31m\u{2717}\x1b[0m Unknown profile: {profile} — will fall back to safe_pr_fixer"
        );
        ok = false;
    }

    // 4. Check compartment env
    if let Ok(comp) = std::env::var("NUCLEUS_COMPARTMENT") {
        if portcullis_core::compartment::Compartment::from_str_opt(&comp).is_some() {
            println!("\x1b[32m\u{2713}\x1b[0m Compartment: {comp}");
        } else {
            println!("\x1b[31m\u{2717}\x1b[0m Invalid NUCLEUS_COMPARTMENT: {comp}");
            ok = false;
        }
    } else {
        println!("\x1b[33m-\x1b[0m No compartment set (using profile defaults)");
    }

    // 5. Check receipt directory
    let receipt_dir = sess_dir.join("receipts");
    if receipt_dir.exists() {
        let count = std::fs::read_dir(&receipt_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        println!("\x1b[32m\u{2713}\x1b[0m Receipt chains: {count} sessions");
    } else {
        println!("\x1b[33m-\x1b[0m No receipt chains yet");
    }

    // 6. Version
    println!(
        "\x1b[32m\u{2713}\x1b[0m Version: {}",
        env!("CARGO_PKG_VERSION")
    );

    println!();
    if ok {
        println!("\x1b[32mAll checks passed.\x1b[0m");
    } else {
        println!("\x1b[31mSome checks failed.\x1b[0m Run --setup to configure.");
    }
}

fn show_profile(name: &str) {
    let perms = match resolve_profile(name) {
        Some(p) => p,
        None => {
            println!("Unknown profile: '{name}'");
            println!("Available: {}", PROFILES.join(", "));
            return;
        }
    };

    println!("Profile: {name}");
    println!("{}", perms.description);
    println!();
    println!("Capabilities:");

    let caps = &perms.capabilities;
    let fmt = |level: portcullis_core::CapabilityLevel| match level {
        portcullis_core::CapabilityLevel::Never => "\x1b[31mNever\x1b[0m",
        portcullis_core::CapabilityLevel::LowRisk => "\x1b[33mLowRisk\x1b[0m",
        portcullis_core::CapabilityLevel::Always => "\x1b[32mAlways\x1b[0m",
    };

    println!("  read_files:   {}", fmt(caps.read_files));
    println!("  write_files:  {}", fmt(caps.write_files));
    println!("  edit_files:   {}", fmt(caps.edit_files));
    println!("  run_bash:     {}", fmt(caps.run_bash));
    println!("  glob_search:  {}", fmt(caps.glob_search));
    println!("  grep_search:  {}", fmt(caps.grep_search));
    println!("  web_search:   {}", fmt(caps.web_search));
    println!("  web_fetch:    {}", fmt(caps.web_fetch));
    println!("  git_commit:   {}", fmt(caps.git_commit));
    println!("  git_push:     {}", fmt(caps.git_push));
    println!("  create_pr:    {}", fmt(caps.create_pr));
    println!("  manage_pods:  {}", fmt(caps.manage_pods));
    println!("  spawn_agent:  {}", fmt(caps.spawn_agent));
}

fn run_help() {
    println!("nucleus-claude-hook — Nucleus verified permission kernel for Claude Code");
    println!();
    println!("USAGE:");
    println!("  nucleus-claude-hook              Read hook JSON from stdin (normal mode)");
    println!("  nucleus-claude-hook --setup       Configure ~/.claude/settings.json");
    println!("  nucleus-claude-hook --status      Show active sessions");
    println!("  nucleus-claude-hook --gc          Remove stale session files (>24h)");
    println!("  nucleus-claude-hook --help        This message");
    println!("  nucleus-claude-hook --version     Show version");
    println!();
    println!("PROFILES (set NUCLEUS_PROFILE env var):");
    for (name, desc) in PROFILE_DESCRIPTIONS {
        println!("  {name:<16} {desc}");
    }
    println!();
    println!("ENVIRONMENT:");
    println!("  NUCLEUS_PROFILE            Permission profile (default: safe_pr_fixer)");
    println!("  NUCLEUS_COMPARTMENT        Compartment: research, draft, execute, breakglass");
    println!("  NUCLEUS_FAIL_CLOSED        Set to 1: infrastructure errors block (CISO mode)");
    println!("  NUCLEUS_REQUIRE_MANIFESTS  Set to 1: deny MCP tools without manifests");
    println!("  NUCLEUS_AUTONOMY_CEILING   Org cap: production, sandbox (default: unrestricted)");
    println!();
    println!("COMPARTMENTS:");
    println!("  research    Read + web only (no writes, no execution)");
    println!("  draft       Read + write (no execution, no web)");
    println!("  execute     Read + write + bash (no push)");
    println!("  breakglass  All capabilities + enhanced audit (reason required)");
    println!();
    println!("Learn more: https://github.com/coproduct-opensource/nucleus/blob/main/docs/quickstart-hook.md");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let start_time = std::time::Instant::now();
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
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("nucleus-claude-hook {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // Show the compartment file path for a session (so external tools can write to it)
    if let Some(pos) = args.iter().position(|a| a == "--compartment-path") {
        if let Some(session_id) = args.get(pos + 1) {
            let path = compartment_file_path(session_id);
            println!("{}", path.display());
        } else {
            eprintln!("usage: nucleus-claude-hook --compartment-path <session-id>");
        }
        return;
    }

    // Reset a tainted session (#567)
    if let Some(pos) = args.iter().position(|a| a == "--reset-session") {
        if let Some(session_id) = args.get(pos + 1) {
            let state_path = session_state_path(session_id);
            let hwm_path = session_hwm_path(session_id);
            if state_path.exists() {
                std::fs::remove_file(&state_path).ok();
                std::fs::remove_file(&hwm_path).ok();
                println!("nucleus: session '{session_id}' reset — taint cleared");
                println!("nucleus: Note: receipt chain preserved for audit");
            } else {
                println!("nucleus: no session found for '{session_id}'");
            }
        } else {
            println!("usage: nucleus-claude-hook --reset-session <session-id>");
        }
        return;
    }
    if args.iter().any(|a| a == "--init") {
        run_init();
        return;
    }
    if args.iter().any(|a| a == "--uninstall") {
        run_uninstall();
        return;
    }
    if args.iter().any(|a| a == "--doctor") {
        run_doctor();
        return;
    }
    if args.iter().any(|a| a == "--smoke-test") {
        run_smoke_test();
        return;
    }
    if args.iter().any(|a| a == "--gc") {
        run_gc();
        return;
    }
    // Show what a profile allows (#556)
    if let Some(pos) = args.iter().position(|a| a == "--show-profile") {
        if let Some(name) = args.get(pos + 1) {
            show_profile(name);
        } else {
            println!("Available profiles:");
            for p in PROFILES {
                println!("  {p}");
            }
            println!("\nUsage: nucleus-claude-hook --show-profile <name>");
        }
        return;
    }

    // View receipt chain for a session (#561)
    if let Some(pos) = args.iter().position(|a| a == "--receipts") {
        if let Some(session_id) = args.get(pos + 1) {
            show_receipts(session_id);
        } else {
            // List all receipt files
            let receipts_dir = session_dir().join("receipts");
            if receipts_dir.exists() {
                println!("Receipt chains:");
                if let Ok(entries) = std::fs::read_dir(&receipts_dir) {
                    for entry in entries.flatten() {
                        if entry.path().extension().is_some_and(|e| e == "jsonl") {
                            let name = entry
                                .path()
                                .file_stem()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let lines = std::fs::read_to_string(entry.path())
                                .map(|c| c.lines().count())
                                .unwrap_or(0);
                            println!("  {name}  ({lines} receipts)");
                        }
                    }
                }
            } else {
                println!("No receipt chains found.");
            }
            println!("\nUsage: nucleus-claude-hook --receipts <session-id>");
        }
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

    // Handle non-PreToolUse events
    if input.hook_event_name != "PreToolUse" {
        // SessionEnd: seal receipt chain and clean up (#499)
        if input.hook_event_name == "SessionEnd" {
            if let SessionLoad::Loaded(session) = load_session(&input.session_id) {
                let chain_hash = hex::encode(session.chain_head_hash);
                let op_count = session.allowed_ops.len();
                eprintln!(
                    "nucleus: session ended — {op_count} operations, chain hash: {chain_hash}"
                );

                persist_transition_receipt(
                    &input.session_id,
                    session.active_compartment.as_deref(),
                    "session_end",
                    "finalized",
                );

                // Clean up session state (keep receipts for audit)
                let state_path = session_state_path(&input.session_id);
                let hwm_path = session_hwm_path(&input.session_id);
                std::fs::remove_file(&state_path).ok();
                std::fs::remove_file(&hwm_path).ok();
                if !session.compartment_token.is_empty() {
                    let keyed =
                        keyed_compartment_name(&input.session_id, &session.compartment_token);
                    let comp_path = session_dir().join(format!("{keyed}.compartment"));
                    std::fs::remove_file(&comp_path).ok();
                }
                eprintln!("nucleus: session state cleaned up (receipts preserved)");

                // Opportunistic GC: clean up stale sessions from other
                // sessions that didn't get a SessionEnd event (#520).
                // Use a simple hash of session_id to get ~10% probability.
                let gc_trigger: u8 = input
                    .session_id
                    .bytes()
                    .fold(0u8, |acc, b| acc.wrapping_add(b));
                if gc_trigger % 10 == 0 {
                    let removed = gc_stale_sessions(SESSION_GC_TTL_SECS);
                    if removed > 0 {
                        eprintln!("nucleus: gc — removed {removed} stale session file(s)");
                    }
                }
            }
        }
        // PostToolUse: observe the tool result and insert into flow graph (#593, #497)
        if input.hook_event_name == "PostToolUse" && !input.tool_name.is_empty() {
            if let Some(ref result_text) = input.tool_result {
                // Check MCP tool output against manifest
                if input.tool_name.starts_with("mcp__") {
                    let cwd = std::env::current_dir().unwrap_or_default();
                    let registry =
                        portcullis::manifest_registry::ManifestRegistry::load_from_dir(&cwd);
                    let mcp_tool_name = input
                        .tool_name
                        .strip_prefix("mcp__")
                        .unwrap_or(&input.tool_name);
                    if let Some(manifest) = registry.get(mcp_tool_name) {
                        let violations = portcullis::manifest_enforcement::check_output(
                            mcp_tool_name,
                            manifest,
                            result_text,
                        );
                        if !violations.is_empty() {
                            for v in &violations {
                                eprintln!(
                                    "nucleus: MANIFEST VIOLATION — {}: {:?} — {}",
                                    v.tool_name, v.kind, v.description
                                );
                            }
                            // Persist violation count in session state (#485).
                            // Trust revocation is monotonic — count only increases.
                            if let SessionLoad::Loaded(ref mut session)
                            | SessionLoad::Fresh(ref mut session) =
                                load_session(&input.session_id)
                            {
                                let count = session
                                    .flagged_tools
                                    .entry(input.tool_name.clone())
                                    .or_insert(0);
                                *count = count.saturating_add(violations.len() as u32);
                                let current = *count;
                                save_session(&input.session_id, session);
                                if current >= MANIFEST_VIOLATION_REVOKE_THRESHOLD {
                                    eprintln!(
                                        "nucleus: tool '{}' has {} violations (threshold {}) — will be DENIED on next use",
                                        input.tool_name, current, MANIFEST_VIOLATION_REVOKE_THRESHOLD
                                    );
                                } else {
                                    eprintln!(
                                        "nucleus: tool '{}' flagged ({}/{} violations before revocation)",
                                        input.tool_name, current, MANIFEST_VIOLATION_REVOKE_THRESHOLD
                                    );
                                }
                            }
                        }
                    }
                }

                // Insert tool output as a ToolResponse observation in the flow graph.
                // This closes the gap where tool outputs were invisible to IFC (#593).
                // The ToolResponse node's kind depends on the tool: web tools produce
                // WebContent (adversarial), file reads produce FileRead (trusted),
                // everything else produces ToolResponse (model-category).
                match load_session(&input.session_id) {
                    SessionLoad::Loaded(mut session) | SessionLoad::Fresh(mut session) => {
                        // Classify the tool output's node kind based on the operation.
                        // The output of a web fetch IS web content (adversarial).
                        // The output of a file read IS file content (trusted).
                        // Everything else is a generic tool response (model category).
                        let op = map_tool(&input.tool_name);
                        let output_kind = classify_tool_output(op);

                        session.flow_observations.push((
                            node_kind_to_u8(output_kind),
                            format!("post:{op}"),
                            truncate_subject(result_text, 200),
                        ));
                        // Clear the pre-tool index — this PostToolUse is consumed.
                        session.last_pre_tool_obs_index = None;
                        save_session(&input.session_id, &session);

                        eprintln!(
                            "nucleus: post-tool {op} {} — inserted {:?} observation into flow graph",
                            input.tool_name, output_kind
                        );
                    }
                    SessionLoad::Tampered { .. } => {
                        eprintln!("nucleus: post-tool skipped — session tampered");
                    }
                }

                // Log the post-tool observation
                let op = map_tool(&input.tool_name);
                let truncated = truncate_subject(result_text, 100);
                eprintln!(
                    "nucleus: post-tool {op} {} — result: {truncated}",
                    input.tool_name
                );
            }
        }

        // SubagentStart: export parent's taint label + compartment (#498)
        if input.hook_event_name == "SubagentStart" {
            if let SessionLoad::Loaded(session) | SessionLoad::Fresh(session) =
                load_session(&input.session_id)
            {
                let agent_name = input.tool_name.as_str();
                eprintln!(
                    "nucleus: subagent started: {} (parent compartment: {})",
                    if agent_name.is_empty() {
                        "unnamed"
                    } else {
                        agent_name
                    },
                    session.active_compartment.as_deref().unwrap_or("none"),
                );

                // Export parent label for the child agent
                let safe_id = sanitize_session_id(&input.session_id);
                let label_path = session_dir().join(format!("{safe_id}.parent-label"));
                if label_path.exists() {
                    eprintln!("nucleus: parent label exported at {}", label_path.display());
                }

                // Record in receipt chain
                persist_transition_receipt(
                    &input.session_id,
                    session.active_compartment.as_deref(),
                    &format!(
                        "subagent_start:{}",
                        if agent_name.is_empty() {
                            "unnamed"
                        } else {
                            agent_name
                        }
                    ),
                    "spawned",
                );
            }
        }

        // SubagentStop: log child completion (#498)
        if input.hook_event_name == "SubagentStop" {
            let agent_name = input.tool_name.as_str();
            eprintln!(
                "nucleus: subagent stopped: {}",
                if agent_name.is_empty() {
                    "unnamed"
                } else {
                    agent_name
                },
            );

            // Record in receipt chain
            if let SessionLoad::Loaded(session) | SessionLoad::Fresh(session) =
                load_session(&input.session_id)
            {
                persist_transition_receipt(
                    &input.session_id,
                    session.active_compartment.as_deref(),
                    &format!(
                        "subagent_stop:{}",
                        if agent_name.is_empty() {
                            "unnamed"
                        } else {
                            agent_name
                        }
                    ),
                    "completed",
                );
            }
        }

        // Other events — pass through
        return;
    }

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
                "Blocked: MCP tool '{mcp_tool_name}' rejected by manifest admission: {reason:?}"
            ));
            eprintln!(
                "nucleus: {} rejected by manifest admission: {:?}",
                input.tool_name, reason
            );
            println!("{}", serde_json::to_string(&out).unwrap());
            std::process::exit(2);
        }

        // SECURITY (#512): Default-deny unmanifested MCP tools.
        // When NUCLEUS_REQUIRE_MANIFESTS=1, any MCP tool without a manifest
        // in .nucleus/manifests/ is denied. This prevents tools that fetch
        // instructions or executable content from unlabeled origins.
        let require_manifests = std::env::var("NUCLEUS_REQUIRE_MANIFESTS")
            .map(|v| v == "1")
            .unwrap_or(false);
        if require_manifests && registry.get(mcp_tool_name).is_none() {
            let out = HookOutput::deny(format!(
                "Blocked: MCP tool '{mcp_tool_name}' has no manifest. \
                 Add a manifest to .nucleus/manifests/ or run \
                 'nucleus manifest init --server {}'.",
                mcp_tool_name.split("__").next().unwrap_or(mcp_tool_name)
            ));
            eprintln!(
                "nucleus: {} denied — no manifest (NUCLEUS_REQUIRE_MANIFESTS=1)",
                input.tool_name
            );
            println!("{}", serde_json::to_string(&out).unwrap());
            std::process::exit(2);
        }

        // SECURITY (#462): Check if the tool is allowed in the current compartment.
        // A manifest with `allowed_compartments = ["research"]` blocks the tool
        // in draft/execute/breakglass.
        if let Some(manifest) = registry.get(mcp_tool_name) {
            if let Ok(comp_str) = std::env::var("NUCLEUS_COMPARTMENT") {
                let comp_name = comp_str.split(':').next().unwrap_or(&comp_str);
                if !manifest.is_allowed_in_compartment(comp_name) {
                    let out = HookOutput::deny(format!(
                        "Blocked: MCP tool '{mcp_tool_name}' is not allowed in \
                         compartment '{comp_name}'. Allowed in: {}.\n  \
                         How to fix:\n  \
                         - Switch to an allowed compartment\n  \
                         - Or update allowed_compartments in the tool's manifest",
                        if manifest.allowed_compartments.is_empty() {
                            "all".to_string()
                        } else {
                            manifest.allowed_compartments.join(", ")
                        }
                    ));
                    eprintln!(
                        "nucleus: {} denied — not allowed in compartment '{comp_name}'",
                        input.tool_name
                    );
                    println!("{}", serde_json::to_string(&out).unwrap());
                    std::process::exit(2);
                }
            }
        }
    }

    // SECURITY (#485): Check if tool has been flagged for manifest violations.
    // Trust revocation is checked early — before kernel.decide() — because a
    // tool that lied about its manifest should not be re-evaluated against the
    // capability lattice (it already proved it cannot be trusted).
    if let SessionLoad::Loaded(ref session) | SessionLoad::Fresh(ref session) =
        load_session(&input.session_id)
    {
        if let Some(&count) = session.flagged_tools.get(&input.tool_name) {
            if count >= MANIFEST_VIOLATION_REVOKE_THRESHOLD {
                let out = HookOutput::deny(format!(
                    "Blocked: tool '{}' has been revoked for this session — \
                     {} manifest violation(s) detected in prior outputs. \
                     A tool that lies about its manifest cannot be trusted.\n  \
                     How to fix:\n  \
                     - Start a new session to reset trust\n  \
                     - Or update the tool's manifest to match its actual behavior",
                    input.tool_name, count
                ));
                eprintln!(
                    "nucleus: {} DENIED — trust revoked ({} manifest violations, threshold {})",
                    input.tool_name, count, MANIFEST_VIOLATION_REVOKE_THRESHOLD
                );
                println!("{}", serde_json::to_string(&out).unwrap());
                std::process::exit(2);
            }
        }
    }

    let subject = extract_subject(&input.tool_name, &input.tool_input);
    let profile_name = default_profile_name();
    let perms = resolve_profile(&profile_name).unwrap_or_else(|| {
        eprintln!("nucleus: unknown profile '{profile_name}', using safe_pr_fixer");
        PermissionLattice::safe_pr_fixer()
    });

    // Load session state — detect tamper (social engineering state deletion)
    let (mut session, is_first_invocation) = match load_session(&input.session_id) {
        SessionLoad::Fresh(s) => (s, true),
        SessionLoad::Loaded(s) => (s, false),
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

    // DX (#549): Welcome banner on first invocation
    if is_first_invocation {
        eprintln!("nucleus: \u{2713} Active (profile: {profile_name})");
        eprintln!("nucleus: Info: 'nucleus-claude-hook --help' for options");
    }

    // Generate compartment token on first session invocation
    if session.compartment_token.is_empty() {
        session.compartment_token = generate_compartment_token();
    }

    // Apply compartment ceiling. Checks side-channel file first, then env var.
    // Detects transitions and logs them to stderr + receipt chain.
    let compartment = resolve_compartment(&input.session_id, &session.compartment_token);
    let prev_compartment = session
        .active_compartment
        .as_deref()
        .and_then(portcullis_core::compartment::Compartment::from_str_opt);

    // Detect compartment transition
    if compartment != prev_compartment {
        if let Some(ref new_comp) = compartment {
            let is_escalation = matches!(prev_compartment, Some(prev) if *new_comp > prev);
            let direction = if is_escalation {
                "ESCALATION"
            } else if prev_compartment.is_some() {
                "de-escalation"
            } else {
                "activated"
            };

            // SECURITY (#507): Breakglass requires a reason string.
            // Format: "breakglass:emergency fix for production outage"
            if new_comp.is_breakglass() {
                // Read the raw compartment file content to extract the reason
                let reason = if !session.compartment_token.is_empty() {
                    let keyed_name =
                        keyed_compartment_name(&input.session_id, &session.compartment_token);
                    let compartment_file = session_dir().join(format!("{keyed_name}.compartment"));
                    std::fs::read_to_string(&compartment_file)
                        .ok()
                        .and_then(|content| {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            portcullis_core::compartment::BreakglassEntry::parse(
                                content.trim(),
                                now,
                            )
                        })
                } else {
                    None
                };

                match reason {
                    Some(entry) => {
                        eprintln!(
                            "nucleus: BREAKGLASS entered — reason: '{}' (enhanced audit active)",
                            entry.reason
                        );
                    }
                    None => {
                        let msg = "Blocked: breakglass requires a reason. \
                                   Write 'breakglass:your reason here' to the compartment file.";
                        eprintln!("nucleus: {msg}");
                        let out = HookOutput::deny(msg);
                        println!("{}", serde_json::to_string(&out).unwrap());
                        session.high_water_mark += 1;
                        save_session(&input.session_id, &session);
                        std::process::exit(2);
                    }
                }
            }

            // SECURITY (#457): Upward transitions (escalation) require human approval.
            if is_escalation {
                let msg = format!(
                    "nucleus: compartment escalation {} -> {} requires human approval",
                    prev_compartment.map(|c| c.to_string()).unwrap_or_default(),
                    new_comp,
                );
                eprintln!("{msg}");
                let out = HookOutput::ask(&msg);
                println!("{}", serde_json::to_string(&out).unwrap());
                // FIX #483: Do NOT save the escalated compartment before approval.
                // If user denies, the next invocation should still see the old
                // compartment. Only increment HWM (to prevent tampering).
                session.high_water_mark += 1;
                save_session(&input.session_id, &session);
                return;
            }

            let from_str = prev_compartment
                .map(|c| c.to_string())
                .unwrap_or_else(|| "none".to_string());
            eprintln!(
                "nucleus: compartment transition: {from_str} -> {} ({direction})",
                new_comp,
            );

            // Record transition in receipt chain (#460)
            persist_transition_receipt(
                &input.session_id,
                prev_compartment.map(|c| {
                    // Need a string that lives long enough
                    match c {
                        portcullis_core::compartment::Compartment::Research => "research",
                        portcullis_core::compartment::Compartment::Draft => "draft",
                        portcullis_core::compartment::Compartment::Execute => "execute",
                        portcullis_core::compartment::Compartment::Breakglass => "breakglass",
                    }
                }),
                &new_comp.to_string(),
                direction,
            );

            // COMPARTMENT FLOW RESET: On transition, clear flow observations
            // so the new compartment starts with a clean flow graph.
            //
            // This is the key insight: research mode can read web content,
            // but when you switch to draft mode, the web taint doesn't carry
            // over — draft blocks web entirely, so the new compartment's
            // flow graph has no adversarial nodes. You can write freely.
            //
            // The exposure accumulator (allowed_ops) is NOT cleared — it
            // tracks what happened across the entire session for audit.
            // Only the flow graph observations are reset.
            if prev_compartment.is_some() {
                eprintln!(
                    "nucleus: flow graph reset for compartment transition ({} observations cleared)",
                    session.flow_observations.len()
                );
                session.flow_observations.clear();
            }
        }
        session.active_compartment = compartment.map(|c| c.to_string());
    }

    let effective_perms = if let Some(ref comp) = compartment {
        let core_ceiling = comp.ceiling();
        let ceiling = portcullis::CapabilityLattice {
            read_files: core_ceiling.read_files,
            write_files: core_ceiling.write_files,
            edit_files: core_ceiling.edit_files,
            run_bash: core_ceiling.run_bash,
            glob_search: core_ceiling.glob_search,
            grep_search: core_ceiling.grep_search,
            web_search: core_ceiling.web_search,
            web_fetch: core_ceiling.web_fetch,
            git_commit: core_ceiling.git_commit,
            git_push: core_ceiling.git_push,
            create_pr: core_ceiling.create_pr,
            manage_pods: core_ceiling.manage_pods,
            spawn_agent: core_ceiling.spawn_agent,
            ..Default::default()
        };
        let mut narrowed = perms.clone();
        narrowed.capabilities = narrowed.capabilities.meet(&ceiling);
        narrowed
    } else {
        perms
    };

    // Apply organizational autonomy ceiling (#482).
    // NUCLEUS_AUTONOMY_CEILING controls the org-wide cap:
    //   "production" — no git push/PR, writes at LowRisk
    //   "sandbox"    — read-only, no execution
    //   (unset)      — unrestricted (no organizational cap)
    let effective_perms = match std::env::var("NUCLEUS_AUTONOMY_CEILING").ok().as_deref() {
        Some("production") | Some("sandbox") => {
            let core_ceiling =
                if std::env::var("NUCLEUS_AUTONOMY_CEILING").as_deref() == Ok("sandbox") {
                    let c = portcullis_core::autonomy::AutonomyCeiling::sandbox();
                    eprintln!("nucleus: autonomy ceiling: sandbox (read-only)");
                    c.capabilities
                } else {
                    let c = portcullis_core::autonomy::AutonomyCeiling::production();
                    eprintln!("nucleus: autonomy ceiling: production (no push/PR)");
                    c.capabilities
                };
            // Convert portcullis_core::CapabilityLattice to portcullis::CapabilityLattice
            let ceiling = portcullis::CapabilityLattice {
                read_files: core_ceiling.read_files,
                write_files: core_ceiling.write_files,
                edit_files: core_ceiling.edit_files,
                run_bash: core_ceiling.run_bash,
                glob_search: core_ceiling.glob_search,
                grep_search: core_ceiling.grep_search,
                web_search: core_ceiling.web_search,
                web_fetch: core_ceiling.web_fetch,
                git_commit: core_ceiling.git_commit,
                git_push: core_ceiling.git_push,
                create_pr: core_ceiling.create_pr,
                manage_pods: core_ceiling.manage_pods,
                spawn_agent: core_ceiling.spawn_agent,
                ..Default::default()
            };
            let mut capped = effective_perms;
            capped.capabilities = capped.capabilities.meet(&ceiling);
            capped
        }
        _ => effective_perms,
    };

    let mut kernel = Kernel::new(effective_perms);
    kernel.enable_flow_graph();

    // PHASE 4: Import parent agent's flow label and chain reference.
    // When a parent agent spawns this session, it sets:
    //   NUCLEUS_PARENT_LABEL  — encoded IFC label (taint propagation)
    //   NUCLEUS_PARENT_SESSION — parent's session ID (receipt chain link)
    //   NUCLEUS_PARENT_CHAIN_HASH — parent's chain head hash at spawn time
    if session.allowed_ops.is_empty() {
        // Only on first invocation — don't re-import on replay
        if let Ok(parent_label_str) = std::env::var("NUCLEUS_PARENT_LABEL") {
            if let Some(parent_label) = portcullis_core::wire::decode_label(&parent_label_str) {
                let kind = if parent_label.integrity == portcullis_core::IntegLevel::Adversarial {
                    NodeKind::WebContent
                } else {
                    NodeKind::ToolResponse
                };
                if let Ok(id) = kernel.observe(kind, &[]) {
                    eprintln!(
                        "nucleus: inherited parent label: integ={:?} auth={:?} (flow_node: {id})",
                        parent_label.integrity, parent_label.authority,
                    );
                    session.flow_observations.push((
                        node_kind_to_u8(kind),
                        "parent_agent".to_string(),
                        portcullis_core::wire::encode_label(&parent_label),
                    ));
                }
            }
        }
        // Record parent chain reference for cross-agent receipt linking
        if let Ok(parent_sid) = std::env::var("NUCLEUS_PARENT_SESSION") {
            session.parent_session_id = Some(parent_sid.clone());
            if let Ok(parent_hash) = std::env::var("NUCLEUS_PARENT_CHAIN_HASH") {
                session.parent_chain_hash = Some(parent_hash.clone());
                eprintln!(
                    "nucleus: linked to parent chain: session={parent_sid} hash={}...",
                    &parent_hash[..16.min(parent_hash.len())]
                );
            }
        }

        // Inherit parent compartment (#461).
        // The child's compartment is capped at the parent's level:
        // child ≤ parent (can only narrow, never escalate).
        if let Ok(parent_sid) = std::env::var("NUCLEUS_PARENT_SESSION") {
            let safe_parent = sanitize_session_id(&parent_sid);
            let comp_path = session_dir().join(format!("{safe_parent}.parent-compartment"));
            if let Ok(parent_comp_str) = std::fs::read_to_string(&comp_path) {
                if let Some(parent_comp) =
                    portcullis_core::compartment::Compartment::from_str_opt(parent_comp_str.trim())
                {
                    // If child has no compartment, inherit parent's.
                    // If child has a compartment, cap it at parent's level.
                    match &compartment {
                        None => {
                            eprintln!("nucleus: inherited parent compartment: {parent_comp}");
                            // Write compartment file so resolve_compartment picks it up
                            if !session.compartment_token.is_empty() {
                                let keyed = keyed_compartment_name(
                                    &input.session_id,
                                    &session.compartment_token,
                                );
                                let file = session_dir().join(format!("{keyed}.compartment"));
                                std::fs::write(&file, parent_comp.to_string()).ok();
                            }
                            session.active_compartment = Some(parent_comp.to_string());
                        }
                        Some(child_comp) if *child_comp > parent_comp => {
                            eprintln!(
                                "nucleus: child compartment {} exceeds parent {} — capping to parent",
                                child_comp, parent_comp
                            );
                            if !session.compartment_token.is_empty() {
                                let keyed = keyed_compartment_name(
                                    &input.session_id,
                                    &session.compartment_token,
                                );
                                let file = session_dir().join(format!("{keyed}.compartment"));
                                std::fs::write(&file, parent_comp.to_string()).ok();
                            }
                            session.active_compartment = Some(parent_comp.to_string());
                        }
                        _ => {
                            // Child is at or below parent level — OK
                        }
                    }
                }
            }
        }
    }

    // Replay previous operations to rebuild exposure state AND flow graph.
    // Each allowed op is: 1) replayed in the flat kernel for exposure,
    // 2) observed in the flow graph as a DAG node with category-based parents.
    //
    // PHASE 1 UPGRADE: Instead of a linear chain (where every node depends
    // on the previous one, causing total session taint after any web fetch),
    // we use a LeafTracker that maintains leaf nodes by source category.
    // This means file reads and web fetches are independent branches —
    // a write only inherits adversarial taint if web content actually exists
    // in the session. If you never fetch a URL, writes remain untainted.
    let mut leaves = LeafTracker::default();
    for (op_str, subj) in &session.allowed_ops {
        if let Ok(op) = Operation::try_from(op_str.as_str()) {
            kernel.decide(op, subj);
        }
    }
    for &(kind_u8, ref _op_str, ref _subj) in &session.flow_observations {
        let kind = u8_to_node_kind(kind_u8);
        let parents = leaves.parents_for(kind);
        if let Ok(id) = kernel.observe(kind, &parents) {
            leaves.record(kind, id);
        }
    }

    // Make the actual decision using the causal DAG.
    // The current operation's parents come from the leaf tracker —
    // actions depend on all source categories, sources are independent.
    let obs_kind = operation_to_node_kind(operation);
    let parents = leaves.parents_for(obs_kind);
    let (decision, _token) = kernel.decide_with_parents(operation, &subject, &parents);
    let exposure_count = decision.exposure_transition.post_count;

    // Get or create the session's signing key.
    // Ephemeral per session — generated once, persisted in session state.
    // If key generation fails (low entropy, sandboxed env), proceed without
    // signing rather than panicking the security gate (#481).
    let signing_key: Option<Ed25519KeyPair> = if session.signing_key_pkcs8.is_empty() {
        let rng = SystemRandom::new();
        match Ed25519KeyPair::generate_pkcs8(&rng) {
            Ok(pkcs8) => {
                session.signing_key_pkcs8 = pkcs8.as_ref().to_vec();
                Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).ok()
            }
            Err(e) => {
                eprintln!("nucleus: WARNING — Ed25519 key generation failed: {e}. Receipts will be unsigned.");
                None
            }
        }
    } else {
        match Ed25519KeyPair::from_pkcs8(&session.signing_key_pkcs8) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("nucleus: WARNING — stored signing key corrupted: {e}. Receipts will be unsigned.");
                session.signing_key_pkcs8.clear(); // Don't reuse corrupted key
                None
            }
        }
    };

    // Build a receipt from the flow graph's action node (if available).
    // The receipt captures the causal chain and verdict.
    let flow_receipt = decision.flow_node_id.and_then(|node_id| {
        kernel.flow_graph().and_then(|graph| {
            let action_node = graph.get(node_id)?;
            let ancestor_refs: Vec<&_> = parents.iter().filter_map(|&pid| graph.get(pid)).collect();
            let flow_verdict = if decision.verdict.is_denied() {
                portcullis_core::flow::FlowVerdict::Deny(
                    portcullis_core::flow::FlowDenyReason::AuthorityEscalation,
                )
            } else {
                portcullis_core::flow::FlowVerdict::Allow
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut receipt = build_receipt(action_node, &ancestor_refs, flow_verdict, now);
            receipt.set_prev_hash(session.chain_head_hash);
            // Bind receipt to this session (#492)
            let chain_id = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b"nucleus-chain:");
                h.update(input.session_id.as_bytes());
                let hash = h.finalize();
                let mut id = [0u8; 32];
                id.copy_from_slice(&hash);
                id
            };
            receipt.set_chain_id(chain_id);
            if let Some(ref key) = signing_key {
                sign_receipt(&mut receipt, key);
            }
            Some(receipt)
        })
    });

    // Update chain head hash and persist receipt if produced.
    if let Some(ref receipt) = flow_receipt {
        session.chain_head_hash = receipt_hash(receipt);
        persist_receipt(
            &input.session_id,
            receipt,
            operation,
            &subject,
            &session.parent_session_id,
            &session.parent_chain_hash,
            compartment.as_ref().map(|c| c.to_string()).as_deref(),
        );
    }

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
            // Record the observation index so PostToolUse can insert the
            // ToolResponse as a sibling of this pre-tool observation (#593).
            session.last_pre_tool_obs_index = Some(session.flow_observations.len() - 1);

            // DX (#567): When web content taints the session, print recovery path
            if matches!(operation, Operation::WebFetch | Operation::WebSearch) {
                eprintln!(
                    "nucleus: \u{26a0} Session tainted by web content — writes will be blocked."
                );
                if compartment.is_some() {
                    eprintln!(
                        "nucleus: Tip: switch to 'draft' compartment to write (flow graph resets on transition)"
                    );
                } else {
                    eprintln!(
                        "nucleus: Tip: set NUCLEUS_COMPARTMENT=draft or restart to clear taint"
                    );
                }
            }

            // PHASE 4: When SpawnAgent is allowed, export the current flow
            // label AND chain reference so the child inherits taint and
            // its receipt chain links back to the parent's.
            if operation == Operation::SpawnAgent {
                let safe_id = sanitize_session_id(&input.session_id);
                if let Some(graph) = kernel.flow_graph() {
                    if let Some(node_id) = decision.flow_node_id {
                        if let Some(node) = graph.get(node_id) {
                            let label_str = portcullis_core::wire::encode_label(&node.label);
                            let label_path = session_dir().join(format!("{safe_id}.parent-label"));
                            std::fs::write(&label_path, &label_str).ok();
                            eprintln!(
                                "nucleus: exported parent label for child agent: {label_str}"
                            );
                        }
                    }
                }
                // Export chain reference so child can link back
                let chain_hash_hex = hex::encode(session.chain_head_hash);
                let chain_path = session_dir().join(format!("{safe_id}.parent-chain"));
                let chain_ref = format!("session={}\nhash={}\n", &input.session_id, chain_hash_hex);
                std::fs::write(&chain_path, &chain_ref).ok();

                // Export parent compartment so child inherits ceiling (#461).
                // Child compartment ≤ parent compartment (can only narrow).
                if let Some(ref comp) = compartment {
                    let comp_path = session_dir().join(format!("{safe_id}.parent-compartment"));
                    std::fs::write(&comp_path, comp.to_string()).ok();
                    eprintln!(
                        "nucleus: exported parent compartment '{}' for child agent",
                        comp
                    );
                }
            }

            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            // Inject compartment context into Claude's prompt (#459)
            HookOutput::allow_with_context(compartment.as_ref().map(|c| c.to_string()).as_deref())
        }
        Verdict::RequiresApproval => {
            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            HookOutput::ask(format!(
                "nucleus: exposure {exposure_count}/3 — requires human approval"
            ))
        }
        Verdict::Deny(ref reason) => {
            // Do NOT persist op: operation was blocked.
            // Still increment HWM — denied ops prove the session existed.
            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            HookOutput::deny(format_denial_for_user(
                reason,
                operation,
                compartment.as_ref().map(|c| c.to_string()).as_deref(),
            ))
        }
    };

    // Log to stderr
    let verdict_str = output.permission_decision();
    let flow_node = decision
        .flow_node_id
        .map(|id| format!(", flow_node: {id}"))
        .unwrap_or_default();
    let _receipt_status = if flow_receipt
        .as_ref()
        .map(|r| r.is_signed())
        .unwrap_or(false)
    {
        ", receipt: signed"
    } else {
        ""
    };
    // DX (#545): Show latency + clean verdict
    let elapsed_ms = start_time.elapsed().as_millis();
    let timing = if elapsed_ms > 100 {
        format!(" \x1b[33m({elapsed_ms}ms)\x1b[0m") // yellow if slow
    } else {
        format!(" ({elapsed_ms}ms)")
    };
    if verdict_str == "allow" {
        let short_subject = if subject.len() > 40 {
            format!("{}...", &subject[..37])
        } else {
            subject.clone()
        };
        eprintln!("nucleus: \u{2713} {operation} {short_subject}{timing}");
    } else {
        eprintln!(
            "nucleus: \u{2717} {operation} {subject} -> {verdict_str} [exposure: {exposure_count}/3{flow_node}]{timing}"
        );
    }

    // Write output to stdout
    let json = match serde_json::to_string(&output) {
        Ok(j) => j,
        Err(e) => {
            // Defense-in-depth: if serialization fails, output a deny to fail-closed (#481)
            eprintln!("nucleus: CRITICAL — failed to serialize output: {e}. Denying.");
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"internal error: serialization failed"}}"#.to_string()
        }
    };
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
        assert_eq!(map_tool("Agent"), Operation::SpawnAgent);
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

    // Session tamper detection, schema versioning, and save roundtrip tests
    // are in session.rs (extracted in #632).

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
        let out = HookOutput::allow_with_context(None);
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

    // -----------------------------------------------------------------------
    // DAG-backed flow tests (Phase 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_dag_file_read_after_web_fetch_not_tainted() {
        // KEY IMPROVEMENT: In the linear chain model, a file read AFTER a web
        // fetch inherits adversarial taint (because last_node_id points to the
        // web content). In the DAG model, file reads are independent branches
        // — they don't depend on web content.
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let mut leaves = LeafTracker::default();

        // 1. Read a file (trusted source)
        let file_id = kernel.observe(NodeKind::FileRead, &[]).unwrap();
        leaves.record(NodeKind::FileRead, file_id);

        // 2. Fetch web content (adversarial source — independent branch)
        let web_id = kernel
            .observe(
                NodeKind::WebContent,
                &leaves.parents_for(NodeKind::WebContent),
            )
            .unwrap();
        leaves.record(NodeKind::WebContent, web_id);

        // 3. Read another file — should NOT inherit web taint
        let file2_parents = leaves.parents_for(NodeKind::FileRead);
        // Parents should be [file_id], NOT [web_id]
        assert!(
            !file2_parents.contains(&web_id),
            "File read parents should not include web content node"
        );
        assert!(
            file2_parents.contains(&file_id),
            "File read parents should include prior file read"
        );

        let file2_id = kernel.observe(NodeKind::FileRead, &file2_parents).unwrap();
        leaves.record(NodeKind::FileRead, file2_id);

        // 4. Write depending only on file reads — should be ALLOWED
        //    (because the write's parents only include the trusted branch)
        let write_parents = leaves.parents_for(NodeKind::OutboundAction);
        let (d, _) = kernel.decide_with_parents(
            Operation::WriteFiles,
            "/workspace/clean.rs",
            &write_parents,
        );
        // This WILL be denied because OutboundAction parents include ALL
        // source categories (including adversarial). This is the conservative
        // choice — an action may have been influenced by any session data.
        // The improvement over linear chain: SOURCE nodes don't cross-contaminate.
        // Actions still inherit from all sources (conservative).
        assert!(
            d.verdict.is_denied(),
            "Write should still be denied when web content exists in session"
        );
    }

    #[test]
    fn test_dag_write_allowed_without_web_content() {
        // Without any web content in the session, writes should be allowed.
        // This was also true in the linear chain, but confirms the DAG
        // model doesn't break this fundamental property.
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let mut leaves = LeafTracker::default();

        // Read files only — no web content
        let f1 = kernel.observe(NodeKind::FileRead, &[]).unwrap();
        leaves.record(NodeKind::FileRead, f1);
        let f2 = kernel
            .observe(NodeKind::FileRead, &leaves.parents_for(NodeKind::FileRead))
            .unwrap();
        leaves.record(NodeKind::FileRead, f2);

        // Write — parents are only trusted leaves, no adversarial
        let write_parents = leaves.parents_for(NodeKind::OutboundAction);
        assert!(
            leaves.adversarial.is_empty(),
            "No adversarial content should exist"
        );

        let (d, _) = kernel.decide_with_parents(
            Operation::WriteFiles,
            "/workspace/clean.rs",
            &write_parents,
        );
        assert!(
            d.verdict.is_allowed(),
            "Write with only trusted parents should be allowed, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_leaf_tracker_categories() {
        let mut leaves = LeafTracker::default();

        // Record trusted source
        leaves.record(NodeKind::FileRead, 1);
        assert_eq!(leaves.trusted, vec![1]);
        assert!(leaves.adversarial.is_empty());

        // Record adversarial source (independent)
        leaves.record(NodeKind::WebContent, 2);
        assert_eq!(leaves.adversarial, vec![2]);
        assert_eq!(leaves.trusted, vec![1]); // unchanged

        // New trusted source replaces old leaf
        leaves.record(NodeKind::FileRead, 3);
        assert_eq!(leaves.trusted, vec![3]); // replaced

        // OutboundAction parents include both categories
        let action_parents = leaves.parents_for(NodeKind::OutboundAction);
        assert!(action_parents.contains(&3)); // trusted
        assert!(action_parents.contains(&2)); // adversarial

        // FileRead parents only include trusted
        let read_parents = leaves.parents_for(NodeKind::FileRead);
        assert!(read_parents.contains(&3)); // trusted
        assert!(!read_parents.contains(&2)); // NOT adversarial
    }

    // -----------------------------------------------------------------------
    // --setup format validation (#519)
    // -----------------------------------------------------------------------

    #[test]
    fn test_setup_produces_valid_hooks_format() {
        // Simulate what run_setup() generates (without writing to disk)
        let binary = "/usr/local/bin/nucleus-claude-hook";
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "",
                        "hooks": [
                            {
                                "type": "command",
                                "command": binary
                            }
                        ]
                    }
                ]
            }
        });

        // Validate structure matches Claude Code's expected schema
        let hooks = settings.get("hooks").expect("hooks key missing");
        let pre_tool = hooks.get("PreToolUse").expect("PreToolUse key missing");
        let arr = pre_tool.as_array().expect("PreToolUse should be array");
        assert!(!arr.is_empty(), "PreToolUse array should not be empty");

        let entry = &arr[0];
        assert!(entry.get("matcher").is_some(), "entry needs matcher field");
        assert_eq!(
            entry.get("matcher").unwrap().as_str().unwrap(),
            "",
            "matcher should be empty string to match all tools"
        );

        let hooks_arr = entry
            .get("hooks")
            .expect("hooks array missing")
            .as_array()
            .expect("hooks should be array");
        assert!(!hooks_arr.is_empty());

        let hook = &hooks_arr[0];
        assert_eq!(
            hook.get("type").unwrap().as_str().unwrap(),
            "command",
            "hook type must be 'command'"
        );
        assert!(hook.get("command").is_some(), "hook needs command field");
    }

    #[test]
    fn test_setup_preserves_existing_settings() {
        // If settings.json already has other fields, setup should preserve them
        let mut settings = serde_json::json!({
            "effortLevel": "high",
            "enabledPlugins": {"rust-analyzer": true}
        });

        // Simulate adding hooks (what run_setup does)
        let hooks = settings
            .as_object_mut()
            .unwrap()
            .entry("hooks")
            .or_insert_with(|| serde_json::json!({}));
        let hooks_obj = hooks.as_object_mut().unwrap();
        hooks_obj.insert(
            "PreToolUse".to_string(),
            serde_json::json!([{
                "matcher": "",
                "hooks": [{"type": "command", "command": "nucleus-claude-hook"}]
            }]),
        );

        // Verify existing fields preserved
        assert_eq!(
            settings.get("effortLevel").unwrap().as_str().unwrap(),
            "high"
        );
        assert!(settings.get("enabledPlugins").is_some());
        assert!(settings.get("hooks").is_some());
    }

    // ─────────────────────────────────────────────────────────────────────
    // PostToolUse flow graph insertion tests (#593)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_tool_output_web() {
        // Web tool outputs produce WebContent (adversarial taint)
        assert_eq!(
            classify_tool_output(Operation::WebFetch),
            NodeKind::WebContent
        );
        assert_eq!(
            classify_tool_output(Operation::WebSearch),
            NodeKind::WebContent
        );
    }

    #[test]
    fn test_classify_tool_output_file_read() {
        // File read outputs produce FileRead (trusted)
        assert_eq!(
            classify_tool_output(Operation::ReadFiles),
            NodeKind::FileRead
        );
        assert_eq!(
            classify_tool_output(Operation::GlobSearch),
            NodeKind::FileRead
        );
        assert_eq!(
            classify_tool_output(Operation::GrepSearch),
            NodeKind::FileRead
        );
    }

    #[test]
    fn test_classify_tool_output_generic() {
        // Other tool outputs produce ToolResponse (model category)
        assert_eq!(
            classify_tool_output(Operation::WriteFiles),
            NodeKind::ToolResponse
        );
        assert_eq!(
            classify_tool_output(Operation::RunBash),
            NodeKind::ToolResponse
        );
        assert_eq!(
            classify_tool_output(Operation::GitPush),
            NodeKind::ToolResponse
        );
    }

    #[test]
    fn test_truncate_subject_short() {
        assert_eq!(truncate_subject("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_subject_long() {
        let long = "a".repeat(300);
        let truncated = truncate_subject(&long, 100);
        assert!(truncated.len() <= 103); // 100 chars + "..."
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_truncate_subject_unicode() {
        // Ensure truncation doesn't split multi-byte characters
        let s = "a\u{1F600}b\u{1F600}c"; // mixed ASCII + 4-byte emoji
        let truncated = truncate_subject(s, 5);
        // Should truncate at a valid UTF-8 boundary
        assert!(truncated.ends_with("..."));
        // The result should be valid UTF-8
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    // test_post_tool_observation_roundtrip moved to session.rs (#632).

    #[test]
    fn test_flow_graph_with_post_tool_observations() {
        // Verify that PostToolUse observations are correctly replayed
        // into the flow graph during session replay, creating proper
        // causal links so taint propagates through tool outputs.
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let mut leaves = LeafTracker::default();

        // Simulate replay of a web fetch observation (PreToolUse)
        let web_parents = leaves.parents_for(NodeKind::WebContent);
        let web_id = kernel.observe(NodeKind::WebContent, &web_parents).unwrap();
        leaves.record(NodeKind::WebContent, web_id);

        // Simulate replay of the WebContent post-tool observation (PostToolUse)
        // This should go into the adversarial category, maintaining taint
        let post_parents = leaves.parents_for(NodeKind::WebContent);
        let post_id = kernel.observe(NodeKind::WebContent, &post_parents).unwrap();
        leaves.record(NodeKind::WebContent, post_id);

        // Now try a write action — it should inherit the web content taint
        let write_parents = leaves.parents_for(NodeKind::OutboundAction);
        // The write's parents should include the adversarial leaf
        assert!(
            write_parents.contains(&post_id),
            "Write action should depend on post-tool WebContent observation"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Actionable denial message tests (#544)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_denial_messages_include_how_to_fix() {
        use portcullis::kernel::DenyReason;

        // Capability denial
        let msg = format_denial_for_user(
            &DenyReason::InsufficientCapability,
            Operation::RunBash,
            Some("draft"),
        );
        assert!(msg.contains("How to fix"), "capability denial: {msg}");
        assert!(
            msg.contains("execute"),
            "should suggest execute compartment"
        );

        // Flow violation (web taint)
        let msg = format_denial_for_user(
            &DenyReason::FlowViolation {
                rule: "AuthorityEscalation".to_string(),
                receipt: None,
            },
            Operation::WriteFiles,
            Some("research"),
        );
        assert!(msg.contains("How to fix"), "flow violation: {msg}");
        assert!(msg.contains("draft"), "should suggest draft compartment");

        // Budget exhausted
        let msg = format_denial_for_user(
            &DenyReason::BudgetExhausted {
                remaining_usd: "0.00".to_string(),
            },
            Operation::ReadFiles,
            None,
        );
        assert!(msg.contains("How to fix"), "budget: {msg}");
        assert!(msg.contains("max_cost_usd"), "should mention config key");

        // Path blocked
        let msg = format_denial_for_user(
            &DenyReason::PathBlocked {
                path: "/etc/shadow".to_string(),
            },
            Operation::ReadFiles,
            None,
        );
        assert!(msg.contains("How to fix"), "path blocked: {msg}");
        assert!(msg.contains("policy.toml"), "should mention config file");
    }

    // Session GC tests, flagged_tools tests, and violation_count tests
    // are in session.rs (extracted in #632).
}
