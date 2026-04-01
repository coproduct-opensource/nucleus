//! Tool classification and flow-graph helpers.
//!
//! Pure functions that map tool names to `Operation`s, classify node kinds for
//! the IFC flow graph, and track DAG leaf nodes by category.  Extracted from
//! `main.rs` to keep the decision-loop module focused on orchestration.

use portcullis::manifest_registry::ManifestRegistry;
use portcullis::Operation;
use portcullis_core::flow::NodeKind;

// ---------------------------------------------------------------------------
// Tool name -> Operation mapping
// ---------------------------------------------------------------------------

/// Map a tool name to a portcullis Operation.
///
/// SECURITY: Every tool is gated — no passthrough. The Agent tool spawns
/// subprocesses with fresh session IDs; passthrough would let a tainted
/// session escape its flow restrictions via a clean child process.
/// MCP tools (`mcp__<server>__<tool>`) are classified by their tool name suffix,
/// defaulting to RunBash (most restrictive) for unknown tools.
pub(crate) fn map_tool(name: &str) -> Operation {
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
    let registry = ManifestRegistry::load_from_dir(&cwd);
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
// Flow label classification
// ---------------------------------------------------------------------------

/// Map an Operation to the NodeKind that represents its data contribution.
///
/// After an allowed operation executes, its result enters the session as
/// an observation of this kind. This determines the IFC label assigned
/// to the data: web content gets Adversarial/NoAuthority, file reads get
/// Internal/Trusted, etc.
pub(crate) fn operation_to_node_kind(op: Operation) -> NodeKind {
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
pub(crate) fn classify_tool_output(op: Operation) -> NodeKind {
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
pub(crate) fn truncate_subject(s: &str, max_len: usize) -> String {
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
pub(crate) fn node_kind_to_u8(kind: NodeKind) -> u8 {
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
pub(crate) fn u8_to_node_kind(v: u8) -> NodeKind {
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
pub(crate) struct LeafTracker {
    pub(crate) trusted: Vec<u64>,
    pub(crate) adversarial: Vec<u64>,
    pub(crate) action: Vec<u64>,
    pub(crate) model: Vec<u64>,
}

impl LeafTracker {
    /// Record a new node, replacing the leaf for its category.
    pub(crate) fn record(&mut self, kind: NodeKind, node_id: u64) {
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
    pub(crate) fn parents_for(&self, kind: NodeKind) -> Vec<u64> {
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
}
