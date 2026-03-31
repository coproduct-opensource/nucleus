//! Verified hook adapter — pure decision pipeline for Claude Code hooks.
//!
//! This module extracts the security-critical decision logic from the
//! nucleus-claude-hook binary into pure functions that can be:
//! 1. Unit tested in isolation
//! 2. Targeted by Kani bounded model checking
//! 3. Eventually translated to Lean 4 via Aeneas
//!
//! The hook binary becomes a thin I/O wrapper: read JSON from stdin,
//! call these pure functions, write JSON to stdout.
//!
//! ## Decision pipeline
//!
//! ```text
//! tool_name → classify_tool() → Operation
//!                                    ↓
//!         operation + subject → node_kind_for_operation() → NodeKind
//!                                    ↓
//!         node_kind + parents → decide() → HookDecision
//! ```

use portcullis_core::flow::NodeKind;
use portcullis_core::Operation;

/// Classify a Claude Code tool name to a portcullis Operation.
///
/// This is the first step in the decision pipeline. Every tool
/// is mapped to an Operation — no passthrough.
///
/// SECURITY: Unknown tools map to RunBash (most restrictive).
pub fn classify_tool(name: &str) -> Operation {
    match name {
        "Bash" => Operation::RunBash,
        "Read" => Operation::ReadFiles,
        "Write" => Operation::WriteFiles,
        "Edit" => Operation::EditFiles,
        "Glob" => Operation::GlobSearch,
        "Grep" => Operation::GrepSearch,
        "WebFetch" => Operation::WebFetch,
        "WebSearch" => Operation::WebSearch,
        "Agent" => Operation::SpawnAgent,
        _ if name.starts_with("mcp__") => classify_mcp_tool(name),
        _ => Operation::RunBash, // fail-closed
    }
}

/// Classify an MCP tool by its name suffix.
///
/// MCP tool names follow `mcp__<server>__<tool>`. We extract the tool
/// portion and classify by known patterns.
pub fn classify_mcp_tool(name: &str) -> Operation {
    let tool = name
        .strip_prefix("mcp__")
        .and_then(|rest| rest.split("__").nth(1))
        .unwrap_or(name);

    match tool {
        t if t.contains("pull_request") || t.contains("pr_create") => Operation::CreatePr,
        t if t.contains("push") || t.contains("commit") || t.contains("merge") => {
            Operation::GitPush
        }
        t if t.contains("run")
            || t.contains("exec")
            || t.contains("shell")
            || t.contains("command")
            || t.contains("bash")
            || t.contains("terminal") =>
        {
            Operation::RunBash
        }
        t if t.contains("fetch")
            || t.contains("download")
            || t.contains("http")
            || t.contains("url")
            || t.contains("browse") =>
        {
            Operation::WebFetch
        }
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
        t if t.contains("grep") || t.contains("find") || t.contains("glob") => {
            Operation::GlobSearch
        }
        _ => Operation::RunBash, // fail-closed
    }
}

/// Map an Operation to the NodeKind for flow graph observation.
///
/// After an allowed operation executes, its result enters the session
/// as a data node of this kind. This determines the IFC label.
pub fn node_kind_for_operation(op: Operation) -> NodeKind {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => NodeKind::FileRead,
        Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::RunBash
        | Operation::GitCommit
        | Operation::GitPush
        | Operation::CreatePr
        | Operation::ManagePods
        | Operation::SpawnAgent => NodeKind::OutboundAction,
    }
}

/// Source category for the DAG leaf tracker.
///
/// Determines which branch of the causal DAG a node belongs to.
/// Sources are independent; actions depend on all source branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCategory {
    /// Trusted local data (FileRead, UserPrompt, EnvVar, MemoryRead)
    Trusted,
    /// Adversarial external data (WebContent)
    Adversarial,
    /// Side effects (OutboundAction, MemoryWrite)
    Action,
    /// Model-generated content (ModelPlan, ToolResponse, etc.)
    Model,
}

/// Classify a NodeKind into its source category.
pub fn source_category(kind: NodeKind) -> SourceCategory {
    match kind {
        NodeKind::FileRead | NodeKind::UserPrompt | NodeKind::EnvVar | NodeKind::MemoryRead => {
            SourceCategory::Trusted
        }
        NodeKind::WebContent => SourceCategory::Adversarial,
        NodeKind::OutboundAction | NodeKind::MemoryWrite => SourceCategory::Action,
        NodeKind::ModelPlan
        | NodeKind::ToolResponse
        | NodeKind::Secret
        | NodeKind::Summarization
        | NodeKind::Retry => SourceCategory::Model,
    }
}

/// Determine whether an action's parents should include a given category.
///
/// Actions depend on ALL sources (conservative). Sources only depend on
/// their own category (independent branches).
pub fn should_include_parent(action_kind: NodeKind, parent_category: SourceCategory) -> bool {
    match source_category(action_kind) {
        // Sources only depend on their own category
        SourceCategory::Trusted => parent_category == SourceCategory::Trusted,
        SourceCategory::Adversarial => parent_category == SourceCategory::Adversarial,
        // Actions and model outputs depend on everything
        SourceCategory::Action | SourceCategory::Model => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_standard_tools() {
        assert_eq!(classify_tool("Bash"), Operation::RunBash);
        assert_eq!(classify_tool("Read"), Operation::ReadFiles);
        assert_eq!(classify_tool("Write"), Operation::WriteFiles);
        assert_eq!(classify_tool("Edit"), Operation::EditFiles);
        assert_eq!(classify_tool("WebFetch"), Operation::WebFetch);
        assert_eq!(classify_tool("Agent"), Operation::SpawnAgent);
    }

    #[test]
    fn classify_unknown_tools_fail_closed() {
        assert_eq!(classify_tool("UnknownTool"), Operation::RunBash);
    }

    #[test]
    fn classify_mcp_tools() {
        assert_eq!(classify_tool("mcp__fs__read_file"), Operation::ReadFiles);
        assert_eq!(classify_tool("mcp__fs__write_file"), Operation::WriteFiles);
        assert_eq!(classify_tool("mcp__shell__run_command"), Operation::RunBash);
        assert_eq!(classify_tool("mcp__http__fetch_url"), Operation::WebFetch);
        assert_eq!(classify_tool("mcp__evil__pwn"), Operation::RunBash);
    }

    #[test]
    fn node_kind_mapping() {
        assert_eq!(
            node_kind_for_operation(Operation::ReadFiles),
            NodeKind::FileRead
        );
        assert_eq!(
            node_kind_for_operation(Operation::WebFetch),
            NodeKind::WebContent
        );
        assert_eq!(
            node_kind_for_operation(Operation::WriteFiles),
            NodeKind::OutboundAction
        );
        assert_eq!(
            node_kind_for_operation(Operation::SpawnAgent),
            NodeKind::OutboundAction
        );
    }

    #[test]
    fn source_categories() {
        assert_eq!(source_category(NodeKind::FileRead), SourceCategory::Trusted);
        assert_eq!(
            source_category(NodeKind::WebContent),
            SourceCategory::Adversarial
        );
        assert_eq!(
            source_category(NodeKind::OutboundAction),
            SourceCategory::Action
        );
        assert_eq!(source_category(NodeKind::ModelPlan), SourceCategory::Model);
    }

    #[test]
    fn parent_inclusion_rules() {
        // File reads don't include adversarial parents
        assert!(should_include_parent(
            NodeKind::FileRead,
            SourceCategory::Trusted
        ));
        assert!(!should_include_parent(
            NodeKind::FileRead,
            SourceCategory::Adversarial
        ));

        // Actions include all categories
        assert!(should_include_parent(
            NodeKind::OutboundAction,
            SourceCategory::Trusted
        ));
        assert!(should_include_parent(
            NodeKind::OutboundAction,
            SourceCategory::Adversarial
        ));
        assert!(should_include_parent(
            NodeKind::OutboundAction,
            SourceCategory::Model
        ));
    }

    #[test]
    fn all_operations_have_node_kinds() {
        // Every operation maps to a valid NodeKind — no panics
        for op in Operation::ALL {
            let _ = node_kind_for_operation(op);
        }
    }

    #[test]
    fn all_node_kinds_have_categories() {
        // Every NodeKind maps to a category — no panics
        let kinds = [
            NodeKind::UserPrompt,
            NodeKind::ToolResponse,
            NodeKind::WebContent,
            NodeKind::MemoryRead,
            NodeKind::MemoryWrite,
            NodeKind::FileRead,
            NodeKind::EnvVar,
            NodeKind::ModelPlan,
            NodeKind::Secret,
            NodeKind::OutboundAction,
            NodeKind::Summarization,
            NodeKind::Retry,
        ];
        for kind in kinds {
            let _ = source_category(kind);
        }
    }
}
