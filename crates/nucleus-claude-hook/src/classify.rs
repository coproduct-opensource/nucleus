//! Tool classification and flow-graph helpers.
//!
//! Pure functions that map tool names to `Operation`s, classify node kinds for
//! the IFC flow graph, and track DAG leaf nodes by category.  Extracted from
//! `main.rs` to keep the decision-loop module focused on orchestration.

use portcullis::manifest_registry::ManifestRegistry;
use portcullis::Operation;
use portcullis_core::flow::NodeKind;
use serde::Serialize;
use std::fmt;

// ---------------------------------------------------------------------------
// Classification result types (#554)
// ---------------------------------------------------------------------------

/// How the classification was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClassificationSource {
    /// Built-in tool (Bash, Read, Write, etc.).
    Builtin,
    /// Matched via `.nucleus/manifests/` declaration.
    Manifest,
    /// Heuristic: tool name matched a known pattern (e.g. "read_file").
    NameHeuristic,
    /// No pattern matched; fell through to the most restrictive default.
    DefaultFallback,
}

impl fmt::Display for ClassificationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin => write!(f, "builtin"),
            Self::Manifest => write!(f, "manifest"),
            Self::NameHeuristic => write!(f, "name-heuristic"),
            Self::DefaultFallback => write!(f, "default-fallback"),
        }
    }
}

/// How confident we are in the classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Confidence {
    /// Authoritative source (builtin or manifest).
    High,
    /// Strong name match (e.g. "read_file", "write_file").
    Medium,
    /// Weak or default match; may be wrong.
    Low,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Full classification result with provenance and confidence.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ClassificationResult {
    /// The tool name that was classified.
    pub tool_name: String,
    /// The resolved operation.
    pub operation: Operation,
    /// How the classification was determined.
    pub source: ClassificationSource,
    /// Confidence level.
    pub confidence: Confidence,
    /// Human-readable rationale.
    pub rationale: String,
}

impl fmt::Display for ClassificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {:?} [source={}, confidence={}] ({})",
            self.tool_name, self.operation, self.source, self.confidence, self.rationale
        )
    }
}

/// Aggregate classification counts for `--status --json` output.
#[derive(Debug, Clone, Serialize, Default)]
pub(crate) struct ClassificationSummary {
    pub total: usize,
    pub by_builtin: usize,
    pub by_manifest: usize,
    pub by_name_heuristic: usize,
    pub by_default_fallback: usize,
    pub low_confidence_tools: Vec<String>,
}

impl ClassificationSummary {
    /// Build a summary from a set of tool names.
    pub(crate) fn from_tool_names(names: &[String]) -> Self {
        let mut summary = Self::default();
        for name in names {
            summary.total += 1;
            let result = classify_with_detail(name);
            match result.source {
                ClassificationSource::Builtin => summary.by_builtin += 1,
                ClassificationSource::Manifest => summary.by_manifest += 1,
                ClassificationSource::NameHeuristic => summary.by_name_heuristic += 1,
                ClassificationSource::DefaultFallback => {
                    summary.by_default_fallback += 1;
                }
            }
            if result.confidence == Confidence::Low && !summary.low_confidence_tools.contains(name)
            {
                summary.low_confidence_tools.push(name.clone());
            }
        }
        summary
    }
}

// ---------------------------------------------------------------------------
// Tool name -> Operation mapping
// ---------------------------------------------------------------------------

/// Map a tool name to a portcullis Operation.
///
/// SECURITY: Every tool is gated. No passthrough. The Agent tool spawns
/// subprocesses with fresh session IDs; passthrough would let a tainted
/// session escape its flow restrictions via a clean child process.
/// MCP tools (`mcp__<server>__<tool>`) are classified by their tool name suffix,
/// defaulting to RunBash (most restrictive) for unknown tools.
pub(crate) fn map_tool(name: &str) -> Operation {
    classify_with_detail(name).operation
}

/// Classify a tool and return full provenance details (#554).
///
/// Returns the operation, how it was determined, confidence level, and a
/// human-readable rationale.
pub(crate) fn classify_with_detail(name: &str) -> ClassificationResult {
    match name {
        "Bash" | "Read" | "Write" | "Edit" | "Glob" | "Grep" | "WebFetch" | "WebSearch"
        | "Agent" => {
            let operation = match name {
                "Bash" => Operation::RunBash,
                "Read" => Operation::ReadFiles,
                "Write" => Operation::WriteFiles,
                "Edit" => Operation::EditFiles,
                "Glob" => Operation::GlobSearch,
                "Grep" => Operation::GrepSearch,
                "WebFetch" => Operation::WebFetch,
                "WebSearch" => Operation::WebSearch,
                "Agent" => Operation::SpawnAgent,
                _ => unreachable!(),
            };
            ClassificationResult {
                tool_name: name.to_string(),
                operation,
                source: ClassificationSource::Builtin,
                confidence: Confidence::High,
                rationale: format!("built-in {} tool", name),
            }
        }
        _ if name.starts_with("mcp__") => classify_mcp_tool_with_detail(name),
        _ => ClassificationResult {
            tool_name: name.to_string(),
            operation: Operation::RunBash,
            source: ClassificationSource::DefaultFallback,
            confidence: Confidence::Low,
            rationale: format!("unknown tool '{}'; fail-closed as RunBash", name),
        },
    }
}

/// Log classification detail to stderr if `NUCLEUS_LOG_CLASSIFICATION=1`.
pub(crate) fn maybe_log_classification(result: &ClassificationResult) {
    if std::env::var("NUCLEUS_LOG_CLASSIFICATION").as_deref() == Ok("1") {
        eprintln!("nucleus: classify: {result}");
    }
}

/// Classify a tool and log if verbose classification is enabled.
pub(crate) fn map_tool_verbose(name: &str) -> Operation {
    let result = classify_with_detail(name);
    maybe_log_classification(&result);
    result.operation
}

// ---------------------------------------------------------------------------
// MCP tool classification with detail
// ---------------------------------------------------------------------------

/// Classify an MCP tool using its manifest capabilities (if available),
/// falling back to name-based heuristics (#490).
fn classify_mcp_tool_with_detail(name: &str) -> ClassificationResult {
    let mcp_tool_name = name
        .strip_prefix("mcp__")
        .and_then(|rest| rest.split("__").nth(1))
        .unwrap_or(name);

    let cwd = std::env::current_dir().unwrap_or_default();
    let registry = ManifestRegistry::load_from_dir(&cwd);
    if let Some(manifest) = registry.get(mcp_tool_name) {
        if let Some(op) = manifest.capabilities.first() {
            return ClassificationResult {
                tool_name: name.to_string(),
                operation: *op,
                source: ClassificationSource::Manifest,
                confidence: Confidence::High,
                rationale: format!("manifest declares {:?} for '{}'", op, mcp_tool_name),
            };
        }
    } else if registry.admitted_count() > 0 {
        eprintln!(
            "nucleus: MCP tool '{}' has no manifest; using name-based classification (less secure). \
             Add a manifest in .nucleus/manifests/",
            mcp_tool_name
        );
    }

    classify_mcp_tool_by_name_with_detail(name)
}

/// Classify an MCP tool by its name suffix (fallback), returning full detail.
fn classify_mcp_tool_by_name_with_detail(name: &str) -> ClassificationResult {
    let tool = name
        .strip_prefix("mcp__")
        .and_then(|rest| rest.split("__").nth(1))
        .unwrap_or(name);

    let (operation, matched_pattern) = match tool {
        t if t.contains("pull_request") || t.contains("pr_create") => {
            (Operation::CreatePr, "pull_request|pr_create")
        }
        t if t.contains("push") || t.contains("commit") || t.contains("merge") => {
            (Operation::GitPush, "push|commit|merge")
        }
        t if t.contains("run")
            || t.contains("exec")
            || t.contains("shell")
            || t.contains("command")
            || t.contains("bash")
            || t.contains("terminal") =>
        {
            (Operation::RunBash, "run|exec|shell|command|bash|terminal")
        }
        t if t.contains("fetch")
            || t.contains("download")
            || t.contains("http")
            || t.contains("url")
            || t.contains("browse") =>
        {
            (Operation::WebFetch, "fetch|download|http|url|browse")
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
            (
                Operation::WriteFiles,
                "write|create|update|delete|put|set|insert|edit|modify",
            )
        }
        t if t.contains("read")
            || t.contains("get")
            || t.contains("list")
            || t.contains("search")
            || t.contains("query")
            || t.contains("describe")
            || t.contains("request") =>
        {
            (
                Operation::ReadFiles,
                "read|get|list|search|query|describe|request",
            )
        }
        t if t.contains("grep") || t.contains("find") || t.contains("glob") => {
            (Operation::GlobSearch, "grep|find|glob")
        }
        _ => {
            return ClassificationResult {
                tool_name: name.to_string(),
                operation: Operation::RunBash,
                source: ClassificationSource::DefaultFallback,
                confidence: Confidence::Low,
                rationale: format!(
                    "MCP tool '{}' matched no pattern; fail-closed as RunBash \
                     (add a manifest for explicit classification)",
                    tool
                ),
            };
        }
    };

    ClassificationResult {
        tool_name: name.to_string(),
        operation,
        source: ClassificationSource::NameHeuristic,
        confidence: Confidence::Medium,
        rationale: format!("tool '{}' matched pattern [{}]", tool, matched_pattern),
    }
}

// ---------------------------------------------------------------------------
// Flow label classification
// ---------------------------------------------------------------------------

/// Map an Operation to the NodeKind that represents its data contribution.
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
pub(crate) fn classify_tool_output(op: Operation) -> NodeKind {
    match op {
        Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => NodeKind::FileRead,
        _ => NodeKind::ToolResponse,
    }
}

/// Truncate a string for storage/display, preserving valid UTF-8 boundaries.
pub(crate) fn truncate_subject(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
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
// DAG parent assignment
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(crate) struct LeafTracker {
    pub(crate) trusted: Vec<u64>,
    pub(crate) adversarial: Vec<u64>,
    pub(crate) action: Vec<u64>,
    pub(crate) model: Vec<u64>,
}

impl LeafTracker {
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
        *leaves = vec![node_id];
    }

    pub(crate) fn parents_for(&self, kind: NodeKind) -> Vec<u64> {
        match kind {
            NodeKind::FileRead | NodeKind::UserPrompt | NodeKind::EnvVar | NodeKind::MemoryRead => {
                self.trusted.clone()
            }
            NodeKind::WebContent => self.adversarial.clone(),
            NodeKind::OutboundAction | NodeKind::MemoryWrite => {
                let mut parents = Vec::new();
                parents.extend_from_slice(&self.trusted);
                parents.extend_from_slice(&self.adversarial);
                parents.extend_from_slice(&self.model);
                parents.extend_from_slice(&self.action);
                parents
            }
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
        assert_eq!(map_tool("Agent"), Operation::SpawnAgent);
    }

    #[test]
    fn test_mcp_tools_are_gated() {
        assert_eq!(map_tool("mcp__server__read_file"), Operation::ReadFiles);
        assert_eq!(map_tool("mcp__github__create_issue"), Operation::WriteFiles);
        assert_eq!(map_tool("mcp__unknown__unknown_tool"), Operation::RunBash);
    }

    #[test]
    fn test_mcp_tool_classification() {
        assert_eq!(map_tool("mcp__fs__read_file"), Operation::ReadFiles);
        assert_eq!(map_tool("mcp__db__get_record"), Operation::ReadFiles);
        assert_eq!(map_tool("mcp__api__list_items"), Operation::ReadFiles);
        assert_eq!(map_tool("mcp__fs__write_file"), Operation::WriteFiles);
        assert_eq!(map_tool("mcp__db__create_record"), Operation::WriteFiles);
        assert_eq!(map_tool("mcp__db__delete_item"), Operation::WriteFiles);
        assert_eq!(map_tool("mcp__http__fetch_url"), Operation::WebFetch);
        assert_eq!(map_tool("mcp__shell__run_command"), Operation::RunBash);
        assert_eq!(map_tool("mcp__term__exec_script"), Operation::RunBash);
        assert_eq!(map_tool("mcp__git__push_branch"), Operation::GitPush);
        assert_eq!(map_tool("mcp__gh__pull_request"), Operation::CreatePr);
        assert_eq!(map_tool("mcp__evil__pwn"), Operation::RunBash);
    }

    #[test]
    fn test_unknown_tools_fail_closed() {
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
        assert!(truncated.len() <= 103);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_truncate_subject_unicode() {
        let s = "a\u{1F600}b\u{1F600}c";
        let truncated = truncate_subject(s, 5);
        assert!(truncated.ends_with("..."));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    // -----------------------------------------------------------------------
    // Classification detail tests (#554)
    // -----------------------------------------------------------------------

    #[test]
    fn test_builtin_classification_source() {
        for name in &[
            "Bash",
            "Read",
            "Write",
            "Edit",
            "Glob",
            "Grep",
            "WebFetch",
            "WebSearch",
            "Agent",
        ] {
            let result = classify_with_detail(name);
            assert_eq!(result.source, ClassificationSource::Builtin, "tool: {name}");
            assert_eq!(result.confidence, Confidence::High, "tool: {name}");
        }
    }

    #[test]
    fn test_mcp_heuristic_classification_source() {
        let result = classify_with_detail("mcp__fs__read_file");
        assert_eq!(result.operation, Operation::ReadFiles);
        assert_eq!(result.source, ClassificationSource::NameHeuristic);
        assert_eq!(result.confidence, Confidence::Medium);
        assert!(result.rationale.contains("read"));
    }

    #[test]
    fn test_mcp_fallback_classification_source() {
        let result = classify_with_detail("mcp__evil__pwn");
        assert_eq!(result.operation, Operation::RunBash);
        assert_eq!(result.source, ClassificationSource::DefaultFallback);
        assert_eq!(result.confidence, Confidence::Low);
        assert!(result.rationale.contains("no pattern"));
    }

    #[test]
    fn test_unknown_tool_classification_source() {
        let result = classify_with_detail("UnknownTool");
        assert_eq!(result.operation, Operation::RunBash);
        assert_eq!(result.source, ClassificationSource::DefaultFallback);
        assert_eq!(result.confidence, Confidence::Low);
    }

    #[test]
    fn test_classification_result_display() {
        let result = classify_with_detail("mcp__fs__read_file");
        let display = format!("{result}");
        assert!(display.contains("mcp__fs__read_file"));
        assert!(display.contains("ReadFiles"));
        assert!(display.contains("name-heuristic"));
        assert!(display.contains("medium"));
    }

    #[test]
    fn test_classification_result_serializes() {
        let result = classify_with_detail("Bash");
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"source\":\"builtin\""));
        assert!(json.contains("\"confidence\":\"high\""));
        assert!(json.contains("\"operation\":\"run_bash\""));
    }

    #[test]
    fn test_classification_summary() {
        let tools: Vec<String> = vec![
            "Bash".into(),
            "Read".into(),
            "mcp__fs__read_file".into(),
            "mcp__evil__pwn".into(),
            "UnknownTool".into(),
        ];
        let summary = ClassificationSummary::from_tool_names(&tools);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.by_builtin, 2);
        assert_eq!(summary.by_name_heuristic, 1);
        assert_eq!(summary.by_default_fallback, 2);
        assert_eq!(summary.low_confidence_tools.len(), 2);
    }

    #[test]
    fn test_map_tool_verbose_returns_same_operation() {
        assert_eq!(map_tool_verbose("Bash"), map_tool("Bash"));
        assert_eq!(
            map_tool_verbose("mcp__fs__read_file"),
            map_tool("mcp__fs__read_file")
        );
        assert_eq!(
            map_tool_verbose("mcp__evil__pwn"),
            map_tool("mcp__evil__pwn")
        );
    }
}
