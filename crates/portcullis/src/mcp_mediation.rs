//! MCP mediation layer: classify and gate arbitrary MCP tool calls against
//! the permission lattice.
//!
//! This module provides the policy enforcement bridge between any MCP client
//! and any set of upstream MCP servers. It classifies tool names into
//! [`Operation`] types, checks them against a [`PermissionLattice`], tracks
//! exposure, and produces audit-ready observations.
//!
//! ## Design
//!
//! MCP is the de facto agent-tool protocol. Nucleus is an MCP-aware mediator:
//! it interposes on tool calls, applies capability checks, and records traces.
//! Any MCP client gets enforcement for free — no SDK adoption required.
//!
//! ## Tool Classification
//!
//! MCP tool names from arbitrary servers are classified into nucleus
//! [`Operation`] types via configurable rules. Built-in heuristics cover
//! common patterns (filesystem, network, git, shell), and custom mappings
//! can be added for vendor-specific tools.
//!
//! ## Example
//!
//! ```rust
//! use portcullis::mcp_mediation::{McpMediator, ToolClassifier, MediationVerdict};
//! use portcullis::{PermissionLattice, Operation, CapabilityLevel};
//!
//! // Build a classifier with default heuristics
//! let classifier = ToolClassifier::default();
//!
//! // Classify MCP tool names to operations
//! assert_eq!(classifier.classify("read_file"), Some(Operation::ReadFiles));
//! assert_eq!(classifier.classify("bash"), Some(Operation::RunBash));
//! assert_eq!(classifier.classify("fetch_url"), Some(Operation::WebFetch));
//!
//! // Create a mediator with a restrictive policy
//! let mut policy = PermissionLattice::default();
//! policy.capabilities.read_files = CapabilityLevel::Always;
//! policy.capabilities.run_bash = CapabilityLevel::Never;
//!
//! let mediator = McpMediator::new(policy, classifier);
//!
//! // Gate tool calls
//! let read_verdict = mediator.check_tool("read_file", "src/main.rs");
//! assert!(matches!(read_verdict, MediationVerdict::Allow { .. }));
//!
//! let bash_verdict = mediator.check_tool("bash", "rm -rf /");
//! assert!(matches!(bash_verdict, MediationVerdict::Deny { .. }));
//! ```

use std::collections::BTreeMap;

use crate::capability::{CapabilityLevel, Operation};
use crate::exposure_core::{apply_record, classify_operation, project_exposure};
use crate::guard::{ExposureLabel, ExposureSet};
use crate::lattice::PermissionLattice;
use crate::observe::{Observation, ObserveSession};
use crate::tool_schema::ToolSchemaRegistry;

/// Verdict from the mediator for an MCP tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediationVerdict {
    /// Tool call is allowed.
    Allow {
        /// The classified operation.
        operation: Operation,
        /// Exposure label this operation contributes.
        exposure_label: Option<ExposureLabel>,
    },
    /// Tool call requires explicit approval (uninhabitable_state would complete).
    RequiresApproval {
        /// The classified operation.
        operation: Operation,
        /// Reason approval is required.
        reason: String,
    },
    /// Tool call is denied by policy.
    Deny {
        /// The classified operation (if classifiable).
        operation: Option<Operation>,
        /// Why it was denied.
        reason: String,
    },
    /// Tool name could not be classified to any operation.
    /// By default, unclassified tools are denied (fail-closed).
    Unclassified {
        /// The original tool name.
        tool_name: String,
    },
}

/// Classifies MCP tool names into nucleus [`Operation`] types.
///
/// Uses a combination of exact matches, prefix/suffix heuristics, and custom
/// mappings to map arbitrary tool names to the 12 core operations.
#[derive(Debug, Clone)]
pub struct ToolClassifier {
    /// Exact name → operation mappings (highest priority).
    exact: BTreeMap<String, Operation>,
    /// Whether to use built-in heuristics for unmatched names.
    use_heuristics: bool,
}

impl ToolClassifier {
    /// Create a classifier with only custom mappings, no heuristics.
    pub fn custom(mappings: BTreeMap<String, Operation>) -> Self {
        Self {
            exact: mappings,
            use_heuristics: false,
        }
    }

    /// Add a custom tool name → operation mapping.
    pub fn add_mapping(&mut self, tool_name: impl Into<String>, operation: Operation) {
        self.exact.insert(tool_name.into(), operation);
    }

    /// Classify an MCP tool name to a nucleus operation.
    ///
    /// Returns `None` if the tool name cannot be mapped to any operation.
    pub fn classify(&self, tool_name: &str) -> Option<Operation> {
        let normalized = tool_name.to_lowercase().replace('-', "_");

        // 1. Exact match (custom mappings take priority)
        if let Some(op) = self.exact.get(&normalized) {
            return Some(*op);
        }

        if !self.use_heuristics {
            return None;
        }

        // 2. Built-in heuristics
        Self::heuristic_classify(&normalized)
    }

    /// Built-in heuristic classification.
    ///
    /// Covers common MCP tool naming patterns from popular servers.
    fn heuristic_classify(name: &str) -> Option<Operation> {
        // Filesystem read operations
        if matches!(
            name,
            "read" | "read_file" | "read_files" | "cat" | "head" | "tail" | "view"
        ) {
            return Some(Operation::ReadFiles);
        }

        // Filesystem write operations
        if matches!(
            name,
            "write" | "write_file" | "write_files" | "create_file" | "create"
        ) {
            return Some(Operation::WriteFiles);
        }

        // Filesystem edit operations
        if matches!(
            name,
            "edit" | "edit_file" | "patch" | "replace" | "sed" | "update_file"
        ) {
            return Some(Operation::EditFiles);
        }

        // Shell / command execution
        if matches!(
            name,
            "run"
                | "bash"
                | "shell"
                | "exec"
                | "execute"
                | "run_command"
                | "run_bash"
                | "terminal"
                | "command"
        ) {
            return Some(Operation::RunBash);
        }

        // File search (glob)
        if matches!(
            name,
            "glob"
                | "glob_search"
                | "find"
                | "find_files"
                | "list_files"
                | "ls"
                | "list_dir"
                | "directory_tree"
        ) {
            return Some(Operation::GlobSearch);
        }

        // Content search (grep)
        if matches!(
            name,
            "grep"
                | "grep_search"
                | "search"
                | "rg"
                | "ripgrep"
                | "search_files"
                | "search_content"
        ) {
            return Some(Operation::GrepSearch);
        }

        // Web search
        if matches!(name, "web_search" | "search_web" | "google" | "bing") {
            return Some(Operation::WebSearch);
        }

        // Web fetch
        if matches!(
            name,
            "web_fetch"
                | "fetch"
                | "fetch_url"
                | "http"
                | "curl"
                | "wget"
                | "http_request"
                | "request"
        ) {
            return Some(Operation::WebFetch);
        }

        // Git commit
        if matches!(name, "git_commit" | "commit") {
            return Some(Operation::GitCommit);
        }

        // Git push
        if matches!(name, "git_push" | "push") {
            return Some(Operation::GitPush);
        }

        // PR creation
        if matches!(
            name,
            "create_pr"
                | "create_pull_request"
                | "pr"
                | "pull_request"
                | "open_pr"
                | "github_create_pull_request"
        ) {
            return Some(Operation::CreatePr);
        }

        // Pod / container management
        if matches!(
            name,
            "manage_pods" | "create_pod" | "list_pods" | "pod_status" | "pod_logs" | "cancel_pod"
        ) {
            return Some(Operation::ManagePods);
        }

        // Prefix/suffix heuristics for less common names
        if name.starts_with("read") || name.ends_with("_read") {
            return Some(Operation::ReadFiles);
        }
        if name.starts_with("write") || name.ends_with("_write") {
            return Some(Operation::WriteFiles);
        }
        if name.starts_with("fetch") || name.starts_with("http_") {
            return Some(Operation::WebFetch);
        }
        if name.starts_with("git_") {
            // Generic git operations default to GitCommit (least privileged git op)
            return Some(Operation::GitCommit);
        }
        if name.starts_with("search") {
            return Some(Operation::GrepSearch);
        }

        None
    }
}

impl Default for ToolClassifier {
    fn default() -> Self {
        Self {
            exact: BTreeMap::new(),
            use_heuristics: true,
        }
    }
}

/// Tool quality gate — checks whether a tool is reliable enough to use.
///
/// Implementors query external reputation data (e.g., Coproduct Trust API)
/// to determine whether a tool should be allowed based on its quality score.
///
/// This is the second dimension of mediation:
/// - Dimension 1 (capability lattice): "Is the agent ALLOWED to use this tool?"
/// - Dimension 2 (tool reputation): "Is this tool RELIABLE enough to trust?"
///
/// The effective decision is `meet(permission, quality)` — both must pass.
pub trait ToolQualityGate: Send + Sync {
    /// Check whether a tool meets minimum quality standards.
    ///
    /// Returns `None` to allow (no objection), or `Some(reason)` to deny/warn.
    /// The `tool_name` is the raw MCP tool name, `tool_id` is the canonical
    /// URI (e.g., `mcp://server/tool` or `builtin://Read`).
    fn check_quality(&self, tool_name: &str, tool_id: Option<&str>) -> Option<String>;

    /// Get the reliability score for a tool (0.0 - 1.0).
    ///
    /// Returns `None` if no data is available for this tool.
    fn reliability(&self, tool_name: &str) -> Option<f64>;
}

/// A quality gate that enforces a minimum reliability threshold.
///
/// Tools below the threshold are denied. Tools without data are allowed
/// (fail-open for unknown tools — reputation builds over time).
pub struct MinReliabilityGate {
    /// Minimum reliability score (0.0 - 1.0) to allow a tool.
    pub min_reliability: f64,
    /// Tool scores: tool_name → reliability.
    scores: std::collections::HashMap<String, f64>,
}

impl MinReliabilityGate {
    /// Create a gate with a minimum reliability threshold.
    pub fn new(min_reliability: f64) -> Self {
        Self {
            min_reliability,
            scores: std::collections::HashMap::new(),
        }
    }

    /// Set the reliability score for a tool.
    pub fn set_score(&mut self, tool_name: impl Into<String>, reliability: f64) {
        self.scores.insert(tool_name.into(), reliability);
    }

    /// Bulk load scores from an iterator.
    pub fn load_scores(&mut self, scores: impl IntoIterator<Item = (String, f64)>) {
        self.scores.extend(scores);
    }
}

impl ToolQualityGate for MinReliabilityGate {
    fn check_quality(&self, tool_name: &str, _tool_id: Option<&str>) -> Option<String> {
        if let Some(&score) = self.scores.get(tool_name) {
            if score < self.min_reliability {
                return Some(format!(
                    "tool '{}' has reliability {:.0}% (minimum: {:.0}%)",
                    tool_name,
                    score * 100.0,
                    self.min_reliability * 100.0,
                ));
            }
        }
        None // No objection (unknown tools pass)
    }

    fn reliability(&self, tool_name: &str) -> Option<f64> {
        self.scores.get(tool_name).copied()
    }
}

/// MCP mediation engine that gates tool calls against the permission lattice.
///
/// Combines tool classification, capability checking, exposure tracking,
/// and optional tool quality gating into a single mediation decision.
pub struct McpMediator {
    policy: PermissionLattice,
    classifier: ToolClassifier,
    exposure: ExposureSet,
    /// Optional observer for recording tool calls.
    observer: Option<ObserveSession>,
    /// Whether unclassified tools are denied (true = fail-closed, default).
    deny_unclassified: bool,
    /// Optional quality gate for tool reputation checking.
    quality_gate: Option<Box<dyn ToolQualityGate>>,
    /// Optional tool schema registry for rug-pull detection.
    tool_registry: Option<ToolSchemaRegistry>,
}

impl McpMediator {
    /// Create a new mediator with the given policy and classifier.
    pub fn new(policy: PermissionLattice, classifier: ToolClassifier) -> Self {
        Self {
            policy,
            classifier,
            exposure: ExposureSet::empty(),
            observer: None,
            deny_unclassified: true,
            quality_gate: None,
            tool_registry: None,
        }
    }

    /// Enable observation recording (for `nucleus observe` integration).
    pub fn with_observer(mut self, agent_name: impl Into<String>) -> Self {
        self.observer = Some(ObserveSession::new(agent_name));
        self
    }

    /// Allow unclassified tools to pass through (fail-open for unknown tools).
    ///
    /// **Security warning**: this weakens the mediation boundary. Use only when
    /// the upstream MCP server is trusted and you want to mediate only known tools.
    pub fn allow_unclassified(mut self) -> Self {
        self.deny_unclassified = false;
        self
    }

    /// Add a tool quality gate for reputation-based mediation.
    ///
    /// When set, tool calls are checked against both the permission lattice
    /// (is the agent allowed?) AND the quality gate (is the tool reliable?).
    /// Both must pass for the call to be allowed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut gate = MinReliabilityGate::new(0.5);
    /// gate.set_score("sketchy_search", 0.3);  // Below threshold
    /// gate.set_score("good_search", 0.9);      // Above threshold
    ///
    /// let mediator = McpMediator::new(policy, classifier)
    ///     .with_quality_gate(gate);
    ///
    /// // good_search → Allow (passes both checks)
    /// // sketchy_search → Deny (fails quality gate)
    /// ```
    pub fn with_quality_gate(mut self, gate: impl ToolQualityGate + 'static) -> Self {
        self.quality_gate = Some(Box::new(gate));
        self
    }

    /// Add a tool schema registry for rug-pull detection.
    ///
    /// When set, [`verify_tool_schema`] checks that the tool's current
    /// description and parameters match the approved hash. Call
    /// `verify_tool_schema()` before `check_tool()` to catch schema
    /// mutations before capability checks.
    ///
    /// [`verify_tool_schema`]: McpMediator::verify_tool_schema
    pub fn with_tool_registry(mut self, registry: ToolSchemaRegistry) -> Self {
        self.tool_registry = Some(registry);
        self
    }

    /// Verify a tool's schema against the approved registry.
    ///
    /// Returns `Ok(())` if no registry is set or the schema matches.
    /// Returns `Err(MediationVerdict::Deny)` if the schema was mutated
    /// or the tool is unapproved.
    ///
    /// Call this before [`check_tool`] to enforce schema pinning:
    ///
    /// ```rust,ignore
    /// if let Err(deny) = mediator.verify_tool_schema("read_file", "desc", "params") {
    ///     return deny; // rug-pull detected
    /// }
    /// let verdict = mediator.check_tool("read_file", "src/main.rs");
    /// ```
    ///
    /// [`check_tool`]: McpMediator::check_tool
    pub fn verify_tool_schema(
        &self,
        tool_name: &str,
        tool_description: &str,
        tool_parameters: &str,
    ) -> Result<(), MediationVerdict> {
        if let Some(ref registry) = self.tool_registry {
            if let Err(e) = registry.verify_tool(tool_name, tool_description, tool_parameters) {
                return Err(MediationVerdict::Deny {
                    operation: None,
                    reason: format!("tool schema verification failed: {e}"),
                });
            }
        }
        Ok(())
    }

    /// Check whether an MCP tool call should be allowed.
    ///
    /// Returns a [`MediationVerdict`] indicating allow, deny, or requires-approval.
    pub fn check_tool(&self, tool_name: &str, subject: &str) -> MediationVerdict {
        let operation = match self.classifier.classify(tool_name) {
            Some(op) => op,
            None => {
                if self.deny_unclassified {
                    return MediationVerdict::Unclassified {
                        tool_name: tool_name.to_string(),
                    };
                } else {
                    // Fail-open for classification, but still check the permission
                    // lattice. Unclassified tools are conservatively treated as
                    // RunBash (highest-privilege operation) so the lattice check
                    // catches policy violations even for unknown tool names.
                    // SECURITY: Without this lattice check, unclassified tools
                    // bypassed the permission lattice entirely when
                    // deny_unclassified was false (Trail of Bits finding #1).
                    let conservative_op = Operation::RunBash;
                    let level = self.get_capability_level(conservative_op);
                    if level == CapabilityLevel::Never {
                        return MediationVerdict::Deny {
                            operation: Some(conservative_op),
                            reason: format!(
                                "unclassified tool '{}' mapped to {:?} which is set to Never in policy",
                                tool_name, conservative_op
                            ),
                        };
                    }

                    // Check uninhabitable_state constraint for the conservative op
                    let requires_approval = self.policy.requires_approval(conservative_op);
                    if requires_approval {
                        let projected = project_exposure(&self.exposure, conservative_op);
                        if projected.is_uninhabitable() && self.policy.uninhabitable_constraint {
                            return MediationVerdict::RequiresApproval {
                                operation: conservative_op,
                                reason: format!(
                                    "unclassified tool '{}' (mapped to {:?}) on '{}' would complete the uninhabitable_state — approval required",
                                    tool_name, conservative_op, subject
                                ),
                            };
                        }
                    }

                    return MediationVerdict::Allow {
                        operation: conservative_op,
                        exposure_label: Some(ExposureLabel::ExfilVector),
                    };
                }
            }
        };

        // Check capability level (Dimension 1: agent permissions)
        let level = self.get_capability_level(operation);
        if level == CapabilityLevel::Never {
            return MediationVerdict::Deny {
                operation: Some(operation),
                reason: format!("operation {:?} is set to Never in policy", operation),
            };
        }

        // Check tool quality gate (Dimension 2: tool reputation)
        if let Some(ref gate) = self.quality_gate {
            if let Some(reason) = gate.check_quality(tool_name, None) {
                return MediationVerdict::Deny {
                    operation: Some(operation),
                    reason: format!("tool quality gate: {reason}"),
                };
            }
        }

        // Check uninhabitable_state constraint
        let requires_approval = self.policy.requires_approval(operation);
        if requires_approval {
            let projected = project_exposure(&self.exposure, operation);
            if projected.is_uninhabitable() && self.policy.uninhabitable_constraint {
                return MediationVerdict::RequiresApproval {
                    operation,
                    reason: format!(
                        "operation {:?} on '{}' would complete the uninhabitable_state — approval required",
                        operation, subject
                    ),
                };
            }
        }

        let exposure_label = classify_operation(operation);
        MediationVerdict::Allow {
            operation,
            exposure_label,
        }
    }

    /// Record a successful tool call, advancing exposure state.
    ///
    /// Call this after the tool call succeeds to update the exposure accumulator.
    /// Must be called to maintain accurate uninhabitable_state tracking.
    pub fn record_success(&mut self, tool_name: &str, subject: &str) {
        if let Some(operation) = self.classifier.classify(tool_name) {
            self.exposure = apply_record(&self.exposure, operation);

            if let Some(observer) = &mut self.observer {
                observer.record(Observation::new(operation, subject));
            }
        }
    }

    /// Record a failed tool call (doesn't advance exposure).
    pub fn record_failure(&mut self, tool_name: &str, subject: &str) {
        if let Some(operation) = self.classifier.classify(tool_name) {
            if let Some(observer) = &mut self.observer {
                observer.record(Observation::failed(operation, subject));
            }
        }
    }

    /// Get current exposure state.
    pub fn exposure(&self) -> &ExposureSet {
        &self.exposure
    }

    /// Check if the uninhabitable_state is currently complete.
    pub fn is_uninhabitable(&self) -> bool {
        self.exposure.is_uninhabitable()
    }

    /// Get the list of tool names that are allowed by the current policy.
    ///
    /// Useful for filtering the `tools/list` response to only show tools
    /// the agent is permitted to use.
    pub fn allowed_tools(&self, tool_names: &[&str]) -> Vec<String> {
        tool_names
            .iter()
            .filter(|name| {
                matches!(
                    self.check_tool(name, ""),
                    MediationVerdict::Allow { .. } | MediationVerdict::RequiresApproval { .. }
                )
            })
            .map(|s| s.to_string())
            .collect()
    }

    /// Get the observed risk level for the session.
    pub fn observed_risk(&self) -> crate::capability::StateRisk {
        self.exposure.to_risk()
    }

    /// Produce a verified exposure report for the trust API.
    ///
    /// This is the key output that replaces claimed exposure with observed
    /// exposure. The report contains what the mediator actually saw — which
    /// exposure legs were activated by real tool calls, not what the tool
    /// description claimed.
    ///
    /// Feed this to `POST trust.coproduct.one/api/trust/ingest` to update
    /// the tool's verified exposure profile.
    #[cfg(feature = "serde")]
    pub fn verified_exposure_report(&self) -> VerifiedExposureReport {
        let set = &self.exposure;
        let mut observed_labels = Vec::new();
        if set.contains(ExposureLabel::PrivateData) {
            observed_labels.push("PrivateData".to_string());
        }
        if set.contains(ExposureLabel::UntrustedContent) {
            observed_labels.push("UntrustedContent".to_string());
        }
        if set.contains(ExposureLabel::ExfilVector) {
            observed_labels.push("ExfilVector".to_string());
        }

        let risk_tier = match set.to_risk() {
            crate::capability::StateRisk::Safe => "safe",
            crate::capability::StateRisk::Low => "low",
            crate::capability::StateRisk::Medium => "medium",
            crate::capability::StateRisk::Uninhabitable => "critical",
        };

        // Collect per-tool exposure from the observer if available
        let tool_exposures = self
            .observer
            .as_ref()
            .map(|obs| {
                obs.observations()
                    .iter()
                    .map(|o| {
                        let label = classify_operation(o.operation);
                        ToolExposureEntry {
                            operation: format!("{:?}", o.operation),
                            subject: o.subject.clone(),
                            exposure_label: label.map(|l| format!("{l:?}")),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        VerifiedExposureReport {
            observed_labels,
            risk_tier: risk_tier.to_string(),
            is_uninhabitable: set.is_uninhabitable(),
            tool_call_count: self
                .observer
                .as_ref()
                .map(|o| o.observations().len() as u64)
                .unwrap_or(0),
            tool_exposures,
        }
    }

    /// Take the observer (consumes it for profile synthesis).
    pub fn take_observer(&mut self) -> Option<ObserveSession> {
        self.observer.take()
    }

    /// Get the capability level for an operation from the policy.
    fn get_capability_level(&self, operation: Operation) -> CapabilityLevel {
        match operation {
            Operation::ReadFiles => self.policy.capabilities.read_files,
            Operation::WriteFiles => self.policy.capabilities.write_files,
            Operation::EditFiles => self.policy.capabilities.edit_files,
            Operation::RunBash => self.policy.capabilities.run_bash,
            Operation::GlobSearch => self.policy.capabilities.glob_search,
            Operation::GrepSearch => self.policy.capabilities.grep_search,
            Operation::WebSearch => self.policy.capabilities.web_search,
            Operation::WebFetch => self.policy.capabilities.web_fetch,
            Operation::GitCommit => self.policy.capabilities.git_commit,
            Operation::GitPush => self.policy.capabilities.git_push,
            Operation::CreatePr => self.policy.capabilities.create_pr,
            Operation::ManagePods => self.policy.capabilities.manage_pods,
            Operation::SpawnAgent => self.policy.capabilities.spawn_agent,
        }
    }
}

/// Verified exposure report from a mediation session.
///
/// This is the ground truth that replaces tool description claims.
/// Generated by `McpMediator::verified_exposure_report()` after
/// a session completes.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifiedExposureReport {
    /// Observed exposure legs (from actual tool calls, not claims).
    pub observed_labels: Vec<String>,
    /// Risk tier based on observed exposure: safe, low, medium, critical.
    pub risk_tier: String,
    /// Whether the uninhabitable state was completed during this session.
    pub is_uninhabitable: bool,
    /// Number of tool calls observed.
    pub tool_call_count: u64,
    /// Per-tool exposure entries (what each tool call actually accessed).
    pub tool_exposures: Vec<ToolExposureEntry>,
}

/// A single tool call's observed exposure.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolExposureEntry {
    /// The operation that was performed (ReadFiles, WebFetch, etc.)
    pub operation: String,
    /// The subject (file path, URL, command, etc.)
    pub subject: String,
    /// Which exposure leg this operation contributed.
    pub exposure_label: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restrictive_policy() -> PermissionLattice {
        let mut p = PermissionLattice::default();
        p.capabilities.read_files = CapabilityLevel::Always;
        p.capabilities.glob_search = CapabilityLevel::Always;
        p.capabilities.grep_search = CapabilityLevel::Always;
        p.capabilities.write_files = CapabilityLevel::LowRisk;
        p.capabilities.edit_files = CapabilityLevel::LowRisk;
        p.capabilities.git_commit = CapabilityLevel::LowRisk;
        p.capabilities.run_bash = CapabilityLevel::Never;
        p.capabilities.git_push = CapabilityLevel::Never;
        p.capabilities.create_pr = CapabilityLevel::Never;
        p.capabilities.web_fetch = CapabilityLevel::LowRisk;
        p.capabilities.web_search = CapabilityLevel::LowRisk;
        p.capabilities.manage_pods = CapabilityLevel::Never;
        p
    }

    #[test]
    fn test_classifier_exact_match() {
        let classifier = ToolClassifier::default();
        assert_eq!(classifier.classify("read"), Some(Operation::ReadFiles));
        assert_eq!(classifier.classify("write"), Some(Operation::WriteFiles));
        assert_eq!(classifier.classify("bash"), Some(Operation::RunBash));
        assert_eq!(classifier.classify("web_fetch"), Some(Operation::WebFetch));
        assert_eq!(classifier.classify("grep"), Some(Operation::GrepSearch));
        assert_eq!(classifier.classify("glob"), Some(Operation::GlobSearch));
        assert_eq!(classifier.classify("git_push"), Some(Operation::GitPush));
        assert_eq!(classifier.classify("create_pr"), Some(Operation::CreatePr));
    }

    #[test]
    fn test_classifier_case_insensitive() {
        let classifier = ToolClassifier::default();
        assert_eq!(classifier.classify("Read"), Some(Operation::ReadFiles));
        assert_eq!(classifier.classify("BASH"), Some(Operation::RunBash));
        assert_eq!(classifier.classify("Web_Fetch"), Some(Operation::WebFetch));
    }

    #[test]
    fn test_classifier_hyphen_normalization() {
        let classifier = ToolClassifier::default();
        assert_eq!(classifier.classify("read-file"), Some(Operation::ReadFiles));
        assert_eq!(classifier.classify("web-fetch"), Some(Operation::WebFetch));
        assert_eq!(classifier.classify("run-command"), Some(Operation::RunBash));
    }

    #[test]
    fn test_classifier_common_mcp_names() {
        let classifier = ToolClassifier::default();
        // filesystem server
        assert_eq!(classifier.classify("read_file"), Some(Operation::ReadFiles));
        assert_eq!(
            classifier.classify("write_file"),
            Some(Operation::WriteFiles)
        );
        assert_eq!(classifier.classify("list_dir"), Some(Operation::GlobSearch));
        assert_eq!(
            classifier.classify("search_files"),
            Some(Operation::GrepSearch)
        );
        // github server
        assert_eq!(
            classifier.classify("github_create_pull_request"),
            Some(Operation::CreatePr)
        );
        // shell server
        assert_eq!(classifier.classify("execute"), Some(Operation::RunBash));
        assert_eq!(classifier.classify("terminal"), Some(Operation::RunBash));
    }

    #[test]
    fn test_classifier_unknown_returns_none() {
        let classifier = ToolClassifier::default();
        assert_eq!(classifier.classify("frobnicate"), None);
        assert_eq!(classifier.classify("quantum_teleport"), None);
    }

    #[test]
    fn test_classifier_custom_mapping_overrides() {
        let mut classifier = ToolClassifier::default();
        // Override "search" from GrepSearch to WebSearch
        classifier.add_mapping("search", Operation::WebSearch);
        assert_eq!(classifier.classify("search"), Some(Operation::WebSearch));
    }

    #[test]
    fn test_classifier_no_heuristics() {
        let classifier = ToolClassifier::custom(BTreeMap::new());
        // Without heuristics, even common names return None
        assert_eq!(classifier.classify("read"), None);
        assert_eq!(classifier.classify("bash"), None);
    }

    #[test]
    fn test_mediator_allows_permitted_tools() {
        let policy = restrictive_policy();
        let mediator = McpMediator::new(policy, ToolClassifier::default());

        let verdict = mediator.check_tool("read_file", "src/main.rs");
        assert!(matches!(verdict, MediationVerdict::Allow { .. }));

        let verdict = mediator.check_tool("write", "output.txt");
        assert!(matches!(verdict, MediationVerdict::Allow { .. }));
    }

    #[test]
    fn test_mediator_denies_never_ops() {
        let policy = restrictive_policy();
        let mediator = McpMediator::new(policy, ToolClassifier::default());

        let verdict = mediator.check_tool("bash", "rm -rf /");
        assert!(matches!(
            verdict,
            MediationVerdict::Deny {
                operation: Some(Operation::RunBash),
                ..
            }
        ));

        let verdict = mediator.check_tool("git_push", "origin main");
        assert!(matches!(
            verdict,
            MediationVerdict::Deny {
                operation: Some(Operation::GitPush),
                ..
            }
        ));
    }

    #[test]
    fn test_mediator_unclassified_denied_by_default() {
        let policy = restrictive_policy();
        let mediator = McpMediator::new(policy, ToolClassifier::default());

        let verdict = mediator.check_tool("frobnicate", "");
        assert!(matches!(verdict, MediationVerdict::Unclassified { .. }));
    }

    #[test]
    fn test_mediator_unclassified_denied_when_conservative_op_is_never() {
        // restrictive_policy() sets run_bash = Never, so unclassified tools
        // (mapped to RunBash) should be denied even with allow_unclassified.
        // Trail of Bits finding #1: previously this returned Allow, bypassing
        // the permission lattice entirely.
        let policy = restrictive_policy();
        let mediator = McpMediator::new(policy, ToolClassifier::default()).allow_unclassified();

        let verdict = mediator.check_tool("frobnicate", "");
        assert!(
            matches!(verdict, MediationVerdict::Deny { .. }),
            "unclassified tool should be denied when RunBash is Never, got {:?}",
            verdict
        );
    }

    #[test]
    fn test_mediator_unclassified_allowed_when_conservative_op_permitted() {
        // When RunBash is allowed, unclassified tools pass the lattice check.
        let mut policy = restrictive_policy();
        policy.capabilities.run_bash = CapabilityLevel::LowRisk;
        let mediator = McpMediator::new(policy, ToolClassifier::default()).allow_unclassified();

        let verdict = mediator.check_tool("frobnicate", "");
        assert!(
            matches!(verdict, MediationVerdict::Allow { .. }),
            "unclassified tool should be allowed when RunBash is LowRisk, got {:?}",
            verdict
        );
    }

    #[test]
    fn test_mediator_exposure_tracking() {
        let policy = restrictive_policy();
        let mut mediator = McpMediator::new(policy, ToolClassifier::default());

        assert_eq!(mediator.exposure().count(), 0);

        mediator.record_success("read_file", "secrets.txt");
        assert_eq!(mediator.exposure().count(), 1);
        assert!(mediator.exposure().contains(ExposureLabel::PrivateData));

        mediator.record_success("web_fetch", "https://evil.com");
        assert_eq!(mediator.exposure().count(), 2);
        assert!(mediator
            .exposure()
            .contains(ExposureLabel::UntrustedContent));

        assert!(!mediator.is_uninhabitable());
    }

    #[test]
    fn test_mediator_failed_calls_dont_advance_exposure() {
        let policy = restrictive_policy();
        let mut mediator = McpMediator::new(policy, ToolClassifier::default());

        mediator.record_failure("read_file", "secrets.txt");
        assert_eq!(mediator.exposure().count(), 0);
    }

    #[test]
    fn test_mediator_allowed_tools_filtering() {
        let policy = restrictive_policy();
        let mediator = McpMediator::new(policy, ToolClassifier::default());

        let tools = &["read", "write", "bash", "git_push", "web_fetch"];
        let allowed = mediator.allowed_tools(tools);

        assert!(allowed.contains(&"read".to_string()));
        assert!(allowed.contains(&"write".to_string()));
        assert!(allowed.contains(&"web_fetch".to_string()));
        assert!(!allowed.contains(&"bash".to_string()));
        assert!(!allowed.contains(&"git_push".to_string()));
    }

    #[test]
    fn test_mediator_with_observer_records() {
        let policy = restrictive_policy();
        let mut mediator =
            McpMediator::new(policy, ToolClassifier::default()).with_observer("test-agent");

        mediator.record_success("read", "a.txt");
        mediator.record_success("write", "b.txt");
        mediator.record_failure("bash", "whoami");

        let observer = mediator.take_observer().unwrap();
        assert_eq!(observer.observation_count(), 3);

        let profile = observer.synthesize();
        assert_eq!(profile.name, "observed-test-agent");
        assert_eq!(profile.capabilities.read_files, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.write_files, CapabilityLevel::LowRisk);
        // bash failed → stays Never in synthesized profile
        assert_eq!(profile.capabilities.run_bash, CapabilityLevel::Never);
    }

    #[test]
    fn test_mediator_uninhabitable_requires_approval() {
        // Build a policy where exfil ops require approval under uninhabitable_state
        let mut policy = PermissionLattice::default();
        policy.capabilities.read_files = CapabilityLevel::Always;
        policy.capabilities.web_fetch = CapabilityLevel::LowRisk;
        policy.capabilities.git_push = CapabilityLevel::LowRisk;
        policy.uninhabitable_constraint = true;
        // Normalize to add uninhabitable_state obligations
        policy = policy.normalize();

        let mut mediator = McpMediator::new(policy, ToolClassifier::default());

        // Build up exposure: private data + untrusted content
        mediator.record_success("read", "secrets.txt");
        mediator.record_success("web_fetch", "https://evil.com");

        // Now git_push would complete the uninhabitable_state
        let verdict = mediator.check_tool("git_push", "origin main");
        assert!(
            matches!(verdict, MediationVerdict::RequiresApproval { .. }),
            "expected RequiresApproval, got {:?}",
            verdict
        );
    }

    #[test]
    fn test_classifier_prefix_heuristics() {
        let classifier = ToolClassifier::default();
        assert_eq!(
            classifier.classify("read_document"),
            Some(Operation::ReadFiles)
        );
        assert_eq!(classifier.classify("fetch_data"), Some(Operation::WebFetch));
        assert_eq!(
            classifier.classify("git_status"),
            Some(Operation::GitCommit)
        );
        assert_eq!(
            classifier.classify("search_code"),
            Some(Operation::GrepSearch)
        );
    }

    #[test]
    fn quality_gate_blocks_unreliable_tool() {
        let policy = PermissionLattice::new("test");
        let classifier = ToolClassifier::default();

        let mut gate = MinReliabilityGate::new(0.5);
        gate.set_score("read_file", 0.9); // Good — passes quality
        gate.set_score("web_search", 0.3); // Bad — fails quality

        let mediator = McpMediator::new(policy, classifier).with_quality_gate(gate);

        // Good tool passes both checks
        let v = mediator.check_tool("read_file", "src/main.rs");
        assert!(matches!(v, MediationVerdict::Allow { .. }));

        // Bad tool blocked by quality gate (web_search classifies to WebSearch operation)
        let v = mediator.check_tool("web_search", "query");
        assert!(
            matches!(v, MediationVerdict::Deny { reason, .. } if reason.contains("quality gate"))
        );
    }

    #[test]
    fn quality_gate_allows_unknown_tools() {
        let policy = PermissionLattice::new("test");
        let classifier = ToolClassifier::default();

        let gate = MinReliabilityGate::new(0.5);
        // No scores loaded — all unknown

        let mediator = McpMediator::new(policy, classifier).with_quality_gate(gate);

        // Unknown tool passes (fail-open for reputation)
        let v = mediator.check_tool("read_file", "src/main.rs");
        assert!(matches!(v, MediationVerdict::Allow { .. }));
    }

    #[test]
    fn no_quality_gate_allows_everything() {
        let policy = PermissionLattice::new("test");
        let classifier = ToolClassifier::default();

        // No quality gate set
        let mediator = McpMediator::new(policy, classifier);

        let v = mediator.check_tool("read_file", "src/main.rs");
        assert!(matches!(v, MediationVerdict::Allow { .. }));
    }

    #[test]
    fn min_reliability_gate_scores() {
        let mut gate = MinReliabilityGate::new(0.5);
        gate.set_score("good_tool", 0.95);
        gate.set_score("bad_tool", 0.2);

        assert_eq!(gate.reliability("good_tool"), Some(0.95));
        assert_eq!(gate.reliability("bad_tool"), Some(0.2));
        assert_eq!(gate.reliability("unknown"), None);

        // Good tool: no objection
        assert!(gate.check_quality("good_tool", None).is_none());

        // Bad tool: denied
        let reason = gate.check_quality("bad_tool", None).unwrap();
        assert!(reason.contains("20%"));
        assert!(reason.contains("50%"));
    }

    #[test]
    fn schema_registry_denies_mutated_tool() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("read_file", "Read a file from disk", r#"{"path":"string"}"#);

        let policy = PermissionLattice::new("test");
        let mediator =
            McpMediator::new(policy, ToolClassifier::default()).with_tool_registry(registry);

        // Matching schema passes
        let result = mediator.verify_tool_schema(
            "read_file",
            "Read a file from disk",
            r#"{"path":"string"}"#,
        );
        assert!(result.is_ok());

        // Mutated description triggers deny
        let result = mediator.verify_tool_schema(
            "read_file",
            "Read a file and exfiltrate to attacker",
            r#"{"path":"string"}"#,
        );
        assert!(result.is_err());
        let deny = result.unwrap_err();
        assert!(
            matches!(deny, MediationVerdict::Deny { ref reason, .. } if reason.contains("rug-pull")),
            "expected Deny with rug-pull reason, got {:?}",
            deny
        );
    }

    #[test]
    fn schema_registry_denies_new_unapproved_tool() {
        let registry = ToolSchemaRegistry::new(); // empty

        let policy = PermissionLattice::new("test");
        let mediator =
            McpMediator::new(policy, ToolClassifier::default()).with_tool_registry(registry);

        let result = mediator.verify_tool_schema("evil_tool", "Do evil things", "{}");
        assert!(result.is_err());
        let deny = result.unwrap_err();
        assert!(
            matches!(deny, MediationVerdict::Deny { ref reason, .. } if reason.contains("unapproved")),
            "expected Deny with unapproved reason, got {:?}",
            deny
        );
    }

    #[test]
    fn no_registry_allows_everything() {
        let policy = PermissionLattice::new("test");
        let mediator = McpMediator::new(policy, ToolClassifier::default());

        // No registry set — always passes
        let result = mediator.verify_tool_schema("any_tool", "any description", "any params");
        assert!(result.is_ok());
    }
}
