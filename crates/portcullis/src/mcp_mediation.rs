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

/// MCP mediation engine that gates tool calls against the permission lattice.
///
/// Combines tool classification, capability checking, and exposure tracking
/// into a single mediation decision for each MCP tool call.
pub struct McpMediator {
    policy: PermissionLattice,
    classifier: ToolClassifier,
    exposure: ExposureSet,
    /// Optional observer for recording tool calls.
    observer: Option<ObserveSession>,
    /// Whether unclassified tools are denied (true = fail-closed, default).
    deny_unclassified: bool,
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
                    // Fail-open: allow unclassified tools without mediation
                    return MediationVerdict::Allow {
                        operation: Operation::RunBash, // Most conservative classification
                        exposure_label: Some(ExposureLabel::ExfilVector),
                    };
                }
            }
        };

        // Check capability level
        let level = self.get_capability_level(operation);
        if level == CapabilityLevel::Never {
            return MediationVerdict::Deny {
                operation: Some(operation),
                reason: format!("operation {:?} is set to Never in policy", operation),
            };
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
        }
    }
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
    fn test_mediator_unclassified_allowed_when_configured() {
        let policy = restrictive_policy();
        let mediator = McpMediator::new(policy, ToolClassifier::default()).allow_unclassified();

        let verdict = mediator.check_tool("frobnicate", "");
        // Allowed but classified as RunBash (most conservative)
        assert!(matches!(verdict, MediationVerdict::Allow { .. }));
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
}
