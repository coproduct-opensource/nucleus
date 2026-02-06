//! Policy context for CEL expression evaluation.
//!
//! This module defines the context (variables) available to CEL expressions
//! when evaluating policy constraints.
//!
//! # Available Variables
//!
//! | Variable | Type | Description |
//! |----------|------|-------------|
//! | `operation` | string | The operation being performed (e.g., "read_files") |
//! | `path` | string | The file path being accessed (if applicable) |
//! | `capabilities` | object | Current capability levels |
//! | `trifecta_risk` | string | "none", "low", "medium", or "complete" |
//! | `budget_remaining` | float | Remaining budget as a fraction (0.0-1.0) |
//! | `timestamp` | timestamp | Current time |
//! | `isolation.process` | string | "shared", "namespaced", or "microvm" |
//! | `isolation.file` | string | "unrestricted", "sandboxed", "readonly", or "ephemeral" |
//! | `isolation.network` | string | "host", "namespaced", "filtered", or "airgapped" |
//!
//! # Example CEL Expressions
//!
//! ```text
//! // Require approval for writes outside workspace
//! operation == "write_files" && !path.startsWith("/workspace/")
//!
//! // Block when trifecta is complete and no approval
//! trifecta_risk == "complete" && !has_approval
//!
//! // Rate limit web operations
//! operation in ["web_fetch", "web_search"] && request_rate > 60
//!
//! // Require isolation for bash execution
//! operation == "run_bash" && isolation.process == "shared"
//!
//! // Web access only in VM
//! operation == "web_fetch" && isolation.process != "microvm"
//! ```

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};

use crate::capability::TrifectaRisk;
use crate::isolation::IsolationLattice;
use crate::{CapabilityLattice, Obligations, Operation};

/// Context available to CEL expressions during policy evaluation.
///
/// This struct captures the runtime state at the moment of policy evaluation,
/// providing variables that CEL expressions can reference.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// The operation being evaluated.
    pub operation: Operation,

    /// The file path being accessed (for file operations).
    pub path: Option<PathBuf>,

    /// The URL being accessed (for web operations).
    pub url: Option<String>,

    /// Current capability levels.
    pub capabilities: CapabilityLattice,

    /// Current obligations (approval requirements).
    pub obligations: Obligations,

    /// Trifecta risk assessment.
    pub trifecta_risk: TrifectaRisk,

    /// Remaining budget as a fraction (0.0 = exhausted, 1.0 = full).
    pub budget_remaining: f64,

    /// Whether an approval has been provided for this operation.
    pub has_approval: bool,

    /// Current timestamp.
    pub timestamp: DateTime<Utc>,

    /// Request rate for the current operation (requests per minute).
    pub request_rate: u32,

    /// Isolation level of the execution environment.
    pub isolation: IsolationLattice,

    /// Custom fields for extensibility.
    pub custom: HashMap<String, ContextValue>,
}

/// A value in the policy context.
#[derive(Debug, Clone)]
pub enum ContextValue {
    /// String value.
    String(String),
    /// Integer value.
    Int(i64),
    /// Float value.
    Float(f64),
    /// Boolean value.
    Bool(bool),
    /// List of values.
    List(Vec<ContextValue>),
    /// Map of values.
    Map(HashMap<String, ContextValue>),
}

impl PolicyContext {
    /// Create a new policy context with default values.
    pub fn new(operation: Operation) -> Self {
        Self {
            operation,
            path: None,
            url: None,
            capabilities: CapabilityLattice::default(),
            obligations: Obligations::default(),
            trifecta_risk: TrifectaRisk::None,
            budget_remaining: 1.0,
            has_approval: false,
            timestamp: Utc::now(),
            request_rate: 0,
            isolation: IsolationLattice::default(),
            custom: HashMap::new(),
        }
    }

    /// Set the file path.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the URL.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set capabilities.
    pub fn with_capabilities(mut self, caps: CapabilityLattice) -> Self {
        self.capabilities = caps;
        self
    }

    /// Set trifecta risk.
    pub fn with_trifecta_risk(mut self, risk: TrifectaRisk) -> Self {
        self.trifecta_risk = risk;
        self
    }

    /// Set budget remaining.
    pub fn with_budget(mut self, remaining: f64) -> Self {
        self.budget_remaining = remaining.clamp(0.0, 1.0);
        self
    }

    /// Set approval status.
    pub fn with_approval(mut self, has_approval: bool) -> Self {
        self.has_approval = has_approval;
        self
    }

    /// Set request rate.
    pub fn with_request_rate(mut self, rate: u32) -> Self {
        self.request_rate = rate;
        self
    }

    /// Set isolation level.
    pub fn with_isolation(mut self, isolation: IsolationLattice) -> Self {
        self.isolation = isolation;
        self
    }

    /// Add a custom field.
    pub fn with_custom(mut self, key: impl Into<String>, value: ContextValue) -> Self {
        self.custom.insert(key.into(), value);
        self
    }

    /// Get the operation as a string.
    pub fn operation_str(&self) -> &'static str {
        match self.operation {
            Operation::ReadFiles => "read_files",
            Operation::WriteFiles => "write_files",
            Operation::EditFiles => "edit_files",
            Operation::RunBash => "run_bash",
            Operation::GlobSearch => "glob_search",
            Operation::GrepSearch => "grep_search",
            Operation::WebSearch => "web_search",
            Operation::WebFetch => "web_fetch",
            Operation::GitCommit => "git_commit",
            Operation::GitPush => "git_push",
            Operation::CreatePr => "create_pr",
        }
    }

    /// Get the trifecta risk as a string.
    pub fn trifecta_risk_str(&self) -> &'static str {
        match self.trifecta_risk {
            TrifectaRisk::None => "none",
            TrifectaRisk::Low => "low",
            TrifectaRisk::Medium => "medium",
            TrifectaRisk::Complete => "complete",
        }
    }

    /// Get the path as a string (empty if not set).
    pub fn path_str(&self) -> String {
        self.path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    /// Populate a CEL context with variables from this PolicyContext.
    #[cfg(feature = "cel")]
    pub fn populate_cel_context(&self, ctx: &mut cel_interpreter::Context) {
        // Operation
        ctx.add_variable("operation", self.operation_str()).ok();

        // Path
        ctx.add_variable("path", self.path_str()).ok();

        // URL
        ctx.add_variable("url", self.url.clone().unwrap_or_default())
            .ok();

        // Trifecta risk
        ctx.add_variable("trifecta_risk", self.trifecta_risk_str())
            .ok();

        // Budget
        ctx.add_variable("budget_remaining", self.budget_remaining)
            .ok();

        // Approval status
        ctx.add_variable("has_approval", self.has_approval).ok();

        // Request rate
        ctx.add_variable("request_rate", self.request_rate as i64)
            .ok();

        // Isolation as a proper nested object
        // This allows CEL expressions to use standard object access: isolation.process
        let isolation_map = std::collections::HashMap::from([
            (
                "process".to_string(),
                self.isolation.process.as_str().to_string(),
            ),
            ("file".to_string(), self.isolation.file.as_str().to_string()),
            (
                "network".to_string(),
                self.isolation.network.as_str().to_string(),
            ),
        ]);
        ctx.add_variable_from_value("isolation", isolation_map);
    }
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self::new(Operation::ReadFiles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityLevel;

    #[test]
    fn test_context_creation() {
        let ctx = PolicyContext::new(Operation::WriteFiles)
            .with_path("/workspace/src/main.rs")
            .with_budget(0.75)
            .with_trifecta_risk(TrifectaRisk::Medium);

        assert_eq!(ctx.operation_str(), "write_files");
        assert_eq!(ctx.path_str(), "/workspace/src/main.rs");
        assert!((ctx.budget_remaining - 0.75).abs() < f64::EPSILON);
        assert_eq!(ctx.trifecta_risk_str(), "medium");
    }

    #[test]
    fn test_context_with_capabilities() {
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let ctx = PolicyContext::new(Operation::ReadFiles).with_capabilities(caps.clone());

        assert_eq!(ctx.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(ctx.capabilities.web_fetch, CapabilityLevel::LowRisk);
    }

    #[test]
    fn test_budget_clamping() {
        let ctx = PolicyContext::new(Operation::ReadFiles).with_budget(1.5);
        assert!((ctx.budget_remaining - 1.0).abs() < f64::EPSILON);

        let ctx = PolicyContext::new(Operation::ReadFiles).with_budget(-0.5);
        assert!(ctx.budget_remaining.abs() < f64::EPSILON);
    }

    #[test]
    fn test_custom_fields() {
        let ctx = PolicyContext::new(Operation::ReadFiles)
            .with_custom("team", ContextValue::String("platform".into()))
            .with_custom("priority", ContextValue::Int(1));

        assert!(matches!(
            ctx.custom.get("team"),
            Some(ContextValue::String(s)) if s == "platform"
        ));
        assert!(matches!(
            ctx.custom.get("priority"),
            Some(ContextValue::Int(1))
        ));
    }
}
