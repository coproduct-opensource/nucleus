//! Policy specification parsing and loading.
//!
//! This module provides types for loading policies from YAML or TOML files.
//! Policies are declarative, allowing security teams to define constraints
//! without writing Rust code.
//!
//! # File Format
//!
//! ```yaml
//! # policy.yaml
//! name: secure-workspace
//! description: Enforce workspace boundaries and approval flows
//! enforce_trifecta: true  # default: true
//!
//! constraints:
//!   - name: workspace-writes
//!     description: Require approval for writes outside workspace
//!     condition: |
//!       operation == "write_files" && !path.startsWith("/workspace/")
//!     obligations:
//!       - write_files
//!
//!   - name: sensitive-paths
//!     description: Block access to sensitive directories
//!     condition: |
//!       path.startsWith("/etc/") || path.contains("/.ssh/")
//!     obligations:
//!       - read_files
//!       - write_files
//!
//!   - name: rate-limit-web
//!     description: Rate limit web operations
//!     condition: |
//!       operation in ["web_fetch", "web_search"] && request_rate > 60
//!     obligations:
//!       - web_fetch
//!       - web_search
//! ```
//!
//! # Loading Policies
//!
//! ```rust,ignore
//! use lattice_guard::constraint::spec::PolicySpec;
//! use std::fs;
//!
//! let yaml = fs::read_to_string("policy.yaml")?;
//! let spec: PolicySpec = serde_yaml::from_str(&yaml)?;
//! let policy = spec.build()?;
//! ```

use serde::{Deserialize, Serialize};

use super::{CelError, Constraint, Policy};
use crate::Operation;

/// A policy specification that can be loaded from YAML/TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySpec {
    /// Policy name (required).
    pub name: String,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Whether to enforce the built-in trifecta constraint.
    /// Default: true (safe by default).
    #[serde(default = "default_enforce_trifecta")]
    pub enforce_trifecta: bool,

    /// List of constraints to apply.
    #[serde(default)]
    pub constraints: Vec<ConstraintSpec>,
}

fn default_enforce_trifecta() -> bool {
    true
}

/// A constraint specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSpec {
    /// Constraint name (required).
    pub name: String,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// CEL condition expression.
    /// When this evaluates to true, obligations are added.
    pub condition: String,

    /// Operations that require approval when condition matches.
    #[serde(default)]
    pub obligations: Vec<OperationName>,
}

/// Operation names for serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationName {
    /// Read files
    ReadFiles,
    /// Write files
    WriteFiles,
    /// Edit files
    EditFiles,
    /// Run bash commands
    RunBash,
    /// Glob search
    GlobSearch,
    /// Grep search
    GrepSearch,
    /// Web search
    WebSearch,
    /// Web fetch
    WebFetch,
    /// Git commit
    GitCommit,
    /// Git push
    GitPush,
    /// Create PR
    CreatePr,
    /// Manage sub-pods
    ManagePods,
}

impl From<OperationName> for Operation {
    fn from(name: OperationName) -> Self {
        match name {
            OperationName::ReadFiles => Operation::ReadFiles,
            OperationName::WriteFiles => Operation::WriteFiles,
            OperationName::EditFiles => Operation::EditFiles,
            OperationName::RunBash => Operation::RunBash,
            OperationName::GlobSearch => Operation::GlobSearch,
            OperationName::GrepSearch => Operation::GrepSearch,
            OperationName::WebSearch => Operation::WebSearch,
            OperationName::WebFetch => Operation::WebFetch,
            OperationName::GitCommit => Operation::GitCommit,
            OperationName::GitPush => Operation::GitPush,
            OperationName::CreatePr => Operation::CreatePr,
            OperationName::ManagePods => Operation::ManagePods,
        }
    }
}

impl From<Operation> for OperationName {
    fn from(op: Operation) -> Self {
        match op {
            Operation::ReadFiles => OperationName::ReadFiles,
            Operation::WriteFiles => OperationName::WriteFiles,
            Operation::EditFiles => OperationName::EditFiles,
            Operation::RunBash => OperationName::RunBash,
            Operation::GlobSearch => OperationName::GlobSearch,
            Operation::GrepSearch => OperationName::GrepSearch,
            Operation::WebSearch => OperationName::WebSearch,
            Operation::WebFetch => OperationName::WebFetch,
            Operation::GitCommit => OperationName::GitCommit,
            Operation::GitPush => OperationName::GitPush,
            Operation::CreatePr => OperationName::CreatePr,
            Operation::ManagePods => OperationName::ManagePods,
        }
    }
}

/// Error type for policy specification parsing.
#[derive(Debug)]
pub enum SpecError {
    /// YAML parsing error.
    Yaml(String),
    /// TOML parsing error.
    Toml(String),
    /// CEL compilation error.
    Cel(CelError),
    /// Validation error.
    Validation(String),
}

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecError::Yaml(msg) => write!(f, "YAML parse error: {}", msg),
            SpecError::Toml(msg) => write!(f, "TOML parse error: {}", msg),
            SpecError::Cel(e) => write!(f, "CEL error: {}", e),
            SpecError::Validation(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for SpecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpecError::Cel(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CelError> for SpecError {
    fn from(e: CelError) -> Self {
        SpecError::Cel(e)
    }
}

impl PolicySpec {
    /// Parse a policy specification from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self, SpecError> {
        serde_yaml::from_str(yaml).map_err(|e| SpecError::Yaml(e.to_string()))
    }

    /// Parse a policy specification from TOML.
    pub fn from_toml(toml_str: &str) -> Result<Self, SpecError> {
        toml::from_str(toml_str).map_err(|e| SpecError::Toml(e.to_string()))
    }

    /// Build a Policy from this specification.
    ///
    /// This validates all CEL expressions and constructs the Policy.
    pub fn build(&self) -> Result<Policy, SpecError> {
        self.validate()?;

        let mut policy = Policy::new(&self.name);

        // Note: enforce_trifecta is always true unless testing feature is enabled
        #[cfg(feature = "testing")]
        if !self.enforce_trifecta {
            policy = policy.without_trifecta();
        }

        for constraint_spec in &self.constraints {
            let constraint = constraint_spec.build()?;
            policy = policy.with_constraint(constraint);
        }

        Ok(policy)
    }

    /// Validate the specification without building.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.name.is_empty() {
            return Err(SpecError::Validation("Policy name cannot be empty".into()));
        }

        for constraint in &self.constraints {
            constraint.validate()?;
        }

        Ok(())
    }

    /// Serialize to YAML.
    pub fn to_yaml(&self) -> Result<String, SpecError> {
        serde_yaml::to_string(self).map_err(|e| SpecError::Yaml(e.to_string()))
    }

    /// Serialize to TOML.
    pub fn to_toml(&self) -> Result<String, SpecError> {
        toml::to_string_pretty(self).map_err(|e| SpecError::Toml(e.to_string()))
    }
}

impl ConstraintSpec {
    /// Build a Constraint from this specification.
    pub fn build(&self) -> Result<Constraint, SpecError> {
        let mut constraint = Constraint::new(&self.name, &self.condition)?;

        if let Some(desc) = &self.description {
            constraint = constraint.with_description(desc);
        }

        for op_name in &self.obligations {
            constraint = constraint.with_obligation((*op_name).into());
        }

        Ok(constraint)
    }

    /// Validate the specification without building.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.name.is_empty() {
            return Err(SpecError::Validation(
                "Constraint name cannot be empty".into(),
            ));
        }

        if self.condition.is_empty() {
            return Err(SpecError::Validation(format!(
                "Constraint '{}' has empty condition",
                self.name
            )));
        }

        // Validate CEL expression compiles
        cel_interpreter::Program::compile(&self.condition)
            .map_err(|e| SpecError::Cel(CelError::Compile(e.to_string())))?;

        Ok(())
    }
}

/// Builder for creating PolicySpec programmatically.
#[derive(Debug, Clone, Default)]
pub struct PolicySpecBuilder {
    name: String,
    description: Option<String>,
    enforce_trifecta: bool,
    constraints: Vec<ConstraintSpec>,
}

impl PolicySpecBuilder {
    /// Create a new builder with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            enforce_trifecta: true,
            constraints: Vec::new(),
        }
    }

    /// Set the description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set whether to enforce trifecta.
    pub fn enforce_trifecta(mut self, enforce: bool) -> Self {
        self.enforce_trifecta = enforce;
        self
    }

    /// Add a constraint.
    pub fn constraint(mut self, spec: ConstraintSpec) -> Self {
        self.constraints.push(spec);
        self
    }

    /// Build the PolicySpec.
    pub fn build(self) -> PolicySpec {
        PolicySpec {
            name: self.name,
            description: self.description,
            enforce_trifecta: self.enforce_trifecta,
            constraints: self.constraints,
        }
    }
}

/// Builder for creating ConstraintSpec programmatically.
#[derive(Debug, Clone, Default)]
pub struct ConstraintSpecBuilder {
    name: String,
    description: Option<String>,
    condition: String,
    obligations: Vec<OperationName>,
}

impl ConstraintSpecBuilder {
    /// Create a new builder with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            condition: String::new(),
            obligations: Vec::new(),
        }
    }

    /// Set the description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the CEL condition.
    pub fn condition(mut self, cel: impl Into<String>) -> Self {
        self.condition = cel.into();
        self
    }

    /// Add an obligation.
    pub fn obligation(mut self, op: OperationName) -> Self {
        self.obligations.push(op);
        self
    }

    /// Build the ConstraintSpec.
    pub fn build(self) -> ConstraintSpec {
        ConstraintSpec {
            name: self.name,
            description: self.description,
            condition: self.condition,
            obligations: self.obligations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_YAML: &str = r#"
name: secure-workspace
description: Enforce workspace boundaries
enforce_trifecta: true

constraints:
  - name: workspace-writes
    description: Require approval for writes outside workspace
    condition: |
      operation == "write_files" && !path.startsWith("/workspace/")
    obligations:
      - write_files

  - name: rate-limit-web
    condition: request_rate > 60
    obligations:
      - web_fetch
      - web_search
"#;

    #[test]
    fn test_parse_yaml() {
        let spec = PolicySpec::from_yaml(EXAMPLE_YAML).unwrap();

        assert_eq!(spec.name, "secure-workspace");
        assert_eq!(
            spec.description,
            Some("Enforce workspace boundaries".to_string())
        );
        assert!(spec.enforce_trifecta);
        assert_eq!(spec.constraints.len(), 2);

        let c1 = &spec.constraints[0];
        assert_eq!(c1.name, "workspace-writes");
        assert_eq!(c1.obligations.len(), 1);
        assert_eq!(c1.obligations[0], OperationName::WriteFiles);

        let c2 = &spec.constraints[1];
        assert_eq!(c2.name, "rate-limit-web");
        assert_eq!(c2.obligations.len(), 2);
    }

    #[test]
    fn test_build_policy() {
        let spec = PolicySpec::from_yaml(EXAMPLE_YAML).unwrap();
        let policy = spec.build().unwrap();

        assert_eq!(policy.name(), "secure-workspace");
        assert_eq!(policy.constraints().len(), 2);
    }

    #[test]
    fn test_invalid_cel() {
        let yaml = r#"
name: bad-policy
constraints:
  - name: bad-constraint
    condition: "invalid {{ cel }}"
    obligations: []
"#;

        let spec = PolicySpec::from_yaml(yaml).unwrap();
        let result = spec.build();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpecError::Cel(_)));
    }

    #[test]
    fn test_validation_empty_name() {
        let spec = PolicySpec {
            name: "".to_string(),
            description: None,
            enforce_trifecta: true,
            constraints: vec![],
        };

        let result = spec.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_api() {
        let spec = PolicySpecBuilder::new("test-policy")
            .description("A test policy")
            .constraint(
                ConstraintSpecBuilder::new("test-constraint")
                    .condition("true")
                    .obligation(OperationName::WriteFiles)
                    .build(),
            )
            .build();

        assert_eq!(spec.name, "test-policy");
        assert_eq!(spec.constraints.len(), 1);

        let policy = spec.build().unwrap();
        assert_eq!(policy.constraints().len(), 1);
    }

    #[test]
    fn test_roundtrip_yaml() {
        let spec = PolicySpecBuilder::new("roundtrip")
            .description("Test roundtrip")
            .constraint(
                ConstraintSpecBuilder::new("c1")
                    .condition("true")
                    .obligation(OperationName::ReadFiles)
                    .build(),
            )
            .build();

        let yaml = spec.to_yaml().unwrap();
        let parsed = PolicySpec::from_yaml(&yaml).unwrap();

        assert_eq!(parsed.name, spec.name);
        assert_eq!(parsed.constraints.len(), spec.constraints.len());
    }

    #[test]
    fn test_toml_parsing() {
        let toml = r#"
name = "toml-policy"
description = "A TOML policy"
enforce_trifecta = true

[[constraints]]
name = "example"
condition = "true"
obligations = ["write_files"]
"#;

        let spec = PolicySpec::from_toml(toml).unwrap();
        assert_eq!(spec.name, "toml-policy");
        assert_eq!(spec.constraints.len(), 1);
    }

    #[test]
    fn test_operation_name_conversion() {
        let op = Operation::GitPush;
        let name: OperationName = op.into();
        let back: Operation = name.into();
        assert_eq!(op, back);
    }
}
