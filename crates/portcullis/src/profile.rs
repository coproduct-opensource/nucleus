//! Declarative profile specification for complete permission lattices.
//!
//! A [`ProfileSpec`] is a YAML/TOML-serializable description of an entire
//! [`PermissionLattice`], including capabilities, paths, budget, time, and
//! optional CEL constraints. Canonical profiles are embedded at compile time
//! and loadable by name via [`ProfileRegistry`].
//!
//! # File Format
//!
//! ```yaml
//! name: safe-pr-fixer
//! description: "Safe PR fixer — no push, no PR creation"
//!
//! capabilities:
//!   read_files: always
//!   write_files: low_risk
//!   git_push: never
//!   create_pr: never
//!
//! paths:
//!   blocked:
//!     - "**/.ssh/**"
//!     - "**/.env"
//!
//! budget:
//!   max_cost_usd: "5.00"
//!
//! time:
//!   duration_hours: 2
//! ```

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::budget::BudgetLattice;
use crate::capability::{CapabilityLevel, Obligations, Operation};
use crate::command::CommandLattice;
use crate::lattice::PermissionLattice;
use crate::path::PathLattice;
use crate::time::TimeLattice;

/// A complete, declarative profile specification.
///
/// Unlike [`PolicySpec`](crate::constraint::spec::PolicySpec) which only
/// describes CEL constraints, a `ProfileSpec` fully declares all lattice
/// dimensions and builds a [`PermissionLattice`] directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSpec {
    /// Profile name (required, must be non-empty).
    pub name: String,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Capability levels for each operation.
    #[serde(default)]
    pub capabilities: CapabilitiesSpec,

    /// Explicit approval obligations (operations requiring human approval).
    #[serde(default)]
    pub obligations: Vec<ObligationSpec>,

    /// Path access restrictions.
    #[serde(default)]
    pub paths: Option<PathsSpec>,

    /// Budget limits.
    #[serde(default)]
    pub budget: Option<BudgetSpec>,

    /// Time bounds.
    #[serde(default)]
    pub time: Option<TimeSpec>,
}

/// Capability levels for all operations.
///
/// Fields default to the lattice default (not `Never`) when omitted,
/// so profiles only need to declare the capabilities they override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesSpec {
    /// Read files permission level.
    #[serde(default = "default_always")]
    pub read_files: CapabilityLevel,
    /// Write files permission level.
    #[serde(default = "default_low_risk")]
    pub write_files: CapabilityLevel,
    /// Edit files permission level.
    #[serde(default = "default_low_risk")]
    pub edit_files: CapabilityLevel,
    /// Run bash commands permission level.
    #[serde(default)]
    pub run_bash: CapabilityLevel,
    /// Glob search permission level.
    #[serde(default = "default_always")]
    pub glob_search: CapabilityLevel,
    /// Grep search permission level.
    #[serde(default = "default_always")]
    pub grep_search: CapabilityLevel,
    /// Web search permission level.
    #[serde(default = "default_low_risk")]
    pub web_search: CapabilityLevel,
    /// Web fetch permission level.
    #[serde(default = "default_low_risk")]
    pub web_fetch: CapabilityLevel,
    /// Git commit permission level.
    #[serde(default = "default_low_risk")]
    pub git_commit: CapabilityLevel,
    /// Git push permission level.
    #[serde(default)]
    pub git_push: CapabilityLevel,
    /// Create PR permission level.
    #[serde(default = "default_low_risk")]
    pub create_pr: CapabilityLevel,
    /// Manage sub-pods permission level.
    #[serde(default)]
    pub manage_pods: CapabilityLevel,
}

fn default_always() -> CapabilityLevel {
    CapabilityLevel::Always
}

fn default_low_risk() -> CapabilityLevel {
    CapabilityLevel::LowRisk
}

impl Default for CapabilitiesSpec {
    fn default() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::LowRisk,
            edit_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::LowRisk,
            web_fetch: CapabilityLevel::LowRisk,
            git_commit: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::LowRisk,
            manage_pods: CapabilityLevel::Never,
        }
    }
}

/// An operation requiring explicit human approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationSpec {
    /// Read files requires approval.
    ReadFiles,
    /// Write files requires approval.
    WriteFiles,
    /// Edit files requires approval.
    EditFiles,
    /// Run bash requires approval.
    RunBash,
    /// Glob search requires approval.
    GlobSearch,
    /// Grep search requires approval.
    GrepSearch,
    /// Web search requires approval.
    WebSearch,
    /// Web fetch requires approval.
    WebFetch,
    /// Git commit requires approval.
    GitCommit,
    /// Git push requires approval.
    GitPush,
    /// Create PR requires approval.
    CreatePr,
    /// Manage pods requires approval.
    ManagePods,
}

impl From<&ObligationSpec> for Operation {
    fn from(spec: &ObligationSpec) -> Self {
        match spec {
            ObligationSpec::ReadFiles => Operation::ReadFiles,
            ObligationSpec::WriteFiles => Operation::WriteFiles,
            ObligationSpec::EditFiles => Operation::EditFiles,
            ObligationSpec::RunBash => Operation::RunBash,
            ObligationSpec::GlobSearch => Operation::GlobSearch,
            ObligationSpec::GrepSearch => Operation::GrepSearch,
            ObligationSpec::WebSearch => Operation::WebSearch,
            ObligationSpec::WebFetch => Operation::WebFetch,
            ObligationSpec::GitCommit => Operation::GitCommit,
            ObligationSpec::GitPush => Operation::GitPush,
            ObligationSpec::CreatePr => Operation::CreatePr,
            ObligationSpec::ManagePods => Operation::ManagePods,
        }
    }
}

/// Path access specification.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathsSpec {
    /// Allowed path glob patterns. Empty means "all allowed".
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Blocked path glob patterns (checked first, takes priority).
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Budget specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetSpec {
    /// Maximum cost in USD (string to preserve decimal precision).
    #[serde(default = "default_max_cost")]
    pub max_cost_usd: String,
    /// Maximum input tokens.
    #[serde(default = "default_input_tokens")]
    pub max_input_tokens: u64,
    /// Maximum output tokens.
    #[serde(default = "default_output_tokens")]
    pub max_output_tokens: u64,
}

fn default_max_cost() -> String {
    "5.00".to_string()
}

fn default_input_tokens() -> u64 {
    100_000
}

fn default_output_tokens() -> u64 {
    10_000
}

impl Default for BudgetSpec {
    fn default() -> Self {
        Self {
            max_cost_usd: default_max_cost(),
            max_input_tokens: default_input_tokens(),
            max_output_tokens: default_output_tokens(),
        }
    }
}

/// Time bounds specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSpec {
    /// Duration in hours (convenience, mutually exclusive with duration_minutes).
    #[serde(default)]
    pub duration_hours: Option<u64>,
    /// Duration in minutes (convenience, mutually exclusive with duration_hours).
    #[serde(default)]
    pub duration_minutes: Option<u64>,
}

/// Error from profile specification operations.
#[derive(Debug)]
pub enum ProfileError {
    /// YAML parsing error.
    Yaml(String),
    /// TOML parsing error.
    Toml(String),
    /// Validation error.
    Validation(String),
    /// Budget value parse error.
    Budget(String),
    /// Profile not found.
    NotFound(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Yaml(msg) => write!(f, "YAML parse error: {}", msg),
            ProfileError::Toml(msg) => write!(f, "TOML parse error: {}", msg),
            ProfileError::Validation(msg) => write!(f, "Validation error: {}", msg),
            ProfileError::Budget(msg) => write!(f, "Budget parse error: {}", msg),
            ProfileError::NotFound(name) => write!(f, "Profile not found: {}", name),
        }
    }
}

impl std::error::Error for ProfileError {}

impl ProfileSpec {
    /// Parse a profile specification from YAML.
    pub fn from_yaml(yaml: &str) -> Result<Self, ProfileError> {
        serde_yaml::from_str(yaml).map_err(|e| ProfileError::Yaml(e.to_string()))
    }

    /// Parse a profile specification from TOML.
    pub fn from_toml(toml_str: &str) -> Result<Self, ProfileError> {
        toml::from_str(toml_str).map_err(|e| ProfileError::Toml(e.to_string()))
    }

    /// Validate the profile specification.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.name.is_empty() {
            return Err(ProfileError::Validation(
                "Profile name cannot be empty".into(),
            ));
        }

        if let Some(budget) = &self.budget {
            rust_decimal::Decimal::from_str_exact(&budget.max_cost_usd).map_err(|e| {
                ProfileError::Budget(format!(
                    "invalid max_cost_usd '{}': {}",
                    budget.max_cost_usd, e
                ))
            })?;
        }

        if let Some(time) = &self.time {
            if time.duration_hours.is_none() && time.duration_minutes.is_none() {
                return Err(ProfileError::Validation(
                    "time must specify duration_hours or duration_minutes".into(),
                ));
            }
        }

        Ok(())
    }

    /// Build a [`PermissionLattice`] from this profile specification.
    ///
    /// The resulting lattice is always normalized (trifecta enforcement applied).
    pub fn build(&self) -> Result<PermissionLattice, ProfileError> {
        self.validate()?;

        let capabilities = crate::capability::CapabilityLattice {
            read_files: self.capabilities.read_files,
            write_files: self.capabilities.write_files,
            edit_files: self.capabilities.edit_files,
            run_bash: self.capabilities.run_bash,
            glob_search: self.capabilities.glob_search,
            grep_search: self.capabilities.grep_search,
            web_search: self.capabilities.web_search,
            web_fetch: self.capabilities.web_fetch,
            git_commit: self.capabilities.git_commit,
            git_push: self.capabilities.git_push,
            create_pr: self.capabilities.create_pr,
            manage_pods: self.capabilities.manage_pods,
            #[cfg(not(kani))]
            extensions: std::collections::BTreeMap::new(),
        };

        let mut obligations = Obligations::default();
        for ob in &self.obligations {
            obligations.insert(Operation::from(ob));
        }

        let paths = match &self.paths {
            Some(spec) => PathLattice {
                allowed: spec.allowed.iter().cloned().collect::<HashSet<_>>(),
                blocked: spec.blocked.iter().cloned().collect::<HashSet<_>>(),
                work_dir: None,
            },
            None => PathLattice::default(),
        };

        let budget = match &self.budget {
            Some(spec) => {
                let max_cost = rust_decimal::Decimal::from_str_exact(&spec.max_cost_usd)
                    .map_err(|e| ProfileError::Budget(e.to_string()))?;
                BudgetLattice {
                    max_cost_usd: max_cost,
                    consumed_usd: rust_decimal::Decimal::ZERO,
                    max_input_tokens: spec.max_input_tokens,
                    max_output_tokens: spec.max_output_tokens,
                }
            }
            None => BudgetLattice::default(),
        };

        let time = match &self.time {
            Some(spec) => {
                if let Some(hours) = spec.duration_hours {
                    TimeLattice::hours(hours as i64)
                } else if let Some(minutes) = spec.duration_minutes {
                    TimeLattice::minutes(minutes as i64)
                } else {
                    TimeLattice::default()
                }
            }
            None => TimeLattice::default(),
        };

        let description = self
            .description
            .clone()
            .unwrap_or_else(|| format!("{} profile", self.name));

        let lattice = PermissionLattice {
            id: uuid::Uuid::new_v4(),
            description,
            derived_from: None,
            capabilities,
            obligations,
            paths,
            budget,
            commands: CommandLattice::permissive(),
            time,
            trifecta_constraint: true,
            minimum_isolation: None,
            created_at: chrono::Utc::now(),
            created_by: "profile".to_string(),
        };

        Ok(lattice.normalize())
    }

    /// Serialize to YAML.
    pub fn to_yaml(&self) -> Result<String, ProfileError> {
        serde_yaml::to_string(self).map_err(|e| ProfileError::Yaml(e.to_string()))
    }
}

// ── Canonical profiles (embedded at compile time) ─────────────────────

const SAFE_PR_FIXER_YAML: &str = include_str!("../profiles/safe-pr-fixer.yaml");
const DOC_EDITOR_YAML: &str = include_str!("../profiles/doc-editor.yaml");
const TEST_RUNNER_YAML: &str = include_str!("../profiles/test-runner.yaml");
const TRIAGE_BOT_YAML: &str = include_str!("../profiles/triage-bot.yaml");
const CODE_REVIEW_YAML: &str = include_str!("../profiles/code-review.yaml");
const CODEGEN_YAML: &str = include_str!("../profiles/codegen.yaml");
const RELEASE_YAML: &str = include_str!("../profiles/release.yaml");
const RESEARCH_WEB_YAML: &str = include_str!("../profiles/research-web.yaml");
const READ_ONLY_YAML: &str = include_str!("../profiles/read-only.yaml");
const LOCAL_DEV_YAML: &str = include_str!("../profiles/local-dev.yaml");

/// Registry of named profiles, combining embedded canonical profiles
/// with optional user-supplied ones.
#[derive(Debug)]
pub struct ProfileRegistry {
    profiles: Vec<ProfileSpec>,
}

impl ProfileRegistry {
    /// Create a registry with only the canonical (embedded) profiles.
    pub fn canonical() -> Result<Self, ProfileError> {
        let profiles = vec![
            ProfileSpec::from_yaml(SAFE_PR_FIXER_YAML)?,
            ProfileSpec::from_yaml(DOC_EDITOR_YAML)?,
            ProfileSpec::from_yaml(TEST_RUNNER_YAML)?,
            ProfileSpec::from_yaml(TRIAGE_BOT_YAML)?,
            ProfileSpec::from_yaml(CODE_REVIEW_YAML)?,
            ProfileSpec::from_yaml(CODEGEN_YAML)?,
            ProfileSpec::from_yaml(RELEASE_YAML)?,
            ProfileSpec::from_yaml(RESEARCH_WEB_YAML)?,
            ProfileSpec::from_yaml(READ_ONLY_YAML)?,
            ProfileSpec::from_yaml(LOCAL_DEV_YAML)?,
        ];
        Ok(Self { profiles })
    }

    /// Add a profile to the registry.
    pub fn register(&mut self, spec: ProfileSpec) {
        // Replace existing profile with same name
        self.profiles.retain(|p| p.name != spec.name);
        self.profiles.push(spec);
    }

    /// Look up a profile by name and build a [`PermissionLattice`].
    ///
    /// Name matching is case-insensitive and normalizes hyphens/underscores.
    pub fn resolve(&self, name: &str) -> Result<PermissionLattice, ProfileError> {
        let normalized = name.to_lowercase().replace('_', "-");
        self.profiles
            .iter()
            .find(|p| p.name.to_lowercase().replace('_', "-") == normalized)
            .ok_or_else(|| ProfileError::NotFound(name.to_string()))?
            .build()
    }

    /// List all registered profile names.
    pub fn names(&self) -> Vec<&str> {
        self.profiles.iter().map(|p| p.name.as_str()).collect()
    }

    /// Get the raw [`ProfileSpec`] for a profile by name.
    pub fn get(&self, name: &str) -> Option<&ProfileSpec> {
        let normalized = name.to_lowercase().replace('_', "-");
        self.profiles
            .iter()
            .find(|p| p.name.to_lowercase().replace('_', "-") == normalized)
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::canonical().expect("canonical profiles must parse")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_profiles_parse() {
        let registry = ProfileRegistry::canonical().unwrap();
        assert_eq!(registry.names().len(), 10);
        assert!(registry.names().contains(&"safe-pr-fixer"));
        assert!(registry.names().contains(&"doc-editor"));
        assert!(registry.names().contains(&"test-runner"));
        assert!(registry.names().contains(&"triage-bot"));
        assert!(registry.names().contains(&"code-review"));
        assert!(registry.names().contains(&"codegen"));
        assert!(registry.names().contains(&"release"));
        assert!(registry.names().contains(&"research-web"));
        assert!(registry.names().contains(&"read-only"));
        assert!(registry.names().contains(&"local-dev"));
    }

    #[test]
    fn test_canonical_profiles_build() {
        let registry = ProfileRegistry::canonical().unwrap();
        for name in registry.names() {
            let lattice = registry.resolve(name);
            assert!(
                lattice.is_ok(),
                "canonical profile '{}' should build: {:?}",
                name,
                lattice.err()
            );
        }
    }

    #[test]
    fn test_safe_pr_fixer_breaks_trifecta() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("safe-pr-fixer").unwrap();

        // Core invariant: cannot push or create PRs
        assert_eq!(
            lattice.capabilities.git_push,
            CapabilityLevel::Never,
            "safe-pr-fixer must not allow git push"
        );
        assert_eq!(
            lattice.capabilities.create_pr,
            CapabilityLevel::Never,
            "safe-pr-fixer must not allow PR creation"
        );

        // Can read, write, edit, commit
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.git_commit, CapabilityLevel::LowRisk);
    }

    #[test]
    fn test_doc_editor_scoped() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("doc-editor").unwrap();

        // Doc editor should be able to read and write
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::LowRisk);

        // No network exfiltration
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::Never);
    }

    #[test]
    fn test_test_runner_no_write() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("test-runner").unwrap();

        // Test runner can execute but not write source
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);

        // Cannot push, create PRs
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::Never);
    }

    #[test]
    fn test_triage_bot_read_only() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("triage-bot").unwrap();

        // Triage bot reads and searches, no code changes
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.glob_search, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.grep_search, CapabilityLevel::Always);

        // No write, no push, no bash
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::Never);
    }

    #[test]
    fn test_code_review_no_modifications() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("code-review").unwrap();

        // Can read and search
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.glob_search, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.grep_search, CapabilityLevel::Always);

        // Web search allowed with approval
        assert_eq!(lattice.capabilities.web_search, CapabilityLevel::LowRisk);
        assert!(lattice.requires_approval(Operation::WebSearch));

        // No modifications, no execution, no push
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::Never);
    }

    #[test]
    fn test_codegen_network_isolated() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("codegen").unwrap();

        // Full local dev capabilities
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.edit_files, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.git_commit, CapabilityLevel::LowRisk);

        // Network isolated — no web access
        assert_eq!(lattice.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.web_fetch, CapabilityLevel::Never);

        // No push or PR creation
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::Never);
    }

    #[test]
    fn test_release_approval_on_publish() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("release").unwrap();

        // Has push and PR capabilities
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::LowRisk);

        // But they require approval (trifecta: read + web + exfil)
        assert!(lattice.requires_approval(Operation::GitPush));
        assert!(lattice.requires_approval(Operation::CreatePr));

        // Full read/write/edit/run
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::LowRisk);
    }

    #[test]
    fn test_research_web_no_exfil() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("research-web").unwrap();

        // Read (low_risk) + web access
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.web_search, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.web_fetch, CapabilityLevel::LowRisk);

        // No write, no edit, no execution, no push
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::Never);
    }

    #[test]
    fn test_read_only_minimal() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("read-only").unwrap();

        // Can read and search
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.glob_search, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.grep_search, CapabilityLevel::Always);

        // Everything else is Never
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.web_fetch, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.git_commit, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.manage_pods, CapabilityLevel::Never);
    }

    #[test]
    fn test_local_dev_no_network() {
        let registry = ProfileRegistry::canonical().unwrap();
        let lattice = registry.resolve("local-dev").unwrap();

        // Full local capabilities
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.edit_files, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::LowRisk);
        assert_eq!(lattice.capabilities.git_commit, CapabilityLevel::LowRisk);

        // No network
        assert_eq!(lattice.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.web_fetch, CapabilityLevel::Never);

        // No push
        assert_eq!(lattice.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.create_pr, CapabilityLevel::Never);
    }

    #[test]
    fn test_name_normalization() {
        let registry = ProfileRegistry::canonical().unwrap();

        // Hyphens and underscores should be interchangeable
        assert!(registry.resolve("safe-pr-fixer").is_ok());
        assert!(registry.resolve("safe_pr_fixer").is_ok());

        // Case-insensitive
        assert!(registry.resolve("Safe-PR-Fixer").is_ok());

        // Unknown profile
        assert!(registry.resolve("nonexistent").is_err());
    }

    #[test]
    fn test_custom_profile_yaml() {
        let yaml = r#"
name: custom-agent
description: "A custom agent profile"
capabilities:
  read_files: always
  write_files: never
  run_bash: low_risk
  git_push: never
obligations:
  - run_bash
paths:
  blocked:
    - "**/.ssh/**"
budget:
  max_cost_usd: "1.50"
time:
  duration_minutes: 30
"#;

        let spec = ProfileSpec::from_yaml(yaml).unwrap();
        assert_eq!(spec.name, "custom-agent");

        let lattice = spec.build().unwrap();
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(lattice.capabilities.run_bash, CapabilityLevel::LowRisk);
        assert!(lattice.requires_approval(Operation::RunBash));
    }

    #[test]
    fn test_register_custom_profile() {
        let mut registry = ProfileRegistry::canonical().unwrap();

        let spec = ProfileSpec::from_yaml(
            r#"
name: my-profile
capabilities:
  read_files: always
  write_files: never
"#,
        )
        .unwrap();

        registry.register(spec);
        assert!(registry.names().contains(&"my-profile"));
        assert!(registry.resolve("my-profile").is_ok());
    }

    #[test]
    fn test_validation_empty_name() {
        let spec = ProfileSpec {
            name: "".to_string(),
            description: None,
            capabilities: CapabilitiesSpec::default(),
            obligations: vec![],
            paths: None,
            budget: None,
            time: None,
        };

        assert!(spec.build().is_err());
    }

    #[test]
    fn test_validation_invalid_budget() {
        let yaml = r#"
name: bad-budget
budget:
  max_cost_usd: "not-a-number"
"#;

        let spec = ProfileSpec::from_yaml(yaml).unwrap();
        assert!(spec.build().is_err());
    }

    #[test]
    fn test_roundtrip_yaml() {
        let yaml = r#"
name: roundtrip-test
description: "Test roundtrip"
capabilities:
  read_files: always
  write_files: low_risk
  git_push: never
"#;

        let spec = ProfileSpec::from_yaml(yaml).unwrap();
        let serialized = spec.to_yaml().unwrap();
        let parsed = ProfileSpec::from_yaml(&serialized).unwrap();

        assert_eq!(spec.name, parsed.name);
        assert_eq!(spec.capabilities.read_files, parsed.capabilities.read_files);
        assert_eq!(spec.capabilities.git_push, parsed.capabilities.git_push);
    }
}
