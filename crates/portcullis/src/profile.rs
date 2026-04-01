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

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

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
    /// Spawn sub-agent permission level.
    #[serde(default)]
    pub spawn_agent: CapabilityLevel,
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
            spawn_agent: CapabilityLevel::Never,
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
    /// Spawn agent requires approval.
    SpawnAgent,
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
            ObligationSpec::SpawnAgent => Operation::SpawnAgent,
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

/// The source from which a profile was loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSource {
    /// Embedded at compile time (canonical built-in).
    Builtin,
    /// Loaded at runtime from a directory on disk.
    Directory(String),
}

impl std::fmt::Display for ProfileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileSource::Builtin => write!(f, "built-in"),
            ProfileSource::Directory(path) => write!(f, "{}", path),
        }
    }
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
    /// Filesystem I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Yaml(msg) => write!(f, "YAML parse error: {}", msg),
            ProfileError::Toml(msg) => write!(f, "TOML parse error: {}", msg),
            ProfileError::Validation(msg) => write!(f, "Validation error: {}", msg),
            ProfileError::Budget(msg) => write!(f, "Budget parse error: {}", msg),
            ProfileError::NotFound(name) => write!(f, "Profile not found: {}", name),
            ProfileError::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl From<std::io::Error> for ProfileError {
    fn from(err: std::io::Error) -> Self {
        ProfileError::Io(err)
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
    /// The resulting lattice is always normalized (uninhabitable_state enforcement applied).
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
            spawn_agent: self.capabilities.spawn_agent,
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
            uninhabitable_constraint: true,
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

/// A profile entry with its specification and provenance.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    /// The profile specification.
    pub spec: ProfileSpec,
    /// Where this profile was loaded from.
    pub source: ProfileSource,
}

/// Registry of named profiles, combining embedded canonical profiles
/// with optional runtime-loaded ones.
///
/// Profiles are stored in a [`BTreeMap`] keyed by normalized name
/// (lowercase, hyphens). When profiles from different sources share a
/// name, the last one registered wins — enabling runtime overrides of
/// built-in defaults.
#[derive(Debug)]
pub struct ProfileRegistry {
    profiles: BTreeMap<String, ProfileEntry>,
}

/// Normalize a profile name for lookup: lowercase, underscores to hyphens.
fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

impl ProfileRegistry {
    /// Create an empty registry with no profiles.
    pub fn empty() -> Self {
        Self {
            profiles: BTreeMap::new(),
        }
    }

    /// Create a registry with only the canonical (embedded) profiles.
    ///
    /// This is the backward-compatible constructor — all compile-time
    /// profiles are available immediately.
    pub fn canonical() -> Result<Self, ProfileError> {
        let mut registry = Self::empty();
        let builtins = vec![
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
        for spec in builtins {
            registry.register_with_source(spec, ProfileSource::Builtin);
        }
        Ok(registry)
    }

    /// Alias for [`canonical()`](Self::canonical) — creates a registry
    /// pre-loaded with the compile-time built-in profiles.
    pub fn with_builtins() -> Result<Self, ProfileError> {
        Self::canonical()
    }

    /// Load profiles from a directory on disk.
    ///
    /// Reads all `*.yaml`, `*.yml`, and `*.toml` files in the given
    /// directory. Each file must contain a valid [`ProfileSpec`]. Files
    /// that fail to parse or validate are returned as errors rather than
    /// silently ignored.
    ///
    /// Returns an empty registry if the directory does not exist (this is
    /// not an error — the directory is optional).
    pub fn load_from_dir(dir: &Path) -> Result<Self, ProfileError> {
        let mut registry = Self::empty();

        if !dir.exists() {
            return Ok(registry);
        }

        let entries = std::fs::read_dir(dir)?;
        let dir_str = dir.display().to_string();

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Skip non-files (directories, symlinks to dirs, etc.)
            if !path.is_file() {
                continue;
            }

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            let spec = match ext.as_str() {
                "yaml" | "yml" => {
                    let content = std::fs::read_to_string(&path)?;
                    ProfileSpec::from_yaml(&content).map_err(|e| {
                        ProfileError::Validation(format!("{}: {}", path.display(), e))
                    })?
                }
                "toml" => {
                    let content = std::fs::read_to_string(&path)?;
                    ProfileSpec::from_toml(&content).map_err(|e| {
                        ProfileError::Validation(format!("{}: {}", path.display(), e))
                    })?
                }
                _ => continue, // Skip files with unrecognized extensions
            };

            // Validate eagerly so callers get errors at load time.
            spec.validate()
                .map_err(|e| ProfileError::Validation(format!("{}: {}", path.display(), e)))?;

            registry.register_with_source(spec, ProfileSource::Directory(dir_str.clone()));
        }

        Ok(registry)
    }

    /// Add a profile to the registry with explicit provenance.
    pub fn register_with_source(&mut self, spec: ProfileSpec, source: ProfileSource) {
        let key = normalize_name(&spec.name);
        self.profiles.insert(key, ProfileEntry { spec, source });
    }

    /// Add a profile to the registry.
    ///
    /// The profile source is set to [`ProfileSource::Builtin`] for
    /// backward compatibility. Prefer [`register_with_source`](Self::register_with_source)
    /// when the provenance is known.
    pub fn register(&mut self, spec: ProfileSpec) {
        self.register_with_source(spec, ProfileSource::Builtin);
    }

    /// Look up a profile by name and build a [`PermissionLattice`].
    ///
    /// Name matching is case-insensitive and normalizes hyphens/underscores.
    pub fn resolve(&self, name: &str) -> Result<PermissionLattice, ProfileError> {
        let key = normalize_name(name);
        self.profiles
            .get(&key)
            .ok_or_else(|| ProfileError::NotFound(name.to_string()))?
            .spec
            .build()
    }

    /// List all registered profile names (normalized).
    pub fn names(&self) -> Vec<&str> {
        self.profiles
            .values()
            .map(|e| e.spec.name.as_str())
            .collect()
    }

    /// Get the raw [`ProfileSpec`] for a profile by name.
    pub fn get(&self, name: &str) -> Option<&ProfileSpec> {
        let key = normalize_name(name);
        self.profiles.get(&key).map(|e| &e.spec)
    }

    /// Get the [`ProfileEntry`] (spec + source) for a profile by name.
    pub fn get_entry(&self, name: &str) -> Option<&ProfileEntry> {
        let key = normalize_name(name);
        self.profiles.get(&key)
    }

    /// Merge another registry into this one.
    ///
    /// Profiles from `other` take precedence: if both registries contain
    /// a profile with the same normalized name, the one from `other` wins.
    pub fn merge(&mut self, other: ProfileRegistry) {
        for (key, entry) in other.profiles {
            self.profiles.insert(key, entry);
        }
    }

    /// Return the number of profiles in the registry.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Return true if the registry contains no profiles.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
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
        assert_eq!(registry.len(), 10);
        let names = registry.names();
        assert!(names.contains(&"safe-pr-fixer"));
        assert!(names.contains(&"doc-editor"));
        assert!(names.contains(&"test-runner"));
        assert!(names.contains(&"triage-bot"));
        assert!(names.contains(&"code-review"));
        assert!(names.contains(&"codegen"));
        assert!(names.contains(&"release"));
        assert!(names.contains(&"research-web"));
        assert!(names.contains(&"read-only"));
        assert!(names.contains(&"local-dev"));
    }

    #[test]
    fn test_builtin_provenance() {
        let registry = ProfileRegistry::canonical().unwrap();
        let entry = registry.get_entry("codegen").unwrap();
        assert_eq!(entry.source, ProfileSource::Builtin);
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
    fn test_safe_pr_fixer_breaks_uninhabitable() {
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

        // But they require approval (uninhabitable_state: read + web + exfil)
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

    // ── Runtime loading tests ───────────────────────────────────────

    #[test]
    fn test_load_from_dir_yaml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("my-agent.yaml"),
            r#"
name: my-agent
description: "loaded at runtime"
capabilities:
  read_files: always
  write_files: never
  git_push: never
budget:
  max_cost_usd: "2.00"
"#,
        )
        .unwrap();

        let registry = ProfileRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(registry.len(), 1);

        let lattice = registry.resolve("my-agent").unwrap();
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::Never);

        let entry = registry.get_entry("my-agent").unwrap();
        assert!(matches!(entry.source, ProfileSource::Directory(_)));
    }

    #[test]
    fn test_load_from_dir_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("toml-agent.toml"),
            r#"
name = "toml-agent"
description = "loaded from TOML"

[capabilities]
read_files = "always"
write_files = "never"
git_push = "never"

[budget]
max_cost_usd = "3.00"
"#,
        )
        .unwrap();

        let registry = ProfileRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(registry.len(), 1);

        let lattice = registry.resolve("toml-agent").unwrap();
        assert_eq!(lattice.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lattice.capabilities.write_files, CapabilityLevel::Never);
    }

    #[test]
    fn test_load_from_dir_nonexistent_is_empty() {
        let registry =
            ProfileRegistry::load_from_dir(Path::new("/tmp/does-not-exist-nucleus-test")).unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_load_from_dir_skips_unknown_extensions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.md"), "# Not a profile").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "some notes").unwrap();

        let registry = ProfileRegistry::load_from_dir(dir.path()).unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_load_from_dir_invalid_yaml_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.yaml"), "{{invalid yaml").unwrap();

        let result = ProfileRegistry::load_from_dir(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_dir_invalid_profile_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // Valid YAML but empty name fails validation.
        std::fs::write(
            dir.path().join("empty-name.yaml"),
            r#"
name: ""
capabilities:
  read_files: always
"#,
        )
        .unwrap();

        let result = ProfileRegistry::load_from_dir(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_runtime_overrides_builtin() {
        let mut builtins = ProfileRegistry::canonical().unwrap();

        // Verify the built-in codegen allows write_files
        let builtin_codegen = builtins.resolve("codegen").unwrap();
        assert_eq!(
            builtin_codegen.capabilities.write_files,
            CapabilityLevel::LowRisk
        );

        // Create a runtime override that disables write_files
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("codegen.yaml"),
            r#"
name: codegen
description: "Stricter codegen — read-only"
capabilities:
  read_files: always
  write_files: never
  git_push: never
"#,
        )
        .unwrap();

        let runtime = ProfileRegistry::load_from_dir(dir.path()).unwrap();
        builtins.merge(runtime);

        // After merge, the runtime version wins.
        let merged_codegen = builtins.resolve("codegen").unwrap();
        assert_eq!(
            merged_codegen.capabilities.write_files,
            CapabilityLevel::Never
        );

        // The entry should show directory provenance.
        let entry = builtins.get_entry("codegen").unwrap();
        assert!(matches!(entry.source, ProfileSource::Directory(_)));

        // Other builtins are unaffected.
        assert!(builtins.resolve("safe-pr-fixer").is_ok());
    }

    #[test]
    fn test_merge_adds_new_profiles() {
        let mut builtins = ProfileRegistry::canonical().unwrap();
        let initial_count = builtins.len();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("brand-new.yaml"),
            r#"
name: brand-new
capabilities:
  read_files: always
  git_push: never
"#,
        )
        .unwrap();

        let runtime = ProfileRegistry::load_from_dir(dir.path()).unwrap();
        builtins.merge(runtime);

        assert_eq!(builtins.len(), initial_count + 1);
        assert!(builtins.resolve("brand-new").is_ok());
    }

    #[test]
    fn test_with_builtins_alias() {
        let a = ProfileRegistry::canonical().unwrap();
        let b = ProfileRegistry::with_builtins().unwrap();
        assert_eq!(a.len(), b.len());
        for name in a.names() {
            assert!(b.resolve(name).is_ok());
        }
    }

    #[test]
    fn test_load_multiple_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("alpha.yaml"),
            "name: alpha\ncapabilities:\n  read_files: always\n  git_push: never\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("beta.toml"),
            "name = \"beta\"\n\n[capabilities]\nread_files = \"always\"\ngit_push = \"never\"\n",
        )
        .unwrap();

        let registry = ProfileRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(registry.len(), 2);
        assert!(registry.resolve("alpha").is_ok());
        assert!(registry.resolve("beta").is_ok());
    }
}
