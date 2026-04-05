//! `NucleusRuntime` — batteries-included entry point for agent builders (#1193).
//!
//! Wires together `CapabilityLattice` (profiles), `FlowTracker` (IFC),
//! `preflight_action()` (obligation discharge), and `PolicyEnforced` (effects)
//! behind a single, opinionated API.
//!
//! ## 10-line safe session
//!
//! ```rust,ignore
//! use portcullis_effects::runtime::{NucleusRuntime, PolicyProfile};
//!
//! let rt = NucleusRuntime::builder()
//!     .profile(PolicyProfile::Research)
//!     .task("summarize SEC filings")
//!     .build();
//!
//! let data = rt.file().read_str(Path::new("input.txt"))?;
//! let page = rt.web().fetch("https://sec.gov/...")?;
//! rt.file().write(Path::new("output/summary.txt"), summary.as_bytes())?;
//! ```
//!
//! ## Design
//!
//! `NucleusRuntime` is a **facade**, not a framework. It composes existing
//! crate machinery and exposes it through named accessors. Advanced users
//! can still call `production_effects()` and `FlowTracker` directly.

use std::path::{Path, PathBuf};

use portcullis_core::discharge::{preflight_action, ActionTerm, PreflightResult};
use portcullis_core::flow::NodeKind;
use portcullis_core::ifc_api::FlowTracker;
use portcullis_core::{CapabilityLattice, CapabilityLevel, IFCLabel, Operation, SinkClass};

use crate::{
    production_effects, AgentSpawnEffect, EffectError, FileEffect, GitEffect, ShellEffect,
    ShellOutput, WebEffect,
};

// ═══════════════════════════════════════════════════════════════════════════
// PolicyProfile — named capability presets
// ═══════════════════════════════════════════════════════════════════════════

/// Named policy profiles for common agent work patterns.
///
/// Each profile maps to a [`CapabilityLattice`] with secure defaults.
/// Use these instead of constructing a `CapabilityLattice` manually.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyProfile {
    /// Read-only: read + glob + grep. No writes, no network, no shell.
    ReadOnly,
    /// Research: read + glob + grep + web fetch + web search.
    /// No writes, no shell, no git.
    Research,
    /// Codegen: read + write + edit + bash + glob + grep + git commit.
    /// No network, no push.
    Codegen,
    /// Review: read + glob + grep + web + git commit + push + create_pr.
    /// No writes, no shell.
    Review,
    /// Strict: same as default `CapabilityLattice` — balanced profile with
    /// `LowRisk` for common operations, `Never` for dangerous ones.
    Strict,
    /// Permissive: all capabilities at `Always`. **Development only.**
    /// Logs a warning at construction time.
    Permissive,
}

impl PolicyProfile {
    /// Convert this profile to its `CapabilityLattice` representation.
    pub fn to_lattice(self) -> CapabilityLattice {
        match self {
            Self::ReadOnly => CapabilityLattice::for_read_only(),
            Self::Research => CapabilityLattice::for_research(),
            Self::Codegen => CapabilityLattice::for_codegen(),
            Self::Review => CapabilityLattice::for_review(),
            Self::Strict => CapabilityLattice::default(),
            Self::Permissive => CapabilityLattice::top(),
        }
    }

    /// Human-readable name for error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Research => "research",
            Self::Codegen => "codegen",
            Self::Review => "review",
            Self::Strict => "strict",
            Self::Permissive => "permissive",
        }
    }
}

impl std::fmt::Display for PolicyProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RuntimeError — user-facing error with domain language
// ═══════════════════════════════════════════════════════════════════════════

/// Error from `NucleusRuntime` operations.
///
/// Messages use domain language ("you attempted to write to /etc/passwd")
/// rather than implementation terms ("PathAllowed obligation unsatisfied").
#[derive(Debug)]
pub enum RuntimeError {
    /// An effect was denied by the policy.
    Denied {
        /// What the caller tried to do (e.g., "write to /etc/passwd").
        attempted: String,
        /// Why it was denied (e.g., "write_files capability is Never").
        reason: String,
        /// Suggestion for fixing (e.g., "use PolicyProfile::Codegen").
        suggestion: String,
    },
    /// An I/O error occurred after policy approval.
    Io(String),
    /// The runtime was not configured correctly.
    Config(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied {
                attempted,
                reason,
                suggestion,
            } => {
                writeln!(f, "action denied")?;
                writeln!(f, "  attempted: {attempted}")?;
                writeln!(f, "  reason: {reason}")?;
                write!(f, "  fix: {suggestion}")
            }
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<EffectError> for RuntimeError {
    fn from(e: EffectError) -> Self {
        match e {
            EffectError::PolicyDenied(msg) => Self::Denied {
                attempted: "effect call".to_string(),
                reason: msg,
                suggestion: "check your PolicyProfile or CapabilityLattice configuration"
                    .to_string(),
            },
            EffectError::PathViolation(msg) => Self::Denied {
                attempted: format!("path access: {msg}"),
                reason: "path is outside allowed scope".to_string(),
                suggestion: "add the path to allowed_write_paths or use a profile that permits it"
                    .to_string(),
            },
            EffectError::Io(msg) => Self::Io(msg),
            EffectError::CommandFailed { exit_code, stderr } => {
                Self::Io(format!("command failed (exit={exit_code:?}): {stderr}"))
            }
            EffectError::NotImplemented(feat) => {
                Self::Config(format!("feature not available: {feat}"))
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// NucleusRuntime — the batteries-included facade
// ═══════════════════════════════════════════════════════════════════════════

/// Batteries-included entry point for building secure agents on nucleus.
///
/// Wires together:
/// - **Policy** — a [`CapabilityLattice`] from a named [`PolicyProfile`] or custom builder
/// - **Effects** — `PolicyEnforced` effect handlers for file, web, shell, git
/// - **IFC** — a [`FlowTracker`] for integrity/confidentiality tracking
///
/// ## Quick start
///
/// ```rust
/// use portcullis_effects::runtime::{NucleusRuntime, PolicyProfile};
///
/// let rt = NucleusRuntime::builder()
///     .profile(PolicyProfile::Research)
///     .task("analyze repository structure")
///     .build();
///
/// assert_eq!(rt.profile(), PolicyProfile::Research);
/// assert_eq!(rt.task(), "analyze repository structure");
/// ```
pub struct NucleusRuntime {
    profile: PolicyProfile,
    policy: CapabilityLattice,
    task: String,
    flow_tracker: FlowTracker,
    allowed_write_paths: Vec<PathBuf>,
}

impl NucleusRuntime {
    /// Start building a `NucleusRuntime`.
    pub fn builder() -> NucleusRuntimeBuilder {
        NucleusRuntimeBuilder {
            profile: PolicyProfile::Strict,
            custom_policy: None,
            task: String::new(),
            allowed_write_paths: Vec::new(),
        }
    }

    /// The active policy profile.
    pub fn profile(&self) -> PolicyProfile {
        self.profile
    }

    /// The capability lattice in effect.
    pub fn policy(&self) -> &CapabilityLattice {
        &self.policy
    }

    /// The task description (for audit trails and scope enforcement).
    pub fn task(&self) -> &str {
        &self.task
    }

    /// Access the IFC flow tracker for observing data flow.
    ///
    /// Use this to track which data sources (web, file, env) have been
    /// observed in the session and check safety before actions.
    pub fn flow_tracker(&self) -> &FlowTracker {
        &self.flow_tracker
    }

    /// Mutable access to the IFC flow tracker.
    pub fn flow_tracker_mut(&mut self) -> &mut FlowTracker {
        &mut self.flow_tracker
    }

    /// Allowed write paths (empty = no path restriction beyond policy).
    pub fn allowed_write_paths(&self) -> &[PathBuf] {
        &self.allowed_write_paths
    }

    /// Create a policy-enforced effect bundle for performing I/O.
    ///
    /// Every call through the returned bundle is policy-checked.
    /// This is the primary way to perform side effects in a nucleus session.
    ///
    /// ```rust
    /// use portcullis_effects::runtime::{NucleusRuntime, PolicyProfile};
    /// use portcullis_effects::FileEffect;
    ///
    /// let rt = NucleusRuntime::builder()
    ///     .profile(PolicyProfile::Codegen)
    ///     .build();
    ///
    /// let fx = rt.effects();
    /// // fx implements FileEffect + WebEffect + ShellEffect + GitEffect + AgentSpawnEffect
    /// // All calls are policy-checked against the Codegen profile
    /// ```
    pub fn effects(
        &self,
    ) -> impl FileEffect + WebEffect + ShellEffect + GitEffect + AgentSpawnEffect + '_ {
        // We construct fresh effects each time — PolicyEnforced is stateless
        // (the policy is the only state, and it's immutable).
        production_effects(self.policy.clone())
    }

    // ═══════════════════════════════════════════════════════════════════
    // Mediated methods — discharge + path check + effect + IFC (#1239)
    // ═══════════════════════════════════════════════════════════════════

    /// Read a file with full obligation discharge and IFC tracking.
    ///
    /// 1. Discharges obligations via `preflight_action`
    /// 2. Executes the read through `PolicyEnforced`
    /// 3. Observes a `FileRead` node in the FlowTracker
    ///
    /// Returns the file contents and the IFC node ID for the read.
    pub fn read_file(&mut self, path: &Path) -> Result<(Vec<u8>, u64), RuntimeError> {
        let term = self.build_term(Operation::ReadFiles, SinkClass::AuditLogAppend);
        self.discharge(&term)?;

        let fx = production_effects(self.policy.clone());
        let data = fx
            .read(path)
            .map_err(|e| self.translate_error(e, "read file", path))?;

        let node_id = self
            .flow_tracker
            .observe(NodeKind::FileRead)
            .map_err(|e| RuntimeError::Io(e.to_string()))?;

        Ok((data, node_id))
    }

    /// Write a file with full obligation discharge, path checking, and IFC tracking.
    ///
    /// 1. Checks path against `allowed_write_paths` (if configured)
    /// 2. Discharges obligations via `preflight_action`
    /// 3. Executes the write through `PolicyEnforced`
    pub fn write_file(&mut self, path: &Path, content: &[u8]) -> Result<(), RuntimeError> {
        self.check_path_allowed(path)?;

        let term = self.build_term(Operation::WriteFiles, SinkClass::WorkspaceWrite);
        self.discharge(&term)?;

        let fx = production_effects(self.policy.clone());
        fx.write(path, content)
            .map_err(|e| self.translate_error(e, "write file", path))
    }

    /// Fetch a URL with full obligation discharge and IFC tracking.
    ///
    /// 1. Discharges obligations via `preflight_action`
    /// 2. Executes the fetch through `PolicyEnforced`
    /// 3. Observes a `WebContent` node in the FlowTracker (adversarial label)
    ///
    /// Returns the response bytes and the IFC node ID.
    pub fn fetch_url(&mut self, url: &str) -> Result<(Vec<u8>, u64), RuntimeError> {
        let term = self.build_term(Operation::WebFetch, SinkClass::HTTPEgress);
        self.discharge(&term)?;

        let fx = production_effects(self.policy.clone());
        let data = fx.fetch(url).map_err(RuntimeError::from)?;

        let node_id = self
            .flow_tracker
            .observe(NodeKind::WebContent)
            .map_err(|e| RuntimeError::Io(e.to_string()))?;

        Ok((data, node_id))
    }

    /// Run a shell command with full obligation discharge.
    ///
    /// 1. Discharges obligations via `preflight_action`
    /// 2. Executes the command through `PolicyEnforced`
    pub fn run_shell(&mut self, cmd: &str) -> Result<ShellOutput, RuntimeError> {
        let term = self.build_term(Operation::RunBash, SinkClass::BashExec);
        self.discharge(&term)?;

        let fx = production_effects(self.policy.clone());
        fx.run(cmd).map_err(RuntimeError::from)
    }

    /// Git commit with full obligation discharge.
    pub fn git_commit(&mut self, message: &str) -> Result<String, RuntimeError> {
        let term = self.build_term(Operation::GitCommit, SinkClass::GitCommit);
        self.discharge(&term)?;

        let fx = production_effects(self.policy.clone());
        fx.commit(message).map_err(RuntimeError::from)
    }

    /// Git push with full obligation discharge.
    pub fn git_push(&mut self, remote: &str, branch: &str) -> Result<(), RuntimeError> {
        let term = self.build_term(Operation::GitPush, SinkClass::GitPush);
        self.discharge(&term)?;

        let fx = production_effects(self.policy.clone());
        fx.push(remote, branch).map_err(RuntimeError::from)
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Build an `ActionTerm` for the given operation and sink.
    fn build_term(&self, operation: Operation, sink_class: SinkClass) -> ActionTerm {
        ActionTerm {
            operation,
            sink_class,
            source_labels: vec![],
            artifact_label: IFCLabel::default(),
            subject: self.task.clone(),
            estimated_cost_micro_usd: 0,
        }
    }

    /// Run `preflight_action` and convert denials to `RuntimeError`.
    fn discharge(&self, term: &ActionTerm) -> Result<(), RuntimeError> {
        match preflight_action(term) {
            PreflightResult::Allowed(_bundle) => Ok(()),
            PreflightResult::Denied(reason) => Err(RuntimeError::Denied {
                attempted: format!("{:?} → {:?}", term.operation, term.sink_class),
                reason,
                suggestion: format!(
                    "check your PolicyProfile ({}) or adjust the ActionTerm labels",
                    self.profile
                ),
            }),
            PreflightResult::RequiresApproval { reason } => Err(RuntimeError::Denied {
                attempted: format!("{:?} → {:?}", term.operation, term.sink_class),
                reason: format!("requires human approval: {reason}"),
                suggestion: "obtain approval before retrying this action".to_string(),
            }),
        }
    }

    /// Check that a path is within `allowed_write_paths` (if configured).
    fn check_path_allowed(&self, path: &Path) -> Result<(), RuntimeError> {
        if self.allowed_write_paths.is_empty() {
            return Ok(()); // No restriction configured
        }
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        for allowed in &self.allowed_write_paths {
            let allowed_canonical = allowed.canonicalize().unwrap_or_else(|_| allowed.clone());
            if canonical.starts_with(&allowed_canonical) {
                return Ok(());
            }
        }
        Err(RuntimeError::Denied {
            attempted: format!("write to {}", path.display()),
            reason: format!(
                "path is outside allowed write paths: {:?}",
                self.allowed_write_paths
            ),
            suggestion: "restrict writes to a subdirectory of the allowed paths, \
                         or add this path to .allowed_write_paths() in the builder"
                .to_string(),
        })
    }

    /// Translate an `EffectError` into a `RuntimeError` with path context.
    fn translate_error(&self, err: EffectError, action: &str, path: &Path) -> RuntimeError {
        match err {
            EffectError::PolicyDenied(msg) => RuntimeError::Denied {
                attempted: format!("{action}: {}", path.display()),
                reason: msg,
                suggestion: format!(
                    "your profile ({}) does not allow this — \
                     consider a profile with the required capability",
                    self.profile
                ),
            },
            other => RuntimeError::from(other),
        }
    }

    /// Check whether a specific capability is available in this runtime.
    ///
    /// Returns `true` if the capability level is `LowRisk` or `Always`.
    pub fn can(&self, check: RuntimeCapability) -> bool {
        let level = match check {
            RuntimeCapability::ReadFiles => self.policy.read_files,
            RuntimeCapability::WriteFiles => self.policy.write_files,
            RuntimeCapability::EditFiles => self.policy.edit_files,
            RuntimeCapability::RunBash => self.policy.run_bash,
            RuntimeCapability::WebFetch => self.policy.web_fetch,
            RuntimeCapability::WebSearch => self.policy.web_search,
            RuntimeCapability::GitCommit => self.policy.git_commit,
            RuntimeCapability::GitPush => self.policy.git_push,
            RuntimeCapability::CreatePr => self.policy.create_pr,
        };
        level != CapabilityLevel::Never
    }

    /// Returns `true` if the session's IFC flow tracker has observed
    /// any adversarially-tainted data.
    pub fn is_tainted(&self) -> bool {
        self.flow_tracker.is_tainted()
    }

    /// Returns `true` if the session has observed confidential (non-public) data.
    pub fn has_confidential_data(&self) -> bool {
        self.flow_tracker.has_confidential_data()
    }
}

impl std::fmt::Debug for NucleusRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NucleusRuntime")
            .field("profile", &self.profile)
            .field("task", &self.task)
            .field("node_count", &self.flow_tracker.node_count())
            .field("is_tainted", &self.flow_tracker.is_tainted())
            .field("allowed_write_paths", &self.allowed_write_paths)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RuntimeCapability — queryable capability dimensions
// ═══════════════════════════════════════════════════════════════════════════

/// Queryable capability dimensions for `NucleusRuntime::can()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeCapability {
    ReadFiles,
    WriteFiles,
    EditFiles,
    RunBash,
    WebFetch,
    WebSearch,
    GitCommit,
    GitPush,
    CreatePr,
}

// ═══════════════════════════════════════════════════════════════════════════
// NucleusRuntimeBuilder
// ═══════════════════════════════════════════════════════════════════════════

/// Builder for [`NucleusRuntime`].
///
/// Defaults to `PolicyProfile::Strict` with no task description.
pub struct NucleusRuntimeBuilder {
    profile: PolicyProfile,
    custom_policy: Option<CapabilityLattice>,
    task: String,
    allowed_write_paths: Vec<PathBuf>,
}

impl NucleusRuntimeBuilder {
    /// Set the policy profile.
    ///
    /// This is the recommended way to configure capabilities. If you also
    /// call [`custom_policy`], the custom policy takes precedence.
    pub fn profile(mut self, profile: PolicyProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set a custom `CapabilityLattice` instead of using a named profile.
    ///
    /// When set, this overrides the profile's lattice. The profile name
    /// is still stored for diagnostics/audit.
    pub fn custom_policy(mut self, policy: CapabilityLattice) -> Self {
        self.custom_policy = Some(policy);
        self
    }

    /// Set the task description (natural language).
    ///
    /// Used in audit trails and as context for scope enforcement.
    pub fn task(mut self, task: impl Into<String>) -> Self {
        self.task = task.into();
        self
    }

    /// Restrict file writes to these paths (and their descendants).
    ///
    /// Empty = no path restriction beyond the capability lattice.
    pub fn allowed_write_paths(
        mut self,
        paths: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Self {
        self.allowed_write_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Build the `NucleusRuntime`.
    pub fn build(self) -> NucleusRuntime {
        let policy = self
            .custom_policy
            .unwrap_or_else(|| self.profile.to_lattice());

        NucleusRuntime {
            profile: self.profile,
            policy,
            task: self.task,
            flow_tracker: FlowTracker::new(),
            allowed_write_paths: self.allowed_write_paths,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_to_strict() {
        let rt = NucleusRuntime::builder().build();
        assert_eq!(rt.profile(), PolicyProfile::Strict);
        assert_eq!(rt.task(), "");
    }

    #[test]
    fn builder_sets_profile() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .build();
        assert_eq!(rt.profile(), PolicyProfile::Research);
    }

    #[test]
    fn builder_sets_task() {
        let rt = NucleusRuntime::builder()
            .task("summarize SEC filings")
            .build();
        assert_eq!(rt.task(), "summarize SEC filings");
    }

    #[test]
    fn builder_sets_allowed_write_paths() {
        let rt = NucleusRuntime::builder()
            .allowed_write_paths(["./output/", "./tmp/"])
            .build();
        assert_eq!(rt.allowed_write_paths().len(), 2);
    }

    #[test]
    fn custom_policy_overrides_profile() {
        let custom = CapabilityLattice::builder()
            .read_files(CapabilityLevel::Always)
            .run_bash(CapabilityLevel::Always)
            .build();
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::ReadOnly)
            .custom_policy(custom.clone())
            .build();
        // Profile name is still ReadOnly (for diagnostics)
        assert_eq!(rt.profile(), PolicyProfile::ReadOnly);
        // But the actual policy is the custom one
        assert_eq!(rt.policy().run_bash, CapabilityLevel::Always);
    }

    // ── PolicyProfile tests ─────────────────────────────────────────────

    #[test]
    fn read_only_profile_capabilities() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::ReadOnly)
            .build();
        assert!(rt.can(RuntimeCapability::ReadFiles));
        assert!(!rt.can(RuntimeCapability::WriteFiles));
        assert!(!rt.can(RuntimeCapability::RunBash));
        assert!(!rt.can(RuntimeCapability::WebFetch));
        assert!(!rt.can(RuntimeCapability::GitPush));
    }

    #[test]
    fn research_profile_capabilities() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .build();
        assert!(rt.can(RuntimeCapability::ReadFiles));
        assert!(rt.can(RuntimeCapability::WebFetch));
        assert!(rt.can(RuntimeCapability::WebSearch));
        assert!(!rt.can(RuntimeCapability::WriteFiles));
        assert!(!rt.can(RuntimeCapability::RunBash));
        assert!(!rt.can(RuntimeCapability::GitPush));
    }

    #[test]
    fn codegen_profile_capabilities() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        assert!(rt.can(RuntimeCapability::ReadFiles));
        assert!(rt.can(RuntimeCapability::WriteFiles));
        assert!(rt.can(RuntimeCapability::EditFiles));
        assert!(rt.can(RuntimeCapability::RunBash));
        assert!(rt.can(RuntimeCapability::GitCommit));
        assert!(!rt.can(RuntimeCapability::WebFetch));
        assert!(!rt.can(RuntimeCapability::GitPush));
    }

    #[test]
    fn review_profile_capabilities() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Review)
            .build();
        assert!(rt.can(RuntimeCapability::ReadFiles));
        assert!(rt.can(RuntimeCapability::WebFetch));
        assert!(rt.can(RuntimeCapability::GitCommit));
        assert!(rt.can(RuntimeCapability::GitPush));
        assert!(rt.can(RuntimeCapability::CreatePr));
        assert!(!rt.can(RuntimeCapability::WriteFiles));
        assert!(!rt.can(RuntimeCapability::RunBash));
    }

    #[test]
    fn permissive_profile_allows_everything() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Permissive)
            .build();
        assert!(rt.can(RuntimeCapability::ReadFiles));
        assert!(rt.can(RuntimeCapability::WriteFiles));
        assert!(rt.can(RuntimeCapability::RunBash));
        assert!(rt.can(RuntimeCapability::WebFetch));
        assert!(rt.can(RuntimeCapability::GitPush));
    }

    // ── FlowTracker integration ─────────────────────────────────────────

    #[test]
    fn fresh_runtime_is_not_tainted() {
        let rt = NucleusRuntime::builder().build();
        assert!(!rt.is_tainted());
        assert!(!rt.has_confidential_data());
    }

    #[test]
    fn flow_tracker_accessible() {
        use portcullis_core::flow::NodeKind;

        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .build();

        let web = rt.flow_tracker_mut().observe(NodeKind::WebContent).unwrap();
        assert!(rt.is_tainted());
        assert!(rt.flow_tracker().check_action_safety(web, true).is_denied());
    }

    #[test]
    fn confidential_data_detected() {
        use portcullis_core::flow::NodeKind;

        let mut rt = NucleusRuntime::builder().build();
        rt.flow_tracker_mut().observe(NodeKind::EnvVar).unwrap();
        assert!(rt.has_confidential_data());
    }

    // ── Effects integration ─────────────────────────────────────────────

    #[test]
    fn effects_respect_policy() {
        use crate::FileEffect;

        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::ReadOnly)
            .build();
        let fx = rt.effects();

        // Read should be policy-allowed (may fail on I/O, but not on policy)
        let result = fx.write(std::path::Path::new("/tmp/test"), b"data");
        assert!(result.is_err()); // WriteFiles is Never in ReadOnly
    }

    // ── Debug / Display ─────────────────────────────────────────────────

    #[test]
    fn debug_output_shows_profile_and_task() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .task("implement feature X")
            .build();
        let debug = format!("{rt:?}");
        assert!(debug.contains("Codegen"));
        assert!(debug.contains("implement feature X"));
    }

    #[test]
    fn policy_profile_display() {
        assert_eq!(PolicyProfile::ReadOnly.to_string(), "read_only");
        assert_eq!(PolicyProfile::Research.to_string(), "research");
        assert_eq!(PolicyProfile::Codegen.to_string(), "codegen");
        assert_eq!(PolicyProfile::Review.to_string(), "review");
        assert_eq!(PolicyProfile::Strict.to_string(), "strict");
        assert_eq!(PolicyProfile::Permissive.to_string(), "permissive");
    }

    // ── RuntimeError formatting ─────────────────────────────────────────

    #[test]
    fn runtime_error_denied_display() {
        let err = RuntimeError::Denied {
            attempted: "write to /etc/passwd".to_string(),
            reason: "write_files capability is Never".to_string(),
            suggestion: "use PolicyProfile::Codegen".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("action denied"));
        assert!(msg.contains("/etc/passwd"));
        assert!(msg.contains("Codegen"));
    }

    #[test]
    fn effect_error_converts_to_runtime_error() {
        let effect_err = EffectError::PolicyDenied("write_files is Never".to_string());
        let rt_err: RuntimeError = effect_err.into();
        assert!(matches!(rt_err, RuntimeError::Denied { .. }));
    }

    // ── Mediated method tests (#1239) ───────────────────────────────────

    #[test]
    fn write_file_denied_by_read_only_profile() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::ReadOnly)
            .build();
        let result = rt.write_file(std::path::Path::new("/tmp/test.txt"), b"data");
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should be a Denied error from either discharge or effects
        assert!(matches!(err, RuntimeError::Denied { .. }));
    }

    #[test]
    fn write_file_path_allowlist_blocks_outside_paths() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .allowed_write_paths(["/allowed/dir"])
            .build();
        let result = rt.write_file(std::path::Path::new("/etc/passwd"), b"data");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("outside allowed write paths"));
    }

    #[test]
    fn write_file_empty_allowlist_permits_any_path() {
        // Empty allowlist = no path restriction (only policy governs)
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        // This will fail on discharge (IFCLabel default is Untrusted integrity)
        // or on the actual I/O, but NOT on path checking
        let result = rt.write_file(std::path::Path::new("/tmp/nucleus-test-1239"), b"test");
        // May succeed or fail on I/O — the point is it doesn't fail on path check
        if let Err(RuntimeError::Denied { reason, .. }) = &result {
            assert!(!reason.contains("outside allowed write paths"));
        }
    }

    #[test]
    fn read_file_updates_flow_tracker() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        assert_eq!(rt.flow_tracker().node_count(), 0);

        // Read a file that exists
        let result = rt.read_file(std::path::Path::new("Cargo.toml"));
        if let Ok((_, node_id)) = result {
            assert!(node_id > 0);
            assert_eq!(rt.flow_tracker().node_count(), 1);
            // The label should be FileRead (Internal, Trusted)
            let label = rt.flow_tracker().label(node_id).unwrap();
            assert_eq!(label.integrity, portcullis_core::IntegLevel::Trusted);
        }
    }

    #[test]
    fn fetch_url_updates_flow_tracker_with_adversarial() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .build();

        // fetch will fail (stub) but we can test that it gets past discharge
        let result = rt.fetch_url("https://example.com");
        // The fetch may fail with NotImplemented or Io, but not PolicyDenied
        match result {
            Ok((_, node_id)) => {
                assert!(rt.is_tainted());
                assert!(node_id > 0);
            }
            Err(RuntimeError::Io(_)) | Err(RuntimeError::Config(_)) => {
                // Stub returned error — that's fine, discharge passed
            }
            Err(RuntimeError::Denied { reason, .. }) => {
                // Should not be denied by policy — Research has WebFetch
                panic!("unexpected denial: {reason}");
            }
        }
    }

    #[test]
    fn run_shell_denied_by_research_profile() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .build();
        let result = rt.run_shell("echo hello");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuntimeError::Denied { .. }));
    }

    #[test]
    fn git_push_denied_by_codegen_profile() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        let result = rt.git_push("origin", "main");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuntimeError::Denied { .. }));
    }

    #[test]
    fn denied_error_mentions_capability() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::ReadOnly)
            .build();
        let result = rt.run_shell("echo hello");
        let err = result.unwrap_err();
        let msg = err.to_string();
        // The denial comes from PolicyEnforced (run_bash is Never)
        assert!(
            msg.contains("denied") || msg.contains("Never"),
            "expected denial message, got: {msg}"
        );
    }
}
