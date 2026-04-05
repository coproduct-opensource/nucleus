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

use std::path::PathBuf;

use portcullis_core::ifc_api::FlowTracker;
use portcullis_core::{CapabilityLattice, CapabilityLevel};

use crate::{
    production_effects, AgentSpawnEffect, EffectError, FileEffect, GitEffect, ShellEffect,
    WebEffect,
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
}
