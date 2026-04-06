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
use portcullis_core::labeled::{self, Labeled};
use portcullis_core::{CapabilityLattice, CapabilityLevel, IFCLabel, Operation, SinkClass};

use crate::{
    production_effects, AgentSpawnEffect, EffectError, FileEffect, GitEffect, ShellEffect,
    ShellOutput, WebEffect,
};

// ═══════════════════════════════════════════════════════════════════════════
// UnmediatedAccess — sealed token for escape hatch (#1264)
// ═══════════════════════════════════════════════════════════════════════════

/// Sealed token proving the caller explicitly opted into unmediated effect
/// access at builder time.
///
/// Cannot be constructed outside this module — the private `_seal` field
/// prevents external creation. The only way to obtain one is through
/// [`NucleusRuntimeBuilder::allow_unmediated_access`].
///
/// Same sealing pattern as `Discharged<O>` in `portcullis-core`.
#[derive(Debug)]
pub struct UnmediatedAccess {
    _seal: Seal,
}

struct Seal;

impl std::fmt::Debug for Seal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seal")
    }
}

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

    /// Compose this profile with an additional capability (#1251).
    ///
    /// Returns a [`ComposedPolicy`] that is the lattice join of this profile's
    /// lattice with the given capability raised to `Always`.
    ///
    /// ```rust
    /// use portcullis_effects::runtime::{PolicyProfile, RuntimeCapability};
    ///
    /// let policy = PolicyProfile::Research.with(RuntimeCapability::RunBash);
    /// // Research capabilities + RunBash
    /// assert!(policy.allows(RuntimeCapability::WebFetch));  // from Research
    /// assert!(policy.allows(RuntimeCapability::RunBash));   // added
    /// assert!(!policy.allows(RuntimeCapability::WriteFiles)); // neither has it
    /// ```
    pub fn with(self, cap: RuntimeCapability) -> ComposedPolicy {
        let mut lattice = self.to_lattice();
        cap.raise(&mut lattice, CapabilityLevel::Always);
        ComposedPolicy {
            base: self,
            lattice,
        }
    }

    /// Compose two profiles via lattice join (#1251).
    ///
    /// The result has every capability that either profile grants.
    ///
    /// ```rust
    /// use portcullis_effects::runtime::{PolicyProfile, RuntimeCapability};
    ///
    /// let policy = PolicyProfile::Research.join_profile(PolicyProfile::Codegen);
    /// // Has both web (Research) and bash (Codegen)
    /// assert!(policy.allows(RuntimeCapability::WebFetch));
    /// assert!(policy.allows(RuntimeCapability::RunBash));
    /// ```
    pub fn join_profile(self, other: PolicyProfile) -> ComposedPolicy {
        let lattice = self.to_lattice().join(&other.to_lattice());
        ComposedPolicy {
            base: self,
            lattice,
        }
    }

    /// Remove a capability from this profile (#1298).
    ///
    /// Returns a [`ComposedPolicy`] with the named capability set to `Never`.
    ///
    /// ```rust
    /// use portcullis_effects::runtime::{PolicyProfile, RuntimeCapability};
    ///
    /// let policy = PolicyProfile::Research.without(RuntimeCapability::WebSearch);
    /// assert!(policy.allows(RuntimeCapability::WebFetch));   // still has fetch
    /// assert!(!policy.allows(RuntimeCapability::WebSearch));  // removed
    /// ```
    pub fn without(self, cap: RuntimeCapability) -> ComposedPolicy {
        let mut lattice = self.to_lattice();
        cap.set_never(&mut lattice);
        ComposedPolicy {
            base: self,
            lattice,
        }
    }
}

impl std::fmt::Display for PolicyProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ComposedPolicy — result of profile composition (#1251)
// ═══════════════════════════════════════════════════════════════════════════

/// A policy composed from a base profile plus additional capabilities.
///
/// Created by [`PolicyProfile::with`] or [`PolicyProfile::join_profile`].
/// Can be further composed via chained `.with()` calls.
///
/// ```rust
/// use portcullis_effects::runtime::{PolicyProfile, RuntimeCapability};
///
/// let policy = PolicyProfile::Research
///     .with(RuntimeCapability::RunBash)
///     .with(RuntimeCapability::WriteFiles);
///
/// assert!(policy.allows(RuntimeCapability::WebFetch));   // Research
/// assert!(policy.allows(RuntimeCapability::RunBash));    // added
/// assert!(policy.allows(RuntimeCapability::WriteFiles)); // added
/// ```
#[derive(Debug, Clone)]
pub struct ComposedPolicy {
    /// The base profile (for diagnostics and audit).
    base: PolicyProfile,
    /// The composed lattice.
    lattice: CapabilityLattice,
}

impl ComposedPolicy {
    /// Add another capability to this composed policy.
    pub fn with(mut self, cap: RuntimeCapability) -> Self {
        cap.raise(&mut self.lattice, CapabilityLevel::Always);
        self
    }

    /// Remove a capability from this composed policy (#1298).
    pub fn without(mut self, cap: RuntimeCapability) -> Self {
        cap.set_never(&mut self.lattice);
        self
    }

    /// Check whether a capability is allowed in this composed policy.
    pub fn allows(&self, cap: RuntimeCapability) -> bool {
        cap.level_in(&self.lattice) != CapabilityLevel::Never
    }

    /// The composed `CapabilityLattice`.
    pub fn to_lattice(&self) -> CapabilityLattice {
        self.lattice.clone()
    }

    /// The base profile name (for diagnostics).
    pub fn base_profile(&self) -> PolicyProfile {
        self.base
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Typed output structs (#1262, #1263)
// ═══════════════════════════════════════════════════════════════════════════

/// Output from [`NucleusRuntime::read_file`].
///
/// Data is `Labeled<Vec<u8>, Trusted, Internal>` — file reads carry
/// trusted integrity and internal confidentiality at the type level.
#[derive(Debug, Clone)]
pub struct ReadOutput {
    data: Labeled<Vec<u8>, labeled::Trusted, labeled::Internal>,
    node_id: u64,
}

impl ReadOutput {
    /// The file contents with compile-time IFC tags.
    pub fn data(&self) -> &Labeled<Vec<u8>, labeled::Trusted, labeled::Internal> {
        &self.data
    }
    /// Consume and return the labeled data.
    pub fn into_data(self) -> Labeled<Vec<u8>, labeled::Trusted, labeled::Internal> {
        self.data
    }
    /// The FlowTracker node ID for this read (for IFC ancestry tracking).
    pub fn node_id(&self) -> u64 {
        self.node_id
    }
}

/// Output from [`NucleusRuntime::fetch_url`].
///
/// Data is `Labeled<Vec<u8>, Adversarial, Public>` — web content carries
/// adversarial integrity and public confidentiality. Passing this to a
/// function requiring `Trusted` input is a **compile error**.
#[derive(Debug, Clone)]
pub struct FetchOutput {
    data: Labeled<Vec<u8>, labeled::Adversarial, labeled::Public>,
    node_id: u64,
}

impl FetchOutput {
    /// The response bytes with compile-time IFC tags.
    pub fn data(&self) -> &Labeled<Vec<u8>, labeled::Adversarial, labeled::Public> {
        &self.data
    }
    /// Consume and return the labeled data.
    pub fn into_data(self) -> Labeled<Vec<u8>, labeled::Adversarial, labeled::Public> {
        self.data
    }
    /// The FlowTracker node ID for this fetch (adversarial ancestry).
    pub fn node_id(&self) -> u64 {
        self.node_id
    }
}

/// Output from [`NucleusRuntime::run_shell`].
///
/// Shell output is `Labeled<ShellOutput, Untrusted, Public>` — command
/// output is untrusted (the process ran, but output may be attacker-influenced)
/// and public confidentiality.
#[derive(Debug)]
pub struct ShellResult {
    data: Labeled<ShellOutput, labeled::Untrusted, labeled::Public>,
}

impl ShellResult {
    /// The shell output with compile-time IFC tags.
    pub fn data(&self) -> &Labeled<ShellOutput, labeled::Untrusted, labeled::Public> {
        &self.data
    }
    /// Consume and return the labeled shell output.
    pub fn into_data(self) -> Labeled<ShellOutput, labeled::Untrusted, labeled::Public> {
        self.data
    }
}

/// Output from [`NucleusRuntime::git_commit`].
///
/// Commit hash is `Labeled<String, Trusted, Internal>` — the hash is
/// a deterministic output from a trusted local operation.
#[derive(Debug, Clone)]
pub struct CommitOutput {
    hash: Labeled<String, labeled::Trusted, labeled::Internal>,
}

impl CommitOutput {
    /// The commit hash with compile-time IFC tags.
    pub fn hash(&self) -> &Labeled<String, labeled::Trusted, labeled::Internal> {
        &self.hash
    }
    /// Consume and return the labeled hash.
    pub fn into_hash(self) -> Labeled<String, labeled::Trusted, labeled::Internal> {
        self.hash
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
    effects: crate::PolicyEnforced<crate::RealEffects>,
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

    /// Raw policy-enforced effect bundle — **advanced use only** (#1248).
    ///
    /// Returns an effect bundle that checks **capability levels** but does
    /// **NOT** run obligation discharge, path allowlist checks, or FlowTracker
    /// updates. For the full safety pipeline, use the mediated methods instead:
    /// [`read_file`], [`write_file`], [`fetch_url`], [`run_shell`], etc.
    ///
    /// This escape hatch exists for performance-critical paths or callers
    /// that manage discharge and IFC tracking externally. Most code should
    /// use the mediated methods.
    ///
    /// ```rust
    /// use portcullis_effects::runtime::{NucleusRuntime, PolicyProfile};
    /// use portcullis_effects::FileEffect;
    ///
    /// let (builder, token) = NucleusRuntime::builder()
    ///     .profile(PolicyProfile::Codegen)
    ///     .allow_unmediated_access();
    /// let rt = builder.build();
    ///
    /// // Prefer: rt.read_file(path) — runs discharge + IFC
    /// // Only use this when you manage discharge externally:
    /// let fx = rt.unmediated_effects(&token);
    /// ```
    pub fn unmediated_effects(
        &self,
        _token: &UnmediatedAccess,
    ) -> impl FileEffect + WebEffect + ShellEffect + GitEffect + AgentSpawnEffect + '_ {
        production_effects(self.policy.clone()) // unmediated: fresh instance for isolation
    }

    // ═══════════════════════════════════════════════════════════════════
    // Mediated methods — discharge + path check + effect + IFC (#1239)
    // ═══════════════════════════════════════════════════════════════════

    /// Read a file with full obligation discharge and IFC tracking (#1249).
    ///
    /// 1. Discharges obligations via `preflight_action`
    /// 2. Executes the read through `PolicyEnforced`
    /// 3. Observes a `FileRead` node in the FlowTracker
    ///
    /// Returns `Labeled<Vec<u8>, Trusted, Internal>` — the compile-time type
    /// encodes that file reads are trusted-integrity, internal-confidentiality.
    /// Passing this to a function requiring `Adversarial` input is a type error.
    pub fn read_file(&mut self, path: &Path) -> Result<ReadOutput, RuntimeError> {
        let term = self.build_term(Operation::ReadFiles, SinkClass::AuditLogAppend);
        self.discharge(&term)?;

        let fx = &self.effects;
        let data = fx
            .read(path)
            .map_err(|e| self.translate_error(e, "read file", path))?;

        let node_id = self
            .flow_tracker
            .observe(NodeKind::FileRead)
            .map_err(|e| RuntimeError::Io(e.to_string()))?;

        Ok(ReadOutput {
            data: Labeled::new(data),
            node_id,
        })
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

        let fx = &self.effects;
        fx.write(path, content)
            .map_err(|e| self.translate_error(e, "write file", path))
    }

    /// Fetch a URL with full obligation discharge and IFC tracking (#1249).
    ///
    /// 1. Discharges obligations via `preflight_action`
    /// 2. Executes the fetch through `PolicyEnforced`
    /// 3. Observes a `WebContent` node in the FlowTracker (adversarial label)
    ///
    /// Returns `Labeled<Vec<u8>, Adversarial, Public>` — the compile-time type
    /// encodes that web content is adversarial-integrity, public-confidentiality.
    /// Passing this to a function requiring `Trusted` input is a **compile error**.
    pub fn fetch_url(&mut self, url: &str) -> Result<FetchOutput, RuntimeError> {
        let term = self.build_term(Operation::WebFetch, SinkClass::HTTPEgress);
        self.discharge(&term)?;

        let fx = &self.effects;
        let data = fx.fetch(url).map_err(RuntimeError::from)?;

        let node_id = self
            .flow_tracker
            .observe(NodeKind::WebContent)
            .map_err(|e| RuntimeError::Io(e.to_string()))?;

        Ok(FetchOutput {
            data: Labeled::new(data),
            node_id,
        })
    }

    /// Run a shell command with full obligation discharge.
    ///
    /// 1. Discharges obligations via `preflight_action`
    /// 2. Executes the command through `PolicyEnforced`
    pub fn run_shell(&mut self, cmd: &str) -> Result<ShellResult, RuntimeError> {
        let term = self.build_term(Operation::RunBash, SinkClass::BashExec);
        self.discharge(&term)?;

        let fx = &self.effects;
        let output = fx.run(cmd).map_err(RuntimeError::from)?;
        Ok(ShellResult {
            data: Labeled::new(output),
        })
    }

    /// Git commit with full obligation discharge.
    pub fn git_commit(&mut self, message: &str) -> Result<CommitOutput, RuntimeError> {
        let term = self.build_term(Operation::GitCommit, SinkClass::GitCommit);
        self.discharge(&term)?;

        let fx = &self.effects;
        let hash = fx.commit(message).map_err(RuntimeError::from)?;
        Ok(CommitOutput {
            hash: Labeled::new(hash),
        })
    }

    /// Git push with full obligation discharge.
    pub fn git_push(&mut self, remote: &str, branch: &str) -> Result<(), RuntimeError> {
        let term = self.build_term(Operation::GitPush, SinkClass::GitPush);
        self.discharge(&term)?;

        let fx = &self.effects;
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
            PreflightResult::Denied { reason, hint } => Err(RuntimeError::Denied {
                attempted: format!("{:?} → {:?}", term.operation, term.sink_class),
                reason,
                suggestion: hint.to_string(),
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
        check.level_in(&self.policy) != CapabilityLevel::Never
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

    // ═══════════════════════════════════════════════════════════════════
    // Cross-agent delegation (#1335)
    // ═══════════════════════════════════════════════════════════════════

    /// Spawn a child runtime with narrowed capabilities (#1335).
    ///
    /// Enforces the delegation ceiling: child ≤ parent on every dimension.
    /// The child also inherits the parent's session taint and confidentiality
    /// ceilings, preventing taint laundering through agent delegation.
    ///
    /// Returns `Err` if the child profile exceeds the parent on any dimension.
    ///
    /// ```rust
    /// use portcullis_effects::runtime::{NucleusRuntime, PolicyProfile};
    ///
    /// let parent = NucleusRuntime::builder()
    ///     .profile(PolicyProfile::Codegen)
    ///     .build();
    ///
    /// // ReadOnly ≤ Codegen → OK
    /// let child = parent.spawn_child(PolicyProfile::ReadOnly, "review code");
    /// assert!(child.is_ok());
    ///
    /// // Review has git_push, Codegen doesn't → DENIED
    /// let child = parent.spawn_child(PolicyProfile::Review, "push changes");
    /// assert!(child.is_err());
    /// ```
    pub fn spawn_child(
        &self,
        child_profile: PolicyProfile,
        task: impl Into<String>,
    ) -> Result<NucleusRuntime, RuntimeError> {
        let child_lattice = child_profile.to_lattice();
        let parent_lattice = &self.policy;

        // Check every dimension: child ≤ parent
        for &dim in &CapabilityLattice::DIMENSION_NAMES {
            let child_level = child_lattice.get(dim).unwrap_or(CapabilityLevel::Never);
            let parent_level = parent_lattice.get(dim).unwrap_or(CapabilityLevel::Never);
            if child_level > parent_level {
                return Err(RuntimeError::Denied {
                    attempted: format!("spawn child with {child_profile}"),
                    reason: format!(
                        "delegation violation: child has {dim}={child_level:?} \
                         but parent has {dim}={parent_level:?}"
                    ),
                    suggestion: format!(
                        "use a profile where {dim} ≤ {:?}, or narrow with .without()",
                        parent_level
                    ),
                });
            }
        }

        // Child inherits parent's taint and conf ceilings
        let mut child = NucleusRuntime::builder()
            .profile(child_profile)
            .task(task)
            .build();

        // Propagate session ceilings — child starts at parent's level
        // (monotonic: child can only raise, never lower)
        if self.flow_tracker.is_tainted() || self.has_confidential_data() {
            // Observe a sentinel node to raise the child's ceilings
            // to match the parent's. This uses the WebContent kind which
            // raises both taint ceiling (OpaqueExternal) and conf ceiling.
            // A more precise approach would set ceilings directly, but
            // the FlowTracker API only allows raising via observation.
            let _ = child
                .flow_tracker_mut()
                .observe(portcullis_core::flow::NodeKind::WebContent);
        }

        Ok(child)
    }

    // ═══════════════════════════════════════════════════════════════════
    // Typed context bridge — opt-in compile-time capability checking
    // ═══════════════════════════════════════════════════════════════════

    /// Enter a compile-time-checked capability scope.
    ///
    /// Inside the closure, all operations are type-checked against `Caps`.
    /// A function requiring `HasWebFetch` that's called with a `Caps` lacking
    /// it is a **compile error**, not a runtime denial.
    ///
    /// This is the bridge between the runtime path (`NucleusRuntime`) and
    /// the typed path (`Context<Caps>`). Most code uses the runtime path;
    /// security-critical subsystems opt into compile-time checking.
    ///
    /// ```rust
    /// use portcullis_core::caps;
    /// use portcullis_core::capability_traits::*;
    /// use portcullis_effects::runtime::{NucleusRuntime, PolicyProfile};
    ///
    /// caps!(ResearchCaps: HasFileRead, HasGlobSearch, HasWebFetch);
    ///
    /// let rt = NucleusRuntime::builder()
    ///     .profile(PolicyProfile::Research)
    ///     .build();
    ///
    /// let result = rt.with_typed_context::<ResearchCaps, _, _>(|ctx| {
    ///     // Inside here: compile-time checked
    ///     let _ = read_file(&ctx, "config.toml");  // OK: ResearchCaps has HasFileRead
    ///     // bash_exec(&ctx, "rm -rf /");  // COMPILE ERROR: no HasBashExec
    ///     Ok("done".to_string())
    /// });
    /// ```
    pub fn with_typed_context<Caps, F, T>(&self, f: F) -> Result<T, RuntimeError>
    where
        Caps: portcullis_core::capability_traits::sealed::Sealed,
        F: FnOnce(portcullis_core::capability_traits::Context<Caps>) -> Result<T, RuntimeError>,
    {
        let ctx = portcullis_core::capability_traits::Context::new(
            self.task.clone(),
            std::path::PathBuf::from("."),
        );
        f(ctx)
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

/// Queryable capability dimensions for `NucleusRuntime::can()` and
/// `PolicyProfile::with()`.
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

impl RuntimeCapability {
    /// Get the current level of this capability in a lattice.
    pub fn level_in(self, lattice: &CapabilityLattice) -> CapabilityLevel {
        match self {
            Self::ReadFiles => lattice.read_files,
            Self::WriteFiles => lattice.write_files,
            Self::EditFiles => lattice.edit_files,
            Self::RunBash => lattice.run_bash,
            Self::WebFetch => lattice.web_fetch,
            Self::WebSearch => lattice.web_search,
            Self::GitCommit => lattice.git_commit,
            Self::GitPush => lattice.git_push,
            Self::CreatePr => lattice.create_pr,
        }
    }

    /// Raise this capability to the given level in a lattice (join semantics).
    pub fn raise(self, lattice: &mut CapabilityLattice, level: CapabilityLevel) {
        let field = self.field_mut(lattice);
        *field = (*field).join(level);
    }

    /// Set this capability to `Never` in the lattice (#1298).
    pub fn set_never(self, lattice: &mut CapabilityLattice) {
        *self.field_mut(lattice) = CapabilityLevel::Never;
    }

    fn field_mut(self, lattice: &mut CapabilityLattice) -> &mut CapabilityLevel {
        match self {
            Self::ReadFiles => &mut lattice.read_files,
            Self::WriteFiles => &mut lattice.write_files,
            Self::EditFiles => &mut lattice.edit_files,
            Self::RunBash => &mut lattice.run_bash,
            Self::WebFetch => &mut lattice.web_fetch,
            Self::WebSearch => &mut lattice.web_search,
            Self::GitCommit => &mut lattice.git_commit,
            Self::GitPush => &mut lattice.git_push,
            Self::CreatePr => &mut lattice.create_pr,
        }
    }
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

    /// Set a composed policy from [`PolicyProfile::with`] or [`PolicyProfile::join_profile`].
    ///
    /// ```rust
    /// use portcullis_effects::runtime::{NucleusRuntime, PolicyProfile, RuntimeCapability};
    ///
    /// let rt = NucleusRuntime::builder()
    ///     .composed(PolicyProfile::Research.with(RuntimeCapability::RunBash))
    ///     .build();
    /// assert!(rt.can(RuntimeCapability::WebFetch));  // Research
    /// assert!(rt.can(RuntimeCapability::RunBash));   // added
    /// ```
    pub fn composed(mut self, policy: ComposedPolicy) -> Self {
        self.profile = policy.base;
        self.custom_policy = Some(policy.to_lattice());
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

    /// Explicitly opt into unmediated effect access (#1264).
    ///
    /// Returns `(self, UnmediatedAccess)` — the token is required by
    /// [`NucleusRuntime::unmediated_effects`]. This opt-in is visible
    /// in code review and auditable.
    ///
    /// Most code should NOT call this. Use the mediated methods instead.
    pub fn allow_unmediated_access(self) -> (Self, UnmediatedAccess) {
        (self, UnmediatedAccess { _seal: Seal })
    }

    /// Build the `NucleusRuntime`.
    pub fn build(self) -> NucleusRuntime {
        let policy = self
            .custom_policy
            .unwrap_or_else(|| self.profile.to_lattice());

        let effects = crate::production_effects_concrete(policy.clone());
        NucleusRuntime {
            profile: self.profile,
            policy,
            effects,
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

        let (builder, token) = NucleusRuntime::builder()
            .profile(PolicyProfile::ReadOnly)
            .allow_unmediated_access();
        let rt = builder.build();
        let fx = rt.unmediated_effects(&token);

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
        if let Ok(output) = result {
            assert!(output.node_id() > 0);
            assert_eq!(rt.flow_tracker().node_count(), 1);
            let label = rt.flow_tracker().label(output.node_id()).unwrap();
            assert_eq!(label.integrity, portcullis_core::IntegLevel::Trusted);
            // Named struct gives clean access
            assert_eq!(
                output.data().integrity_level(),
                portcullis_core::IntegLevel::Trusted
            );
            assert_eq!(
                output.data().conf_level(),
                portcullis_core::ConfLevel::Internal
            );
            assert!(!output.data().inner().is_empty());
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
            Ok(output) => {
                assert!(rt.is_tainted());
                assert!(output.node_id() > 0);
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

    // ── Profile composition tests (#1251) ───────────────────────────────

    #[test]
    fn profile_with_adds_capability() {
        let policy = PolicyProfile::Research.with(RuntimeCapability::RunBash);
        assert!(policy.allows(RuntimeCapability::WebFetch)); // from Research
        assert!(policy.allows(RuntimeCapability::RunBash)); // added
        assert!(!policy.allows(RuntimeCapability::WriteFiles)); // neither has it
    }

    #[test]
    fn profile_with_chained() {
        let policy = PolicyProfile::ReadOnly
            .with(RuntimeCapability::WebFetch)
            .with(RuntimeCapability::RunBash);
        assert!(policy.allows(RuntimeCapability::ReadFiles)); // ReadOnly
        assert!(policy.allows(RuntimeCapability::WebFetch)); // added
        assert!(policy.allows(RuntimeCapability::RunBash)); // added
        assert!(!policy.allows(RuntimeCapability::GitPush)); // not added
    }

    #[test]
    fn join_profile_combines_both() {
        let policy = PolicyProfile::Research.join_profile(PolicyProfile::Codegen);
        // Research: web fetch + web search
        assert!(policy.allows(RuntimeCapability::WebFetch));
        assert!(policy.allows(RuntimeCapability::WebSearch));
        // Codegen: bash + write + edit + git commit
        assert!(policy.allows(RuntimeCapability::RunBash));
        assert!(policy.allows(RuntimeCapability::WriteFiles));
        assert!(policy.allows(RuntimeCapability::GitCommit));
    }

    #[test]
    fn composed_policy_in_builder() {
        let rt = NucleusRuntime::builder()
            .composed(PolicyProfile::Research.with(RuntimeCapability::RunBash))
            .build();
        assert!(rt.can(RuntimeCapability::WebFetch));
        assert!(rt.can(RuntimeCapability::RunBash));
        assert!(!rt.can(RuntimeCapability::WriteFiles));
    }

    #[test]
    fn composed_base_profile_preserved() {
        let policy = PolicyProfile::Research.with(RuntimeCapability::RunBash);
        assert_eq!(policy.base_profile(), PolicyProfile::Research);
    }

    #[test]
    fn profile_without_removes_capability() {
        let policy = PolicyProfile::Research.without(RuntimeCapability::WebSearch);
        assert!(policy.allows(RuntimeCapability::WebFetch)); // still has fetch
        assert!(policy.allows(RuntimeCapability::ReadFiles)); // still has read
        assert!(!policy.allows(RuntimeCapability::WebSearch)); // removed
    }

    #[test]
    fn composed_without_chains() {
        let policy = PolicyProfile::Codegen
            .without(RuntimeCapability::RunBash)
            .without(RuntimeCapability::GitCommit);
        assert!(policy.allows(RuntimeCapability::WriteFiles)); // still has write
        assert!(!policy.allows(RuntimeCapability::RunBash)); // removed
        assert!(!policy.allows(RuntimeCapability::GitCommit)); // removed
    }

    #[test]
    fn with_then_without() {
        // Add then remove — net effect is removal
        let policy = PolicyProfile::ReadOnly
            .with(RuntimeCapability::RunBash)
            .without(RuntimeCapability::RunBash);
        assert!(!policy.allows(RuntimeCapability::RunBash));
    }

    #[test]
    fn runtime_capability_level_in() {
        let lattice = CapabilityLattice::for_codegen();
        assert_eq!(
            RuntimeCapability::RunBash.level_in(&lattice),
            CapabilityLevel::Always
        );
        assert_eq!(
            RuntimeCapability::WebFetch.level_in(&lattice),
            CapabilityLevel::Never
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Full pipeline enforcement tests (#1295)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn write_file_denied_by_path_allowlist() {
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
    fn git_push_denied_by_codegen_profile_via_discharge() {
        // Codegen has git_commit but NOT git_push
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        let result = rt.git_push("origin", "main");
        assert!(result.is_err());
    }

    #[test]
    fn git_commit_allowed_by_codegen_profile() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        // git_commit may fail on I/O (no repo) but should NOT fail on policy
        let result = rt.git_commit("test commit");
        if let Err(RuntimeError::Denied { .. }) = &result {
            panic!("git_commit should not be denied by Codegen profile");
        }
    }

    #[test]
    fn run_shell_allowed_by_codegen_profile() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        // run_shell may fail on I/O but should NOT fail on policy
        let result = rt.run_shell("echo test");
        if let Err(RuntimeError::Denied { .. }) = &result {
            panic!("run_shell should not be denied by Codegen profile");
        }
    }

    #[test]
    fn read_file_returns_labeled_with_correct_tags() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        let result = rt.read_file(std::path::Path::new("Cargo.toml"));
        if let Ok(output) = result {
            assert_eq!(
                output.data().integrity_level(),
                portcullis_core::IntegLevel::Trusted
            );
            assert_eq!(
                output.data().conf_level(),
                portcullis_core::ConfLevel::Internal
            );
        }
    }

    #[test]
    fn session_tracks_taint_after_operations() {
        let mut rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        assert!(!rt.is_tainted());
        assert_eq!(rt.flow_tracker().node_count(), 0);

        // Read a file — should add a node
        if rt.read_file(std::path::Path::new("Cargo.toml")).is_ok() {
            assert_eq!(rt.flow_tracker().node_count(), 1);
            assert!(rt.has_confidential_data()); // FileRead is Internal
        }
    }

    #[test]
    fn permissive_all_caps_via_can() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Permissive)
            .build();
        for cap in [
            RuntimeCapability::ReadFiles,
            RuntimeCapability::WriteFiles,
            RuntimeCapability::RunBash,
            RuntimeCapability::WebFetch,
            RuntimeCapability::GitPush,
            RuntimeCapability::CreatePr,
        ] {
            assert!(rt.can(cap), "Permissive should allow {cap:?}");
        }
    }

    #[test]
    fn strict_profile_denies_bash_and_push() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Strict)
            .build();
        // Strict = default lattice: run_bash=Never, git_push=Never
        assert!(!rt.can(RuntimeCapability::RunBash));
        assert!(!rt.can(RuntimeCapability::GitPush));
        // But allows reads
        assert!(rt.can(RuntimeCapability::ReadFiles));
    }

    // ════════════════════════════════════════════════════════════════════
    // Typed context bridge tests
    // ════════════════════════════════════════════════════════════════════

    #[allow(unused_imports)]
    use portcullis_core::capability_traits::*;
    use portcullis_core::caps;

    caps!(TestReadWebCaps: HasFileRead, HasGlobSearch, HasWebFetch);
    caps!(TestReadOnlyCaps: HasFileRead, HasGlobSearch);

    #[test]
    fn typed_context_bridge_works() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .build();

        let result = rt.with_typed_context::<TestReadWebCaps, _, _>(|ctx| {
            // This compiles: TestReadWebCaps has HasFileRead
            assert_eq!(ctx.session_id(), "");
            Ok(42)
        });
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn typed_context_uses_task_as_session_id() {
        let rt = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .task("analyze filings")
            .build();

        rt.with_typed_context::<TestReadOnlyCaps, _, _>(|ctx| {
            assert_eq!(ctx.session_id(), "analyze filings");
            Ok(())
        })
        .unwrap();
    }

    // This would NOT compile — proving the bridge enforces caps at compile time:
    // fn _test_typed_context_rejects_missing_caps() {
    //     let rt = NucleusRuntime::builder().build();
    //     rt.with_typed_context::<TestReadOnlyCaps, _, _>(|ctx| {
    //         web_fetch(&ctx, "https://evil.com");  // ERROR: TestReadOnlyCaps lacks HasWebFetch
    //         Ok(())
    //     });
    // }

    // ════════════════════════════════════════════════════════════════════
    // Cross-agent delegation tests (#1335)
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn spawn_child_read_only_under_codegen() {
        let parent = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        let child = parent.spawn_child(PolicyProfile::ReadOnly, "review");
        assert!(child.is_ok());
        let child = child.unwrap();
        assert!(child.can(RuntimeCapability::ReadFiles));
        assert!(!child.can(RuntimeCapability::WriteFiles)); // ReadOnly has no write
    }

    #[test]
    fn spawn_child_rejects_escalation() {
        let parent = NucleusRuntime::builder()
            .profile(PolicyProfile::ReadOnly)
            .build();
        // Codegen has write + bash — exceeds ReadOnly
        let child = parent.spawn_child(PolicyProfile::Codegen, "generate");
        assert!(child.is_err());
        let err = child.unwrap_err();
        assert!(matches!(err, RuntimeError::Denied { .. }));
    }

    #[test]
    fn spawn_child_review_under_codegen_rejected() {
        let parent = NucleusRuntime::builder()
            .profile(PolicyProfile::Codegen)
            .build();
        // Review has git_push + create_pr — Codegen doesn't
        let child = parent.spawn_child(PolicyProfile::Review, "review and push");
        assert!(child.is_err());
    }

    #[test]
    fn spawn_child_same_profile_ok() {
        let parent = NucleusRuntime::builder()
            .profile(PolicyProfile::Research)
            .build();
        let child = parent.spawn_child(PolicyProfile::Research, "more research");
        assert!(child.is_ok());
    }
}
