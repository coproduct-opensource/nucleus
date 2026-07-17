//! Command execution with policy enforcement.
//!
//! Unlike `portcullis::CommandLattice` which provides a `can_execute()` predicate,
//! `Executor` actually spawns processes - but only after validating against policy.
//!
//! The key difference: with `CommandLattice`, a caller could ignore the predicate.
//! With `Executor`, there is no way to spawn a process without going through
//! the policy check.

use std::collections::BTreeMap;
use std::io;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use crate::approval::{ApprovalRequest, ApprovalToken, Approver, CallbackApprover};
use crate::budget::AtomicBudget;
use crate::error::{NucleusError, Result};
use crate::sandbox::Sandbox;
use crate::time::MonotonicGuard;
use nucleus_ifc_kernel::discharge::DischargedBundle;
use portcullis::kernel::DecisionToken;
use portcullis::{
    CapabilityLattice, CapabilityLevel, CommandLattice, IsolationLattice, Obligations, Operation,
    PermissionLattice,
};

use crate::hardening::HostSandbox;

const MIN_EXEC_COST_USD: f64 = 0.000001;

/// Budget cost model for command execution.
#[derive(Debug, Clone, Copy)]
pub struct BudgetModel {
    /// Base cost charged for any command execution.
    pub base_cost_usd: f64,
    /// Cost charged per second of allowed execution time.
    pub cost_per_second_usd: f64,
}

impl Default for BudgetModel {
    fn default() -> Self {
        Self {
            base_cost_usd: MIN_EXEC_COST_USD,
            cost_per_second_usd: 0.0001,
        }
    }
}

/// How the Executor confines the subprocesses it spawns (most-paranoid #2).
///
/// The Executor refuses to spawn anything until a containment mode is declared
/// (the default is [`ContainmentMode::Unconfigured`], which fails closed). Each
/// mode maps to the isolation it can honestly *attest*, and a spawn is permitted
/// only when that attested isolation meets the policy's `minimum_isolation`.
///
/// This makes "silently run untrusted code as a normal host process" impossible:
/// the caller must consciously choose its posture, and an under-provisioned
/// posture is rejected rather than silently downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainmentMode {
    /// No posture declared. Every spawn refuses with `IsolationNotConfigured`.
    /// This is the fail-closed default.
    #[default]
    Unconfigured,
    /// Explicit developer opt-in to bare host execution (Tier-1 `--local`).
    /// Attests only `localhost()` isolation; emits an audit warning on use.
    /// A policy that requires anything stronger will fail closed.
    Unsandboxed,
    /// Linux host hardening via a `pre_exec` hook (no-new-privs + rlimits today;
    /// seccomp/landlock are a tracked follow-up). Attests a strengthened *file*
    /// dimension only; on non-Linux this mode fails closed with
    /// `HardeningUnavailable`. Cannot satisfy `sandboxed()`/`microvm()` policies.
    HostHardened,
    /// The Executor is itself running inside a managed microVM guest (the VM is
    /// the boundary). Attests `microvm()`. Must only be declared when the process
    /// is provably inside the sandbox (e.g. the tool-proxy's enforced
    /// `SandboxProof` at startup). No in-process hardening is applied.
    MicroVM,
}

/// Command executor with policy enforcement.
///
/// All process spawning goes through this executor, which validates commands
/// against the policy before execution.
///
/// # Environment Variable Isolation
///
/// By default, the executor clears the environment for all spawned processes,
/// preventing secret leakage from the parent process. Only explicitly allowed
/// environment variables are passed through via `with_env()`.
pub struct Executor<'a> {
    /// Capability policy (normalized)
    capabilities: CapabilityLattice,
    /// Approval obligations (normalized)
    obligations: Obligations,
    /// The command-specific policy (normalized)
    command_policy: CommandLattice,
    /// The sandbox for working directory
    sandbox: &'a Sandbox,
    /// Budget for charging execution costs
    budget: &'a AtomicBudget,
    /// Budget model for execution cost
    budget_model: BudgetModel,
    /// Time guard for temporal constraints
    time_guard: Option<&'a MonotonicGuard>,
    /// Approver for approval-gated operations
    approver: Option<Arc<dyn Approver>>,
    /// Environment variables to pass to spawned processes.
    /// Parent environment is cleared; only these vars are available.
    allowed_env: BTreeMap<String, String>,
    /// Isolation the policy demands (`effective_minimum_isolation`); the achieved
    /// containment must meet this or the spawn is refused (most-paranoid #2).
    required_isolation: IsolationLattice,
    /// The declared containment posture. Default fails closed.
    containment: ContainmentMode,
}

impl<'a> Executor<'a> {
    /// Create a new executor with the given policy and sandbox.
    ///
    /// By default, spawned processes receive an empty environment. Use `with_env()`
    /// to explicitly pass environment variables to spawned processes.
    pub fn new(
        policy: &'a PermissionLattice,
        sandbox: &'a Sandbox,
        budget: &'a AtomicBudget,
    ) -> Self {
        let normalized = policy.clone().normalize();
        // The required isolation is the policy's declared minimum; absent any
        // requirement it resolves to the weakest level (localhost = "no requirement").
        let required_isolation = normalized.effective_minimum_isolation();
        Self {
            capabilities: normalized.capabilities,
            obligations: normalized.obligations,
            command_policy: normalized.commands,
            sandbox,
            budget,
            budget_model: BudgetModel::default(),
            time_guard: None,
            approver: None,
            allowed_env: BTreeMap::new(),
            required_isolation,
            containment: ContainmentMode::Unconfigured,
        }
    }

    /// Explicitly opt into bare host execution (Tier-1 `nucleus run --local`).
    ///
    /// This is the conscious, audited downgrade: the spawned process is a normal
    /// host child with only env/cwd scoping. It attests `localhost()` isolation,
    /// so any policy requiring stronger isolation will still fail closed.
    #[must_use]
    pub fn allow_unsandboxed_local(mut self) -> Self {
        self.containment = ContainmentMode::Unsandboxed;
        self
    }

    /// Request Linux host hardening (no-new-privs + rlimits via `pre_exec`).
    /// Fails closed on non-Linux platforms.
    #[must_use]
    pub fn with_host_hardening(mut self) -> Self {
        self.containment = ContainmentMode::HostHardened;
        self
    }

    /// Declare that this Executor runs inside a managed microVM guest (the VM is
    /// the boundary). Only sound when the process is provably inside the sandbox.
    #[must_use]
    pub fn in_microvm(mut self) -> Self {
        self.containment = ContainmentMode::MicroVM;
        self
    }

    /// Set the containment posture directly (used by `PodRuntime` to plumb the
    /// pod's declared mode). Equivalent to the matching builder method.
    #[must_use]
    pub fn with_containment(mut self, mode: ContainmentMode) -> Self {
        self.containment = mode;
        self
    }

    /// The isolation the current containment mode can honestly attest.
    ///
    /// Fails closed for [`ContainmentMode::Unconfigured`] (no posture declared)
    /// and for [`ContainmentMode::HostHardened`] on non-Linux platforms.
    fn attest_containment(&self) -> Result<IsolationLattice> {
        match self.containment {
            ContainmentMode::Unconfigured => Err(NucleusError::IsolationNotConfigured),
            ContainmentMode::Unsandboxed => Ok(IsolationLattice::localhost()),
            ContainmentMode::MicroVM => Ok(IsolationLattice::microvm()),
            ContainmentMode::HostHardened => {
                #[cfg(target_os = "linux")]
                {
                    // Host hardening strengthens the *file* dimension (and reduces
                    // syscall surface, not representable here) but does NOT add
                    // process/network namespaces — so it honestly reports Shared
                    // process + Host network. Policies demanding `sandboxed()` or
                    // `microvm()` therefore fail closed against this mode.
                    Ok(IsolationLattice {
                        process: portcullis::ProcessIsolation::Shared,
                        file: portcullis::FileIsolation::Sandboxed,
                        network: portcullis::NetworkIsolation::Host,
                    })
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Err(NucleusError::HardeningUnavailable {
                        platform: std::env::consts::OS.to_string(),
                    })
                }
            }
        }
    }

    /// Fail-closed isolation gate, called at the top of every spawn path. Refuses
    /// unless the attested containment meets the policy's required isolation, and
    /// never silently downgrades (most-paranoid #2).
    fn enforce_isolation(&self) -> Result<()> {
        let achieved = self.attest_containment()?;
        if self.containment == ContainmentMode::Unsandboxed {
            tracing::warn!(
                required = %self.required_isolation,
                "AUDIT: executor spawning UNSANDBOXED (Tier-1 local opt-in) — bare host process"
            );
        }
        if !achieved.at_least(&self.required_isolation) {
            return Err(NucleusError::IsolationInsufficient {
                required: self.required_isolation.to_string(),
                achieved: achieved.to_string(),
            });
        }
        Ok(())
    }

    /// Set a time guard for temporal enforcement.
    pub fn with_time_guard(mut self, guard: &'a MonotonicGuard) -> Self {
        self.time_guard = Some(guard);
        self
    }

    /// Set the budget cost model for command execution.
    pub fn with_budget_model(mut self, model: BudgetModel) -> Self {
        self.budget_model = model;
        self
    }

    /// Set an approver for approval-gated operations.
    pub fn with_approver(mut self, approver: Arc<dyn Approver>) -> Self {
        self.approver = Some(approver);
        self
    }

    /// Set a callback-based approver for approval-gated operations.
    ///
    /// The callback receives an approval request and should return `true` if
    /// human approval was granted.
    pub fn with_approval_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ApprovalRequest) -> bool + Send + Sync + 'static,
    {
        self.approver = Some(Arc::new(CallbackApprover::new(callback)));
        self
    }

    /// Set environment variables to pass to spawned processes.
    ///
    /// This replaces any previously set environment variables. The parent
    /// process's environment is always cleared; only these explicitly
    /// allowed variables will be available to spawned commands.
    ///
    /// # Security
    ///
    /// This is the only way to pass environment variables to spawned processes.
    /// The orchestrator is responsible for filtering which credentials/env vars
    /// should be passed through based on the workload type.
    pub fn with_env(mut self, env: BTreeMap<String, String>) -> Self {
        self.allowed_env = env;
        self
    }

    /// Add a single environment variable to the allowed set.
    pub fn with_env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.allowed_env.insert(key.into(), value.into());
        self
    }

    /// Build an approval request for a command.
    pub fn approval_request(&self, command: &str) -> ApprovalRequest {
        ApprovalRequest::new(command)
    }

    /// Request approval for a command.
    pub fn request_approval(&self, command: &str) -> Result<ApprovalToken> {
        let request = self.approval_request(command);
        if let Some(ref approver) = self.approver {
            approver.approve(&request)
        } else {
            Err(NucleusError::ApprovalRequired {
                operation: request.operation().to_string(),
            })
        }
    }

    /// The single, mediated choke point through which every *synchronous* spawn
    /// is built and executed.
    ///
    /// All process hardening that is invariant across the synchronous call sites
    /// lives here exactly once: environment isolation (`env_clear` +
    /// `envs(allowed_env)`), stdout/stderr capture, and — under
    /// [`ContainmentMode::HostHardened`] — `HostSandbox::harden_std`. Callers
    /// supply only what legitimately differs between sites:
    ///
    /// * `program` / `args` — the argv (never a shell string; no shell is ever
    ///   involved, preserving the "argv-not-shell" injection defense),
    /// * `cwd` — the already-validated working directory,
    /// * `stdin_data` — `Some` to feed the child stdin over a pipe, `None` to
    ///   close it with `Stdio::null()`.
    ///
    /// This is deliberately the *only* `Command::new` on the synchronous paths.
    /// Keeping all three public methods routed through this one function lets the
    /// executor-proof gate require a `_proof: &DischargedBundle` as the final
    /// parameter here (and on every public method that reaches it): a synchronous
    /// spawn cannot even be *named* without a discharged bundle in hand, so an
    /// un-preflighted spawn is a compile error rather than a runtime check. The
    /// proof is a sealed 7-witness bundle that only `preflight_action` can mint;
    /// it is required by type but otherwise unused here (`_proof`) — its presence
    /// in the signature is the enforcement.
    fn spawn_checked(
        &self,
        program: &str,
        args: &[String],
        cwd: &std::path::Path,
        stdin_data: Option<&str>,
        _proof: &DischargedBundle,
    ) -> io::Result<Output> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .current_dir(cwd)
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env) // Only explicitly allowed vars
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Stdin: pipe it when the caller has data to write, otherwise close it.
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        if self.containment == ContainmentMode::HostHardened {
            HostSandbox::harden_std(&mut cmd);
        }

        if let Some(input) = stdin_data {
            let mut child = cmd.spawn()?;
            if let Some(ref mut stdin_pipe) = child.stdin {
                use std::io::Write;
                stdin_pipe.write_all(input.as_bytes())?;
            }
            child.wait_with_output()
        } else {
            cmd.output()
        }
    }

    /// Execute a command and return its output.
    ///
    /// The command string is parsed, validated against policy, and then executed
    /// in the sandbox directory. Requires a `DecisionToken` from `Kernel::decide()`
    /// and a `&DischargedBundle` proof (mint via `preflight_action`) — the
    /// executor-proof gate: no spawn without a discharged bundle.
    pub fn run(
        &self,
        command: &str,
        decision: &DecisionToken,
        proof: &DischargedBundle,
    ) -> Result<Output> {
        debug_assert_eq!(
            decision.operation(),
            Operation::RunBash,
            "DecisionToken operation mismatch"
        );
        // Fail-closed isolation gate: refuse unless containment is declared and
        // meets the policy's required isolation (most-paranoid #2).
        self.enforce_isolation()?;
        // Check temporal constraints
        if let Some(guard) = self.time_guard {
            guard.check()?;
        }

        // Parse the command
        let args = shell_words::split(command).map_err(|_| NucleusError::CommandDenied {
            command: command.to_string(),
            reason: "malformed command (unbalanced quotes)".into(),
        })?;

        if args.is_empty() {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "empty command".into(),
            });
        }

        // Check capability level
        self.check_capability(command, &args, None)?;

        // Check command policy (allowlist/blocklist)
        if !self.command_policy.can_execute(command) {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "blocked by command policy".into(),
            });
        }

        // Enforce budget before spawning any process
        self.reserve_budget(self.max_duration_for_run())?;

        // Build and execute the command
        let (program, program_args) = args.split_first().unwrap();

        let output =
            self.spawn_checked(program, program_args, self.sandbox.root_path(), None, proof)?;

        Ok(output)
    }

    /// Execute a command and return just the exit status.
    pub fn status(
        &self,
        command: &str,
        decision: &DecisionToken,
        proof: &DischargedBundle,
    ) -> Result<ExitStatus> {
        let output = self.run(command, decision, proof)?;
        Ok(output.status)
    }

    /// Execute a pre-parsed command array.
    ///
    /// This is the preferred method for MCP tool calls as it prevents shell injection
    /// by bypassing shell interpretation entirely.
    ///
    /// Requires a `&DischargedBundle` proof (mint via `preflight_action`). This is
    /// the executor-proof gate: an un-preflighted spawn is a *compile* error, not a
    /// runtime check. The following omits the proof and does **not** compile
    /// (mirrors the sealed-bundle `compile_fail` doctest in
    /// `nucleus_ifc_kernel::discharge`):
    ///
    /// ```compile_fail
    /// use nucleus::Executor;
    /// use nucleus::portcullis::kernel::DecisionToken;
    ///
    /// fn un_preflighted_spawn(executor: &Executor, args: &[String], dt: &DecisionToken) {
    ///     // No trailing `&DischargedBundle` — the sealed proof is missing, so
    ///     // this call cannot be typed. There is no way to spawn without one.
    ///     let _ = executor.run_args(args, None, None, dt);
    /// }
    /// ```
    pub fn run_args(
        &self,
        args: &[String],
        stdin: Option<&str>,
        directory: Option<&str>,
        decision: &DecisionToken,
        proof: &DischargedBundle,
    ) -> Result<Output> {
        debug_assert_eq!(
            decision.operation(),
            Operation::RunBash,
            "DecisionToken operation mismatch"
        );
        self.run_args_internal(args, stdin, directory, None, proof)
    }

    /// Execute a pre-parsed command array with an approval token.
    pub fn run_args_with_approval(
        &self,
        args: &[String],
        stdin: Option<&str>,
        directory: Option<&str>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
        proof: &DischargedBundle,
    ) -> Result<Output> {
        debug_assert_eq!(
            decision.operation(),
            Operation::RunBash,
            "DecisionToken operation mismatch"
        );
        self.run_args_internal(args, stdin, directory, Some(approval), proof)
    }

    /// Internal implementation for array-based command execution.
    fn run_args_internal(
        &self,
        args: &[String],
        stdin_data: Option<&str>,
        directory: Option<&str>,
        approval: Option<&ApprovalToken>,
        proof: &DischargedBundle,
    ) -> Result<Output> {
        // Fail-closed isolation gate (most-paranoid #2).
        self.enforce_isolation()?;
        // Check temporal constraints
        if let Some(guard) = self.time_guard {
            guard.check()?;
        }

        if args.is_empty() {
            return Err(NucleusError::CommandDenied {
                command: String::new(),
                reason: "empty command".into(),
            });
        }

        // Build a display string for logging/auditing (not for execution)
        let display_command = args.join(" ");

        // Check capability level
        self.check_capability(&display_command, args, approval)?;

        // Check command policy (allowlist/blocklist)
        if !self.command_policy.can_execute(&display_command) {
            return Err(NucleusError::CommandDenied {
                command: display_command,
                reason: "blocked by command policy".into(),
            });
        }

        // Enforce budget before spawning any process
        self.reserve_budget(self.max_duration_for_run())?;

        // Build the command
        let (program, program_args) = args.split_first().unwrap();

        // Set working directory
        let work_dir = if let Some(dir) = directory {
            // Reject absolute paths immediately
            if std::path::Path::new(dir).is_absolute() {
                return Err(NucleusError::SandboxEscape {
                    path: std::path::PathBuf::from(dir),
                });
            }
            // Resolve relative to sandbox root
            let resolved = self.sandbox.root_path().join(dir);
            // Canonicalize to resolve symlinks and .. components
            // Note: This requires the path to exist, which is the desired behavior
            let canonical = resolved
                .canonicalize()
                .map_err(|_| NucleusError::SandboxEscape {
                    path: resolved.clone(),
                })?;
            let sandbox_canonical = self.sandbox.root_path().canonicalize().map_err(|e| {
                NucleusError::Io(std::io::Error::new(e.kind(), "sandbox root not accessible"))
            })?;
            // Security check: ensure canonicalized path is within sandbox
            if !canonical.starts_with(&sandbox_canonical) {
                return Err(NucleusError::SandboxEscape { path: resolved });
            }
            canonical
        } else {
            self.sandbox.root_path().to_path_buf()
        };

        self.spawn_checked(program, program_args, &work_dir, stdin_data, proof)
            .map_err(Into::into)
    }

    /// Execute a command with an approval token for approval-gated operations.
    pub fn run_with_approval(
        &self,
        command: &str,
        decision: &DecisionToken,
        approval: &ApprovalToken,
        proof: &DischargedBundle,
    ) -> Result<Output> {
        debug_assert_eq!(
            decision.operation(),
            Operation::RunBash,
            "DecisionToken operation mismatch"
        );
        // Fail-closed isolation gate (most-paranoid #2).
        self.enforce_isolation()?;
        // Check temporal constraints
        if let Some(guard) = self.time_guard {
            guard.check()?;
        }

        // Parse the command
        let args = shell_words::split(command).map_err(|_| NucleusError::CommandDenied {
            command: command.to_string(),
            reason: "malformed command (unbalanced quotes)".into(),
        })?;

        if args.is_empty() {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "empty command".into(),
            });
        }

        // Check capability level (with approval token)
        self.check_capability(command, &args, Some(approval))?;

        // Check command policy (allowlist/blocklist)
        if !self.command_policy.can_execute(command) {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "blocked by command policy".into(),
            });
        }

        // Enforce budget before spawning any process
        self.reserve_budget(self.max_duration_for_run())?;

        // Build and execute the command
        let (program, program_args) = args.split_first().unwrap();

        let output =
            self.spawn_checked(program, program_args, self.sandbox.root_path(), None, proof)?;

        Ok(output)
    }

    /// Execute a command with a timeout.
    #[cfg(feature = "async")]
    pub async fn run_with_timeout(
        &self,
        command: &str,
        timeout: Duration,
        decision: &DecisionToken,
    ) -> Result<Output> {
        debug_assert_eq!(
            decision.operation(),
            Operation::RunBash,
            "DecisionToken operation mismatch"
        );
        // Fail-closed isolation gate (most-paranoid #2).
        self.enforce_isolation()?;
        // Check temporal constraints
        if let Some(guard) = self.time_guard {
            guard.check()?;
        }

        // Parse the command
        let args = shell_words::split(command).map_err(|_| NucleusError::CommandDenied {
            command: command.to_string(),
            reason: "malformed command (unbalanced quotes)".into(),
        })?;

        if args.is_empty() {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "empty command".into(),
            });
        }

        // Check capability level
        self.check_capability(command, &args, None)?;

        // Check command policy
        if !self.command_policy.can_execute(command) {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "blocked by command policy".into(),
            });
        }

        // Enforce budget before spawning any process
        self.reserve_budget(Some(timeout))?;

        // Build and execute with timeout
        let (program, program_args) = args.split_first().unwrap();

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(program_args)
            .current_dir(self.sandbox.root_path())
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env) // Only explicitly allowed vars
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if self.containment == ContainmentMode::HostHardened {
            HostSandbox::harden_tokio(&mut cmd);
        }
        let child = cmd.spawn()?;

        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(result) => result.map_err(Into::into),
            Err(_) => Err(NucleusError::TimeViolation {
                reason: format!("command timed out after {:?}", timeout),
            }),
        }
    }

    /// Execute a command with a timeout and an approval token.
    #[cfg(feature = "async")]
    pub async fn run_with_timeout_approved(
        &self,
        command: &str,
        timeout: Duration,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<Output> {
        debug_assert_eq!(
            decision.operation(),
            Operation::RunBash,
            "DecisionToken operation mismatch"
        );
        // Fail-closed isolation gate (most-paranoid #2).
        self.enforce_isolation()?;
        // Check temporal constraints
        if let Some(guard) = self.time_guard {
            guard.check()?;
        }

        // Parse the command
        let args = shell_words::split(command).map_err(|_| NucleusError::CommandDenied {
            command: command.to_string(),
            reason: "malformed command (unbalanced quotes)".into(),
        })?;

        if args.is_empty() {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "empty command".into(),
            });
        }

        // Check capability level (with approval token)
        self.check_capability(command, &args, Some(approval))?;

        // Check command policy
        if !self.command_policy.can_execute(command) {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "blocked by command policy".into(),
            });
        }

        // Enforce budget before spawning any process
        self.reserve_budget(Some(timeout))?;

        // Build and execute with timeout
        let (program, program_args) = args.split_first().unwrap();

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(program_args)
            .current_dir(self.sandbox.root_path())
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env) // Only explicitly allowed vars
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if self.containment == ContainmentMode::HostHardened {
            HostSandbox::harden_tokio(&mut cmd);
        }
        let child = cmd.spawn()?;

        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(result) => result.map_err(Into::into),
            Err(_) => Err(NucleusError::TimeViolation {
                reason: format!("command timed out after {:?}", timeout),
            }),
        }
    }

    /// Check if the command requires a certain capability level.
    fn check_capability(
        &self,
        command: &str,
        args: &[String],
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        // Determine required capability based on command type
        let (operation, capability_name, level) = if is_git_push_command(args) {
            (Operation::GitPush, "git_push", self.capabilities.git_push)
        } else if is_git_commit_command(args) {
            (
                Operation::GitCommit,
                "git_commit",
                self.capabilities.git_commit,
            )
        } else if is_pr_command(args) {
            (
                Operation::CreatePr,
                "create_pr",
                self.capabilities.create_pr,
            )
        } else {
            (Operation::RunBash, "run_bash", self.capabilities.run_bash)
        };

        if level == CapabilityLevel::Never {
            return Err(NucleusError::InsufficientCapability {
                capability: capability_name.into(),
                actual: level,
                required: CapabilityLevel::LowRisk,
            });
        }

        if self.obligations.requires(operation) {
            if let Some(token) = approval {
                if token.matches(command) {
                    Ok(())
                } else {
                    Err(NucleusError::InvalidApproval {
                        operation: command.to_string(),
                    })
                }
            } else {
                Err(NucleusError::ApprovalRequired {
                    operation: command.to_string(),
                })
            }
        } else {
            Ok(())
        }
    }

    fn max_duration_for_run(&self) -> Option<Duration> {
        self.time_guard.map(|guard| guard.remaining())
    }

    fn reserve_budget(&self, max_duration: Option<Duration>) -> Result<()> {
        let mut cost = self.budget_model.base_cost_usd;
        if self.budget_model.cost_per_second_usd > 0.0 {
            let duration = max_duration.ok_or_else(|| NucleusError::TimeViolation {
                reason: "time guard required for budget reservation".into(),
            })?;
            cost += duration.as_secs_f64() * self.budget_model.cost_per_second_usd;
        }
        self.budget.charge_usd(cost)
    }
}

/// Check if the command is a git push operation.
fn is_git_push_command(args: &[String]) -> bool {
    args.len() >= 2 && args[0] == "git" && args[1] == "push"
}

/// Check if the command is a git commit operation.
fn is_git_commit_command(args: &[String]) -> bool {
    args.len() >= 2 && args[0] == "git" && args[1] == "commit"
}

/// Check if the command is a PR creation operation (gh pr create).
fn is_pr_command(args: &[String]) -> bool {
    args.len() >= 3 && args[0] == "gh" && args[1] == "pr" && args[2] == "create"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AtomicBudget;
    use crate::sandbox::Sandbox;
    // Sanctioned cross-crate test-only bundle: runs a real `preflight_action` on a
    // known-good term. This is the only supported way for out-of-module tests to
    // obtain a sealed `DischargedBundle` (the constructor is private to discharge).
    use nucleus_ifc_kernel::discharge::test_helpers::allowed_bundle;
    use portcullis::kernel::Kernel;
    use portcullis::BudgetLattice;
    use rust_decimal::Decimal;
    use tempfile::tempdir;

    fn test_policy() -> PermissionLattice {
        let mut policy = PermissionLattice::default();
        policy.capabilities.read_files = CapabilityLevel::Never;
        policy.capabilities.run_bash = CapabilityLevel::LowRisk;
        policy.capabilities.web_fetch = CapabilityLevel::Never;
        policy.capabilities.web_search = CapabilityLevel::Never;
        policy.obligations = Obligations::default();
        policy.commands = CommandLattice::permissive();
        policy
    }

    fn test_budget() -> BudgetLattice {
        BudgetLattice {
            max_cost_usd: Decimal::try_from(10.0).unwrap(),
            consumed_usd: Decimal::ZERO,
            max_input_tokens: 100_000,
            max_output_tokens: 10_000,
        }
    }

    fn zero_budget() -> BudgetLattice {
        BudgetLattice {
            max_cost_usd: Decimal::ZERO,
            consumed_usd: Decimal::ZERO,
            max_input_tokens: 100_000,
            max_output_tokens: 10_000,
        }
    }

    /// Helper: get a DecisionToken for RunBash from a kernel matching the test policy.
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn run_token(kernel: &mut Kernel, subject: &str) -> DecisionToken {
        let (_decision, tok) = kernel.decide(Operation::RunBash, subject);
        tok.expect("test kernel should allow RunBash")
    }

    #[test]
    fn test_basic_command() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let dt = run_token(&mut kernel, "echo hello");
        let output = executor.run("echo hello", &dt, &allowed_bundle()).unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }

    #[test]
    fn test_budget_exhausted_blocks_execution() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = zero_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let dt = run_token(&mut kernel, "echo hello");
        let result = executor.run("echo hello", &dt, &allowed_bundle());
        assert!(matches!(result, Err(NucleusError::BudgetExhausted { .. })));
    }

    #[test]
    fn test_blocked_command() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.commands = CommandLattice::default(); // Has blocklist
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        // rm -rf should be blocked by executor's command policy.
        // Kernel also blocks it (CommandBlocked), so force a token to test the executor layer.
        let dt = kernel.issue_approved_token(
            Operation::RunBash,
            "test: bypass kernel for executor blocklist test",
        );
        let result = executor.run("rm -rf /", &dt, &allowed_bundle());
        assert!(result.is_err());
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_never_capability() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.capabilities.run_bash = CapabilityLevel::Never;
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        // Kernel will deny — no token. Use issue_approved_token to force a token for test.
        let (_d, tok) = kernel.decide(Operation::RunBash, "echo hello");
        assert!(tok.is_none(), "kernel should deny Never capability");

        let forced = kernel.issue_approved_token(Operation::RunBash, "test: force token");
        let result = executor.run("echo hello", &forced, &allowed_bundle());
        assert!(matches!(
            result,
            Err(NucleusError::InsufficientCapability { .. })
        ));
    }

    #[test]
    fn test_approval_required_without_callback() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.obligations.insert(Operation::RunBash);
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        // Kernel requires approval — force a token via issue_approved_token to test executor layer
        let forced = kernel.issue_approved_token(Operation::RunBash, "test: force token");
        let result = executor.run("echo hello", &forced, &allowed_bundle());
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
    }

    #[test]
    fn test_approval_with_token() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.obligations.insert(Operation::RunBash);
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_approval_callback(|_| true)
            .allow_unsandboxed_local(); // Always approve

        // Grant approval in kernel, then get a token
        kernel.grant_approval(Operation::RunBash, 1);
        let dt = run_token(&mut kernel, "echo hello");

        let approval = executor.request_approval("echo hello").unwrap();
        let result = executor.run_with_approval("echo hello", &dt, &approval, &allowed_bundle());
        assert!(result.is_ok());
    }

    #[test]
    fn test_uninhabitable_requires_approval_for_exfiltration() {
        let tmp = tempdir().unwrap();
        let mut policy = PermissionLattice::default();
        policy.capabilities.read_files = CapabilityLevel::Always; // Private data
        policy.capabilities.web_fetch = CapabilityLevel::LowRisk; // Untrusted content
        policy.capabilities.run_bash = CapabilityLevel::LowRisk; // Allows curl
        policy.obligations = Obligations::default();
        policy.commands = CommandLattice::permissive();

        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        // curl is an exfiltration vector, uninhabitable_state should require approval
        // Force a token to test the executor-level check
        let forced = kernel.issue_approved_token(Operation::RunBash, "test: force for exfil check");
        let result = executor.run("curl http://example.com", &forced, &allowed_bundle());
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
    }

    #[test]
    fn test_uninhabitable_requires_approval_for_interpreter_invocation() {
        let tmp = tempdir().unwrap();
        let mut policy = PermissionLattice::default();
        policy.capabilities.read_files = CapabilityLevel::Always; // Private data
        policy.capabilities.web_fetch = CapabilityLevel::LowRisk; // Untrusted content
        policy.capabilities.run_bash = CapabilityLevel::LowRisk; // Allows shell
        policy.obligations = Obligations::default();
        policy.commands = CommandLattice::permissive();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let forced =
            kernel.issue_approved_token(Operation::RunBash, "test: force for interpreter check");
        let result = executor.run("bash -c \"echo hi\"", &forced, &allowed_bundle());
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
    }

    #[test]
    fn test_run_args_basic() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let args = vec!["echo".to_string(), "hello".to_string(), "world".to_string()];
        let dt = run_token(&mut kernel, "echo hello world");
        let output = executor
            .run_args(&args, None, None, &dt, &allowed_bundle())
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello world"));
    }

    #[test]
    fn test_run_args_prevents_shell_injection() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        // With array form, shell metacharacters are passed literally
        let args = vec!["echo".to_string(), "$(whoami)".to_string()];
        let dt = run_token(&mut kernel, "echo $(whoami)");
        let output = executor
            .run_args(&args, None, None, &dt, &allowed_bundle())
            .unwrap();
        // Should print the literal string, not execute whoami
        assert!(String::from_utf8_lossy(&output.stdout).contains("$(whoami)"));
    }

    #[test]
    fn test_run_args_with_stdin() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let args = vec!["cat".to_string()];
        let dt = run_token(&mut kernel, "cat");
        let output = executor
            .run_args(
                &args,
                Some("hello from stdin"),
                None,
                &dt,
                &allowed_bundle(),
            )
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello from stdin"));
    }

    #[test]
    fn test_run_args_empty_command() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let args: Vec<String> = vec![];
        // Kernel also blocks empty commands, so force a token to test executor layer
        let dt = kernel.issue_approved_token(Operation::RunBash, "test: empty command");
        let result = executor.run_args(&args, None, None, &dt, &allowed_bundle());
        assert!(matches!(result, Err(NucleusError::CommandDenied { .. })));
    }

    #[test]
    fn test_run_args_directory_escape() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let args = vec!["pwd".to_string()];
        let dt = run_token(&mut kernel, "pwd");
        // Attempt to escape sandbox using absolute path
        let result = executor.run_args(&args, None, Some("/etc"), &dt, &allowed_bundle());
        assert!(matches!(result, Err(NucleusError::SandboxEscape { .. })));
    }

    #[test]
    fn test_env_isolation_clears_parent_env() {
        // Set a secret in the parent environment
        std::env::set_var("TEST_PARENT_SECRET", "super-secret-value");

        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        // Try to access the parent env var - should NOT be visible
        let dt = run_token(&mut kernel, "printenv TEST_PARENT_SECRET");
        let output = executor
            .run("printenv TEST_PARENT_SECRET", &dt, &allowed_bundle())
            .unwrap();

        // Command should succeed but output should be empty (var not found)
        // printenv returns exit code 1 when var is not found
        assert!(!output.status.success(), "env var should not be accessible");

        // Clean up
        std::env::remove_var("TEST_PARENT_SECRET");
    }

    #[test]
    fn test_env_isolation_passes_allowed_env() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);

        // Explicitly allow a specific env var
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_env_var("ALLOWED_TOKEN", "test-value-123")
            .allow_unsandboxed_local();

        // The allowed var should be visible
        let dt = run_token(&mut kernel, "printenv ALLOWED_TOKEN");
        let output = executor
            .run("printenv ALLOWED_TOKEN", &dt, &allowed_bundle())
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("test-value-123"));
    }

    #[test]
    fn test_env_isolation_with_multiple_vars() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);

        let mut env = BTreeMap::new();
        env.insert("VAR_A".to_string(), "value_a".to_string());
        env.insert("VAR_B".to_string(), "value_b".to_string());

        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_env(env)
            .allow_unsandboxed_local();

        // Both vars should be visible
        let dt_a = run_token(&mut kernel, "printenv VAR_A");
        let output_a = executor
            .run("printenv VAR_A", &dt_a, &allowed_bundle())
            .unwrap();
        assert!(output_a.status.success());
        assert!(String::from_utf8_lossy(&output_a.stdout).contains("value_a"));

        let dt_b = run_token(&mut kernel, "printenv VAR_B");
        let output_b = executor
            .run("printenv VAR_B", &dt_b, &allowed_bundle())
            .unwrap();
        assert!(output_b.status.success());
        assert!(String::from_utf8_lossy(&output_b.stdout).contains("value_b"));
    }

    #[test]
    fn test_env_isolation_run_args() {
        // Verify env isolation also works for run_args
        std::env::set_var("TEST_RUN_ARGS_SECRET", "leaked-secret");

        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();
        let mut kernel = Kernel::new(policy.clone());

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_env_var("ALLOWED_VAR", "allowed-value")
            .allow_unsandboxed_local();

        // Parent env should not be visible
        let args = vec!["printenv".to_string(), "TEST_RUN_ARGS_SECRET".to_string()];
        let dt1 = run_token(&mut kernel, "printenv TEST_RUN_ARGS_SECRET");
        let output = executor
            .run_args(&args, None, None, &dt1, &allowed_bundle())
            .unwrap();
        assert!(
            !output.status.success(),
            "parent env should not be accessible"
        );

        // But allowed env should be visible
        let args = vec!["printenv".to_string(), "ALLOWED_VAR".to_string()];
        let dt2 = run_token(&mut kernel, "printenv ALLOWED_VAR");
        let output = executor
            .run_args(&args, None, None, &dt2, &allowed_bundle())
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("allowed-value"));

        // Clean up
        std::env::remove_var("TEST_RUN_ARGS_SECRET");
    }

    // ───────────────────────────────────────────────────────────────────────
    // Fail-closed isolation gate (most-paranoid #2)
    // ───────────────────────────────────────────────────────────────────────
    mod isolation_gate {
        use super::*;

        /// Default `Unconfigured` containment refuses to spawn — the hard-flip
        /// fail-closed default that closes "silently run as a bare host process".
        #[test]
        fn unconfigured_default_refuses_spawn() {
            let tmp = tempdir().unwrap();
            let policy = test_policy();
            let mut kernel = Kernel::new(policy.clone());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&test_budget());
            let guard = MonotonicGuard::seconds(10);
            // NOTE: no containment builder called — stays Unconfigured.
            let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

            let dt = run_token(&mut kernel, "echo hi");
            let err = executor.run("echo hi", &dt, &allowed_bundle()).unwrap_err();
            assert!(
                matches!(err, NucleusError::IsolationNotConfigured),
                "expected IsolationNotConfigured, got {err:?}"
            );
        }

        /// `run_args` is gated too (not just `run`).
        #[test]
        fn unconfigured_refuses_run_args() {
            let tmp = tempdir().unwrap();
            let policy = test_policy();
            let mut kernel = Kernel::new(policy.clone());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&test_budget());
            let guard = MonotonicGuard::seconds(10);
            let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

            let args = vec!["echo".to_string(), "hi".to_string()];
            let dt = run_token(&mut kernel, "echo hi");
            let err = executor
                .run_args(&args, None, None, &dt, &allowed_bundle())
                .unwrap_err();
            assert!(
                matches!(err, NucleusError::IsolationNotConfigured),
                "got {err:?}"
            );
        }

        /// Explicit Tier-1 opt-in to unsandboxed execution allows spawn when the
        /// policy demands no stronger isolation.
        #[test]
        fn unsandboxed_opt_in_allows_spawn() {
            let tmp = tempdir().unwrap();
            let policy = test_policy();
            let mut kernel = Kernel::new(policy.clone());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&test_budget());
            let guard = MonotonicGuard::seconds(10);
            let executor = Executor::new(&policy, &sandbox, &budget)
                .with_time_guard(&guard)
                .allow_unsandboxed_local();

            let dt = run_token(&mut kernel, "echo hi");
            let output = executor.run("echo hi", &dt, &allowed_bundle()).unwrap();
            assert!(output.status.success());
        }

        /// A policy requiring a microVM is refused — never silently downgraded —
        /// when the Executor can only attest unsandboxed host execution. This is
        /// the fail-closed-without-a-VM property (the "not contained" state is
        /// simulated purely via the declared containment mode; no KVM needed).
        #[test]
        fn microvm_required_but_unsandboxed_refuses() {
            let tmp = tempdir().unwrap();
            let policy = test_policy().with_minimum_isolation(IsolationLattice::microvm());
            // Kernel built WITH microvm isolation so it still mints a token; the
            // Executor gate is what must refuse.
            let mut kernel = Kernel::with_isolation(policy.clone(), IsolationLattice::microvm());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&test_budget());
            let guard = MonotonicGuard::seconds(10);
            let executor = Executor::new(&policy, &sandbox, &budget)
                .with_time_guard(&guard)
                .allow_unsandboxed_local();

            let dt = run_token(&mut kernel, "echo hi");
            let err = executor.run("echo hi", &dt, &allowed_bundle()).unwrap_err();
            assert!(
                matches!(err, NucleusError::IsolationInsufficient { .. }),
                "expected IsolationInsufficient, got {err:?}"
            );
        }

        /// When the Executor attests it is inside a microVM, a microVM-requiring
        /// policy passes the gate.
        #[test]
        fn microvm_required_and_in_microvm_allows() {
            let tmp = tempdir().unwrap();
            let policy = test_policy().with_minimum_isolation(IsolationLattice::microvm());
            let mut kernel = Kernel::with_isolation(policy.clone(), IsolationLattice::microvm());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&test_budget());
            let guard = MonotonicGuard::seconds(10);
            let executor = Executor::new(&policy, &sandbox, &budget)
                .with_time_guard(&guard)
                .in_microvm();

            let dt = run_token(&mut kernel, "echo hi");
            let output = executor.run("echo hi", &dt, &allowed_bundle()).unwrap();
            assert!(output.status.success());
        }

        /// On non-Linux hosts, requesting host hardening fails CLOSED rather than
        /// silently running unhardened. (On Linux this path attests a strengthened
        /// file dimension instead; see the Linux smoke test.)
        #[cfg(not(target_os = "linux"))]
        #[test]
        fn host_hardening_fails_closed_off_linux() {
            let tmp = tempdir().unwrap();
            let policy = test_policy();
            let mut kernel = Kernel::new(policy.clone());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&test_budget());
            let guard = MonotonicGuard::seconds(10);
            let executor = Executor::new(&policy, &sandbox, &budget)
                .with_time_guard(&guard)
                .with_host_hardening();

            let dt = run_token(&mut kernel, "echo hi");
            let err = executor.run("echo hi", &dt, &allowed_bundle()).unwrap_err();
            assert!(
                matches!(err, NucleusError::HardeningUnavailable { .. }),
                "expected HardeningUnavailable off-Linux, got {err:?}"
            );
        }

        /// Linux smoke test: a host-hardened child actually has seccomp/no-new-privs
        /// posture. Marked ignore — needs a Linux host; validated in Linux CI.
        #[cfg(target_os = "linux")]
        #[test]
        #[ignore = "requires Linux host; run in linux CI (NoNewPrivs check)"]
        fn host_hardened_child_has_no_new_privs() {
            let tmp = tempdir().unwrap();
            let policy = test_policy();
            let mut kernel = Kernel::new(policy.clone());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&test_budget());
            let guard = MonotonicGuard::seconds(10);
            let executor = Executor::new(&policy, &sandbox, &budget)
                .with_time_guard(&guard)
                .with_host_hardening();

            let dt = run_token(&mut kernel, "cat /proc/self/status");
            let output = executor
                .run("cat /proc/self/status", &dt, &allowed_bundle())
                .unwrap();
            let status = String::from_utf8_lossy(&output.stdout);
            assert!(
                status
                    .lines()
                    .any(|l| l.starts_with("NoNewPrivs:") && l.contains('1')),
                "hardened child should have NoNewPrivs:1, got:\n{status}"
            );
        }
    }
}
