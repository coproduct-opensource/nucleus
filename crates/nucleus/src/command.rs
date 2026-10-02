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
use std::process::{Command, ExitStatus, Output};
use std::sync::Arc;
use std::time::Duration;

use crate::approval::{ApprovalRequest, ApprovalToken, Approver, CallbackApprover};
use crate::budget::AtomicBudget;
use crate::error::{NucleusError, Result};
use crate::sandbox::Sandbox;
use crate::time::MonotonicGuard;
// The sealed effects home (B1). `portcullis_core::CapabilityLattice` — the type
// `production_effects` requires — is a re-export of `nucleus_ifc_kernel`'s
// lattice (already a nucleus dependency), so no new dep is needed to name it.
use nucleus_ifc_kernel::CapabilityLattice as CoreCapabilityLattice;
use portcullis::kernel::DecisionToken;
use portcullis::{
    CapabilityLattice, CapabilityLevel, CommandLattice, IsolationLattice, Obligations, Operation,
    PermissionLattice,
};
// The Executor holds a CONCRETE `PolicyEnforced<RealEffects>` (not a trait
// object) so it can reach the async spawn home: `AsyncShellSpawnEffect` has an
// `async fn` and is not dyn-compatible, so `Arc<dyn AsyncShellSpawnEffect>`
// would be `E0038`. `ShellEffect` (sync) is still needed in scope for the
// `spawn_checked` call. Under `feature = "async"`, `AsyncShellSpawnEffect` must
// also be in scope to name `run_argv_async` on the concrete handle.
#[cfg(feature = "async")]
use portcullis_effects::AsyncShellSpawnEffect;
use portcullis_effects::authority::Authority;
use portcullis_effects::{PolicyEnforced, RealEffects, ShellEffect, production_effects_concrete};

use crate::hardening::ChildConfinement;

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
    ///
    /// "Bare" means no namespace or seccomp confinement, never root: a root
    /// runtime's child still drops to
    /// [`DEFAULT_CHILD_UID`](crate::DEFAULT_CHILD_UID) (owner decision,
    /// 2026-10-02). Only a non-root runtime's child runs at the runtime's uid,
    /// and only with [`UnsandboxedOptIn::Explicit`](crate::UnsandboxedOptIn)
    /// (the tool-proxy's `--unsandboxed`); without it every spawn is refused
    /// with [`NucleusError::UnsandboxedNotOptedIn`].
    Unsandboxed,
    /// Linux host hardening via a `pre_exec` hook (no-new-privs + rlimits today;
    /// seccomp/landlock are a tracked follow-up). Attests a strengthened *file*
    /// dimension only; on non-Linux this mode fails closed with
    /// `HardeningUnavailable`. Cannot satisfy `sandboxed()`/`microvm()` policies.
    ///
    /// A root runtime's child also drops to
    /// [`DEFAULT_CHILD_UID`](crate::DEFAULT_CHILD_UID) (owner decision,
    /// 2026-10-02); a non-root one self-restricts at the runtime's uid.
    HostHardened,
    /// The Executor is itself running inside a managed microVM guest (the VM is
    /// the boundary). Attests `microvm()`. Must only be declared when the process
    /// is provably inside the sandbox (e.g. the tool-proxy's enforced
    /// `SandboxProof` at startup).
    ///
    /// The VM is the boundary against the HOST, not against the runtime: in
    /// the guest the tool-proxy is PID 1 and root and holds every pod secret in
    /// its environment. So each child drops to the workload uid
    /// ([`DEFAULT_CHILD_UID`](crate::DEFAULT_CHILD_UID)) and is hardened, by
    /// the same [`ChildConfinement`](crate::ChildConfinement) the workload
    /// launch uses. It used to get nothing, and ran as guest root.
    ///
    /// Only a root runtime can drop. A non-root runtime under this mode
    /// refuses every spawn with
    /// [`NucleusError::ChildSeparationUnavailable`] rather than running the
    /// child at its own uid (#3120).
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
    /// Checksum of the permissions this executor runs under.
    ///
    /// A `DecisionToken` carries the checksum of the permissions it was decided
    /// against, and `run` refuses a token whose checksum is not this one. Before
    /// this, the redeem-side check compared two `Operation`s and consulted no
    /// state at all, so a token decided under one policy was redeemable under
    /// any other.
    permissions: String,
    /// The declared containment posture. Default fails closed.
    containment: ContainmentMode,
    /// The operator's opt-in to the bare host tier. `Absent` unless declared
    /// ([`Self::allow_unsandboxed_local`], [`Self::with_unsandboxed_opt_in`]):
    /// a non-root `Unsandboxed` executor without it refuses every spawn.
    unsandboxed_opt_in: crate::UnsandboxedOptIn,
    /// The sealed effects home (B1) that *both* the synchronous and the async
    /// spawns delegate to. Held as the **concrete** `PolicyEnforced<RealEffects>`
    /// (from [`production_effects_concrete`]), not a trait object, for one
    /// reason: the async home [`AsyncShellSpawnEffect::run_argv_async`] has an
    /// `async fn`, so its trait is not dyn-compatible and `Arc<dyn
    /// AsyncShellSpawnEffect>` is a compile error (`E0038`). The concrete handle
    /// impls both `ShellEffect` (sync — reached by `spawn_checked`) and, under
    /// `feature = "async"`, `AsyncShellSpawnEffect` (async — reached by
    /// `run_with_timeout*`), so one value serves both paths. Every call still
    /// passes through the `PolicyEnforced` capability gate, and the only raw
    /// `Command::new` / `tokio::process::Command::new` now lives inside the
    /// sealed home, reached solely past that gate and a single-use `Authority`.
    effects: Arc<PolicyEnforced<RealEffects>>,
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
        let permissions = normalized.checksum();
        // The required isolation is the policy's declared minimum; absent any
        // requirement it resolves to the weakest level (localhost = "no requirement").
        let required_isolation = normalized.effective_minimum_isolation();
        // Build the sealed effects home from this Executor's own capabilities.
        // `production_effects_concrete` wraps `RealEffects` in `PolicyEnforced`
        // (concrete, so the async spawn is reachable — see the `effects` field),
        // so the spawn keeps the crate's policy gate; the Executor's own
        // capability checks (`check_capability`) remain the primary
        // authorization and run first, so behavior on the bash path is unchanged.
        let effects = Arc::new(production_effects_concrete(core_capabilities(
            &normalized.capabilities,
        )));
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
            permissions,
            containment: ContainmentMode::Unconfigured,
            unsandboxed_opt_in: crate::UnsandboxedOptIn::Absent,
            effects,
        }
    }

    /// Explicitly opt into bare host execution (Tier-1 `nucleus run --local`).
    ///
    /// This is the conscious, audited downgrade: the spawned process is a normal
    /// host child with only env/cwd scoping. It attests `localhost()` isolation,
    /// so any policy requiring stronger isolation will still fail closed.
    ///
    /// The name IS the explicit opt-in: it declares the mode and
    /// [`UnsandboxedOptIn::Explicit`](crate::UnsandboxedOptIn::Explicit)
    /// together. [`Self::with_containment`] with `Unsandboxed` alone does not,
    /// and a non-root runtime then refuses every spawn by name.
    #[must_use]
    pub fn allow_unsandboxed_local(mut self) -> Self {
        self.containment = ContainmentMode::Unsandboxed;
        self.unsandboxed_opt_in = crate::UnsandboxedOptIn::Explicit;
        self
    }

    /// Carry the operator's bare-tier opt-in (the tool-proxy's
    /// `--unsandboxed`) to the confinement decision. Meaningful only under
    /// `Unsandboxed` on a non-root runtime; it grants nothing elsewhere.
    #[must_use]
    pub fn with_unsandboxed_opt_in(mut self, opt_in: crate::UnsandboxedOptIn) -> Self {
        self.unsandboxed_opt_in = opt_in;
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
    /// The raw `Command::new` no longer lives here: this now DELEGATES to the
    /// sealed effects home [`ShellEffect::run_argv`] (brick B1), which reproduces
    /// the previous inline builder byte-for-byte — environment isolation
    /// (`env_clear` + `envs(allowed_env)`), stdout/stderr capture, stdin
    /// pipe-vs-null, and the host-hardening hook. Callers supply only what
    /// legitimately differs between sites:
    ///
    /// * `program` / `args` — the argv (never a shell string; no shell is ever
    ///   involved, preserving the "argv-not-shell" injection defense),
    /// * `cwd` — the already-validated working directory,
    /// * `stdin_data` — `Some` to feed the child stdin over a pipe, `None` to
    ///   close it with `Stdio::null()`.
    ///
    /// The invariant hardening is threaded through `run_argv`: the environment
    /// allowlist as `&self.allowed_env`, and the executor's
    /// [`ChildConfinement`] as the injected `harden` hook — always `Some`, for
    /// every containment mode, so there is no un-hardened branch to take.
    ///
    /// Keeping all three public methods routed through this one function lets the
    /// executor-proof gate require an `Authority` as the final parameter
    /// here (and on every public method that reaches it): a synchronous spawn
    /// cannot even be *named* without a discharged bundle in hand, so an
    /// un-preflighted spawn is a compile error rather than a runtime check. The
    /// bundle is a sealed 7-witness proof that only `preflight_action` can mint;
    /// it is now threaded on into `run_argv` (the sealed home requires it too).
    /// Every synchronous spawn, inside the execute-on-consume guard: the watched
    /// files are snapshotted before the child runs and any change it made is
    /// reverted and refused after it exits, whatever its exit status
    /// (`consume_guard`).
    fn spawn_checked(
        &self,
        program: &str,
        args: &[String],
        cwd: &std::path::Path,
        stdin_data: Option<&str>,
        authority: Authority,
    ) -> Result<Output> {
        // Decided BEFORE anything is snapshotted or spawned, and handed to the
        // spawn by value: `spawn_unguarded` cannot be called without one.
        let confinement = self.child_confinement()?;
        self.hand_over_workspace(confinement);
        let before = crate::consume_guard::Snapshot::take(self.sandbox.root_dir())?;
        let result = self.spawn_unguarded(program, args, cwd, stdin_data, confinement, authority);
        let reverted = before.revert_changes(self.sandbox.root_dir())?;
        if !reverted.is_empty() {
            let command = std::iter::once(program)
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            return Err(crate::consume_guard::refusal(&command, &reverted));
        }
        result.map_err(NucleusError::from)
    }

    /// How every child this executor spawns is confined — asked of the one
    /// decider ([`ChildConfinement::for_containment`]), never re-derived here.
    ///
    /// # Errors
    /// [`NucleusError::IsolationNotConfigured`] when no posture was declared.
    pub fn child_confinement(&self) -> Result<ChildConfinement> {
        ChildConfinement::for_containment(self.containment, self.unsandboxed_opt_in)
    }

    /// Give the sandbox root to a dropped child's uid so it can enter and
    /// write its working directory — the same best-effort step the workload
    /// launch takes for its work dir. Not the security control (the drop is);
    /// a read-only scratch legitimately refuses it.
    fn hand_over_workspace(&self, confinement: ChildConfinement) {
        if let Err(e) = confinement.hand_over(self.sandbox.root_path()) {
            tracing::warn!(
                root = %self.sandbox.root_path().display(),
                error = %e,
                "could not hand the sandbox root to the child uid; the child runs \
                 without ownership of it (expected when the scratch is read-only)"
            );
        }
    }

    fn spawn_unguarded(
        &self,
        program: &str,
        args: &[String],
        cwd: &std::path::Path,
        stdin_data: Option<&str>,
        confinement: ChildConfinement,
        authority: Authority,
    ) -> io::Result<Output> {
        // The hook is ALWAYS installed: there is no `None` to forget. Under
        // MicroVM the child leaves the runtime's (root) uid exactly as the
        // workload does; `hardening.rs` has the table.
        let hook = move |cmd: &mut Command| confinement.apply(cmd);
        let harden: Option<&(dyn Fn(&mut Command) + Send + Sync)> = Some(&hook);

        // Delegate to the sealed home. `stdin_data` (an `Option<&str>`) becomes
        // `Option<&[u8]>` via `str::as_bytes` — the child receives the exact same
        // bytes the previous inline `write_all(input.as_bytes())` wrote.
        self.effects.run_argv(
            program,
            args,
            cwd,
            stdin_data.map(str::as_bytes),
            &self.allowed_env,
            harden,
            authority,
        )
    }

    /// Execute a command and return its output.
    ///
    /// The command string is parsed, validated against policy, and then executed
    /// in the sandbox directory. Requires a `DecisionToken` from `Kernel::decide()`
    /// and an `Authority` (mint via `preflight_action`, then wrap) — the
    /// executor-proof gate: no spawn without a discharged bundle.
    pub fn run(
        &self,
        command: &str,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<Output> {
        decision.redeem(&self.permissions, Operation::RunBash)?;
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

        // The ONE argv predicate both spawn boundaries apply (#2573).
        refuse_bad_argv(&args, command)?;

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

        let output = self.spawn_checked(
            program,
            program_args,
            self.sandbox.root_path(),
            None,
            authority,
        )?;

        Ok(output)
    }

    /// Execute a command and return just the exit status.
    pub fn status(
        &self,
        command: &str,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<ExitStatus> {
        let output = self.run(command, decision, authority)?;
        Ok(output.status)
    }

    /// Execute a pre-parsed command array.
    ///
    /// This is the preferred method for MCP tool calls as it prevents shell injection
    /// by bypassing shell interpretation entirely.
    ///
    /// Requires an `Authority` (mint via `preflight_action`, then wrap). This is
    /// the executor-proof gate: an un-preflighted spawn is a *compile* error, not a
    /// runtime check.
    ///
    /// ## Why the snippet below passes the wrong number of arguments on purpose
    ///
    /// This doctest used to omit the last argument entirely:
    ///
    /// ```ignore
    /// let _ = executor.run_args(args, None, None, dt);   // four arguments
    /// ```
    ///
    /// and its comment claimed the snippet failed because "the sealed proof is
    /// missing". **It did not.** Compiled directly, that snippet reports
    ///
    /// ```text
    /// error[E0061]: this method takes 5 arguments but 4 arguments were supplied
    /// ```
    ///
    /// — measured, not inferred. `compile_fail` passes when a snippet fails for
    /// ANY reason, so an arity error satisfied it exactly as well as a missing
    /// authority would: the test would have stayed green if the fifth parameter
    /// were `verbose: bool`. It pinned the arity of the signature and nothing
    /// about authorisation (ADR 0007 D-3, and I-1 — a gate whose green is
    /// indistinguishable from vacuity). The comment also named
    /// `&DischargedBundle`, a parameter this signature has not had for some time.
    ///
    /// So the snippet now supplies the right NUMBER of arguments and the wrong
    /// KIND, which makes the failure a type error about `Authority` specifically:
    ///
    /// ```compile_fail
    /// use nucleus::Executor;
    /// use nucleus::portcullis::kernel::DecisionToken;
    ///
    /// fn un_preflighted_spawn(executor: &Executor, args: &[String], dt: &DecisionToken) {
    ///     // Right arity, no authority. `()` is not an `Authority`, and an
    ///     // `Authority` cannot be conjured — `Authority::new` takes a sealed
    ///     // `DischargedBundle` whose constructor is private to discharge.
    ///     let _ = executor.run_args(args, None, None, dt, ());
    /// }
    /// ```
    ///
    /// Established by perturbation rather than assumed, the discipline the
    /// `Authority` doctests in `portcullis-effects` already document: pass a real
    /// `Authority` as that fifth argument and the snippet COMPILES, so the failure
    /// does depend on the authority and on nothing else.
    pub fn run_args(
        &self,
        args: &[String],
        stdin: Option<&str>,
        directory: Option<&str>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<Output> {
        decision.redeem(&self.permissions, Operation::RunBash)?;
        self.run_args_internal(args, stdin, directory, None, authority)
    }

    /// Execute a pre-parsed command array with an approval token.
    pub fn run_args_with_approval(
        &self,
        args: &[String],
        stdin: Option<&str>,
        directory: Option<&str>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<Output> {
        decision.redeem(&self.permissions, Operation::RunBash)?;
        self.run_args_internal(args, stdin, directory, Some(approval), authority)
    }

    /// Internal implementation for array-based command execution.
    fn run_args_internal(
        &self,
        args: &[String],
        stdin_data: Option<&str>,
        directory: Option<&str>,
        approval: Option<&ApprovalToken>,
        authority: Authority,
    ) -> Result<Output> {
        // Fail-closed isolation gate (most-paranoid #2).
        self.enforce_isolation()?;
        // Check temporal constraints
        if let Some(guard) = self.time_guard {
            guard.check()?;
        }

        // The ONE argv predicate both spawn boundaries apply (#2573).
        refuse_bad_argv(args, &args.join(" "))?;

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

        self.spawn_checked(program, program_args, &work_dir, stdin_data, authority)
    }

    /// Execute a command with an approval token for approval-gated operations.
    pub fn run_with_approval(
        &self,
        command: &str,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<Output> {
        decision.redeem(&self.permissions, Operation::RunBash)?;
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

        // The ONE argv predicate both spawn boundaries apply (#2573).
        refuse_bad_argv(&args, command)?;

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

        let output = self.spawn_checked(
            program,
            program_args,
            self.sandbox.root_path(),
            None,
            authority,
        )?;

        Ok(output)
    }

    /// Execute a command with a timeout.
    ///
    /// Requires a `&DischargedBundle` proof (mint via `preflight_action`): the
    /// async spawn is behind the same executor-proof gate as the synchronous
    /// paths, so it cannot be *named* without a discharged bundle. (This
    /// parameter was added when the raw `tokio::process::Command::new` was
    /// relocated into the sealed async home; the previous inline spawn predated
    /// the gate and did not require one — see the delegation below.)
    #[cfg(feature = "async")]
    pub async fn run_with_timeout(
        &self,
        command: &str,
        timeout: Duration,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<Output> {
        decision.redeem(&self.permissions, Operation::RunBash)?;
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

        // The ONE argv predicate both spawn boundaries apply (#2573).
        refuse_bad_argv(&args, command)?;

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

        self.spawn_with_timeout(program, program_args, timeout, authority)
            .await
    }

    /// Execute a command with a timeout and an approval token.
    ///
    /// Requires an `Authority`, like [`Self::run_with_timeout`].
    #[cfg(feature = "async")]
    pub async fn run_with_timeout_approved(
        &self,
        command: &str,
        timeout: Duration,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<Output> {
        decision.redeem(&self.permissions, Operation::RunBash)?;
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

        // The ONE argv predicate both spawn boundaries apply (#2573).
        refuse_bad_argv(&args, command)?;

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

        self.spawn_with_timeout(program, program_args, timeout, authority)
            .await
    }

    /// The single async spawn choke point, shared by `run_with_timeout` and
    /// `run_with_timeout_approved`.
    ///
    /// The raw `tokio::process::Command::new` no longer lives here: this
    /// DELEGATES to the sealed async home
    /// [`AsyncShellSpawnEffect::run_argv_async`] (brick B1), reached through the
    /// concrete `PolicyEnforced<RealEffects>` handle (a trait object is
    /// impossible — the trait is not dyn-compatible). The sealed home reproduces
    /// the previous inline builder exactly: `env_clear` + `envs(allowed_env)`,
    /// piped stdout/stderr, `Stdio::null()` stdin (the timeout paths never feed
    /// stdin, so `None` is passed), `kill_on_drop(true)`, the executor's
    /// [`ChildConfinement`] as the hook, and `tokio::time::timeout` around
    /// the wait.
    ///
    /// Behavior is preserved byte-for-byte, including the error mapping: the
    /// sealed home surfaces a timeout as `io::ErrorKind::TimedOut`, which is
    /// mapped back to [`NucleusError::TimeViolation`] with the identical message;
    /// every other `io::Error` maps through `From` to [`NucleusError::Io`] — the
    /// same result the previous `result.map_err(Into::into)` / `?` produced.
    #[cfg(feature = "async")]
    async fn spawn_with_timeout(
        &self,
        program: &str,
        program_args: &[String],
        timeout: Duration,
        authority: Authority,
    ) -> Result<Output> {
        // The same confinement as the synchronous spawn, on `tokio::process`.
        let confinement = self.child_confinement()?;
        self.hand_over_workspace(confinement);
        let hook = move |cmd: &mut tokio::process::Command| confinement.apply(cmd.as_std_mut());
        let harden: Option<&(dyn Fn(&mut tokio::process::Command) + Send + Sync)> = Some(&hook);

        // The execute-on-consume guard, as on the synchronous path: a timed-out
        // command can have written before it was killed, so the comparison runs
        // on every outcome.
        let before = crate::consume_guard::Snapshot::take(self.sandbox.root_dir())?;

        // The previous inline spawn used `Stdio::null()` for stdin (no input), so
        // pass `None`. `Some(timeout)` asks the sealed home to wrap the wait in
        // `tokio::time::timeout`.
        let result = self
            .effects
            .run_argv_async(
                program,
                program_args,
                self.sandbox.root_path(),
                None,
                &self.allowed_env,
                harden,
                Some(timeout),
                authority,
            )
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    NucleusError::TimeViolation {
                        reason: format!("command timed out after {:?}", timeout),
                    }
                } else {
                    NucleusError::from(e)
                }
            });
        let reverted = before.revert_changes(self.sandbox.root_dir())?;
        if !reverted.is_empty() {
            let command = std::iter::once(program)
                .chain(program_args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            return Err(crate::consume_guard::refusal(&command, &reverted));
        }
        result
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
            // The command executor used to key approvals on the RAW COMMAND
            // (`echo hello`) — no operation at all, and so a third vocabulary
            // beside the kernel's and the sandbox's. Measured on a live pod:
            // the kernel deferred `RunBash echo nucleus-agency`, a person
            // approved exactly that, and this gate then asked for
            // `echo nucleus-agency` and refused the retry as unapproved. Same
            // defect as #2406, one layer over. One name, from
            // `approval::approval_key`.
            let key = crate::approval::approval_key(operation, command);
            if let Some(token) = approval {
                if token.matches(&key) {
                    Ok(())
                } else {
                    Err(NucleusError::InvalidApproval { operation: key })
                }
            } else {
                Err(NucleusError::ApprovalRequired { operation: key })
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

/// Convert the Executor's `portcullis::CapabilityLattice` into the
/// `portcullis_core` lattice `production_effects` expects.
///
/// The two lattices carry the identical 13 named dimensions and share the same
/// `CapabilityLevel` enum (both re-exported from `portcullis_core`), so this is
/// a straight field-for-field copy; the `portcullis` lattice's extension
/// dimensions have no `portcullis_core` counterpart and are not spawn-relevant,
/// so they are dropped.
fn core_capabilities(caps: &CapabilityLattice) -> CoreCapabilityLattice {
    CoreCapabilityLattice {
        read_files: caps.read_files,
        write_files: caps.write_files,
        edit_files: caps.edit_files,
        run_bash: caps.run_bash,
        glob_search: caps.glob_search,
        grep_search: caps.grep_search,
        web_search: caps.web_search,
        web_fetch: caps.web_fetch,
        git_commit: caps.git_commit,
        git_push: caps.git_push,
        create_pr: caps.create_pr,
        manage_pods: caps.manage_pods,
        spawn_agent: caps.spawn_agent,
    }
}

/// Program basename, so a path-qualified binary (`/usr/bin/git`) classifies by
/// its real operation instead of slipping into the broad `run_bash` bucket and
/// bypassing a per-operation capability (e.g. `git_push = Never`).
fn program_basename(prog: &str) -> &str {
    prog.rsplit('/').next().unwrap_or(prog)
}

/// Check if the command is a git push operation.
/// Refuse a malformed argv with the shared predicate (`portcullis_effects::argv`),
/// as a `CommandDenied` whose reason carries the shared prefix. This is the
/// executor's half of the parity with `RealEffects::run_argv`, which applies
/// the same function to the same argv and refuses with the same message —
/// see `tests::argv_parity`.
fn refuse_bad_argv(args: &[String], display: &str) -> Result<()> {
    portcullis_effects::argv::split_and_check(args)
        .map(|_| ())
        .map_err(|rejection| NucleusError::CommandDenied {
            command: display.to_string(),
            reason: rejection.message(),
        })
}

fn is_git_push_command(args: &[String]) -> bool {
    args.len() >= 2 && program_basename(&args[0]) == "git" && args[1] == "push"
}

/// Check if the command is a git commit operation.
fn is_git_commit_command(args: &[String]) -> bool {
    args.len() >= 2 && program_basename(&args[0]) == "git" && args[1] == "commit"
}

/// Check if the command is a PR creation operation (gh pr create).
fn is_pr_command(args: &[String]) -> bool {
    args.len() >= 3 && program_basename(&args[0]) == "gh" && args[1] == "pr" && args[2] == "create"
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;
