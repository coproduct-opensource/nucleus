//! Command execution with policy enforcement.
//!
//! Unlike `lattice_guard::CommandLattice` which provides a `can_execute()` predicate,
//! `Executor` actually spawns processes - but only after validating against policy.
//!
//! The key difference: with `CommandLattice`, a caller could ignore the predicate.
//! With `Executor`, there is no way to spawn a process without going through
//! the policy check.

use std::collections::BTreeMap;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use crate::approval::{ApprovalRequest, ApprovalToken, Approver, CallbackApprover};
use crate::budget::AtomicBudget;
use crate::error::{NucleusError, Result};
use crate::sandbox::Sandbox;
use crate::time::MonotonicGuard;
use lattice_guard::{
    CapabilityLattice, CapabilityLevel, CommandLattice, Obligations, Operation, PermissionLattice,
};

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
        }
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

    /// Execute a command and return its output.
    ///
    /// The command string is parsed, validated against policy, and then executed
    /// in the sandbox directory.
    pub fn run(&self, command: &str) -> Result<Output> {
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

        let output = Command::new(program)
            .args(program_args)
            .current_dir(self.sandbox.root_path())
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env) // Only explicitly allowed vars
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        Ok(output)
    }

    /// Execute a command and return just the exit status.
    pub fn status(&self, command: &str) -> Result<ExitStatus> {
        let output = self.run(command)?;
        Ok(output.status)
    }

    /// Execute a pre-parsed command array.
    ///
    /// This is the preferred method for MCP tool calls as it prevents shell injection
    /// by bypassing shell interpretation entirely.
    pub fn run_args(
        &self,
        args: &[String],
        stdin: Option<&str>,
        directory: Option<&str>,
    ) -> Result<Output> {
        self.run_args_internal(args, stdin, directory, None)
    }

    /// Execute a pre-parsed command array with an approval token.
    pub fn run_args_with_approval(
        &self,
        args: &[String],
        stdin: Option<&str>,
        directory: Option<&str>,
        approval: &ApprovalToken,
    ) -> Result<Output> {
        self.run_args_internal(args, stdin, directory, Some(approval))
    }

    /// Internal implementation for array-based command execution.
    fn run_args_internal(
        &self,
        args: &[String],
        stdin_data: Option<&str>,
        directory: Option<&str>,
        approval: Option<&ApprovalToken>,
    ) -> Result<Output> {
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

        let mut cmd = Command::new(program);
        cmd.args(program_args)
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env); // Only explicitly allowed vars

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
        cmd.current_dir(&work_dir);

        // Handle stdin
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        // Spawn and handle stdin if needed
        if let Some(input) = stdin_data {
            let mut child = cmd.spawn()?;
            if let Some(ref mut stdin_pipe) = child.stdin {
                use std::io::Write;
                stdin_pipe.write_all(input.as_bytes())?;
            }
            child.wait_with_output().map_err(Into::into)
        } else {
            cmd.output().map_err(Into::into)
        }
    }

    /// Execute a command with an approval token for approval-gated operations.
    pub fn run_with_approval(&self, command: &str, approval: &ApprovalToken) -> Result<Output> {
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

        let output = Command::new(program)
            .args(program_args)
            .current_dir(self.sandbox.root_path())
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env) // Only explicitly allowed vars
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        Ok(output)
    }

    /// Execute a command with a timeout.
    #[cfg(feature = "async")]
    pub async fn run_with_timeout(&self, command: &str, timeout: Duration) -> Result<Output> {
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

        let child = tokio::process::Command::new(program)
            .args(program_args)
            .current_dir(self.sandbox.root_path())
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env) // Only explicitly allowed vars
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

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
        approval: &ApprovalToken,
    ) -> Result<Output> {
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

        let child = tokio::process::Command::new(program)
            .args(program_args)
            .current_dir(self.sandbox.root_path())
            .env_clear() // Security: prevent secret leakage from parent
            .envs(&self.allowed_env) // Only explicitly allowed vars
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

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
    use lattice_guard::{BudgetLattice, CapabilityLattice};
    use rust_decimal::Decimal;
    use tempfile::tempdir;

    fn test_policy() -> PermissionLattice {
        PermissionLattice {
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::LowRisk,
                web_fetch: CapabilityLevel::Never,
                web_search: CapabilityLevel::Never,
                ..Default::default()
            },
            obligations: Obligations::default(),
            commands: CommandLattice::permissive(),
            ..Default::default()
        }
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

    #[test]
    fn test_basic_command() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let output = executor.run("echo hello").unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }

    #[test]
    fn test_budget_exhausted_blocks_execution() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = zero_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let result = executor.run("echo hello");
        assert!(matches!(result, Err(NucleusError::BudgetExhausted { .. })));
    }

    #[test]
    fn test_blocked_command() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.commands = CommandLattice::default(); // Has blocklist
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        // rm -rf should be blocked
        let result = executor.run("rm -rf /");
        assert!(result.is_err());
    }

    #[test]
    fn test_never_capability() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.capabilities.run_bash = CapabilityLevel::Never;
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let result = executor.run("echo hello");
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

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let result = executor.run("echo hello");
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
    }

    #[test]
    fn test_approval_with_token() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.obligations.insert(Operation::RunBash);
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_approval_callback(|_| true); // Always approve

        let token = executor.request_approval("echo hello").unwrap();
        let result = executor.run_with_approval("echo hello", &token);
        assert!(result.is_ok());
    }

    #[test]
    fn test_trifecta_requires_approval_for_exfiltration() {
        let tmp = tempdir().unwrap();
        let policy = PermissionLattice {
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always, // Private data
                web_fetch: CapabilityLevel::LowRisk, // Untrusted content
                run_bash: CapabilityLevel::LowRisk,  // Allows curl
                ..Default::default()
            },
            obligations: Obligations::default(),
            commands: CommandLattice::permissive(),
            trifecta_constraint: true,
            ..Default::default()
        };
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        // curl is an exfiltration vector, trifecta should require approval
        let result = executor.run("curl http://example.com");
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
    }

    #[test]
    fn test_trifecta_requires_approval_for_interpreter_invocation() {
        let tmp = tempdir().unwrap();
        let policy = PermissionLattice {
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always, // Private data
                web_fetch: CapabilityLevel::LowRisk, // Untrusted content
                run_bash: CapabilityLevel::LowRisk,  // Allows shell
                ..Default::default()
            },
            obligations: Obligations::default(),
            commands: CommandLattice::permissive(),
            trifecta_constraint: true,
            ..Default::default()
        };
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let result = executor.run("bash -c \"echo hi\"");
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
    }

    #[test]
    fn test_run_args_basic() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let args = vec!["echo".to_string(), "hello".to_string(), "world".to_string()];
        let output = executor.run_args(&args, None, None).unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello world"));
    }

    #[test]
    fn test_run_args_prevents_shell_injection() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        // With array form, shell metacharacters are passed literally
        let args = vec!["echo".to_string(), "$(whoami)".to_string()];
        let output = executor.run_args(&args, None, None).unwrap();
        // Should print the literal string, not execute whoami
        assert!(String::from_utf8_lossy(&output.stdout).contains("$(whoami)"));
    }

    #[test]
    fn test_run_args_with_stdin() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let args = vec!["cat".to_string()];
        let output = executor
            .run_args(&args, Some("hello from stdin"), None)
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello from stdin"));
    }

    #[test]
    fn test_run_args_empty_command() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let args: Vec<String> = vec![];
        let result = executor.run_args(&args, None, None);
        assert!(matches!(result, Err(NucleusError::CommandDenied { .. })));
    }

    #[test]
    fn test_run_args_directory_escape() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let args = vec!["pwd".to_string()];
        // Attempt to escape sandbox using absolute path
        let result = executor.run_args(&args, None, Some("/etc"));
        assert!(matches!(result, Err(NucleusError::SandboxEscape { .. })));
    }

    #[test]
    fn test_env_isolation_clears_parent_env() {
        // Set a secret in the parent environment
        std::env::set_var("TEST_PARENT_SECRET", "super-secret-value");

        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        // Try to access the parent env var - should NOT be visible
        let output = executor.run("printenv TEST_PARENT_SECRET").unwrap();

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

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);

        // Explicitly allow a specific env var
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_env_var("ALLOWED_TOKEN", "test-value-123");

        // The allowed var should be visible
        let output = executor.run("printenv ALLOWED_TOKEN").unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("test-value-123"));
    }

    #[test]
    fn test_env_isolation_with_multiple_vars() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);

        let mut env = BTreeMap::new();
        env.insert("VAR_A".to_string(), "value_a".to_string());
        env.insert("VAR_B".to_string(), "value_b".to_string());

        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_env(env);

        // Both vars should be visible
        let output_a = executor.run("printenv VAR_A").unwrap();
        assert!(output_a.status.success());
        assert!(String::from_utf8_lossy(&output_a.stdout).contains("value_a"));

        let output_b = executor.run("printenv VAR_B").unwrap();
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

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_env_var("ALLOWED_VAR", "allowed-value");

        // Parent env should not be visible
        let args = vec!["printenv".to_string(), "TEST_RUN_ARGS_SECRET".to_string()];
        let output = executor.run_args(&args, None, None).unwrap();
        assert!(
            !output.status.success(),
            "parent env should not be accessible"
        );

        // But allowed env should be visible
        let args = vec!["printenv".to_string(), "ALLOWED_VAR".to_string()];
        let output = executor.run_args(&args, None, None).unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("allowed-value"));

        // Clean up
        std::env::remove_var("TEST_RUN_ARGS_SECRET");
    }
}
