//! Command execution with policy enforcement.
//!
//! Unlike `lattice_guard::CommandLattice` which provides a `can_execute()` predicate,
//! `Executor` actually spawns processes - but only after validating against policy.
//!
//! The key difference: with `CommandLattice`, a caller could ignore the predicate.
//! With `Executor`, there is no way to spawn a process without going through
//! the policy check.

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
}

impl<'a> Executor<'a> {
    /// Create a new executor with the given policy and sandbox.
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
}
