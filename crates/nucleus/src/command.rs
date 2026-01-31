//! Command execution with policy enforcement.
//!
//! Unlike `lattice_guard::CommandLattice` which provides a `can_execute()` predicate,
//! `Executor` actually spawns processes - but only after validating against policy.
//!
//! The key difference: with `CommandLattice`, a caller could ignore the predicate.
//! With `Executor`, there is no way to spawn a process without going through
//! the policy check.

use std::collections::HashSet;
use std::process::{Command, ExitStatus, Output, Stdio};

use crate::budget::AtomicBudget;
use crate::error::{NucleusError, Result};
use crate::sandbox::Sandbox;
use crate::time::MonotonicGuard;
use lattice_guard::{CapabilityLevel, CommandLattice, PermissionLattice};

/// Command executor with policy enforcement.
///
/// All process spawning goes through this executor, which validates commands
/// against the policy before execution.
pub struct Executor<'a> {
    /// The full permission policy
    policy: &'a PermissionLattice,
    /// The command-specific policy (extracted for convenience)
    command_policy: &'a CommandLattice,
    /// The sandbox for working directory
    sandbox: &'a Sandbox,
    /// Budget for charging execution costs
    budget: &'a AtomicBudget,
    /// Time guard for temporal constraints
    time_guard: Option<&'a MonotonicGuard>,
    /// Approval callback for AskFirst operations
    approval_callback: Option<Box<dyn Fn(&str) -> bool + Send + Sync>>,
}

impl<'a> Executor<'a> {
    /// Create a new executor with the given policy and sandbox.
    pub fn new(
        policy: &'a PermissionLattice,
        sandbox: &'a Sandbox,
        budget: &'a AtomicBudget,
    ) -> Self {
        Self {
            policy,
            command_policy: &policy.commands,
            sandbox,
            budget,
            time_guard: None,
            approval_callback: None,
        }
    }

    /// Set a time guard for temporal enforcement.
    pub fn with_time_guard(mut self, guard: &'a MonotonicGuard) -> Self {
        self.time_guard = Some(guard);
        self
    }

    /// Set an approval callback for AskFirst operations.
    ///
    /// The callback receives the command string and should return `true` if
    /// human approval was granted.
    pub fn with_approval_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.approval_callback = Some(Box::new(callback));
        self
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
        self.check_capability(command, &args)?;

        // Check command policy (allowlist/blocklist)
        if !self.command_policy.can_execute(command) {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "blocked by command policy".into(),
            });
        }

        // Check for trifecta completion
        self.check_trifecta(command, &args)?;

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

    /// Execute a command with a timeout.
    #[cfg(feature = "async")]
    pub async fn run_with_timeout(
        &self,
        command: &str,
        timeout: Duration,
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

        // Check capability level
        self.check_capability(command, &args)?;

        // Check command policy
        if !self.command_policy.can_execute(command) {
            return Err(NucleusError::CommandDenied {
                command: command.to_string(),
                reason: "blocked by command policy".into(),
            });
        }

        // Check for trifecta completion
        self.check_trifecta(command, &args)?;

        // Build and execute with timeout
        let (program, program_args) = args.split_first().unwrap();

        let mut child = tokio::process::Command::new(program)
            .args(program_args)
            .current_dir(self.sandbox.root_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(result) => result.map_err(Into::into),
            Err(_) => {
                // Kill the process on timeout
                child.kill().await.ok();
                Err(NucleusError::TimeViolation {
                    reason: format!("command timed out after {:?}", timeout),
                })
            }
        }
    }

    /// Check if the command requires a certain capability level.
    fn check_capability(&self, command: &str, args: &[String]) -> Result<()> {
        let _program = &args[0];

        // Determine required capability based on command type
        let (capability_name, level) = if is_git_push_command(args) {
            ("git_push", self.policy.capabilities.git_push)
        } else if is_git_commit_command(args) {
            ("git_commit", self.policy.capabilities.git_commit)
        } else if is_pr_command(args) {
            ("create_pr", self.policy.capabilities.create_pr)
        } else {
            ("run_bash", self.policy.capabilities.run_bash)
        };

        match level {
            CapabilityLevel::Never => {
                return Err(NucleusError::InsufficientCapability {
                    capability: capability_name.into(),
                    actual: level,
                    required: CapabilityLevel::AskFirst,
                });
            }
            CapabilityLevel::AskFirst => {
                // Check if we have an approval callback
                if let Some(ref callback) = self.approval_callback {
                    if !callback(command) {
                        return Err(NucleusError::ApprovalRequired {
                            operation: command.to_string(),
                        });
                    }
                } else {
                    return Err(NucleusError::ApprovalRequired {
                        operation: command.to_string(),
                    });
                }
            }
            CapabilityLevel::LowRisk | CapabilityLevel::Always => {
                // Allowed
            }
        }

        Ok(())
    }

    /// Check if executing this command would complete the lethal trifecta.
    fn check_trifecta(&self, command: &str, args: &[String]) -> Result<()> {
        if !self.policy.trifecta_constraint {
            return Ok(());
        }

        // Check if this command is an exfiltration vector
        let is_exfil = is_git_push_command(args)
            || is_pr_command(args)
            || is_network_command(args);

        if !is_exfil {
            return Ok(());
        }

        // Check if we have private data access AND untrusted content exposure
        let has_private_data = self.policy.capabilities.read_files >= CapabilityLevel::LowRisk;
        let has_untrusted = self.policy.capabilities.web_fetch >= CapabilityLevel::LowRisk
            || self.policy.capabilities.web_search >= CapabilityLevel::LowRisk;

        if has_private_data && has_untrusted {
            return Err(NucleusError::TrifectaBlocked {
                operation: command.to_string(),
            });
        }

        Ok(())
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

/// Check if the command could send data over the network.
fn is_network_command(args: &[String]) -> bool {
    let network_programs: HashSet<&str> = ["curl", "wget", "nc", "netcat", "ssh", "scp", "rsync"]
        .into_iter()
        .collect();

    args.first()
        .map(|p| network_programs.contains(p.as_str()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AtomicBudget;
    use crate::sandbox::Sandbox;
    use lattice_guard::{BudgetLattice, CapabilityLattice, PathLattice};
    use rust_decimal::Decimal;
    use tempfile::tempdir;

    fn test_policy() -> PermissionLattice {
        PermissionLattice {
            capabilities: CapabilityLattice {
                run_bash: CapabilityLevel::LowRisk,
                ..Default::default()
            },
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

    #[test]
    fn test_basic_command() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&PathLattice::default(), tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let executor = Executor::new(&policy, &sandbox, &budget);

        let output = executor.run("echo hello").unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }

    #[test]
    fn test_blocked_command() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.commands = CommandLattice::default(); // Has blocklist
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&PathLattice::default(), tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let executor = Executor::new(&policy, &sandbox, &budget);

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

        let sandbox = Sandbox::new(&PathLattice::default(), tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let executor = Executor::new(&policy, &sandbox, &budget);

        let result = executor.run("echo hello");
        assert!(matches!(result, Err(NucleusError::InsufficientCapability { .. })));
    }

    #[test]
    fn test_askfirst_without_callback() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.capabilities.run_bash = CapabilityLevel::AskFirst;
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&PathLattice::default(), tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let executor = Executor::new(&policy, &sandbox, &budget);

        let result = executor.run("echo hello");
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
    }

    #[test]
    fn test_askfirst_with_approval() {
        let tmp = tempdir().unwrap();
        let mut policy = test_policy();
        policy.capabilities.run_bash = CapabilityLevel::AskFirst;
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&PathLattice::default(), tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_approval_callback(|_| true); // Always approve

        let result = executor.run("echo hello");
        assert!(result.is_ok());
    }

    #[test]
    fn test_trifecta_blocks_exfiltration() {
        let tmp = tempdir().unwrap();
        let policy = PermissionLattice {
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,    // Private data
                web_fetch: CapabilityLevel::LowRisk,    // Untrusted content
                run_bash: CapabilityLevel::LowRisk,     // Allows curl
                ..Default::default()
            },
            commands: CommandLattice::permissive(),
            trifecta_constraint: true,
            ..Default::default()
        };
        let budget_policy = test_budget();

        let sandbox = Sandbox::new(&PathLattice::default(), tmp.path()).unwrap();
        let budget = AtomicBudget::new(&budget_policy);
        let executor = Executor::new(&policy, &sandbox, &budget);

        // curl is an exfiltration vector, trifecta should block it
        let result = executor.run("curl http://example.com");
        assert!(matches!(result, Err(NucleusError::TrifectaBlocked { .. })));
    }
}
