//! Run command - Execute tasks with enforced permissions

use anyhow::{bail, Result};
use clap::Args;
use lattice_guard::{BudgetLattice, PermissionLattice};
use nucleus::{CallbackApprover, NucleusError, PodRuntime, PodSpec};
use rust_decimal::Decimal;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use crate::config::Config;
use crate::profiles::Profile;

/// Run a task with enforced permissions
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Task prompt (use - for stdin)
    pub prompt: String,

    /// Working directory (default: current directory)
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,

    /// Permission profile to use
    #[arg(short, long, default_value = "restrictive")]
    pub profile: String,

    /// Custom permission config file (overrides --profile)
    #[arg(short, long)]
    pub config: Option<String>,

    /// Maximum budget in USD (overrides profile)
    #[arg(long)]
    pub max_cost: Option<f64>,

    /// Timeout in seconds
    #[arg(long, default_value = "3600")]
    pub timeout: u64,

    /// Claude model to use
    #[arg(long, default_value = "claude-sonnet-4-20250514")]
    pub model: String,

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    pub output: String,

    /// Dry run: show what would be executed without running
    #[arg(long)]
    pub dry_run: bool,

    /// Run the agent command through nucleus enforcement (process spawn guarded)
    #[arg(long)]
    pub enforce_runner: bool,
}

/// Execute the run command
pub async fn execute(args: RunArgs, global_config_path: &str) -> Result<()> {
    // Load global config (reserved for future use)
    let _global_config = Config::load(global_config_path)?;

    // Read prompt from stdin if "-"
    let prompt = if args.prompt == "-" {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        buffer.trim().to_string()
    } else {
        args.prompt.clone()
    };

    if prompt.is_empty() {
        bail!("Prompt cannot be empty");
    }

    // Resolve working directory
    let work_dir = shellexpand::tilde(&args.dir).to_string();
    let work_dir = PathBuf::from(&work_dir).canonicalize()?;

    info!(
        prompt_len = prompt.len(),
        work_dir = %work_dir.display(),
        profile = %args.profile,
        "Starting nucleus execution"
    );

    // Build permission lattice
    let policy = if let Some(ref config_path) = args.config {
        // Load custom config
        load_permission_config(config_path)?
    } else {
        // Use profile
        Profile::from_name(&args.profile)
            .map(|p| p.to_lattice())
            .unwrap_or_else(|| {
                eprintln!(
                    "Warning: Unknown profile '{}', using restrictive",
                    args.profile
                );
                PermissionLattice::restrictive()
            })
    };

    // Override budget if specified
    let policy = if let Some(max_cost) = args.max_cost {
        PermissionLattice {
            budget: BudgetLattice {
                max_cost_usd: Decimal::try_from(max_cost).unwrap_or(Decimal::from(5)),
                ..policy.budget
            },
            ..policy
        }
    } else {
        policy
    };
    let policy = policy.normalize();

    // Create pod runtime (kubelet-style instance)
    let spec = PodSpec::new(
        policy.clone(),
        work_dir.clone(),
        Duration::from_secs(args.timeout),
    );
    let mut pod = PodRuntime::new(spec)?;

    // Attach approver for approval-gated operations only when needed
    if has_approval_obligations(&policy) {
        let approver = Arc::new(CallbackApprover::new(|request| {
            // Interactive approval prompt
            eprint!("Approve command '{}'? [y/N] ", request.operation());
            io::stderr().flush().ok();

            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            input.trim().eq_ignore_ascii_case("y")
        }));
        pod = pod.with_approver(approver)?;

    }

    let executor = pod.executor();

    if args.dry_run {
        println!("Dry run - would execute with:");
        println!("  Working directory: {}", work_dir.display());
        println!("  Profile: {}", args.profile);
        println!("  Budget: ${:.2}", policy.budget.max_cost_usd);
        println!("  Timeout: {}s", args.timeout);
        println!("  Trifecta constraint: {}", policy.trifecta_constraint);
        println!("  Enforce runner: {}", args.enforce_runner);
        println!();
        println!("Capabilities:");
        println!("  read_files: {:?}", policy.capabilities.read_files);
        println!("  write_files: {:?}", policy.capabilities.write_files);
        println!("  run_bash: {:?}", policy.capabilities.run_bash);
        println!("  git_push: {:?}", policy.capabilities.git_push);
        println!("  web_fetch: {:?}", policy.capabilities.web_fetch);
        return Ok(());
    }

    // Build Claude Code command (allowed tools reflect policy, but do not enforce it).
    let allowed_tools = build_allowed_tools(&policy);

    info!(
        allowed_tools = %allowed_tools,
        model = %args.model,
        enforce_runner = args.enforce_runner,
        "Spawning Claude Code"
    );

    let mut argv = Vec::new();
    argv.push("claude".to_string());
    argv.push("--print".to_string());
    argv.push("--model".to_string());
    argv.push(args.model.clone());
    argv.push("--allowedTools".to_string());
    argv.push(allowed_tools);
    argv.push("--max-turns".to_string());
    argv.push("20".to_string());
    argv.push("--max-budget-usd".to_string());
    argv.push(policy.budget.max_cost_usd.to_string());
    if has_approval_obligations(&policy) {
        argv.push("--permission-mode".to_string());
        argv.push("plan".to_string());
    }
    argv.push(prompt.clone());

    let start = std::time::Instant::now();
    let output = if args.enforce_runner {
        let command = shell_words::join(&argv);
        match executor.run(&command) {
            Ok(output) => output,
            Err(NucleusError::ApprovalRequired { operation }) => {
                let token = executor.request_approval(&operation)?;
                executor.run_with_approval(&command, &token)?
            }
            Err(err) => return Err(err.into()),
        }
    } else {
        let mut cmd = Command::new("claude");
        cmd.args(argv.iter().skip(1))
            .current_dir(&work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.output()?
    };
    let duration = start.elapsed();

    // Charge budget for execution
    // (In a real implementation, we'd parse the actual cost from Claude's output)
    let estimated_cost = 0.01; // Placeholder
    if let Err(e) = pod.budget().charge_usd(estimated_cost) {
        error!(error = %e, "Budget charge failed");
    }

    // Output results
    if args.output == "json" {
        let result = serde_json::json!({
            "success": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
            "duration_ms": duration.as_millis(),
            "budget_consumed": pod.budget().consumed_usd(),
            "budget_remaining": pod.budget().remaining_usd(),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        // Print stdout
        io::stdout().write_all(&output.stdout)?;

        // Print summary
        if !output.status.success() {
            eprintln!("\n--- Execution Failed ---");
            eprintln!("Exit code: {:?}", output.status.code());
            if !output.stderr.is_empty() {
                eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        eprintln!("\n--- Summary ---");
        eprintln!("Duration: {:?}", duration);
        eprintln!("Budget consumed: ${:.4}", pod.budget().consumed_usd());
        eprintln!("Budget remaining: ${:.4}", pod.budget().remaining_usd());
    }

    if output.status.success() {
        Ok(())
    } else {
        bail!("Execution failed with exit code {:?}", output.status.code())
    }
}

/// Load permission config from a TOML file
fn load_permission_config(path: &str) -> Result<PermissionLattice> {
    let expanded = shellexpand::tilde(path).to_string();
    let content = std::fs::read_to_string(&expanded)?;

    // For now, just use a preset based on the file
    // In a full implementation, we'd parse a custom format
    let config: toml::Value = toml::from_str(&content)?;

    // Check for profile key
    if let Some(profile) = config.get("profile").and_then(|v| v.as_str()) {
        if let Some(p) = Profile::from_name(profile) {
            return Ok(p.to_lattice());
        }
    }

    // Default to restrictive
    Ok(PermissionLattice::restrictive())
}

/// Build --allowedTools string from policy
fn build_allowed_tools(policy: &PermissionLattice) -> String {
    use lattice_guard::CapabilityLevel;

    let mut tools = Vec::new();

    // File operations
    if policy.capabilities.read_files >= CapabilityLevel::LowRisk {
        tools.push("Read");
    }
    if policy.capabilities.write_files >= CapabilityLevel::LowRisk {
        tools.push("Write");
    }
    if policy.capabilities.edit_files >= CapabilityLevel::LowRisk {
        tools.push("Edit");
    }
    if policy.capabilities.glob_search >= CapabilityLevel::LowRisk {
        tools.push("Glob");
    }
    if policy.capabilities.grep_search >= CapabilityLevel::LowRisk {
        tools.push("Grep");
    }

    // Web operations
    if policy.capabilities.web_search >= CapabilityLevel::LowRisk {
        tools.push("WebSearch");
    }
    if policy.capabilities.web_fetch >= CapabilityLevel::LowRisk {
        tools.push("WebFetch");
    }

    // Bash - be careful with trifecta
    if policy.capabilities.run_bash >= CapabilityLevel::LowRisk {
        tools.push("Bash");
    }

    // Task tool for sub-agents
    tools.push("Task");

    tools.join(",")
}

/// Check if any approval obligations are present.
fn has_approval_obligations(policy: &PermissionLattice) -> bool {
    !policy.obligations.approvals.is_empty()
}
