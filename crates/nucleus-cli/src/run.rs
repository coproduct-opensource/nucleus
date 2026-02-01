//! Run command - Execute tasks via tool-proxy (enforced by default)

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use lattice_guard::{BudgetLattice, CapabilityLevel, PermissionLattice};
use nucleus::{CallbackApprover, NucleusError, PodRuntime, PodSpec};
use nucleus_spec::{PodSpec as SpecPodSpec, PodSpecInner, PolicySpec};
use rust_decimal::Decimal;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info};
use uuid::Uuid;

use crate::config::Config;
use crate::profiles::Profile;

/// Run a task with tool-level enforcement (unsafe mode optional)
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

    /// Path to nucleus-tool-proxy binary (enforced mode)
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_PATH",
        default_value = "nucleus-tool-proxy"
    )]
    pub tool_proxy_path: String,

    /// Path to nucleus-mcp binary (enforced mode)
    #[arg(long, env = "NUCLEUS_MCP_PATH", default_value = "nucleus-mcp")]
    pub mcp_path: String,

    /// Allow running Claude directly without tool-level enforcement (unsafe)
    #[arg(long)]
    pub unsafe_allow_claude: bool,
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

    if args.dry_run {
        println!("Dry run - would execute with:");
        println!("  Working directory: {}", work_dir.display());
        println!("  Profile: {}", args.profile);
        println!("  Budget: ${:.2}", policy.budget.max_cost_usd);
        println!("  Timeout: {}s", args.timeout);
        println!("  Trifecta constraint: {}", policy.trifecta_constraint);
        println!(
            "  Mode: {}",
            if args.unsafe_allow_claude {
                "unsafe"
            } else {
                "enforced"
            }
        );
        println!();
        println!("Capabilities:");
        println!("  read_files: {:?}", policy.capabilities.read_files);
        println!("  write_files: {:?}", policy.capabilities.write_files);
        println!("  run_bash: {:?}", policy.capabilities.run_bash);
        println!("  git_push: {:?}", policy.capabilities.git_push);
        println!("  web_fetch: {:?}", policy.capabilities.web_fetch);
        return Ok(());
    }

    if args.unsafe_allow_claude {
        run_unsafe(&args, &policy, &work_dir, &prompt).await
    } else {
        run_enforced(&args, &policy, &work_dir, &prompt).await
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

/// Build --allowedTools string from policy (unsafe direct mode)
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

fn resolve_binary_path(path: &str) -> Result<PathBuf> {
    let candidate = PathBuf::from(path);
    if candidate.exists() {
        return Ok(candidate);
    }

    if !candidate.is_absolute()
        && !path.contains(std::path::MAIN_SEPARATOR)
        && !path.contains('/')
        && !path.contains('\\')
    {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sibling = dir.join(path);
                if sibling.exists() {
                    return Ok(sibling);
                }
            }
        }
    }

    Ok(candidate)
}

struct ProxyGuard {
    child: Option<Child>,
    tmp_dir: PathBuf,
}

impl ProxyGuard {
    fn new(child: Child, tmp_dir: PathBuf) -> Self {
        Self {
            child: Some(child),
            tmp_dir,
        }
    }

    fn child_mut(&mut self) -> Option<&mut Child> {
        self.child.as_mut()
    }

    fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.tmp_dir);
    }
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn run_enforced(
    args: &RunArgs,
    policy: &PermissionLattice,
    work_dir: &Path,
    prompt: &str,
) -> Result<()> {
    warn_unimplemented_caps(policy);

    let run_id = Uuid::new_v4();
    let tmp_dir = std::env::temp_dir().join(format!("nucleus-cli-{run_id}"));
    fs::create_dir_all(&tmp_dir)?;

    let spec_path = tmp_dir.join("pod.yaml");
    let announce_path = tmp_dir.join("tool-proxy.addr");
    let mcp_config_path = tmp_dir.join("mcp.json");
    let tool_proxy_log = tmp_dir.join("tool-proxy.log");
    let auth_secret = Uuid::new_v4().to_string();

    write_tool_proxy_spec(&spec_path, policy, work_dir, args.timeout)?;

    let tool_proxy_path = resolve_binary_path(&args.tool_proxy_path)?;
    let mcp_command_path = resolve_binary_path(&args.mcp_path)?;

    let proxy_child = spawn_tool_proxy(
        &tool_proxy_path,
        &spec_path,
        &announce_path,
        &tool_proxy_log,
        &auth_secret,
    )?;
    let mut guard = ProxyGuard::new(proxy_child, tmp_dir.clone());

    let proxy_addr = wait_for_announce(
        guard
            .child_mut()
            .ok_or_else(|| anyhow!("tool-proxy missing child process"))?,
        &announce_path,
    )
    .await?;
    let proxy_url = if proxy_addr.starts_with("http://") || proxy_addr.starts_with("https://") {
        proxy_addr
    } else {
        format!("http://{proxy_addr}")
    };

    write_mcp_config(
        &mcp_config_path,
        &mcp_command_path,
        &proxy_url,
        &auth_secret,
        &spec_path,
    )?;

    let allowed_tools = build_mcp_allowed_tools(policy);
    if allowed_tools.is_empty() {
        guard.shutdown();
        return Err(anyhow!(
            "no allowed MCP tools for enforced mode (policy is too restrictive)"
        ));
    }

    info!(
        allowed_tools = %allowed_tools.join(","),
        model = %args.model,
        "Spawning Claude Code (enforced MCP mode)"
    );

    let start = Instant::now();
    let output = match run_claude_mcp(
        args,
        policy,
        &mcp_config_path,
        &allowed_tools,
        prompt,
        work_dir,
    ) {
        Ok(output) => output,
        Err(err) => {
            guard.shutdown();
            return Err(err);
        }
    };
    let duration = start.elapsed();
    let result = render_output(&output, duration, args.output.as_str(), None);
    guard.shutdown();
    result
}

async fn run_unsafe(
    args: &RunArgs,
    policy: &PermissionLattice,
    work_dir: &Path,
    prompt: &str,
) -> Result<()> {
    let mut policy = policy.clone();
    policy.commands.allow("claude");
    let policy = policy.normalize();

    let spec = PodSpec::new(
        policy.clone(),
        work_dir.to_path_buf(),
        Duration::from_secs(args.timeout),
    );
    let mut pod = PodRuntime::new(spec)?;

    if has_approval_obligations(&policy) {
        let approver = Arc::new(CallbackApprover::new(|request| {
            eprint!("Approve command '{}'? [y/N] ", request.operation());
            io::stderr().flush().ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            input.trim().eq_ignore_ascii_case("y")
        }));
        pod = pod.with_approver(approver)?;
    }

    let executor = pod.executor();
    let allowed_tools = build_allowed_tools(&policy);

    info!(
        allowed_tools = %allowed_tools,
        model = %args.model,
        "Spawning Claude Code (unsafe direct mode)"
    );

    let mut argv = vec![
        "claude".to_string(),
        "--print".to_string(),
        "--model".to_string(),
        args.model.clone(),
        "--allowedTools".to_string(),
        allowed_tools,
        "--max-turns".to_string(),
        "20".to_string(),
        "--max-budget-usd".to_string(),
        policy.budget.max_cost_usd.to_string(),
    ];
    if has_approval_obligations(&policy) {
        argv.push("--permission-mode".to_string());
        argv.push("plan".to_string());
    }
    argv.push(prompt.to_string());

    let start = Instant::now();
    let command = shell_words::join(&argv);
    let output = match executor.run(&command) {
        Ok(output) => output,
        Err(NucleusError::ApprovalRequired { operation }) => {
            let token = executor.request_approval(&operation)?;
            executor.run_with_approval(&command, &token)?
        }
        Err(err) => return Err(err.into()),
    };
    let duration = start.elapsed();

    let estimated_cost = 0.01;
    if let Err(e) = pod.budget().charge_usd(estimated_cost) {
        error!(error = %e, "Budget charge failed");
    }

    render_output(&output, duration, args.output.as_str(), Some(&pod))
}

fn write_tool_proxy_spec(
    spec_path: &Path,
    policy: &PermissionLattice,
    work_dir: &Path,
    timeout_secs: u64,
) -> Result<()> {
    let spec = SpecPodSpec::new(PodSpecInner {
        work_dir: work_dir.to_path_buf(),
        timeout_seconds: timeout_secs,
        policy: PolicySpec::Inline {
            lattice: Box::new(policy.clone()),
        },
        budget_model: None,
        resources: None,
        network: None,
        image: None,
        vsock: None,
        seccomp: None,
        cgroup: None,
    });
    let yaml = serde_yaml::to_string(&spec)?;
    fs::write(spec_path, yaml)?;
    Ok(())
}

fn spawn_tool_proxy(
    tool_proxy_path: &Path,
    spec_path: &Path,
    announce_path: &Path,
    log_path: &Path,
    auth_secret: &str,
) -> Result<Child> {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    let mut cmd = Command::new(tool_proxy_path);
    cmd.arg("--spec")
        .arg(spec_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--announce-path")
        .arg(announce_path)
        .arg("--auth-secret")
        .arg(auth_secret)
        .stdout(Stdio::from(log_file.try_clone()?))
        .stderr(Stdio::from(log_file));

    let child = cmd.spawn().context("failed to spawn nucleus-tool-proxy")?;
    Ok(child)
}

async fn wait_for_announce(child: &mut Child, announce_path: &Path) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(contents) = fs::read_to_string(announce_path) {
            let addr = contents.trim();
            if !addr.is_empty() {
                return Ok(addr.to_string());
            }
        }

        if let Some(status) = child.try_wait()? {
            return Err(anyhow!("tool-proxy exited early with {status}"));
        }

        if Instant::now() > deadline {
            return Err(anyhow!("timed out waiting for tool-proxy to announce"));
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn write_mcp_config(
    mcp_path: &Path,
    mcp_command: &Path,
    proxy_url: &str,
    auth_secret: &str,
    spec_path: &Path,
) -> Result<()> {
    #[derive(Serialize)]
    struct McpServer {
        #[serde(rename = "type")]
        server_type: String,
        command: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
        #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        env: std::collections::BTreeMap<String, String>,
    }

    #[derive(Serialize)]
    struct McpConfig {
        #[serde(rename = "mcpServers")]
        servers: std::collections::BTreeMap<String, McpServer>,
    }

    let mut env = std::collections::BTreeMap::new();
    env.insert("NUCLEUS_MCP_PROXY_URL".to_string(), proxy_url.to_string());
    env.insert(
        "NUCLEUS_MCP_AUTH_SECRET".to_string(),
        auth_secret.to_string(),
    );
    env.insert(
        "NUCLEUS_MCP_SPEC".to_string(),
        spec_path.display().to_string(),
    );

    let server = McpServer {
        server_type: "stdio".to_string(),
        command: mcp_command.display().to_string(),
        args: Vec::new(),
        env,
    };

    let mut servers = std::collections::BTreeMap::new();
    servers.insert("nucleus".to_string(), server);

    let config = McpConfig { servers };
    let json = serde_json::to_string_pretty(&config)?;
    fs::write(mcp_path, json)?;
    Ok(())
}

fn run_claude_mcp(
    args: &RunArgs,
    policy: &PermissionLattice,
    mcp_config_path: &Path,
    allowed_tools: &[String],
    prompt: &str,
    work_dir: &Path,
) -> Result<std::process::Output> {
    let mut cmd = Command::new("claude");
    cmd.arg("--print")
        .arg("--model")
        .arg(&args.model)
        .arg("--mcp-config")
        .arg(mcp_config_path)
        .arg("--allowedTools")
        .arg(allowed_tools.join(","))
        .arg("--max-turns")
        .arg("20")
        .arg("--max-budget-usd")
        .arg(policy.budget.max_cost_usd.to_string())
        .arg(prompt)
        .current_dir(work_dir);

    if has_approval_obligations(policy) {
        cmd.arg("--permission-mode").arg("plan");
    }

    cmd.output().context("failed to spawn claude")
}

fn build_mcp_allowed_tools(policy: &PermissionLattice) -> Vec<String> {
    let mut tools = Vec::new();
    if policy.capabilities.read_files >= CapabilityLevel::LowRisk {
        tools.push("mcp__nucleus__read".to_string());
    }
    if policy.capabilities.write_files >= CapabilityLevel::LowRisk
        || policy.capabilities.edit_files >= CapabilityLevel::LowRisk
    {
        tools.push("mcp__nucleus__write".to_string());
    }
    if policy.capabilities.run_bash >= CapabilityLevel::LowRisk
        || policy.capabilities.git_commit >= CapabilityLevel::LowRisk
        || policy.capabilities.git_push >= CapabilityLevel::LowRisk
        || policy.capabilities.create_pr >= CapabilityLevel::LowRisk
    {
        tools.push("mcp__nucleus__run".to_string());
    }
    tools
}

fn warn_unimplemented_caps(policy: &PermissionLattice) {
    let mut missing = Vec::new();
    if policy.capabilities.web_search >= CapabilityLevel::LowRisk {
        missing.push("web_search");
    }
    if policy.capabilities.web_fetch >= CapabilityLevel::LowRisk {
        missing.push("web_fetch");
    }
    if policy.capabilities.glob_search >= CapabilityLevel::LowRisk {
        missing.push("glob_search");
    }
    if policy.capabilities.grep_search >= CapabilityLevel::LowRisk {
        missing.push("grep_search");
    }
    if !missing.is_empty() {
        info!(
            missing = %missing.join(","),
            "Enforced mode does not expose tools for these capabilities"
        );
    }
}

fn render_output(
    output: &std::process::Output,
    duration: Duration,
    mode: &str,
    pod: Option<&PodRuntime>,
) -> Result<()> {
    if mode == "json" {
        let result = serde_json::json!({
            "success": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
            "duration_ms": duration.as_millis(),
            "budget_consumed": pod.map(|p| p.budget().consumed_usd()),
            "budget_remaining": pod.map(|p| p.budget().remaining_usd()),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        io::stdout().write_all(&output.stdout)?;

        if !output.status.success() {
            eprintln!("\n--- Execution Failed ---");
            eprintln!("Exit code: {:?}", output.status.code());
            if !output.stderr.is_empty() {
                eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
            }
        }

        eprintln!("\n--- Summary ---");
        eprintln!("Duration: {:?}", duration);
        if let Some(pod) = pod {
            eprintln!("Budget consumed: ${:.4}", pod.budget().consumed_usd());
            eprintln!("Budget remaining: ${:.4}", pod.budget().remaining_usd());
        }
    }

    if output.status.success() {
        Ok(())
    } else {
        bail!("Execution failed with exit code {:?}", output.status.code())
    }
}
