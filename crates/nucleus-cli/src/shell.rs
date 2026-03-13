//! Shell command - Launch interactive Claude Code with nucleus security context
//!
//! Spawns nucleus-tool-proxy and nucleus-mcp as the security boundary,
//! then launches `claude` in interactive mode with only sandboxed tools
//! visible. All tool calls flow through the permission lattice.

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use nucleus_spec::{CredentialsSpec, PodSpec as SpecPodSpec, PodSpecInner, PolicySpec};
use portcullis::{BudgetLattice, PermissionLattice};
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tracing::info;
use uuid::Uuid;

use crate::profiles;
use crate::run::{build_mcp_allowed_tools, write_mcp_config, McpEnvConfig};

/// Launch interactive Claude Code with nucleus as the security context.
///
/// All built-in Claude tools are replaced by sandboxed equivalents that
/// flow through the nucleus permission lattice. The tool-proxy enforces
/// capabilities, budget, command restrictions, and taint tracking.
#[derive(Args, Debug)]
pub struct ShellArgs {
    /// Working directory (default: current directory)
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,

    /// Permission profile to use
    #[arg(short, long, default_value = "codegen")]
    pub profile: String,

    /// Custom permission config file (overrides --profile)
    #[arg(short, long)]
    pub config: Option<String>,

    /// Maximum budget in USD (overrides profile)
    #[arg(long)]
    pub max_cost: Option<f64>,

    /// Timeout in seconds
    #[arg(long, default_value = "7200")]
    pub timeout: u64,

    /// Environment variables to pass as credentials (KEY=VALUE).
    /// Can be specified multiple times: --env FOO=bar --env BAZ=qux
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub envs: Vec<String>,

    /// Path to nucleus-mcp binary
    #[arg(long, env = "NUCLEUS_MCP_PATH", default_value = "nucleus-mcp")]
    pub mcp_path: String,

    /// Path to nucleus-tool-proxy binary
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_PATH",
        default_value = "nucleus-tool-proxy"
    )]
    pub tool_proxy_path: String,

    /// Path to write kernel decision trace in JSONL format.
    #[arg(long, env = "NUCLEUS_KERNEL_TRACE")]
    pub kernel_trace: Option<PathBuf>,

    /// Print the MCP config and exit (useful for manual claude invocation)
    #[arg(long)]
    pub print_config: bool,

    /// Additional arguments to pass to claude
    #[arg(last = true)]
    pub claude_args: Vec<String>,
}

/// Execute the shell command
pub async fn execute(args: ShellArgs) -> Result<()> {
    // Resolve working directory
    let work_dir = shellexpand::tilde(&args.dir).to_string();
    let work_dir = PathBuf::from(&work_dir).canonicalize()?;

    // Build permission lattice
    let policy = if let Some(ref config_path) = args.config {
        load_permission_config(config_path)?
    } else {
        profiles::resolve(&args.profile).unwrap_or_else(|| {
            eprintln!("Warning: Unknown profile '{}', using codegen", args.profile);
            profiles::resolve("codegen").unwrap_or_else(PermissionLattice::restrictive)
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

    let run_id = Uuid::new_v4();
    let tmp_dir = std::env::temp_dir().join(format!("nucleus-shell-{run_id}"));
    fs::create_dir_all(&tmp_dir)?;

    // Generate per-session auth secrets
    let auth_secret = hex::encode(rand::random::<[u8; 32]>());
    let approval_secret = hex::encode(rand::random::<[u8; 32]>());

    // Build PodSpec
    let spec_path = tmp_dir.join("pod.yaml");
    let pod_spec = build_shell_pod_spec(&args, &policy, &work_dir)?;
    let yaml = serde_yaml::to_string(&pod_spec)?;
    fs::write(&spec_path, &yaml)?;

    // Generate sandbox token
    let spec_hash = hex::encode(Sha256::digest(yaml.as_bytes()));
    let sandbox_token = nucleus_client::generate_sandbox_token(
        auth_secret.as_bytes(),
        &run_id.to_string(),
        &spec_hash,
    );

    let announce_path = tmp_dir.join("proxy.addr");
    let audit_path = tmp_dir.join("audit.log");

    // Resolve tool-proxy binary
    let proxy_bin = resolve_binary_path(&args.tool_proxy_path)?;

    info!(
        proxy_bin = %proxy_bin.display(),
        profile = %args.profile,
        work_dir = %work_dir.display(),
        "Starting nucleus shell"
    );

    // Spawn tool-proxy as subprocess
    let mut proxy_child = tokio::process::Command::new(&proxy_bin)
        .arg("--spec")
        .arg(&spec_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--announce-path")
        .arg(&announce_path)
        .arg("--auth-secret")
        .arg(&auth_secret)
        .arg("--approval-secret")
        .arg(&approval_secret)
        .arg("--audit-log")
        .arg(&audit_path)
        .env("NUCLEUS_SANDBOX_TOKEN", &sandbox_token)
        .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn nucleus-tool-proxy")?;

    // Wait for proxy readiness
    let proxy_addr = wait_for_proxy_ready(&announce_path, Duration::from_secs(10)).await?;
    let proxy_url = format!("http://{proxy_addr}");

    info!(proxy_url = %proxy_url, "Tool-proxy ready");

    // Build MCP config
    let mcp_config_path = tmp_dir.join("mcp.json");
    let mcp_command_path = resolve_binary_path(&args.mcp_path)?;

    write_mcp_config(
        &mcp_config_path,
        &mcp_command_path,
        &McpEnvConfig {
            proxy_url: &proxy_url,
            auth_secret: Some(&auth_secret),
            approval_secret: Some(&approval_secret),
            spec_path: &spec_path,
            kernel_trace: args.kernel_trace.as_deref(),
            sandbox_token: Some(&sandbox_token),
        },
    )?;

    let allowed_tools = build_mcp_allowed_tools(&policy);
    if allowed_tools.is_empty() {
        let _ = proxy_child.kill().await;
        return Err(anyhow!(
            "no allowed MCP tools for this profile (policy is too restrictive)"
        ));
    }

    if args.print_config {
        let config_contents = fs::read_to_string(&mcp_config_path)?;
        println!("MCP config: {}", mcp_config_path.display());
        println!("{config_contents}");
        println!();
        println!("Allowed tools: {}", allowed_tools.join(","));
        println!();
        println!("Launch claude with:");
        println!(
            "  claude --mcp-config {} --allowedTools {} --disallowedTools Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,NotebookEdit,Agent",
            mcp_config_path.display(),
            allowed_tools.join(",")
        );
        println!();
        println!("Tool-proxy: {proxy_url}");
        println!("Audit log: {}", audit_path.display());
        if let Some(ref trace_path) = args.kernel_trace {
            println!("Kernel trace: {}", trace_path.display());
        }
        // Keep proxy alive - user will launch claude manually
        println!("\nProxy running. Press Ctrl+C to stop.");
        tokio::signal::ctrl_c().await?;
        let _ = proxy_child.kill().await;
        return Ok(());
    }

    // Print session info
    eprintln!(
        "nucleus shell | profile={} budget=${:.2} timeout={}s",
        args.profile, policy.budget.max_cost_usd, args.timeout
    );
    eprintln!(
        "  tools: {}",
        allowed_tools
            .iter()
            .map(|t| t.strip_prefix("mcp__nucleus__").unwrap_or(t))
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("  audit: {}", audit_path.display());
    if let Some(ref trace_path) = args.kernel_trace {
        eprintln!("  trace: {}", trace_path.display());
    }
    eprintln!();

    // Launch claude in interactive mode.
    //
    // --allowedTools: only nucleus MCP tools are auto-approved
    // --disallowedTools: explicitly block built-in tools so Claude doesn't
    //   attempt to use them (they'd fail anyway, but this prevents wasted tokens
    //   on tool definitions and failed invocations).
    //
    // CLAUDECODE env var must be removed to allow launching claude from within
    // an existing Claude Code session (e.g. testing nucleus shell from claude).
    let mut cmd = Command::new("claude");
    cmd.arg("--mcp-config")
        .arg(&mcp_config_path)
        .arg("--allowedTools")
        .arg(allowed_tools.join(","))
        .arg("--disallowedTools")
        .arg("Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,NotebookEdit,Agent")
        .env_remove("CLAUDECODE")
        .current_dir(&work_dir);

    // Pass through any additional claude args
    for arg in &args.claude_args {
        cmd.arg(arg);
    }

    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("failed to spawn claude")?;

    // Kill tool-proxy
    let _ = proxy_child.kill().await;

    // Print audit summary
    print_audit_summary(&audit_path);

    // Cleanup tmp dir
    let _ = fs::remove_dir_all(&tmp_dir);

    if status.success() {
        Ok(())
    } else {
        bail!("claude exited with code {:?}", status.code())
    }
}

fn build_shell_pod_spec(
    args: &ShellArgs,
    policy: &PermissionLattice,
    work_dir: &Path,
) -> Result<SpecPodSpec> {
    let mut env = BTreeMap::new();
    for env_str in &args.envs {
        if let Some((key, value)) = env_str.split_once('=') {
            env.insert(key.to_string(), value.to_string());
        } else {
            return Err(anyhow!(
                "invalid --env format (expected KEY=VALUE): {}",
                env_str
            ));
        }
    }

    let credentials = if env.is_empty() {
        None
    } else {
        Some(CredentialsSpec { env })
    };

    Ok(SpecPodSpec::new(PodSpecInner {
        work_dir: work_dir.to_path_buf(),
        timeout_seconds: args.timeout,
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
        audit_sink: None,
        credentials,
    }))
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

/// Load permission config from a TOML file
fn load_permission_config(path: &str) -> Result<PermissionLattice> {
    let expanded = shellexpand::tilde(path).to_string();
    let content = fs::read_to_string(&expanded)?;
    let config: toml::Value = toml::from_str(&content)?;

    if let Some(profile) = config.get("profile").and_then(|v| v.as_str()) {
        if let Some(lattice) = profiles::resolve(profile) {
            return Ok(lattice);
        }
    }

    Ok(PermissionLattice::restrictive())
}

/// Poll the announce_path file until the proxy writes its bound address.
async fn wait_for_proxy_ready(announce_path: &Path, timeout: Duration) -> Result<String> {
    let start = std::time::Instant::now();
    loop {
        if announce_path.exists() {
            let addr = fs::read_to_string(announce_path)?.trim().to_string();
            if !addr.is_empty() {
                return Ok(addr);
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "tool-proxy did not become ready within {:?}",
                timeout
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Print a summary of the audit log after the session ends.
fn print_audit_summary(audit_path: &Path) {
    if !audit_path.exists() {
        return;
    }

    let contents = match fs::read_to_string(audit_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let line_count = contents.lines().count();
    if line_count == 0 {
        return;
    }

    // Count operations by type
    let mut op_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut denied = 0usize;
    for line in contents.lines() {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(op) = entry.get("operation").and_then(|v| v.as_str()) {
                *op_counts.entry(op.to_string()).or_default() += 1;
            }
            if entry
                .get("denied")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                denied += 1;
            }
        }
    }

    eprintln!();
    eprintln!("--- nucleus audit summary ---");
    eprintln!("  total entries: {line_count}");
    if denied > 0 {
        eprintln!("  denied: {denied}");
    }
    for (op, count) in &op_counts {
        eprintln!("  {op}: {count}");
    }
    eprintln!("  log: {}", audit_path.display());
}
