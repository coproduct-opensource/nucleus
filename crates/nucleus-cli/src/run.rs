//! Run command - Execute tasks via tool-proxy (enforced by default)

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use lattice_guard::{BudgetLattice, CapabilityLevel, PermissionLattice};
use nucleus_client::sign_http_headers;
use nucleus_spec::{ImageSpec, PodSpec as SpecPodSpec, PodSpecInner, PolicySpec, VsockSpec};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fs::{self};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use crate::keychain::{SecretKind, SecretStore};
use crate::profiles::Profile;

/// Resolved configuration from args, config file, and Keychain
struct ResolvedConfig {
    node_url: String,
    node_auth_secret: String,
    node_actor: String,
    kernel_path: String,
    rootfs_path: String,
}

/// Resolve configuration from multiple sources (args > keychain > config > defaults)
fn resolve_config(args: &RunArgs, config: &Config) -> Result<ResolvedConfig> {
    // Node URL: args > config > error
    let node_url = if !args.node_url.is_empty() {
        args.node_url.clone()
    } else if !config.node.url.is_empty() {
        config.node.url.clone()
    } else {
        return Err(anyhow!("missing --node-url (NUCLEUS_NODE_URL)"));
    };

    // Node auth secret: args > keychain > error
    let node_auth_secret = if !args.node_auth_secret.is_empty() {
        args.node_auth_secret.clone()
    } else if config.auth.use_keychain {
        // Try to get from Keychain
        match SecretStore::get(SecretKind::NodeAuthSecret)? {
            Some(secret) => {
                // Convert bytes to hex string for HMAC signing
                hex::encode(secret)
            }
            None => {
                return Err(anyhow!(
                    "Node auth secret not found in Keychain.\n\
                     Run 'nucleus setup' to generate secrets, or set NUCLEUS_NODE_AUTH_SECRET."
                ));
            }
        }
    } else {
        return Err(anyhow!(
            "missing --node-auth-secret (NUCLEUS_NODE_AUTH_SECRET)"
        ));
    };

    // Node actor: args > config
    let node_actor = if args.node_actor != "nucleus-cli" {
        args.node_actor.clone()
    } else {
        config.node.actor.clone()
    };

    // Kernel path: args > config
    let kernel_path = if let Some(ref path) = args.kernel_path {
        path.clone()
    } else {
        config.kernel_path()?.display().to_string()
    };

    // Rootfs path: args > config
    let rootfs_path = if let Some(ref path) = args.rootfs_path {
        path.clone()
    } else {
        config.rootfs_path()?.display().to_string()
    };

    Ok(ResolvedConfig {
        node_url,
        node_auth_secret,
        node_actor,
        kernel_path,
        rootfs_path,
    })
}

/// Run a task with tool-level enforcement via nucleus-node (Firecracker only).
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

    /// Path to nucleus-mcp binary (enforced mode)
    #[arg(long, env = "NUCLEUS_MCP_PATH", default_value = "nucleus-mcp")]
    pub mcp_path: String,

    /// nucleus-node base URL (Firecracker required).
    #[arg(long, env = "NUCLEUS_NODE_URL")]
    pub node_url: String,

    /// Auth secret for nucleus-node API (HMAC).
    #[arg(long, env = "NUCLEUS_NODE_AUTH_SECRET")]
    pub node_auth_secret: String,

    /// Actor name for signed node requests.
    #[arg(long, env = "NUCLEUS_NODE_ACTOR", default_value = "nucleus-cli")]
    pub node_actor: String,

    /// Firecracker kernel image path.
    #[arg(long, env = "NUCLEUS_FIRECRACKER_KERNEL_PATH")]
    pub kernel_path: Option<String>,

    /// Firecracker rootfs image path.
    #[arg(long, env = "NUCLEUS_FIRECRACKER_ROOTFS_PATH")]
    pub rootfs_path: Option<String>,

    /// Firecracker vsock CID.
    #[arg(long, env = "NUCLEUS_FIRECRACKER_VSOCK_CID", default_value_t = 3)]
    pub vsock_cid: u32,

    /// Firecracker vsock port.
    #[arg(long, env = "NUCLEUS_FIRECRACKER_VSOCK_PORT", default_value_t = 5000)]
    pub vsock_port: u32,

    /// Mount rootfs read-only (recommended).
    #[arg(long, env = "NUCLEUS_FIRECRACKER_READ_ONLY", default_value_t = true)]
    pub rootfs_read_only: bool,
}

/// Execute the run command
pub async fn execute(args: RunArgs, global_config_path: &str) -> Result<()> {
    // Load global config
    let global_config = Config::load(global_config_path)?;

    // Resolve secrets and paths from config/keychain/env
    let resolved = resolve_config(&args, &global_config)?;

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
        println!("  Node URL: {}", resolved.node_url);
        println!("  Kernel: {}", resolved.kernel_path);
        println!("  Rootfs: {}", resolved.rootfs_path);
        println!("  Vsock: cid={} port={}", args.vsock_cid, args.vsock_port);
        println!("  Rootfs read-only: {}", args.rootfs_read_only);
        println!();
        println!("Capabilities:");
        println!("  read_files: {:?}", policy.capabilities.read_files);
        println!("  write_files: {:?}", policy.capabilities.write_files);
        println!("  run_bash: {:?}", policy.capabilities.run_bash);
        println!("  git_push: {:?}", policy.capabilities.git_push);
        println!("  web_fetch: {:?}", policy.capabilities.web_fetch);
        return Ok(());
    }

    run_enforced(&args, &resolved, &policy, &work_dir, &prompt).await
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

struct TmpDirGuard {
    path: PathBuf,
}

impl TmpDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TmpDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn run_enforced(
    args: &RunArgs,
    resolved: &ResolvedConfig,
    policy: &PermissionLattice,
    work_dir: &Path,
    prompt: &str,
) -> Result<()> {
    warn_unimplemented_caps(policy);

    let run_id = Uuid::new_v4();
    let tmp_dir = std::env::temp_dir().join(format!("nucleus-cli-{run_id}"));
    fs::create_dir_all(&tmp_dir)?;
    let _tmp_guard = TmpDirGuard::new(tmp_dir.clone());

    let spec_path = tmp_dir.join("pod.yaml");
    let mcp_config_path = tmp_dir.join("mcp.json");

    let pod_spec = build_pod_spec(
        args,
        policy,
        work_dir,
        &resolved.kernel_path,
        &resolved.rootfs_path,
    )?;
    write_pod_spec(&spec_path, &pod_spec)?;

    let mcp_command_path = resolve_binary_path(&args.mcp_path)?;

    let proxy_addr = create_pod_via_node(
        &resolved.node_url,
        &pod_spec,
        &resolved.node_auth_secret,
        &resolved.node_actor,
    )?;
    let proxy_url = if proxy_addr.starts_with("http://") || proxy_addr.starts_with("https://") {
        proxy_addr
    } else {
        format!("http://{proxy_addr}")
    };

    write_mcp_config(
        &mcp_config_path,
        &mcp_command_path,
        &proxy_url,
        None,
        &spec_path,
    )?;

    let allowed_tools = build_mcp_allowed_tools(policy);
    if allowed_tools.is_empty() {
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
        Err(err) => return Err(err),
    };
    let duration = start.elapsed();
    render_output(&output, duration, args.output.as_str())
}

fn build_pod_spec(
    args: &RunArgs,
    policy: &PermissionLattice,
    work_dir: &Path,
    kernel_path: &str,
    rootfs_path: &str,
) -> Result<SpecPodSpec> {
    Ok(SpecPodSpec::new(PodSpecInner {
        work_dir: work_dir.to_path_buf(),
        timeout_seconds: args.timeout,
        policy: PolicySpec::Inline {
            lattice: Box::new(policy.clone()),
        },
        budget_model: None,
        resources: None,
        network: None,
        image: Some(ImageSpec {
            kernel_path: PathBuf::from(kernel_path),
            rootfs_path: PathBuf::from(rootfs_path),
            boot_args: None,
            read_only: args.rootfs_read_only,
            scratch_path: None,
        }),
        vsock: Some(VsockSpec {
            guest_cid: args.vsock_cid,
            port: args.vsock_port,
        }),
        seccomp: None,
        cgroup: None,
        credentials: None,
    }))
}

fn write_pod_spec(spec_path: &Path, spec: &SpecPodSpec) -> Result<()> {
    let yaml = serde_yaml::to_string(spec)?;
    fs::write(spec_path, yaml)?;
    Ok(())
}

#[derive(Deserialize)]
struct CreatePodResponse {
    #[serde(rename = "id")]
    _id: Uuid,
    proxy_addr: Option<String>,
}

#[derive(Deserialize)]
struct NodeErrorBody {
    error: String,
}

fn create_pod_via_node(
    node_url: &str,
    spec: &SpecPodSpec,
    auth_secret: &str,
    actor: &str,
) -> Result<String> {
    let url = format!("{}/v1/pods", node_url.trim_end_matches('/'));
    let body = serde_yaml::to_string(spec)?;
    let mut request = ureq::post(&url).header("content-type", "application/yaml");

    let signed = sign_http_headers(auth_secret.as_bytes(), Some(actor), body.as_bytes());
    for (key, value) in signed.headers {
        request = request.header(&key, &value);
    }

    match request.send(body.as_bytes()) {
        Ok(mut response) => {
            if response.status().as_u16() >= 400 {
                let status = response.status();
                if let Ok(body) = response.body_mut().read_json::<NodeErrorBody>() {
                    Err(anyhow!("node error: {}", body.error))
                } else {
                    Err(anyhow!("node error: status {}", status))
                }
            } else {
                let parsed: CreatePodResponse = response
                    .body_mut()
                    .read_json()
                    .map_err(|e| anyhow!("failed to decode node response: {e}"))?;
                parsed
                    .proxy_addr
                    .ok_or_else(|| anyhow!("node did not return proxy address"))
            }
        }
        Err(err) => Err(anyhow!("node request failed: {err}")),
    }
}

fn write_mcp_config(
    mcp_path: &Path,
    mcp_command: &Path,
    proxy_url: &str,
    auth_secret: Option<&str>,
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
    if let Some(secret) = auth_secret {
        env.insert("NUCLEUS_MCP_AUTH_SECRET".to_string(), secret.to_string());
    }
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
    if policy.capabilities.web_fetch >= CapabilityLevel::LowRisk {
        tools.push("mcp__nucleus__web_fetch".to_string());
    }
    tools
}

fn warn_unimplemented_caps(policy: &PermissionLattice) {
    // Capabilities that exist in the policy model but have no MCP tool implementation
    // Note: web_fetch IS implemented - don't warn about it
    let mut missing = Vec::new();
    if policy.capabilities.web_search >= CapabilityLevel::LowRisk {
        missing.push("web_search");
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

fn render_output(output: &std::process::Output, duration: Duration, mode: &str) -> Result<()> {
    if mode == "json" {
        let result = serde_json::json!({
            "success": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
            "duration_ms": duration.as_millis(),
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
    }

    if output.status.success() {
        Ok(())
    } else {
        bail!("Execution failed with exit code {:?}", output.status.code())
    }
}
