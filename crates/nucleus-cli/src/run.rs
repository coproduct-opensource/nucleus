//! Run command - Execute tasks via tool-proxy (enforced by default)

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use nucleus_client::sign_http_headers;
use nucleus_spec::{
    CredentialsSpec, ImageSpec, PodSpec as SpecPodSpec, PodSpecInner, PolicySpec, RootfsSource,
    VsockSpec,
};
use portcullis::{CapabilityLevel, PermissionLattice};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use crate::keychain::{SecretKind, SecretStore};
use crate::profiles;

mod agent_process;
mod apple_host;
mod pod_agent;
mod pod_egress;
mod pod_session;

/// Resolved configuration from args, config file, and Keychain
pub(crate) struct ResolvedConfig {
    node_url: String,
    /// mTLS, when the identity `nucleus setup` provisions (Move A step 6) is
    /// present — the preferred path, and the only one that still works
    /// against a real node: Move B deleted the node's HMAC tier entirely.
    /// `None` when that identity hasn't been provisioned, in which case
    /// `node_auth_secret` is required instead (and will fail against any
    /// node updated past Move B — kept for a transition window / a node the
    /// operator has not yet migrated, matching `node.rs`'s own dual mode).
    node_mtls_client: Option<reqwest::Client>,
    node_auth_secret: Option<String>,
    node_actor: String,
    kernel_path: String,
    rootfs_path: String,
}

/// Resolve configuration from multiple sources (args > keychain > config > defaults).
///
/// Returns `None` for local mode or deferred Apple host readiness.
pub(crate) fn resolve_config(args: &RunArgs, config: &Config) -> Result<Option<ResolvedConfig>> {
    if args.local {
        return Ok(None);
    }
    if let Some(path) = &args.apple_host_config {
        apple_host::configuration(path)?;
        return Ok(None);
    }

    // Node URL: args > config > error
    let node_url = if let Some(ref url) = args.node_url {
        if !url.is_empty() {
            url.clone()
        } else {
            config.node.url.clone()
        }
    } else if !config.node.url.is_empty() {
        config.node.url.clone()
    } else {
        return Err(anyhow!(
            "missing --node-url (NUCLEUS_NODE_URL). Use --local for CI mode."
        ));
    };

    // mTLS first: the identity `nucleus setup` provisions (Move A step 6),
    // used automatically when present — see `node.rs`'s
    // `apply_provisioned_identity_defaults` for the same pattern.
    let node_mtls_client = match &args.identity_dir {
        Some(dir) => Some(crate::provision::mtls_client_from_identity_dir(dir)?),
        None => crate::provision::mtls_client_if_provisioned()?,
    };

    // Node auth secret: args > keychain > (required only if mTLS isn't
    // available). A node updated past Move B has no HMAC tier to check this
    // against at all — it exists for a not-yet-migrated node / a transition
    // window, not as the normal path.
    let node_auth_secret = if node_mtls_client.is_some() {
        None
    } else if let Some(ref secret) = args.node_auth_secret {
        if !secret.is_empty() {
            Some(secret.clone())
        } else {
            return Err(anyhow!("--node-auth-secret is empty"));
        }
    } else if config.auth.use_keychain {
        SecretStore::get(SecretKind::NodeAuthSecret)?.map(hex::encode)
    } else {
        None
    };
    if node_mtls_client.is_none() && node_auth_secret.is_none() {
        return Err(anyhow!(
            "no way to authenticate to nucleus-node: no mTLS identity provisioned \
             (run: nucleus setup) and no --node-auth-secret (NUCLEUS_NODE_AUTH_SECRET) \
             either. Use --local for CI mode."
        ));
    }

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

    Ok(Some(ResolvedConfig {
        node_url,
        node_mtls_client,
        node_auth_secret,
        node_actor,
        kernel_path,
        rootfs_path,
    }))
}

/// Run a task with tool-level enforcement.
///
/// By default, requires a running nucleus-node with Firecracker. Use `--local`
/// to run the tool-proxy as a local subprocess instead (suitable for CI).
#[derive(Args, Debug)]
#[command(mut_args = |a| a.hide_env_values(true))]
pub struct RunArgs {
    /// Task prompt (use - for stdin). Not needed with --goal or --grant.
    #[arg(required_unless_present_any = ["goal", "grant"])]
    pub prompt: Option<String>,

    /// State the outcome you want instead of a profile: nucleus compiles the
    /// goal into the minimum authority it needs (met with --ceiling), shows
    /// what the agent can and cannot do, and runs after one confirmation.
    #[arg(long, conflicts_with_all = ["config"])]
    pub goal: Option<String>,

    /// The profile a --goal grant may never exceed. The one knob that widens.
    #[arg(long, default_value = "codegen")]
    pub ceiling: String,

    /// Effects to grant in addition to what the goal implies (comma-separated
    /// ids such as github/read-ci-logs). See `nucleus profiles`.
    #[arg(long, value_delimiter = ',')]
    pub effects: Vec<String>,

    /// Accept the compiled grant without prompting (required without a TTY).
    #[arg(long)]
    pub yes: bool,

    /// How much of the grant to show: plain | technical | policy-trace.
    #[arg(long, default_value = "plain")]
    pub explain: String,

    /// An external effect proposer: a program that reads {goal, context,
    /// catalog} as JSON on stdin and writes {effects: [...]} on stdout. Its
    /// output is validated against the catalog and clamped under --ceiling.
    #[arg(long, value_name = "PROGRAM")]
    pub proposer: Option<PathBuf>,

    /// Seal the accepted grant to PATH, signed with this host's grant key,
    /// so the same task can run again with --grant and no confirmation.
    #[arg(long, value_name = "PATH")]
    pub save_grant: Option<PathBuf>,

    /// Run a previously sealed grant (see --save-grant, `nucleus grant seal`).
    /// Verified against this host's trusted signers and this repository; no
    /// confirmation is asked because one was already given.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["goal", "config"])]
    pub grant: Option<PathBuf>,

    /// Ed25519 key (PKCS#8 PEM) that seals grants and whose public half is
    /// trusted when verifying one. Created on first use.
    #[arg(long, env = "NUCLEUS_GRANT_KEY", value_name = "PATH")]
    pub grant_key: Option<PathBuf>,

    /// Additional trusted grant signers (hex Ed25519 public keys). Repeatable.
    #[arg(long = "grant-signer", value_name = "HEX")]
    pub grant_signers: Vec<String>,

    /// The task grant this run executes under (set by --goal / --grant, not a
    /// flag): carried in the pod spec so the exit report names it.
    #[arg(skip)]
    pub task_grant_id: Option<String>,

    /// The sealed grant's certificate (base64 attenuation token) and the key
    /// that signed it, handed to the tool-proxy in local mode so the run is
    /// enforced per effect (set by --goal / --grant, not flags).
    #[arg(skip)]
    pub pod_cert_b64: Option<String>,
    #[arg(skip)]
    pub cert_root_pubkey_hex: Option<String>,

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

    /// The agent CLI to launch (required; no default). Its leading arguments
    /// go after `--`. Falls back to `[agent] command` in the config file.
    #[arg(long, env = "NUCLEUS_AGENT", value_name = "PROGRAM")]
    pub agent: Option<String>,

    /// Arguments for the agent program, placed before nucleus's own flags.
    #[arg(last = true, value_name = "AGENT_ARGS")]
    pub agent_args: Vec<String>,

    /// Model identifier to pass to the agent CLI.
    // Intrinsic interop: the flag name and any value are passed verbatim to the
    // external agent binary's `--model` flag. Nucleus supplies NO default: which
    // model to run is the orchestrator's decision, not the runtime's (CLAUDE.md),
    // and a pinned vendor model id also rots the moment that model is retired.
    // Unset means the agent binary applies its own default.
    #[arg(long)]
    pub model: Option<String>,

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    pub output: String,

    /// Dry run: show what would be executed without running
    #[arg(long)]
    pub dry_run: bool,

    /// Run locally without Firecracker (spawns tool-proxy as subprocess).
    /// Suitable for CI environments like GitHub Actions.
    #[arg(long)]
    pub local: bool,

    /// Run with agent-hook enforcement (lightest weight).
    /// Uses the sibling hook binary as a PreToolUse hook — no tool-proxy or MCP
    /// server needed. Provides IFC flow labels, exposure tracking, and
    /// capability gating with zero infrastructure.
    #[arg(long)]
    pub hook: bool,

    /// Accept that the agent runs on THIS host, as your user, outside any
    /// microVM. Required by --local and --hook; a microVM pod always runs its
    /// agent inside the guest and refuses it. Prints a banner and records the
    /// launch in ~/.config/nucleus/audit/host-agent-launches.jsonl.
    #[arg(long, conflicts_with_all = ["apple_host_config", "guest_work_dir"])]
    pub unsandboxed: bool,

    /// Environment variables to pass as credentials (KEY=VALUE).
    /// Can be specified multiple times: --env FOO=bar --env BAZ=qux
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub envs: Vec<String>,

    /// Path to nucleus-mcp binary (local mode; a pod uses the guest's own)
    #[arg(long, env = "NUCLEUS_MCP_PATH", default_value = "nucleus-mcp")]
    pub mcp_path: String,

    /// Path to nucleus-tool-proxy binary (local mode only)
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_PATH",
        default_value = "nucleus-tool-proxy"
    )]
    pub tool_proxy_path: String,

    /// nucleus-node base URL (required for Firecracker mode).
    #[arg(long, env = "NUCLEUS_NODE_URL")]
    pub node_url: Option<String>,

    /// Node mTLS identity directory (cli-cert.pem, cli-key.pem, trust-bundle.pem)
    #[arg(long, env = "NUCLEUS_IDENTITY_DIR", conflicts_with = "local")]
    pub identity_dir: Option<PathBuf>,

    /// Apple host JSON configuration; start/check host and relay the pod proxy
    #[arg(long, conflicts_with_all = ["local", "hook", "node_url", "identity_dir", "node_auth_secret"])]
    pub apple_host_config: Option<PathBuf>,

    /// Existing workspace directory inside the guest (does not upload host files)
    #[arg(long, conflicts_with_all = ["local", "hook"], value_parser = absolute_guest_dir)]
    pub guest_work_dir: Option<PathBuf>,

    /// Auth secret for nucleus-node API (HMAC).
    #[arg(long, env = "NUCLEUS_NODE_AUTH_SECRET")]
    pub node_auth_secret: Option<String>,

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

    /// Mount rootfs read-only. The node refuses `false` at create (#3132): the
    /// rootfs is its shared artifact, and writable storage is `/work`.
    #[arg(long, env = "NUCLEUS_FIRECRACKER_READ_ONLY", default_value_t = true)]
    pub rootfs_read_only: bool,

    /// Path to write kernel decision trace in JSONL format.
    /// Each tool call decision (allow/deny/requires_approval) is recorded.
    /// Feed the output into `nucleus observe` to synthesize a minimal policy.
    #[arg(long, env = "NUCLEUS_KERNEL_TRACE")]
    pub kernel_trace: Option<PathBuf>,

    /// A credentialed upstream (an `[[upstream]]` name in the node's registry)
    /// the host performs calls to for the agent in the pod. Repeatable. None
    /// by default: without this flag nothing reaches any upstream.
    #[arg(long = "egress", value_name = "UPSTREAM", requires = "upstreams",
          conflicts_with_all = ["local", "hook"])]
    pub egress: Vec<String>,

    /// The node's upstream registry (its `--upstreams` file), read for the
    /// entries `--egress` names. Never sent; only their projections are.
    #[arg(long, env = "NUCLEUS_UPSTREAMS", value_name = "PATH")]
    pub upstreams: Option<PathBuf>,

    /// Give the agent an upstream's loopback URL under its own variable:
    /// `VAR=UPSTREAM`. Repeatable.
    #[arg(
        long = "egress-export",
        value_name = "VAR=UPSTREAM",
        requires = "egress"
    )]
    pub egress_exports: Vec<String>,

    /// Set `VAR` to a fixed non-secret placeholder in the agent's environment,
    /// for an agent that will not start without a credential variable. The
    /// host injects the real credential. Repeatable.
    #[arg(long = "egress-placeholder", value_name = "VAR", requires = "egress")]
    pub egress_placeholders: Vec<String>,
}

/// Execute the run command
pub async fn execute(mut args: RunArgs, global_config_path: &str) -> Result<()> {
    let global_config = Config::load(global_config_path)?;
    apple_host::apply_default(&mut args, &global_config);
    crate::agent::fold_config_default(&mut args.agent, &mut args.agent_args, &global_config.agent);
    // Refuse before anything is compiled, confirmed or booted: every mode
    // launches the agent, and nucleus has no default one. A dry run launches
    // nothing, so it shows the agent (or its absence) instead.
    if !args.dry_run {
        named_agent(&args)?;
    }
    if args.goal.is_some() {
        return crate::goal::execute(args, global_config_path).await;
    }
    if args.grant.is_some() {
        return crate::goal::execute_grant(args, global_config_path).await;
    }

    // Resolve secrets and paths from config/keychain/env
    let resolved = resolve_config(&args, &global_config)?;

    // Read prompt from stdin if "-"
    let prompt = match args.prompt.as_deref() {
        Some("-") => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            buffer.trim().to_string()
        }
        Some(p) => p.to_string(),
        None => String::new(),
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
        // Use profile (canonical YAML → aliases → legacy → restrictive fallback)
        profiles::resolve(&args.profile).unwrap_or_else(|| {
            eprintln!(
                "Warning: Unknown profile '{}', using restrictive",
                args.profile
            );
            PermissionLattice::restrictive()
        })
    };

    // Override budget if specified
    let mut policy = policy;
    if let Some(max_cost) = args.max_cost {
        policy.budget.max_cost_usd = Decimal::try_from(max_cost).unwrap_or(Decimal::from(5));
    }
    let policy = policy.normalize();

    if args.dry_run {
        println!("Dry run - would execute with:");
        println!("  Working directory: {}", work_dir.display());
        println!("  Profile: {}", args.profile);
        println!(
            "  Mode: {}",
            if args.hook {
                "hook (agent on this host; needs --unsandboxed)"
            } else if args.local {
                "local (agent on this host; needs --unsandboxed)"
            } else {
                "microVM pod (agent inside the guest)"
            }
        );
        println!("  Budget: ${:.2}", policy.budget.max_cost_usd);
        println!("  Timeout: {}s", args.timeout);
        match named_agent(&args) {
            Ok(agent) => println!("  Agent: {}", agent.display()),
            Err(_) => println!("  Agent: (none named; --agent is required to run)"),
        }
        println!(
            "   UninhabitableState constraint: {}",
            policy.is_uninhabitable_enforced()
        );
        if let Some(ref resolved) = resolved {
            println!("  Node URL: {}", resolved.node_url);
            println!("  Kernel: {}", resolved.kernel_path);
            println!("  Rootfs: {}", resolved.rootfs_path);
            println!("  Vsock: cid={} port={}", args.vsock_cid, args.vsock_port);
            println!("  Rootfs read-only: {}", args.rootfs_read_only);
        }
        if let Some(path) = &args.apple_host_config {
            println!(
                "  Apple host configuration: {} (not started)",
                path.display()
            );
        }
        println!();
        print!(
            "{}",
            portcullis::render_capabilities(&policy, "Capabilities:")
        );
        return Ok(());
    }

    dispatch(&args, resolved, &policy, &work_dir, &prompt).await
}

/// The agent this run launches: `--agent` / `NUCLEUS_AGENT`, or the config
/// file's `[agent] command` once [`execute`] has folded it in. The one place a
/// run decides which agent it has, so the early refusal and the launch agree.
fn named_agent(args: &RunArgs) -> Result<crate::agent::AgentCommand> {
    crate::agent::AgentCommand::named(args.agent.as_deref(), &args.agent_args)
}

/// Run `prompt` under `policy` in whichever mode the args select. Shared by
/// the profile path and the `--goal` path, which differ only in where the
/// policy came from.
pub(crate) async fn dispatch(
    args: &RunArgs,
    resolved: Option<ResolvedConfig>,
    policy: &PermissionLattice,
    work_dir: &Path,
    prompt: &str,
) -> Result<()> {
    let agent = named_agent(args)?;
    if args.hook || args.local {
        // The agent on this host: only on the operator's own `--unsandboxed`,
        // with a banner and an audit record (owner decision D9).
        let command = if args.hook {
            "run --hook"
        } else {
            "run --local"
        };
        let declared =
            crate::host_tier::HostAgentOptIn::declare(args.unsandboxed, command, &agent, work_dir)?;
        return if args.hook {
            run_hook(args, &agent, declared, policy, work_dir, prompt).await
        } else {
            run_local(args, &agent, declared, policy, work_dir, prompt).await
        };
    }

    refuse_host_only_flags(args)?;
    // Before a host or a pod is started: a declared upstream this policy can
    // never call is a contradiction the operator should hear now, not from the
    // agent's first model call inside the pod (#3218).
    pod_egress::refuse_unreachable(&args.egress, policy, &policy_source(args))?;
    if let Some(path) = &args.apple_host_config {
        let (resolved, host) = apple_host::ready(path, args).await?;
        run_in_pod(
            args,
            &agent,
            &resolved,
            policy,
            work_dir,
            prompt,
            Some(host),
        )
        .await
    } else {
        let resolved = resolved.ok_or_else(|| {
            anyhow!("node config required for Firecracker mode. Use --local for CI.")
        })?;
        run_in_pod(args, &agent, &resolved, policy, work_dir, prompt, None).await
    }
}

/// Where the run's policy came from, as a refusal names it.
fn policy_source(args: &RunArgs) -> String {
    if let Some(grant) = &args.grant {
        format!("the sealed grant {}", grant.display())
    } else if args.goal.is_some() {
        format!("the --goal grant (under --ceiling {})", args.ceiling)
    } else if let Some(config) = &args.config {
        format!("the policy in {config}")
    } else {
        format!("profile '{}'", args.profile)
    }
}

/// Flags that only mean something when the agent runs on this host, refused by
/// name for a pod run rather than dropped (ADR 0007 A-1: a flag that silently
/// does nothing reads as one that worked).
fn refuse_host_only_flags(args: &RunArgs) -> Result<()> {
    if args.unsandboxed {
        bail!(
            "--unsandboxed launches the agent on this host and applies only to --local or \
             --hook; a microVM pod always runs its agent inside the guest"
        );
    }
    if !args.envs.is_empty() {
        bail!(
            "--env is not delivered into a pod: the agent in the pod receives nothing from this \
             host's environment. A model upstream is a declared credentialed egress that the \
             host performs for the pod (#3031); --env applies to --local --unsandboxed."
        );
    }
    if args.kernel_trace.is_some() {
        bail!(
            "--kernel-trace records the MCP bridge's decisions on this host, but in a pod the \
             bridge runs inside the guest; use --local --unsandboxed to trace on this host"
        );
    }
    Ok(())
}

/// Load permission config from a TOML file
fn load_permission_config(path: &str) -> Result<PermissionLattice> {
    let expanded = shellexpand::tilde(path).to_string();
    let content = std::fs::read_to_string(&expanded)?;

    // For now, just use a preset based on the file
    // In a full implementation, we'd parse a custom format
    let config: toml::Value = toml::from_str(&content)?;

    // Check for profile key
    if let Some(profile) = config.get("profile").and_then(|v| v.as_str())
        && let Some(lattice) = profiles::resolve(profile)
    {
        return Ok(lattice);
    }

    // Default to restrictive
    Ok(PermissionLattice::restrictive())
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
        && let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(path);
        if sibling.exists() {
            return Ok(sibling);
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

/// Run with agent-hook enforcement (lightest weight).
///
/// Writes a temporary settings.json that registers the sibling hook binary as
/// the PreToolUse hook, then runs the agent CLI with that config. No tool-proxy
/// or MCP server needed — the hook intercepts every tool call and runs it
/// through the portcullis kernel with IFC flow labels.
async fn run_hook(
    args: &RunArgs,
    agent: &crate::agent::AgentCommand,
    declared: crate::host_tier::HostAgentOptIn,
    policy: &PermissionLattice,
    work_dir: &Path,
    prompt: &str,
) -> Result<()> {
    let run_id = Uuid::new_v4();
    let tmp_dir = std::env::temp_dir().join(format!("nucleus-hook-{run_id}"));
    fs::create_dir_all(&tmp_dir)?;
    let _tmp_guard = TmpDirGuard::new(tmp_dir.clone());

    // Resolve hook binary
    let hook_bin = resolve_binary_path(crate::constants::HOOK_BINARY_NAME)?;
    if !hook_bin.exists() {
        bail!(
            "{name} not found at {hook_bin:?}. Install with: cargo install --path crates/{name}",
            name = crate::constants::HOOK_BINARY_NAME,
        );
    }

    // Write temporary settings.json with the hook configured.
    //
    // The document comes from `mediation::hook_settings_for_exe` rather than
    // being built here, because the registration shape is FAIL-OPEN: this site
    // previously emitted the matcher-group entry `{"type","command"}` without
    // the nested `hooks` array, which registers no hook at all — silently, with
    // every tool call proceeding unhooked. In this mode the hook is the only
    // boundary there is, so that made the enforcement vacuous.
    let profile_name = &args.profile;
    let settings_path = crate::mediation::HookSettings::for_exe(&hook_bin, &[])
        .write_to(&tmp_dir, "settings.json")?;

    info!(
        hook_bin = %hook_bin.display(),
        profile = %profile_name,
        "Running agent CLI under nucleus hook enforcement"
    );

    let start = Instant::now();

    // Confined by construction: `launch` applies the confinement flags.
    let mut cmd = agent.launch(declared);
    cmd.arg("--print");
    if let Some(model) = &args.model {
        cmd.arg("--model").arg(model);
    }
    cmd.arg("--max-budget-usd")
        .arg(policy.budget.max_cost_usd.to_string())
        .arg("--settings")
        .arg(settings_path.as_path())
        .arg(prompt)
        .current_dir(work_dir)
        .env("NUCLEUS_PROFILE", profile_name);

    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn agent `{}`", agent.program()))?;
    let duration = start.elapsed();

    render_output(&output, duration, args.output.as_str())
}

/// Run in local mode: spawn tool-proxy as a subprocess (no Firecracker).
///
/// This gives lattice enforcement via tool-proxy intercept without needing a
/// Firecracker VM. Suitable for CI environments like GitHub Actions.
async fn run_local(
    args: &RunArgs,
    agent: &crate::agent::AgentCommand,
    declared: crate::host_tier::HostAgentOptIn,
    policy: &PermissionLattice,
    work_dir: &Path,
    prompt: &str,
) -> Result<()> {
    warn_unimplemented_caps(policy);

    let run_id = Uuid::new_v4();
    let tmp_dir = std::env::temp_dir().join(format!("nucleus-local-{run_id}"));
    fs::create_dir_all(&tmp_dir)?;
    let _tmp_guard = TmpDirGuard::new(tmp_dir.clone());

    // The session task token, from the policy the proxy's spec will carry and,
    // when the proxy gets a pod certificate, bound to that certificate's
    // fingerprint -- the proxy refuses a token naming another authority.
    // Without it the proxy starts `Missing` and InScopeWithTask refuses every
    // action (see `crate::session_token`).
    let authority = match &args.pod_cert_b64 {
        Some(cert) => Some(
            portcullis::AttenuationToken::from_base64(cert.trim())
                .map_err(|e| anyhow!("--pod-cert is not a certificate: {e}"))?
                .fingerprint(),
        ),
        None => None,
    };
    let task_token =
        crate::session_token::mint_local(&run_id.to_string(), policy, args.timeout, authority)?;

    // Generate per-run auth secrets
    let auth_secret = hex::encode(rand::random::<[u8; 32]>());
    let approval_secret = hex::encode(rand::random::<[u8; 32]>());

    // Build minimal PodSpec (no image/vsock)
    let spec_path = tmp_dir.join("pod.yaml");
    let pod_spec = build_local_pod_spec(args, policy, work_dir)?;
    write_pod_spec(&spec_path, &pod_spec)?;

    // Generate sandbox token (Tier 3 OrchestratorToken)
    let spec_contents = fs::read_to_string(&spec_path)?;
    let spec_hash = hex::encode(Sha256::digest(spec_contents.as_bytes()));
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
        "Spawning local tool-proxy"
    );

    // The bare host tier, declared: this command passes the tool-proxy's
    // explicit opt-in and says so (owner decision 1, 2026-10-02).
    crate::host_tier::announce("run --local");

    // Spawn tool-proxy as subprocess
    let mut proxy_child = tokio::process::Command::new(&proxy_bin)
        .arg(crate::host_tier::TOOL_PROXY_OPT_IN)
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
        .args(pod_cert_args(args))
        .args(crate::session_token::proxy_args(&task_token))
        .env("NUCLEUS_SANDBOX_TOKEN", &sandbox_token)
        .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("failed to spawn nucleus-tool-proxy")?;

    // Wait for proxy readiness
    let proxy_addr = wait_for_proxy_ready(&announce_path, Duration::from_secs(10)).await?;
    let proxy_url = format!("http://{proxy_addr}");

    info!(proxy_url = %proxy_url, "Tool-proxy ready");

    // Build MCP config and spawn the agent CLI
    let mcp_config_path = tmp_dir.join("mcp.json");
    let mcp_command_path = resolve_binary_path(&args.mcp_path)?;

    write_mcp_config(
        &mcp_config_path,
        &mcp_command_path,
        &McpEnvConfig {
            proxy_url: &proxy_url,
            auth: McpProxyAuth::Hmac {
                auth_secret: &auth_secret,
                approval_secret: &approval_secret,
            },
            spec_path: &spec_path,
            kernel_trace: args.kernel_trace.as_deref(),
            sandbox_token: Some(&sandbox_token),
        },
    )?;

    let allowed_tools = build_mcp_allowed_tools(policy);
    if allowed_tools.is_empty() {
        return Err(anyhow!(
            "no allowed MCP tools for this profile (policy is too restrictive)"
        ));
    }

    // Establish the complete-mediation confinement guard BEFORE launching the
    // agent with the approval bypass. The tool-proxy is up (checked above) and
    // every allowed tool routes through the lattice; if that can't be proven we
    // refuse to launch rather than leak an unconfined agent.
    let guard = MediationGuard::establish(&allowed_tools).ok_or_else(|| {
        anyhow!("cannot establish confinement guard: allowed tools are not fully lattice-mediated")
    })?;

    if let Some(ref trace_path) = args.kernel_trace {
        info!(trace_path = %trace_path.display(), "Kernel trace enabled");
    }

    info!(
        allowed_tools = %allowed_tools.join(","),
        model = args.model.as_deref().unwrap_or("<agent default>"),
        "Spawning agent CLI (local enforced mode)"
    );

    let start = Instant::now();
    let output = run_agent_mcp(
        args,
        agent,
        declared,
        policy,
        &mcp_config_path,
        &guard,
        prompt,
        work_dir,
    )
    .await;
    let duration = start.elapsed();

    // Kill tool-proxy
    let _ = proxy_child.kill().await;

    render_output(&output?, duration, args.output.as_str())
}

/// `--pod-cert` / `--cert-root-pubkey` for the tool-proxy when this run is
/// under a sealed grant: the certificate carries the grant's `effect/` keys,
/// which the proxy enforces per method + host + path (ADR 0004).
fn pod_cert_args(args: &RunArgs) -> Vec<String> {
    match (&args.pod_cert_b64, &args.cert_root_pubkey_hex) {
        (Some(cert), Some(key)) => vec![
            "--pod-cert".into(),
            cert.clone(),
            "--cert-root-pubkey".into(),
            key.clone(),
        ],
        _ => Vec::new(),
    }
}

/// Poll the announce_path file until the proxy writes its bound address.
async fn wait_for_proxy_ready(announce_path: &Path, timeout: Duration) -> Result<String> {
    let start = Instant::now();
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

/// Build a PodSpec for local mode (no image/vsock, credentials from --env).
fn build_local_pod_spec(
    args: &RunArgs,
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
        Some(CredentialsSpec {
            env,
            ..Default::default()
        })
    };

    let mut spec = SpecPodSpec::new(PodSpecInner {
        work_dir: work_dir.to_path_buf(),
        timeout_seconds: args.timeout,
        policy: PolicySpec::Inline {
            lattice: Box::new(policy.clone()),
        },
        budget_model: None,
        resources: None,
        network: None,
        image: None,
        credentialed_egress: Vec::new(),
        workload: None,
        vsock: None,
        seccomp: None,
        cgroup: None,
        audit_sink: None,
        credentials,
    });
    spec.metadata.task_grant_id = args.task_grant_id.clone();
    Ok(spec)
}

/// Run the agent INSIDE a microVM pod: the pod's workload is the named agent,
/// started by the guest's tool-proxy under its confinement, and this host only
/// waits for it to exit and prints what it wrote (owner decision D9; see
/// `pod_agent` for what crosses into the guest and what does not).
async fn run_in_pod(
    args: &RunArgs,
    agent: &crate::agent::AgentCommand,
    resolved: &ResolvedConfig,
    policy: &PermissionLattice,
    work_dir: &Path,
    prompt: &str,
    host: Option<crate::microvm_host::lifecycle::MicroVmHost>,
) -> Result<()> {
    warn_unimplemented_caps(policy);
    // The Apple host stays ready for the run's length; nothing on this host
    // talks to the pod's proxy any more, so it needs no relay.
    let _host = host;

    // Observing the workload is a node API, and the node serves it over mTLS
    // only (Move B removed its HMAC tier). Refused before a pod exists.
    let client = resolved.node_mtls_client.as_ref().ok_or_else(|| {
        anyhow!(
            "running the agent in a pod needs the node's mTLS identity (run: nucleus setup); \
             the node no longer accepts the HMAC secret"
        )
    })?;

    let allowed_tools = build_mcp_allowed_tools(policy);
    // The same guard a host launch needs: the agent is told to use only
    // lattice-routed tools, and the approval bypass is passed only then.
    let guard = MediationGuard::establish(&allowed_tools).ok_or_else(|| {
        anyhow!(
            "no lattice-mediated MCP tools for this policy (it is too restrictive to run an agent)"
        )
    })?;
    let workload = pod_agent::workload(agent, &guard, policy, args.model.as_deref(), prompt)?;
    let egress = pod_egress::declare(&pod_egress::EgressFlags {
        upstreams: &args.egress,
        registry: args.upstreams.as_deref(),
        exports: &args.egress_exports,
        placeholders: &args.egress_placeholders,
    })?;
    let (workload, credentialed_egress) = match egress {
        Some(egress) => egress.wrap(workload),
        None => (workload, Vec::new()),
    };
    let mut pod_spec = build_pod_spec(
        args,
        policy,
        &resolved.kernel_path,
        &resolved.rootfs_path,
        Some(workload),
    )?;
    pod_spec.spec.credentialed_egress = credentialed_egress;

    info!(
        agent = agent.program(),
        allowed_tools = %allowed_tools.join(","),
        guest_work_dir = %pod_spec.spec.work_dir.display(),
        host_dir_not_uploaded = %work_dir.display(),
        "Starting the agent inside a microVM pod"
    );
    let start = Instant::now();
    let pod = create_pod_via_node(
        &resolved.node_url,
        &pod_spec,
        Some(client),
        None,
        &resolved.node_actor,
    )
    .await
    .with_context(|| {
        format!(
            "creating the pod that runs the agent `{}` (it must be in the guest image)",
            agent.program()
        )
    })?;
    // The pod's own deadline plus a margin: the node reaps it at its timeout,
    // and the wait should report that rather than race it.
    let deadline = Duration::from_secs(args.timeout.saturating_add(60));
    let result = tokio::select! {
        exit = pod_agent::wait_for_exit(client, &resolved.node_url, pod.id, deadline) => exit,
        signal = tokio::signal::ctrl_c() => match signal {
            Ok(()) => Err(anyhow!("interrupted; stopping the pod")),
            Err(e) => Err(anyhow::Error::new(e).context("installing the interrupt handler")),
        },
    }
    .and_then(|exit| render_pod_exit(&exit, start.elapsed(), args.output.as_str()));
    let cleanup = pod_session::cancel(resolved, pod.id).await;
    pod_session::finish(result, cleanup, pod.id)
}

/// Print what the agent in the pod wrote, as `render_output` does for a host
/// launch, and fail the run when it did not exit 0.
fn render_pod_exit(exit: &pod_agent::AgentExit, duration: Duration, mode: &str) -> Result<()> {
    let success = exit.exit_code == Some(0);
    if mode == "json" {
        let result = serde_json::json!({
            "success": success,
            "exit_code": exit.exit_code,
            "stdout": String::from_utf8_lossy(&exit.stdout),
            "stderr": String::from_utf8_lossy(&exit.stderr),
            "duration_ms": duration.as_millis(),
            "ran_in": "pod",
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        io::stdout().write_all(&exit.stdout)?;
        if !success {
            eprintln!("\n--- Execution Failed ---");
            eprintln!("Exit code: {:?}", exit.exit_code);
            if !exit.stderr.is_empty() {
                eprintln!("Stderr: {}", String::from_utf8_lossy(&exit.stderr));
            }
        }
        eprintln!("\n--- Summary ---");
        eprintln!("Ran in: microVM pod");
        eprintln!("Duration: {duration:?}");
    }
    if success {
        Ok(())
    } else {
        bail!("the agent in the pod exited with code {:?}", exit.exit_code)
    }
}

fn absolute_guest_dir(value: &str) -> std::result::Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("guest workspace must be an absolute path inside the guest".into())
    }
}

/// The pod's working directory, inside the guest. The guest's own `/work`
/// unless `--guest-work-dir` names another: the agent runs in the guest and
/// starts there, and no host directory is uploaded into it, so this host's
/// path would name nothing a guest has.
fn guest_work_dir(args: &RunArgs) -> PathBuf {
    match &args.guest_work_dir {
        Some(path) => path.clone(),
        None => nucleus_spec::guest_layout::WORK_DIR.into(),
    }
}

fn build_pod_spec(
    args: &RunArgs,
    policy: &PermissionLattice,
    kernel_path: &str,
    rootfs_path: &str,
    workload: Option<nucleus_spec::WorkloadSpec>,
) -> Result<SpecPodSpec> {
    let mut spec = SpecPodSpec::new(PodSpecInner {
        work_dir: guest_work_dir(args),
        timeout_seconds: args.timeout,
        policy: PolicySpec::Inline {
            lattice: Box::new(policy.clone()),
        },
        budget_model: None,
        resources: None,
        network: None,
        image: Some(ImageSpec {
            kernel_path: PathBuf::from(kernel_path),
            rootfs: RootfsSource::Path(PathBuf::from(rootfs_path)),
            boot_args: None,
            read_only: args.rootfs_read_only,
            scratch_path: None,
            kernel_digest: None,
            rootfs_digest: None,
            scratch_digest: None,
            data_path: None,
            data_digest: None,
        }),
        credentialed_egress: Vec::new(),
        workload,
        vsock: Some(VsockSpec {
            guest_cid: args.vsock_cid,
            port: args.vsock_port,
        }),
        seccomp: None,
        cgroup: None,
        audit_sink: None,
        credentials: None,
    });
    spec.metadata.task_grant_id = args.task_grant_id.clone();
    Ok(spec)
}

fn write_pod_spec(spec_path: &Path, spec: &SpecPodSpec) -> Result<()> {
    let yaml = serde_yaml::to_string(spec)?;
    fs::write(spec_path, yaml)?;
    Ok(())
}

/// The node's answer to a create. Only the id: the agent runs in the pod, so
/// nothing on this host talks to the pod's proxy address.
#[derive(Deserialize)]
struct CreatePodResponse {
    id: Uuid,
}

#[derive(Deserialize)]
struct NodeErrorBody {
    error: String,
}

/// Creates the pod through nucleus-node, over mTLS when `mtls_client` is
/// `Some` (the preferred, Move-B-compatible path — see `ResolvedConfig`'s
/// doc comment), else HMAC-signed over plain `ureq` for a node that has not
/// been migrated past Move B yet.
async fn create_pod_via_node(
    node_url: &str,
    spec: &SpecPodSpec,
    mtls_client: Option<&reqwest::Client>,
    auth_secret: Option<&str>,
    actor: &str,
) -> Result<CreatePodResponse> {
    let url = format!("{}/v1/pods", node_url.trim_end_matches('/'));
    let body = serde_yaml::to_string(spec)?;

    if let Some(client) = mtls_client {
        let response = client
            .post(&url)
            .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
            .header("content-type", "application/yaml")
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow!("node request failed: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            return match response.json::<NodeErrorBody>().await {
                Ok(body) => Err(anyhow!("node error: {}", body.error)),
                Err(_) => Err(anyhow!("node error: status {status}")),
            };
        }
        let parsed: CreatePodResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("failed to decode node response: {e}"))?;
        return Ok(parsed);
    }

    let auth_secret = auth_secret
        .ok_or_else(|| anyhow!("neither an mTLS identity nor an auth secret is available"))?;
    let mut request = ureq::post(&url)
        .config()
        .timeout_global(Some(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT))
        // Without this, ureq turns a 4xx into a transport error and discards the
        // body, so the `>= 400` branch below never ran and the node's own
        // sentence ("no such policy profile") arrived as "http status: 400".
        .http_status_as_error(false)
        .build()
        .header("content-type", "application/yaml");
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
                Ok(parsed)
            }
        }
        Err(err) => Err(anyhow!("node request failed: {err}")),
    }
}

/// How a HOST `nucleus-mcp` authenticates to a local TCP tool-proxy. No
/// unauthenticated arm: the bridge refuses to start against TCP without one.
///
/// The `SignedUpstream` arm (a host bridge behind the node's signing proxy)
/// went with the host agent launch for microVM pods: an agent in a pod reaches
/// its tools through the guest's own bridge and the workload door.
pub enum McpProxyAuth<'a> {
    /// The bridge signs with the proxy's shared secret, and approvals with the
    /// approval secret.
    Hmac {
        auth_secret: &'a str,
        approval_secret: &'a str,
    },
}

pub struct McpEnvConfig<'a> {
    pub proxy_url: &'a str,
    pub auth: McpProxyAuth<'a>,
    pub spec_path: &'a Path,
    pub kernel_trace: Option<&'a Path>,
    pub sandbox_token: Option<&'a str>,
}

pub fn write_mcp_config(
    mcp_path: &Path,
    mcp_command: &Path,
    env_cfg: &McpEnvConfig<'_>,
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
    env.insert(
        "NUCLEUS_MCP_PROXY_URL".to_string(),
        env_cfg.proxy_url.to_string(),
    );
    let McpProxyAuth::Hmac {
        auth_secret,
        approval_secret,
    } = env_cfg.auth;
    env.insert(
        "NUCLEUS_MCP_AUTH_SECRET".to_string(),
        auth_secret.to_string(),
    );
    env.insert(
        "NUCLEUS_MCP_APPROVAL_SECRET".to_string(),
        approval_secret.to_string(),
    );
    env.insert(
        "NUCLEUS_MCP_SPEC".to_string(),
        env_cfg.spec_path.display().to_string(),
    );
    if let Some(trace_path) = env_cfg.kernel_trace {
        env.insert(
            "NUCLEUS_MCP_KERNEL_TRACE".to_string(),
            trace_path.display().to_string(),
        );
    }
    if let Some(token) = env_cfg.sandbox_token {
        env.insert("NUCLEUS_MCP_SANDBOX_TOKEN".to_string(), token.to_string());
    }

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

/// Prefix identifying nucleus MCP tools. Only tools carrying this prefix route
/// through the `PermissionLattice`-enforcing MCP server; anything else is a
/// built-in tool that would act OUTSIDE the kernel.
pub(crate) const NUCLEUS_MCP_TOOL_PREFIX: &str = "mcp__nucleus__";

/// Capability token proving the *complete-mediation* confinement guard that
/// makes launching the agent with the approval bypass safe.
///
/// `run_agent_mcp` spawns the agent with `--dangerously-skip-permissions` /
/// `bypassPermissions`. That is safe ONLY under complete mediation: the agent's
/// built-in tools are disallowed (`DISALLOWED_BUILTIN_TOOLS`) and every tool it
/// is *allowed* to use is a nucleus MCP tool routed through the
/// `PermissionLattice`. This token is unforgeable proof that a caller
/// established that confinement — its only constructor,
/// [`MediationGuard::establish`], re-verifies the invariant at the call edge and
/// refuses to mint a token otherwise.
///
/// `run_agent_mcp` takes a `&MediationGuard` and reads the agent's allowed-tool
/// set *from the token* (never from an unvetted argument), so the guard is
/// **closed under the call**: no caller can reach `run_agent_mcp` without first
/// proving mediation. The confinement flows across the call edge as a real
/// value rather than an implicit precondition.
pub struct MediationGuard {
    /// The vetted, lattice-mediated tools the agent may use. Guaranteed
    /// non-empty and all `NUCLEUS_MCP_TOOL_PREFIX`-prefixed by `establish`.
    allowed_tools: Vec<String>,
}

impl MediationGuard {
    /// Establish the confinement guard from the tools a policy resolved to.
    ///
    /// Returns `None` — refusing to mint the capability — unless there is at
    /// least one allowed tool and *every* allowed tool routes through the
    /// nucleus MCP server. A `None` means the caller CANNOT obtain the token,
    /// and therefore CANNOT reach `run_agent_mcp`, so the agent is never
    /// launched with the approval bypass while a non-mediated (built-in) tool
    /// is reachable.
    pub fn establish(allowed_tools: &[String]) -> Option<Self> {
        if allowed_tools.is_empty() {
            return None;
        }
        if !allowed_tools
            .iter()
            .all(|tool| tool.starts_with(NUCLEUS_MCP_TOOL_PREFIX))
        {
            return None;
        }
        Some(Self {
            allowed_tools: allowed_tools.to_vec(),
        })
    }

    /// The vetted set of lattice-mediated tools the confined agent may use.
    fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the host launch takes its --unsandboxed declaration by value (C-4) beside the \
              inputs of the protocol it shares with the pod"
)]
async fn run_agent_mcp(
    args: &RunArgs,
    agent: &crate::agent::AgentCommand,
    declared: crate::host_tier::HostAgentOptIn,
    policy: &PermissionLattice,
    mcp_config_path: &Path,
    guard: &MediationGuard,
    prompt: &str,
    work_dir: &Path,
) -> Result<std::process::Output> {
    // Runtime complete mediation: the PreToolUse hook denies every tool that
    // is not one of the guard's allowed nucleus MCP tools, so a built-in the
    // static denylist has never heard of is still blocked at the call edge.
    // The settings file lives beside the MCP config.
    let settings_path = crate::mediation::write_hook_settings(
        mcp_config_path
            .parent()
            .ok_or_else(|| anyhow!("mcp config path has no parent directory"))?,
    )?;

    // Confined by construction: `launch` applies the confinement flags, and
    // takes the operator's `--unsandboxed` declaration.
    let mut cmd = agent.launch(declared);
    cmd.args(mcp_launch_protocol(
        args.model.as_deref(),
        mcp_config_path.as_os_str(),
        guard,
        policy,
        prompt,
    ))
    .arg("--settings")
    .arg(settings_path.as_path())
    .env(
        crate::mediation::ALLOWED_TOOLS_ENV,
        guard.allowed_tools().join(","),
    )
    .current_dir(work_dir);

    agent_process::output(cmd).await
}

/// The MCP launch protocol after the agent's own argv and the confinement
/// flags: one builder for the host launch (`run_agent_mcp`, which adds its
/// `--settings` mediation hook) and the in-pod workload (`pod_agent`), so the
/// two cannot tell an agent different things (ADR 0007 G-1).
fn mcp_launch_protocol(
    model: Option<&str>,
    mcp_config: &std::ffi::OsStr,
    guard: &MediationGuard,
    policy: &PermissionLattice,
    prompt: &str,
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = vec!["--print".into()];
    if let Some(model) = model {
        argv.extend(["--model".into(), model.into()]);
    }
    argv.extend([
        "--mcp-config".into(),
        mcp_config.to_owned(),
        // Allowed tools come ONLY from the confinement guard, which has already
        // vetted that every one routes through the PermissionLattice. There is
        // no path to hand the agent an unmediated tool set.
        "--allowedTools".into(),
        guard.allowed_tools().join(",").into(),
        // CRITICAL — complete mediation. Block the agent's BUILT-IN tools so it
        // can act ONLY through the nucleus MCP tools, every one of which routes
        // through the PermissionLattice. Without this, the approval bypass below
        // lets the built-in Bash/Read/Write/WebFetch/etc. run OUTSIDE the kernel.
        // Mirrors `shell.rs`.
        "--disallowedTools".into(),
        crate::constants::DISALLOWED_BUILTIN_TOOLS.into(),
        "--max-budget-usd".into(),
        policy.budget.max_cost_usd.to_string().into(),
        prompt.into(),
        // Bypass the agent's built-in *interactive approval* — SAFE ONLY
        // because `--disallowedTools` above removed every built-in tool, so the
        // agent's remaining tools are the nucleus MCP tools, each routed through
        // the PermissionLattice. The interactive approval cannot function in
        // non-interactive `--print` mode anyway, so the lattice IS the boundary.
        "--dangerously-skip-permissions".into(),
        "--permission-mode".into(),
        "bypassPermissions".into(),
    ]);
    argv
}

pub fn build_mcp_allowed_tools(policy: &PermissionLattice) -> Vec<String> {
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
    if policy.capabilities.glob_search >= CapabilityLevel::LowRisk {
        tools.push("mcp__nucleus__glob".to_string());
    }
    if policy.capabilities.grep_search >= CapabilityLevel::LowRisk {
        tools.push("mcp__nucleus__grep".to_string());
    }
    if policy.capabilities.web_search >= CapabilityLevel::LowRisk {
        tools.push("mcp__nucleus__web_search".to_string());
    }
    tools
}

fn warn_unimplemented_caps(_policy: &PermissionLattice) {
    // All standard capabilities now have MCP tool implementations
    // (read, write, run, web_fetch, glob, grep, web_search).
    // This function remains as a hook for future capabilities.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_workspace_is_distinct_from_the_host_agent_directory() {
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: RunArgs,
        }
        let mut args =
            Parse::try_parse_from(["run", "ordinary task", "--apple-host-config", "host.json"])
                .unwrap()
                .args;
        let policy = PermissionLattice::restrictive();
        let spec = build_pod_spec(&args, &policy, "/kernel", "/rootfs", None).unwrap();
        assert_eq!(
            spec.spec.work_dir,
            Path::new(nucleus_spec::guest_layout::WORK_DIR)
        );
        args.guest_work_dir = Some("/tmp/project".into());
        let spec = build_pod_spec(&args, &policy, "/kernel", "/rootfs", None).unwrap();
        assert_eq!(spec.spec.work_dir, Path::new("/tmp/project"));
        // Every pod starts its agent in the guest's own /work: no host
        // directory is uploaded, so a host path would name nothing there.
        args.apple_host_config = None;
        args.guest_work_dir = None;
        assert_eq!(
            guest_work_dir(&args),
            Path::new(nucleus_spec::guest_layout::WORK_DIR)
        );
        assert!(
            Parse::try_parse_from(["run", "ordinary task", "--guest-work-dir", "relative",])
                .is_err()
        );
        assert!(
            Parse::try_parse_from([
                "run",
                "ordinary task",
                "--guest-work-dir",
                "/work",
                "--local",
            ])
            .is_err()
        );
    }

    #[test]
    fn the_agent_is_what_the_user_named_and_nothing_else() {
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: RunArgs,
        }
        let args = Parse::try_parse_from([
            "run",
            "--agent",
            "my-agent",
            "fix the bug",
            "--",
            "--agent-flag",
            "value",
        ])
        .unwrap()
        .args;
        assert_eq!(args.prompt.as_deref(), Some("fix the bug"));
        let agent = named_agent(&args).expect("named");
        let cmd = agent.launch(crate::host_tier::HostAgentOptIn::for_test());
        assert_eq!(cmd.get_program(), "my-agent");
        let argv: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(&argv[..2], ["--agent-flag", "value"]);

        // Nothing named: refused, with directions, before any mode is chosen.
        if std::env::var_os("NUCLEUS_AGENT").is_none() {
            let args = Parse::try_parse_from(["run", "--local", "fix the bug"])
                .unwrap()
                .args;
            let err = named_agent(&args).expect_err("no default agent");
            assert!(err.to_string().contains("--agent"), "{err}");
        }
    }

    #[tokio::test]
    async fn explicit_host_identity_resolves_and_missing_files_do_not_fall_back() {
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: RunArgs,
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let parsed = Parse::try_parse_from([
            "run",
            "check the project",
            "--identity-dir",
            path,
            "--node-url",
            "https://127.0.0.1:8080",
            "--kernel-path",
            "/var/lib/nucleus/artifacts/vmlinux",
            "--rootfs-path",
            "/var/lib/nucleus/artifacts/rootfs.ext4",
        ])
        .unwrap();
        let mut config = Config::default();
        config.auth.use_keychain = true;
        assert!(resolve_config(&parsed.args, &config).is_err());
        let ca = nucleus_identity::SelfSignedCa::new("selected-host.nucleus.local").unwrap();
        crate::provision::mint_cli_identity(&ca, "selected-host.nucleus.local", dir.path())
            .await
            .unwrap();
        let resolved = resolve_config(&parsed.args, &config).unwrap().unwrap();
        assert!(resolved.node_mtls_client.is_some());
        assert!(resolved.node_auth_secret.is_none());
        assert_eq!(resolved.node_url, "https://127.0.0.1:8080");
        std::fs::remove_file(dir.path().join("cli-key.pem")).unwrap();
        assert!(resolve_config(&parsed.args, &config).is_err());
        assert!(
            Parse::try_parse_from([
                "run",
                "check the project",
                "--local",
                "--identity-dir",
                path,
            ])
            .is_err()
        );
    }

    // Confinement-guard tests: exercise the REAL invariant that
    // `run_agent_mcp` depends on — the agent may be launched with the approval
    // bypass only when every tool it can reach routes through the lattice.

    #[test]
    fn guard_established_for_a_real_policy_tool_set() {
        // A permissive policy resolves to a set of nucleus MCP tools; because
        // they are all lattice-mediated, the confinement guard is established
        // and carries exactly that vetted set into `run_agent_mcp`.
        let policy = PermissionLattice::permissive();
        let allowed = build_mcp_allowed_tools(&policy);
        assert!(
            !allowed.is_empty(),
            "permissive policy should allow at least one MCP tool"
        );
        let guard =
            MediationGuard::establish(&allowed).expect("all-MCP tool set must mint the guard");
        assert_eq!(guard.allowed_tools(), allowed.as_slice());
        // Every tool that reaches the agent is lattice-routed.
        assert!(
            guard
                .allowed_tools()
                .iter()
                .all(|t| t.starts_with(NUCLEUS_MCP_TOOL_PREFIX))
        );
    }

    #[test]
    fn guard_refuses_when_a_builtin_tool_is_reachable() {
        // If mediation were incomplete — a built-in (non-MCP) tool alongside
        // the MCP tools — the agent could act OUTSIDE the kernel. The guard
        // must refuse to mint a token, making `run_agent_mcp` unreachable so
        // the agent is never launched with the approval bypass off-guard.
        let mut tools = build_mcp_allowed_tools(&PermissionLattice::permissive());
        tools.push("Bash".to_string()); // a built-in, lattice-bypassing tool
        assert!(
            MediationGuard::establish(&tools).is_none(),
            "a reachable non-MCP tool must block the confinement guard"
        );
    }

    #[test]
    fn guard_refuses_empty_tool_set() {
        // No mediated tools at all is not a launchable confinement.
        assert!(MediationGuard::establish(&[]).is_none());
    }

    #[test]
    fn guard_refuses_a_bare_mcp_lookalike_prefix() {
        // Defense in depth: a tool that merely mentions "mcp" but is not a
        // nucleus MCP tool is not lattice-mediated and must be refused.
        let tools = vec!["mcp__other__exec".to_string()];
        assert!(MediationGuard::establish(&tools).is_none());
    }

    fn parse(argv: &[&str]) -> RunArgs {
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: RunArgs,
        }
        Parse::try_parse_from(argv).expect("parses").args
    }

    /// D9: the agent reaches this host only on `--unsandboxed`. Without it,
    /// `--local` and `--hook` refuse in `dispatch` before a tool-proxy, a temp
    /// dir or a process exists. (The record written WITH it is pinned in
    /// `host_tier`'s tests, against a temp audit log.)
    #[tokio::test]
    async fn the_local_tiers_refuse_a_host_agent_without_the_opt_in() {
        let policy = PermissionLattice::permissive();
        for mode in ["--local", "--hook"] {
            let args = parse(&["run", mode, "--agent", "my-agent", "task"]);
            let err = dispatch(&args, None, &policy, Path::new("/w"), "task")
                .await
                .expect_err("no host launch without --unsandboxed");
            let msg = err.to_string();
            assert!(msg.contains("--unsandboxed"), "{mode}: {msg}");
            assert!(msg.contains("my-agent"), "{mode}: {msg}");
        }
    }

    /// `--egress` is a pod declaration: it needs the registry, it means nothing
    /// to a host agent, and its companions need it.
    #[test]
    fn egress_flags_parse_only_as_a_pod_declaration() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Parse {
            #[command(flatten)]
            args: RunArgs,
        }
        let ok = parse(&[
            "run",
            "--egress",
            "model-api",
            "--upstreams",
            "/etc/nucleus/upstreams.toml",
            "--egress-export",
            "HARNESS_BASE_URL=model-api",
            "--egress-placeholder",
            "HARNESS_TOKEN",
            "t",
        ]);
        assert_eq!(ok.egress, ["model-api"]);
        for argv in [
            vec!["run", "--egress", "model-api", "t"],
            vec!["run", "--egress-export", "V=model-api", "t"],
            vec!["run", "--egress-placeholder", "V", "t"],
            vec![
                "run",
                "--local",
                "--egress",
                "model-api",
                "--upstreams",
                "/r.toml",
                "t",
            ],
        ] {
            assert!(Parse::try_parse_from(&argv).is_err(), "{argv:?}");
        }
    }

    /// #3218: `--egress` under a profile that can never make the call is
    /// refused by `dispatch` before a host or a pod is started. Without the
    /// check this run gets as far as the node configuration instead (no node
    /// is configured here), which is the point the pod would be created from.
    #[tokio::test]
    async fn egress_under_a_profile_that_cannot_call_is_refused_before_any_pod() {
        let argv = |profile| {
            parse(&[
                "run",
                "--agent",
                "a",
                "--profile",
                profile,
                "--egress",
                "model-api",
                "--upstreams",
                "/r.toml",
                "t",
            ])
        };
        let dir = std::env::temp_dir();
        let run = |profile: &'static str| {
            let dir = dir.clone();
            async move {
                let args = argv(profile);
                let policy = profiles::resolve(profile).expect("canonical profile");
                dispatch(&args, None, &policy, &dir, "t")
                    .await
                    .expect_err("no node is configured")
                    .to_string()
            }
        };
        let refused = run("codegen").await;
        assert!(refused.contains("profile 'codegen'"), "{refused}");
        assert!(refused.contains("safe-pr-fixer"), "{refused}");
        // The profile that grants the call passes the check and stops only at
        // the missing node: the refusal above is the egress check's, not this.
        let admitted = run("safe-pr-fixer").await;
        assert!(admitted.contains("node config required"), "{admitted}");
    }

    /// The flags that only mean something for a host agent are refused for a
    /// pod by name, never silently dropped (A-1).
    #[test]
    fn a_pod_run_refuses_host_only_flags_by_name() {
        assert!(refuse_host_only_flags(&parse(&["run", "--agent", "a", "t"])).is_ok());
        for (flag, argv) in [
            ("--unsandboxed", vec!["run", "--unsandboxed", "t"]),
            ("--env", vec!["run", "--env", "K=V", "t"]),
            (
                "--kernel-trace",
                vec!["run", "--kernel-trace", "/tmp/t", "t"],
            ),
        ] {
            let err = refuse_host_only_flags(&parse(&argv)).expect_err(flag);
            assert!(err.to_string().contains(flag), "{flag}: {err}");
        }
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: RunArgs,
        }
        assert!(
            Parse::try_parse_from(["run", "--unsandboxed", "--apple-host-config", "h.json", "t"])
                .is_err(),
            "an Apple host is a microVM host: no host agent there"
        );
    }

    /// The host launch and the pod workload speak one protocol: the pod's argv
    /// after the confinement flags is exactly what `mcp_launch_protocol` gives
    /// a host launch, with the guest's bridge config in place of a path.
    #[test]
    fn the_pod_and_the_host_get_one_launch_protocol() {
        let policy = PermissionLattice::permissive();
        let guard = MediationGuard::establish(&build_mcp_allowed_tools(&policy)).unwrap();
        let agent = crate::agent::AgentCommand::named(Some("/opt/agent"), &[]).unwrap();
        let w = pod_agent::workload(&agent, &guard, &policy, None, "task").unwrap();
        let config = pod_agent::guest_mcp_config();
        let host: Vec<String> = mcp_launch_protocol(None, config.as_ref(), &guard, &policy, "task")
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(
            w.args[crate::mediation::CONFINEMENT_FLAGS.len()..],
            host[..]
        );
    }

    // ── create_pod_via_node mTLS (Move B) ───────────────────────────────────

    /// A real mTLS handshake against a real server, proving the NEW code path
    /// end to end — not just the general reqwest-mTLS mechanism (already
    /// proven elsewhere this session), but this function's own request
    /// shape and response parsing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_pod_via_node_completes_a_real_mtls_handshake() {
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let trust_domain = "run-mtls-test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        let server_identity = Identity::new(trust_domain, "system", "node");
        let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = ca
            .sign_csr(
                server_csr.csr(),
                server_csr.private_key(),
                &server_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let client_identity = Identity::new(trust_domain, "system", "cli");
        let client_csr = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = ca
            .sign_csr(
                client_csr.csr(),
                client_csr.private_key(),
                &client_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut identity_pem = client_cert.chain_pem().into_bytes();
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(client_cert.private_key_pem().as_bytes());
        let bundle_pem = trust_bundle
            .roots()
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let tls =
            nucleus_identity::node_tls::node_client_config(&identity_pem, &bundle_pem).unwrap();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .build()
            .unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let acceptor = TlsServerConfig::new(server_cert, trust_bundle)
                .build_acceptor()
                .unwrap();
            let pod = "550e8400-e29b-41d4-a716-446655440000";
            let said = "the agent says hi\n";
            let exited = format!(
                r#"{{"state":"exited","exit_code":0,"stdout_sha256":"{}","stderr_sha256":"{}","launch_hash":"l","environment":{{"inputs_sha256":"i","complete_sha256":"c"}},"program":{{"state":"bound","digest":"d"}},"isolation":"uid_isolated"}}"#,
                hex::encode(Sha256::digest(said.as_bytes())),
                hex::encode(Sha256::digest(b"")),
            );
            let mut created = String::new();
            for (request, status, body) in [
                (
                    "POST /v1/pods".to_string(),
                    "200 OK",
                    format!(r#"{{"id":"{pod}","proxy_addr":"127.0.0.1:9"}}"#),
                ),
                (
                    format!("POST /v1/pods/{pod}/cancel"),
                    "200 OK",
                    r#"{"status":"cancelled"}"#.to_string(),
                ),
                (
                    format!("POST /v1/pods/{pod}/cancel"),
                    "503 Service Unavailable",
                    r#"{"error":"temporarily unavailable"}"#.to_string(),
                ),
                // The in-pod run: create, wait for the workload, read its
                // output, cancel. No proxy address is needed or asked for.
                (
                    "POST /v1/pods".to_string(),
                    "200 OK",
                    format!(r#"{{"id":"{pod}","proxy_addr":null}}"#),
                ),
                (
                    format!("GET /v1/pods/{pod}/workload-result"),
                    "200 OK",
                    r#"{"state":"running"}"#.to_string(),
                ),
                (
                    format!("GET /v1/pods/{pod}/workload-result"),
                    "200 OK",
                    exited.clone(),
                ),
                (
                    format!("GET /v1/pods/{pod}/workload-logs/stdout"),
                    "200 OK",
                    said.to_string(),
                ),
                (
                    format!("GET /v1/pods/{pod}/workload-logs/stderr"),
                    "200 OK",
                    String::new(),
                ),
                (
                    format!("POST /v1/pods/{pod}/cancel"),
                    "200 OK",
                    r#"{"status":"cancelled"}"#.to_string(),
                ),
            ] {
                let (stream, _) = tcp_listener.accept().await.unwrap();
                let mut tls = acceptor.accept(stream).await.unwrap();
                // Read the whole request: a pod spec carries a full lattice, and
                // closing on unread bytes would reset the connection.
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = tls.read(&mut buf).await.unwrap();
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if raw.len() >= end + 4 + length {
                            break;
                        }
                    }
                    assert!(n > 0, "request ended early");
                }
                let text = String::from_utf8_lossy(&raw).into_owned();
                assert!(
                    text.starts_with(&format!("{request} HTTP/1.1")),
                    "expected {request}, got {}",
                    text.lines().next().unwrap_or("")
                );
                if request == "POST /v1/pods" {
                    created = text;
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                tls.write_all(response.as_bytes()).await.unwrap();
            }
            created
        });

        let spec: SpecPodSpec =
            serde_yaml::from_str("apiVersion: nucleus/v1\nkind: Pod\nspec:\n  work_dir: /work\n")
                .unwrap();
        let created_pod = create_pod_via_node(
            &format!("https://{addr}"),
            &spec,
            Some(&client),
            None,
            "test-actor",
        )
        .await
        .expect("a real mTLS handshake against the SAME CA must succeed");
        let config = ResolvedConfig {
            node_url: format!("https://{addr}"),
            node_mtls_client: Some(client),
            node_auth_secret: None,
            node_actor: "test-actor".into(),
            kernel_path: "/kernel".into(),
            rootfs_path: "/rootfs".into(),
        };
        pod_session::cancel(&config, created_pod.id).await.unwrap();
        let error = pod_session::cancel(&config, created_pod.id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("503"));
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: RunArgs,
        }
        let args = Parse::try_parse_from(["run", "--agent", "/opt/agent", "ordinary task"])
            .unwrap()
            .args;
        let work = tempfile::tempdir().unwrap();
        let agent = named_agent(&args).unwrap();
        run_in_pod(
            &args,
            &agent,
            &config,
            &PermissionLattice::permissive(),
            work.path(),
            "ordinary task",
            None,
        )
        .await
        .expect("the agent ran in the pod, exited 0, and its output matched its digest");

        let created = server_handle.await.unwrap();
        let body = &created[created.find("\r\n\r\n").unwrap() + 4..];
        let sent: SpecPodSpec = serde_yaml::from_str(body).unwrap();
        let workload = sent.spec.workload.expect("the agent is the pod's workload");
        assert_eq!(workload.command, "/opt/agent");
        assert!(workload.env.is_empty());
        assert_eq!(
            sent.spec.work_dir,
            Path::new(nucleus_spec::guest_layout::WORK_DIR)
        );
    }
}
