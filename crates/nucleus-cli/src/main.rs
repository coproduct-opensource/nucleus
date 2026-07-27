//! Nucleus CLI - Run AI agents with policy-aware defaults
//!
//! `nucleus-cli` runs an agent CLI with MCP + nucleus-tool-proxy for tool enforcement.
//! Use `nucleus-node` (Firecracker) for all execution.
//!
//! # Examples
//!
//! ```bash
//! # Run with default permissions (restrictive)
//! nucleus run "Fix the bug in src/main.rs"
//!
//! # Run with a permission profile
//! nucleus run --profile fix-issue "Implement the feature"
//!
//! # Run with custom config
//! nucleus run --config permissions.toml "Review the code"
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod audit;
mod bundle;
mod config;
mod constants;
mod doctor;
mod envelope;
mod envelope_verify;
mod guard;
mod identity;
mod keychain;
mod lineage;
mod lineage_verify;
mod lockdown;
mod manifest;
mod node;
mod observe;
mod profiles;
mod replay;
mod run;
mod setup;
mod shell;
mod start;
mod stop;
mod token;

/// Nucleus CLI - policy-aware wrapper (tool enforcement via proxy)
#[derive(Parser)]
#[command(name = "nucleus")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, env = "NUCLEUS_CONFIG")]
    #[arg(default_value = "~/.config/nucleus/config.toml")]
    config: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit agent configurations for security risks (Tier 0)
    Audit(audit::AuditArgs),

    /// Secure your MCP servers — audit, policy, enforce
    Guard(guard::GuardArgs),

    /// Manage MCP tool manifests — generate, sign, verify
    Manifest(manifest::ManifestArgs),

    /// Execute a task with enforced permissions
    Run(Box<run::RunArgs>),

    /// Launch an interactive agent session with nucleus security context
    Shell(shell::ShellArgs),

    /// Set up nucleus environment (Lima VM, artifacts, secrets)
    Setup(setup::SetupArgs),

    /// Start nucleus-node in the Lima VM
    Start(start::StartArgs),

    /// Stop nucleus-node and optionally the Lima VM
    Stop(stop::StopArgs),

    /// Emergency lockdown — drop all agents to read-only
    Lockdown(lockdown::LockdownArgs),

    /// Check setup status and diagnose issues
    Doctor,

    /// List available permission profiles
    Profiles,

    /// Show current configuration
    Config,

    /// Observe agent behavior and generate a minimal policy profile
    Observe(observe::ObserveArgs),

    /// Replay a kernel decision trace for audit
    Replay(replay::ReplayArgs),

    /// Manage attenuation tokens for delegation
    Token(token::TokenArgs),

    /// JWT-SVID inspection + OP token-exchange affordances (#48)
    Identity(identity::IdentityArgs),

    /// Interact with a running nucleus-node (test utilities)
    Node(node::NodeArgs),

    /// Walk the data-lineage DAG for a SPIFFE call ID
    Lineage(lineage::LineageArgs),

    /// Verify Merkle integrity of a lineage log against signed checkpoints
    LineageVerifyChain(lineage_verify::VerifyChainArgs),

    /// Extract a portable provenance bundle (payload + IFC envelope) for a session
    Envelope(envelope::EnvelopeArgs),

    /// Verify a provenance bundle standalone
    EnvelopeVerify(envelope_verify::EnvelopeVerifyArgs),

    /// Content-addressed bundle transfer over iroh-blobs (publish/fetch)
    Bundle(bundle::BundleArgs),
}

fn init_logging(verbose: bool) {
    let filter = if verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("nucleus=debug,info"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("nucleus=info,warn"))
    };

    // Route tracing to stderr so subcommands that emit machine-readable
    // output on stdout (e.g. `nucleus envelope --out -`) aren't polluted
    // by INFO lines.
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS connections (via ureq).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    init_logging(cli.verbose);

    let config_path = shellexpand::tilde(&cli.config).to_string();
    info!(config_path = %config_path, "Starting nucleus");

    match cli.command {
        Commands::Audit(args) => audit::execute(args),
        Commands::Guard(args) => guard::execute(args),
        Commands::Manifest(args) => {
            manifest::execute(args);
            Ok(())
        }
        Commands::Run(args) => run::execute(*args, &config_path).await,
        Commands::Shell(args) => shell::execute(args).await,
        Commands::Setup(args) => setup::execute(args).await,
        Commands::Start(args) => start::execute(args).await,
        Commands::Stop(args) => stop::execute(args).await,
        Commands::Lockdown(args) => lockdown::execute(args).await,
        Commands::Doctor => doctor::diagnose().await,
        Commands::Profiles => profiles::list(),
        Commands::Config => config::show(&config_path),
        Commands::Observe(args) => observe::execute(args),
        Commands::Replay(args) => replay::execute(args),
        Commands::Token(args) => token::execute(args),
        Commands::Identity(args) => identity::execute(args),
        Commands::Node(args) => node::execute(args).await,
        Commands::Lineage(args) => lineage::execute(args),
        Commands::LineageVerifyChain(args) => lineage_verify::execute(args),
        Commands::Envelope(args) => envelope::execute(args),
        Commands::EnvelopeVerify(args) => envelope_verify::execute(args),
        Commands::Bundle(args) => bundle::execute(args).await,
    }
}
