//! Nucleus CLI - Run AI agents with policy-aware defaults
//!
//! `nucleus-cli` runs Claude with MCP + nucleus-tool-proxy for tool enforcement.
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

mod config;
mod constants;
mod doctor;
mod keychain;
mod node;
mod profiles;
mod run;
mod setup;
mod start;
mod stop;

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
    /// Execute a task with enforced permissions
    Run(Box<run::RunArgs>),

    /// Set up nucleus environment (Lima VM, artifacts, secrets)
    Setup(setup::SetupArgs),

    /// Start nucleus-node in the Lima VM
    Start(start::StartArgs),

    /// Stop nucleus-node and optionally the Lima VM
    Stop(stop::StopArgs),

    /// Check setup status and diagnose issues
    Doctor,

    /// List available permission profiles
    Profiles,

    /// Show current configuration
    Config,

    /// Interact with a running nucleus-node (test utilities)
    Node(node::NodeArgs),
}

fn init_logging(verbose: bool) {
    let filter = if verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("nucleus=debug,info"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("nucleus=info,warn"))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let config_path = shellexpand::tilde(&cli.config).to_string();
    info!(config_path = %config_path, "Starting nucleus");

    match cli.command {
        Commands::Run(args) => run::execute(*args, &config_path).await,
        Commands::Setup(args) => setup::execute(args).await,
        Commands::Start(args) => start::execute(args).await,
        Commands::Stop(args) => stop::execute(args).await,
        Commands::Doctor => doctor::diagnose().await,
        Commands::Profiles => profiles::list(),
        Commands::Config => config::show(&config_path),
        Commands::Node(args) => node::execute(args).await,
    }
}
