//! `mcp-guard` — Trifecta Gate CLI. See what your AI agent can exfiltrate.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nucleus_mcp_guard::{analyze_session, proxy, Classifier, ClassifierConfig, SessionMonitor};
use proxy::{GuardConfig, Mode};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(
    name = "mcp-guard",
    about = "Trifecta Gate: see \u{2014} or stop \u{2014} what your AI agent can exfiltrate."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Optional classifier-override config (JSON) — extend or replace the defaults.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Emit machine-readable JSON instead of the human report.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Wrap a live stdio MCP server and observe the session. The server command
    /// and its args follow `--`, e.g. `mcp-guard proxy -- npx my-mcp-server`.
    Proxy {
        /// Block denied calls instead of only reporting them. Off by default,
        /// so wrapping a server never starts refusing traffic by surprise.
        #[arg(long)]
        enforce: bool,
        /// Persist pinned tool schemas here (JSON). Without it a rug-pull can
        /// only be caught within a single session, which is not the threat:
        /// the attack is to be benign at approval time and mutate later.
        #[arg(long, value_name = "PATH")]
        pin_file: Option<PathBuf>,
        #[arg(last = true, required = true, num_args = 1..)]
        server: Vec<String>,
    },
    /// Replay a recorded session offline and report. The session file is a JSON
    /// array of tool names (in call order), or `{"tools": [...]}`.
    Analyze { session: PathBuf },
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum SessionFile {
    List(Vec<String>),
    Obj { tools: Vec<String> },
}

fn load_classifier(path: &Option<PathBuf>) -> Result<Classifier> {
    match path {
        Some(p) => {
            let s = std::fs::read_to_string(p)
                .with_context(|| format!("reading classifier config {}", p.display()))?;
            let cfg: ClassifierConfig =
                serde_json::from_str(&s).context("parsing classifier config JSON")?;
            Ok(Classifier::from_config(&cfg))
        }
        None => Ok(Classifier::default()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let classifier = load_classifier(&cli.config)?;

    let (report, protocol_on_stdout) = match cli.cmd {
        Cmd::Analyze { session } => {
            let s = std::fs::read_to_string(&session)
                .with_context(|| format!("reading session file {}", session.display()))?;
            let sf: SessionFile = serde_json::from_str(&s).context("parsing session file")?;
            let tools = match sf {
                SessionFile::List(v) => v,
                SessionFile::Obj { tools } => tools,
            };
            (analyze_session(&tools, classifier), false)
        }
        Cmd::Proxy {
            enforce,
            pin_file,
            server,
        } => {
            let (cmd, args) = server.split_first().context("missing MCP server command")?;
            let monitor = Arc::new(Mutex::new(SessionMonitor::new(classifier)));
            let config = GuardConfig {
                mode: if enforce {
                    Mode::Enforce
                } else {
                    Mode::Observe
                },
                pin_file,
            };
            let report = proxy::run_stdio_proxy_with(monitor, cmd, args, config).await?;
            (report, true) // stdout is the MCP channel — report must go to stderr
        }
    };

    let rendered = if cli.json {
        report.to_json()
    } else {
        report.render()
    };
    if protocol_on_stdout {
        eprintln!("{rendered}");
    } else {
        println!("{rendered}");
    }

    // Non-zero exit when exfiltration is possible, so CI / assessments can gate.
    if report.exfiltration_possible {
        std::process::exit(1);
    }
    Ok(())
}
