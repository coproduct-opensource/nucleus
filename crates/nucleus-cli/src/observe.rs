//! `nucleus observe` — progressive discovery of agent capabilities.
//!
//! Reads a JSONL log of tool calls (from audit log or stdin) and generates
//! a minimal policy profile that permits exactly the observed behavior.

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use portcullis::observe::{format_summary, parse_jsonl_observations, ObserveSession};

/// Observe agent behavior and generate a minimal policy profile.
#[derive(Args)]
pub struct ObserveArgs {
    /// Agent name for the generated profile.
    #[arg(short = 'n', long, default_value = "agent")]
    pub name: String,

    /// Path to JSONL audit log file. Use "-" or omit for stdin.
    /// Accepts both simple format and kernel Decision JSONL from --kernel-trace.
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Output file for generated YAML policy. Omit for stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Show summary report alongside policy.
    #[arg(long, default_value_t = true)]
    pub summary: bool,
}

pub fn execute(args: ObserveArgs) -> Result<()> {
    // Read input
    let input_data = match &args.input {
        Some(path) if path.to_str() != Some("-") => std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?,
        _ => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read stdin")?;
            buf
        }
    };

    if input_data.trim().is_empty() {
        eprintln!("No observations to process. Provide JSONL input via --input or stdin.");
        eprintln!();
        eprintln!("Expected format (one JSON object per line):");
        eprintln!(r#"  {{"operation":"read_files","subject":"src/main.rs","succeeded":true}}"#);
        eprintln!(r#"  {{"operation":"web_fetch","subject":"https://docs.rs","succeeded":true}}"#);
        eprintln!(r#"  {{"operation":"git_push","subject":"origin main","succeeded":false}}"#);
        return Ok(());
    }

    // Parse observations
    let observations = parse_jsonl_observations(&input_data);

    if observations.is_empty() {
        eprintln!("No valid observations found in input.");
        return Ok(());
    }

    // Build session
    let mut session = ObserveSession::new(&args.name);
    for obs in observations {
        session.record(obs);
    }

    // Synthesize profile
    let profile = session.synthesize();
    let yaml = profile.to_yaml().context("Failed to serialize profile")?;

    // Print summary to stderr if requested
    if args.summary {
        let summary = session.summary();
        let report = format_summary(&summary);
        eprintln!("{}", report);
    }

    // Output YAML
    match &args.output {
        Some(path) => {
            std::fs::write(path, &yaml)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            eprintln!("Policy written to {}", path.display());
        }
        None => {
            println!("{}", yaml);
        }
    }

    Ok(())
}
