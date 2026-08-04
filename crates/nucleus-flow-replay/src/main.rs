//! Replay a recorded tool-call trace through the real kernel decision path.
//!
//! ```text
//! nucleus-flow-replay --trace episode.jsonl --out outcomes.jsonl
//! ```
//!
//! Reads JSONL steps, emits one outcome per step plus a summary on stderr.
//! Needs no network, no model, and no API budget — the whole point is that the
//! kernel's behaviour is measurable without any of them.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "nucleus-flow-replay",
    about = "Replay tool-call traces through the real kernel decision path"
)]
struct Args {
    /// JSONL trace file; `-` reads stdin.
    #[arg(long)]
    trace: String,

    /// Write per-step outcomes here as JSONL (default: stdout).
    #[arg(long)]
    out: Option<PathBuf>,

    /// Emit only the summary object, not per-step outcomes.
    #[arg(long)]
    summary_only: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let src = if args.trace == "-" {
        std::io::read_to_string(std::io::stdin()).context("reading trace from stdin")?
    } else {
        std::fs::read_to_string(&args.trace)
            .with_context(|| format!("reading trace {}", args.trace))?
    };

    let steps = nucleus_flow_replay::parse_trace(&src)?;
    // An empty trace must not report a clean bill of health: a summary of zero
    // steps is indistinguishable from "nothing was refused" unless it fails.
    anyhow::ensure!(!steps.is_empty(), "trace is empty — nothing to replay");

    let (outcomes, summary) = nucleus_flow_replay::replay(&steps);

    let mut sink: Box<dyn Write> = match &args.out {
        Some(p) => Box::new(std::fs::File::create(p).with_context(|| format!("creating {p:?}"))?),
        None => Box::new(std::io::stdout()),
    };

    if !args.summary_only {
        for o in &outcomes {
            writeln!(sink, "{}", serde_json::to_string(o)?)?;
        }
    }
    writeln!(sink, "{}", serde_json::to_string(&summary)?)?;
    sink.flush()?;

    eprintln!(
        "replayed {} steps: {} allowed, {} denied, {} requires-approval; \
         {} denial(s) charged to the session ceiling",
        summary.steps,
        summary.allowed,
        summary.denied,
        summary.requires_approval,
        summary.ceiling_attributable,
    );
    Ok(())
}
