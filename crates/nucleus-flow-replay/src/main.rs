//! Replay a recorded tool-call trace through the real kernel decision path.
//!
//! ```text
//! nucleus-flow-replay --trace episode.jsonl --out outcomes.jsonl
//! ```
//!
//! Reads JSONL steps, emits one outcome per step plus a summary on stderr.
//! Needs no network, no model, and no API budget — the whole point is that the
//! kernel's behaviour is measurable without any of them.
//!
//! ```text
//! nucleus-flow-replay --frontier-corpus corpus.jsonl [--profiles a,b] --out frontier.json
//! ```
//!
//! The frontier mode replays a corpus (one episode per line) under each named
//! canonical profile's REAL lattice and writes `frontier.json`: the share of
//! the corpus each authorization lets through, beside the guards that stop
//! that share from being gamed. `scripts/exemplar-scoreboard.sh` embeds it and
//! `cargo xtask scoreboard-ratchet` pins it in both directions.

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
    #[arg(
        long,
        conflicts_with = "frontier_corpus",
        required_unless_present = "frontier_corpus"
    )]
    trace: Option<String>,

    /// Frontier mode: a corpus (one `{"trace": n, "steps": [...]}` episode per
    /// line) replayed under each canonical profile's lattice.
    #[arg(long, value_name = "CORPUS")]
    frontier_corpus: Option<PathBuf>,

    /// Frontier mode: comma-separated canonical profile names (default: all).
    #[arg(long, value_delimiter = ',')]
    profiles: Vec<String>,

    /// Write per-step outcomes here as JSONL (default: stdout).
    #[arg(long)]
    out: Option<PathBuf>,

    /// Emit only the summary object, not per-step outcomes.
    #[arg(long)]
    summary_only: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(corpus_path) = &args.frontier_corpus {
        return frontier_main(corpus_path, &args.profiles, args.out.as_deref());
    }
    let trace = args.trace.as_deref().unwrap_or("-");

    let src = if trace == "-" {
        std::io::read_to_string(std::io::stdin()).context("reading trace from stdin")?
    } else {
        std::fs::read_to_string(trace).with_context(|| format!("reading trace {trace}"))?
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

/// Frontier mode. Every canonical profile resolves through the same
/// `ProfileRegistry` the CLI uses, so the lattice replayed is the one a pod
/// launched with that profile would enforce.
fn frontier_main(
    corpus_path: &std::path::Path,
    profiles: &[String],
    out: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let src = std::fs::read_to_string(corpus_path)
        .with_context(|| format!("reading corpus {}", corpus_path.display()))?;
    let corpus = nucleus_flow_replay::parse_corpus(&src)?;
    anyhow::ensure!(!corpus.is_empty(), "corpus is empty — nothing to replay");

    let registry =
        portcullis::profile::ProfileRegistry::canonical().context("loading canonical profiles")?;
    let names: Vec<String> = if profiles.is_empty() {
        registry.names().into_iter().map(str::to_string).collect()
    } else {
        profiles.to_vec()
    };
    let mut lattices = Vec::with_capacity(names.len());
    for name in &names {
        let lattice = registry
            .resolve(name)
            .map_err(|e| anyhow::anyhow!("profile {name:?}: {e}"))?;
        lattices.push((name.clone(), lattice));
    }

    let report = nucleus_flow_replay::frontier(&corpus, &lattices);
    let json = serde_json::to_string_pretty(&report)?;
    match out {
        Some(p) => std::fs::write(p, format!("{json}\n"))
            .with_context(|| format!("writing {}", p.display()))?,
        None => println!("{json}"),
    }
    eprintln!(
        "frontier: {} episodes / {} steps under {} profile(s)",
        report.corpus_traces,
        report.corpus_steps,
        report.profiles.len()
    );
    for (name, f) in &report.profiles {
        eprintln!(
            "  {name:<16} allowed {:>4}‰  denied {:>3} (exfil {:>3}, local {:>3})  approval {:>3}",
            f.allowed_share_permille,
            f.denied,
            f.denied_at_exfil_vector,
            f.denied_at_local_reversible,
            f.requires_approval
        );
    }
    Ok(())
}
