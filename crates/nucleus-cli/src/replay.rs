//! Replay command — reconstruct and display kernel decision traces.
//!
//! Reads JSONL trace files produced by `nucleus run --kernel-trace` or
//! `nucleus shell --kernel-trace` and renders the decision history for
//! audit and debugging.
//!
//! Each line in the trace is a serialized `portcullis::kernel::Decision`
//! with verdict, operation, subject, exposure transitions, and flow node IDs.

use anyhow::{Context, Result};
use clap::Args;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use portcullis::kernel::{Decision, DenyReason, Verdict};

/// Replay a kernel decision trace for audit.
#[derive(Args, Debug)]
pub struct ReplayArgs {
    /// Path to JSONL trace file (from --kernel-trace).
    pub trace_file: PathBuf,

    /// Only show denied decisions.
    #[arg(long)]
    pub denied_only: bool,

    /// Only show decisions with flow violations.
    #[arg(long)]
    pub flow_only: bool,

    /// Output as JSON instead of human-readable.
    #[arg(long)]
    pub json: bool,

    /// Show exposure transitions.
    #[arg(long)]
    pub exposure: bool,

    /// Verify decision chain integrity (monotonic sequence numbers).
    #[arg(long)]
    pub verify: bool,
}

pub fn execute(args: ReplayArgs) -> Result<()> {
    let file = fs::File::open(&args.trace_file)
        .with_context(|| format!("failed to open trace: {}", args.trace_file.display()))?;
    let reader = BufReader::new(file);

    let mut decisions: Vec<Decision> = Vec::new();
    let mut parse_errors = 0u64;
    let mut summary_lines = 0u64;

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read error at line {}", line_num + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Session summary lines are JSON objects with "type" field
        if trimmed.contains("\"type\":\"session_summary\"")
            || trimmed.contains("\"type\": \"session_summary\"")
        {
            summary_lines += 1;
            continue;
        }

        match serde_json::from_str::<Decision>(trimmed) {
            Ok(decision) => decisions.push(decision),
            Err(_) => {
                parse_errors += 1;
            }
        }
    }

    if decisions.is_empty() {
        eprintln!("No decisions found in {}", args.trace_file.display());
        if parse_errors > 0 {
            eprintln!("  ({parse_errors} unparseable lines)");
        }
        return Ok(());
    }

    // Verify chain integrity
    if args.verify {
        verify_chain(&decisions)?;
    }

    // Filter
    let filtered: Vec<&Decision> = decisions
        .iter()
        .filter(|d| {
            if args.denied_only && !d.verdict.is_denied() {
                return false;
            }
            if args.flow_only
                && !matches!(d.verdict, Verdict::Deny(DenyReason::FlowViolation { .. }))
            {
                return false;
            }
            true
        })
        .collect();

    if args.json {
        for d in &filtered {
            println!("{}", serde_json::to_string(d).unwrap_or_default());
        }
    } else {
        render_text(&filtered, args.exposure);
    }

    // Stats
    let total = decisions.len();
    let allowed = decisions.iter().filter(|d| d.verdict.is_allowed()).count();
    let denied = decisions.iter().filter(|d| d.verdict.is_denied()).count();
    let approvals = decisions
        .iter()
        .filter(|d| matches!(d.verdict, Verdict::RequiresApproval))
        .count();
    let flow_violations = decisions
        .iter()
        .filter(|d| matches!(d.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })))
        .count();

    eprintln!();
    eprintln!("--- Trace Summary ---");
    eprintln!("  File: {}", args.trace_file.display());
    eprintln!(
        "  Decisions: {total} ({allowed} allowed, {denied} denied, {approvals} approval-required)"
    );
    if flow_violations > 0 {
        eprintln!("  Flow violations: {flow_violations}");
    }
    if summary_lines > 0 {
        eprintln!("  Sessions: {summary_lines}");
    }
    if parse_errors > 0 {
        eprintln!("  Parse errors: {parse_errors}");
    }
    if filtered.len() != decisions.len() {
        eprintln!("  Showing: {} of {} (filtered)", filtered.len(), total);
    }

    Ok(())
}

fn verify_chain(decisions: &[Decision]) -> Result<()> {
    let mut last_seq = None;

    for (i, d) in decisions.iter().enumerate() {
        if let Some(prev) = last_seq {
            if d.sequence <= prev {
                eprintln!(
                    "INTEGRITY ERROR: decision {} has sequence {} but previous was {} (non-monotonic)",
                    i, d.sequence, prev
                );
                anyhow::bail!("chain integrity violation at decision {i}");
            }
        }
        last_seq = Some(d.sequence);
    }

    eprintln!(
        "Chain integrity: OK ({} decisions, sequences monotonic)",
        decisions.len()
    );
    Ok(())
}

fn render_text(decisions: &[&Decision], show_exposure: bool) {
    for d in decisions {
        let icon = match &d.verdict {
            Verdict::Allow => "\u{2713}", // checkmark
            Verdict::RequiresApproval => "?",
            Verdict::Deny(_) => "X",
        };

        let flow = d
            .flow_node_id
            .map(|id| format!(" [flow:{id}]"))
            .unwrap_or_default();

        print!(
            "[{:>4}] {icon} {:?} {}{flow}",
            d.sequence, d.operation, d.subject
        );

        match &d.verdict {
            Verdict::Allow => println!(),
            Verdict::RequiresApproval => println!(" (requires approval)"),
            Verdict::Deny(reason) => match reason {
                DenyReason::FlowViolation { rule, receipt } => {
                    println!(" DENIED: flow:{rule}");
                    if let Some(receipt_text) = receipt {
                        for line in receipt_text.lines() {
                            println!("        {line}");
                        }
                    }
                }
                other => println!(" DENIED: {other:?}"),
            },
        }

        if show_exposure {
            let t = &d.exposure_transition;
            if t.pre_count != t.post_count || t.state_uninhabitable {
                print!("        exposure: {}/3 -> {}/3", t.pre_count, t.post_count);
                if t.state_uninhabitable {
                    print!(" UNINHABITABLE");
                }
                if t.dynamic_gate_applied {
                    print!(" (dynamic gate)");
                }
                println!();
            }
        }
    }
}
