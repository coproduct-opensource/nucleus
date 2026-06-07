//! Mint real `CreditEvent`s from a small batch of eval receipts, fold them into a
//! `nucleus_creditworthiness::CreditFile`, and print its `reputation_micro()` and
//! a `required_bond`.
//!
//! Run with: `cargo run -p nucleus-eval --example eval_to_credit`

use nucleus_creditworthiness::Polarity;
use nucleus_eval::{
    credit_file_from_runs, mint_event, receipt_hash_hex, Attested, DeterministicCheck, EvalCase,
    EvalRun,
};

/// Build a run whose recorded cases genuinely yield `produced_passes` of `total`,
/// with the agent's claimed counts set explicitly (so we can demo an overclaim).
fn make_run(
    agent_id: &str,
    task_id: &str,
    produced_passes: u64,
    total: u64,
    claimed_passed: u64,
    declared_magnitude_micro: u64,
) -> EvalRun {
    let cases = (0..total)
        .map(|i| {
            let pass = i < produced_passes;
            EvalCase {
                case_id: format!("case-{i}"),
                produced: if pass { "ok".into() } else { "WRONG".into() },
                expected: "ok".into(),
            }
        })
        .collect();
    EvalRun {
        agent_id: agent_id.into(),
        task_id: task_id.into(),
        // ATTESTED (carried, not recomputed) — do not affect the mint.
        cost_micro_usd: 12_345,
        tokens: 8_192,
        latency_ms: 430,
        deterministic: DeterministicCheck {
            cases,
            claimed_passed,
            claimed_total: total,
        },
        attested: Attested {
            llm_judge_score: Some(88),
        },
        declared_magnitude_micro,
    }
}

fn main() {
    // A small batch: a full pass, an honest partial, and an overclaim (the lie).
    let runs = vec![
        make_run("agent-a", "swe-bench", 10, 10, 10, 1_000_000), // honest full  → +1_000_000
        make_run("agent-a", "humaneval", 7, 10, 7, 1_000_000),   // honest 7/10  →   +700_000
        make_run("agent-a", "claims-12", 4, 10, 10, 1_000_000),  // OVERCLAIM    → −1_000_000 debit
    ];

    println!("Minting CreditEvents from {} eval receipts:\n", runs.len());
    for run in &runs {
        let e = mint_event(run);
        let (passed, total) = run.deterministic.recompute();
        let verdict = match e.polarity {
            Polarity::Credit => "CREDIT",
            Polarity::Debit => "DEBIT (caught defection)",
        };
        println!(
            "  {:<10} {:<10}  recomputed {}/{}  claimed {}/{}  → {:<24} weight={} micro-USD",
            run.agent_id,
            run.task_id,
            passed,
            total,
            run.deterministic.claimed_passed,
            run.deterministic.claimed_total,
            verdict,
            e.weight_micro,
        );
        println!("             receipt_hash = {}", receipt_hash_hex(run));
    }

    let file = credit_file_from_runs(&runs);
    let reputation = file.reputation_micro();
    println!("\nFolded into a real CreditFile:");
    println!("  events           = {}", runs.len());
    println!("  reputation_micro = {reputation} micro-USD");
    // What bond would still be required to deter a 2_000_000 micro-USD defection,
    // given the reputation accrued (composes the proven required_bond kernel).
    let bond = file.required_bond(2_000_000);
    println!("  required_bond(2_000_000 gain) = {} micro-USD", bond.0);

    // And the honest-only subset, to show the overclaim genuinely cost standing.
    let honest_only = credit_file_from_runs(&runs[..2]);
    println!(
        "\n  (honest receipts only) reputation_micro = {} micro-USD",
        honest_only.reputation_micro()
    );
}
