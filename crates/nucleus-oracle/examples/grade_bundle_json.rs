//! Grade one or more RECORDED submissions, each a JSON-serialized [`GradingBundle`],
//! through the held-out oracle. Prints the receipt + the honest rubric provenance
//! it mints for each, so a third party can re-run the exact grade from the same
//! recorded bytes.
//!
//! This is the vendor-neutral driver used by the adversarial pressure-test
//! (`docs/oracle-adversarial-pressure-test.md`): solver programs are run on
//! held-out inputs elsewhere, their produced-vs-expected outputs recorded into a
//! bundle, and graded here. The oracle never executes anything — it grades
//! recorded bytes.
//!
//! Run: `cargo run -p nucleus-oracle --example grade_bundle_json -- bundle1.json [bundle2.json ...]`

use nucleus_oracle::{grade, grade_rubric_inputs, GradingBundle};
use std::process::ExitCode;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: grade_bundle_json <bundle.json> [more.json ...]");
        return ExitCode::FAILURE;
    }

    for path in &paths {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{path}: read error: {e}");
                return ExitCode::FAILURE;
            }
        };
        let bundle: GradingBundle = match serde_json::from_str(&raw) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{path}: parse error: {e}");
                return ExitCode::FAILURE;
            }
        };

        let receipt = grade(&bundle);
        let inputs = grade_rubric_inputs(&receipt, 10, 7);

        println!("=== {} ===", receipt.submission_id);
        println!(
            "  exact held-out pass (DEDUCTIVE, load-bearing): {}/{}",
            receipt.exact_pass.matched, receipt.exact_pass.total
        );
        println!(
            "  MR coverage (STATISTICAL, carried/inert):      {}/{}",
            receipt.mr.matched, receipt.mr.total
        );
        println!(
            "  mutation kill (STATISTICAL, carried/inert):    {}/{}",
            receipt.mutation.matched, receipt.mutation.total
        );
        println!(
            "  k-of-n determinism-pinning (gate, not consensus): agree={} n={} k={} pinned={}",
            receipt.k_of_n.agree, receipt.k_of_n.n, receipt.k_of_n.k, receipt.k_of_n.pinned
        );
        match &receipt.quarantine {
            Some(reason) => println!("  -> QUARANTINED: {reason}"),
            None => println!("  -> quarantine: none"),
        }
        println!(
            "  -> mints load-bearing credit: {}",
            inputs.mints_load_bearing()
        );
        println!("  receipt hash: {}", receipt.receipt_hash_hex());
        println!();
    }

    ExitCode::SUCCESS
}
