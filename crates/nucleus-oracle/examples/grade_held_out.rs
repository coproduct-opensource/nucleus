//! Grade a recorded submission with the held-out oracle and print the receipt +
//! the honest rubric provenance it mints.
//!
//! Run: `cargo run -p nucleus-oracle --example grade_held_out`

use nucleus_eval::EvalCase;
use nucleus_oracle::{
    grade, grade_rubric_inputs, DeterminismPinning, GradingBundle, HeldOutRecompute,
    MetamorphicCheck, MetamorphicRelation, MutantOutcome, MutationAdequacy,
};

fn held_out_case(id: &str, produced: &str, expected: &str) -> EvalCase {
    EvalCase {
        case_id: id.into(),
        produced: produced.into(),
        expected: expected.into(),
    }
}

fn main() {
    // A recorded submission: 4 of 5 held-out cases pass by byte-equality.
    let bundle = GradingBundle {
        submission_id: "solver-demo".into(),
        held_out: HeldOutRecompute {
            cases: vec![
                held_out_case("h0", "42", "42"),
                held_out_case("h1", "7", "7"),
                held_out_case("h2", "100", "100"),
                held_out_case("h3", "WRONG", "13"),
                held_out_case("h4", "0", "0"),
            ],
        },
        // Two metamorphic checks; one holds, one fails. Coverage is reported but
        // never moves the load-bearing grade.
        metamorphic: vec![
            MetamorphicCheck {
                id: "mr-identity".into(),
                source_output: "42".into(),
                perturbed_output: "42".into(),
                relation: MetamorphicRelation::Equal,
            },
            MetamorphicCheck {
                id: "mr-negate".into(),
                source_output: "7".into(),
                perturbed_output: "8".into(),
                relation: MetamorphicRelation::ExpectedTransform {
                    expected: "-7".into(),
                },
            },
        ],
        // Three re-runs all produced the same result hash → determinism pinned.
        determinism: DeterminismPinning {
            run_result_hashes: vec!["deadbeef".into(), "deadbeef".into(), "deadbeef".into()],
            k: 2,
        },
        // The held-out suite kills 3 of 4 injected mutants → it has teeth.
        mutation: MutationAdequacy {
            mutants: vec![
                MutantOutcome {
                    id: "m0".into(),
                    killed: true,
                },
                MutantOutcome {
                    id: "m1".into(),
                    killed: true,
                },
                MutantOutcome {
                    id: "m2".into(),
                    killed: true,
                },
                MutantOutcome {
                    id: "m3".into(),
                    killed: false,
                },
            ],
        },
        held_out_expected_leaked: false,
    };

    let receipt = grade(&bundle);

    println!("=== GradeReceipt for {} ===", receipt.submission_id);
    println!(
        "  exact held-out pass (LOAD-BEARING): {}/{}",
        receipt.exact_pass.matched, receipt.exact_pass.total
    );
    println!(
        "  MR coverage (statistical, carried): {}/{}",
        receipt.mr.matched, receipt.mr.total
    );
    println!(
        "  k-of-n determinism-pinning (gate):  agree={} n={} k={} pinned={}",
        receipt.k_of_n.agree, receipt.k_of_n.n, receipt.k_of_n.k, receipt.k_of_n.pinned
    );
    println!(
        "  mutation kill (statistical, carried): {}/{}",
        receipt.mutation.matched, receipt.mutation.total
    );
    match &receipt.quarantine {
        Some(reason) => println!("  QUARANTINED: {reason}"),
        None => println!("  quarantine: none"),
    }
    println!("  receipt hash: {}", receipt.receipt_hash_hex());

    println!("\n=== Rubric inputs (honest provenance) ===");
    let inputs = grade_rubric_inputs(&receipt, 10, 7);
    for d in inputs.dimensions() {
        let lb = if d.criterion.provenance.is_load_bearing() {
            "LOAD-BEARING"
        } else {
            "carried/inert"
        };
        println!(
            "  {:<22} grade={:<3} provenance={:?} ({lb})",
            d.criterion.id, d.grade, d.criterion.provenance
        );
    }
    println!(
        "  mints load-bearing credit: {}",
        inputs.mints_load_bearing()
    );
}
