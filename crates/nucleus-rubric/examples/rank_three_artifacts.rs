//! `cargo run -p nucleus-rubric --example rank_three_artifacts`
//!
//! Demonstrates the whole kernel end-to-end on three artifacts over a fixed
//! 5-criterion rubric (3 RecomputeVerified, 1 Attested, 1 AttestationOnly):
//!   1. the FAITHFUL RANK (RV columns only — Attested/AttestationOnly are inert),
//!   2. the PARETO FRONT over the RV product-poset,
//!   3. the WINNER selected by weighted-sum scalarization (proven to be on the front),
//!   4. the recomputable VCG-MARGINAL (winner − runner_up) + a byte-identical recompute,
//!   5. the minted real CreditEvent + resulting CreditFile reputation.

use nucleus_creditworthiness::CreditFile;
use nucleus_rubric::{
    counterfactual, faithful_total, pareto_front, rank, winner, Criterion, Provenance, Rubric,
    Scorecard,
};

fn main() {
    // A fixed rubric: 3 RV criteria (load-bearing), 1 Attested, 1 AttestationOnly.
    let rubric = Rubric::new(vec![
        Criterion {
            id: "correctness".into(),
            provenance: Provenance::RecomputeVerified,
            weight: 5,
            max_grade: 10,
        },
        Criterion {
            id: "coverage".into(),
            provenance: Provenance::RecomputeVerified,
            weight: 3,
            max_grade: 10,
        },
        Criterion {
            id: "determinism".into(),
            provenance: Provenance::RecomputeVerified,
            weight: 2,
            max_grade: 10,
        },
        Criterion {
            id: "cost".into(),
            provenance: Provenance::Attested, // carried, inert
            weight: 7,
            max_grade: 10,
        },
        Criterion {
            id: "llm_judge".into(),
            provenance: Provenance::AttestationOnly, // carried, inert
            weight: 9,
            max_grade: 100,
        },
    ])
    .expect("valid rubric");

    // Grades aligned to [correctness, coverage, determinism, cost, llm_judge].
    // A: high correctness, low coverage.
    // B: balanced, strong RV profile.
    // C: dominated on EVERY RV axis, but with a maxed-out judge AND best cost.
    let artifacts = vec![
        Scorecard {
            artifact_id: "A".into(),
            grades: vec![9, 2, 5, 5, 50],
        },
        Scorecard {
            artifact_id: "B".into(),
            grades: vec![6, 8, 7, 5, 50],
        },
        Scorecard {
            artifact_id: "C".into(),
            grades: vec![3, 1, 2, 10, 100],
        },
    ];
    rubric.validate_all(&artifacts).expect("valid scorecards");

    println!("== Rubric (RV columns are load-bearing) ==");
    for (i, c) in rubric.criteria.iter().enumerate() {
        let tier = if c.provenance.is_load_bearing() {
            "RV  (load-bearing)"
        } else {
            "    (carried/inert)"
        };
        println!(
            "  [{i}] {:<12} w={} max={:<3} {:?} {tier}",
            c.id, c.weight, c.max_grade, c.provenance
        );
    }

    println!("\n== (1) Faithful rank (RV-only weighted cardinal total) ==");
    for r in rank(&rubric, &artifacts) {
        println!(
            "  #{}  {}  faithful_total = {}",
            r.position, r.artifact_id, r.faithful_total
        );
    }
    println!(
        "  → C is LAST despite its perfect judge (100) and best cost (10): \
         AttestationOnly + Attested dims are inert."
    );

    println!("\n== (2) Pareto front over the RV product-poset ==");
    let front = pareto_front(&rubric, &artifacts);
    for &i in &front {
        println!(
            "  in front: {}  rv_total = {}",
            artifacts[i].artifact_id,
            faithful_total(&rubric, &artifacts[i])
        );
    }
    println!("  → A and B are incomparable (both retained); C is strictly dominated (excluded).");

    println!("\n== (3) Winner by weighted-sum scalarization ==");
    let w = winner(&rubric, &artifacts).expect("non-empty");
    println!("  winner = {}", artifacts[w].artifact_id);
    assert!(
        front.contains(&w),
        "scalarized winner must be a Pareto-front member"
    );
    println!("  assertion OK: winner ∈ Pareto front (positive RV weights ⇒ Pareto-optimal).");

    println!("\n== (4) Recomputable VCG-marginal (winner − runner_up) ==");
    let receipt = counterfactual(&rubric, &artifacts).expect(">= 2 artifacts");
    println!(
        "  winner   {} total = {}",
        receipt.winner_id, receipt.winner_total
    );
    println!(
        "  runnerup {} total = {}",
        receipt.runner_up_id, receipt.runner_up_total
    );
    println!("  marginal = {}", receipt.marginal);
    println!("  receipt_hash = {}", receipt.receipt_hash_hex());
    // Independent recompute from the receipt's recorded inputs.
    let (wt, rt, m) = receipt.recompute_marginal();
    println!(
        "  independent recompute → winner_total={wt} runner_up_total={rt} marginal={m} \
         (byte-identical: {})",
        m == receipt.marginal && wt == receipt.winner_total && rt == receipt.runner_up_total
    );

    println!("\n== (5) Minted reward (real CreditEvent → CreditFile) ==");
    let event = receipt.mint_reward();
    println!(
        "  CreditEvent {{ dimension: {:?}, polarity: {:?}, weight_micro: {} }}",
        event.dimension, event.polarity, event.weight_micro
    );
    let file = CreditFile::from_events(&[event]);
    println!(
        "  CreditFile reputation_micro = {}",
        file.reputation_micro()
    );
}
