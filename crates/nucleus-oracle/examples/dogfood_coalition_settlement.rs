//! Dogfood: settle a two-agent COALITION through the verified loop, end to end.
//!
//! This is the proof→reputation flywheel run on ourselves (see
//! `docs/dogfood-coalition.md`). Two real LLM agents formed a coalition to add
//! the `summarize` rollup to this crate:
//!
//! * **Agent S** (test author) wrote the held-out suite `tests/summarize_heldout.rs`.
//! * **Agent I** (implementer) wrote `src/summary.rs` from the spec ALONE,
//!   never seeing S's tests.
//!
//! The oracle's own rule — solver ≠ test-author — is what *forces* the
//! collaboration: an implementation with no independent held-out tests is
//! unverifiable (no load-bearing credit), and a test suite with no
//! implementation delivers nothing. So neither agent's output is creditworthy
//! alone; the value exists only in the coalition, and Shapley splits it.
//!
//! Run: `cargo run -p nucleus-oracle --example dogfood_coalition_settlement`

use nucleus_creditworthiness::{CreditEvent, CreditFile};
use nucleus_eval::EvalCase;
use nucleus_oracle::{
    grade, grade_rubric_inputs, DeterminismPinning, GradingBundle, HeldOutRecompute,
    MutationAdequacy,
};

/// Exact Shapley value for an `n`-player game given a value function over
/// coalitions encoded as bitmasks. Mirrors `axelrod-equilibrium::shapley_value`
/// (the production primitive); inlined here so this public example takes no
/// cross-repo dependency. For our 2-player coalition it returns the fair split.
fn shapley(n: usize, value: impl Fn(u32) -> u64) -> Vec<u64> {
    // Σ over permutations of (v(prefix∪{i}) − v(prefix)) / n!  — computed exactly
    // as integer micro-USD via the marginal-over-subsets form:
    // φ_i = Σ_{S⊆N\{i}} |S|!(n-|S|-1)!/n! · (v(S∪{i}) − v(S)).
    fn fact(k: usize) -> u128 {
        (1..=k as u128).product::<u128>().max(1)
    }
    let nfact = fact(n);
    let mut phi = vec![0u128; n];
    for (i, slot) in phi.iter_mut().enumerate() {
        let mut acc = 0u128;
        for s in 0u32..(1 << n) {
            if s & (1 << i) != 0 {
                continue; // S must exclude i
            }
            let size = (s.count_ones()) as usize;
            let weight = fact(size) * fact(n - size - 1); // numerator; /n! at the end
            let marginal = value(s | (1 << i)).saturating_sub(value(s)) as u128;
            acc += weight * marginal;
        }
        *slot = acc / nfact;
    }
    phi.into_iter()
        .map(|x| x.min(u128::from(u64::MAX)) as u64)
        .collect()
}

fn main() {
    // ── 1. The coalition's submission, graded through the REAL oracle ──────────
    // Agent I's `summarize` was run against Agent S's 20 held-out tests: 20/20
    // pass, byte-identical across 3 re-runs (determinism pinned). We encode that
    // recorded outcome as a GradingBundle and grade it with the shipped oracle.
    const HELD_OUT: u64 = 20;
    let cases: Vec<EvalCase> = (0..HELD_OUT)
        .map(|i| EvalCase {
            case_id: format!("summarize_heldout::{i}"),
            produced: "pass".into(),
            expected: "pass".into(),
        })
        .collect();
    let bundle = GradingBundle {
        submission_id: "coalition:S+I/summarize".into(),
        held_out: HeldOutRecompute { cases },
        metamorphic: vec![],
        // 3 identical cargo-test result hashes → k-of-n determinism pinned.
        determinism: DeterminismPinning {
            run_result_hashes: vec!["20pass".into(), "20pass".into(), "20pass".into()],
            k: 2,
        },
        mutation: MutationAdequacy { mutants: vec![] },
        held_out_expected_leaked: false,
    };
    let receipt = grade(&bundle);
    let inputs = grade_rubric_inputs(&receipt, 10, 7);

    println!("=== coalition submission graded by the shipped oracle ===");
    println!(
        "  exact held-out pass (load-bearing): {}/{}",
        receipt.exact_pass.matched, receipt.exact_pass.total
    );
    println!(
        "  determinism pinned: {}  | quarantine: {:?}",
        receipt.k_of_n.pinned, receipt.quarantine
    );
    println!(
        "  mints load-bearing credit: {}",
        inputs.mints_load_bearing()
    );
    assert!(
        inputs.mints_load_bearing(),
        "verified work must mint credit"
    );

    // ── 2. Coalition value + Shapley split ────────────────────────────────────
    // Value of a coalition = the load-bearing credit it can produce, scaled by
    // the recomputed pass-rate. Players: 0 = S (tests), 1 = I (impl).
    //   v(∅)=0, v({S})=0 (tests, nothing delivered),
    //   v({I})=0 (impl, but UNVERIFIABLE without held-out tests → no LB credit),
    //   v({S,I}) = full magnitude × pass-rate.
    const MAGNITUDE_MICRO: u64 = 1_000_000; // $1.00, declared for this gap
    let full = MAGNITUDE_MICRO * receipt.exact_pass.matched / receipt.exact_pass.total;
    let value = |mask: u32| -> u64 {
        match mask {
            0b11 => full, // both S and I
            _ => 0,       // any sub-coalition delivers no verifiable value
        }
    };
    let split = shapley(2, value); // [φ_S, φ_I]
    let (phi_s, phi_i) = (split[0], split[1]);
    println!("\n=== Shapley split of {full} µUSD (both agents essential) ===");
    println!("  φ(S, tests) = {phi_s} µUSD");
    println!("  φ(I, impl)  = {phi_i} µUSD");
    assert_eq!(
        phi_s + phi_i,
        full,
        "Shapley is budget-balanced (efficiency)"
    );

    // ── 3. Mint durable CreditEvents into each agent's published CreditFile ────
    let receipt_hash = receipt.receipt_hash();
    let mut file_s = CreditFile::new();
    file_s.observe(&CreditEvent::honest_settlement(phi_s, receipt_hash));
    let mut file_i = CreditFile::new();
    file_i.observe(&CreditEvent::honest_settlement(phi_i, receipt_hash));

    // What standing buys: a lower required anti-grief bond (capital substitution).
    let max_gain = 2_000_000; // worst-case defection gain this round would protect
    println!("\n=== durable reputation (nucleus-creditworthiness) ===");
    for (who, f) in [("S (tests)", &file_s), ("I (impl)", &file_i)] {
        println!(
            "  {who:10}  reputation = {} µUSD   required_bond = {} µUSD",
            f.reputation_micro(),
            f.required_bond(max_gain).0
        );
    }
    println!(
        "\nreceipt hash (provenance): {}",
        receipt.receipt_hash_hex()
    );
    println!(
        "\nThe loop closed: verified work → Shapley-split credit → durable standing\n\
         → a smaller bond next round. Neither agent could have earned it alone."
    );
}
