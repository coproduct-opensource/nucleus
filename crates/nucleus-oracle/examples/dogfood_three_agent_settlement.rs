//! Dogfood, round 2: a **3-agent** coalition with an *unequal* Shapley split.
//!
//! Three real LLM agents added `PortfolioSummary::merge` to this crate:
//! * **S** (functional tests) — `tests/merge_func.rs` (13 example-based tests),
//! * **I** (implementer)      — `merge` in `src/summary.rs` (spec only),
//! * **R** (property tests)   — `tests/merge_prop.rs` (6 algebraic-law tests:
//!   the metamorphic `summarize(a++b) == summarize(a).merge(summarize(b))`,
//!   commutativity, associativity, identity).
//!
//! Each suite was graded against I's implementation: **S 13/13, R 6/6** — both
//! confer load-bearing credit independently, so they are *substitute verifiers*.
//! I is a **veto player**: nothing has value without the implementation. That
//! structure makes the fair (Shapley) split UNEQUAL even though every productive
//! coalition has the same value — the irreplaceable producer earns ~2/3, the two
//! redundant verifiers ~1/6 each.
//!
//! Run: `cargo run -p nucleus-oracle --example dogfood_three_agent_settlement`

use nucleus_creditworthiness::{CreditEvent, CreditFile};
use nucleus_eval::EvalCase;
use nucleus_oracle::{
    grade, grade_rubric_inputs, DeterminismPinning, GradingBundle, HeldOutRecompute,
    MutationAdequacy,
};

/// Exact Shapley value for an `n`-player game over coalitions encoded as
/// bitmasks, apportioned to whole µUSD that sum EXACTLY to `v(N)` (no money lost
/// to integer rounding) via the largest-remainder method. Mirrors
/// `axelrod-equilibrium::shapley_value`; inlined so this public example takes no
/// cross-repo dependency.
fn shapley(n: usize, value: impl Fn(u32) -> u64) -> Vec<u64> {
    fn fact(k: usize) -> u128 {
        (1..=k as u128).product::<u128>().max(1)
    }
    let nfact = fact(n);
    // Exact rational numerators φ_i = acc_i / nfact.
    let mut acc = vec![0u128; n];
    for (i, a) in acc.iter_mut().enumerate() {
        for s in 0u32..(1 << n) {
            if s & (1 << i) != 0 {
                continue;
            }
            let size = s.count_ones() as usize;
            let weight = fact(size) * fact(n - size - 1);
            let marginal = value(s | (1 << i)).saturating_sub(value(s)) as u128;
            *a += weight * marginal;
        }
    }
    let mut floors: Vec<u64> = acc.iter().map(|a| (a / nfact) as u64).collect();
    // Distribute the rounding remainder to the largest fractional parts (ties →
    // lowest index), so Σ floors == v(N) exactly (the efficiency axiom holds).
    let grand = value((1 << n) - 1);
    let mut dust = grand.saturating_sub(floors.iter().sum());
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&i, &j| (acc[j] % nfact).cmp(&(acc[i] % nfact)).then(i.cmp(&j)));
    let mut k = 0;
    while dust > 0 && n > 0 {
        floors[order[k % n]] += 1;
        dust -= 1;
        k += 1;
    }
    floors
}

/// Grade a coalition's combined held-out suite through the SHIPPED oracle and
/// return the load-bearing credit it mints (0 if it mints none).
fn coalition_value(passed: u64, total: u64, magnitude: u64) -> u64 {
    if total == 0 {
        return 0; // no held-out tests present → unverifiable → no load-bearing credit
    }
    let cases: Vec<EvalCase> = (0..total)
        .map(|i| EvalCase {
            case_id: format!("merge::{i}"),
            produced: if i < passed { "pass" } else { "fail" }.into(),
            expected: "pass".into(),
        })
        .collect();
    let bundle = GradingBundle {
        submission_id: "coalition/merge".into(),
        held_out: HeldOutRecompute { cases },
        metamorphic: vec![],
        determinism: DeterminismPinning {
            run_result_hashes: vec!["det".into(), "det".into(), "det".into()],
            k: 2,
        },
        mutation: MutationAdequacy { mutants: vec![] },
        held_out_expected_leaked: false,
    };
    let receipt = grade(&bundle);
    if !grade_rubric_inputs(&receipt, 10, 7).mints_load_bearing() {
        return 0;
    }
    // Load-bearing credit = magnitude scaled by the recomputed pass-rate.
    magnitude * receipt.exact_pass.matched / receipt.exact_pass.total
}

fn main() {
    // Players: bit 0 = S (functional tests), 1 = I (impl), 2 = R (property tests).
    const S: u32 = 1 << 0;
    const I: u32 = 1 << 1;
    const R: u32 = 1 << 2;
    const MAGNITUDE: u64 = 1_000_000; // $1.00 declared for this gap

    // REAL per-suite grades from this round (cargo test, 3× deterministic):
    let (s_pass, s_total) = (13u64, 13u64); // tests/merge_func.rs
    let (r_pass, r_total) = (6u64, 6u64); // tests/merge_prop.rs

    // Value function: a coalition delivers verifiable value iff it contains I
    // (the impl) AND at least one held-out suite (S or R). Its value is graded
    // through the oracle over whichever suites are present.
    let value = |mask: u32| -> u64 {
        if mask & I == 0 {
            return 0; // no implementation → nothing to verify
        }
        let mut passed = 0;
        let mut total = 0;
        if mask & S != 0 {
            passed += s_pass;
            total += s_total;
        }
        if mask & R != 0 {
            passed += r_pass;
            total += r_total;
        }
        coalition_value(passed, total, MAGNITUDE)
    };

    println!("=== coalition value function (graded by the shipped oracle) ===");
    for (name, m) in [
        ("{S,I}", S | I),
        ("{I,R}", I | R),
        ("{S,I,R}", S | I | R),
        ("{I} only", I),
        ("{S,R} (no impl)", S | R),
    ] {
        println!("  v({name:16}) = {} µUSD", value(m));
    }

    let phi = shapley(3, value); // [φ_S, φ_I, φ_R]
    let total: u64 = phi.iter().sum();
    println!("\n=== Shapley split of {MAGNITUDE} µUSD (UNEQUAL by structure) ===");
    println!(
        "  φ(I, implementer / veto player) = {} µUSD  (~2/3)",
        phi[1]
    );
    println!(
        "  φ(S, functional tests / substitute) = {} µUSD  (~1/6)",
        phi[0]
    );
    println!(
        "  φ(R, property tests / substitute)   = {} µUSD  (~1/6)",
        phi[2]
    );
    assert_eq!(
        total,
        value(S | I | R),
        "Shapley is budget-balanced (efficiency)"
    );
    assert!(
        phi[1] > phi[0] && phi[1] > phi[2],
        "the veto implementer earns strictly more"
    );
    // S and R have equal EXACT Shapley value (M/6); they agree up to the ≤1 µUSD
    // integer-apportionment dust the largest-remainder method must place somewhere.
    assert!(
        (phi[0] as i64 - phi[2] as i64).abs() <= 1,
        "substitute verifiers symmetric up to rounding"
    );

    // Mint durable CreditEvents — each agent's share, bound to the grade receipt.
    let receipt_hash = grade(&GradingBundle {
        submission_id: "coalition/merge/full".into(),
        held_out: HeldOutRecompute {
            cases: (0..(s_total + r_total))
                .map(|i| EvalCase {
                    case_id: format!("merge::full::{i}"),
                    produced: "pass".into(),
                    expected: "pass".into(),
                })
                .collect(),
        },
        metamorphic: vec![],
        determinism: DeterminismPinning {
            run_result_hashes: vec!["det".into(), "det".into(), "det".into()],
            k: 2,
        },
        mutation: MutationAdequacy { mutants: vec![] },
        held_out_expected_leaked: false,
    })
    .receipt_hash();

    println!("\n=== durable reputation (nucleus-creditworthiness) ===");
    let max_gain = 2_000_000;
    for (who, share) in [
        ("S (func)", phi[0]),
        ("I (impl)", phi[1]),
        ("R (prop)", phi[2]),
    ] {
        let mut f = CreditFile::new();
        f.observe(&CreditEvent::honest_settlement(share, receipt_hash));
        println!(
            "  {who:10} reputation = {:>7} µUSD   required_bond = {:>7} µUSD",
            f.reputation_micro(),
            f.required_bond(max_gain).0
        );
    }
    println!(
        "\nUnequal, and fair: the implementer is irreplaceable (every productive\n\
         coalition needs it); the two verifiers are substitutes (either suffices),\n\
         so they split a verifier's share. The split falls out of the structure —\n\
         no weights were chosen by hand."
    );
}
