// Iteration-10: integration tests are separate compilation units —
// the lib-root `#![deny(clippy::float_arithmetic)]` doesn't reach
// here. Apply explicitly so a future test that smuggles f64 via
// proptest fixture generation fails the build, not the wedge.
#![deny(clippy::float_arithmetic)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]

//! Property-based tests for the integer VCG kernel.
//!
//! Per the kernel's `src/vcg.rs` module docs, this is **greedy
//! approximation-VCG in the heterogeneous-proposal regime** and
//! **classical Vickrey 2nd-price in the homogeneous-proposal regime**
//! (all bids share one `proposal_id` — Nucleus's primary use case). The
//! proptest suite asserts only properties that hold over the kernel as
//! shipped:
//!
//! 1. **Budget conservation** — Σ winning costs ≤ budget for every input
//!    (universal; the headline structural invariant; the Lean theorem
//!    at `formal/Nucleus/Auctions/BudgetConservation.lean` will prove this).
//! 2. **Permutation invariance** — output depends only on the set of
//!    bids, not their submission order.
//! 3. **Homogeneous-proposal classical Vickrey** — all bids on the same
//!    proposal, budget admits one winner: winner is highest-effective
//!    bidder, pays second-highest effective bid, IR holds, Σ payments ≤
//!    Σ values. Truthfulness here holds *by construction* under Option A
//!    (the ratio sort reduces to effective-value sort when all costs are
//!    equal).
//! 4. **Determinism** — repeated calls produce identical output.
//! 5. **Tied-bid sha256 determinism** — when all bidders submit identical
//!    effective values, the kernel deterministically picks the bidder
//!    whose sha256(bidder_id) sorts lex-first. Closes audit item:
//!    deterministic tie-break must also hold under VCG payment, not just
//!    allocation.
//!
//! Heterogeneous-regime IR and `Σ payments ≤ Σ values` are NOT universal
//! under greedy-VCG; the corresponding proptests would surface inputs
//! where the greedy is sub-optimal and break those invariants. Those
//! bounds return when the exact knapsack-DP allocator (`ddo` crate) lands
//! in Month 8.
//!
//! Strategy parameters are kept tight (≤ 8 bidders, ≤ 8 proposals,
//! values up to 1B µUSD) so proptest's default 256 cases run in
//! milliseconds.

use nucleus_econ_kernels::{run_vcg, IntegerBid, IntegerProposal};
use proptest::prelude::*;
use std::collections::HashMap;

/// Strategy: generate up to 8 cost-only proposals with cost ∈ [1, 1B] µUSD.
/// Under Option A (Week 6 fix), proposals carry only `cost_micro_usd`; social
/// value comes from bidders via `effective_value_micro_usd`.
fn proposals_strategy() -> impl Strategy<Value = Vec<IntegerProposal>> {
    prop::collection::vec(
        (1u64..1_000_000_000).prop_map(|cost| IntegerProposal {
            id: String::new(), // filled in below
            cost_micro_usd: cost,
        }),
        1..=8,
    )
    .prop_map(|mut ps| {
        for (i, p) in ps.iter_mut().enumerate() {
            p.id = format!("p{i}");
        }
        ps
    })
}

/// Strategy: from the given proposal set, generate bids — at most one per
/// proposal, at most one per bidder. Effective values are in [1, 1B].
fn bids_strategy(proposals: Vec<IntegerProposal>) -> impl Strategy<Value = Vec<IntegerBid>> {
    let n = proposals.len();
    // Pick a subset size first, then which proposals get bids and at
    // what effective values.
    (1..=n).prop_flat_map(move |k| {
        let proposals = proposals.clone();
        prop::collection::vec(0u64..1_000_000_000, k).prop_map(move |values| {
            values
                .into_iter()
                .enumerate()
                .map(|(i, v)| IntegerBid {
                    bidder: format!("bidder-{i}"),
                    proposal_id: proposals[i].id.clone(),
                    // Effective value is at least 1 to avoid zero-value
                    // bids that the greedy filters trivially.
                    effective_value_micro_usd: v.saturating_add(1),
                })
                .collect()
        })
    })
}

/// Combined strategy: proposals + matched bids + budget.
fn auction_strategy() -> impl Strategy<Value = (Vec<IntegerProposal>, Vec<IntegerBid>, u64)> {
    proposals_strategy().prop_flat_map(|proposals| {
        let proposals_clone = proposals.clone();
        (
            Just(proposals),
            bids_strategy(proposals_clone),
            1u64..500_000_000u64,
        )
    })
}

proptest! {
    /// Σ winning costs ≤ budget. The headline structural invariant.
    /// Failure means the greedy allocator handed out a proposal we
    /// couldn't afford — the exact bug that integer-VCG must NOT have.
    #[test]
    fn budget_conservation_holds(
        (proposals, bids, budget) in auction_strategy()
    ) {
        let clearing = run_vcg(&bids, &proposals, budget).unwrap();
        let by_id: HashMap<&str, &IntegerProposal> =
            proposals.iter().map(|p| (p.id.as_str(), p)).collect();
        let total_cost: u64 = clearing
            .winners
            .iter()
            .map(|w| by_id[w.proposal_id.as_str()].cost_micro_usd)
            .sum();
        prop_assert!(
            total_cost <= budget,
            "Σ winning costs {} exceeds budget {}",
            total_cost,
            budget
        );
        prop_assert_eq!(
            clearing.budget_remaining_micro_usd,
            budget - total_cost,
            "budget_remaining must equal budget − Σ winning costs"
        );
    }

    /// Shuffling the bid list does not change the clearing. The greedy
    /// sort + deterministic tie-break must depend only on the bid set.
    #[test]
    fn permutation_invariance(
        (proposals, mut bids, budget) in auction_strategy()
    ) {
        let original = run_vcg(&bids, &proposals, budget).unwrap();
        bids.reverse();
        let reversed = run_vcg(&bids, &proposals, budget).unwrap();
        prop_assert_eq!(original.winners, reversed.winners);
        prop_assert_eq!(
            original.total_payments_micro_usd,
            reversed.total_payments_micro_usd
        );
    }

    /// **Homogeneous-proposal Vickrey 2nd-price** — Nucleus's primary use case:
    /// many agents competing to serve one call. All bids reference the same
    /// proposal_id; budget admits exactly one bidder; greedy ≡ optimal in
    /// this regime because the sort key (effective_value/cost ratio) reduces
    /// to effective_value alone (all costs equal). Classical Vickrey theorem
    /// holds by construction:
    ///
    /// - Winner is the highest effective bidder
    /// - Winner pays the second-highest effective bid
    /// - Payment does not depend on winner's own bid
    /// - IR: payment ≤ winner's effective value
    /// - Σ payments ≤ Σ value of winners
    #[test]
    fn homogeneous_proposal_classical_vickrey(
        (proposal_cost, mut effective_values) in (
            1u64..1_000_000u64,
            prop::collection::vec(1u64..1_000_000_000u64, 2..=8),
        )
    ) {
        // One proposal; all bids reference it.
        let proposals = vec![IntegerProposal {
            id: "shared".into(),
            cost_micro_usd: proposal_cost,
        }];
        let bids: Vec<IntegerBid> = effective_values
            .iter()
            .enumerate()
            .map(|(i, &v)| IntegerBid {
                bidder: format!("bidder-{i:02}"),
                proposal_id: "shared".into(),
                effective_value_micro_usd: v,
            })
            .collect();
        // Budget exactly admits one. (Budget = cost ensures only one fits
        // since 2*cost > budget for cost ≥ 1.)
        let clearing = run_vcg(&bids, &proposals, proposal_cost).unwrap();
        prop_assert_eq!(
            clearing.winners.len(), 1,
            "homogeneous-proposal budget=cost admits exactly one winner"
        );

        // IR: payment ≤ winner's effective value.
        let winner = &clearing.winners[0];
        let winning_bid = bids.iter().find(|b| b.bidder == winner.bidder).unwrap();
        prop_assert!(
            winner.vcg_payment_micro_usd <= winning_bid.effective_value_micro_usd,
            "IR violated: winner {} pays {} > effective bid {}",
            winner.bidder,
            winner.vcg_payment_micro_usd,
            winning_bid.effective_value_micro_usd
        );

        // Σ payments ≤ Σ value of winners.
        prop_assert!(
            clearing.total_payments_micro_usd <= clearing.total_effective_value_micro_usd,
            "Σ payments {} > Σ value {}",
            clearing.total_payments_micro_usd,
            clearing.total_effective_value_micro_usd
        );

        // Winner is the highest-effective-bid bidder (modulo deterministic
        // tie-breaks).
        effective_values.sort();
        let max_effective = effective_values.last().copied().unwrap();
        prop_assert_eq!(
            winning_bid.effective_value_micro_usd, max_effective,
            "winner must be the highest effective bidder"
        );

        // Classical 2nd-price: payment equals second-highest effective bid
        // (or 0 if only one bidder). When there are ties at the top,
        // payment equals the max (rest of the field tied with the winner).
        let n = effective_values.len();
        let second_highest = if n >= 2 { effective_values[n - 2] } else { 0 };
        prop_assert_eq!(
            winner.vcg_payment_micro_usd, second_highest,
            "homogeneous-proposal Vickrey: payment must equal second-highest effective bid"
        );
    }

    /// Determinism across two identical runs. (Trivial given the
    /// algorithm is pure, but worth asserting because any future
    /// HashMap-iteration-order or floating-point regression would
    /// break this property first.)
    #[test]
    fn idempotent_under_repeated_calls(
        (proposals, bids, budget) in auction_strategy()
    ) {
        let a = run_vcg(&bids, &proposals, budget).unwrap();
        let b = run_vcg(&bids, &proposals, budget).unwrap();
        prop_assert_eq!(a, b);
    }
}

// Close-to-Highest A5 — `tie_break_total_order` named acceptance
// test. Runs ≥10_000 proptest cases that confirm the sha256(bidder)
// tie-break induces a TOTAL order across all tied bidders, plus an
// explicit 8-bidder fixture that re-runs the auction with every
// possible input permutation (8! = 40320 calls) and asserts the
// winner is identical every time.

#[test]
fn tie_break_total_order_explicit_8_bidder_fixture() {
    // A5 explicit fixture: 8 bidders, identical effective_value, same
    // proposal. Enumerate all 8! = 40320 permutations via iterative
    // Heap's algorithm; every permutation must select the SAME winner.
    let bidders = [
        "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi",
    ];
    let proposals = vec![IntegerProposal {
        id: "shared".into(),
        cost_micro_usd: 10_000,
    }];
    let tied_value = 1_000_000_u64;
    let base_bids: Vec<IntegerBid> = bidders
        .iter()
        .map(|name| IntegerBid {
            bidder: name.to_string(),
            proposal_id: "shared".into(),
            effective_value_micro_usd: tied_value,
        })
        .collect();
    let canonical = run_vcg(&base_bids, &proposals, 10_000).unwrap();
    let canonical_winner = canonical.winners[0].bidder.clone();

    // Iterative Heap's algorithm: yields every permutation exactly once.
    let n = base_bids.len();
    let mut perm: Vec<usize> = (0..n).collect();
    let mut counters = vec![0usize; n];
    let mut perms_run: u64 = 1;
    // The initial perm is the canonical, already verified.
    let mut i = 0usize;
    while i < n {
        if counters[i] < i {
            if i.is_multiple_of(2) {
                perm.swap(0, i);
            } else {
                perm.swap(counters[i], i);
            }
            let shuffled: Vec<IntegerBid> = perm.iter().map(|&j| base_bids[j].clone()).collect();
            let c = run_vcg(&shuffled, &proposals, 10_000).unwrap();
            assert_eq!(
                c.winners[0].bidder, canonical_winner,
                "permutation {perm:?} broke total-order; expected {canonical_winner}, got {}",
                c.winners[0].bidder
            );
            perms_run += 1;
            counters[i] += 1;
            i = 0;
        } else {
            counters[i] = 0;
            i += 1;
        }
    }
    // 8! = 40320; we should have run every one.
    assert_eq!(
        perms_run, 40_320,
        "expected 40320 perms (8!); got {perms_run}"
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 10_000,
        max_global_rejects: 100,
        .. proptest::test_runner::Config::default()
    })]

    /// A5 acceptance: tie-break order is a TOTAL order across the
    /// tied set. For any two distinct bidder names a, b drawn from
    /// the fuzz space, sha256(a) and sha256(b) compare lex-distinctly
    /// (no ties beyond the literal identical-name case). The
    /// `run_vcg` kernel always selects ONE winner, even with many
    /// tied bidders — never zero, never two.
    #[test]
    fn tie_break_total_order(
        // 2..=12 bidders; all share the same identical effective_value.
        names in proptest::collection::vec("[a-z]{3,12}", 2..=12),
        tied_value in 1_000u64..=1_000_000_000u64,
    ) {
        // Dedup names (proptest may repeat). If <2 distinct, skip.
        let mut unique: Vec<String> = names;
        unique.sort();
        unique.dedup();
        if unique.len() < 2 {
            return Ok(());
        }
        let proposals = vec![IntegerProposal {
            id: "p".into(),
            cost_micro_usd: 10,
        }];
        let bids: Vec<IntegerBid> = unique.iter().map(|n| IntegerBid {
            bidder: n.clone(),
            proposal_id: "p".into(),
            effective_value_micro_usd: tied_value,
        }).collect();
        let c = run_vcg(&bids, &proposals, 10).unwrap();
        // Total-order axiom: exactly one winner.
        proptest::prop_assert_eq!(c.winners.len(), 1);
        // Same bid set in a different order produces the same winner —
        // permutation invariance under ties (cross-cuts the total order
        // claim: only a total order over bidder names can do this).
        let mut reversed = bids.clone();
        reversed.reverse();
        let c2 = run_vcg(&reversed, &proposals, 10).unwrap();
        proptest::prop_assert_eq!(&c.winners[0].bidder, &c2.winners[0].bidder);
    }
}

#[test]
fn tied_homogeneous_bids_sha256_tiebreak_deterministic_under_payment() {
    // Audit closure: when all bids submit IDENTICAL effective values on
    // the same proposal, the kernel must (a) deterministically select
    // ONE winner via sha256(bidder) ascending, and (b) the second-price
    // payment must equal that same tied value (since the second-highest
    // bidder also bids the same amount). Closes the audit gap: tie-break
    // determinism must hold under payment, not just allocation.
    let proposals = vec![IntegerProposal {
        id: "shared".into(),
        cost_micro_usd: 50_000_000,
    }];
    let tied_value = 100_000_000_u64;
    let bidders = ["alice", "bob", "carol", "dave", "eve"];
    let bids: Vec<IntegerBid> = bidders
        .iter()
        .map(|name| IntegerBid {
            bidder: name.to_string(),
            proposal_id: "shared".into(),
            effective_value_micro_usd: tied_value,
        })
        .collect();

    let c = run_vcg(&bids, &proposals, 50_000_000).unwrap();
    assert_eq!(c.winners.len(), 1, "exactly one winner");

    // Determinism: re-run with shuffled input must produce same winner.
    let mut shuffled = bids.clone();
    shuffled.reverse();
    let c2 = run_vcg(&shuffled, &proposals, 50_000_000).unwrap();
    assert_eq!(
        c.winners[0].bidder, c2.winners[0].bidder,
        "tied bids must pick the same winner under input permutation"
    );

    // Tie-break is sha256(bidder) ascending. Compute the expected winner
    // independently and assert it matches.
    use sha2::{Digest, Sha256};
    let expected = bidders
        .iter()
        .min_by_key(|name| {
            let mut h = Sha256::new();
            h.update(name.as_bytes());
            h.finalize().to_vec()
        })
        .unwrap();
    assert_eq!(
        c.winners[0].bidder, *expected,
        "winner must be sha256(bidder) lex-minimum among tied bids"
    );

    // Under all-tied bids, the second-highest effective is also `tied_value`,
    // so the Vickrey payment equals the winner's own bid (utility = 0 — a
    // degenerate boundary case but algorithmically sound).
    assert_eq!(
        c.winners[0].vcg_payment_micro_usd, tied_value,
        "all-tied homogeneous Vickrey: payment must equal the tied value"
    );
}

#[test]
fn truthfulness_survives_rounding_on_single_item_displacement() {
    // The headline VCG truthfulness property from
    // `docs/ECON-PRECISION.md`: when a bidder strictly wins under both
    // their truthful bid AND any over-bid, the payment is identical.
    //
    // Single-item case (budget admits at most one proposal). Alice's
    // effective value is 100M; Bob's is 80M. Cost of each proposal is
    // 50M; budget 70M → exactly one fits.
    let proposals = vec![
        IntegerProposal {
            id: "p1".into(),
            cost_micro_usd: 50_000_000,
        },
        IntegerProposal {
            id: "p2".into(),
            cost_micro_usd: 50_000_000,
        },
    ];
    let bob = IntegerBid {
        bidder: "bob".into(),
        proposal_id: "p2".into(),
        effective_value_micro_usd: 80_000_000,
    };

    // Alice's truthful bid + a sweep of over-bids. She wins in all
    // cases; her payment must equal bob's effective value (the
    // externality she imposes) regardless of her own bid.
    for alice_bid in [100_000_000_u64, 150_000_000, 200_000_000, 500_000_000] {
        let alice = IntegerBid {
            bidder: "alice".into(),
            proposal_id: "p1".into(),
            effective_value_micro_usd: alice_bid,
        };
        let c = run_vcg(&[alice, bob.clone()], &proposals, 70_000_000).unwrap();
        assert_eq!(c.winners.len(), 1, "exactly one winner with budget 70M");
        assert_eq!(c.winners[0].bidder, "alice");
        assert_eq!(
            c.winners[0].vcg_payment_micro_usd, 80_000_000,
            "alice's VCG payment must equal bob's effective value (80M), \
             not depend on her own bid amount {alice_bid}"
        );
    }
}
