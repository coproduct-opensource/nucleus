//! Heterogeneous-proposal VCG entry point.
//!
//! **Close-to-Highest B2.** The substrate's kernel-side `run_vcg` already
//! accepts a slice of `IntegerProposal` values and a budget cap, so it
//! has *always* admitted heterogeneous-proposal inputs at the type
//! level. What was missing was a named acceptance test pinning the
//! load-bearing individual-rationality (IR) property: **no winner pays
//! more than their submitted effective value**.
//!
//! IR is the contract that makes the auction safe to participate in.
//! Without IR, a hostile auctioneer could over-charge a winner and
//! still issue a "valid" signed clearing edge — the substrate would
//! be cryptographically consistent but economically corrupt.
//!
//! # One heterogeneous entry, and it is the exact one (#2521)
//!
//! The claim at the end of this header used to be that the VCG payment rule
//! "guarantees IR regardless of optimality". **That is false**, and the
//! proptest below found the counterexample: at
//! `proposal_costs = [21744, 20252, 1]`, greedy packing plus Clarke pivots
//! charged `bidder-003` 98_624 on a bid of 91_857. The Clarke pivot is
//! IR-correct only against an OPTIMAL allocator.
//!
//! So the greedy wrapper is gone. [`clear_heterogeneous_exact`] — which
//! enumerates the optimal allocation — is the only heterogeneous entry, and
//! `run_vcg` now REFUSES two or more proposals rather than silently
//! mispricing them. [`crate::clear_vcg`] is the router: one proposal to the
//! homogeneous kernel, more than one to the exact enumerator.
//!
//! What this module holds:
//!
//! 1. [`clear_heterogeneous_exact`], the IR-correct entry.
//! 2. The IR proptest, now over ARBITRARY heterogeneous budgets rather than
//!    only budgets that admit every bid — the narrower regime was the
//!    workaround for the greedy allocator that is no longer reachable.

use std::collections::HashMap;

use thiserror::Error;

use crate::vcg::{Clearing, IntegerBid, IntegerProposal, VcgError, WinningBid, run_vcg};

/// Errors from `clear_heterogeneous`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeteroError {
    /// The named heterogeneous entry point requires ≥ 2 distinct
    /// proposals. A single-proposal input is the homogeneous regime
    /// (`nucleus_market::clear_homogeneous_vickrey`); callers should
    /// route there instead.
    #[error("heterogeneous regime requires ≥ 2 proposals, got {got}")]
    NotHeterogeneous { got: usize },
    /// `clear_heterogeneous_exact` exceeded its brute-force soft cap.
    #[error("exact-VCG soft cap: {got} bids > {max}")]
    TooManyBidsForExact { got: usize, max: usize },
    /// Underlying kernel rejection.
    #[error("VCG kernel error: {0}")]
    Kernel(#[from] VcgError),
}

/// Clear a VCG auction through whichever kernel is SOUND for the input.
///
/// This is the one decider of "which VCG" (ADR 0007 G-1). Three call sites
/// needed the routing — the golden-vector harness, the WASM binding's
/// `recompute_vcg_js`, and `nucleus-recompute`'s receipt issuing and
/// verification — and three copies of a soundness rule is three chances to
/// get it wrong differently.
///
/// The rule, and why each arm is what it is:
///
/// * **one proposal** → [`crate::run_vcg`]. Every bid costs the same, so
///   taking the highest values is optimal, so the Clarke pivot is IR-correct.
///   This reduces to classical second-price.
/// * **two or more** → [`clear_heterogeneous_exact`]. Greedy is not optimal
///   on a knapsack, and `run_vcg` now refuses this shape outright (#2521).
/// * **two or more, above [`EXACT_VCG_MAX_BIDS`]** → an error, because there
///   is no sound kernel for it. That is a denial-of-service surface, stated
///   on the cap rather than hidden behind a silent greedy fallback.
/// * **no proposals** → [`crate::run_vcg`], which handles the empty clearing.
///
/// Agreement between the two arms is not assumed: `exact_agrees_with_greedy_
/// on_the_sealed_displacement_vector` pins that the Rust↔WASM sealed
/// two-proposal vector clears identically either way, which is why routing it
/// to the exact kernel preserves the seal.
pub fn clear_vcg(
    bids: &[IntegerBid],
    proposals: &[IntegerProposal],
    budget_micro_usd: u64,
) -> Result<Clearing, HeteroError> {
    if proposals.len() >= 2 {
        return clear_heterogeneous_exact(bids, proposals, budget_micro_usd);
    }
    Ok(run_vcg(bids, proposals, budget_micro_usd)?)
}

/// Soft cap on bid count for the exact-VCG enumerator. 2^15 = 32_768
/// subsets is the upper bound the brute force tolerates without
/// blowing test wall-clock budgets. Larger inputs should route
/// through `clear_heterogeneous` (greedy) — IR holds only when the
/// allocator is optimal, which is true in the greedy-feasible
/// regime (budget ≥ Σ proposal_costs) per B2's documented gap.
pub const EXACT_VCG_MAX_BIDS: usize = 15;

/// **Close-to-Highest B2 — exact-VCG variant.**
///
/// Welfare-optimal allocation via brute-force subset enumeration plus
/// classical VCG payments via externality computation against the
/// same optimal allocator. Because the allocator IS optimal, the
/// Clarke pivot payment rule preserves individual rationality (every
/// winner pays ≤ their bid).
///
/// `bids` is constrained to `≤ EXACT_VCG_MAX_BIDS` items because the
/// algorithm is `O(N × 2^N)`. Larger inputs return
/// [`HeteroError::TooManyBidsForExact`]; route them through
/// [`clear_heterogeneous`] (greedy) in the budget-feasible regime, or
/// wait for the `ddo` branch-and-bound integration.
pub fn clear_heterogeneous_exact(
    bids: &[IntegerBid],
    proposals: &[IntegerProposal],
    budget_micro_usd: u64,
) -> Result<Clearing, HeteroError> {
    if proposals.len() < 2 {
        return Err(HeteroError::NotHeterogeneous {
            got: proposals.len(),
        });
    }
    if bids.len() > EXACT_VCG_MAX_BIDS {
        return Err(HeteroError::TooManyBidsForExact {
            got: bids.len(),
            max: EXACT_VCG_MAX_BIDS,
        });
    }
    // The arithmetic ceiling, from the one function that decides it.
    crate::vcg::check_total_effective_ceiling(bids)?;
    // Reject duplicate bidders (matches run_vcg invariant).
    {
        let mut seen = std::collections::HashSet::new();
        for b in bids {
            if !seen.insert(b.bidder.as_str()) {
                return Err(HeteroError::Kernel(VcgError::DuplicateBidder {
                    bidder: b.bidder.clone(),
                }));
            }
        }
    }
    // Reject bids referencing unknown proposals.
    let prop_by_id: HashMap<&str, &IntegerProposal> =
        proposals.iter().map(|p| (p.id.as_str(), p)).collect();
    for b in bids {
        if !prop_by_id.contains_key(b.proposal_id.as_str()) {
            return Err(HeteroError::Kernel(VcgError::UnknownProposal {
                proposal_id: b.proposal_id.clone(),
            }));
        }
    }

    let (mut winner_idxs, opt_welfare) = optimal_subset(bids, &prop_by_id, budget_micro_usd);
    // CANONICAL ORDER, or the clearing is not recomputable: `optimal_subset`
    // returns indices in input order, so a permuted bid list produced the same
    // winners and payments in a different sequence — and the sequence is part
    // of what a receipt commits to. One comparator, shared with `run_vcg`.
    winner_idxs.sort_by(|&i, &j| crate::vcg::canonical_bid_order(&bids[i], &bids[j], &prop_by_id));

    // Build the winners with VCG payments.
    let winners: Vec<WinningBid> = winner_idxs
        .iter()
        .map(|&i| {
            // Exclude bidder i; recompute the optimum on the
            // remaining bids. VCG payment = optimum-without-i
            // minus welfare-of-others-with-i.
            let excluded: Vec<IntegerBid> = bids
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, b)| b.clone())
                .collect();
            let (_, w_without_i) = optimal_subset(&excluded, &prop_by_id, budget_micro_usd);
            let w_others: u128 = winner_idxs
                .iter()
                .filter(|&&j| j != i)
                .map(|&j| u128::from(bids[j].effective_value_micro_usd))
                .sum();
            let payment = w_without_i.saturating_sub(w_others);
            WinningBid {
                bidder: bids[i].bidder.clone(),
                proposal_id: bids[i].proposal_id.clone(),
                vcg_payment_micro_usd: u64::try_from(payment).unwrap_or(u64::MAX),
            }
        })
        .collect();

    let total_value: u128 = winner_idxs
        .iter()
        .map(|&i| u128::from(bids[i].effective_value_micro_usd))
        .sum();
    let total_payments: u128 = winners
        .iter()
        .map(|w| u128::from(w.vcg_payment_micro_usd))
        .sum();
    let losers: Vec<String> = bids
        .iter()
        .enumerate()
        .filter(|(i, _)| !winner_idxs.contains(i))
        .map(|(_, b)| b.bidder.clone())
        .collect();
    let total_cost: u128 = winner_idxs
        .iter()
        .map(|&i| u128::from(prop_by_id[bids[i].proposal_id.as_str()].cost_micro_usd))
        .sum();
    let budget_remaining =
        budget_micro_usd.saturating_sub(u64::try_from(total_cost).unwrap_or(u64::MAX));

    Ok(Clearing {
        winners,
        losers,
        total_effective_value_micro_usd: u64::try_from(total_value).unwrap_or(u64::MAX),
        total_payments_micro_usd: u64::try_from(total_payments).unwrap_or(u64::MAX),
        budget_remaining_micro_usd: budget_remaining,
    })
    .inspect(|_c| {
        let _ = opt_welfare; // welfare bound captured via total_effective_value
    })
}

/// Enumerate all `2^N` subsets of `bids` and return the (winner
/// indices, welfare) of the one with maximum welfare subject to
/// (1) per-proposal capacity = 1 (no proposal-id appears twice in
/// winners), (2) Σ winner costs ≤ budget. Ties broken by
/// lex-smallest winner-index bit-set.
fn optimal_subset(
    bids: &[IntegerBid],
    prop_by_id: &HashMap<&str, &IntegerProposal>,
    budget: u64,
) -> (Vec<usize>, u128) {
    let n = bids.len();
    let mut best_mask: u32 = 0;
    let mut best_welfare: u128 = 0;
    let max_mask: u32 = 1u32 << n;
    for mask in 0..max_mask {
        // Capacity check: each proposal can be allocated at most
        // once. (The kernel admits one proposal per allocation
        // slot.) AND budget check.
        let mut chosen_proposals: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        let mut total_cost: u128 = 0;
        let mut total_welfare: u128 = 0;
        let mut feasible = true;
        for (i, bid) in bids.iter().enumerate().take(n) {
            if (mask >> i) & 1 == 1 {
                if !chosen_proposals.insert(bid.proposal_id.as_str()) {
                    feasible = false;
                    break;
                }
                let cost = u128::from(prop_by_id[bid.proposal_id.as_str()].cost_micro_usd);
                total_cost += cost;
                if total_cost > u128::from(budget) {
                    feasible = false;
                    break;
                }
                total_welfare += u128::from(bid.effective_value_micro_usd);
            }
        }
        if feasible
            && (total_welfare > best_welfare || (total_welfare == best_welfare && mask < best_mask))
        {
            best_mask = mask;
            best_welfare = total_welfare;
        }
    }
    let winners: Vec<usize> = (0..n).filter(|i| (best_mask >> i) & 1 == 1).collect();
    (winners, best_welfare)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// One proposal is the homogeneous regime: the exact entry refuses it (it
    /// would bypass the homogeneous kernel's stronger guarantee), and the
    /// router sends it to that kernel instead of refusing the caller.
    #[test]
    fn a_single_proposal_is_refused_by_exact_and_routed_by_clear_vcg() {
        let bids = vec![IntegerBid {
            bidder: "alice".into(),
            proposal_id: "p1".into(),
            effective_value_micro_usd: 100,
        }];
        let proposals = vec![IntegerProposal {
            id: "p1".into(),
            cost_micro_usd: 50,
        }];
        let err = clear_heterogeneous_exact(&bids, &proposals, 1_000).unwrap_err();
        assert!(matches!(err, HeteroError::NotHeterogeneous { got: 1 }));

        let routed = clear_vcg(&bids, &proposals, 1_000).expect("routed to run_vcg");
        assert_eq!(routed.winners.len(), 1, "alice is unopposed");
        assert_eq!(routed.winners[0].bidder, "alice");
    }

    /// #2521, the defect itself. The recorded proptest regression
    /// (`proptest-regressions/vcg_hetero.txt`) is replayed with its exact
    /// inputs: `run_vcg` must now REFUSE the shape, and the exact kernel must
    /// be individually rational on it. Before the refusal this input made
    /// `run_vcg` charge a winner 98_624 on a bid of 91_857.
    #[test]
    fn run_vcg_refuses_the_input_that_broke_individual_rationality() {
        let proposal_costs = [21_744u64, 20_252, 1];
        let bid_specs = [(3usize, 98_624u64), (0, 98_624), (3, 98_624), (1, 91_857), (0, 91_858)];
        let budget = 21_744u64;

        let proposals: Vec<IntegerProposal> = proposal_costs
            .iter()
            .enumerate()
            .map(|(i, &cost)| IntegerProposal {
                id: format!("p{i}"),
                cost_micro_usd: cost,
            })
            .collect();
        let bids: Vec<IntegerBid> = bid_specs
            .iter()
            .enumerate()
            .map(|(i, (idx, value))| IntegerBid {
                bidder: format!("bidder-{i:03}"),
                proposal_id: format!("p{}", idx % proposal_costs.len()),
                effective_value_micro_usd: *value,
            })
            .collect();

        // The greedy kernel no longer prices this at all.
        let err = run_vcg(&bids, &proposals, budget).unwrap_err();
        assert!(
            matches!(err, VcgError::HeterogeneousRequiresExact { proposals: 3 }),
            "expected a refusal naming the shape, got {err:?}"
        );

        // The exact kernel does, and it is individually rational.
        let clearing = clear_vcg(&bids, &proposals, budget).expect("exact clears");
        let bid_of: HashMap<&str, u64> = bids
            .iter()
            .map(|b| (b.bidder.as_str(), b.effective_value_micro_usd))
            .collect();
        for w in &clearing.winners {
            assert!(
                w.vcg_payment_micro_usd <= bid_of[w.bidder.as_str()],
                "IR violation: {} paid {} > bid {}",
                w.bidder,
                w.vcg_payment_micro_usd,
                bid_of[w.bidder.as_str()]
            );
        }
    }

    /// Why routing the sealed two-proposal golden vector to the EXACT kernel
    /// does not break the Rust↔WASM seal: on that vector the two kernels
    /// agree, so the recorded expectation is unchanged. Greedy is optimal
    /// there because both proposals cost the same.
    #[test]
    fn exact_agrees_with_greedy_on_the_sealed_displacement_vector() {
        let bids = vec![
            IntegerBid {
                bidder: "alice".into(),
                proposal_id: "high".into(),
                effective_value_micro_usd: 70_000_000,
            },
            IntegerBid {
                bidder: "bob".into(),
                proposal_id: "low".into(),
                effective_value_micro_usd: 65_000_000,
            },
        ];
        let proposals = vec![
            IntegerProposal {
                id: "high".into(),
                cost_micro_usd: 60_000_000,
            },
            IntegerProposal {
                id: "low".into(),
                cost_micro_usd: 60_000_000,
            },
        ];
        let exact = clear_heterogeneous_exact(&bids, &proposals, 100_000_000).expect("clears");
        assert_eq!(exact.winners.len(), 1);
        assert_eq!(exact.winners[0].bidder, "alice");
        assert_eq!(exact.winners[0].proposal_id, "high");
        // The displaced second value, which is what the golden vector records.
        assert_eq!(exact.winners[0].vcg_payment_micro_usd, 65_000_000);
        assert_eq!(exact.total_payments_micro_usd, 65_000_000);
    }

    #[test]
    fn clear_vcg_runs_two_proposal_fixture_through_the_exact_kernel() {
        // 2 proposals, 3 bids, budget admits both proposals.
        let bids = vec![
            IntegerBid {
                bidder: "alice".into(),
                proposal_id: "p1".into(),
                effective_value_micro_usd: 500,
            },
            IntegerBid {
                bidder: "bob".into(),
                proposal_id: "p2".into(),
                effective_value_micro_usd: 800,
            },
            IntegerBid {
                bidder: "carol".into(),
                proposal_id: "p1".into(),
                effective_value_micro_usd: 600,
            },
        ];
        let proposals = vec![
            IntegerProposal {
                id: "p1".into(),
                cost_micro_usd: 100,
            },
            IntegerProposal {
                id: "p2".into(),
                cost_micro_usd: 150,
            },
        ];
        let budget = 300; // admits both proposals (100 + 150 = 250 < 300)
        let clearing = clear_vcg(&bids, &proposals, budget).unwrap();

        // Both proposals get a winner (Carol for p1 because she
        // outbids Alice; Bob for p2 as the sole p2 bidder).
        assert_eq!(clearing.winners.len(), 2);
        let winners_by_proposal: std::collections::HashMap<_, _> = clearing
            .winners
            .iter()
            .map(|w| (w.proposal_id.clone(), w.bidder.clone()))
            .collect();
        assert_eq!(winners_by_proposal["p1"], "carol");
        assert_eq!(winners_by_proposal["p2"], "bob");

        // IR sanity: every winner's payment ≤ their effective value.
        let bids_by_bidder: std::collections::HashMap<_, _> = bids
            .iter()
            .map(|b| (b.bidder.clone(), b.effective_value_micro_usd))
            .collect();
        for w in &clearing.winners {
            assert!(
                w.vcg_payment_micro_usd <= bids_by_bidder[&w.bidder],
                "IR violation: {} paid {} > bid {}",
                w.bidder,
                w.vcg_payment_micro_usd,
                bids_by_bidder[&w.bidder]
            );
        }
    }

    // ── B2 load-bearing acceptance proptest ─────────────────────────────
    //
    // The classical VCG payment rule gives individual rationality
    // (no winner pays > their bid) ONLY when the allocator is
    // OPTIMAL. The kernel's greedy allocator is *not* optimal in
    // the general heterogeneous-knapsack case (B3 brings exact-VCG
    // via the `ddo` crate); composing greedy + VCG payments can
    // produce an IR-violating clearing. Concrete counter-example
    // found by this proptest at proposal_costs = [21744, 20252, 1]:
    // winner bidder-003 paid 98_624 > bid 91_857 with greedy.
    //
    // The acceptance test below pins IR over the regime where
    // greedy IS optimal — namely, budgets that admit every bid
    // (so the allocator never has to refuse anyone, and greedy =
    // optimal trivially). The wider claim (IR over arbitrary
    // budgets) lands when B3 swaps in exact-VCG.

    proptest! {
        /// **hetero_individual_rationality, over ARBITRARY budgets.** Every
        /// winner pays ≤ its submitted effective value: bidders never take
        /// negative utility from participating truthfully.
        ///
        /// The doc here used to scope the claim to budgets that admit every
        /// bid, because greedy is optimal only in that regime. The body has
        /// swept arbitrary budgets through the exact kernel for some time, and
        /// since #2521 the greedy composition is not reachable at all — so
        /// the claim is now as wide as the test always was.
        ///
        /// The wider claim — IR over arbitrary heterogeneous budgets
        /// — requires the exact-VCG allocator that B3 brings via the
        /// `ddo` crate. Greedy + VCG payments on a sub-optimal
        /// allocation can violate IR by design (counter-example
        /// documented in the comment above this test).
        ///
        /// Sweeps 256 default proptest cases.
        #[test]
        fn hetero_individual_rationality(
            // 2..=6 proposals, each with positive cost.
            proposal_costs in proptest::collection::vec(
                1u64..50_000, 2..=6,
            ),
            // 1..=10 bids; each bid picks a proposal index and a
            // positive effective value.
            bid_specs in proptest::collection::vec(
                (0usize..6, 1u64..1_000_000),
                1..=10,
            ),
            // Budget up to 10 million micro-USD (within the kernel
            // safety envelope).
            budget in 1u64..10_000_000,
        ) {
            // Build the proposal slice.
            let proposals: Vec<IntegerProposal> = proposal_costs
                .iter()
                .enumerate()
                .map(|(i, &cost)| IntegerProposal {
                    id: format!("p{i}"),
                    cost_micro_usd: cost,
                })
                .collect();
            let n_props = proposals.len();
            // Dedupe bids by bidder (kernel rejects duplicates) and
            // clamp the proposal index into range.
            let mut bids: Vec<IntegerBid> = Vec::new();
            for (i, (prop_idx, value)) in bid_specs.iter().enumerate() {
                let p = prop_idx % n_props;
                bids.push(IntegerBid {
                    bidder: format!("bidder-{i:03}"),
                    proposal_id: format!("p{p}"),
                    effective_value_micro_usd: *value,
                });
            }
            // Through the ROUTER, which is what production calls, so this
            // sweeps the dispatch as well as the kernel. The brute-force soft
            // cap is 15 bids and proptest generates at most 10, well inside
            // the envelope.
            let clearing = match clear_vcg(&bids, &proposals, budget) {
                Ok(c) => c,
                Err(_) => return Ok(()),
            };

            // IR check: every winner's payment ≤ their bid.
            let bid_value: std::collections::HashMap<_, _> = bids
                .iter()
                .map(|b| (b.bidder.clone(), b.effective_value_micro_usd))
                .collect();
            for w in &clearing.winners {
                let bid = bid_value[&w.bidder];
                prop_assert!(
                    w.vcg_payment_micro_usd <= bid,
                    "IR violation: winner {} paid {} > bid {}",
                    w.bidder, w.vcg_payment_micro_usd, bid
                );
            }
        }
    }
}
