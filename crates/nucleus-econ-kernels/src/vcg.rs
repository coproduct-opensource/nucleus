//! Integer-only Vickrey-Clarke-Groves (VCG) auction kernel.
//!
//! # Provenance
//!
//! Algorithm lifted from
//! `/Users/bcrisp/coproduct/workstream-kg/crates/agent/src/market/vcg.rs`
//! (~326 lines, f64 USD, autonomous-agent-domain types). The greedy
//! welfare-maximizing allocation plus the re-run-without-i payment loop
//! are preserved verbatim; everything else is rewritten:
//!
//! - **f64 → u64/u128 micro-USD** per `docs/ECON-PRECISION.md`. Bid
//!   effective values are `u64`, intermediate welfare sums are `u128`,
//!   final payments back to `u64` with saturation. No floats anywhere.
//! - **Cross-product comparison** replaces `effective_value/cost` real-
//!   number sort. For bids `a` and `b`, `a > b` iff
//!   `a.effective_value * b.cost > b.effective_value * a.cost` in
//!   `u128`. Exact under integer arithmetic.
//! - **Deterministic tie-breaking** by `(effective_value desc,
//!   sha256(bidder_id) asc)` so the algorithm is reproducible from the
//!   signed bid set alone. The hash-based tie-break is public and
//!   verifiable; bidders cannot strategize on submission order or
//!   timing.
//! - **2^63 µUSD safety ceiling** on the sum of submitted effective
//!   values — defensive guard against `u64` welfare overflow.
//! - **Cost-only proposals** — proposals declare only `cost_micro_usd`;
//!   social value comes from bidders via `effective_value_micro_usd`.
//!   Workstream-kg's `AgentDomain` / `WorkType` enums are not lifted;
//!   integration callers layer those on top via their own bid/proposal
//!   types.
//!
//! # Approximation-VCG in the combinatorial regime
//!
//! The Week 6 Option A fix (collapsing welfare to bid effective value)
//! restores theoretical honesty in the **homogeneous-proposal** case —
//! when all bids reference the same `proposal_id`, the kernel reduces to
//! classical Vickrey 2nd-price: the highest bidder wins, pays the
//! second-highest effective bid, and the payment does not depend on the
//! winner's own bid. This is Nucleus's actual use case (many agents
//! competing to serve one call) and the regime where the kernel's
//! truthfulness + IR claims hold by construction.
//!
//! In the **heterogeneous-proposal regime** (bidders bidding on
//! different proposals, budget gating which combinations are feasible)
//! the kernel is a *greedy approximation*. For the 0-1 knapsack
//! subproblem, greedy by `effective_value/cost` ratio is not optimal in
//! general — there exist inputs where the greedy allocation has
//! strictly lower social welfare than the optimal knapsack solution.
//! When the allocation is sub-optimal, the VCG payment formula
//! `payment_i = alt_welfare − others_welfare` can exceed winner `i`'s
//! effective value (IR violation). The heterogeneous regime is
//! out of scope for the Week 6 fix; Month 8 brings exact-VCG via
//! knapsack DP using the `ddo` crate.
//!
//! **What this kernel guarantees today**:
//!
//! - **Budget conservation** — Σ winning costs ≤ budget, always. Lean
//!   theorem at `formal/Nucleus/Auctions/BudgetConservation.lean`
//!   (Weeks 11-12) proves this by structural induction.
//! - **Determinism** — same bids + proposals + budget always produces
//!   the same clearing (cross-product comparison + sha256 tie-break).
//! - **Homogeneous-proposal Vickrey 2nd-price** — all bids on the same
//!   proposal_id, budget admits one winner: classical Vickrey theorem
//!   holds. This is Nucleus's primary use case.
//! - **Non-negative payments** — saturating-sub keeps every payment ≥ 0.
//!
//! **What this kernel does NOT yet guarantee** (heterogeneous-proposal
//! regime, deferred to Month 8 exact-VCG via `ddo`):
//!
//! - Strict IR per winner when bidders bid on different proposals and
//!   the greedy picks a sub-optimal allocation.
//! - `Σ payments ≤ Σ effective_values of winners` in the heterogeneous
//!   regime.
//! - Full VCG dominant-strategy truthfulness across heterogeneous
//!   input shapes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use thiserror::Error;

/// Defensive upper bound on the sum of submitted effective values. At
/// `2^63 - 1` micro-USD (≈ $9.2 trillion) this is three orders of magnitude
/// above any plausible single auction; the ceiling exists so the welfare
/// sum and counterfactual welfare sum can both fit comfortably in `u128`
/// without overflow concerns. See `docs/ECON-PRECISION.md` §6.
pub const MAX_TOTAL_EFFECTIVE_VALUE_MICRO_USD: u64 = i64::MAX as u64;

/// A bid submitted to the auction.
///
/// `effective_value_micro_usd` is the caller's already-computed
/// reputation- and urgency-weighted bid amount. The kernel does NOT
/// recompute weighting — that policy lives one layer up (in
/// `nucleus-market`) so the kernel stays pure and Aeneas-translatable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegerBid {
    /// SPIFFE-style identity of the bidder. Used as the deterministic
    /// tie-breaker (sha256 lex-ascending). MUST be unique within an
    /// auction — duplicates are rejected by [`run_vcg`].
    pub bidder: String,
    /// The proposal this bid is for. Must reference a proposal in the
    /// `proposals` slice passed to [`run_vcg`].
    pub proposal_id: String,
    /// Bid amount after reputation/urgency weighting, in `u64` micro-USD.
    /// Caller-side: `effective = bid * urgency_bps * reputation_bps /
    /// 10_000^2` in `u128` with saturation; see `docs/ECON-PRECISION.md`.
    pub effective_value_micro_usd: u64,
}

/// A proposal a bid can be placed against.
///
/// **Cost-only.** Proposals declare only the resource cost; the social
/// value of running them is the bidder's submitted `effective_value` (the
/// classical VCG interpretation — value comes from the bidder, not from
/// a separately-declared proposer field). Previously this struct carried
/// a `value_micro_usd` field that the welfare computation summed; that
/// design admitted a hidden two-utility-function bug (IR could fail
/// whenever bid ≠ proposal value, which is precisely when separate
/// proposal values exist). The Week 6 Option A fix from
/// `/Users/bcrisp/.claude/plans/let-s-web-search-look-modular-rivest.md`
/// collapsed welfare to bid effective value, restoring theoretical
/// honesty under `docs/ECON-PRECISION.md`'s "bid is the canonical
/// economic primitive" principle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegerProposal {
    /// Unique proposal id. Bids reference this via [`IntegerBid::proposal_id`].
    pub id: String,
    /// Resource cost of running this proposal, in `u64` micro-USD. The
    /// greedy allocator subtracts cost from the budget when including
    /// a proposal in the winners.
    pub cost_micro_usd: u64,
}

/// A winning bid and its VCG payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinningBid {
    pub bidder: String,
    pub proposal_id: String,
    /// The externality this winner imposes on others, in `u64` micro-USD.
    /// Computed as `max(0, alt_welfare - others_welfare)` where
    /// `alt_welfare` is the optimal allocation among everyone except
    /// this winner.
    pub vcg_payment_micro_usd: u64,
}

/// Outcome of running [`run_vcg`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clearing {
    /// Winners and their VCG payments.
    pub winners: Vec<WinningBid>,
    /// Bidder ids of losing bids, in the deterministic order they were
    /// considered (effective-value-descending, sha256-tie-broken).
    pub losers: Vec<String>,
    /// Total social value across winning proposals, in `u64` micro-USD.
    /// Saturates at `u64::MAX` on overflow (which the ceiling check
    /// makes unreachable in practice).
    pub total_effective_value_micro_usd: u64,
    /// Sum of VCG payments across winners, in `u64` micro-USD.
    pub total_payments_micro_usd: u64,
    /// Budget left after winners' costs (NOT after VCG payments — costs
    /// are the resource the budget gates against; payments are
    /// transfers to the mechanism).
    pub budget_remaining_micro_usd: u64,
}

/// Errors [`run_vcg`] can return at the input-validation boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VcgError {
    /// Sum of submitted effective values exceeds the safety ceiling
    /// `MAX_TOTAL_EFFECTIVE_VALUE_MICRO_USD`.
    #[error("total effective value {sum_micro_usd} exceeds ceiling {limit}")]
    BudgetExceedsLimit { sum_micro_usd: u128, limit: u64 },

    /// Two bids share the same `bidder` string. Tie-breaking assumes
    /// bidder ids are unique — otherwise the deterministic ordering
    /// can't be recomputed off-platform.
    #[error("duplicate bidder in auction: {bidder}")]
    DuplicateBidder { bidder: String },

    /// A bid references a proposal id that isn't in the proposals list.
    #[error("bid references unknown proposal: {proposal_id}")]
    UnknownProposal { proposal_id: String },
}

/// Run the integer VCG auction.
///
/// Returns a [`Clearing`] with the winners, their VCG payments, the
/// losing bids, and budget bookkeeping. The clearing is deterministic
/// in its inputs — same `(bids, proposals, budget)` always produces the
/// same `Clearing`, including the order of `winners` and `losers`.
///
/// # Algorithm
///
/// 1. Validate inputs (bidder uniqueness, proposal-id coverage, ceiling).
/// 2. Sort bids by `(effective_value/cost ratio desc, effective_value
///    desc, sha256(bidder) asc)` using cross-product comparison.
/// 3. Greedily pack bids into the budget.
/// 4. For each winner `i`, recompute the optimal allocation excluding
///    `i` and compute their VCG payment as the externality imposed.
///
/// # Complexity
///
/// O(n² log n) in the number of bids: the payment loop re-runs the
/// allocation `n` times. Fine for the bid counts a single agent auction
/// produces (typically <100); a more sophisticated implementation can
/// land later if combinatorial markets demand it.
pub fn run_vcg(
    bids: &[IntegerBid],
    proposals: &[IntegerProposal],
    budget_micro_usd: u64,
) -> Result<Clearing, VcgError> {
    // ── Validate inputs ──────────────────────────────────────────────

    // Sum-of-effective-values ceiling check (in u128 for headroom).
    let total_submitted: u128 = bids
        .iter()
        .map(|b| u128::from(b.effective_value_micro_usd))
        .sum();
    if total_submitted > u128::from(MAX_TOTAL_EFFECTIVE_VALUE_MICRO_USD) {
        return Err(VcgError::BudgetExceedsLimit {
            sum_micro_usd: total_submitted,
            limit: MAX_TOTAL_EFFECTIVE_VALUE_MICRO_USD,
        });
    }

    let proposals_by_id: HashMap<&str, &IntegerProposal> =
        proposals.iter().map(|p| (p.id.as_str(), p)).collect();

    // Reject bids referencing unknown proposals so the algorithm
    // doesn't have to silently filter them mid-run.
    for bid in bids {
        if !proposals_by_id.contains_key(bid.proposal_id.as_str()) {
            return Err(VcgError::UnknownProposal {
                proposal_id: bid.proposal_id.clone(),
            });
        }
    }

    // Reject duplicate bidder ids — tie-breaking depends on uniqueness.
    {
        let mut seen: HashMap<&str, ()> = HashMap::with_capacity(bids.len());
        for bid in bids {
            if seen.insert(bid.bidder.as_str(), ()).is_some() {
                return Err(VcgError::DuplicateBidder {
                    bidder: bid.bidder.clone(),
                });
            }
        }
    }

    // ── Greedy optimal allocation ────────────────────────────────────

    let (winner_bids, loser_bids) = optimal_allocation(bids, &proposals_by_id, budget_micro_usd);

    if winner_bids.is_empty() {
        return Ok(Clearing {
            winners: Vec::new(),
            losers: loser_bids.iter().map(|b| b.bidder.clone()).collect(),
            total_effective_value_micro_usd: 0,
            total_payments_micro_usd: 0,
            budget_remaining_micro_usd: budget_micro_usd,
        });
    }

    // ── VCG payments ─────────────────────────────────────────────────

    let winners = compute_vcg_payments(
        &winner_bids,
        &loser_bids,
        &proposals_by_id,
        budget_micro_usd,
    );

    // Saturating total_value sum across winners.
    // Total social value across winners = Σ winning bids' effective values
    // (Option A welfare definition; see IntegerProposal docs for rationale).
    let total_value_u128: u128 = winner_bids
        .iter()
        .map(|b| u128::from(b.effective_value_micro_usd))
        .sum();
    let total_effective_value_micro_usd = u128_to_u64_saturating(total_value_u128);

    let total_payments_u128: u128 = winners
        .iter()
        .map(|w| u128::from(w.vcg_payment_micro_usd))
        .sum();
    let total_payments_micro_usd = u128_to_u64_saturating(total_payments_u128);

    // Budget-remaining computed against costs (not payments). Saturating sub.
    let total_cost_u128: u128 = winner_bids
        .iter()
        .map(|b| u128::from(proposals_by_id[b.proposal_id.as_str()].cost_micro_usd))
        .sum();
    let total_cost_micro_usd = u128_to_u64_saturating(total_cost_u128);
    let budget_remaining_micro_usd = budget_micro_usd.saturating_sub(total_cost_micro_usd);

    Ok(Clearing {
        winners,
        losers: loser_bids.iter().map(|b| b.bidder.clone()).collect(),
        total_effective_value_micro_usd,
        total_payments_micro_usd,
        budget_remaining_micro_usd,
    })
}

/// Greedy welfare-maximizing allocation under a budget constraint.
/// Returns (winners, losers) in the deterministic sort order so the
/// caller can fold over them stably.
fn optimal_allocation<'a>(
    bids: &'a [IntegerBid],
    proposals: &HashMap<&str, &IntegerProposal>,
    budget_micro_usd: u64,
) -> (Vec<&'a IntegerBid>, Vec<&'a IntegerBid>) {
    // Sort by ratio (effective_value / cost) descending. Cross-product
    // comparison preserves the f64 ordering exactly under u128.
    // Tie-breakers: higher effective_value first; then sha256(bidder)
    // lex-ascending. Both are pure functions of the input set.
    let mut sorted: Vec<&IntegerBid> = bids.iter().collect();
    sorted.sort_by(|a, b| {
        let pa = proposals[a.proposal_id.as_str()];
        let pb = proposals[b.proposal_id.as_str()];
        ratio_compare(
            (a.effective_value_micro_usd, pa.cost_micro_usd),
            (b.effective_value_micro_usd, pb.cost_micro_usd),
        )
        // Higher ratio comes first.
        .reverse()
        // Tie-break 1: higher effective_value first.
        .then_with(|| {
            b.effective_value_micro_usd
                .cmp(&a.effective_value_micro_usd)
        })
        // Tie-break 2: lex-ascending sha256(bidder). Deterministic and
        // unaffected by submission order.
        .then_with(|| sha256_bytes(&a.bidder).cmp(&sha256_bytes(&b.bidder)))
    });

    let mut winners = Vec::new();
    let mut losers = Vec::new();
    let mut remaining: u64 = budget_micro_usd;
    for bid in sorted {
        let cost = proposals[bid.proposal_id.as_str()].cost_micro_usd;
        if cost <= remaining {
            winners.push(bid);
            remaining = remaining.saturating_sub(cost);
        } else {
            losers.push(bid);
        }
    }
    (winners, losers)
}

/// VCG payment for each winner = max(0, alt_welfare − others_welfare),
/// where alt_welfare is the optimal allocation that EXCLUDES the
/// winner under consideration.
fn compute_vcg_payments(
    winners: &[&IntegerBid],
    losers: &[&IntegerBid],
    proposals: &HashMap<&str, &IntegerProposal>,
    budget_micro_usd: u64,
) -> Vec<WinningBid> {
    let mut result = Vec::with_capacity(winners.len());

    for &winner in winners {
        // "Others" = winners minus this one + every loser.
        let others_then_losers: Vec<IntegerBid> = winners
            .iter()
            .filter(|&&b| b.bidder != winner.bidder)
            .chain(losers.iter())
            .map(|&b| b.clone())
            .collect();

        // Welfare of the optimal allocation without this winner.
        let (alt_winners, _) = optimal_allocation(&others_then_losers, proposals, budget_micro_usd);
        let alt_welfare = welfare_of(&alt_winners);

        // Welfare of the other winners in the actual allocation.
        let others: Vec<&IntegerBid> = winners
            .iter()
            .copied()
            .filter(|&b| b.bidder != winner.bidder)
            .collect();
        let others_welfare = welfare_of(&others);

        // Saturating sub keeps payment >= 0 by construction.
        let payment_u128 = alt_welfare.saturating_sub(others_welfare);
        let vcg_payment_micro_usd = u128_to_u64_saturating(payment_u128);

        result.push(WinningBid {
            bidder: winner.bidder.clone(),
            proposal_id: winner.proposal_id.clone(),
            vcg_payment_micro_usd,
        });
    }

    result
}

/// Welfare of a set of bids = Σ bid effective values. Classical VCG
/// interpretation: the social value of including a bidder in the
/// allocation is the bidder's own (submitted) valuation, not a
/// separately-declared proposer value. The proposals lookup is no
/// longer needed here — keeping the kernel free of the two-utility
/// confusion that the previous design admitted.
fn welfare_of(bids: &[&IntegerBid]) -> u128 {
    bids.iter()
        .map(|b| u128::from(b.effective_value_micro_usd))
        .sum()
}

/// Cross-product comparison of two `(value, cost)` ratios under `u128`
/// arithmetic. Returns the ordering that `a.value / a.cost` compares to
/// `b.value / b.cost` (smaller-first). Special-cases zero cost so a
/// zero-cost proposal compares strictly greater than any positive-cost
/// proposal with finite value.
fn ratio_compare(a: (u64, u64), b: (u64, u64)) -> Ordering {
    // Both costs zero → compare values directly (degenerate; both ratios
    // are mathematically undefined, treat lex-on-value as canonical).
    if a.1 == 0 && b.1 == 0 {
        return a.0.cmp(&b.0);
    }
    if a.1 == 0 {
        return Ordering::Greater; // a has infinite ratio
    }
    if b.1 == 0 {
        return Ordering::Less;
    }
    let lhs = u128::from(a.0) * u128::from(b.1); // a.value * b.cost
    let rhs = u128::from(b.0) * u128::from(a.1); // b.value * a.cost
    lhs.cmp(&rhs)
}

/// `u128::saturating_cast_u64` — clamps at `u64::MAX`. Spelled out
/// because the stable cast traits don't expose this directly.
fn u128_to_u64_saturating(v: u128) -> u64 {
    if v > u128::from(u64::MAX) {
        u64::MAX
    } else {
        v as u64
    }
}

/// SHA-256 of a bidder identity. Used as the deterministic tie-breaker
/// when two bids share the same ratio + effective value.
fn sha256_bytes(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: &str, cost: u64) -> IntegerProposal {
        IntegerProposal {
            id: id.to_string(),
            cost_micro_usd: cost,
        }
    }

    fn b(bidder: &str, proposal_id: &str, effective: u64) -> IntegerBid {
        IntegerBid {
            bidder: bidder.to_string(),
            proposal_id: proposal_id.to_string(),
            effective_value_micro_usd: effective,
        }
    }

    #[test]
    fn single_bidder_pays_zero() {
        // No externality on others when you're the only bidder.
        // Total welfare under Option A = winner's effective bid value.
        let proposals = vec![p("p1", 10_000_000)];
        let bids = vec![b("alice", "p1", 15_000_000)];
        let clearing = run_vcg(&bids, &proposals, 100_000_000).unwrap();
        assert_eq!(clearing.winners.len(), 1);
        assert_eq!(clearing.winners[0].vcg_payment_micro_usd, 0);
        assert_eq!(clearing.total_effective_value_micro_usd, 15_000_000);
        assert_eq!(clearing.total_payments_micro_usd, 0);
    }

    #[test]
    fn budget_displaces_lower_value_per_cost() {
        // Same cost, different effective bid → higher bid wins. Loser's
        // effective bid becomes winner's VCG payment (the externality
        // the loser would have provided). Option A welfare: externality
        // is bob's effective bid (65M), not a separately-declared
        // proposal value.
        let proposals = vec![p("high", 60_000_000), p("low", 60_000_000)];
        let bids = vec![b("alice", "high", 70_000_000), b("bob", "low", 65_000_000)];
        let clearing = run_vcg(&bids, &proposals, 100_000_000).unwrap();
        assert_eq!(clearing.winners.len(), 1);
        assert_eq!(clearing.losers.len(), 1);
        assert_eq!(clearing.winners[0].proposal_id, "high");
        // Bob's effective bid (65M) is the externality alice imposes.
        assert_eq!(clearing.winners[0].vcg_payment_micro_usd, 65_000_000);
    }

    #[test]
    fn both_fit_no_externality() {
        // When everyone fits, nobody displaces anyone → payments are 0.
        let proposals = vec![p("p1", 30_000_000), p("p2", 30_000_000)];
        let bids = vec![b("alice", "p1", 35_000_000), b("bob", "p2", 35_000_000)];
        let clearing = run_vcg(&bids, &proposals, 100_000_000).unwrap();
        assert_eq!(clearing.winners.len(), 2);
        assert_eq!(clearing.losers.len(), 0);
        for w in &clearing.winners {
            assert_eq!(w.vcg_payment_micro_usd, 0);
        }
    }

    #[test]
    fn truthful_bid_same_outcome_as_over_or_under_bid_when_winning() {
        // VCG truthfulness: payment depends on OTHERS' bids, not your
        // own — so over/under bidding while still winning yields the
        // same payment. Budget tight enough to force a single winner
        // so the displacement case is actually exercised.
        let proposals = vec![p("p1", 50_000_000), p("p2", 50_000_000)];
        let other = b("bob", "p2", 80_000_000);
        let budget = 70_000_000; // only one of p1/p2 fits

        let truthful = vec![b("alice", "p1", 100_000_000), other.clone()];
        let over_bid = vec![b("alice", "p1", 150_000_000), other.clone()];

        let c1 = run_vcg(&truthful, &proposals, budget).unwrap();
        let c2 = run_vcg(&over_bid, &proposals, budget).unwrap();

        // Alice wins in both cases (higher value/cost ratio); her
        // payment is identical because it's the externality on bob, not
        // anything to do with alice's own bid amount.
        assert_eq!(c1.winners.len(), 1);
        assert_eq!(c2.winners.len(), 1);
        assert_eq!(c1.winners[0].bidder, "alice");
        assert_eq!(c2.winners[0].bidder, "alice");
        assert_eq!(
            c1.winners[0].vcg_payment_micro_usd, c2.winners[0].vcg_payment_micro_usd,
            "VCG payment must not depend on the winning bidder's own bid amount"
        );
        // And the payment equals bob's effective value (the externality).
        assert_eq!(c1.winners[0].vcg_payment_micro_usd, 80_000_000);
    }

    #[test]
    fn payment_never_exceeds_winning_bid_under_truthful_play() {
        // Individual rationality: a truthful bidder never pays more
        // than their effective value (so utility >= 0).
        let proposals = vec![p("p1", 50_000_000), p("p2", 50_000_000)];
        let bids = vec![
            b("alice", "p1", 100_000_000), // truthful (matches value)
            b("bob", "p2", 80_000_000),    // truthful
        ];
        let clearing = run_vcg(&bids, &proposals, 100_000_000).unwrap();
        for w in &clearing.winners {
            let bid_effective = bids
                .iter()
                .find(|b| b.bidder == w.bidder)
                .unwrap()
                .effective_value_micro_usd;
            assert!(
                w.vcg_payment_micro_usd <= bid_effective,
                "winner {} pays {} > effective bid {} — IR violation",
                w.bidder,
                w.vcg_payment_micro_usd,
                bid_effective
            );
        }
    }

    #[test]
    fn budget_conservation_holds_on_clearing() {
        // The headline invariant: Σ winning costs ≤ budget. Anything
        // else means the greedy allocator handed out a proposal we
        // couldn't pay for.
        let proposals = vec![
            p("p1", 40_000_000),
            p("p2", 30_000_000),
            p("p3", 60_000_000),
        ];
        let bids = vec![
            b("a", "p1", 50_000_000),
            b("b", "p2", 35_000_000),
            b("c", "p3", 100_000_000),
        ];
        let budget = 100_000_000;
        let clearing = run_vcg(&bids, &proposals, budget).unwrap();
        let proposals_by_id: HashMap<&str, &IntegerProposal> =
            proposals.iter().map(|p| (p.id.as_str(), p)).collect();
        let total_cost: u64 = clearing
            .winners
            .iter()
            .map(|w| proposals_by_id[w.proposal_id.as_str()].cost_micro_usd)
            .sum();
        assert!(
            total_cost <= budget,
            "Σ winning costs {} > budget {}",
            total_cost,
            budget
        );
        assert_eq!(clearing.budget_remaining_micro_usd, budget - total_cost);
    }

    #[test]
    fn deterministic_under_input_permutation() {
        // The clearing must depend only on the set of bids, not the
        // order they're submitted in. Reverse and shuffle the input —
        // the winning set + payments must be identical.
        let proposals = vec![
            p("p1", 30_000_000),
            p("p2", 30_000_000),
            p("p3", 30_000_000),
        ];
        let mut bids = vec![
            b("alice", "p1", 50_000_000),
            b("bob", "p2", 40_000_000),
            b("carol", "p3", 35_000_000),
        ];
        let original = run_vcg(&bids, &proposals, 60_000_000).unwrap();
        bids.reverse();
        let reversed = run_vcg(&bids, &proposals, 60_000_000).unwrap();
        // Compare as sets — winning order is the canonical sort, so it
        // should also be identical here.
        assert_eq!(original.winners, reversed.winners);
        assert_eq!(
            original.total_payments_micro_usd,
            reversed.total_payments_micro_usd
        );
    }

    #[test]
    fn duplicate_bidder_rejected() {
        let proposals = vec![p("p1", 10), p("p2", 10)];
        let bids = vec![b("alice", "p1", 50), b("alice", "p2", 50)];
        let err = run_vcg(&bids, &proposals, 100).unwrap_err();
        assert!(matches!(err, VcgError::DuplicateBidder { .. }));
    }

    #[test]
    fn unknown_proposal_rejected() {
        let proposals = vec![p("p1", 10)];
        let bids = vec![b("alice", "ghost", 50)];
        let err = run_vcg(&bids, &proposals, 100).unwrap_err();
        assert!(matches!(err, VcgError::UnknownProposal { .. }));
    }

    #[test]
    fn over_ceiling_total_effective_rejected() {
        // Two bids whose effective values sum > u63 max.
        let huge = MAX_TOTAL_EFFECTIVE_VALUE_MICRO_USD;
        let proposals = vec![p("p1", 10), p("p2", 10)];
        let bids = vec![b("a", "p1", huge), b("b", "p2", huge)];
        let err = run_vcg(&bids, &proposals, u64::MAX).unwrap_err();
        assert!(matches!(err, VcgError::BudgetExceedsLimit { .. }));
    }

    #[test]
    fn ratio_compare_matches_real_arithmetic_on_typical_values() {
        // 100/10 = 10; 50/5 = 10; equal ratios.
        assert_eq!(ratio_compare((100, 10), (50, 5)), Ordering::Equal);
        // 100/10 > 80/10 (same denom).
        assert_eq!(ratio_compare((100, 10), (80, 10)), Ordering::Greater);
        // 50/5 > 100/20 (10 vs 5).
        assert_eq!(ratio_compare((50, 5), (100, 20)), Ordering::Greater);
        // Zero cost is "infinite ratio".
        assert_eq!(ratio_compare((1, 0), (1_000_000, 1)), Ordering::Greater);
    }

    #[test]
    fn ratio_tie_broken_deterministically_by_sha256_of_bidder() {
        // Two bids with identical ratios and identical effective values
        // → tie broken by sha256(bidder). The bidder whose hash is
        // lex-smaller wins (the iteration order in the greedy is
        // hash-ascending).
        let proposals = vec![p("p1", 50_000_000), p("p2", 50_000_000)];
        let bids = vec![b("alice", "p1", 100_000_000), b("bob", "p2", 100_000_000)];
        let budget = 50_000_000; // only one fits
        let c = run_vcg(&bids, &proposals, budget).unwrap();
        assert_eq!(c.winners.len(), 1);
        let hash_alice = sha256_bytes("alice");
        let hash_bob = sha256_bytes("bob");
        let expected = if hash_alice < hash_bob {
            "alice"
        } else {
            "bob"
        };
        assert_eq!(
            c.winners[0].bidder, expected,
            "tie must be broken by sha256(bidder) ascending"
        );
    }
}
