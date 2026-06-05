//! Aeneas-grade mirror of `formal/Nucleus/Auctions/BudgetConservation.lean`.
//!
//! Each function below is intended to be byte-faithful to its Lean
//! counterpart. Reviewers asked to verify changes here should compare
//! against the Lean source line-by-line; the parity proptests in
//! `crates/nucleus-econ-kernels/tests/lean_model_parity.rs` exercise
//! the equivalence at runtime.
//!
//! When the Aeneas pipeline (Charon → LLBC → Aeneas → Lean-emitted
//! Rust mirror) goes live this file is regenerated; until then the
//! contents are hand-translated. The
//! `coproduct-opensource/aeneas-ci@v1` GHA holds the freshness check.

#![deny(clippy::float_arithmetic)]

/// Rust mirror of `Nucleus.Auctions.BudgetConservation.greedyPack`.
///
/// Lean definition (verbatim from `formal/Nucleus/Auctions/BudgetConservation.lean`):
///
/// ```text
/// def greedyPack : List Nat → Nat → Nat
///   | [], _ => 0
///   | cost :: rest, remaining =>
///       if cost ≤ remaining then
///         cost + greedyPack rest (remaining - cost)
///       else
///         greedyPack rest remaining
/// ```
///
/// Rust shape: head/tail destructure via `slice::split_first`, branch
/// on `cost <= remaining`, either-include-or-skip, recurse. The Lean
/// theorem `greedyPack_le_budget` quantifies
/// `forall costs budget, greedyPack costs budget <= budget`, and this
/// Rust mirror is exercised against that bound in
/// `tests::lean_model_parity::lean_greedy_pack_respects_budget`.
///
/// Saturating arithmetic is used to bridge Lean's unbounded `Nat` to
/// Rust's `u64`. The bound `result <= remaining` holds in both
/// arithmetic regimes; saturation prevents the Rust panic without
/// changing the invariant.
pub fn greedy_pack(costs: &[u64], remaining: u64) -> u64 {
    match costs.split_first() {
        None => 0,
        Some((&cost, rest)) => {
            if cost <= remaining {
                cost.saturating_add(greedy_pack(rest, remaining.saturating_sub(cost)))
            } else {
                greedy_pack(rest, remaining)
            }
        }
    }
}

/// Rust mirror of `Nucleus.Auctions.IntegerVcgTruthful.maxBid`.
///
/// Lean definition (verbatim from
/// `formal/Nucleus/Auctions/IntegerVcgTruthful.lean:60-62`):
///
/// ```text
/// def maxBid : List Nat → Nat
///   | [] => 0
///   | b :: rest => Nat.max b (maxBid rest)
/// ```
///
/// This is the single-good Vickrey clearing price: the winner pays
/// `maxBid others`. The Lean theorem
/// `truthful_price_is_max_others` (lines 128-132) proves the truthful
/// winner's price equals `maxBid others`, and `vickrey_truthful`
/// (lines 90-117) proves truthful bidding weakly dominates any
/// deviation under exactly this price rule.
///
/// Rust shape: a `fold` from `0` taking `u64::max` at each step is the
/// iterative transcription of the structural `Nat.max b (maxBid rest)`
/// recursion. The empty case folds to the `0` seed, matching the Lean
/// `[] => 0` branch. Stays in the Aeneas integer-only subset (no
/// floats, no allocation, pure `u64` arithmetic).
///
/// Exercised against the production `run_vcg` single-good price in
/// `crates/nucleus-econ-kernels/tests/single_good_second_price_parity.rs`.
pub fn max_bid(others: &[u64]) -> u64 {
    others.iter().copied().fold(0, u64::max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_costs_pack_to_zero() {
        assert_eq!(greedy_pack(&[], 100), 0);
    }

    #[test]
    fn single_fits() {
        assert_eq!(greedy_pack(&[42], 100), 42);
    }

    #[test]
    fn single_too_big() {
        assert_eq!(greedy_pack(&[200], 100), 0);
    }

    #[test]
    fn greedy_includes_in_order() {
        // 30 + 40 fit in 100; the next 50 does not, but 20 still
        // does after the previous includes. Greedy left-to-right.
        assert_eq!(greedy_pack(&[30, 40, 50, 20], 100), 30 + 40 + 20);
    }

    #[test]
    fn max_bid_empty_is_zero() {
        // Lean nil case: `maxBid [] = 0`.
        assert_eq!(max_bid(&[]), 0);
    }

    #[test]
    fn max_bid_single() {
        assert_eq!(max_bid(&[42]), 42);
    }

    #[test]
    fn max_bid_takes_maximum() {
        // Lean cons case folds `Nat.max` left-to-right; order-independent.
        assert_eq!(max_bid(&[3, 9, 1, 7]), 9);
        assert_eq!(max_bid(&[7, 1, 9, 3]), 9);
        assert_eq!(max_bid(&[5, 5, 5]), 5);
    }

    #[test]
    fn max_bid_saturates_at_u64_max() {
        assert_eq!(max_bid(&[1, u64::MAX, 2]), u64::MAX);
    }

    #[test]
    fn bound_holds_for_every_prefix() {
        // The Lean theorem says result <= budget; spot-check it on
        // a few hand-picked cost lists.
        for costs in [
            vec![],
            vec![10],
            vec![10, 10, 10],
            vec![100, 1, 1, 1],
            vec![u64::MAX],
            vec![1, u64::MAX],
        ] {
            for &budget in &[0u64, 1, 10, 100, u64::MAX] {
                assert!(
                    greedy_pack(&costs, budget) <= budget,
                    "Lean budget invariant violated: costs={costs:?}, budget={budget}"
                );
            }
        }
    }
}
