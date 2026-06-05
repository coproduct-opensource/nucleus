// Track A — price-to-Lean parity proptest for the single-good
// (homogeneous) regime. Bridges the production VCG clearing price to
// the Lean-proven second-price rule, byte-for-byte.
//
// ── Proof ↔ price pin (grep me) ─────────────────────────────────────
//
// Lean source: `formal/Nucleus/Auctions/IntegerVcgTruthful.lean`
//
//   • `maxBid : List Nat → Nat`        (lines 60-62) — the clearing
//     price function: `[] => 0`, `b :: rest => Nat.max b (maxBid rest)`.
//   • `utility` (lines 76-77) — the winner pays `maxBid others`.
//   • theorem `truthful_price_is_max_others` (lines 128-132) — when the
//     truthful bidder wins (`v ≥ maxBid others`), the price paid equals
//     `maxBid others`, independent of the winner's own valuation.
//   • theorem `vickrey_truthful` (lines 90-117) — truthful bidding
//     weakly dominates any deviation under exactly this price rule.
//
// The Rust mirror of `maxBid` lives in
// `crates/nucleus-econ-kernels/src/extracted/vcg_aeneas.rs::max_bid`
// (Aeneas integer-only subset; empty => 0, fold of `u64::max`).
//
// **The parity claim** asserted below: in the single-good regime (one
// shared proposal with cost C, budget = C so exactly one winner fits),
// the production `run_vcg` sets the lone winner's
// `vcg_payment_micro_usd` BYTE-FOR-BYTE equal to `max_bid(others)`,
// where `others` is every submitted effective value except the
// winning bidder's. This is the Rust transcription of the Lean
// theorem `truthful_price_is_max_others`: production single-good price
// == proven `maxBid(others)`.
//
// This test is self-contained inside nucleus-econ-kernels: it imports
// only the crate's own public surface plus proptest. No auction-hub
// import.

#![deny(clippy::float_arithmetic)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]

use nucleus_econ_kernels::extracted::vcg_aeneas::max_bid;
use nucleus_econ_kernels::{run_vcg, IntegerBid, IntegerProposal};
use proptest::prelude::*;

/// Build the single-good regime: one shared proposal of cost `C`,
/// budget exactly `C`, one bid per supplied effective value. Returns
/// the clearing or panics if the kernel rejects a well-formed input.
fn run_single_good(values: &[u64], cost: u64) -> nucleus_econ_kernels::Clearing {
    let proposals = vec![IntegerProposal {
        id: "p-shared".to_string(),
        cost_micro_usd: cost,
    }];
    let bids: Vec<IntegerBid> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| IntegerBid {
            bidder: format!("bidder-{i:03}"),
            proposal_id: "p-shared".to_string(),
            effective_value_micro_usd: v,
        })
        .collect();
    // budget = cost forces EXACTLY one winner (the highest effective
    // value); every other bid is a loser because remaining < cost.
    run_vcg(&bids, &proposals, cost).expect("well-formed single-good input must clear")
}

/// `others` = every submitted effective value except the winner's,
/// matching the bidder removed by index. The winner is identified by
/// its bidder id `bidder-{i:03}`, so we drop exactly that index.
fn others_except_winner(values: &[u64], winner_bidder: &str) -> Vec<u64> {
    let winner_idx: usize = winner_bidder
        .strip_prefix("bidder-")
        .and_then(|s| s.parse().ok())
        .expect("winner bidder id has the bidder-NNN shape");
    values
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != winner_idx)
        .map(|(_, &v)| v)
        .collect()
}

proptest! {
    // **The Lean theorem `truthful_price_is_max_others`, transcribed
    // to a Rust assertion over random single-good bid vectors.**
    //
    // For a random Vec<u64> of effective values, the production
    // single-good clearing price (the lone winner's
    // `vcg_payment_micro_usd`) must equal `max_bid(others)`
    // byte-for-byte — where `others` is every value except the
    // winner's. This pins production price == proven maxBid(others).
    #[test]
    fn single_good_price_equals_max_bid_others(
        values in prop::collection::vec(1u64..1_000_000, 2..12),
    ) {
        // Cost well below the kernel's effective-value ceiling so the
        // only fired path is a normal clearing (no BudgetExceedsLimit:
        // 12 × 1M = 12M, far under i64::MAX).
        let cost = 500_000u64;
        let clearing = run_single_good(&values, cost);

        // budget = cost ⇒ exactly one winner fits.
        prop_assert_eq!(clearing.winners.len(), 1, "single-good regime must yield exactly one winner");

        let winner = &clearing.winners[0];
        let others = others_except_winner(&values, &winner.bidder);

        // BYTE-FOR-BYTE: production price == Lean-proven maxBid(others).
        prop_assert_eq!(
            winner.vcg_payment_micro_usd,
            max_bid(&others),
            "production single-good price diverged from Lean maxBid(others): \
             values={:?}, winner={}, others={:?}",
            values, winner.bidder, others
        );
    }
}

// ── Named fixtures (mirroring lean_model_parity.rs) ─────────────────

#[test]
fn single_bidder_pays_max_bid_empty_equals_zero() {
    // One bidder ⇒ others = [] ⇒ maxBid([]) = 0. The Lean nil case.
    // (Production: no externality on others when you are the only bid.)
    let clearing = run_single_good(&[42_000], 500_000);
    assert_eq!(clearing.winners.len(), 1);
    let others = others_except_winner(&[42_000], &clearing.winners[0].bidder);
    assert!(others.is_empty());
    assert_eq!(max_bid(&others), 0);
    assert_eq!(clearing.winners[0].vcg_payment_micro_usd, 0);
}

#[test]
fn two_bidders_winner_pays_loser_bid() {
    // Two bidders, distinct values ⇒ higher wins, pays the loser's
    // bid = maxBid([loser]) = loser value. Lean truthful_price_is_max_others.
    let values = [70_000u64, 65_000u64];
    let clearing = run_single_good(&values, 500_000);
    assert_eq!(clearing.winners.len(), 1);
    let winner = &clearing.winners[0];
    // bidder-000 has the higher value (70k), so it wins.
    assert_eq!(winner.bidder, "bidder-000");
    let others = others_except_winner(&values, &winner.bidder);
    assert_eq!(others, vec![65_000]);
    assert_eq!(max_bid(&others), 65_000);
    assert_eq!(winner.vcg_payment_micro_usd, 65_000);
}

#[test]
fn tie_case_winner_pays_max_bid_of_tied_others() {
    // Two bidders at the SAME value. One wins (sha256(bidder)
    // tie-break), `others` still contains the other tied bidder, so
    // maxBid(others) = the tied value. Production must pay that.
    let values = [50_000u64, 50_000u64];
    let clearing = run_single_good(&values, 500_000);
    assert_eq!(clearing.winners.len(), 1);
    let winner = &clearing.winners[0];
    let others = others_except_winner(&values, &winner.bidder);
    assert_eq!(others, vec![50_000]);
    assert_eq!(max_bid(&others), 50_000);
    assert_eq!(winner.vcg_payment_micro_usd, max_bid(&others));
    assert_eq!(winner.vcg_payment_micro_usd, 50_000);
}

#[test]
fn three_bidders_winner_pays_second_highest() {
    // Classic single-good second price: highest wins, pays the
    // second-highest = maxBid of the remaining two.
    let values = [30_000u64, 90_000u64, 55_000u64];
    let clearing = run_single_good(&values, 500_000);
    assert_eq!(clearing.winners.len(), 1);
    let winner = &clearing.winners[0];
    assert_eq!(winner.bidder, "bidder-001"); // 90k is highest
    let others = others_except_winner(&values, &winner.bidder);
    assert_eq!(max_bid(&others), 55_000); // second-highest
    assert_eq!(winner.vcg_payment_micro_usd, 55_000);
}
