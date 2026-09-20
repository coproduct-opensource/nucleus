//! The property the crate exists to deliver: **no misreport pays.**
//!
//! `IntegerVcgTruthful.lean::vickrey_truthful` proves this about a `Nat` model
//! of single-good Vickrey. These tests check the same statement about the thing
//! that actually runs — [`VcgClearing`] over a [`Round`] — so that a change to
//! how this crate *encodes* a round into the kernel (which slot cost, which
//! budget, which proposal) cannot quietly leave the regime the theorem covers.
//!
//! That is not hypothetical. The first version of this crate encoded the slot as
//! a zero-cost proposal under a zero budget. Every bidder "won", nobody
//! displaced anybody, and the clearing price was zero for every input — a
//! mechanism with a proof behind it and no price in front of it. The kernel was
//! right the whole time; the encoding was outside its regime.
//!
//! A-19: these tests were driven red on exactly that defect before being trusted
//! green. Restoring `SLOT_UNITS = 0` fails three of the four below —
//! `no_misreport_beats_the_truth`, `inflating_a_bid_to_steal_a_slot_loses_money`
//! and `the_truthfulness_property_is_not_vacuous`. The fourth,
//! `truthful_bidding_never_pays_above_value`, stays green, which is the reason
//! it is not the only one here: a mechanism that charges everyone zero is
//! perfectly individually rational and completely useless.

use nucleus_authority_exchange::test_support::bid;
use nucleus_authority_exchange::{Clearing, Round, RoundOutcome, VcgClearing};
use nucleus_econ_types::AuctionId;
use nucleus_permission_market::PermissionDimension;
use proptest::prelude::*;
use std::num::NonZeroU32;

const EGRESS: PermissionDimension = PermissionDimension::NetworkEgress;

/// Bidder 0 reports `report`; everyone else reports their true value. Returns
/// bidder 0's realised utility, `true_value - price` if it wins and `0` if not.
fn utility_of_first(report: u64, others: &[u64], true_value: u64) -> i128 {
    let mut round = Round::open(AuctionId::new("r"), EGRESS);
    round
        .submit(bid("bidder-00", report, EGRESS))
        .expect("admitted");
    for (i, v) in others.iter().enumerate() {
        round
            .submit(bid(&format!("bidder-{:02}", i + 1), *v, EGRESS))
            .expect("admitted");
    }
    let outcome = VcgClearing.clear(&round).expect("clears");
    match &outcome {
        RoundOutcome::Cleared { winners, price, .. }
            if winners.iter().any(|w| w.as_str() == "bidder-00") =>
        {
            i128::from(true_value) - i128::from(price.get())
        }
        _ => 0,
    }
}

proptest! {
    /// Misreporting never beats the truth. Both directions — shading down and
    /// inflating — because they fail differently: shading loses a slot that was
    /// worth having, and inflating wins one at a price above its value.
    #[test]
    fn no_misreport_beats_the_truth(
        (true_value, report, others) in (
            1u64..1_000_000u64,
            1u64..1_000_000u64,
            prop::collection::vec(1u64..1_000_000u64, 1..=6),
        )
    ) {
        let truthful = utility_of_first(true_value, &others, true_value);
        let misreport = utility_of_first(report, &others, true_value);
        prop_assert!(
            misreport <= truthful,
            "reporting {report} instead of {true_value} against {others:?} \
             paid {misreport} > {truthful}"
        );
    }

    /// Individual rationality: telling the truth never costs more than the slot
    /// is worth. A mechanism can be truthful and still bankrupt its winners if
    /// the payment rule is wrong, so this is a separate obligation.
    #[test]
    fn truthful_bidding_never_pays_above_value(
        (true_value, others) in (
            1u64..1_000_000u64,
            prop::collection::vec(1u64..1_000_000u64, 1..=6),
        )
    ) {
        prop_assert!(utility_of_first(true_value, &others, true_value) >= 0);
    }
}

/// NON-VACUITY. The proptests above are satisfied trivially by a mechanism that
/// never lets bidder 0 win — utility 0 everywhere, `0 <= 0` forever. These two
/// cases prove both branches are reachable, so the property above is a statement
/// about a mechanism that actually allocates.
#[test]
fn the_truthfulness_property_is_not_vacuous() {
    // Wins, and pays the second-highest bid: utility 100 - 70 = 30.
    assert_eq!(
        utility_of_first(100, &[70], 100),
        30,
        "bidder 0 must be able to win at a second price"
    );
    // Loses: utility 0.
    assert_eq!(
        utility_of_first(50, &[70], 50),
        0,
        "bidder 0 must be able to lose"
    );
}

/// The concrete shape of the win: inflating a bid to steal a slot worth less
/// than its price is exactly the move the mechanism must make unprofitable.
#[test]
fn inflating_a_bid_to_steal_a_slot_loses_money() {
    // True value 50, opponent at 70. Bidding 90 wins the slot at a price of 70,
    // which is 20 more than it is worth.
    assert_eq!(utility_of_first(90, &[70], 50), -20);
    // Telling the truth simply loses the slot, at no cost.
    assert_eq!(utility_of_first(50, &[70], 50), 0);
}

// ── Multi-unit: the Rust kernel against the Lean threshold ──────────────────

/// `ThresholdTruthful.lean::slotThreshold` in Rust: the `k`-th highest of the
/// other bids, `0` when there are fewer than `k` of them.
///
/// Written here rather than imported because it is the *independent* statement
/// of what the theorem says the price should be. A shared helper would let the
/// kernel and the check drift together, which is the failure this pins.
fn lean_slot_threshold(slots: usize, others: &[u64]) -> u64 {
    let mut sorted = others.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.get(slots - 1).copied().unwrap_or(0)
}

/// **PARITY.** With `k` identical slots and unit demand, every winner pays the
/// `k`-th highest of the bids it faces — which is the `k+1`-th highest overall,
/// and exactly the threshold `multi_unit_truthful` is stated at.
///
/// This is the bridge between the Lean statement and the shipped kernel. The
/// theorem is about a threshold; this asserts `run_vcg` computes that threshold
/// through the encoding `VcgClearing` chooses (budget = k · cost).
#[test]
fn the_kernel_charges_the_lean_threshold_at_every_slot_count() {
    let values: [u64; 6] = [100, 85, 70, 55, 40, 25];
    for slots in 1usize..=5 {
        let mut round = Round::open_with_slots(
            AuctionId::new(format!("r-{slots}")),
            EGRESS,
            NonZeroU32::new(slots as u32).expect("slots ≥ 1"),
        );
        for (i, v) in values.iter().enumerate() {
            round
                .submit(bid(&format!("bidder-{i:02}"), *v, EGRESS))
                .expect("admitted");
        }
        let out = VcgClearing.clear(&round).expect("clears");
        let RoundOutcome::Cleared { winners, price, .. } = &out else {
            panic!("6 bidders for {slots} slot(s) is contested: {out:?}");
        };
        assert_eq!(winners.len(), slots, "k slots go to k bidders");
        // The winners are the top k by value.
        for (i, w) in winners.iter().enumerate() {
            assert_eq!(
                w.as_str(),
                format!("bidder-{i:02}"),
                "slot {i} should go to the {i}-th highest bid"
            );
        }
        // And each pays the Lean threshold: the k-th highest of the OTHERS,
        // which for a winner is the (k+1)-th highest overall.
        let expected = lean_slot_threshold(slots, &values[1..]);
        assert_eq!(
            price.get(),
            expected,
            "at {slots} slot(s) the price must be the Lean slotThreshold"
        );
        assert_eq!(
            price.get(),
            values[slots],
            "which is the (k+1)-th highest bid"
        );
    }
}

/// NON-VACUITY for the parity test above: the threshold must actually MOVE with
/// the slot count. A kernel that charged a constant would satisfy a check
/// written against a single `k`.
#[test]
fn the_threshold_moves_with_the_slot_count() {
    let values: [u64; 6] = [100, 85, 70, 55, 40, 25];
    let prices: Vec<u64> = (1..=5)
        .map(|slots| lean_slot_threshold(slots, &values[1..]))
        .collect();
    assert_eq!(prices, vec![85, 70, 55, 40, 25]);
    assert!(
        prices.windows(2).all(|w| w[0] > w[1]),
        "more supply must mean a strictly lower price here: {prices:?}"
    );
}

/// Truthfulness at every slot count, not just at one. `multi_unit_truthful` is
/// stated for all `k`, so the check is too.
#[test]
fn no_misreport_beats_the_truth_at_any_slot_count() {
    let others = [90u64, 70, 50, 30];
    for slots in 1usize..=4 {
        for true_value in [20u64, 45, 60, 80, 95] {
            let truthful = utility_at_slots(slots, true_value, &others, true_value);
            for report in [1u64, 25, 55, 75, 99] {
                let misreport = utility_at_slots(slots, report, &others, true_value);
                assert!(
                    misreport <= truthful,
                    "at {slots} slot(s), reporting {report} instead of {true_value} \
                     paid {misreport} > {truthful}"
                );
            }
        }
    }
}

fn utility_at_slots(slots: usize, report: u64, others: &[u64], true_value: u64) -> i128 {
    let mut round = Round::open_with_slots(
        AuctionId::new("r"),
        EGRESS,
        NonZeroU32::new(slots as u32).expect("slots ≥ 1"),
    );
    round.submit(bid("me", report, EGRESS)).expect("admitted");
    for (i, v) in others.iter().enumerate() {
        round
            .submit(bid(&format!("other-{i}"), *v, EGRESS))
            .expect("admitted");
    }
    let outcome = VcgClearing.clear(&round).expect("clears");
    let me = nucleus_econ_types::AgentId::new("me");
    match &outcome {
        RoundOutcome::Cleared { price, .. } if outcome.won(&me) => {
            i128::from(true_value) - i128::from(price.get())
        }
        _ => 0,
    }
}
