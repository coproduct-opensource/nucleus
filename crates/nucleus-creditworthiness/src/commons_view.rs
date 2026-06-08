//! Recompute-verifiable commons-ledger accounting **view** — "watch the money
//! fund the fix", checkable by anyone.
//!
//! This is a pure, deterministic, read-only projection over recompute-verified
//! `Commons` clearing receipts: it sums the externality dues that were *actually*
//! routed to the commons, per destination and in total. It is the auditor's lens
//! on the social-good claim — the marketplace prices the true cost (Pigouvian)
//! and routes the revenue to fixing it (`route_to_commons`), and THIS view lets
//! a third party re-derive, from the same receipts, exactly how much reached each
//! remediation destination.
//!
//! # Why it is trustworthy (recompute-gated, not claim-trusting)
//!
//! The view does **not** trust a receipt's *claimed* `allocations`. For every
//! receipt it calls [`nucleus_recompute::verify_receipt`], which re-runs the
//! proven [`route_to_commons`](nucleus_econ_kernels::route_to_commons) kernel
//! (pinned to `Commons.lean`'s `routed_conserves`) and compares. Only a receipt
//! that **recomputes** ([`RecomputeOutcome::Match`]) contributes to the routed
//! totals; a receipt whose claimed allocations diverge from the recomputed split
//! is a *dumped* externality — counted separately as `dumped_pool_micro`, never
//! as routed dues. So the routed figure can never be inflated by the very
//! mis-routing it is meant to catch.
//!
//! Because [`route_to_commons`] is conservation-exact (no skim: the allocations
//! sum to the pool — `routed_conserves`), the sum of the per-destination routed
//! amounts over all matched receipts equals the sum of their pools. Any verifier
//! replaying the same receipts recomputes the SAME [`CommonsLedgerView`]
//! (deterministic + order-independent — see the property tests), so the
//! social-good accounting is independently recompute-verifiable.
//!
//! # Honesty boundary (do NOT overclaim)
//!
//! * This proves dues were *routed* (the allocations are conservation-exact and
//!   match the proven split). It does NOT prove the destination *performed* the
//!   remediation — that the carbon-removal address really removed carbon. That
//!   last-mile attestation is an oracle problem (the same open frontier as
//!   measuring the externality itself); see `nucleus-econ-kernels`'s
//!   `commons` module docs.
//! * This accounts what *was* routed. It says nothing about whether the
//!   Pigouvian *rate* was correct — what the dues *should* be is a governed,
//!   contestable process, never a baked-in constant. See
//!   `docs/rfcs/regenerative-default-substrate.md`.
//! * No real money moves here. This is an accounting projection over receipts;
//!   actual settlement/custody is out of scope (operator-gated).

use std::collections::BTreeMap;

use nucleus_econ_kernels::route_to_commons;
use nucleus_recompute::{verify_receipt, ClearingReceipt, RecomputeOutcome};

/// Per-destination routed total, micro-USD — one row of the audit view.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DestinationRouted {
    /// Where the dues went (a chain address, a remediation program id, …).
    pub destination: String,
    /// Total micro-USD routed to this destination across all matched receipts.
    pub routed_micro: u128,
}

/// A recompute-verified accounting of externality dues routed to the commons.
///
/// Built by [`commons_ledger_view`] from a batch of `Commons` receipts. Every
/// figure is derived ONLY from receipts that recomputed, so the whole view is
/// independently re-derivable from the same receipts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommonsLedgerView {
    /// Per-destination routed totals, keyed by destination in canonical (sorted)
    /// order — so the view is order-independent and serde-stable.
    by_destination: BTreeMap<String, u128>,
    /// Number of `Commons` receipts that recomputed (Match) and were counted.
    matched_receipts: u64,
    /// Number of `Commons` receipts whose claimed allocations diverged from the
    /// recomputed split (Mismatch) — dues *claimed* but not faithfully routed.
    dumped_receipts: u64,
    /// Number of `Commons` receipts that were not well-formed (Invalid) — no
    /// baseline, so neither routed nor dumped.
    invalid_receipts: u64,
    /// Sum of pools over the *dumped* (Mismatch) receipts, micro-USD: dues that
    /// were claimed but, by recompute, not faithfully routed to the commons.
    dumped_pool_micro: u128,
}

impl CommonsLedgerView {
    /// Total micro-USD actually routed to the commons across all destinations.
    ///
    /// By `route_to_commons`'s no-skim conservation (`routed_conserves`), this
    /// equals the sum of the pools over the matched receipts — nothing is lost
    /// between "pool collected" and "routed to the commons".
    pub fn total_routed_micro(&self) -> u128 {
        self.by_destination.values().copied().sum()
    }

    /// The per-destination routed totals, in canonical (sorted-by-destination)
    /// order — the audit rows.
    pub fn destinations(&self) -> Vec<DestinationRouted> {
        self.by_destination
            .iter()
            .map(|(destination, &routed_micro)| DestinationRouted {
                destination: destination.clone(),
                routed_micro,
            })
            .collect()
    }

    /// Micro-USD routed to a single destination (0 if it never appeared).
    pub fn routed_to(&self, destination: &str) -> u128 {
        self.by_destination
            .get(destination)
            .copied()
            .unwrap_or_default()
    }

    /// How many `Commons` receipts recomputed and were counted as routed.
    pub fn matched_receipts(&self) -> u64 {
        self.matched_receipts
    }

    /// How many `Commons` receipts were caught dumping (claimed ≠ recomputed).
    pub fn dumped_receipts(&self) -> u64 {
        self.dumped_receipts
    }

    /// How many `Commons` receipts were not well-formed (no baseline).
    pub fn invalid_receipts(&self) -> u64 {
        self.invalid_receipts
    }

    /// Sum of pools over the dumped (Mismatch) receipts: dues claimed but,
    /// by recompute, not faithfully routed to the commons.
    pub fn dumped_pool_micro(&self) -> u128 {
        self.dumped_pool_micro
    }
}

/// Build a [`CommonsLedgerView`] by recomputing a batch of clearing receipts.
///
/// Non-`Commons` receipts (`Settlement` / `Vcg`) are ignored — this view is the
/// commons-routing lens only. Each `Commons` receipt is re-verified:
///
/// * **Match** → its *recomputed* allocations (via the proven `route_to_commons`,
///   not the claimed ones) are folded into the per-destination routed totals;
/// * **Mismatch** → counted as a dumped externality (its pool added to
///   `dumped_pool_micro`), never as routed dues;
/// * **Invalid** → counted as not-well-formed; contributes nothing.
///
/// Pure + deterministic + order-independent: any verifier replaying the same
/// receipts in any order recomputes the same view.
pub fn commons_ledger_view(receipts: &[ClearingReceipt]) -> CommonsLedgerView {
    let mut view = CommonsLedgerView::default();
    for receipt in receipts {
        let claim = match receipt {
            ClearingReceipt::Commons(c) => c,
            // Not a commons-routing receipt — outside this view.
            _ => continue,
        };
        match verify_receipt(receipt) {
            RecomputeOutcome::Match => {
                // Recompute the split from the proven kernel and fold THAT in —
                // never the (now-verified-equal) claimed allocations, so the
                // routed figure is sourced from the proof, not the claim.
                match route_to_commons(claim.pool_micro, &claim.shares) {
                    Ok(allocations) => {
                        for alloc in allocations {
                            let entry = view
                                .by_destination
                                .entry(alloc.destination)
                                .or_insert(0u128);
                            *entry = entry.saturating_add(u128::from(alloc.amount_micro));
                        }
                        view.matched_receipts = view.matched_receipts.saturating_add(1);
                    }
                    // A Match guarantees the inputs were accepted by the kernel,
                    // so this arm is unreachable; fail closed to Invalid rather
                    // than panic on the impossible.
                    Err(_) => {
                        view.invalid_receipts = view.invalid_receipts.saturating_add(1);
                    }
                }
            }
            RecomputeOutcome::Mismatch { .. } => {
                view.dumped_receipts = view.dumped_receipts.saturating_add(1);
                view.dumped_pool_micro = view
                    .dumped_pool_micro
                    .saturating_add(u128::from(claim.pool_micro));
            }
            RecomputeOutcome::Invalid(_) => {
                view.invalid_receipts = view.invalid_receipts.saturating_add(1);
            }
        }
    }
    view
}

#[cfg(test)]
mod tests {
    use nucleus_econ_kernels::{classify, refund, route_to_commons, seller_gross, CommonsShare};
    use nucleus_recompute::{ClearingReceipt, CommonsClaim, SettlementClaim};

    use super::*;

    fn share(dest: &str, bps: u64) -> CommonsShare {
        CommonsShare {
            destination: dest.into(),
            bps,
        }
    }

    /// A genuinely-honest commons receipt: allocations computed by the SAME
    /// proven kernel recompute checks against, so the Match is real, not asserted.
    fn honest_commons(pool_micro: u64, shares: Vec<CommonsShare>) -> ClearingReceipt {
        let allocations = route_to_commons(pool_micro, &shares).unwrap();
        ClearingReceipt::Commons(CommonsClaim {
            pool_micro,
            shares,
            allocations,
        })
    }

    fn example_splits() -> Vec<CommonsShare> {
        vec![
            share("carbon-removal", 6_000),
            share("affected-party-rebate", 2_500),
            share("public-verifier-commons", 1_500),
        ]
    }

    #[test]
    fn routes_are_summed_per_destination_from_the_proof() {
        let receipts = vec![
            honest_commons(1_000_000, example_splits()),
            honest_commons(500_000, example_splits()),
        ];
        let view = commons_ledger_view(&receipts);
        assert_eq!(view.matched_receipts(), 2);
        assert_eq!(view.dumped_receipts(), 0);
        // 60% of 1.5M = 900k to carbon-removal.
        assert_eq!(view.routed_to("carbon-removal"), 900_000);
        assert_eq!(view.routed_to("affected-party-rebate"), 375_000);
        assert_eq!(view.routed_to("public-verifier-commons"), 225_000);
        // No skim: the total routed equals the sum of the pools (routed_conserves).
        assert_eq!(view.total_routed_micro(), 1_500_000);
        assert_eq!(view.dumped_pool_micro(), 0);
    }

    #[test]
    fn dumped_receipt_is_not_counted_as_routed() {
        // Valid shares, tampered allocations → recompute (route_to_commons)
        // catches it → counted as dumped, NOT as routed dues.
        let mut r = honest_commons(300_000, example_splits());
        if let ClearingReceipt::Commons(ref mut c) = r {
            c.allocations[0].amount_micro += 1; // dumped, not actually routed
        }
        let view = commons_ledger_view(&[r]);
        assert_eq!(view.matched_receipts(), 0);
        assert_eq!(view.dumped_receipts(), 1);
        assert_eq!(view.total_routed_micro(), 0);
        assert_eq!(view.dumped_pool_micro(), 300_000);
        assert_eq!(view.routed_to("carbon-removal"), 0);
    }

    #[test]
    fn invalid_receipt_contributes_nothing() {
        // Shares that don't sum to 10_000 → Invalid (no baseline).
        let bad = ClearingReceipt::Commons(CommonsClaim {
            pool_micro: 1_000,
            shares: vec![share("x", 9_999)],
            allocations: vec![],
        });
        let view = commons_ledger_view(&[bad]);
        assert_eq!(view.invalid_receipts(), 1);
        assert_eq!(view.matched_receipts(), 0);
        assert_eq!(view.total_routed_micro(), 0);
        assert_eq!(view.dumped_pool_micro(), 0);
    }

    #[test]
    fn non_commons_receipts_are_ignored() {
        let settlement = ClearingReceipt::Settlement(SettlementClaim {
            price_micro: 1_000_000,
            delivered_bps: 10_000,
            verdict: classify(10_000),
            seller_gross: seller_gross(1_000_000, 10_000),
            refund: refund(1_000_000, 10_000),
        });
        let view = commons_ledger_view(&[settlement, honest_commons(100_000, example_splits())]);
        // Only the commons receipt is in scope.
        assert_eq!(view.matched_receipts(), 1);
        assert_eq!(view.total_routed_micro(), 100_000);
    }

    #[test]
    fn conservation_total_routed_equals_sum_of_matched_pools() {
        // The auditable property: across destinations, total routed == sum of
        // matched pools (no skim) — for arbitrary pools and splits.
        for &pool in &[0u64, 1, 7, 13, 1_000_000, 9_999_999] {
            let view = commons_ledger_view(&[honest_commons(pool, example_splits())]);
            assert_eq!(view.total_routed_micro(), u128::from(pool));
        }
    }

    #[test]
    fn view_is_order_independent() {
        let a = honest_commons(700_000, example_splits());
        let b = honest_commons(300_000, example_splits());
        let mut dumped = honest_commons(50_000, example_splits());
        if let ClearingReceipt::Commons(ref mut c) = dumped {
            c.allocations[0].amount_micro += 1;
        }
        let forward = commons_ledger_view(&[a.clone(), b.clone(), dumped.clone()]);
        let reverse = commons_ledger_view(&[dumped, b, a]);
        // Any verifier, any order → the same view.
        assert_eq!(forward, reverse);
        assert_eq!(forward.total_routed_micro(), 1_000_000);
        assert_eq!(forward.dumped_pool_micro(), 50_000);
    }

    #[test]
    fn serde_round_trips() {
        let view = commons_ledger_view(&[honest_commons(123_456, example_splits())]);
        let json = serde_json::to_string(&view).unwrap();
        let back: CommonsLedgerView = serde_json::from_str(&json).unwrap();
        assert_eq!(view, back);
    }

    #[test]
    fn empty_batch_is_the_empty_view() {
        let view = commons_ledger_view(&[]);
        assert_eq!(view, CommonsLedgerView::default());
        assert_eq!(view.total_routed_micro(), 0);
        assert!(view.destinations().is_empty());
    }
}
