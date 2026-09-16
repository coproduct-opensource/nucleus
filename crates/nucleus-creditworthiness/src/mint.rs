//! Mint [`CreditEvent`]s from recompute-verified clearing receipts — the bridge
//! that closes the pipeline
//! `receipt → recompute → CreditEvent → CreditFile → required_bond`.
//!
//! The rule is the whole thesis in three lines:
//! * a receipt that **recomputes** is an honest outcome → a **credit**;
//! * a receipt that **diverges** is a caught defection — the recompute IS the
//!   fraud proof → a **debit**;
//! * a malformed/un-recomputable receipt mints **nothing** — there is no
//!   established baseline to attribute, so it neither builds nor burns standing.
//!
//! # What changed when the type was sealed
//!
//! This module used to compute the weight and the provenance hash ITSELF and
//! hand them to a public `CreditEvent::test_honest_settlement(weight, hash)`. The
//! recompute and the mint were two separate steps, and only convention kept the
//! weight passed to the second one equal to the receipt checked by the first.
//! Any other crate could skip straight to step two.
//!
//! Now [`nucleus_recompute::witness_receipt`] mints a sealed witness that
//! carries both, and [`CreditEvent`] has no other constructor. The weight is the
//! one the recompute measured, structurally — not by agreement.

use nucleus_recompute::{ClearingReceipt, RecomputeWitness, witness_receipt};

use crate::{CreditEvent, CreditFile};

/// Mint a [`CreditEvent`] from a sealed recompute witness, however that witness
/// was obtained — a bare receipt, a signed envelope, or a countersigned one.
///
/// The single decider for "which witness means which event" (**G-1**). A caller
/// holding a witness from a two-party envelope mints through this same function,
/// so the countersigned path cannot drift from the bare one.
pub fn mint_from_witness(witness: &RecomputeWitness) -> Option<CreditEvent> {
    match witness {
        RecomputeWitness::Matched(m) => Some(CreditEvent::from_match(m)),
        RecomputeWitness::Diverged(d) => Some(CreditEvent::from_divergence(d)),
        RecomputeWitness::Invalid(_) => None,
    }
}

/// Mint a [`CreditEvent`] from one receipt by recomputing it. Returns `None` for
/// a receipt whose declared inputs the kernel rejects (nothing to attribute).
pub fn mint_event(receipt: &ClearingReceipt) -> Option<CreditEvent> {
    mint_from_witness(&witness_receipt(receipt))
}

/// Mint events from a batch of receipts, skipping un-recomputable ones.
pub fn mint_events(receipts: &[ClearingReceipt]) -> Vec<CreditEvent> {
    receipts.iter().filter_map(mint_event).collect()
}

/// Build a [`CreditFile`] directly from recompute-verified receipts — the whole
/// pipeline in one call. Order-independent (inherited from [`CreditFile`]).
pub fn credit_file_from_receipts(receipts: &[ClearingReceipt]) -> CreditFile {
    CreditFile::from_events(&mint_events(receipts))
}

#[cfg(test)]
mod tests {
    use nucleus_econ_kernels::{CommonsShare, classify, refund, route_to_commons, seller_gross};
    use nucleus_recompute::{
        ClearingReceipt, CommonsClaim, RecomputeOutcome, SettlementClaim, receipt_hash_bytes,
        verify_receipt,
    };
    use nucleus_witness_olog::AmountMicro;

    use super::*;
    use crate::CreditDimension;

    /// A genuinely-honest settlement receipt: outputs computed by the SAME proven
    /// kernels recompute checks against, so the Match is real, not asserted.
    fn honest_settlement(price_micro: u64, delivered_bps: u64) -> ClearingReceipt {
        ClearingReceipt::Settlement(SettlementClaim {
            price_micro,
            delivered_bps,
            verdict: classify(delivered_bps),
            seller_gross: seller_gross(price_micro, delivered_bps),
            refund: refund(price_micro, delivered_bps),
        })
    }

    fn honest_commons(pool_micro: u64) -> ClearingReceipt {
        let shares = vec![
            CommonsShare {
                destination: "commons".into(),
                bps: 7_000,
            },
            CommonsShare {
                destination: "ops".into(),
                bps: 3_000,
            },
        ];
        let allocations = route_to_commons(pool_micro, &shares).unwrap();
        ClearingReceipt::Commons(CommonsClaim {
            pool_micro,
            shares,
            allocations,
        })
    }

    #[test]
    fn honest_receipt_mints_a_financial_credit() {
        let r = honest_settlement(1_000_000, 10_000);
        let e = mint_event(&r).expect("honest receipt mints an event");
        assert_eq!(e.dimension(), CreditDimension::FinancialDefault);
        assert_eq!(e.weight_micro(), 1_000_000); // from price_micro (declared input)
        assert_eq!(e.receipt_hash(), receipt_hash_bytes(&r));
        // It builds standing: a file of just this event has positive reputation.
        let f = CreditFile::from_events(&[e]);
        assert_eq!(f.reputation_micro(), 1_000_000);
    }

    #[test]
    fn a_mismatched_receipt_mints_a_caught_defection() {
        // Tamper the seller_gross — recompute will catch it.
        let mut r = honest_settlement(1_000_000, 10_000);
        if let ClearingReceipt::Settlement(ref mut c) = r {
            c.seller_gross += 1;
        }
        assert!(!verify_receipt(&r).is_match());
        let e = mint_event(&r).expect("a caught lie still mints an event (a debit)");
        // Weight is the DECLARED price, not the inflated claim — the lie can't
        // inflate its own penalty's magnitude.
        assert_eq!(e.weight_micro(), 1_000_000);
        // It burns standing: stacked on prior honest history it lowers reputation.
        let f = CreditFile::from_events(&[
            CreditEvent::test_honest_settlement(1_000_000, [0u8; 32]),
            e,
        ]);
        assert_eq!(f.reputation_micro(), 0); // 1M credit − 1M debit
    }

    #[test]
    fn an_honest_commons_receipt_mints_an_externality_credit() {
        // The Pigouvian path: dues actually routed to the commons (recompute-Match)
        // build standing on the EXTERNALITY dimension — regenerative by default.
        let r = honest_commons(300_000);
        let e = mint_event(&r).expect("honest commons mints an event");
        assert_eq!(e.dimension(), CreditDimension::Externality);
        assert_eq!(e.polarity(), crate::Polarity::Credit);
        assert_eq!(e.weight_micro(), 300_000); // pool_micro (declared input)
        // It builds bond-substituting reputation now that externality is active.
        let f = CreditFile::from_events(&[e]);
        assert_eq!(f.reputation_micro(), 300_000);
    }

    #[test]
    fn a_mismatched_commons_receipt_mints_an_externality_debit() {
        // Claimed-but-unrouted dues: valid shares, tampered allocations →
        // recompute (route_to_commons) catches it → an externality DUMPED debit.
        let mut r = honest_commons(300_000);
        if let ClearingReceipt::Commons(ref mut c) = r {
            c.allocations[0].amount_micro += 1; // dumped, not actually routed
        }
        assert!(!verify_receipt(&r).is_match());
        let e = mint_event(&r).expect("a caught dump still mints an event (a debit)");
        assert_eq!(e.dimension(), CreditDimension::Externality);
        assert_eq!(e.polarity(), crate::Polarity::Debit);
        // Stacked on prior externality credit it lowers standing.
        let f = CreditFile::from_events(&[
            CreditEvent::test_externality_internalized(300_000, [0u8; 32]),
            e,
        ]);
        assert_eq!(f.reputation_micro(), 0); // 300k credit − 300k debit
    }

    #[test]
    fn an_invalid_receipt_mints_nothing() {
        // Commons shares that don't sum to 10_000 → Invalid (no baseline).
        let bad = ClearingReceipt::Commons(CommonsClaim {
            pool_micro: 1_000,
            shares: vec![CommonsShare {
                destination: "x".into(),
                bps: 9_999,
            }],
            allocations: vec![],
        });
        assert!(matches!(verify_receipt(&bad), RecomputeOutcome::Invalid(_)));
        assert_eq!(mint_event(&bad), None);
    }

    #[test]
    fn full_pipeline_receipts_to_required_bond() {
        // Three honest receipts (settlement + commons) → credit file → bond.
        let receipts = vec![
            honest_settlement(400_000, 10_000),
            honest_commons(300_000),
            honest_settlement(0, 5_000), // a low-delivery settlement, price 0
        ];
        let file = credit_file_from_receipts(&receipts);
        // reputation sums BOTH active dimensions: 400k+0 financial (settlements)
        // + 300k externality (commons pool) = 700k.
        assert_eq!(file.reputation_micro(), 700_000);
        // 700k of recompute-verified history covers 700k of a 1M defection gain.
        assert_eq!(file.required_bond(1_000_000), AmountMicro(300_000));
        assert_eq!(file.event_count(), 3);
    }

    #[test]
    fn invalid_receipts_are_skipped_in_a_batch() {
        let bad = ClearingReceipt::Commons(CommonsClaim {
            pool_micro: 1,
            shares: vec![CommonsShare {
                destination: "x".into(),
                bps: 1,
            }],
            allocations: vec![],
        });
        let receipts = vec![honest_settlement(500_000, 10_000), bad];
        let evs = mint_events(&receipts);
        assert_eq!(evs.len(), 1); // the Invalid one is dropped
        assert_eq!(
            credit_file_from_receipts(&receipts).reputation_micro(),
            500_000
        );
    }
}
