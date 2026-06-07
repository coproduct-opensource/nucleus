//! Mint [`CreditEvent`]s directly from recompute-verified clearing receipts —
//! the bridge that closes the pipeline
//! `receipt → recompute → CreditEvent → CreditFile → required_bond`.
//!
//! The rule is the whole thesis in three lines:
//! * a receipt that **recomputes** ([`RecomputeOutcome::Match`]) is an honest
//!   outcome → a financial **credit**;
//! * a receipt that **diverges** ([`RecomputeOutcome::Mismatch`]) is a caught
//!   defection — the recompute IS the fraud proof → a financial **debit**;
//! * a malformed/un-recomputable receipt ([`RecomputeOutcome::Invalid`]) mints
//!   **nothing** — there is no established baseline to attribute, so it neither
//!   builds nor burns standing.
//!
//! The event's `weight_micro` is the receipt's economic magnitude taken from its
//! **declared inputs** (price / pool / budget), never a claimed output — so the
//! weight itself can't be inflated by the very lie being caught.

use nucleus_recompute::{content_hash_hex, verify_receipt, ClearingReceipt, RecomputeOutcome};

use crate::{CreditEvent, CreditFile};

/// The economic magnitude of a receipt, micro-USD, taken from its declared
/// inputs (sound regardless of any claimed-output lie).
pub fn economic_magnitude(receipt: &ClearingReceipt) -> u64 {
    match receipt {
        ClearingReceipt::Settlement(c) => c.price_micro,
        ClearingReceipt::Commons(c) => c.pool_micro,
        ClearingReceipt::Vcg(c) => c.budget_micro_usd,
    }
}

/// The receipt's content hash as raw bytes — the same `sha256` the lineage
/// edge's `content_hash_hex` commits to — used as the
/// [`CreditEvent::receipt_hash`] provenance binding.
pub fn receipt_hash(receipt: &ClearingReceipt) -> [u8; 32] {
    let hex_str = content_hash_hex(receipt);
    let mut out = [0u8; 32];
    // `content_hash_hex` is a sha256 hex digest → exactly 32 bytes. Decode
    // defensively: fail closed to all-zero rather than panic on the impossible.
    let _ = hex::decode_to_slice(hex_str.as_bytes(), &mut out);
    out
}

/// Mint a [`CreditEvent`] from one receipt by recomputing it. Returns `None`
/// for an [`RecomputeOutcome::Invalid`] receipt (nothing to attribute).
///
/// The receipt KIND chooses the creditworthiness dimension:
/// * a `Commons` receipt is the Pigouvian / `route_to_commons` path (pinned to
///   `Commons.lean`'s `routed_conserves`), so a recompute-**Match** is true-cost
///   dues actually routed to the commons → an **externality credit**, and a
///   **Mismatch** is a claimed-but-unrouted routing — an externality **dumped**
///   on the commons → an externality **debit**;
/// * a `Settlement` / `Vcg` receipt is the financial path → a financial credit on
///   Match, a caught-defection debit on Mismatch.
///
/// Both dimensions are now load-bearing on reputation (see
/// [`CreditDimension::is_active`]) — the substrate is regenerative by default:
/// recompute-verified commons-routing builds standing, exactly as honest
/// settlement does, and only ever from a receipt that already recomputed.
pub fn mint_event(receipt: &ClearingReceipt) -> Option<CreditEvent> {
    let weight = economic_magnitude(receipt);
    let hash = receipt_hash(receipt);
    let is_commons = matches!(receipt, ClearingReceipt::Commons(_));
    match verify_receipt(receipt) {
        RecomputeOutcome::Match if is_commons => {
            Some(CreditEvent::externality_internalized(weight, hash))
        }
        RecomputeOutcome::Match => Some(CreditEvent::honest_settlement(weight, hash)),
        RecomputeOutcome::Mismatch { .. } if is_commons => {
            Some(CreditEvent::externality_dumped(weight, hash))
        }
        RecomputeOutcome::Mismatch { .. } => Some(CreditEvent::caught_defection(weight, hash)),
        RecomputeOutcome::Invalid(_) => None,
    }
}

/// Mint events from a batch of receipts, skipping `Invalid` ones.
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
    use nucleus_econ_kernels::{classify, refund, route_to_commons, seller_gross, CommonsShare};
    use nucleus_recompute::{ClearingReceipt, CommonsClaim, SettlementClaim};
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
        assert_eq!(e.dimension, CreditDimension::FinancialDefault);
        assert_eq!(e.weight_micro, 1_000_000); // from price_micro (declared input)
        assert_eq!(e.receipt_hash, receipt_hash(&r));
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
        assert_eq!(e.weight_micro, 1_000_000);
        // It burns standing: stacked on prior honest history it lowers reputation.
        let f = CreditFile::from_events(&[CreditEvent::honest_settlement(1_000_000, [0u8; 32]), e]);
        assert_eq!(f.reputation_micro(), 0); // 1M credit − 1M debit
    }

    #[test]
    fn an_honest_commons_receipt_mints_an_externality_credit() {
        // The Pigouvian path: dues actually routed to the commons (recompute-Match)
        // build standing on the EXTERNALITY dimension — regenerative by default.
        let r = honest_commons(300_000);
        let e = mint_event(&r).expect("honest commons mints an event");
        assert_eq!(e.dimension, CreditDimension::Externality);
        assert_eq!(e.polarity, crate::Polarity::Credit);
        assert_eq!(e.weight_micro, 300_000); // pool_micro (declared input)
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
        assert_eq!(e.dimension, CreditDimension::Externality);
        assert_eq!(e.polarity, crate::Polarity::Debit);
        // Stacked on prior externality credit it lowers standing.
        let f = CreditFile::from_events(&[
            CreditEvent::externality_internalized(300_000, [0u8; 32]),
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
