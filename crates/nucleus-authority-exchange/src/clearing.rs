//! The mechanism seam: how a round's bids become an allocation and a price.
//!
//! One implementation: [`VcgClearing`] runs the proven kernel and emits a
//! receipt that a stranger can re-derive. A `PostedPriceClearing` adapter over
//! the Lagrangian screen used to sit beside it as a fallback; it was deleted
//! when `PermissionBid` became constructible only from a verified certificate
//! (#2526), because the adapter built one by struct literal — and because the
//! proxy already runs that screen itself on the non-auctioned path, so a second
//! copy here was a second decider for the same fact (G-1). A round is cleared
//! by the mechanism or not at all.
//!
//! The seam mirrors `nucleus-marketplace-dashboard`'s `Clearing` trait, which
//! was written with the same intent and the same honesty note ("only
//! `FixedPriceClearing` is implemented today… so the UI never implies VCG/Pigou
//! pricing that isn't actually running").

use nucleus_econ_kernels::{IntegerBid, IntegerProposal, VcgError};
use nucleus_econ_types::{AgentId, MicroUsd};
// No `nucleus_permission_market` import survives the merge: `PermissionBid`,
// `PermissionMarket` and `TrustTier` came with `PostedPriceClearing`, which
// this branch deleted (G-1), and the slot id now keys on `ScarceGood`.
use crate::good::ScarceGood;
use nucleus_recompute::ClearingReceipt;

use crate::round::{Round, RoundOutcome};

/// The proposal id prefix. One proposal per round is what makes `run_vcg`
/// reduce to the threshold mechanism — see [`crate::Round`].
const SLOT_PREFIX: &str = "authority-slot/";

/// The proposal id for a round: the prefix plus the good's label.
///
/// The good is part of the id **on purpose**: the proposal is a declared
/// input, so it is under the receipt's content hash, so the receipt says what
/// was auctioned. A receipt that only said "a slot" could not be attributed to
/// egress or exec afterwards, and an index over receipts — the price of egress
/// this week — would have to trust a label kept somewhere the hash does not
/// reach. [`slot_good`] is the inverse, and a reader with only the receipt uses
/// it to recover the good.
///
/// Keyed on [`ScarceGood`] rather than on `PermissionDimension`, because a
/// round carries a good and not every scarce good is a permission — that is
/// what `good.rs` is for. A `PermissionDimension` still reaches this through
/// its `From` impl, so nothing that auctions a permission dimension changed.
#[must_use]
pub fn slot_id(good: &ScarceGood) -> String {
    format!("{SLOT_PREFIX}{}", good.label())
}

/// Recover the good a receipt's proposal names, or `None` for a proposal this
/// crate did not issue or whose label is not a good this crate would mint.
#[must_use]
pub fn slot_good(proposal_id: &str) -> Option<ScarceGood> {
    let label = proposal_id.strip_prefix(SLOT_PREFIX)?;
    ScarceGood::new(label).ok()
}

/// Why a round could not be cleared.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClearError {
    /// The proven kernel rejected the declared inputs.
    #[error("VCG kernel rejected the round: {0}")]
    Kernel(#[from] VcgError),
    /// The kernel allocated the slot to nobody despite admissible bids. Not
    /// reachable through this crate's inputs (one zero-cost proposal, a
    /// zero budget, every bid strictly positive) — surfaced rather than
    /// unwrapped so a future change to those inputs cannot turn a silent
    /// no-allocation into a panic.
    #[error("the kernel allocated the slot to nobody")]
    NoAllocation,
    /// `issue_vcg` returned a receipt that is not a VCG receipt. Structurally
    /// impossible today; refused rather than assumed (A-1).
    #[error("expected a VCG clearing receipt")]
    WrongReceiptKind,
    /// Winners were charged different prices. With identical units and unit
    /// demand the Clarke pivot is the same for every winner, so a spread means
    /// the clearing is outside the regime
    /// `ThresholdTruthful.lean::multi_unit_truthful` covers — refused rather
    /// than reported as if it were that mechanism.
    #[error("winners were not charged a uniform price")]
    NonUniformPrice,
}

/// Prices and allocates one round's bids.
pub trait Clearing {
    /// Clear the round.
    ///
    /// # Errors
    ///
    /// [`ClearError`] if the kernel rejects the declared inputs.
    fn clear(&self, round: &Round) -> Result<RoundOutcome, ClearError>;
}

/// The proven mechanism: single-good Vickrey via `run_vcg`, with the Clarke
/// pivot as the price and a recomputable receipt as the record.
///
/// Truthfulness here is not an aspiration. `IntegerVcgTruthful.lean::vickrey_truthful`
/// proves that no misreport improves a bidder's utility, and `run_vcg`'s own
/// `homogeneous_proposal_classical_vickrey` test pins the reduction this clearing
/// relies on. What makes that property *mean* something at runtime is that the
/// price is charged: a bid that costs nothing to inflate is not a bid, which is
/// why the live path debits the pivot against the budget ledger.
#[derive(Debug, Default, Clone, Copy)]
pub struct VcgClearing;

impl Clearing for VcgClearing {
    fn clear(&self, round: &Round) -> Result<RoundOutcome, ClearError> {
        if round.bids().is_empty() {
            return Ok(RoundOutcome::NoBids);
        }

        let bids: Vec<IntegerBid> = round
            .bids()
            .iter()
            .map(|b| IntegerBid {
                bidder: b.bidder().as_str().to_owned(),
                proposal_id: slot_id(round.dimension()),
                effective_value_micro_usd: b.value().get(),
            })
            .collect();
        // The slots, and the exclusivity comes from the budget — not from the
        // proposal being unique.
        //
        // `optimal_allocation` packs *bids* against the budget, so several bids
        // on the same proposal can all win if the budget admits them. A
        // zero-cost slot with a zero budget therefore makes every bidder a
        // winner who displaces nobody and pays nothing: an auction that charges
        // zero, which is a posted price at price zero wearing a theorem's name.
        // (Written that way first; the second-price test caught it.)
        //
        // A budget of `k · cost` with `cost ≥ 1` admits exactly `k` bids,
        // because the `k+1`-th no longer fits. That is the encoding `run_vcg`'s
        // own `homogeneous_proposal_classical_vickrey` property uses at k = 1,
        // and at any k it makes every winner's Clarke pivot the `k+1`-th
        // highest bid — the threshold
        // `ThresholdTruthful.lean::multi_unit_truthful` is stated at. The unit
        // is notional: authority is the scarce good, and SLOT_UNITS is one
        // indivisible unit of it, not a price.
        const SLOT_UNITS: u64 = 1;
        let slots = u64::from(round.slots().get());
        let proposals = vec![IntegerProposal {
            id: slot_id(round.dimension()),
            cost_micro_usd: SLOT_UNITS,
        }];

        let receipt = nucleus_recompute::issue_vcg(bids, proposals, slots * SLOT_UNITS)?;
        let ClearingReceipt::Vcg(ref claim) = receipt else {
            return Err(ClearError::WrongReceiptKind);
        };
        // `first()` rather than `[0]` behind an emptiness check: the check and
        // the index are two places that have to agree about the same fact, and
        // only one of them is in the type.
        let head = claim
            .clearing
            .winners
            .first()
            .ok_or(ClearError::NoAllocation)?;
        // Every winner pays the same pivot in this regime. Checked rather than
        // assumed: a per-winner price would mean the kernel had left the regime
        // the theorem covers, and silently pricing the first winner's pivot as
        // everyone's would hide that.
        let price = MicroUsd::new(head.vcg_payment_micro_usd);
        if claim
            .clearing
            .winners
            .iter()
            .any(|w| w.vcg_payment_micro_usd != price.get())
        {
            return Err(ClearError::NonUniformPrice);
        }
        let winners: Vec<AgentId> = claim
            .clearing
            .winners
            .iter()
            .map(|w| AgentId::new(w.bidder.clone()))
            .collect();

        Ok(if round.is_contested() {
            RoundOutcome::Cleared {
                winners,
                price,
                receipt: Box::new(receipt),
            }
        } else {
            RoundOutcome::Uncontested {
                winners,
                receipt: Box::new(receipt),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The good these tests contend for. A function rather than a `const`
    /// because a good owns its label; `PermissionDimension` is the source so
    /// the tests exercise the conversion the in-pod path uses.
    fn egress() -> ScarceGood {
        ScarceGood::from(nucleus_permission_market::PermissionDimension::NetworkEgress)
    }

    use crate::bid::{CertifiedCeiling, SignedBid};
    use crate::good::ScarceGood;
    use nucleus_econ_types::AuctionId;
    use nucleus_recompute::{RecomputeOutcome, verify_receipt};

    fn round_of(values: &[(&str, u64)]) -> Round {
        let mut r = Round::open(AuctionId::new("r1"), egress());
        for (agent, v) in values {
            r.submit(
                SignedBid::new(
                    AgentId::new(*agent),
                    egress(),
                    MicroUsd::new(*v),
                    CertifiedCeiling::for_test(1_000_000),
                )
                .expect("within ceiling"),
            )
            .expect("admitted");
        }
        r
    }

    /// NON-VACUITY, and it is written first on purpose. If a round is not
    /// contested there is no price to discover, and an "auction" that only ever
    /// sees one bidder is a posted price wearing a theorem's name.
    #[test]
    fn an_uncontested_round_is_not_reported_as_a_cleared_price() {
        let out = VcgClearing.clear(&round_of(&[("a", 100)])).expect("clears");
        assert!(
            matches!(out, RoundOutcome::Uncontested { .. }),
            "one bidder must not produce Cleared: {out:?}"
        );
        assert_eq!(out.price(), Some(MicroUsd::ZERO), "nobody was displaced");
    }

    /// The property the whole crate is for: the winner pays the SECOND-highest
    /// bid, not its own. This is the Clarke pivot in the single-good regime and
    /// the reason truthful bidding is a dominant strategy.
    #[test]
    fn the_winner_pays_the_second_highest_bid() {
        let out = VcgClearing
            .clear(&round_of(&[("a", 100), ("b", 70), ("c", 40)]))
            .expect("clears");
        let RoundOutcome::Cleared { winners, price, .. } = &out else {
            panic!("three bidders is contested: {out:?}");
        };
        assert_eq!(winners.len(), 1, "one slot, one winner");
        assert_eq!(winners[0].as_str(), "a");
        assert_eq!(*price, MicroUsd::new(70));
    }

    /// The receipt is the product. A third party with only these bytes and the
    /// published kernel reaches the same verdict.
    #[test]
    fn the_receipt_recomputes() {
        let out = VcgClearing
            .clear(&round_of(&[("a", 100), ("b", 70)]))
            .expect("clears");
        let receipt = out.receipt().expect("a cleared round has a receipt");
        assert_eq!(verify_receipt(receipt), RecomputeOutcome::Match);
    }

    /// A-19 in miniature: the check above is only worth something if it can
    /// fail. Tamper with the claimed payment and the same verifier must reject.
    #[test]
    fn a_tampered_payment_fails_the_same_check() {
        let out = VcgClearing
            .clear(&round_of(&[("a", 100), ("b", 70)]))
            .expect("clears");
        let mut receipt = out.receipt().expect("receipt").clone();
        let ClearingReceipt::Vcg(ref mut claim) = receipt else {
            panic!("vcg receipt");
        };
        claim.clearing.winners[0].vcg_payment_micro_usd = 1;
        assert!(
            matches!(verify_receipt(&receipt), RecomputeOutcome::Mismatch { .. }),
            "a forged price must not verify"
        );
    }

    /// The receipt must say what was auctioned. A reader holding only the
    /// bytes recovers the good from the declared proposal — which is under
    /// the content hash — not from anything the hash does not cover.
    #[test]
    fn the_receipt_declares_which_good_was_sold() {
        let out = VcgClearing
            .clear(&round_of(&[("a", 100), ("b", 70)]))
            .expect("clears");
        let ClearingReceipt::Vcg(claim) = out.receipt().expect("receipt") else {
            panic!("vcg");
        };
        let ids: Vec<&str> = claim.proposals.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, [slot_id(&egress()).as_str()]);
        assert_eq!(slot_good(&claim.proposals[0].id), Some(egress()));
        // A good is whatever the operator named, not one of a fixed four, so
        // an unfamiliar label round-trips. What does not is a proposal that is
        // not a slot, or a label no `ScarceGood` can carry.
        assert_eq!(
            slot_good("authority-slot/ci-runner"),
            ScarceGood::new("ci-runner").ok()
        );
        assert_eq!(slot_good("authority-slot/"), None);
        assert_eq!(slot_good("something-else"), None);
    }

    #[test]
    fn an_empty_round_clears_to_nothing() {
        let r = Round::open(AuctionId::new("r1"), egress());
        assert_eq!(VcgClearing.clear(&r).expect("clears"), RoundOutcome::NoBids);
    }
}
