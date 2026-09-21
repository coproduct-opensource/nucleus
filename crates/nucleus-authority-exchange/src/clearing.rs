//! The mechanism seam: how a round's bids become an allocation and a price.
//!
//! Two implementations, and the difference between them is the point of this
//! crate. [`VcgClearing`] runs the proven kernel and emits a receipt that a
//! stranger can re-derive. [`PostedPriceClearing`] runs the Lagrangian screen
//! that is live on the tool-proxy hot path today, and emits **no receipt**,
//! because there is nothing to recompute — the λ curve is a heuristic with no
//! truthfulness property and no Lean statement. That absence is in the type
//! ([`RoundOutcome::PostedPrice`] has no receipt field), so a caller cannot
//! report a discovered, verifiable price for a round that had neither.
//!
//! The seam mirrors `nucleus-marketplace-dashboard`'s `Clearing` trait, which
//! was written with the same intent and the same honesty note ("only
//! `FixedPriceClearing` is implemented today… so the UI never implies VCG/Pigou
//! pricing that isn't actually running").

use nucleus_econ_kernels::{IntegerBid, IntegerProposal, VcgError};
use nucleus_econ_types::{AgentId, MicroUsd};
use nucleus_permission_market::{PermissionBid, PermissionMarket, TrustTier};
use nucleus_recompute::ClearingReceipt;

use crate::round::{Round, RoundOutcome};

/// The single slot every round allocates, as the kernel names it. One proposal
/// is what makes `run_vcg` reduce to classical second-price — see [`crate::Round`].
const SLOT: &str = "authority-slot";

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
                proposal_id: SLOT.to_owned(),
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
            id: SLOT.to_owned(),
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

/// The incumbent screen, kept as a fallback so a dimension can be moved back
/// without a deploy.
///
/// It prices each bid independently against the Lagrangian shadow price and
/// awards the contended slot to the highest-valued bid that clears it. Two
/// deliberate differences from the live `evaluate_permission_bid` path:
///
/// 1. **The trust tier is not taken from the bidder.** Today's header path reads
///    `trust_tier` out of the request and uses it to pick a discount factor as
///    low as 0.1× — a self-scored screen. This adapter always uses
///    [`TrustTier::Unverified`] (no discount). A tier belongs to a verified
///    certificate chain, and until it is read from one it is not an input.
/// 2. **No receipt.** There is nothing to recompute, and the outcome type says
///    so by having nowhere to put one.
#[derive(Debug, Default)]
pub struct PostedPriceClearing {
    market: PermissionMarket,
}

impl PostedPriceClearing {
    /// Wrap an existing market.
    #[must_use]
    pub fn new(market: PermissionMarket) -> Self {
        PostedPriceClearing { market }
    }
}

impl Clearing for PostedPriceClearing {
    fn clear(&self, round: &Round) -> Result<RoundOutcome, ClearError> {
        let mut admitted: Vec<&crate::bid::SignedBid> = Vec::new();
        for b in round.bids() {
            let grant = self.market.evaluate_bid(&PermissionBid {
                skill_id: b.bidder().as_str().to_owned(),
                requested: vec![b.dimension()],
                // Micro-USD as the abstract unit the market documents
                // (`value_estimate` is "an abstract unit — the orchestrator
                // calibrates what 1.0 means"). Converted losslessly through u32:
                // a bid above u32::MAX µUSD ($4 294) is clamped, which for a
                // screen that grants at the asking value changes nothing below
                // the clamp and nothing this crate would put a proof on above it.
                value_estimate: f64::from(u32::try_from(b.value().get()).unwrap_or(u32::MAX)),
                trust_tier: TrustTier::Unverified,
            });
            if grant.granted.is_empty() {
                continue;
            }
            admitted.push(b);
        }
        // Highest values take the slots. The screen's own price is an `f64`
        // cost; the slot's price is what the winner bid, because a posted price
        // grants at the asking value. Rounding a float into money is not
        // something this crate will do.
        admitted.sort_by_key(|b| std::cmp::Reverse(b.value()));
        admitted.truncate(round.slots().get() as usize);
        Ok(if admitted.is_empty() {
            RoundOutcome::NoBids
        } else {
            // The lowest admitted value, so the reported price is one every
            // winner actually cleared rather than the top bid alone.
            let price = admitted.last().map_or(MicroUsd::ZERO, |b| b.value());
            RoundOutcome::PostedPrice {
                winners: admitted.iter().map(|b| b.bidder().clone()).collect(),
                price,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bid::{CertifiedCeiling, SignedBid};
    use nucleus_econ_types::AuctionId;
    use nucleus_permission_market::PermissionDimension;
    use nucleus_recompute::{RecomputeOutcome, verify_receipt};

    const EGRESS: PermissionDimension = PermissionDimension::NetworkEgress;

    fn round_of(values: &[(&str, u64)]) -> Round {
        let mut r = Round::open(AuctionId::new("r1"), EGRESS);
        for (agent, v) in values {
            r.submit(
                SignedBid::new(
                    AgentId::new(*agent),
                    EGRESS,
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

    #[test]
    fn an_empty_round_clears_to_nothing() {
        let r = Round::open(AuctionId::new("r1"), EGRESS);
        assert_eq!(VcgClearing.clear(&r).expect("clears"), RoundOutcome::NoBids);
    }

    /// The fallback allocates, and carries no receipt — the absence is the
    /// honest signal, not an omission.
    #[test]
    fn the_posted_price_fallback_awards_without_a_receipt() {
        let c = PostedPriceClearing::new(PermissionMarket::new());
        let out = c
            .clear(&round_of(&[("a", 100), ("b", 70)]))
            .expect("clears");
        let RoundOutcome::PostedPrice { winners, price } = &out else {
            panic!("expected a posted price: {out:?}");
        };
        assert_eq!(winners.len(), 1, "one slot, one winner");
        assert_eq!(winners[0].as_str(), "a");
        assert_eq!(*price, MicroUsd::new(100));
        assert!(out.receipt().is_none(), "the screen recomputes nothing");
    }
}
