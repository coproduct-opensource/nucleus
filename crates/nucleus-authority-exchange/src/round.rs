//! A round: one contended authority slot, the bids for it, and what came of it.
//!
//! # How many slots, and why the count is bounded by a theorem
//!
//! A round allocates `slots` identical units of one [`PermissionDimension`] to
//! **unit-demand** bidders — each bidder wants at most one.
//!
//! One slot was the only offer here until the regime was proved wider.
//! `IntegerVcgTruthful.lean::vickrey_truthful` covers single-good Vickrey;
//! `ThresholdTruthful.lean::multi_unit_truthful` now covers `k` identical slots,
//! by observing that both are the same theorem about a price threshold that does
//! not depend on the bid. With `k` units the threshold is the `k`-th highest of
//! the *other* bids, and `slot_threshold_one_is_max` pins that the single-slot
//! case is the classical mechanism unchanged.
//!
//! What is still NOT covered, and is not offered: **multi-unit demand**, a
//! bidder that values a second slot. That is VCG over a combinatorial domain,
//! where `VcgRevenueNonMonotone.lean` has a machine-checked witness that revenue
//! is not even monotone. A round admits one bid per bidder, so the type keeps
//! the mechanism inside the theorem.

use std::num::NonZeroU32;

use nucleus_econ_types::{AgentId, AuctionId, MicroUsd};
use nucleus_permission_market::PermissionDimension;
use nucleus_recompute::ClearingReceipt;

use crate::bid::SignedBid;

/// Who may bid at all, decided before any bid is read.
///
/// # The signature is the theorem's hypothesis
///
/// `ThresholdTruthful.lean::admitted_truthful` holds because admission is one
/// value shared by both arms of the comparison — it cannot depend on which bid
/// was submitted. Here that is not a convention to be checked in review: the
/// method is handed a [`AgentId`] and nothing else, so an implementation
/// **cannot** see a bid value to condition on. Standing, tier, allow-lists and
/// rate limits are all expressible; a bid-dependent gate is not.
///
/// This is the second of the two channels `docs/rfcs/reputation-weighted-clearing.md`
/// permits. The first — standing buying a cheaper bond — is proved by
/// `bonded_truthful` but not wired, because a bond that cannot be slashed is
/// theatre: condition 3 of `receipt-provenance-defection.md` is unmet.
pub trait Admission: Send + Sync {
    /// Whether `bidder` may take part at all.
    fn admits(&self, bidder: &AgentId) -> bool;
}

/// Everyone bids. The default, and the only honest one until standing is
/// durable enough to gate on.
#[derive(Debug, Default, Clone, Copy)]
pub struct AdmitAll;

impl Admission for AdmitAll {
    fn admits(&self, _bidder: &AgentId) -> bool {
        true
    }
}

/// A round in progress: a contended slot and the bids submitted for it.
#[derive(Debug, Clone)]
pub struct Round {
    id: AuctionId,
    dimension: PermissionDimension,
    /// Identical units on offer. Always ≥ 1: a round with nothing to allocate
    /// is not a round, and a `0` would make "win iff bid ≥ threshold" grant the
    /// slot to everyone, since every `MicroUsd` clears a threshold of zero.
    slots: NonZeroU32,
    bids: Vec<SignedBid>,
}

/// Why a bid was not admitted to a round.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmitError {
    /// The bid is for a different scarce good than this round allocates.
    #[error("round allocates {round:?}, bid is for {bid:?}")]
    WrongDimension {
        /// What this round is clearing.
        round: PermissionDimension,
        /// What the bid asked for.
        bid: PermissionDimension,
    },
    /// This bidder already has a bid in the round. `run_vcg` rejects duplicate
    /// bidders outright, so admitting two would turn a caller's mistake into a
    /// kernel error at clearing time, far from its cause.
    #[error("{bidder} has already bid in this round")]
    DuplicateBidder {
        /// The agent that bid twice.
        bidder: String,
    },
    /// The admission policy refused this bidder. Decided from identity alone —
    /// see [`Admission`].
    #[error("{bidder} is not admitted to this round")]
    NotAdmitted {
        /// The agent that was refused.
        bidder: String,
    },
}

impl Round {
    /// Open a round for one slot of `dimension` — the classical regime.
    #[must_use]
    pub fn open(id: AuctionId, dimension: PermissionDimension) -> Self {
        Round::open_with_slots(id, dimension, NonZeroU32::MIN)
    }

    /// Open a round for `slots` identical units of `dimension`.
    #[must_use]
    pub fn open_with_slots(
        id: AuctionId,
        dimension: PermissionDimension,
        slots: NonZeroU32,
    ) -> Self {
        Round {
            id,
            dimension,
            slots,
            bids: Vec::new(),
        }
    }

    /// How many identical units this round allocates.
    #[must_use]
    pub fn slots(&self) -> NonZeroU32 {
        self.slots
    }

    /// Admit a bid, with everyone eligible.
    ///
    /// # Errors
    ///
    /// [`AdmitError::WrongDimension`] or [`AdmitError::DuplicateBidder`].
    pub fn submit(&mut self, bid: SignedBid) -> Result<(), AdmitError> {
        self.submit_under(bid, &AdmitAll)
    }

    /// Admit a bid, subject to an [`Admission`] policy.
    ///
    /// # Errors
    ///
    /// [`AdmitError::WrongDimension`], [`AdmitError::DuplicateBidder`] or
    /// [`AdmitError::NotAdmitted`].
    pub fn submit_under(
        &mut self,
        bid: SignedBid,
        admission: &dyn Admission,
    ) -> Result<(), AdmitError> {
        // Checked first, and on the identity alone: a bidder that is not
        // admitted never enters the profile, so the clearing among the admitted
        // is the mechanism the theorem covers, unchanged.
        if !admission.admits(bid.bidder()) {
            return Err(AdmitError::NotAdmitted {
                bidder: bid.bidder().as_str().to_owned(),
            });
        }
        if bid.dimension() != self.dimension {
            return Err(AdmitError::WrongDimension {
                round: self.dimension,
                bid: bid.dimension(),
            });
        }
        if self.bids.iter().any(|b| b.bidder() == bid.bidder()) {
            return Err(AdmitError::DuplicateBidder {
                bidder: bid.bidder().as_str().to_owned(),
            });
        }
        self.bids.push(bid);
        Ok(())
    }

    /// The round's id.
    #[must_use]
    pub fn id(&self) -> &AuctionId {
        &self.id
    }

    /// The scarce good this round allocates.
    #[must_use]
    pub fn dimension(&self) -> PermissionDimension {
        self.dimension
    }

    /// The bids submitted so far.
    #[must_use]
    pub fn bids(&self) -> &[SignedBid] {
        &self.bids
    }

    /// Whether demand exceeds supply. A round with no more bidders than slots
    /// has no price to discover: everyone wins, nobody is displaced, and the
    /// Clarke pivot is zero. See [`RoundOutcome`].
    #[must_use]
    pub fn is_contested(&self) -> bool {
        self.bids.len() > self.slots.get() as usize
    }
}

/// What a round produced.
///
/// Three cases, not a `bool` and not an `Option`: "nobody wanted it", "one agent
/// wanted it" and "the market priced it" are different facts, and collapsing the
/// middle one into the last is how an auction comes to mean nothing. A caller
/// that treats [`RoundOutcome::Uncontested`] as a cleared price is reporting a
/// discovered price for a round in which nothing was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundOutcome {
    /// Demand exceeded supply. `price` is the Clarke pivot, and it is the SAME
    /// for every winner: with `k` identical units and unit demand the pivot is
    /// the `k+1`-th highest bid, which is what
    /// `ThresholdTruthful.lean::multi_unit_truthful` is stated at. A per-winner
    /// price would mean the mechanism had left that regime.
    Cleared {
        /// The agents that won a slot.
        winners: Vec<AgentId>,
        /// What each winner pays — one uniform price.
        price: MicroUsd,
        /// The declared inputs beside the claimed outputs, so a third party can
        /// re-derive the whole outcome with `nucleus_recompute::verify_receipt`.
        receipt: Box<ClearingReceipt>,
    },
    /// No more bidders than slots. Everyone takes a unit, and the price is zero
    /// because nobody was displaced: a VCG payment is the externality a winner
    /// imposes on others, and here there were none. Whether a free grant is
    /// acceptable is a policy question for the caller (a reserve price), not a
    /// question the mechanism answers.
    Uncontested {
        /// Every bidder, each of which took a unit.
        winners: Vec<AgentId>,
        /// The receipt for the degenerate clearing, which still recomputes.
        receipt: Box<ClearingReceipt>,
    },
    /// The fallback screen allocated the slot. There is **no receipt**, and the
    /// missing field is the claim: the Lagrangian λ curve is a heuristic with no
    /// truthfulness property and nothing a third party could re-derive. A caller
    /// holding this variant knows it has a price and not a discovered one.
    PostedPrice {
        /// The agents that took a slot.
        winners: Vec<AgentId>,
        /// What it pays — its own bid, since a posted price grants at the asking
        /// value.
        price: MicroUsd,
    },
    /// Nobody bid. There is nothing to allocate and nothing to price.
    NoBids,
}

impl RoundOutcome {
    /// Everyone that took a unit.
    #[must_use]
    pub fn winners(&self) -> &[AgentId] {
        match self {
            Self::Cleared { winners, .. }
            | Self::Uncontested { winners, .. }
            | Self::PostedPrice { winners, .. } => winners,
            Self::NoBids => &[],
        }
    }

    /// Whether `agent` took a unit.
    #[must_use]
    pub fn won(&self, agent: &AgentId) -> bool {
        self.winners().iter().any(|w| w == agent)
    }

    /// What the winner pays. `Uncontested` is [`MicroUsd::ZERO`] by the
    /// mechanism, and `NoBids` has no payer.
    #[must_use]
    pub fn price(&self) -> Option<MicroUsd> {
        match self {
            Self::Cleared { price, .. } | Self::PostedPrice { price, .. } => Some(*price),
            Self::Uncontested { .. } => Some(MicroUsd::ZERO),
            Self::NoBids => None,
        }
    }

    /// The receipt, if the round produced one.
    ///
    /// `None` for [`RoundOutcome::PostedPrice`] is not a missing feature: that
    /// path runs a heuristic, and there is no declared-input recomputation that
    /// would make its number checkable.
    #[must_use]
    pub fn receipt(&self) -> Option<&ClearingReceipt> {
        match self {
            Self::Cleared { receipt, .. } | Self::Uncontested { receipt, .. } => Some(receipt),
            Self::PostedPrice { .. } | Self::NoBids => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bid::CertifiedCeiling;

    fn signed(agent: &str, value: u64, dim: PermissionDimension) -> SignedBid {
        SignedBid::new(
            AgentId::new(agent),
            dim,
            MicroUsd::new(value),
            CertifiedCeiling::for_test(1_000_000),
        )
        .expect("within ceiling")
    }

    #[test]
    fn a_bid_for_another_dimension_is_refused() {
        let mut r = Round::open(AuctionId::new("r1"), PermissionDimension::NetworkEgress);
        let err = r
            .submit(signed("a", 10, PermissionDimension::CommandExec))
            .expect_err("wrong good");
        assert!(matches!(err, AdmitError::WrongDimension { .. }));
        assert!(r.bids().is_empty(), "a refused bid must not be recorded");
    }

    /// `run_vcg` rejects duplicate bidders; catching it here keeps the error
    /// beside its cause instead of surfacing as a kernel rejection at clearing.
    #[test]
    fn the_same_bidder_cannot_bid_twice() {
        let mut r = Round::open(AuctionId::new("r1"), PermissionDimension::NetworkEgress);
        r.submit(signed("a", 10, PermissionDimension::NetworkEgress))
            .expect("first");
        let err = r
            .submit(signed("a", 99, PermissionDimension::NetworkEgress))
            .expect_err("second");
        assert!(matches!(err, AdmitError::DuplicateBidder { .. }));
        assert_eq!(r.bids().len(), 1);
    }

    #[test]
    fn contention_needs_two_agents() {
        let mut r = Round::open(AuctionId::new("r1"), PermissionDimension::NetworkEgress);
        assert!(!r.is_contested());
        r.submit(signed("a", 10, PermissionDimension::NetworkEgress))
            .expect("a");
        assert!(!r.is_contested(), "one bid is not a contest");
        r.submit(signed("b", 20, PermissionDimension::NetworkEgress))
            .expect("b");
        assert!(r.is_contested());
    }

    /// Admission is decided on identity alone, so it cannot distort bidding
    /// among the admitted — which is the hypothesis
    /// `ThresholdTruthful.lean::admitted_truthful` is stated under.
    #[test]
    fn admission_refuses_on_identity_and_the_bid_never_enters() {
        struct OnlyA;
        impl Admission for OnlyA {
            fn admits(&self, bidder: &AgentId) -> bool {
                bidder.as_str() == "a"
            }
        }
        let mut r = Round::open(AuctionId::new("r1"), PermissionDimension::NetworkEgress);
        r.submit_under(signed("b", 999, PermissionDimension::NetworkEgress), &OnlyA)
            .expect_err("b is not admitted");
        assert!(
            r.bids().is_empty(),
            "a refused bidder must not be in the profile at all — if it were, its \
             value would enter the clearing it was excluded from"
        );
        r.submit_under(signed("a", 10, PermissionDimension::NetworkEgress), &OnlyA)
            .expect("a is admitted");
        assert_eq!(r.bids().len(), 1);
    }

    /// The default admits everyone, because standing is not yet durable enough
    /// to gate on.
    #[test]
    fn the_default_admission_refuses_nobody() {
        assert!(AdmitAll.admits(&AgentId::new("anyone")));
    }

    #[test]
    fn no_bids_has_no_winner_no_price_and_no_receipt() {
        let o = RoundOutcome::NoBids;
        assert!(o.winners().is_empty());
        assert!(o.price().is_none());
        assert!(o.receipt().is_none());
    }
}
