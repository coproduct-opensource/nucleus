//! A round: one contended authority slot, the bids for it, and what came of it.
//!
//! # One slot, on purpose
//!
//! A round allocates exactly **one** slot of one [`PermissionDimension`]. That is
//! not a simplification waiting to be lifted — it is the regime the truthfulness
//! theorem covers. `IntegerVcgTruthful.lean::vickrey_truthful` is about a
//! single-good Vickrey auction, and `run_vcg` reduces to classical second-price
//! exactly when every bid is on one proposal (its own
//! `homogeneous_proposal_classical_vickrey` test). Allocating *k* identical slots
//! is multi-unit VCG, which the shipped greedy allocator approximates and which
//! no theorem here covers, so the type does not offer it. Widening the regime is
//! a proof obligation before it is an API change.

use nucleus_econ_types::{AgentId, AuctionId, MicroUsd};
use nucleus_permission_market::PermissionDimension;
use nucleus_recompute::ClearingReceipt;

use crate::bid::SignedBid;

/// A round in progress: a contended slot and the bids submitted for it.
#[derive(Debug, Clone)]
pub struct Round {
    id: AuctionId,
    dimension: PermissionDimension,
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
}

impl Round {
    /// Open a round for one slot of `dimension`.
    #[must_use]
    pub fn open(id: AuctionId, dimension: PermissionDimension) -> Self {
        Round {
            id,
            dimension,
            bids: Vec::new(),
        }
    }

    /// Admit a bid.
    ///
    /// # Errors
    ///
    /// [`AdmitError::WrongDimension`] or [`AdmitError::DuplicateBidder`].
    pub fn submit(&mut self, bid: SignedBid) -> Result<(), AdmitError> {
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

    /// Whether more than one agent is competing. A round that is not contested
    /// has no price to discover — see [`RoundOutcome`].
    #[must_use]
    pub fn is_contested(&self) -> bool {
        self.bids.len() > 1
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
    /// Two or more agents competed. `price` is the Clarke pivot — under
    /// single-good Vickrey, the second-highest bid.
    Cleared {
        /// The agent that won the slot.
        winner: AgentId,
        /// What the winner pays.
        price: MicroUsd,
        /// The declared inputs beside the claimed outputs, so a third party can
        /// re-derive the whole outcome with `nucleus_recompute::verify_receipt`.
        receipt: Box<ClearingReceipt>,
    },
    /// Exactly one agent bid. It takes the slot, and the mechanism's price is
    /// zero because it displaced nobody: a VCG payment is the externality the
    /// winner imposes on others, and there were no others. Whether a free grant
    /// is acceptable is a policy question for the caller (a reserve price), not
    /// a question the mechanism answers.
    Uncontested {
        /// The only bidder.
        winner: AgentId,
        /// The receipt for the degenerate clearing, which still recomputes.
        receipt: Box<ClearingReceipt>,
    },
    /// The fallback screen allocated the slot. There is **no receipt**, and the
    /// missing field is the claim: the Lagrangian λ curve is a heuristic with no
    /// truthfulness property and nothing a third party could re-derive. A caller
    /// holding this variant knows it has a price and not a discovered one.
    PostedPrice {
        /// The agent that took the slot.
        winner: AgentId,
        /// What it pays — its own bid, since a posted price grants at the asking
        /// value.
        price: MicroUsd,
    },
    /// Nobody bid. There is nothing to allocate and nothing to price.
    NoBids,
}

impl RoundOutcome {
    /// The winner, if the round had one.
    #[must_use]
    pub fn winner(&self) -> Option<&AgentId> {
        match self {
            Self::Cleared { winner, .. }
            | Self::Uncontested { winner, .. }
            | Self::PostedPrice { winner, .. } => Some(winner),
            Self::NoBids => None,
        }
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

    #[test]
    fn no_bids_has_no_winner_no_price_and_no_receipt() {
        let o = RoundOutcome::NoBids;
        assert!(o.winner().is_none());
        assert!(o.price().is_none());
        assert!(o.receipt().is_none());
    }
}
