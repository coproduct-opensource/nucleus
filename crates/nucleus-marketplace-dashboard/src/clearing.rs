//! The pricing / allocation seam — the third pillar (efficient & truthful
//! commerce), alongside the [`crate::Facilitator`] settlement seam.
//!
//! Today the marketplace is fixed-price: each call pays a static base price. This
//! trait is where **verified mechanism design** drops in later, exactly the way
//! the real `X402Facilitator` drops into [`crate::Facilitator`]:
//!
//! - **`FixedPriceClearing`** (here, the honest default) — price = base, no
//!   externality. No price discovery.
//! - **`PigouvianClearing`** (future) — adds a surcharge that internalises the
//!   externality a call imposes (risk / congestion), derived from the IFC
//!   verdict's `externality_signal`. Turns the gate's binary allow/deny into a
//!   *priced* gradient on the safe slope.
//! - **`VcgClearing`** (future) — clears a *contended* resource truthfully. VCG
//!   needs the whole bid profile, which is why [`Clearing::clear`] takes a
//!   **slice of bids** and returns one outcome per bid. The current per-call
//!   loop passes a single-element slice (the degenerate no-contention case); a
//!   future round-batching orchestrator passes the full profile. The clearing
//!   rule will run the **exact** sorry-free Lean-proven VCG function, and the
//!   price is folded into the receipt so truthfulness is independently
//!   re-derivable (the "provably-honest clearing" artifact).
//!
//! Honesty: only `FixedPriceClearing` is implemented today; the others are the
//! roadmap. The [`crate::event::MarketEvent::Settlement`] carries the
//! [`crate::event::ClearingMethod`] so the UI never implies VCG/Pigou pricing
//! that isn't actually running.

use crate::event::{AgentId, ClearingMethod, MicroUsd};

/// One agent's bid for a (possibly contended) resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bid {
    /// The bidding agent.
    pub agent: AgentId,
    /// The resource being bid for.
    pub resource: String,
    /// The agent's base / reserve price.
    pub base_price: MicroUsd,
    /// A measure of the externality this call imposes on the shared system
    /// (e.g. derived from the IFC verdict — number/sensitivity of declared
    /// inputs, shared-budget congestion). `FixedPriceClearing` ignores it; a
    /// Pigouvian/VCG mechanism prices it.
    pub externality_signal: u32,
}

/// The cleared result for one bid: what the agent pays, the Pigouvian component
/// of that price, and which mechanism produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingOutcome {
    /// The price the agent pays (settled amount).
    pub price: MicroUsd,
    /// The externality (Pigouvian) component of `price`. `0` for fixed-price.
    pub externality: MicroUsd,
    /// The mechanism that priced this bid.
    pub method: ClearingMethod,
}

/// Prices and allocates a set of bids. Implementations range from the trivial
/// fixed-price pass-through to a verified VCG clearing rule.
pub trait Clearing: Send + Sync {
    /// Clear `bids`, returning exactly one [`ClearingOutcome`] per input bid (in
    /// order). A single-element slice is the degenerate no-contention case used
    /// by the current per-call loop; VCG/Pigou mechanisms use the full profile.
    fn clear(&self, bids: &[Bid]) -> Vec<ClearingOutcome>;

    /// The mechanism this clearing implements.
    fn method(&self) -> ClearingMethod;
}

/// The honest default: every bid pays its own base price; no externality, no
/// price discovery. Behaviourally identical to the pre-clearing fixed-price flow.
#[derive(Debug, Default, Clone, Copy)]
pub struct FixedPriceClearing;

impl Clearing for FixedPriceClearing {
    fn clear(&self, bids: &[Bid]) -> Vec<ClearingOutcome> {
        bids.iter()
            .map(|b| ClearingOutcome {
                price: b.base_price,
                externality: MicroUsd(0),
                method: ClearingMethod::FixedPrice,
            })
            .collect()
    }

    fn method(&self) -> ClearingMethod {
        ClearingMethod::FixedPrice
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(agent: &str, price: i64, ext: u32) -> Bid {
        Bid {
            agent: AgentId::from(agent),
            resource: "/v1/x".into(),
            base_price: MicroUsd(price),
            externality_signal: ext,
        }
    }

    #[test]
    fn fixed_price_passes_base_through_with_zero_externality() {
        let c = FixedPriceClearing;
        let out = c.clear(&[bid("a", 10_000, 3), bid("b", 20_000, 1)]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].price, MicroUsd(10_000));
        assert_eq!(out[0].externality, MicroUsd(0));
        assert_eq!(out[0].method, ClearingMethod::FixedPrice);
        assert_eq!(out[1].price, MicroUsd(20_000));
        assert_eq!(c.method(), ClearingMethod::FixedPrice);
    }

    #[test]
    fn empty_profile_clears_to_nothing() {
        assert!(FixedPriceClearing.clear(&[]).is_empty());
    }
}
