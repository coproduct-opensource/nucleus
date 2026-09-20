//! Truthful clearing of scarce agent authority.
//!
//! # The gap this closes
//!
//! Nucleus has a machine-checked auction mechanism and a heuristic one, and
//! until now the heuristic decided everything.
//!
//! `nucleus-econ-kernels` ships integer VCG under 2,620 lines of `sorry`-free
//! Lean — `IntegerVcgTruthful.lean::vickrey_truthful`,
//! `VcgPigouTruthful.lean::pigou_vickrey_truthful`,
//! `BudgetConservation.lean::greedyPack_le_budget` — with golden vectors sealed
//! across Lean, Rust, WASM and Solidity. In this repository nothing called it:
//! `run_vcg` ran only as a *verifier* of receipts produced elsewhere.
//!
//! Meanwhile the one auction-shaped thing on the live path,
//! `nucleus-permission-market`, is an `f64` Lagrangian screen —
//! `compute_lambda(u) = exp(3·(u−0.5)/0.5) − 1`, trust discounts 1.0/0.8/0.5/0.1
//! — with no cited derivation, no Lean, no Kani, and a `value_estimate` the
//! bidder self-reports with no incentive to be truthful. `FORMAL_METHODS.md`
//! files it as "Tested… a Lagrangian pricing oracle", which is accurate and is
//! not a mechanism.
//!
//! This crate wires the proven one to a decision: a round, a Clarke-pivot price,
//! and a receipt anyone can re-derive.
//!
//! # What a round is
//!
//! One contended slot of one [`nucleus_permission_market::PermissionDimension`],
//! bids from agents whose *principals* authorised the value, and an outcome that
//! distinguishes "the market priced this" from "one agent asked" from "nobody
//! did". See [`Round`] for why it is one slot and [`RoundOutcome`] for why that
//! distinction is three variants rather than an `Option`.
//!
//! ```
//! use nucleus_authority_exchange::{Clearing, Round, RoundOutcome, VcgClearing};
//! # use nucleus_authority_exchange::test_support::bid;
//! use nucleus_econ_types::{AuctionId, MicroUsd};
//! use nucleus_permission_market::PermissionDimension::NetworkEgress;
//!
//! let mut round = Round::open(AuctionId::new("egress-1"), NetworkEgress);
//! round.submit(bid("agent-a", 100, NetworkEgress)).unwrap();
//! round.submit(bid("agent-b", 70, NetworkEgress)).unwrap();
//!
//! let outcome = VcgClearing.clear(&round).unwrap();
//! // The winner pays the second-highest bid, not its own.
//! assert_eq!(outcome.winner().unwrap().as_str(), "agent-a");
//! assert_eq!(outcome.price(), Some(MicroUsd::new(70)));
//! // And the price is re-derivable from the receipt by someone who trusts
//! // neither the winner nor the operator.
//! assert_eq!(
//!     nucleus_recompute::verify_receipt(outcome.receipt().unwrap()),
//!     nucleus_recompute::RecomputeOutcome::Match,
//! );
//! ```
//!
//! # What this crate does not do
//!
//! It does not charge anyone. Truthfulness is a statement about a bidder's
//! *utility*, and a bid that costs nothing to inflate has no utility to reason
//! about — so the theorem means nothing until the pivot is debited against a
//! real budget. That debit is the live path's job
//! (`portcullis::budget_ledger`), and until it is wired this crate computes an
//! honest price for a bid nobody pays.
//!
//! It does not run a service, hold a key, or know a tenant — see
//! `docs/adr/0008-the-public-private-line.md`.
//!
//! # Why a win does not mint a certificate
//!
//! The obvious next step is to hand the winner an attenuated delegation
//! certificate with an expiry, minted through the path `verify_certificate`
//! already walks. It is the wrong artifact, for two reasons that are worth
//! recording so nobody re-derives them.
//!
//! **The exchange does not grant authority.** Every bidder already holds the
//! capability it is bidding for — that is where [`CertifiedCeiling`] comes from.
//! What is scarce is not the right but the *opportunity to exercise it*, and the
//! auction rations that. A certificate says "you may"; the winner could already.
//! Issuing one would overstate what happened, and `chain_attenuates` would be
//! guarding a hop that widens nothing.
//!
//! **The pod cannot mint its own authority.** The proxy runs inside the
//! workload. A certificate it signed for itself would be an agent granting
//! itself a capability, which inverts the trust model this repository exists to
//! hold: `exercised authority ≼ delegated authority` is a bound set by the
//! *principal*, upstream, not by the party exercising it.
//!
//! So a win is a decision about *this request*, recorded and charged. If a
//! future version wants a winner to hold a slot across several calls, the honest
//! primitive is a **lease** on a capability already held — not a certificate,
//! and not minted here.

#![forbid(unsafe_code)]
// A function whose type says `-> T` and panics is lying about its type, and this
// crate decides who may spend authority. Denied for the shipped build only:
// `assert!` IS a panic, so denying inside `#[cfg(test)]` would forbid the thing
// tests are made of. Same line `is_production_path` draws.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod bid;
pub mod clearing;
pub mod round;
pub mod scheduler;

pub use bid::{BidError, CertifiedCeiling, SignedBid};
pub use clearing::{ClearError, Clearing, PostedPriceClearing, VcgClearing};
pub use round::{AdmitError, Round, RoundOutcome};
pub use scheduler::{ChargeError, Charger, DenyReason, RoundScheduler, UnwiredCharger, Verdict};

/// Fixtures for doctests and downstream tests.
///
/// A [`CertifiedCeiling`] is deliberately unforgeable outside this crate — that
/// is the whole guarantee of [`bid`] — which would otherwise make every example
/// unwritable. This module mints one, and is documented rather than hidden so
/// nobody mistakes it for a production path: **do not use it to originate a real
/// bid.** It grants an effectively unbounded ceiling, which is exactly what a
/// certificate must never do.
///
/// Gated on the `test-support` feature, which `default` does not enable.
#[cfg(feature = "test-support")]
pub mod test_support {
    use super::SignedBid;
    use nucleus_econ_types::{AgentId, MicroUsd};
    use nucleus_permission_market::PermissionDimension;

    /// A bid that bypasses the ceiling check, for examples and tests only.
    #[must_use]
    pub fn bid(agent: &str, value: u64, dimension: PermissionDimension) -> SignedBid {
        SignedBid::fixture(AgentId::new(agent), dimension, MicroUsd::new(value))
    }
}
