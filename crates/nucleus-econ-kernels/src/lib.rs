//! Integer-only economic kernels for Nucleus's substrate.
//!
//! Math primitives lifted from sibling repos with per-file provenance comments
//! and rewritten to use `u64` / `u128` micro-USD instead of `f64` USD. See
//! `docs/ECON-PRECISION.md` for the full policy and the rationale for the
//! integer-VCG mechanism modification.
//!
//! # No floating-point arithmetic
//!
//! `#![deny(clippy::float_arithmetic)]` at the lib root enforces this for
//! the entire crate. The float ban is not aesthetic — it preserves the
//! VCG truthfulness theorem under the rounded-payment construction, which
//! is broken by naïve f64-round-at-the-end implementations.
//!
//! # Currently included
//!
//! - [`vcg`] — integer VCG mechanism (lifted from
//!   `workstream-kg/crates/agent/src/market/vcg.rs`, ~326 lines f64 →
//!   ~250 lines u64). Algorithm preserved; types and arithmetic rewritten.

#![deny(clippy::float_arithmetic)]

// Re-export the financially load-bearing newtypes from the dedicated
// `nucleus-econ-types` crate so the economic surface has a single
// discoverable home for `MicroUsd` and the id types. The kernel's own
// `IntegerBid`/`IntegerProposal`/`WinningBid` structs still carry bare
// `u64`/`String` today (their receipt-byte hashing + Lean-parity
// surface makes the conversion a wider sweep — see the PR's residual
// section); callers that want the newtypes can reach them here.
pub use nucleus_econ_types::{AgentId, AuctionId, MicroUsd, ProposalId};

pub mod commons;
pub mod extracted;
pub mod rational;
pub mod sealed;
pub mod settlement;
pub mod tlock;
pub mod vcg;
pub mod vcg_combo;
pub mod vcg_hetero;
pub mod vcg_pigou;

pub use commons::{CommonsAllocation, CommonsError, CommonsShare, route_to_commons};
pub use settlement::{Verdict, classify, refund, seller_gross};

pub use rational::Rational;
pub use sealed::{
    BidCommitment, BidOpening, COMMIT_DOMAIN, COMMIT_SET_DOMAIN, CommitAck, CommitmentSetRoot,
    OmissionAudit, SealedBidError, audit_commit_ack, compute_commitment,
    compute_commitment_set_root, opening_to_integer_bid, sorted_commitment_set, verify_reveal,
};
pub use tlock::{DrandRound, StubBeacon, TimelockBackend, TimelockedBid, TlockError};

pub use vcg::{Clearing, IntegerBid, IntegerProposal, VcgError, WinningBid, run_vcg};
pub use vcg_combo::{
    Combinatorial2GoodClearing, CombinatorialBid, CombinatorialError, clear_combinatorial_2good,
};
pub use vcg_hetero::{
    EXACT_VCG_MAX_BIDS, HeteroError, clear_heterogeneous, clear_heterogeneous_exact,
};
pub use vcg_pigou::{
    LAMBDA_CARBON_SCC_MICRO_USD_PER_GRAM, LAMBDA_WATER_SHADOW_MICRO_USD_PER_LITRE,
    PigouvianClearing, PigouvianError, PigouvianRates, effective_minus_pigou_micro,
    run_vcg_with_externalities,
};

// A6 (docs/CLOSE-TO-HIGHEST.md): the welfare-overflow Kani harness
// lives at `proofs/welfare_no_overflow.rs` (outside `src/`) per the
// acceptance check. Stitch it in via `#[path]` so it compiles only
// under the kani driver.
#[cfg(kani)]
#[path = "../proofs/welfare_no_overflow.rs"]
mod welfare_no_overflow_proofs;
