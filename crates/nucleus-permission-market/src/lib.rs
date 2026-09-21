//! # nucleus-permission-market
//!
//! Lagrangian permission pricing for multi-dimensional capability constraints.
//!
//! ## Overview
//!
//! In constrained optimization, a Lagrange multiplier `λ` converts a hard
//! constraint into a continuous penalty; by duality, `λ` **is** the market
//! price of relaxing that constraint by one unit. This crate keeps one `λ` per
//! permission dimension (filesystem, command exec, network egress, approval).
//! When a dimension's utilization is low, `λ ≈ 0` and the permission is
//! effectively free; as utilization approaches its limit, `λ` grows
//! exponentially and prices out low-value operations first.
//!
//! ## What a bid is, and where it comes from
//!
//! A [`PermissionBid`] is **derived from a verified delegation certificate**,
//! never declared by a request. The only public constructor is
//! [`PermissionBid::from_verified`], which takes a sealed
//! `portcullis::VerifiedPermissions` — a value that cannot exist unless a
//! certificate chain was walked — and reads the requested dimensions, the
//! spend ceiling and the trust tier out of it. There is no `Deserialize`, and
//! there is no header. A bid that could arrive on the wire is a bid the wire
//! could set, and that was the defect this crate used to have (#2526).
//!
//! ```text
//! request ─► certificate chain ─► verify_certificate ─► VerifiedPermissions
//!                                                              │
//!                                                  PermissionBid::from_verified
//!                                                              │
//!                                            PermissionMarket::evaluate_bid ─► grant / 402
//! ```
//!
//! ## Integer, on a money path
//!
//! Prices are micro-USD and utilization is basis points. `λ` is computed by a
//! fixed-point exponential in `u128` — no float anywhere in the shipped build
//! — and pinned to the `f64` curve it replaced within one micro-unit at every
//! basis point (#2540). A Kani harness certifies the curve is overflow-free
//! and monotone.
//!
//! ## What this crate decides, and what it must not
//!
//! Price, and which of an already-authorised request's dimensions clear it.
//! Never *whether* an agent may act — that is the capability boundary's
//! decision, and `cargo xtask econ-boundary` refuses this crate a way into it
//! (`docs/econ-layer-boundary.md`).

#![forbid(unsafe_code)]
// This crate prices authority. A price two machines can disagree about is not
// a price, and a function whose type says `-> u64` and panics is lying. Denied
// for the shipped build only: `assert!` is a panic and the parity oracle is an
// `f64`, and both belong in tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::float_arithmetic,
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
pub mod dimension;
pub mod market;

pub use bid::{DeniedDimension, PermissionBid, PermissionGrant};
pub use dimension::{PermissionDimension, TrustTier};
pub use market::{
    CRITICAL_LAMBDA_MICRO, DimensionState, HARD_LAMBDA_MAX_MICRO, LAMBDA_ONE_MICRO,
    PermissionConstraintState, PermissionMarket, compute_lambda_micro,
};

// The λ-curve Kani harness is gated on `cfg(kani)`. Lives outside `src/` per
// the econ-kernels precedent, so a plain build never compiles it.
#[cfg(kani)]
#[path = "../proofs/lambda_monotone.rs"]
mod lambda_monotone_proofs;
