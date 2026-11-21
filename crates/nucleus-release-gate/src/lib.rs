//! The gate between a proposed checkpoint and the one being served.
//!
//! `nucleus-weight-patch` measures a change to a checkpoint. This crate
//! decides whether the changed checkpoint may be served, from evidence that
//! does not depend on the word of whoever proposed the change.
//!
//! - [`body`]: the bodies of the chain — proposal grant, patch manifest, apply
//!   receipt, evaluation receipt, approval, rollback order, release receipt —
//!   each carried in a `nucleus_receipt::Receipt`, with [`body::seal`] and
//!   [`body::open`] as the only ways in and out.
//! - [`policy`]: who holds each role, which tensors a patch may write, what
//!   an evaluation must show. The deployer's; the gate is configured with it.
//! - [`runner`]: the runner's outcome, derived from measurements.
//! - [`eval`]: results computed from per-item outcomes, and the thresholds.
//! - [`chain`]: the walk. Five receipts in, and either a [`chain::PointerMove`]
//!   — the right to move the pointer once — or the first reason not to.
//! - [`registry`]: the pointer on disk, its log, promotion, rollback, and
//!   [`registry::audit`], which replays a log from public material alone.
//!
//! # What a release record establishes
//!
//! Which checkpoint was changed, by which program, writing which tensors;
//! what was measured, under which settings; and which keys authorized each
//! step. It does not establish that the candidate is better, or safe, outside
//! the conditions measured.
//!
//! No model, framework or vendor is named anywhere in this crate, by mandate.

#![forbid(unsafe_code)]
// A function whose type says `-> T` and panics is lying about its type, and
// this crate decides what is served. Denied for the shipped build only:
// `assert!` IS a panic, so denying inside `#[cfg(test)]` would forbid the
// thing tests are made of.
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

pub mod body;
pub mod chain;
pub mod eval;
pub mod keys;
pub mod policy;
pub mod registry;
pub mod runner;

#[cfg(test)]
pub(crate) mod testkit;
