//! The serving side of a weight-patch release.
//!
//! `nucleus-release-gate` decides whether the pointer may move. This crate is
//! what stands between that pointer and a request:
//!
//! - [`store`]: checkpoints filed under their measured digest and measured
//!   again before they are handed out.
//! - [`archive`]: the programs and transcripts a record's receipts name.
//! - [`app`]: the HTTP surface. One endpoint answers from the checkpoint the
//!   pointer names and reports the digest and generation that answered, so a
//!   client can tell which checkpoint it was talking to.
//! - [`record`]: verifying a release record from files — replaying the log,
//!   replaying each patch, recomputing each score — with "could not look"
//!   kept apart from both pass and fail.
//!
//! No model is named and none is run here: the backend is a trait the
//! operator implements.

#![forbid(unsafe_code)]
// This crate decides what a request is answered from. Denied for the shipped
// build only: `assert!` IS a panic, so denying inside `#[cfg(test)]` would
// forbid the thing tests are made of.
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

pub mod app;
pub mod archive;
pub mod record;
pub mod store;
