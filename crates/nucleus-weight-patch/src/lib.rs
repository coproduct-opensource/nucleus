//! A change to a tensor checkpoint, as something a stranger can replay.
//!
//! A model that proposes a change to its own weights is making a claim about
//! three things: which checkpoint it started from, what it did to it, and
//! which tensors it touched. This crate makes each of those a value that is
//! computed from bytes, so that none of them has to be taken on the proposer's
//! word.
//!
//! - [`digest`]: one digest per tensor (name, element type, shape, bytes) and
//!   one per checkpoint (the sorted list of tensor digests). The checkpoint
//!   digest does not depend on how the tensors are split across files.
//! - [`container`]: a reader for the common tensor-file layout — an 8-byte
//!   little-endian header length, a JSON header, then the tensor bytes — that
//!   refuses every header a second reader could interpret differently.
//! - [`program`]: a declarative patch program. It names tensors explicitly and
//!   carries no code. Its digest is what a proposal binds.
//! - [`apply`]: runs a program over a checkpoint in one streaming pass and
//!   returns the digests of every tensor before and after. The arithmetic is
//!   done on bit patterns with one stated rounding rule, so the output is the
//!   same bytes on every platform.
//! - [`writes`]: the tensors that actually changed, measured as a difference
//!   of digests, checked against the set a proposal declared. An empty
//!   declared set is not representable: "nothing declared" never means
//!   "anything allowed".
//!
//! # What this crate does not do
//!
//! It signs nothing and decides nothing about release. It does not evaluate a
//! model. It measures what changed; whether the change was permitted, measured
//! and approved is the release gate's question, asked of these measurements.
//!
//! No model, framework or vendor is named anywhere in this crate, by mandate:
//! it is for any checkpoint stored as named tensors.

#![forbid(unsafe_code)]
// A function whose type says `-> T` and panics is lying about its type, and
// this crate measures what a release decision rests on. Denied for the shipped
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

pub mod apply;
pub mod container;
pub mod digest;
pub mod program;
pub mod writes;

pub use apply::{Applied, Applier, ApplyError, Indexer};
pub use container::{Dtype, Header, HeaderError, MAX_HEADER_BYTES, TensorInfo, write_checkpoint};
pub use digest::{CheckpointDigest, CheckpointIndex, DigestParseError, TensorDigest};
pub use program::{Op, PROGRAM_SCHEMA, PatchProgram, ProgramDigest, ProgramError, Scalar};
pub use writes::{
    DeclarationError, DeclaredWrites, Diff, DiffError, TensorWrite, WithinDeclared, WriteVerdict,
    check_writes, diff,
};
