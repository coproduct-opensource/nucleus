//! The pure kernel of context-indexed, versioned memory (Program B, M1).
//!
//! # The model
//!
//! A memory space is an **object** with a linear history of versions. A run never
//! inherits a dead process's powers over it: the node mints a fresh [`Binding`] per
//! run, carrying a [`View`] (which scope atoms, up to which label), a pinned base
//! [`Version`], a mode, an [`Epoch`] and a `not_after`. Three graphs stay separate:
//! who spawned whom (execution), who delegated what (authority), and what state was
//! derived from what (memory versions). This crate is the third graph's decision
//! kernel, and nothing else:
//!
//! * [`restrict`] — a view only narrows. Restriction is not authorization: it can
//!   take away, never grant.
//! * [`observe`] — what a view sees of a [`Section`]: every visible entry,
//!   unchanged (label included), and nothing else.
//! * [`compare_on_overlap`] — do two local sections agree where both write?
//! * [`assemble_candidate`] — glue patches over a pinned [`Snapshot`]. A key two
//!   patches write differently is marked conflicted, never last-writer-wins.
//! * [`validate_candidate`] — the WHOLE candidate: keyed conflicts, label
//!   monotonicity (a stored label never lowers) and a global additive quota.
//!   Overlap agreement is not validity: two disjoint patches of 6 units each agree
//!   everywhere and still break a quota of 10.
//! * [`History::commit`] — compare-and-swap: a [`ValidCandidate`] commits only onto
//!   the head it was validated against.
//! * [`admit`] — a binding is admitted only in the current epoch and before its
//!   `not_after`; [`AdmittedOp`] has a private constructor.
//!
//! # Finite domain
//!
//! Three scope atoms, three label ranks, four keys, four content ids and quota units
//! up to 15 per entry. The domain is finite so that every decision slice in
//! [`extracted`] is bound to its production function by an EXHAUSTIVE parity test,
//! and so that the Lean model (`crates/portcullis-core/lean/MemoryContext.lean`)
//! closes its finite facts by kernel `decide`. See the crate README for exactly what
//! is proved, what is parity-tested and what is not yet extracted.

// The shipped build cannot panic (the `tot` family): a kernel that decides what a run
// may see of shared memory must answer, not abort.
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
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admit;
mod candidate;
pub mod extracted;
mod history;
mod section;
mod view;

pub use admit::{AdmitRefusal, AdmittedOp, Binding, Epoch, Mode, ReadRefusal, admit};
pub use candidate::{
    Candidate, CandidateRefusal, Invariants, ValidCandidate, assemble_candidate, validate_candidate,
};
pub use history::{CommitRefusal, History, Snapshot, Version};
pub use section::{Entry, Key, Overlap, Section, Units, ValueId, compare_on_overlap, observe};
pub use view::{LabelRank, Scope, ScopeAtom, View, restrict};

#[cfg(test)]
mod laws_tests;
#[cfg(test)]
mod parity_tests;
