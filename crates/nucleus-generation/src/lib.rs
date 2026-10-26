//! Generation certificates: how a runtime and the CI that judges it release each other.
//!
//! The runtime executes the judge's gates; the judge admits every change to the runtime, and
//! to itself. Each release of either is a **generation**: one change, judged by the latest
//! judge generation before it, evidenced by execution receipts from pinned runtime nodes, and
//! promoted only if it **strictly improved** its own ledger. A chain of generations starts at a
//! **seed** the relying party pins, and this crate checks the whole chain offline, with no
//! control plane and no secret.
//!
//! * [`record`] is the format: the seed, the generation, its envelope, and their one encoding.
//! * [`improve`] is the order: no metric regresses unless the owner waived it by name, and at
//!   least one strictly improves, which no waiver can excuse (owner decision, 2026-10-26).
//! * [`verify_chain`] is the only way to obtain a [`VerifiedChain`].
//!
//! # The three properties a co-recursive release needs
//!
//! * **A candidate never judges itself.** A generation verifies only under the key of the
//!   latest judge generation *before* it. A judge generation names the key it will judge its
//!   successors with, and that naming is itself signed by its predecessor.
//! * **The numbers are measured, not asserted.** The ledger a generation is judged on must hash
//!   to an artifact that a required gate's verified execution receipt names.
//! * **Weaker is visible.** Every generation carries its reproduction [`Tier`]; the seed sets
//!   the floor. A release two builders disagreed on is never shown as reproduced.
//!
//! # What this does not claim
//!
//! * **Not freshness.** Receipt windows were the judge's to enforce when it judged.
//! * **Not log inclusion.** No transparency-log proof or witness cosignature is checked here.
//! * **Not plan soundness.** `plan_sha256` and the required-gate list are the judge's; this
//!   checks that every gate the judge required ran and passed, not that the judge required the
//!   right gates.
//! * **Not the seed.** Everything is relative to a seed the relying party chose to pin, and to
//!   the executor keys and owner roots it pinned beside it.
//! * **Not rollback.** Under strict improvement a revert can never be a generation: it can only
//!   hold or regress what the generation it undoes improved. Owner decision, 2026-10-26:
//!   rollback moves the promotion pointer back to an earlier verified generation and does not
//!   extend the chain. That record is not in this format yet, so a chain verified here names
//!   its head as promoted even when an operator has rolled back.

#![forbid(unsafe_code)]
// Panic-free in the shipped build: a verifier that can panic on hostile bytes is a verifier an
// attacker can stop.
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

pub mod improve;
pub mod record;
mod verify;

#[cfg(test)]
mod tests;

pub use record::{
    Build, DecodeError, Direction, GENERATION_DOMAIN, GateEvidence, Generation, JudgeKey, Role,
    SEED_DOMAIN, Seed, SignedGeneration, Tier, WAIVER_CAPABILITY, decode, encode, id_of,
    ledger_bytes, waiver_capability,
};
pub use verify::{
    ChainError, Pins, Refusal, SeedError, VerifiedChain, VerifiedGeneration, verify_chain,
};
