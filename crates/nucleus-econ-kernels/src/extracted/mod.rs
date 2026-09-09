//! Hand-transcribed Rust mirrors of the Nucleus Lean specifications.
//!
//! The corresponding Lean sources live in
//! `crates/nucleus-econ-kernels/lean/Nucleus/` (including `Auctions/`).
//! The historical `extracted` directory and `_aeneas` module names do not
//! establish that these Rust implementations were generated or verified by
//! Aeneas. There is no regeneration pipeline for this module today.
//!
//! `crates/nucleus-econ-kernels/tests/lean_model_parity.rs` compares the Rust
//! implementations with independently written reference models on test inputs.
//! These tests can detect disagreement; passing them is not a proof of
//! equivalence to Lean or an exhaustive guarantee about production executions.
//! Lean theorems establish properties of their Lean definitions only.
//!
//! Keep model changes and parity tests together in review. A registry-backed
//! hash pin for eligible leaf mirrors is planned in issue #2593; it is not an
//! active drift gate. Future Aeneas extraction would translate Rust to Lean,
//! with an explicit, reproducible regeneration check before claiming that link.

pub mod commons_aeneas;
pub mod pigou_aeneas;
pub mod settlement_aeneas;
pub mod vcg_aeneas;
