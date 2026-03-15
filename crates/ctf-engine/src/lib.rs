//! CTF Engine — "The Vault"
//!
//! A browser-native CTF where players try to exfiltrate secrets from
//! a formally verified permission lattice. Runs entirely in WASM.
//!
//! Each level uses a real portcullis `PermissionLattice` profile and
//! tracks exposure via the same `ExposureSet` that production nucleus
//! uses. Verdicts are backed by Verus SMT proofs.

mod engine;
mod level;
mod sandbox;

pub use engine::CtfEngine;
pub use level::{Defense, Explainer, Level, LevelMeta};
pub use sandbox::{AttackResult, ExposureState, StepResult, ToolCall, Verdict};

#[cfg(feature = "wasm")]
mod wasm_bindings;
