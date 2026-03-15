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
mod takeaways;

/// Benchmark version stamp. Bump when scoring, defenses, or level
/// definitions change in ways that invalidate prior results.
pub const BENCHMARK_VERSION: &str = "1.0.0";

pub use engine::CtfEngine;
pub use level::{CanonicalStep, Defense, Explainer, Level, LevelMeta};
pub use sandbox::{AttackResult, DecisionSource, ExposureState, StepResult, ToolCall, Verdict};
pub use takeaways::build_takeaways;

#[cfg(feature = "wasm")]
mod wasm_bindings;
