//! The delegation compiler: goal → required effects → minimum authority.
//!
//! ```text
//! goal ──► [proposers] ──► effects ──► lower ──► meet(ceiling) ──► TaskGrant
//!             │                                      │
//!        rules over repo context          never wider than the ceiling
//!        (+ optional child process)
//! ```
//!
//! The compiler is the layer that lets the lattice, sink scopes and egress
//! lists become internals: a person states an outcome and reviews meaning
//! (Can / Cannot / Limits / Risk), and the kernel keeps enforcing the lattice
//! the grant lowers to. Two properties hold by construction and are tested:
//!
//! - **Clamped**: `compile(..).lattice ≤ ceiling` for every goal and every
//!   ceiling ([`compile`] meets with the ceiling and asserts delegability).
//! - **Fail-closed**: a goal nothing recognises is
//!   [`CompileError::NothingRecognised`], never a fallback to a permissive
//!   profile; an effect the ceiling clips is reported in `cannot`, never
//!   silently dropped or silently granted.
//!
//! The crate never opens a socket. The pluggable [`EffectProposer`] is a
//! child process so an LLM-backed proposer stays outside nucleus.

pub mod compile;
pub mod proposer;
pub mod repo_context;
pub mod rules;

pub use compile::{COMPILER_NAME, CompileError, CompileInput, LimitOverrides, compile};
pub use proposer::{
    EffectProposer, ExternalCommandProposer, Proposal, ProposerError, RuleProposer,
};
pub use repo_context::{CiSystem, Ecosystem, GitRemote, RepoContext, probe};
pub use rules::{RULES, Requires, Rule, apply};
