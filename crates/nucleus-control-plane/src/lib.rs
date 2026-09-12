//! Control-plane orchestrator for nucleus agent sessions.
//!
//! Given a typed [`JobSpec`] (input reference, task, destination, agent
//! driver) and a [`JobRunner`] implementation, [`execute_job`] runs the
//! agent inside a fresh SPIFFE-rooted session, captures every lineage
//! edge it emits, and produces a verified provenance [`Bundle`] via
//! `nucleus-envelope`.
//!
//! # Vendor neutrality
//!
//! `JobRunner` is a trait — every concrete agent integration (an
//! agent CLI, OpenHands, Goose, …) lives outside this crate as a separate
//! implementation. The orchestrator core knows only: "run agent X,
//! collect lineage Y, package result Z." It does not know which LLM
//! is doing the work, what its API costs, or how its credentials are
//! formatted. Vendor-specific cost models, OAuth handling, and API
//! adapters live in downstream crates (e.g. workstream-kg).
//!
//! [`Bundle`]: nucleus_envelope::Bundle
//! [`JobSpec`]: spec::JobSpec
//! [`JobRunner`]: runner::JobRunner
//! [`execute_job`]: executor::execute_job

// ADR 0007 totality: a function whose signature says it returns is lying if it
// panics. Denied for the shipped build only — `assert!` IS a panic, so denying
// inside `#[cfg(test)]` would forbid the thing tests are made of. This is the
// same line `is_production_path` draws when it strips the test region.
//
// Added because this crate measures ZERO of all seven lints today, per
// `clippy.toml`'s own rule: entries are added only when the tree is already
// clean of them.
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

pub mod executor;
pub mod runner;
pub mod session_writer;
pub mod spec;
pub mod state;

pub use executor::{ExecuteJobError, execute_job};
pub use runner::{JobRunner, JobRunnerError, MockJobRunner};
pub use session_writer::{SessionWriter, SessionWriterError};
pub use spec::{AgentDriverRef, Destination, InputRef, JobSpec};
pub use state::{JobId, JobOutcome, JobState};
