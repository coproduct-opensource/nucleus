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
//! `JobRunner` is a trait — every concrete agent integration (a CLI-agent
//! adapter, OpenHands, Goose, …) lives outside this crate as a separate
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

pub mod executor;
pub mod runner;
pub mod session_writer;
pub mod spec;
pub mod state;

pub use executor::{execute_job, ExecuteJobError};
pub use runner::{JobRunner, JobRunnerError, MockJobRunner};
pub use session_writer::{SessionWriter, SessionWriterError};
pub use spec::{AgentDriverRef, Destination, InputRef, JobSpec};
pub use state::{JobId, JobOutcome, JobState};
