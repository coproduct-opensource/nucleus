//! [`JobId`] and lifecycle state for orchestrated jobs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Stable identifier for a control-plane job. Distinct from the SPIFFE
/// `CallSpiffeId` of the session pod — `JobId` is the customer-facing
/// handle, the pod id is the internal identity. They have a 1:1
/// correspondence within a job's lifetime; tracking both means a job
/// can be addressed before its pod has been admitted (queued state).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(String);

impl JobId {
    /// Mint a fresh random JobId.
    pub fn new() -> Self {
        Self(format!("job-{}", Uuid::new_v4()))
    }

    /// Construct a JobId from a pre-existing string. Used by stores
    /// reading persisted jobs back in.
    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle state. Persisted by whatever backing store the
/// orchestrator uses; in-process executors simply hold this enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JobState {
    /// Submitted but not yet picked up.
    Queued { submitted_at: DateTime<Utc> },
    /// Agent is running.
    Running {
        started_at: DateTime<Utc>,
        session_root: String,
    },
    /// Job finished successfully. The bundle is in [`JobOutcome::bundle`].
    ///
    /// `outcome` is boxed so this variant doesn't dominate the enum
    /// size — a real Bundle is several KB once Merkle inclusion proofs
    /// are attached, and the other variants are <100 bytes.
    Completed {
        started_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
        outcome: Box<JobOutcome>,
    },
    /// Job failed. `reason` is a human-readable error string; structured
    /// errors flow through the [`crate::executor::ExecuteJobError`] type
    /// at the API boundary.
    Failed {
        started_at: Option<DateTime<Utc>>,
        failed_at: DateTime<Utc>,
        reason: String,
    },
}

/// What a completed job produced. The bundle is the value the customer
/// paid for; `delivered` records whether the destination push succeeded
/// (for non-`InResponse` destinations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobOutcome {
    /// The provenance bundle (payload + envelope).
    pub bundle: nucleus_envelope::Bundle,
    /// `true` if the bundle was successfully delivered to the spec's
    /// destination. `InResponse` destinations are always considered
    /// delivered (the API response carries the bundle).
    pub delivered: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_id_is_unique() {
        let a = JobId::new();
        let b = JobId::new();
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("job-"));
    }

    #[test]
    fn job_state_round_trips_through_json() {
        let s = JobState::Queued {
            submitted_at: Utc::now(),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: JobState = serde_json::from_str(&json).unwrap();
        matches!(back, JobState::Queued { .. });
    }
}
