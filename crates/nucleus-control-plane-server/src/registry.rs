//! In-memory job and runner registries.
//!
//! The job registry holds every job's lifecycle state plus an
//! idempotency-key index. The runner registry maps an
//! [`AgentDriverRef::name`] to a boxed [`JobRunner`] implementation.
//!
//! Both are deliberately in-memory for the MVP. A future slice can swap
//! the [`JobRegistry`] for a Postgres-backed implementation behind the
//! same trait without touching route code.
//!
//! [`AgentDriverRef::name`]: nucleus_control_plane::AgentDriverRef::name
//! [`JobRunner`]: nucleus_control_plane::JobRunner

use std::collections::HashMap;
use std::sync::RwLock;

use nucleus_control_plane::{JobId, JobRunner, JobState};
use thiserror::Error;

/// Errors raised by the registry layer.
#[derive(Debug, Error)]
pub enum JobRegistryError {
    #[error("registry lock poisoned")]
    Poisoned,
    #[error("job {0} not found")]
    NotFound(JobId),
}

/// Append-and-update store for job lifecycle state.
pub trait JobRegistry: Send + Sync {
    /// Insert a new job. Returns the assigned [`JobId`].
    fn insert(&self, initial: JobState) -> Result<JobId, JobRegistryError>;
    /// Replace the state of an existing job. Errors if `id` is unknown.
    fn update(&self, id: &JobId, state: JobState) -> Result<(), JobRegistryError>;
    /// Snapshot the current state of a job.
    fn get(&self, id: &JobId) -> Result<JobState, JobRegistryError>;
    /// Look up a JobId by its idempotency key, if one has been recorded.
    fn find_by_idempotency_key(&self, key: &str) -> Result<Option<JobId>, JobRegistryError>;
    /// Associate an idempotency key with a JobId. Subsequent calls with
    /// the same key return the same JobId via `find_by_idempotency_key`.
    fn record_idempotency(&self, key: String, id: JobId) -> Result<(), JobRegistryError>;
}

/// Process-local registry. Edges (jobs) keyed by [`JobId`]; idempotency
/// keys are a separate map. Both behind a single `RwLock` since jobs
/// are typically read-heavy after submission.
pub struct InMemoryRegistry {
    inner: RwLock<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    jobs: HashMap<JobId, JobState>,
    idempotency: HashMap<String, JobId>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RegistryInner::default()),
        }
    }
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl JobRegistry for InMemoryRegistry {
    fn insert(&self, initial: JobState) -> Result<JobId, JobRegistryError> {
        let id = JobId::new();
        let mut inner = self.inner.write().map_err(|_| JobRegistryError::Poisoned)?;
        inner.jobs.insert(id.clone(), initial);
        Ok(id)
    }

    fn update(&self, id: &JobId, state: JobState) -> Result<(), JobRegistryError> {
        let mut inner = self.inner.write().map_err(|_| JobRegistryError::Poisoned)?;
        if !inner.jobs.contains_key(id) {
            return Err(JobRegistryError::NotFound(id.clone()));
        }
        inner.jobs.insert(id.clone(), state);
        Ok(())
    }

    fn get(&self, id: &JobId) -> Result<JobState, JobRegistryError> {
        let inner = self.inner.read().map_err(|_| JobRegistryError::Poisoned)?;
        inner
            .jobs
            .get(id)
            .cloned()
            .ok_or_else(|| JobRegistryError::NotFound(id.clone()))
    }

    fn find_by_idempotency_key(&self, key: &str) -> Result<Option<JobId>, JobRegistryError> {
        let inner = self.inner.read().map_err(|_| JobRegistryError::Poisoned)?;
        Ok(inner.idempotency.get(key).cloned())
    }

    fn record_idempotency(&self, key: String, id: JobId) -> Result<(), JobRegistryError> {
        let mut inner = self.inner.write().map_err(|_| JobRegistryError::Poisoned)?;
        inner.idempotency.insert(key, id);
        Ok(())
    }
}

/// Registry of available agent drivers. Keyed by [`AgentDriverRef::name`].
pub struct RunnerRegistry {
    runners: HashMap<String, Box<dyn JobRunner>>,
}

impl RunnerRegistry {
    pub fn new() -> Self {
        Self {
            runners: HashMap::new(),
        }
    }

    /// Register a driver under `name`. Replaces any prior registration.
    pub fn register(mut self, name: impl Into<String>, runner: Box<dyn JobRunner>) -> Self {
        self.runners.insert(name.into(), runner);
        self
    }

    /// Lookup a driver by name.
    pub fn get(&self, name: &str) -> Option<&dyn JobRunner> {
        self.runners.get(name).map(|b| b.as_ref())
    }
}

impl Default for RunnerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn insert_then_get_round_trips() {
        let reg = InMemoryRegistry::new();
        let id = reg
            .insert(JobState::Queued {
                submitted_at: Utc::now(),
            })
            .unwrap();
        let state = reg.get(&id).unwrap();
        matches!(state, JobState::Queued { .. });
    }

    #[test]
    fn update_unknown_job_errors() {
        let reg = InMemoryRegistry::new();
        let unknown = JobId::new();
        let err = reg
            .update(
                &unknown,
                JobState::Queued {
                    submitted_at: Utc::now(),
                },
            )
            .unwrap_err();
        assert!(matches!(err, JobRegistryError::NotFound(_)));
    }

    #[test]
    fn idempotency_round_trips() {
        let reg = InMemoryRegistry::new();
        let id = reg
            .insert(JobState::Queued {
                submitted_at: Utc::now(),
            })
            .unwrap();
        reg.record_idempotency("key-1".to_string(), id.clone())
            .unwrap();
        assert_eq!(reg.find_by_idempotency_key("key-1").unwrap(), Some(id));
        assert_eq!(reg.find_by_idempotency_key("missing").unwrap(), None);
    }
}
