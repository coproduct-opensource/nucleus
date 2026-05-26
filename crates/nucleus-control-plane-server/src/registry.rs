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

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

use nucleus_control_plane::{JobId, JobRunner, JobState};
use thiserror::Error;

/// Soft cap on the in-memory job registry. Once exceeded, the oldest
/// jobs are evicted FIFO. Industry-typical idempotency retention is
/// 24h–30d; here we cap by count for the MVP. Production deployments
/// should swap to a backed store with TTL.
const REGISTRY_MAX_JOBS: usize = 10_000;
/// Same cap on the idempotency index. Bounding both maps prevents
/// unbounded memory growth from random-key flooding.
const REGISTRY_MAX_IDEMPOTENCY: usize = 10_000;

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
    /// Atomically: if `key` already maps to a JobId, return
    /// `(existing_id, false)`; otherwise insert `initial` as a new job,
    /// record `(key → new_id)`, and return `(new_id, true)`.
    ///
    /// This single-lock operation defends against the lookup-then-insert
    /// race where two concurrent submissions with the same Idempotency-Key
    /// both miss the lookup and both create jobs.
    fn insert_with_idempotency(
        &self,
        key: String,
        initial: JobState,
    ) -> Result<(JobId, bool), JobRegistryError>;
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
    /// FIFO insertion order for eviction when `jobs` exceeds the cap.
    job_insertion_order: VecDeque<JobId>,
    idempotency: HashMap<String, JobId>,
    /// FIFO insertion order for eviction when `idempotency` exceeds the cap.
    idempotency_insertion_order: VecDeque<String>,
}

impl RegistryInner {
    fn insert_job(&mut self, id: JobId, state: JobState) {
        self.jobs.insert(id.clone(), state);
        self.job_insertion_order.push_back(id);
        while self.jobs.len() > REGISTRY_MAX_JOBS {
            if let Some(oldest) = self.job_insertion_order.pop_front() {
                self.jobs.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn insert_idempotency(&mut self, key: String, id: JobId) {
        self.idempotency.insert(key.clone(), id);
        self.idempotency_insertion_order.push_back(key);
        while self.idempotency.len() > REGISTRY_MAX_IDEMPOTENCY {
            if let Some(oldest) = self.idempotency_insertion_order.pop_front() {
                self.idempotency.remove(&oldest);
            } else {
                break;
            }
        }
    }
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
        inner.insert_job(id.clone(), initial);
        Ok(id)
    }

    fn update(&self, id: &JobId, state: JobState) -> Result<(), JobRegistryError> {
        let mut inner = self.inner.write().map_err(|_| JobRegistryError::Poisoned)?;
        if !inner.jobs.contains_key(id) {
            return Err(JobRegistryError::NotFound(id.clone()));
        }
        // Replace in-place; don't touch insertion-order queue so the
        // eviction policy keeps treating this as the same job.
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

    fn insert_with_idempotency(
        &self,
        key: String,
        initial: JobState,
    ) -> Result<(JobId, bool), JobRegistryError> {
        let mut inner = self.inner.write().map_err(|_| JobRegistryError::Poisoned)?;
        if let Some(existing) = inner.idempotency.get(&key) {
            return Ok((existing.clone(), false));
        }
        let id = JobId::new();
        inner.insert_job(id.clone(), initial);
        inner.insert_idempotency(key, id.clone());
        Ok((id, true))
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
    fn insert_with_idempotency_returns_existing_on_repeat() {
        let reg = InMemoryRegistry::new();
        let (id1, inserted1) = reg
            .insert_with_idempotency(
                "key-1".to_string(),
                JobState::Queued {
                    submitted_at: Utc::now(),
                },
            )
            .unwrap();
        assert!(inserted1);
        let (id2, inserted2) = reg
            .insert_with_idempotency(
                "key-1".to_string(),
                JobState::Queued {
                    submitted_at: Utc::now(),
                },
            )
            .unwrap();
        assert!(!inserted2);
        assert_eq!(id1, id2, "same key must return same id atomically");
        assert_eq!(reg.find_by_idempotency_key("key-1").unwrap(), Some(id1));
    }
}
