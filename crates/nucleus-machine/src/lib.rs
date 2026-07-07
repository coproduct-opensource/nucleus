//! `nucleus-machine` — an execution-substrate abstraction for agent runtimes.
//!
//! A [`MachineDriver`] is a microVM lifecycle backend: `create → start →
//! suspend → start → stop → destroy`. The agent control plane's reconciler
//! depends only on this trait, so the substrate is swappable and never
//! load-bearing lock-in (see `docs/rfcs/agent-control-plane-on-fly.md`):
//!
//! - [`MockMachineDriver`] — an in-memory state machine for tests and local
//!   orchestration development. Fully implemented.
//! - [`FlyMachineDriver`] — a **skeleton** backend for [Fly.io
//!   Machines](https://fly.io/docs/machines/) (Firecracker microVMs with native
//!   `suspend`/`start`, i.e. memory snapshot/restore). The Machines-API
//!   *endpoint mapping* is implemented and tested; the HTTP transport is a
//!   documented P0 TODO and currently returns [`MachineError::NotWired`] — it
//!   does **not** fake calls.
//!
//! The key primitive is [`MachineDriver::suspend`]: on Fly this snapshots VM
//! memory to disk so an idle agent costs ~nothing and resumes in ~ms on the next
//! message — the efficiency win that is structurally impossible on Kubernetes.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Opaque backend identifier for a machine.
pub type MachineId = String;

/// Lifecycle state of a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineState {
    /// Created but not started.
    Created,
    /// Running.
    Active,
    /// Memory snapshotted to disk (Fly `suspend`); compute stopped, resumable.
    Frozen,
    /// Fully stopped (no memory snapshot); a cold start is required to resume.
    Stopped,
    /// Destroyed — terminal.
    Destroyed,
}

/// Desired configuration for a new machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineSpec {
    /// OCI image / rootfs reference.
    pub image: String,
    /// Preferred region (backend-specific code, e.g. a Fly region); `None` =
    /// let the backend choose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// vCPUs.
    pub cpus: u16,
    /// Memory in MiB.
    pub memory_mb: u32,
    /// Environment variables for the guest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

/// Errors a [`MachineDriver`] may surface.
#[derive(Debug, thiserror::Error)]
pub enum MachineError {
    /// No machine with this id is known to the backend.
    #[error("machine not found: {0}")]
    NotFound(MachineId),
    /// The requested operation is not valid from the machine's current state.
    #[error("invalid transition for {id}: cannot {op} from {from:?}")]
    InvalidTransition {
        /// The machine id.
        id: MachineId,
        /// Its current state.
        from: MachineState,
        /// The attempted operation.
        op: &'static str,
    },
    /// A skeleton backend whose transport has not been wired yet.
    #[error("driver transport not yet wired: {0}")]
    NotWired(&'static str),
    /// A backend (transport / API) error.
    #[error("backend error: {0}")]
    Backend(String),
}

/// A microVM lifecycle backend.
///
/// Implementations must be cheap to clone/share (`Send + Sync`) so the
/// reconciler can hold one behind an `Arc`.
#[async_trait]
pub trait MachineDriver: Send + Sync {
    /// Create a machine in [`MachineState::Created`] and return its id.
    async fn create(&self, spec: &MachineSpec) -> Result<MachineId, MachineError>;
    /// Start (or resume from `Frozen`/`Stopped`) → [`MachineState::Active`].
    async fn start(&self, id: &str) -> Result<(), MachineError>;
    /// Snapshot memory to disk → [`MachineState::Frozen`] (resume via `start`).
    async fn suspend(&self, id: &str) -> Result<(), MachineError>;
    /// Stop without a memory snapshot → [`MachineState::Stopped`].
    async fn stop(&self, id: &str) -> Result<(), MachineError>;
    /// Destroy the machine (terminal).
    async fn destroy(&self, id: &str) -> Result<(), MachineError>;
    /// Current lifecycle state.
    async fn status(&self, id: &str) -> Result<MachineState, MachineError>;
}

// ── MockMachineDriver ────────────────────────────────────────────────────────

/// In-memory [`MachineDriver`] for tests and orchestration development.
///
/// Enforces the same lifecycle transitions a real backend would, so reconciler
/// logic can be exercised without any infrastructure.
#[derive(Default)]
pub struct MockMachineDriver {
    // (next_id_counter, id → state). std Mutex is fine: no `.await` is held
    // across the lock in any method.
    inner: std::sync::Mutex<(u64, BTreeMap<MachineId, MachineState>)>,
}

impl MockMachineDriver {
    /// A fresh, empty mock driver.
    pub fn new() -> Self {
        Self::default()
    }

    fn transition(
        &self,
        id: &str,
        op: &'static str,
        allowed_from: &[MachineState],
        to: MachineState,
    ) -> Result<(), MachineError> {
        let mut guard = self.inner.lock().expect("mock driver mutex poisoned");
        let state = guard
            .1
            .get_mut(id)
            .ok_or_else(|| MachineError::NotFound(id.to_string()))?;
        if !allowed_from.contains(state) {
            return Err(MachineError::InvalidTransition {
                id: id.to_string(),
                from: *state,
                op,
            });
        }
        *state = to;
        Ok(())
    }
}

#[async_trait]
impl MachineDriver for MockMachineDriver {
    async fn create(&self, _spec: &MachineSpec) -> Result<MachineId, MachineError> {
        let mut guard = self.inner.lock().expect("mock driver mutex poisoned");
        guard.0 += 1;
        let id = format!("mock-{}", guard.0);
        guard.1.insert(id.clone(), MachineState::Created);
        Ok(id)
    }

    async fn start(&self, id: &str) -> Result<(), MachineError> {
        self.transition(
            id,
            "start",
            &[
                MachineState::Created,
                MachineState::Frozen,
                MachineState::Stopped,
                MachineState::Active, // idempotent
            ],
            MachineState::Active,
        )
    }

    async fn suspend(&self, id: &str) -> Result<(), MachineError> {
        self.transition(id, "suspend", &[MachineState::Active], MachineState::Frozen)
    }

    async fn stop(&self, id: &str) -> Result<(), MachineError> {
        self.transition(
            id,
            "stop",
            &[MachineState::Active, MachineState::Frozen],
            MachineState::Stopped,
        )
    }

    async fn destroy(&self, id: &str) -> Result<(), MachineError> {
        self.transition(
            id,
            "destroy",
            &[
                MachineState::Created,
                MachineState::Active,
                MachineState::Frozen,
                MachineState::Stopped,
            ],
            MachineState::Destroyed,
        )
    }

    async fn status(&self, id: &str) -> Result<MachineState, MachineError> {
        let guard = self.inner.lock().expect("mock driver mutex poisoned");
        guard
            .1
            .get(id)
            .copied()
            .ok_or_else(|| MachineError::NotFound(id.to_string()))
    }
}

// ── InMemoryMachineProvider ──────────────────────────────────────────────────

/// An in-memory [`MachineDriver`] test double.
///
/// Like [`MockMachineDriver`] it enforces the real lifecycle transitions, but it
/// additionally retains the [`MachineSpec`] each machine was created with so a
/// test can assert on the *stored configuration*, not just the lifecycle state.
/// All state lives in an in-memory map behind the crate's own [`std::sync::Mutex`];
/// there are no external dependencies and no network access, which makes it a
/// drop-in provider for reconciler round-trip tests.
#[derive(Default)]
pub struct InMemoryMachineProvider {
    // (next_id_counter, id → record). std Mutex is fine: no `.await` is held
    // across the lock in any method.
    inner: std::sync::Mutex<(u64, BTreeMap<MachineId, MachineRecord>)>,
}

/// The in-memory bookkeeping for one machine held by an
/// [`InMemoryMachineProvider`].
#[derive(Debug, Clone)]
struct MachineRecord {
    state: MachineState,
    spec: MachineSpec,
}

impl InMemoryMachineProvider {
    /// A fresh, empty in-memory provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of machine records currently tracked (including destroyed ones).
    /// Purely an observability hook for tests.
    pub fn machine_count(&self) -> usize {
        let guard = self.inner.lock().expect("provider mutex poisoned");
        guard.1.len()
    }

    /// Return a clone of the [`MachineSpec`] a machine was created with, or
    /// [`MachineError::NotFound`] if the id is unknown. Lets a test verify that
    /// the provider round-tripped the requested configuration.
    pub fn spec_of(&self, id: &str) -> Result<MachineSpec, MachineError> {
        let guard = self.inner.lock().expect("provider mutex poisoned");
        guard
            .1
            .get(id)
            .map(|rec| rec.spec.clone())
            .ok_or_else(|| MachineError::NotFound(id.to_string()))
    }

    fn transition(
        &self,
        id: &str,
        op: &'static str,
        allowed_from: &[MachineState],
        to: MachineState,
    ) -> Result<(), MachineError> {
        let mut guard = self.inner.lock().expect("provider mutex poisoned");
        let record = guard
            .1
            .get_mut(id)
            .ok_or_else(|| MachineError::NotFound(id.to_string()))?;
        if !allowed_from.contains(&record.state) {
            return Err(MachineError::InvalidTransition {
                id: id.to_string(),
                from: record.state,
                op,
            });
        }
        record.state = to;
        Ok(())
    }
}

#[async_trait]
impl MachineDriver for InMemoryMachineProvider {
    async fn create(&self, spec: &MachineSpec) -> Result<MachineId, MachineError> {
        let mut guard = self.inner.lock().expect("provider mutex poisoned");
        guard.0 += 1;
        let id = format!("inmem-{}", guard.0);
        guard.1.insert(
            id.clone(),
            MachineRecord {
                state: MachineState::Created,
                spec: spec.clone(),
            },
        );
        Ok(id)
    }

    async fn start(&self, id: &str) -> Result<(), MachineError> {
        self.transition(
            id,
            "start",
            &[
                MachineState::Created,
                MachineState::Frozen,
                MachineState::Stopped,
                MachineState::Active, // idempotent
            ],
            MachineState::Active,
        )
    }

    async fn suspend(&self, id: &str) -> Result<(), MachineError> {
        self.transition(id, "suspend", &[MachineState::Active], MachineState::Frozen)
    }

    async fn stop(&self, id: &str) -> Result<(), MachineError> {
        self.transition(
            id,
            "stop",
            &[MachineState::Active, MachineState::Frozen],
            MachineState::Stopped,
        )
    }

    async fn destroy(&self, id: &str) -> Result<(), MachineError> {
        self.transition(
            id,
            "destroy",
            &[
                MachineState::Created,
                MachineState::Active,
                MachineState::Frozen,
                MachineState::Stopped,
            ],
            MachineState::Destroyed,
        )
    }

    async fn status(&self, id: &str) -> Result<MachineState, MachineError> {
        let guard = self.inner.lock().expect("provider mutex poisoned");
        guard
            .1
            .get(id)
            .map(|rec| rec.state)
            .ok_or_else(|| MachineError::NotFound(id.to_string()))
    }
}

// ── FlyMachineDriver (skeleton) ──────────────────────────────────────────────

/// A Fly.io Machines API operation, used to map a [`MachineDriver`] call to its
/// REST endpoint (method + path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlyOp {
    /// Create a machine.
    Create,
    /// Start / resume.
    Start,
    /// Suspend (memory snapshot).
    Suspend,
    /// Stop (no snapshot).
    Stop,
    /// Destroy.
    Destroy,
    /// Read state.
    Status,
}

/// Skeleton [`MachineDriver`] backend for Fly.io Machines.
///
/// The endpoint mapping ([`FlyMachineDriver::endpoint`]) is implemented and
/// tested; the HTTP transport is a P0 TODO — the trait methods currently return
/// [`MachineError::NotWired`] rather than faking calls. Wiring is intentionally
/// kept out of this crate so the dependency stays transport-free until the
/// control plane needs it.
pub struct FlyMachineDriver {
    app: String,
    api_base: String,
    #[allow(dead_code)] // used once the HTTP transport is wired (P0).
    token: String,
}

impl FlyMachineDriver {
    /// Default Fly Machines API base URL.
    pub const DEFAULT_API_BASE: &'static str = "https://api.machines.dev/v1";

    /// Construct against `app`, authenticating with `token`
    /// (a Fly API / OIDC-exchanged token), using the default API base.
    pub fn new(app: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            app: app.into(),
            api_base: Self::DEFAULT_API_BASE.to_string(),
            token: token.into(),
        }
    }

    /// Override the API base (e.g. for a mock server in integration tests).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Map an operation to its `(HTTP method, full URL)` against the Machines
    /// API. Pure — the unit of behavior that's testable without a network.
    pub fn endpoint(&self, op: FlyOp, id: Option<&str>) -> (&'static str, String) {
        let base = &self.api_base;
        let app = &self.app;
        match op {
            FlyOp::Create => ("POST", format!("{base}/apps/{app}/machines")),
            FlyOp::Start => (
                "POST",
                format!("{base}/apps/{app}/machines/{}/start", id.unwrap_or("")),
            ),
            FlyOp::Suspend => (
                "POST",
                format!("{base}/apps/{app}/machines/{}/suspend", id.unwrap_or("")),
            ),
            FlyOp::Stop => (
                "POST",
                format!("{base}/apps/{app}/machines/{}/stop", id.unwrap_or("")),
            ),
            FlyOp::Destroy => (
                "DELETE",
                format!("{base}/apps/{app}/machines/{}", id.unwrap_or("")),
            ),
            FlyOp::Status => (
                "GET",
                format!("{base}/apps/{app}/machines/{}", id.unwrap_or("")),
            ),
        }
    }
}

const FLY_TODO: &str =
    "FlyMachineDriver: HTTP transport is a P0 TODO (see docs/rfcs/agent-control-plane-on-fly.md)";

#[async_trait]
impl MachineDriver for FlyMachineDriver {
    async fn create(&self, _spec: &MachineSpec) -> Result<MachineId, MachineError> {
        Err(MachineError::NotWired(FLY_TODO))
    }
    async fn start(&self, _id: &str) -> Result<(), MachineError> {
        Err(MachineError::NotWired(FLY_TODO))
    }
    async fn suspend(&self, _id: &str) -> Result<(), MachineError> {
        Err(MachineError::NotWired(FLY_TODO))
    }
    async fn stop(&self, _id: &str) -> Result<(), MachineError> {
        Err(MachineError::NotWired(FLY_TODO))
    }
    async fn destroy(&self, _id: &str) -> Result<(), MachineError> {
        Err(MachineError::NotWired(FLY_TODO))
    }
    async fn status(&self, _id: &str) -> Result<MachineState, MachineError> {
        Err(MachineError::NotWired(FLY_TODO))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> MachineSpec {
        MachineSpec {
            image: "registry.fly.io/agent:latest".into(),
            region: Some("sjc".into()),
            cpus: 1,
            memory_mb: 512,
            env: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn mock_full_lifecycle() {
        let d = MockMachineDriver::new();
        let id = d.create(&spec()).await.unwrap();
        assert_eq!(d.status(&id).await.unwrap(), MachineState::Created);
        d.start(&id).await.unwrap();
        assert_eq!(d.status(&id).await.unwrap(), MachineState::Active);
        // suspend → frozen → resume (the freeze/resume primitive)
        d.suspend(&id).await.unwrap();
        assert_eq!(d.status(&id).await.unwrap(), MachineState::Frozen);
        d.start(&id).await.unwrap();
        assert_eq!(d.status(&id).await.unwrap(), MachineState::Active);
        d.stop(&id).await.unwrap();
        assert_eq!(d.status(&id).await.unwrap(), MachineState::Stopped);
        d.destroy(&id).await.unwrap();
        assert_eq!(d.status(&id).await.unwrap(), MachineState::Destroyed);
    }

    #[tokio::test]
    async fn mock_rejects_invalid_transition() {
        let d = MockMachineDriver::new();
        let id = d.create(&spec()).await.unwrap();
        // Can't suspend a machine that was never started.
        let err = d.suspend(&id).await.unwrap_err();
        assert!(matches!(
            err,
            MachineError::InvalidTransition { op: "suspend", .. }
        ));
    }

    #[tokio::test]
    async fn mock_unknown_id_is_not_found() {
        let d = MockMachineDriver::new();
        assert!(matches!(
            d.status("nope").await.unwrap_err(),
            MachineError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn in_memory_provider_full_round_trip() {
        let p = InMemoryMachineProvider::new();
        assert_eq!(p.machine_count(), 0);

        // create → look up spec + state (observable state assertions)
        let s = spec();
        let id = p.create(&s).await.unwrap();
        assert_eq!(p.machine_count(), 1);
        assert_eq!(p.status(&id).await.unwrap(), MachineState::Created);
        let stored = p.spec_of(&id).unwrap();
        assert_eq!(stored.image, s.image);
        assert_eq!(stored.region, s.region);
        assert_eq!(stored.cpus, s.cpus);
        assert_eq!(stored.memory_mb, s.memory_mb);

        // full lifecycle: start → suspend → resume → stop → destroy
        p.start(&id).await.unwrap();
        assert_eq!(p.status(&id).await.unwrap(), MachineState::Active);
        p.suspend(&id).await.unwrap();
        assert_eq!(p.status(&id).await.unwrap(), MachineState::Frozen);
        p.start(&id).await.unwrap();
        assert_eq!(p.status(&id).await.unwrap(), MachineState::Active);
        p.stop(&id).await.unwrap();
        assert_eq!(p.status(&id).await.unwrap(), MachineState::Stopped);
        p.destroy(&id).await.unwrap();
        assert_eq!(p.status(&id).await.unwrap(), MachineState::Destroyed);

        // error paths behave per the trait's conventions
        assert!(matches!(
            p.status("nope").await.unwrap_err(),
            MachineError::NotFound(_)
        ));
        let fresh = p.create(&s).await.unwrap();
        assert_eq!(p.machine_count(), 2);
        assert!(matches!(
            p.suspend(&fresh).await.unwrap_err(),
            MachineError::InvalidTransition { op: "suspend", .. }
        ));
    }

    #[test]
    fn fly_endpoint_mapping() {
        let d = FlyMachineDriver::new("my-app", "tok").with_api_base("https://x/v1");
        assert_eq!(
            d.endpoint(FlyOp::Create, None),
            ("POST", "https://x/v1/apps/my-app/machines".to_string())
        );
        assert_eq!(
            d.endpoint(FlyOp::Suspend, Some("m1")),
            (
                "POST",
                "https://x/v1/apps/my-app/machines/m1/suspend".to_string()
            )
        );
        assert_eq!(
            d.endpoint(FlyOp::Destroy, Some("m1")),
            ("DELETE", "https://x/v1/apps/my-app/machines/m1".to_string())
        );
        assert_eq!(
            d.endpoint(FlyOp::Status, Some("m1")),
            ("GET", "https://x/v1/apps/my-app/machines/m1".to_string())
        );
    }

    #[tokio::test]
    async fn fly_transport_is_honestly_unwired() {
        let d = FlyMachineDriver::new("my-app", "tok");
        assert!(matches!(
            d.start("m1").await.unwrap_err(),
            MachineError::NotWired(_)
        ));
    }
}
