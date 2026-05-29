//! Server-wide shared state.

use std::sync::Arc;

use nucleus_lineage::{CallSpiffeId, LineageSink, LocalIssuer, MerkleProver};
use tokio::sync::Semaphore;

use crate::auth::SpiffeAuthConfig;
use crate::events::JobEventBroker;
use crate::registry::{InMemoryRegistry, JobRegistry, RunnerRegistry};

/// **MED-6 (audit) fix.** Maximum concurrent in-flight jobs. Each
/// job grabs one permit before `spawn_job` and releases on terminal
/// state. Bounds total `tokio::spawn` + `spawn_blocking` task count
/// regardless of how many distinct `Idempotency-Key` values the
/// caller generates — closes the audit-flagged DoS where unbounded
/// unique keys would queue unlimited blocking tasks. 128 covers
/// healthy load on a multi-replica deployment with sub-minute jobs
/// while bounding pathological multi-hour-runaway producers.
pub const MAX_INFLIGHT_JOBS: usize = 128;

/// Cloneable handle to the server's shared state. Routes receive this
/// via [`axum::extract::State`].
///
/// Boxed sink + concrete issuer are held by `Arc` so the [`AppState`]
/// stays cheap to clone (axum clones state for each request).
#[derive(Clone)]
pub struct AppState {
    /// Job lifecycle store. In v1 this is in-memory; swap for Postgres
    /// behind the same trait later.
    pub jobs: Arc<dyn JobRegistry>,
    /// Available agent drivers, keyed by name. Held by Arc since
    /// [`RunnerRegistry`] is not `Clone`.
    pub runners: Arc<RunnerRegistry>,
    /// Sink every job writes its lineage into. A single shared sink is
    /// fine for v1 because every edge is namespaced by its session's
    /// pod SPIFFE id — session subgraph extraction filters by URI prefix.
    pub sink: Arc<dyn LineageSink>,
    /// Signer used for every emitted lineage edge. The bundle's
    /// embedded JWKS is whatever this issuer publishes.
    pub issuer: Arc<LocalIssuer>,
    /// Trust domain authority used when minting fresh pod SPIFFE ids
    /// for new sessions (e.g. `"prod.example.com"`).
    pub trust_domain: String,
    /// SPIFFE namespace segment for new pods.
    pub namespace: String,
    /// SPIFFE service-account segment for new pods.
    pub service_account: String,
    /// Per-job event broker driving the SSE stream endpoint.
    pub events: Arc<JobEventBroker>,
    /// Optional Merkle inclusion-proof generator. When set, every job's
    /// bundle gains a `merkle_anchor` that binds its edges to a witness-
    /// signed root — clients with the witness pubkey can prove tree-
    /// inclusion offline. When `None`, bundles are v1 (chain-only).
    pub merkle_prover: Option<Arc<dyn MerkleProver>>,
    /// The witness verifying-key bytes corresponding to `merkle_prover`.
    /// `Some` iff `merkle_prover.is_some()`. Exposed on the API so the
    /// server can publish it alongside the JWKS — clients use it for
    /// `nucleus envelope-verify --witness-pub`.
    pub witness_pubkey: Option<[u8; 32]>,
    /// **MED-6 (audit) fix.** Semaphore bounding concurrent in-flight
    /// jobs to [`MAX_INFLIGHT_JOBS`]. The submit handler acquires a
    /// permit via `try_acquire_owned`; on failure returns 503
    /// `at_capacity`. The permit is held by the spawned task and
    /// dropped when the terminal state is published.
    pub job_slots: Arc<Semaphore>,
    /// **Iter-1 of #79.** Optional SPIFFE JWT-SVID Bearer auth.
    /// When `None`, every endpoint is open (legacy MVP behavior).
    /// When `Some`, the `RequireSpiffeAuth` extractor on protected
    /// routes rejects unauthenticated traffic with 401/403. Wired
    /// into AppState as an `Arc` so it's cheap to clone alongside
    /// the rest of the state.
    pub spiffe_auth: Option<Arc<SpiffeAuthConfig>>,
}

impl AppState {
    /// Construct a fresh pod SPIFFE id for a new job session — UNIQUE
    /// PER CALL. The service account segment carries a UUID suffix
    /// (`<sa>-<uuid>`) so two concurrent jobs never share a session
    /// root.
    ///
    /// Why per-session uniqueness matters: the envelope extractor
    /// (`extract_session_subgraph`) filters edges by SPIFFE URI prefix
    /// over a shared sink. If every job shared the same pod URI,
    /// concurrent jobs' edges would all match each other's prefix
    /// filter and bundle envelopes would cross-contaminate. The chain
    /// check would then fail because each job's signed `prev_hash`
    /// values reflect that job's emission order, not the interleaved
    /// global order.
    ///
    /// The returned id is pod-shaped (no `/call/` suffix), so the
    /// envelope verifier's `is_pod()` check passes. The unique SA
    /// segment is a structural property of the id; the `trust_domain`
    /// and `namespace` remain the deployment's identity.
    pub fn new_session_pod(&self) -> CallSpiffeId {
        let unique_sa = format!("{}-{}", self.service_account, uuid::Uuid::new_v4());
        CallSpiffeId::pod(&self.trust_domain, &self.namespace, &unique_sa).expect(
            "trust_domain/namespace + per-session SA must produce a valid pod id; \
             check that trust_domain/namespace/service_account args satisfy SPIFFE charset",
        )
    }
}

/// Construct an [`AppState`] with the in-memory registry, a fresh
/// random demo issuer, and a caller-supplied sink. Convenience wrapper
/// used by tests and the binary.
pub fn build_demo_state(
    runners: RunnerRegistry,
    sink: Arc<dyn LineageSink>,
    trust_domain: impl Into<String>,
    namespace: impl Into<String>,
    service_account: impl Into<String>,
) -> Result<AppState, anyhow::Error> {
    Ok(AppState {
        jobs: Arc::new(InMemoryRegistry::new()),
        runners: Arc::new(runners),
        sink,
        issuer: Arc::new(LocalIssuer::random()?),
        trust_domain: trust_domain.into(),
        namespace: namespace.into(),
        service_account: service_account.into(),
        events: Arc::new(JobEventBroker::new()),
        merkle_prover: None,
        witness_pubkey: None,
        job_slots: Arc::new(Semaphore::new(MAX_INFLIGHT_JOBS)),
        spiffe_auth: None,
    })
}
