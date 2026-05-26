//! Server-wide shared state.

use std::sync::Arc;

use nucleus_lineage::{CallSpiffeId, LineageSink, LocalIssuer};

use crate::registry::{InMemoryRegistry, JobRegistry, RunnerRegistry};

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
}

impl AppState {
    /// Construct a fresh pod SPIFFE id for a new job session. Format:
    /// `spiffe://<trust>/ns/<ns>/sa/<sa>/call/<uuid>/job`. The trailing
    /// `/call/<uuid>/job` makes each session structurally distinct so
    /// concurrent jobs don't share a SPIFFE root.
    ///
    /// NOTE: this returns a child id (has `/call/` suffix), NOT a pure
    /// pod id. v1 envelope verification requires session_root to be pod-
    /// shaped, so callers must use the parent (`.parent()`) as the
    /// session root. The child id is what the runner derives from.
    pub fn new_session_pod(&self) -> CallSpiffeId {
        // A pure pod id without a per-session uuid suffix. Concurrent
        // sessions all share the same pod root and rely on the
        // `/call/<uuid>` segments their edges add to disambiguate.
        // This matches the existing three_step_demo.rs convention.
        CallSpiffeId::pod(&self.trust_domain, &self.namespace, &self.service_account)
            .expect("trust_domain/namespace/sa configured at startup must produce a valid pod id")
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
    })
}
