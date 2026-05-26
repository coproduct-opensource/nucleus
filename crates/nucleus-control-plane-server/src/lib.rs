//! REST API server wrapping [`nucleus_control_plane`] for HTTP job
//! submission and bundle delivery.
//!
//! Surface is intentionally minimal for the MVP:
//!
//! | Endpoint                     | Purpose                              |
//! |------------------------------|--------------------------------------|
//! | `POST /v1/jobs`              | Submit a `JobSpec` (returns 202)     |
//! | `GET  /v1/jobs/{id}`         | Status snapshot                      |
//! | `GET  /v1/jobs/{id}/bundle`  | Fetch the verified bundle on success |
//! | `GET  /healthz`              | Liveness                             |
//!
//! `Idempotency-Key` (request header) collapses repeat submissions of the
//! same logical job within a configurable retention window.
//!
//! # Deferred surface (3c+)
//!
//! - `GET /v1/jobs/{id}/events/stream` (SSE)
//! - Webhook delivery via `Destination::HttpPost` (needs a signing
//!   story to be product-grade)
//! - `POST /v1/jobs/{id}/cancel`
//! - Auth middleware (SPIFFE-mTLS / Bearer — nucleus has SPIFFE infra
//!   elsewhere; wire it in slice 4)
//!
//! # Trust model reminder
//!
//! The server signs lineage edges with an [`EdgeSigner`] supplied at
//! construction. The JWKS embedded in each bundle's envelope is whatever
//! that signer publishes — clients MUST treat the bundle's `jwks` as
//! producer-controlled and verify against an out-of-band trust anchor,
//! per `nucleus_envelope`'s [`TrustAnchor`] requirement.
//!
//! [`EdgeSigner`]: nucleus_lineage::EdgeSigner
//! [`TrustAnchor`]: nucleus_envelope::TrustAnchor

pub mod app;
pub mod error;
pub mod registry;
pub mod routes;
pub mod state;

pub use app::build_app;
pub use error::ApiError;
pub use registry::{InMemoryRegistry, JobRegistry, JobRegistryError, RunnerRegistry};
pub use state::AppState;
