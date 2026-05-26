//! Router assembly.

use std::time::Duration;

use axum::{
    http::StatusCode,
    routing::{get, post},
    Router,
};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

use crate::routes;
use crate::state::AppState;

/// Build the axum [`Router`] with all routes mounted. The returned
/// router is ready to hand to `axum::serve` or to drive synchronously
/// in tests via `tower::ServiceExt::oneshot`.
///
/// Middleware stack (outer → inner):
/// - `TraceLayer` — emits `tracing` spans for each request.
/// - `TimeoutLayer` (60s) — cap any single request so a stuck runner
///   doesn't hold a connection indefinitely. Increase for slow drivers.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(routes::healthz))
        .route("/v1/jobs", post(routes::submit_job))
        .route("/v1/jobs/{job_id}", get(routes::get_job))
        .route("/v1/jobs/{job_id}/bundle", get(routes::get_bundle))
        .route(
            "/v1/jobs/{job_id}/events/stream",
            get(routes::stream_job_events),
        )
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ))
        .with_state(state)
}
