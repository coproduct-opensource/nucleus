//! Router assembly.

use std::time::Duration;

use axum::{
    http::StatusCode,
    routing::{get, post},
    Router,
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};

use crate::routes;
use crate::state::AppState;

/// Max request body bytes for the standard (non-SSE) routes.
/// JobSpec.input_ref.Inline.content is the only large field a client
/// can stuff bytes into; 256 KiB cap rejects pathological inputs while
/// covering normal use.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Build the axum [`Router`] with all routes mounted.
///
/// The standard routes (`/healthz`, `/v1/jobs/...` except the SSE
/// stream) get a 60-second `TimeoutLayer` and a 256 KiB body cap. The
/// SSE stream is mounted on a sub-router that DELIBERATELY skips the
/// global timeout — SSE connections are long-lived by design and a
/// 60-second cut-off would break legitimate clients.
pub fn build_app(state: AppState) -> Router {
    // Long-lived endpoints (SSE) — no global timeout. Trace + body
    // limit still apply because they're applied at the top level.
    let streaming = Router::new().route(
        "/v1/jobs/{job_id}/events/stream",
        get(routes::stream_job_events),
    );

    // Standard request/response endpoints.
    let standard = Router::new()
        .route("/healthz", get(routes::healthz))
        .route("/v1/jobs", post(routes::submit_job))
        .route("/v1/jobs/{job_id}", get(routes::get_job))
        .route("/v1/jobs/{job_id}/cancel", post(routes::cancel_job))
        .route("/v1/jobs/{job_id}/bundle", get(routes::get_bundle))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ));

    standard
        .merge(streaming)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
