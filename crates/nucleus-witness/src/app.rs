//! Router assembly for the witness server. Mirrors the axum 0.8 +
//! shared-state pattern used by `nucleus-verifier-service`.

use std::time::Duration;

use axum::{
    http::StatusCode,
    routing::{get, post},
    Router,
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};

use crate::server::{add_checkpoint_handler, WitnessState};

/// Max request body size. A checkpoint + up to 63 consistency-proof
/// lines + signatures is a few KiB; 64 KiB is generous while bounding
/// trivial DoS via giant bodies.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// `GET /healthz` — liveness.
async fn healthz() -> &'static str {
    "ok"
}

/// Build the witness router.
pub fn build_app(state: WitnessState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/add-checkpoint", post(add_checkpoint_handler))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .with_state(state)
}
