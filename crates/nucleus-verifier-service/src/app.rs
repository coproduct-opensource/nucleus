//! Router assembly.

use std::time::Duration;

use axum::{
    http::StatusCode,
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::CorsLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer,
};

use crate::routes;

/// Max request body size in bytes. Provenance bundles are bounded by
/// the size of the lineage subgraph; a 2 MiB ceiling comfortably covers
/// thousand-edge sessions while preventing trivial DoS via giant
/// payloads.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Build the router. Layered with:
/// - permissive CORS so browsers can verify from any origin
/// - request-body size limit (anti-DoS)
/// - per-request timeout
/// - tracing
pub fn build_app() -> Router {
    Router::new()
        .route("/", get(routes::root))
        .route("/healthz", get(routes::healthz))
        .route("/v1/verify", post(routes::verify))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(CorsLayer::permissive())
}
