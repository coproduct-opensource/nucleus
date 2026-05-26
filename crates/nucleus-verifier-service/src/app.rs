//! Router assembly.

use std::time::Duration;

use axum::{
    http::{header, Method, StatusCode},
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::routes;

/// Max request body size in bytes. Provenance bundles are bounded by
/// the size of the lineage subgraph; a 2 MiB ceiling comfortably covers
/// thousand-edge sessions while preventing trivial DoS via giant
/// payloads.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Build the router.
///
/// Middleware:
/// - **CORS**: allows POST/GET from any origin BUT does NOT advertise
///   `Access-Control-Allow-Credentials: true`. `CorsLayer::permissive()`
///   is the canonical CSRF amplifier (Allow-Origin: * + credentials =
///   any attacker page can read responses with the victim's cookies if
///   any are ever introduced). The verifier is a public, no-auth
///   surface, so we want public CORS but explicitly no credentials.
/// - **Body limit**: 2 MiB cap rejects pathological payloads.
/// - **Timeout**: 30s per request.
/// - **Tracing**: spans per request.
pub fn build_app() -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

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
        .layer(cors)
}
