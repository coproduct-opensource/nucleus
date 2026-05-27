//! Router assembly.

use std::time::Duration;

use axum::{
    http::{header, Method, StatusCode},
    routing::{get, post},
    Router,
};
use tower::limit::ConcurrencyLimitLayer;
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

/// **MED-5 (audit) fix.** Maximum concurrent in-flight requests across
/// the whole service. Each verify request does up to
/// `MAX_ENVELOPE_EDGES (10_000) * 1 Ed25519 verify` plus inclusion-proof
/// work — under heavy concurrent load these would pin all worker
/// threads. 256 leaves headroom for legitimate traffic while bounding
/// the worst case. Operators in production should ALSO front the
/// service with k8s HPA + tower-governor / WAF-side rate limiting per
/// client IP — `ConcurrencyLimitLayer` is a fast-path defense, NOT a
/// per-client rate limit.
const MAX_CONCURRENT_REQUESTS: usize = 256;

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
/// - **Concurrency limit (MED-5)**: 256 in-flight requests. Excess
///   requests are queued at the tower layer (no 503 emitted; they
///   wait for a slot) — combined with the 30s timeout, this bounds
///   total worker thread occupancy under load.
/// - **Timeout**: 30s per request.
/// - **Tracing**: spans per request.
///
/// # Operator notes
///
/// This service is public + no-auth by design (verification is a
/// public function; bundles are self-contained certificates). For
/// production deployments:
///
/// 1. Front with k8s HPA or autoscaling proxy to spread load across
///    replicas.
/// 2. Add per-IP rate limiting at the edge (Cloudflare WAF / nginx
///    `limit_req_zone` / `tower-governor` middleware).
/// 3. Monitor `MAX_CONCURRENT_REQUESTS` saturation as a load signal.
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
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(cors)
}
