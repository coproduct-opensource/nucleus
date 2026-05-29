//! Router assembly + hardened middleware stack.
//!
//! Mirrors `nucleus-verifier-service/src/app.rs` so the audit work
//! from the v2.x cycle (MED-5 concurrency limit, MED-6 body limit,
//! timeout discipline) lands here verbatim — no re-litigation.
//!
//! # Middleware order (request flow inward, response flow outward)
//!
//! Layers are added bottom-up; later `.layer(...)` calls become
//! OUTERMOST. Effective request flow:
//!
//! 1. CORS (rejects unsuitable preflights before any other work)
//! 2. Timeout (10s; cancels everything below if exceeded)
//! 3. Concurrency limit (256 in-flight; excess requests queue at this layer)
//! 4. Body size limit (64 KiB; rejects oversized payloads early)
//! 5. TraceLayer (per-request tracing spans)
//! 6. Handler (route-specific logic)

use std::sync::Arc;
use std::time::Duration;

use axum::{
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::discovery;
use crate::federation::FederationRegistry;
use crate::issuer::JwtIssuer;
use crate::jwks;
use crate::keystore::JwtKeyStore;
use crate::spire::SpireBundleProvider;
use crate::token;
use nucleus_oidc_core::JtiCache;

/// Max request body in bytes. Token-exchange requests are small
/// (a few hundred bytes of form-encoded fields + a JWT subject_token
/// rarely > 8 KiB). 64 KiB leaves headroom for unusually large
/// subject_tokens while rejecting trivial DoS via giant payloads.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Max concurrent in-flight requests. Each token-exchange does up to
/// ~1ms of cryptographic work (Ed25519 sign + jti cache check); 256
/// gives ~256k req/s upper bound on this layer, comfortably above
/// any sane single-replica load. Operators must front the OP with
/// per-IP rate limiting at the edge (WAF / nginx) for hostile traffic;
/// this layer is a fast-path defense, not per-client throttling.
const MAX_CONCURRENT_REQUESTS: usize = 256;

/// Per-request timeout. Worst-case cryptographic path is single-digit
/// milliseconds; 10s catches pathological clients without affecting
/// legitimate traffic.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared state plumbed via `axum::extract::State`.
///
/// Cheap to `Clone` — every field is an `Arc<…>` so cloning is just
/// reference-counting. Per-route handlers take `State<AppState>` and
/// access fields directly.
#[derive(Clone)]
pub struct AppState {
    pub keystore: Arc<dyn JwtKeyStore>,
    /// The OP's external HTTPS issuer URL — what we advertise as `iss`
    /// in minted tokens, in the discovery doc, and as the prefix the
    /// JWKS URL is derived from. MUST start with `https://`.
    pub issuer_url: Arc<str>,
    /// Token-mint helper bound to the keystore + issuer URL. Built
    /// once at startup; per-request mint calls reuse it.
    pub issuer: Arc<JwtIssuer>,
    /// Replay-defense cache for subject_token `jti` values at the
    /// token endpoint. Stub today; swapped to nucleus-oidc-core's
    /// shared `JtiCache` when task #38 resumes.
    pub jti_cache: Arc<JtiCache>,
    /// Declarative `(subject_prefix, audience, allowed_grants,
    /// max_lifetime)` registry. Token endpoint consults this for every
    /// exchange; default-deny when empty.
    pub federation: Arc<FederationRegistry>,
    /// SPIRE trust-bundle source — validates subject_token signatures
    /// against per-trust-domain verifying keys (#45).
    pub bundle_provider: Arc<dyn SpireBundleProvider>,
}

/// Build the OP router with the full hardened middleware stack.
///
/// Routes:
/// - `GET /healthz` — operator-meaningful liveness (key-store loaded,
///   federation rule count).
/// - `GET /jwks.json` — RFC 7517 verify-set (task #35).
/// - `GET /.well-known/openid-configuration` — RFC 8414 discovery (task #36).
/// - `POST /oauth/token` — RFC 8693 token exchange (task #39).
pub fn build_app(state: AppState) -> Router {
    // CORS: permissive on discovery + JWKS (public configuration),
    // restricted to POST + headers on /oauth/token. Single layer
    // (axum 0.8 doesn't easily compose per-route CORS); we pick
    // the most permissive shape across our routes and document the
    // tightening operators should apply via edge config.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);
    // NOTE: no `.allow_credentials(true)` — the OP is a no-auth
    // public surface; combining `Allow-Origin: *` with credentials
    // is the canonical CSRF amplifier we explicitly avoid.

    Router::new()
        .route("/healthz", get(healthz))
        .route("/jwks.json", get(jwks::handler))
        .route("/.well-known/openid-configuration", get(discovery::handler))
        .route("/oauth/token", post(token::handler))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(cors)
        .with_state(state)
}

/// Wire shape of the healthz body — JSON so operators can graph each
/// subsystem state directly.
#[derive(Debug, Serialize)]
struct HealthBody {
    ok: bool,
    /// The active KID (RFC 7638 thumbprint of the active signing key)
    /// or an empty string if the key store hasn't bootstrapped.
    active_kid: String,
    /// Number of verify-set entries — active + grace-window keys.
    verify_keys: usize,
    /// Currently-loaded federation rules. 0 means default-deny —
    /// operators should see this in dashboards and load rules.
    federation_rules: usize,
    /// (#55 LOW-4) Total verifying keys across all trust-domains in
    /// the SPIRE trust bundle. 0 means the token endpoint will
    /// reject every subject_token — observable directly rather than
    /// hidden behind every Deny.
    bundle_keys: usize,
}

/// Operator-meaningful health check.
///
/// Returns 200 + JSON body when:
/// - Key store can be queried for an active KID.
/// - Federation registry can return a rule count (always succeeds).
///
/// Returns 503 + JSON body if the key store is poisoned or otherwise
/// unable to return its active KID (e.g., on persistent backend
/// failure). The body keeps the rest of the state visible so the
/// operator can diagnose without reading logs.
async fn healthz(axum::extract::State(state): axum::extract::State<AppState>) -> impl IntoResponse {
    let active_kid = state.keystore.active_kid().unwrap_or_default();
    let verify_keys = state
        .keystore
        .all_verify_keys()
        .map(|v| v.len())
        .unwrap_or(0);
    let federation_rules = state.federation.rule_count();
    let bundle_keys = state.bundle_provider.total_key_count();

    let ok = !active_kid.is_empty();
    let body = HealthBody {
        ok,
        active_kid,
        verify_keys,
        federation_rules,
        bundle_keys,
    };
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let issuer = Arc::new(
            JwtIssuer::new(
                store.clone(),
                "https://oidc.nucleus.example/".to_string(),
                Duration::from_secs(300),
            )
            .unwrap(),
        );
        build_app(AppState {
            keystore: store,
            issuer_url: Arc::from("https://oidc.nucleus.example/"),
            issuer,
            jti_cache: Arc::new(JtiCache::new()),
            federation: Arc::new(FederationRegistry::empty()),
            bundle_provider: Arc::new(crate::spire::StaticBundleProvider::new()),
        })
    }

    async fn body_to_value(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_operator_meaningful_state_when_bootstrapped() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_value(resp.into_body()).await;
        assert_eq!(body["ok"], true);
        // active_kid is the RFC 7638 thumbprint — 43 chars base64url-no-pad.
        assert_eq!(body["active_kid"].as_str().unwrap().len(), 43);
        // Fresh store has 1 verify-set entry.
        assert_eq!(body["verify_keys"], 1);
        // Empty federation registry has 0 rules.
        assert_eq!(body["federation_rules"], 0);
    }

    #[tokio::test]
    async fn body_limit_rejects_oversized_post() {
        // MAX_BODY_BYTES = 64 KiB. Send 128 KiB.
        let huge_body = "x=".to_string() + &"A".repeat(128 * 1024);
        let resp = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(huge_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // tower-http's RequestBodyLimitLayer returns 413 Payload Too Large.
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn cors_advertises_get_post_options_without_credentials() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/oauth/token")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // CORS preflight should succeed.
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "preflight got {}",
            resp.status()
        );
        let methods = resp
            .headers()
            .get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        for m in ["GET", "POST", "OPTIONS"] {
            assert!(methods.contains(m), "expected {m:?} in {methods:?}");
        }
        // Critical: no credentials advertised — closes the CSRF amplifier
        // documented in `THREAT_MODEL.md`.
        assert!(
            resp.headers()
                .get("access-control-allow-credentials")
                .is_none(),
            "Allow-Credentials must NOT be advertised on a public no-auth surface"
        );
    }
}
