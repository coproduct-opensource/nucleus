//! Router assembly.

use std::time::Duration;

use axum::{
    http::{header, Method, StatusCode},
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::SqlitePool;

use crate::merkle::SharedMerkleLog;
use tower::limit::ConcurrencyLimitLayer;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::routes;
use crate::signing::VerifierSigner;

/// Per-IP rate limit applied to every endpoint. Configured around the
/// most-expensive endpoint (`POST /v1/verify`), which can do up to
/// thousands of Ed25519 verifies on a single request. tower-governor
/// gives us a token-bucket per peer IP via `governor::Quota`.
///
/// **Default policy**: 1 token regenerated per second, burst capacity
/// of 60. A client can fire 60 requests immediately, then must space
/// follow-ups to ~1/sec sustained. Tuned so a developer kicking the
/// tires never hits the limit but a hostile spammer does.
///
/// Operators tuning this for a high-traffic deployment should add a
/// CDN/WAF in front first (Cloudflare's free tier handles 10k+ req/sec)
/// and use this as defense-in-depth only.
const RATE_LIMIT_REPLENISH_SECS: u64 = 1;
const RATE_LIMIT_BURST_SIZE: u32 = 60;

/// Shared state for verifier-service handlers.
///
/// `db` is `None` in legacy stateless mode (the default); when `Some`,
/// the verify endpoint records every result and the hash-lookup
/// endpoint reads from it. `signer` is `None` when STH signing is
/// disabled (chain head is still computed, just unsigned); when
/// `Some`, the STH endpoint returns a signed tree head and
/// `/.well-known/jwks.json` publishes the matching public key.
#[derive(Clone, Default)]
pub struct AppState {
    /// Optional persistence pool. When `None`, the service runs in
    /// the original stateless mode and bundle hash-lookup returns 404
    /// for every request ("persistence disabled"). When `Some`, the
    /// pool is shared (cheap Arc-backed clone) across all handlers.
    pub db: Option<SqlitePool>,
    /// Optional Ed25519 signer for the verification log's STH.
    /// `None` means iter-1 behavior (unsigned `root_hash_hex` chain
    /// head); `Some` flips `signed: true` and adds a base64 signature
    /// + `kid` to the STH response.
    pub signer: Option<Arc<VerifierSigner>>,
    /// Optional Prometheus exporter handle. When `Some`, the
    /// `/metrics` route renders the registered metrics; counters +
    /// histograms inside `verify` log via the `metrics` macros.
    /// `None` means the route returns 503 — metrics are deliberately
    /// opt-in so the test harness doesn't install a process-global
    /// recorder.
    pub metrics: Option<Arc<PrometheusHandle>>,
    /// **Iter-3 of #69 (#95).** RFC 9162 Merkle tree over the same
    /// leaves as the chain-hash log. When `Some`, the STH endpoint
    /// publishes `merkle_root_hex` alongside the chain head, and
    /// `/v1/log/inclusion-proof` + `/v1/log/consistency-proof` are
    /// live. When `None`, those endpoints 503 (test path).
    pub merkle: Option<SharedMerkleLog>,
    /// **#73 iter-1.** Peer witness federation handle. When `Some`,
    /// `/v1/witness/peer-sth` accepts cosignatures from configured
    /// peers and `/v1/witness/peers` exposes the ring. When `None`,
    /// both endpoints return 503.
    pub witness: Option<crate::witness::WitnessFederation>,
    /// Signed Agent Card published at `/.well-known/agent-card.json`. When
    /// `Some`, the service serves its own verify-before-you-act identity
    /// document (an A2A-style card whose detached JWS verifies against the
    /// operator's out-of-band-resolved key). When `None`, the endpoint
    /// returns 404 — the service makes no identity claim.
    pub agent_card: Option<Arc<nucleus_agent_card::SignedAgentCard>>,
    /// Durable, append-only, per-identity credit ledger (set via
    /// `--credit-db` / `NUCLEUS_CREDIT_DB_PATH`). When `Some`, the stateful
    /// credit endpoints — `POST /v1/credit/{agent_id}/accrue` and
    /// `GET /v1/credit/{agent_id}` — persist and re-fold an agent's
    /// recompute-verified history. When `None`, those endpoints return 503
    /// (the default deployment is unchanged: only the stateless `POST
    /// /v1/credit` has behavior). `redb::Database` is `Send + Sync` but not
    /// `Clone`, so it is shared behind `Arc`.
    pub credit_store: Option<Arc<nucleus_creditworthiness::store::CreditLedgerStore>>,
}

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
pub fn build_app(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        // CONTENT_TYPE for every JSON body; the two `x-nucleus-*` headers carry
        // the detached Ed25519 signature + signer pubkey that authenticate
        // `POST /v1/credit/{agent_id}/accrue` (see `crate::auth`). Browser
        // clients can't send them cross-origin unless they're allow-listed here.
        .allow_headers([
            header::CONTENT_TYPE,
            axum::http::HeaderName::from_static(crate::auth::PUBKEY_HEADER),
            axum::http::HeaderName::from_static(crate::auth::SIGNATURE_HEADER),
        ]);

    Router::new()
        .route("/", get(routes::root))
        .route("/quickstart", get(routes::quickstart))
        .route("/static/style.css", get(routes::landing_css))
        .route("/static/quickstart.css", get(routes::quickstart_css))
        .route("/static/quickstart.js", get(routes::quickstart_js))
        .route(
            "/static/wasm/nucleus_verifier_wasm.js",
            get(routes::wasm_js_shim),
        )
        .route(
            "/static/wasm/nucleus_verifier_wasm_bg.wasm",
            get(routes::wasm_binary),
        )
        .route("/healthz", get(routes::healthz))
        .route("/v1/verify", post(routes::verify))
        .route("/v1/credit", post(routes::credit))
        // Stateful credit ledger (503 unless --credit-db is set). `accrue`
        // appends an agent's recompute-verified events to its durable,
        // hash-chained ledger; the GET returns its persisted standing.
        .route("/v1/credit/{agent_id}/accrue", post(routes::credit_accrue))
        .route("/v1/credit/{agent_id}", get(routes::credit_standing))
        .route(
            "/v1/bundles/{hash}/verify",
            get(routes::bundle_verify_lookup),
        )
        .route("/v1/log/size", get(routes::log_size_endpoint))
        .route("/v1/log/sth", get(routes::log_sth_endpoint))
        .route("/v1/log/inclusion-proof", get(routes::log_inclusion_proof))
        .route(
            "/v1/log/consistency-proof",
            get(routes::log_consistency_proof),
        )
        .route("/metrics", get(routes::metrics_endpoint))
        .route(
            "/v1/witness/peer-sth",
            post(routes::witness_accept_peer_sth),
        )
        .route("/v1/witness/peers", get(routes::witness_list_peers))
        .route("/.well-known/jwks.json", get(routes::well_known_jwks))
        .route(
            "/.well-known/agent-card.json",
            get(routes::well_known_agent_card),
        )
        .route(
            "/.well-known/nucleus-verifier-configuration",
            get(routes::well_known_configuration),
        )
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(cors)
        .with_state(state)
}

/// Wrap a router with per-IP rate limiting. Call this from production
/// main.rs BEFORE serving — the resulting router MUST be served via
/// `into_make_service_with_connect_info::<SocketAddr>()` so
/// tower-governor's default `PeerIpKeyExtractor` can find the
/// connecting client's IP. Without that connect-info plumbing every
/// request returns 500.
///
/// Returns a router with the same routes, plus a token-bucket
/// per-peer-IP that allows
/// [`RATE_LIMIT_BURST_SIZE`] requests immediately and replenishes
/// one token every [`RATE_LIMIT_REPLENISH_SECS`] seconds.
pub fn with_rate_limit(router: Router) -> Router {
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(RATE_LIMIT_REPLENISH_SECS)
            .burst_size(RATE_LIMIT_BURST_SIZE)
            .finish()
            .expect("governor config validation passed at build time"),
    );
    router.layer(GovernorLayer::new(governor_conf))
}
