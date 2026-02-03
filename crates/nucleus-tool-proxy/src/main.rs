use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use clap::Parser;
use nucleus::lattice_guard::{CapabilityLevel, Operation};
use nucleus::{
    ApprovalRequest, BudgetModel, CallbackApprover, NucleusError, PodRuntime,
    PodSpec as RuntimePodSpec,
};
use nucleus_spec::{BudgetModelSpec, PodSpec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

mod attestation;
mod auth;
mod mtls;

use attestation::{AttestationConfig, AttestationVerifier};
use auth::{AuthConfig, AuthError};
use mtls::{ClientCertInfo, MtlsConfig, MtlsConnectInfo, MtlsListener};
use nucleus_client::drand::{DrandConfig, DrandFailMode};

#[derive(Parser, Debug)]
#[command(name = "nucleus-tool-proxy")]
#[command(about = "Tool proxy server running inside nucleus pods")]
struct Args {
    /// Pod spec YAML path.
    #[arg(long, env = "NUCLEUS_POD_SPEC")]
    spec: PathBuf,
    /// Listen address for the tool proxy (TCP).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_LISTEN", default_value = "127.0.0.1:0")]
    listen: String,
    /// Optional path to write the bound address for discovery.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ANNOUNCE")]
    announce_path: Option<PathBuf>,
    /// Optional vsock CID override.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_VSOCK_CID")]
    vsock_cid: Option<u32>,
    /// Optional vsock port override.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_VSOCK_PORT")]
    vsock_port: Option<u32>,
    /// Shared secret for HMAC request signing.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUTH_SECRET")]
    auth_secret: String,
    /// Maximum allowed clock skew (seconds) for signed requests.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_AUTH_MAX_SKEW_SECS",
        default_value_t = 60
    )]
    auth_max_skew_secs: u64,
    /// Audit log path.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_AUDIT_LOG",
        default_value = "/tmp/nucleus-audit.log"
    )]
    audit_log: PathBuf,
    /// Optional audit log signing secret (defaults to auth secret if omitted).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_SECRET")]
    audit_secret: Option<String>,
    /// Approval authority secret (separate from tool auth).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET")]
    approval_secret: String,
    /// Optional webhook URL for remote audit log delivery.
    /// Entries are POSTed as JSON with HMAC signature in X-Nucleus-Signature header.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_WEBHOOK")]
    audit_webhook: Option<String>,
    /// Timeout in seconds for web fetch requests.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_WEB_FETCH_TIMEOUT_SECS",
        default_value_t = 30
    )]
    web_fetch_timeout_secs: u64,
    /// Maximum response body size in bytes for web fetch.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_WEB_FETCH_MAX_BYTES",
        default_value_t = 10 * 1024 * 1024
    )]
    web_fetch_max_bytes: usize,
    /// Require attestation for all requests.
    /// When enabled, requests must include valid VM attestation.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_REQUIRE_ATTESTATION")]
    require_attestation: bool,
    /// Comma-separated list of allowed kernel hashes (SHA-256, hex).
    /// If empty, any kernel hash is accepted when attestation is present.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ALLOWED_KERNEL_HASHES")]
    allowed_kernel_hashes: Option<String>,
    /// Comma-separated list of allowed rootfs hashes (SHA-256, hex).
    /// If empty, any rootfs hash is accepted when attestation is present.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ALLOWED_ROOTFS_HASHES")]
    allowed_rootfs_hashes: Option<String>,
    /// Comma-separated list of allowed config hashes (SHA-256, hex).
    /// If empty, any config hash is accepted when attestation is present.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ALLOWED_CONFIG_HASHES")]
    allowed_config_hashes: Option<String>,

    // === mTLS Configuration ===
    /// Enable mTLS mode. Requires --tls-cert and --tls-key and --trust-bundle.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_MTLS")]
    mtls: bool,
    /// Path to server certificate PEM file (for mTLS).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TLS_CERT")]
    tls_cert: Option<std::path::PathBuf>,
    /// Path to server private key PEM file (for mTLS).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TLS_KEY")]
    tls_key: Option<std::path::PathBuf>,
    /// Path to trust bundle PEM file (for mTLS client verification).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TRUST_BUNDLE")]
    trust_bundle: Option<std::path::PathBuf>,
    /// Trust domain for SPIFFE identity verification.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TRUST_DOMAIN")]
    trust_domain: Option<String>,

    // === Drand Configuration ===
    /// Enable drand anchoring for approval signatures.
    /// When enabled, approval requests must include a valid drand round number
    /// to prevent pre-computation attacks.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_DRAND_ENABLED", default_value_t = true)]
    drand_enabled: bool,
    /// Drand API endpoint URL.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_DRAND_URL",
        default_value = "https://api.drand.sh/public/latest"
    )]
    drand_url: String,
    /// Number of previous drand rounds to accept (tolerance for network latency).
    /// With tolerance=1, both current round N and previous round N-1 are valid.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_DRAND_TOLERANCE", default_value_t = 1)]
    drand_tolerance: u64,
    /// Drand failure mode when beacon is unavailable.
    /// - "strict": Reject requests (fail closed) - recommended for production
    /// - "cached": Use cached round for 60 seconds max
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_DRAND_FAIL_MODE",
        default_value = "strict"
    )]
    drand_fail_mode: String,
}

#[derive(Clone)]
struct AppState {
    runtime: Arc<PodRuntime>,
    approvals: Arc<ApprovalRegistry>,
    audit: Arc<AuditLog>,
    auth: AuthConfig,
    approval_auth: AuthConfig,
    approval_nonces: Arc<ApprovalNonceCache>,
    approval_rate_limiter: Arc<ApprovalRateLimiter>,
    web_client: reqwest::Client,
    web_fetch_max_bytes: usize,
    dns_allow: Vec<String>,
    attestation_verifier: AttestationVerifier,
}

#[derive(Default)]
struct ApprovalRegistry {
    approvals: Mutex<HashMap<String, ApprovalEntry>>,
}

#[derive(Default)]
struct ApprovalNonceCache {
    entries: Mutex<HashMap<String, u64>>,
}

impl ApprovalNonceCache {
    fn check_and_insert(&self, nonce: &str, expires_at_unix: u64, now: u64) -> bool {
        let mut guard = self.entries.lock().unwrap();
        guard.retain(|_, exp| *exp > now);
        if guard.contains_key(nonce) {
            return false;
        }
        guard.insert(nonce.to_string(), expires_at_unix);
        true
    }
}

/// Simple token bucket rate limiter for the approval endpoint.
/// Prevents DoS attacks by limiting approval requests per second.
struct ApprovalRateLimiter {
    /// Maximum tokens (burst capacity)
    max_tokens: u32,
    /// Tokens added per second
    refill_rate: u32,
    /// Current token count and last refill timestamp
    state: Mutex<(u32, u64)>,
}

impl ApprovalRateLimiter {
    fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            max_tokens,
            refill_rate,
            state: Mutex::new((max_tokens, now_unix())),
        }
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited.
    fn try_acquire(&self) -> bool {
        let mut guard = self.state.lock().unwrap();
        let (tokens, last_refill) = &mut *guard;
        let now = now_unix();

        // Refill tokens based on elapsed time
        let elapsed = now.saturating_sub(*last_refill);
        if elapsed > 0 {
            let refill = (elapsed as u32).saturating_mul(self.refill_rate);
            *tokens = (*tokens).saturating_add(refill).min(self.max_tokens);
            *last_refill = now;
        }

        // Try to consume a token
        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }
}

impl Default for ApprovalRateLimiter {
    fn default() -> Self {
        // Allow 10 approvals per second with burst of 20
        Self::new(20, 10)
    }
}

#[derive(Clone, Copy)]
struct ApprovalEntry {
    count: usize,
    expires_at_unix: Option<u64>,
}

impl ApprovalRegistry {
    fn approve(&self, operation: &str, count: usize, expires_at_unix: Option<u64>) {
        let mut guard = self.approvals.lock().unwrap();
        let entry = guard.entry(operation.to_string()).or_insert(ApprovalEntry {
            count: 0,
            expires_at_unix,
        });
        entry.count += count;
        entry.expires_at_unix = merge_expiry(entry.expires_at_unix, expires_at_unix);
    }

    fn consume(&self, operation: &str) -> bool {
        let mut guard = self.approvals.lock().unwrap();
        if let Some(entry) = guard.get_mut(operation) {
            if is_expired(entry.expires_at_unix) {
                guard.remove(operation);
                return false;
            }
            if entry.count > 0 {
                entry.count -= 1;
                if entry.count == 0 {
                    guard.remove(operation);
                }
                return true;
            }
        }
        false
    }
}

fn merge_expiry(existing: Option<u64>, incoming: Option<u64>) -> Option<u64> {
    match (existing, incoming) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn is_expired(expires_at_unix: Option<u64>) -> bool {
    match expires_at_unix {
        Some(ts) => ts <= now_unix(),
        None => false,
    }
}

#[derive(Debug, Deserialize)]
struct ReadRequest {
    path: String,
}

#[derive(Debug, Serialize)]
struct ReadResponse {
    contents: String,
}

#[derive(Debug, Deserialize)]
struct WriteRequest {
    path: String,
    contents: String,
}

#[derive(Debug, Serialize)]
struct WriteResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct RunRequest {
    command: String,
}

#[derive(Debug, Serialize)]
struct RunResponse {
    status: i32,
    success: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
struct ApproveRequest {
    operation: String,
    #[serde(default = "default_approve_count")]
    count: usize,
    #[serde(default)]
    expires_at_unix: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
}

fn default_approve_count() -> usize {
    1
}

const MAX_APPROVAL_TTL_SECS: u64 = 300;

#[derive(Debug, Serialize)]
struct ApproveResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct WebFetchRequest {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebFetchResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("spec error: {0}")]
    Spec(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_yaml::Error),
    #[error("nucleus error: {0}")]
    Nucleus(#[from] NucleusError),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("request body error: {0}")]
    Body(String),
    #[error("rate limited: too many approval requests")]
    RateLimited,
    #[error("web fetch error: {0}")]
    WebFetch(String),
    #[error("url not in dns_allow list: {0}")]
    DnsNotAllowed(String),
    #[error("attestation verification failed: {0}")]
    AttestationFailed(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, kind, operation) = match &self {
            ApiError::Nucleus(NucleusError::ApprovalRequired { operation }) => (
                StatusCode::FORBIDDEN,
                "approval_required",
                Some(operation.clone()),
            ),
            ApiError::Nucleus(NucleusError::BudgetExhausted { .. }) => {
                (StatusCode::PAYMENT_REQUIRED, "budget_exhausted", None)
            }
            ApiError::Nucleus(NucleusError::CommandDenied { .. }) => {
                (StatusCode::FORBIDDEN, "command_denied", None)
            }
            ApiError::Nucleus(NucleusError::PathDenied { .. }) => {
                (StatusCode::FORBIDDEN, "path_denied", None)
            }
            ApiError::Nucleus(NucleusError::SandboxEscape { .. }) => {
                (StatusCode::FORBIDDEN, "sandbox_escape", None)
            }
            ApiError::Nucleus(NucleusError::Io(_)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None)
            }
            ApiError::Nucleus(NucleusError::TimeViolation { .. }) => {
                (StatusCode::REQUEST_TIMEOUT, "time_violation", None)
            }
            ApiError::Nucleus(NucleusError::TrifectaBlocked { .. }) => {
                (StatusCode::FORBIDDEN, "trifecta_blocked", None)
            }
            ApiError::Nucleus(NucleusError::InsufficientCapability { .. }) => {
                (StatusCode::FORBIDDEN, "insufficient_capability", None)
            }
            ApiError::Nucleus(NucleusError::InvalidApproval { operation }) => (
                StatusCode::FORBIDDEN,
                "invalid_approval",
                Some(operation.clone()),
            ),
            ApiError::Nucleus(NucleusError::InvalidCharge { .. }) => {
                (StatusCode::BAD_REQUEST, "invalid_charge", None)
            }
            ApiError::Spec(_) => (StatusCode::BAD_REQUEST, "spec_error", None),
            ApiError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None),
            ApiError::Serde(_) => (StatusCode::BAD_REQUEST, "serde_error", None),
            ApiError::Auth(_) => (StatusCode::UNAUTHORIZED, "auth_error", None),
            ApiError::Body(_) => (StatusCode::BAD_REQUEST, "body_error", None),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None),
            ApiError::WebFetch(_) => (StatusCode::BAD_GATEWAY, "web_fetch_error", None),
            ApiError::DnsNotAllowed(_) => (StatusCode::FORBIDDEN, "dns_not_allowed", None),
            ApiError::AttestationFailed(_) => (StatusCode::FORBIDDEN, "attestation_failed", None),
        };

        let body = Json(ErrorBody {
            error: self.to_string(),
            kind: kind.to_string(),
            operation,
        });
        (status, body).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();
    let spec_contents = tokio::fs::read_to_string(&args.spec).await?;
    let spec: PodSpec =
        serde_yaml::from_str(&spec_contents).map_err(|e| ApiError::Spec(e.to_string()))?;

    let runtime = build_runtime(&spec)?;
    let approvals = Arc::new(ApprovalRegistry::default());
    let approver = CallbackApprover::new({
        let approvals = approvals.clone();
        move |request: &ApprovalRequest| approvals.consume(request.operation())
    });
    let runtime = runtime.with_approver(Arc::new(approver))?;

    let auth = AuthConfig::new(
        args.auth_secret.as_bytes(),
        Duration::from_secs(args.auth_max_skew_secs),
    );

    // Build drand config for approval signatures
    let drand_config = if args.drand_enabled {
        let fail_mode = match args.drand_fail_mode.to_lowercase().as_str() {
            "cached" => DrandFailMode::Cached,
            _ => DrandFailMode::Strict, // "degraded" is no longer supported, defaults to strict
        };
        Some(DrandConfig {
            enabled: true,
            api_url: args.drand_url.clone(),
            round_tolerance: args.drand_tolerance,
            cache_ttl: Duration::from_secs(25),
            fail_mode,
            chain_hash: None, // Verification happens on signer side
            public_key: None,
        })
    } else {
        None
    };

    let approval_auth = {
        let config = AuthConfig::new(
            args.approval_secret.as_bytes(),
            Duration::from_secs(args.auth_max_skew_secs),
        );
        if let Some(drand) = drand_config {
            config.with_drand(drand)
        } else {
            config
        }
    };

    let audit = build_audit_log(&args, &auth)?;

    // Build HTTP client for web fetch
    let web_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.web_fetch_timeout_secs))
        .user_agent("nucleus-tool-proxy/0.1")
        .build()
        .map_err(|e| ApiError::Spec(format!("failed to build HTTP client: {e}")))?;

    // Extract DNS allow list from spec
    let dns_allow = spec
        .spec
        .network
        .as_ref()
        .map(|n| n.dns_allow.clone())
        .unwrap_or_default();

    // Build attestation verifier
    let attestation_config = {
        let mut config = if args.require_attestation {
            AttestationConfig::required()
        } else {
            AttestationConfig::default()
        };
        if let Some(ref hashes) = args.allowed_kernel_hashes {
            config = config.with_kernel_hashes(hashes);
        }
        if let Some(ref hashes) = args.allowed_rootfs_hashes {
            config = config.with_rootfs_hashes(hashes);
        }
        if let Some(ref hashes) = args.allowed_config_hashes {
            config = config.with_config_hashes(hashes);
        }
        config
    };
    let attestation_verifier = AttestationVerifier::new(attestation_config);

    let state = AppState {
        runtime: Arc::new(runtime),
        approvals,
        audit,
        auth,
        approval_auth,
        approval_nonces: Arc::new(ApprovalNonceCache::default()),
        approval_rate_limiter: Arc::new(ApprovalRateLimiter::default()),
        web_client,
        web_fetch_max_bytes: args.web_fetch_max_bytes,
        dns_allow,
        attestation_verifier,
    };

    if let Err(err) = emit_boot_report(&state).await {
        warn!("failed to emit boot report: {err}");
    }

    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/read", post(read_file))
        .route("/v1/write", post(write_file))
        .route("/v1/run", post(run_command))
        .route("/v1/web_fetch", post(web_fetch))
        .route("/v1/approve", post(approve_operation))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_middleware));

    if let Some(vsock) = resolve_vsock(&args, &spec)? {
        serve_vsock(app, vsock, args.announce_path).await?;
        return Ok(());
    }

    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;

    if let Some(path) = args.announce_path.as_ref() {
        tokio::fs::write(path, addr.to_string()).await?;
    }

    // Check if mTLS is enabled
    if args.mtls {
        let mtls_config = build_mtls_config(&args).await?;
        let mtls_listener = MtlsListener::new(listener, &mtls_config)
            .map_err(|e| ApiError::Spec(format!("failed to create mTLS listener: {}", e)))?;

        info!(
            "nucleus-tool-proxy listening on {} (mTLS enabled, trust_domain={})",
            addr,
            args.trust_domain.as_deref().unwrap_or("not set")
        );

        // Use into_make_service_with_connect_info to inject MtlsConnectInfo
        axum::serve(
            mtls_listener,
            app.into_make_service_with_connect_info::<MtlsConnectInfo>(),
        )
        .await?;
    } else {
        info!("nucleus-tool-proxy listening on {}", addr);
        axum::serve(listener, app).await?;
    }

    Ok(())
}

/// Builds mTLS configuration from CLI arguments.
async fn build_mtls_config(args: &Args) -> Result<MtlsConfig, ApiError> {
    use nucleus_identity::{TrustBundle, WorkloadCertificate};

    let cert_path = args
        .tls_cert
        .as_ref()
        .ok_or_else(|| ApiError::Spec("--tls-cert required when --mtls is enabled".to_string()))?;

    let key_path = args
        .tls_key
        .as_ref()
        .ok_or_else(|| ApiError::Spec("--tls-key required when --mtls is enabled".to_string()))?;

    let bundle_path = args.trust_bundle.as_ref().ok_or_else(|| {
        ApiError::Spec("--trust-bundle required when --mtls is enabled".to_string())
    })?;

    // Read certificate and key
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .map_err(|e| ApiError::Spec(format!("failed to read TLS cert: {}", e)))?;

    let key_pem = tokio::fs::read_to_string(key_path)
        .await
        .map_err(|e| ApiError::Spec(format!("failed to read TLS key: {}", e)))?;

    let bundle_pem = tokio::fs::read_to_string(bundle_path)
        .await
        .map_err(|e| ApiError::Spec(format!("failed to read trust bundle: {}", e)))?;

    // Parse certificate and trust bundle
    let server_cert = WorkloadCertificate::from_pem(&cert_pem, &key_pem)
        .map_err(|e| ApiError::Spec(format!("failed to parse server certificate: {}", e)))?;

    let trust_bundle = TrustBundle::from_pem(&bundle_pem)
        .map_err(|e| ApiError::Spec(format!("failed to parse trust bundle: {}", e)))?;

    Ok(MtlsConfig::new(server_cert, trust_bundle))
}

const MAX_AUTH_BODY_BYTES: usize = 10 * 1024 * 1024;
const APPROVE_PATH: &str = "/v1/approve";
const HEALTH_PATH: &str = "/v1/health";
const HEADER_ATTESTATION: &str = "x-nucleus-attestation";

async fn auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_AUTH_BODY_BYTES)
        .await
        .map_err(|e| ApiError::Body(e.to_string()))?;

    // Skip attestation check for health endpoint
    if parts.uri.path() == HEALTH_PATH {
        let req = axum::http::Request::from_parts(parts, Body::from(bytes));
        return Ok(next.run(req).await);
    }

    // Verify attestation if required
    if state.attestation_verifier.is_required() {
        // Try to get client certificate from mTLS connection first
        // Check both direct ClientCertInfo and MtlsConnectInfo
        let client_cert_der = parts
            .extensions
            .get::<MtlsConnectInfo>()
            .and_then(|info| info.client_cert.as_ref())
            .or_else(|| parts.extensions.get::<ClientCertInfo>())
            .map(|cert| cert.der());

        let attestation_result = if let Some(cert_der) = client_cert_der {
            // mTLS mode: extract attestation from client certificate
            let spiffe_id = parts
                .extensions
                .get::<MtlsConnectInfo>()
                .and_then(|info| info.client_cert.as_ref())
                .and_then(|cert| cert.spiffe_id.clone());
            tracing::info!(
                spiffe_id = ?spiffe_id,
                path = %parts.uri.path(),
                method = %parts.method,
                event = "attestation_verify_mtls",
                "verifying attestation from client certificate"
            );
            state.attestation_verifier.verify_certificate(cert_der)
        } else if let Some(att_header) = parts.headers.get(HEADER_ATTESTATION) {
            // Fallback: attestation passed via header (base64-encoded DER)
            // This is less secure as headers can be spoofed
            tracing::warn!(
                path = %parts.uri.path(),
                method = %parts.method,
                event = "attestation_verify_header",
                "attestation via header (not mTLS) - consider enabling mTLS for production"
            );
            let att_value = att_header.to_str().map_err(|_| {
                ApiError::AttestationFailed("invalid attestation header encoding".to_string())
            })?;
            state.attestation_verifier.verify_header(att_value)
        } else {
            // No attestation provided
            attestation::AttestationResult {
                attestation_present: false,
                attestation: None,
                matches_requirements: false,
                rejection_reason: Some("attestation required but not provided (enable mTLS or send x-nucleus-attestation header)".to_string()),
            }
        };

        if !attestation_result.matches_requirements {
            let reason = attestation_result
                .rejection_reason
                .unwrap_or_else(|| "unknown attestation failure".to_string());
            return Err(ApiError::AttestationFailed(reason));
        }

        // Log successful attestation verification
        if let Some(ref info) = attestation_result.attestation {
            tracing::debug!(
                kernel_hash = %&info.kernel_hash[..16],
                rootfs_hash = %&info.rootfs_hash[..16],
                "attestation verified"
            );
        }
    }

    if parts.uri.path() == APPROVE_PATH {
        // Use drand-aware verification for approval requests
        let context = auth::verify_http_with_drand(&parts.headers, &bytes, &state.approval_auth)?;
        if context.drand_round.is_some() {
            tracing::info!(
                drand_round = context.drand_round,
                "approval request verified with drand anchoring"
            );
        }
        let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
        req.extensions_mut().insert(context);
        return Ok(next.run(req).await);
    }

    let context = auth::verify_http(&parts.headers, &bytes, &state.auth)?;
    let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(context);
    Ok(next.run(req).await)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn read_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, ApiError> {
    let path = req.path.clone();
    let contents = match state.runtime.sandbox().read_to_string(&path) {
        Ok(contents) => contents,
        Err(NucleusError::ApprovalRequired { operation }) => {
            let token = state
                .runtime
                .sandbox()
                .request_approval(operation.clone())?;
            state
                .runtime
                .sandbox()
                .read_to_string_approved(&path, &token)?
        }
        Err(err) => return Err(ApiError::Nucleus(err)),
    };

    audit_event(&state, &headers, "read", &path, "ok").await?;
    Ok(Json(ReadResponse { contents }))
}

async fn write_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, ApiError> {
    let path = req.path.clone();
    let contents = req.contents.clone();

    match state.runtime.sandbox().write(&path, contents.as_bytes()) {
        Ok(()) => {}
        Err(NucleusError::ApprovalRequired { operation }) => {
            let token = state
                .runtime
                .sandbox()
                .request_approval(operation.clone())?;
            state
                .runtime
                .sandbox()
                .write_approved(&path, contents.as_bytes(), &token)?;
        }
        Err(err) => return Err(ApiError::Nucleus(err)),
    }

    audit_event(&state, &headers, "write", &path, "ok").await?;
    Ok(Json(WriteResponse { ok: true }))
}

async fn run_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, ApiError> {
    let command = req.command.clone();
    let executor = state.runtime.executor();

    let output = match executor.run(&command) {
        Ok(output) => output,
        Err(NucleusError::ApprovalRequired { operation }) => {
            let token = executor.request_approval(&operation)?;
            executor.run_with_approval(&command, &token)?
        }
        Err(err) => return Err(ApiError::Nucleus(err)),
    };

    audit_event(&state, &headers, "run", &command, "ok").await?;
    Ok(Json(RunResponse {
        status: output.status.code().unwrap_or(-1),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }))
}

async fn web_fetch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<WebFetchRequest>,
) -> Result<Json<WebFetchResponse>, ApiError> {
    let url_str = req.url.clone();

    // Check web_fetch capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.web_fetch;
    if level == CapabilityLevel::Never {
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "web_fetch".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if trifecta requires approval for web_fetch
    if policy.requires_approval(Operation::WebFetch) {
        // For now, just check if we have an approval token
        if !state.approvals.consume("web_fetch") {
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("web_fetch {}", url_str),
            }));
        }
    }

    // Parse and validate URL
    let url =
        url::Url::parse(&url_str).map_err(|e| ApiError::WebFetch(format!("invalid URL: {e}")))?;

    // Check DNS allow list (if configured)
    if !state.dns_allow.is_empty() {
        let host = url
            .host_str()
            .ok_or_else(|| ApiError::WebFetch("URL has no host".into()))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let host_port = format!("{}:{}", host, port);

        let allowed = state.dns_allow.iter().any(|pattern| {
            // Match exact host:port or host (any port)
            pattern == &host_port || pattern == host || pattern.starts_with(&format!("{}:", host))
        });

        if !allowed {
            return Err(ApiError::DnsNotAllowed(host_port));
        }
    }

    // Build the request
    let method = req.method.as_deref().unwrap_or("GET").to_uppercase();
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| ApiError::WebFetch(format!("invalid method: {}", method)))?;

    let mut request = state.web_client.request(method, url);

    // Add custom headers
    if let Some(hdrs) = req.headers {
        for (key, value) in hdrs {
            request = request.header(&key, &value);
        }
    }

    // Add body if present
    if let Some(body) = req.body {
        request = request.body(body);
    }

    // Execute request
    let response = request
        .send()
        .await
        .map_err(|e| ApiError::WebFetch(format!("request failed: {e}")))?;

    let status = response.status().as_u16();

    // Collect response headers
    let response_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect();

    // Read body with size limit
    let bytes = response
        .bytes()
        .await
        .map_err(|e| ApiError::WebFetch(format!("failed to read response: {e}")))?;

    let (body, truncated) = if bytes.len() > state.web_fetch_max_bytes {
        let truncated_bytes = &bytes[..state.web_fetch_max_bytes];
        (
            String::from_utf8_lossy(truncated_bytes).to_string(),
            Some(true),
        )
    } else {
        (String::from_utf8_lossy(&bytes).to_string(), None)
    };

    audit_event(&state, &headers, "web_fetch", &url_str, "ok").await?;
    Ok(Json(WebFetchResponse {
        status,
        headers: response_headers,
        body,
        truncated,
    }))
}

async fn approve_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    // Rate limit approval requests to prevent DoS
    if !state.approval_rate_limiter.try_acquire() {
        return Err(ApiError::RateLimited);
    }

    let now = now_unix();
    let expires_at = resolve_approval_expiry(req.expires_at_unix, now)?;
    let nonce = req
        .nonce
        .as_deref()
        .ok_or_else(|| ApiError::Spec("approval nonce required".to_string()))?;
    let expiry = expires_at.unwrap_or(now + MAX_APPROVAL_TTL_SECS);
    if !state.approval_nonces.check_and_insert(nonce, expiry, now) {
        return Err(ApiError::Spec("approval nonce replayed".to_string()));
    }
    state
        .approvals
        .approve(&req.operation, req.count, expires_at);
    audit_event(&state, &headers, "approve", &req.operation, "ok").await?;
    Ok(Json(ApproveResponse { ok: true }))
}

fn resolve_approval_expiry(
    expires_at_unix: Option<u64>,
    now: u64,
) -> Result<Option<u64>, ApiError> {
    let requested = expires_at_unix.unwrap_or(now + MAX_APPROVAL_TTL_SECS);
    if requested < now {
        return Err(ApiError::Spec("approval expiry is in the past".to_string()));
    }
    let max_allowed = now + MAX_APPROVAL_TTL_SECS;
    Ok(Some(requested.min(max_allowed)))
}

fn build_runtime(spec: &PodSpec) -> Result<PodRuntime, ApiError> {
    let policy = spec
        .spec
        .resolve_policy()
        .map_err(|e| ApiError::Spec(e.to_string()))?;
    let timeout = std::time::Duration::from_secs(spec.spec.timeout_seconds);
    let mut runtime_spec = RuntimePodSpec::new(policy, spec.spec.work_dir.clone(), timeout);
    if let Some(model) = spec.spec.budget_model.as_ref() {
        runtime_spec.budget_model = map_budget_model(model);
    }

    PodRuntime::new(runtime_spec).map_err(ApiError::Nucleus)
}

fn map_budget_model(model: &BudgetModelSpec) -> BudgetModel {
    BudgetModel {
        base_cost_usd: model.base_cost_usd,
        cost_per_second_usd: model.cost_per_second_usd,
    }
}

#[cfg(target_os = "linux")]
fn resolve_vsock(args: &Args, spec: &PodSpec) -> Result<Option<VsockConfig>, ApiError> {
    let port = match args
        .vsock_port
        .or_else(|| spec.spec.vsock.as_ref().map(|v| v.port))
    {
        Some(port) => port,
        None => {
            if args.vsock_cid.is_some() {
                return Err(ApiError::Spec("vsock_cid requires vsock_port".to_string()));
            }
            return Ok(None);
        }
    };
    let cid = args
        .vsock_cid
        .or_else(|| spec.spec.vsock.as_ref().map(|v| v.guest_cid))
        .unwrap_or(tokio_vsock::VMADDR_CID_ANY);

    Ok(Some(VsockConfig { cid, port }))
}

#[cfg(not(target_os = "linux"))]
fn resolve_vsock(args: &Args, spec: &PodSpec) -> Result<Option<VsockConfig>, ApiError> {
    if args.vsock_port.is_some() || spec.spec.vsock.is_some() {
        Err(ApiError::Spec(
            "vsock requires Linux (run inside the Firecracker VM)".to_string(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
async fn serve_vsock(
    app: Router,
    vsock: VsockConfig,
    announce_path: Option<PathBuf>,
) -> Result<(), ApiError> {
    let addr = tokio_vsock::VsockAddr::new(vsock.cid, vsock.port);
    let listener = tokio_vsock::VsockListener::bind(addr)?;
    let local = listener.local_addr()?;
    if let Some(path) = announce_path {
        tokio::fs::write(path, format!("vsock://{}:{}", local.cid(), local.port())).await?;
    }
    info!(
        "nucleus-tool-proxy listening on vsock {}:{}",
        local.cid(),
        local.port()
    );
    let listener = VsockAxumListener { inner: listener };
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn serve_vsock(
    _app: Router,
    _vsock: VsockConfig,
    _announce_path: Option<PathBuf>,
) -> Result<(), ApiError> {
    Err(ApiError::Spec(
        "vsock requires Linux (run inside the Firecracker VM)".to_string(),
    ))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
struct VsockConfig {
    cid: u32,
    port: u32,
}

#[cfg(target_os = "linux")]
struct VsockAxumListener {
    inner: tokio_vsock::VsockListener,
}

#[cfg(target_os = "linux")]
impl axum::serve::Listener for VsockAxumListener {
    type Io = tokio_vsock::VsockStream;
    type Addr = tokio_vsock::VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => return (stream, addr),
                Err(err) => {
                    tracing::error!("vsock accept error: {err}");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn build_audit_log(args: &Args, auth: &AuthConfig) -> Result<Arc<AuditLog>, ApiError> {
    let path = args.audit_log.clone();
    let secret = if let Some(secret) = args.audit_secret.as_ref() {
        secret.as_bytes().to_vec()
    } else {
        auth.secret().to_vec()
    };

    let last_hash = load_last_hash(&path).unwrap_or_default();

    // Set up webhook sink if configured
    let webhook = if let Some(url) = args.audit_webhook.as_ref() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| ApiError::Spec(format!("failed to build webhook client: {e}")))?;
        info!("audit webhook configured: {}", url);
        Some(WebhookSink {
            url: url.clone(),
            client,
        })
    } else {
        None
    };

    Ok(Arc::new(AuditLog {
        path,
        secret,
        last_hash: Mutex::new(last_hash),
        webhook,
    }))
}

async fn audit_event(
    state: &AppState,
    headers: &HeaderMap,
    event: &str,
    subject: &str,
    result: &str,
) -> Result<(), ApiError> {
    let actor = headers
        .get("x-nucleus-actor")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    state
        .audit
        .log(AuditEntry {
            timestamp_unix: now_unix(),
            actor,
            event: event.to_string(),
            subject: subject.to_string(),
            result: result.to_string(),
            prev_hash: String::new(),
            hash: String::new(),
            signature: String::new(),
        })
        .await?;
    Ok(())
}

async fn emit_boot_report(state: &AppState) -> Result<(), ApiError> {
    let report = match std::env::var("NUCLEUS_TOOL_PROXY_BOOT_REPORT") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(()),
    };
    let actor = std::env::var("NUCLEUS_TOOL_PROXY_BOOT_ACTOR").ok();

    state
        .audit
        .log(AuditEntry {
            timestamp_unix: now_unix(),
            actor,
            event: "boot".to_string(),
            subject: report,
            result: "ok".to_string(),
            prev_hash: String::new(),
            hash: String::new(),
            signature: String::new(),
        })
        .await?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditEntry {
    timestamp_unix: u64,
    actor: Option<String>,
    event: String,
    subject: String,
    result: String,
    prev_hash: String,
    hash: String,
    signature: String,
}

struct AuditLog {
    path: PathBuf,
    secret: Vec<u8>,
    last_hash: Mutex<String>,
    webhook: Option<WebhookSink>,
}

struct WebhookSink {
    url: String,
    client: reqwest::Client,
}

impl AuditLog {
    async fn log(&self, mut entry: AuditEntry) -> Result<(), ApiError> {
        let actor = entry.actor.clone().unwrap_or_default();
        let (prev_hash, hash, signature) = {
            let mut last_hash = self.last_hash.lock().unwrap();
            let prev_hash = last_hash.clone();
            let message = format!(
                "{}|{}|{}|{}|{}|{}",
                entry.timestamp_unix, actor, entry.event, entry.subject, entry.result, prev_hash
            );
            let signature = auth::sign_message(&self.secret, message.as_bytes());
            let hash = sha256_hex(&format!("{}|{}", message, signature));
            *last_hash = hash.clone();
            (prev_hash, hash, signature)
        };
        entry.prev_hash = prev_hash;
        entry.signature = signature.clone();
        entry.hash = hash;

        let line = serde_json::to_string(&entry).map_err(|e| ApiError::Spec(e.to_string()))?;

        // Write to local file
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;

        // Send to webhook if configured
        if let Some(webhook) = &self.webhook {
            // Fire and forget - don't block on webhook delivery
            // In production, you'd want retry logic and a buffer
            let url = webhook.url.clone();
            let client = webhook.client.clone();
            let body = line.clone();
            let sig = signature;

            tokio::spawn(async move {
                let result = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Nucleus-Signature", &sig)
                    .body(body)
                    .send()
                    .await;

                if let Err(e) = result {
                    tracing::warn!("failed to send audit entry to webhook: {e}");
                }
            });
        }

        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha256_hex(message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}

fn load_last_hash(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() == 0 {
        return None;
    }
    let read_len = metadata.len().min(8192) as usize;
    let mut file = file;
    let start = metadata.len().saturating_sub(read_len as u64);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return None;
    }
    let mut buf = vec![0u8; read_len];
    if file.read_exact(&mut buf).is_err() {
        return None;
    }
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().rev().find(|line| !line.trim().is_empty())?;
    let entry: AuditEntry = serde_json::from_str(line).ok()?;
    if entry.hash.is_empty() {
        return None;
    }
    Some(entry.hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_burst() {
        let limiter = ApprovalRateLimiter::new(5, 1);
        // Should allow burst of 5
        for i in 0..5 {
            assert!(limiter.try_acquire(), "request {} should be allowed", i);
        }
        // 6th should be rejected
        assert!(!limiter.try_acquire(), "request 6 should be rate limited");
    }

    #[test]
    fn test_rate_limiter_default_config() {
        let limiter = ApprovalRateLimiter::default();
        // Default is 20 burst, 10/sec refill
        for i in 0..20 {
            assert!(limiter.try_acquire(), "request {} should be allowed", i);
        }
        assert!(!limiter.try_acquire(), "request 21 should be rate limited");
    }

    #[test]
    fn test_nonce_cache_rejects_replay() {
        let cache = ApprovalNonceCache::default();
        let now = 1000;
        let expiry = 2000;

        // First use should succeed
        assert!(cache.check_and_insert("nonce-1", expiry, now));
        // Replay should fail
        assert!(!cache.check_and_insert("nonce-1", expiry, now));
        // Different nonce should succeed
        assert!(cache.check_and_insert("nonce-2", expiry, now));
    }

    #[test]
    fn test_nonce_cache_expires_old_entries() {
        let cache = ApprovalNonceCache::default();
        let now = 1000;
        let expiry = 1500;

        assert!(cache.check_and_insert("nonce-old", expiry, now));

        // Time passes, entry expires
        let later = 2000;
        // Old nonce was cleaned up, so this should succeed
        assert!(cache.check_and_insert("nonce-old", 3000, later));
    }

    #[test]
    fn test_approval_registry_consume() {
        let registry = ApprovalRegistry::default();

        // Approve 2 uses
        registry.approve("read /etc/passwd", 2, None);

        // Should consume successfully twice
        assert!(registry.consume("read /etc/passwd"));
        assert!(registry.consume("read /etc/passwd"));
        // Third should fail
        assert!(!registry.consume("read /etc/passwd"));
    }
}
