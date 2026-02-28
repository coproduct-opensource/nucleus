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
use nucleus::lattice_guard::escalation::{
    EscalationError, EscalationGrant, EscalationRequest, SpiffeTraceChain, SpiffeTraceLink,
};
use nucleus::lattice_guard::{CapabilityLevel, Operation, PermissionLattice};
use nucleus::{
    ApprovalRequest, BudgetModel, CallbackApprover, NucleusError, PodRuntime,
    PodSpec as RuntimePodSpec,
};
use nucleus_permission_market::{PermissionBid, PermissionGrant, PermissionMarket};
use nucleus_spec::{BudgetModelSpec, PodSpec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

mod attestation;
mod auth;
mod exit_report;
#[cfg(feature = "mcp")]
mod mcp;
mod mtls;
mod node_client;
mod policy;
mod sandbox_proof;
mod validation;

use attestation::{AttestationConfig, AttestationVerifier};
use auth::{AuthConfig, AuthError};
use base64::Engine as _;
use mtls::{ClientCertInfo, MtlsConfig, MtlsConnectInfo, MtlsListener};
use nucleus_client::drand::{DrandConfig, DrandFailMode};
use nucleus_identity::approval_bundle::{compute_manifest_hash, ApprovalBundleVerifier};
use policy::PolicyEngine;

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
        default_value_t = 30
    )]
    auth_max_skew_secs: u64,
    /// Audit log path.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_AUDIT_LOG",
        default_value = "/var/log/nucleus/audit.log"
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
        default_value_t = 15
    )]
    web_fetch_timeout_secs: u64,
    /// Maximum response body size in bytes for web fetch.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_WEB_FETCH_MAX_BYTES",
        default_value_t = 5 * 1024 * 1024
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

    // === Sandbox Proof Configuration ===
    /// Path to identity certificate PEM for sandbox proof (tier 1/2).
    /// Falls back to --tls-cert if not specified.
    #[arg(long, env = "NUCLEUS_IDENTITY_CERT")]
    identity_cert: Option<std::path::PathBuf>,
    /// SPIRE Workload API socket path for sandbox proof (tier 2).
    #[arg(long, env = "NUCLEUS_SPIRE_SOCKET")]
    spire_socket: Option<String>,

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

    // === Policy Configuration ===
    /// Path to identity-based policy YAML file.
    /// When provided, enables zero-prompt authorization for SPIFFE identities.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_POLICY")]
    policy_file: Option<std::path::PathBuf>,

    /// Enable zero-prompt mode (requires --policy-file).
    /// When enabled, operations matching SPIFFE identity policies are auto-approved.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ZERO_PROMPT")]
    zero_prompt: bool,

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

    // === Pod Management Configuration (orchestrator mode) ===
    /// Enable pod management endpoints (for orchestrator pods).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ENABLE_POD_MGMT")]
    enable_pod_mgmt: bool,

    /// nucleus-node HTTP endpoint for pod management.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_NODE_URL")]
    node_url: Option<String>,

    /// Auth secret for requests to nucleus-node (HMAC).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_NODE_AUTH_SECRET")]
    node_auth_secret: Option<String>,

    /// Delegation ceiling for sub-pod permissions (JSON-serialized PermissionLattice).
    /// Sub-pods cannot exceed this ceiling via delegate_to().
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_DELEGATION_CEILING")]
    delegation_ceiling: Option<String>,

    // === Approval Bundle Configuration ===
    /// Require a signed approval bundle at startup.
    /// When set, the tool-proxy refuses to start without a valid JWS bundle
    /// in the NUCLEUS_APPROVAL_BUNDLE environment variable.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_REQUIRE_APPROVAL_BUNDLE")]
    require_approval_bundle: bool,

    // === MCP Server Mode ===
    /// Run as an MCP (Model Context Protocol) server on stdio instead of HTTP.
    /// Mutually exclusive with the HTTP server.
    #[cfg(feature = "mcp")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_MCP")]
    mcp: bool,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) runtime: Arc<PodRuntime>,
    approvals: Arc<ApprovalRegistry>,
    audit: Arc<AuditLog>,
    auth: AuthConfig,
    approval_auth: AuthConfig,
    approval_nonces: Arc<ApprovalNonceCache>,
    approval_rate_limiter: Arc<ApprovalRateLimiter>,
    pub(crate) web_client: reqwest::Client,
    web_fetch_max_bytes: usize,
    dns_allow: Vec<String>,
    attestation_verifier: AttestationVerifier,
    policy_engine: PolicyEngine,
    /// Node client for pod management (orchestrator mode only).
    node_client: Option<Arc<node_client::NodeClient>>,
    /// Delegation ceiling: sub-pod permissions cannot exceed this.
    delegation_ceiling: Option<Arc<PermissionLattice>>,
    /// Credentials loaded from orchestrator environment for injection into sub-pods.
    orchestrator_credentials: std::collections::BTreeMap<String, String>,
    /// Permission market for Lagrangian pricing of capability dimensions.
    permission_market: Arc<Mutex<PermissionMarket>>,
    /// Cryptographic proof that this process is inside a managed sandbox.
    sandbox_proof: sandbox_proof::SandboxProof,
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

/// Load and verify a signed approval bundle from the NUCLEUS_APPROVAL_BUNDLE env var.
///
/// If present and valid, populates the ApprovalRegistry with the approved operations.
/// If `require` is true, the function returns an error when the env var is missing.
fn load_approval_bundle(
    spec_contents: &str,
    approvals: &ApprovalRegistry,
    require: bool,
) -> Result<(), ApiError> {
    let jws = match std::env::var("NUCLEUS_APPROVAL_BUNDLE") {
        Ok(val) if !val.is_empty() => val,
        _ => {
            if require {
                return Err(ApiError::Spec(
                    "--require-approval-bundle is set but NUCLEUS_APPROVAL_BUNDLE is not set"
                        .to_string(),
                ));
            }
            return Ok(());
        }
    };

    verify_and_load_approval_bundle(&jws, spec_contents, approvals)
}

/// Verify a JWS approval bundle and populate the ApprovalRegistry.
fn verify_and_load_approval_bundle(
    jws: &str,
    spec_contents: &str,
    approvals: &ApprovalRegistry,
) -> Result<(), ApiError> {
    let manifest_hash = compute_manifest_hash(spec_contents.as_bytes());

    // Extract the embedded JWK from the JWS header for self-trust verification.
    // In production, the expected key would come from a pinned trust store.
    let header = {
        let header_b64 = jws.split('.').next().ok_or_else(|| {
            ApiError::Spec("approval bundle is not a valid JWS (no header)".to_string())
        })?;
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| ApiError::Spec(format!("approval bundle header decode error: {e}")))?;
        let header: nucleus_identity::approval_bundle::ApprovalBundleHeader =
            serde_json::from_slice(&header_bytes)
                .map_err(|e| ApiError::Spec(format!("approval bundle header parse error: {e}")))?;
        header
    };

    let verifier = ApprovalBundleVerifier::new();
    let claims = verifier
        .verify(jws, &header.jwk, &manifest_hash)
        .map_err(|e| ApiError::Spec(format!("approval bundle verification failed: {e}")))?;

    // Populate the ApprovalRegistry with the approved operations
    let count = claims.max_uses.map(|n| n as usize).unwrap_or(usize::MAX);
    let expiry = Some(claims.exp as u64);
    for op in &claims.approved_operations {
        approvals.approve(op, count, expiry);
        info!(
            operation = %op,
            count = count,
            expires_at = claims.exp,
            event = "approval_bundle_loaded",
            "pre-approved operation from signed bundle"
        );
    }

    info!(
        issuer = %claims.iss,
        jti = %claims.jti,
        operations = ?claims.approved_operations,
        manifest_hash = %claims.manifest_hash,
        event = "approval_bundle_verified",
        "signed approval bundle verified and loaded"
    );

    Ok(())
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

/// Run command request using secure array-based format.
///
/// The array form prevents shell injection by executing commands directly
/// without shell interpretation. Each array element is passed as a separate
/// argument to the process.
#[derive(Debug, Deserialize)]
struct RunRequest {
    /// Command as array, e.g. ["ls", "-la", "/tmp"]
    args: Vec<String>,
    /// Optional input to pass to command stdin
    #[serde(default)]
    stdin: Option<String>,
    /// Optional working directory (relative to sandbox)
    #[serde(default)]
    directory: Option<String>,
    /// Optional timeout in seconds (clamped to policy limit)
    #[serde(default)]
    #[allow(dead_code)] // Reserved for future timeout implementation
    timeout_seconds: Option<u64>,
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

/// Glob pattern search request.
#[derive(Debug, Deserialize)]
struct GlobRequest {
    /// Glob pattern to match (e.g., "**/*.rs", "src/*.json")
    pattern: String,
    /// Optional directory to search in (relative to sandbox root)
    #[serde(default)]
    directory: Option<String>,
    /// Maximum number of results to return
    #[serde(default)]
    max_results: Option<usize>,
}

/// Glob search response.
#[derive(Debug, Serialize)]
struct GlobResponse {
    /// Matching file paths (relative to sandbox)
    matches: Vec<String>,
    /// True if results were truncated due to max_results
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
}

/// Grep (content search) request.
#[derive(Debug, Deserialize)]
struct GrepRequest {
    /// Regex pattern to search for
    pattern: String,
    /// Optional file path to search in (relative to sandbox)
    #[serde(default)]
    path: Option<String>,
    /// Optional glob pattern to filter files
    #[serde(default, rename = "glob")]
    file_glob: Option<String>,
    /// Number of context lines before/after match
    #[serde(default)]
    context_lines: Option<usize>,
    /// Maximum number of matches to return
    #[serde(default)]
    max_matches: Option<usize>,
    /// Case-insensitive search
    #[serde(default)]
    case_insensitive: Option<bool>,
}

/// A single grep match result.
#[derive(Debug, Serialize)]
struct GrepMatch {
    /// File path (relative to sandbox)
    file: String,
    /// Line number (1-indexed)
    line: usize,
    /// Matching line content
    content: String,
    /// Optional context lines before
    #[serde(skip_serializing_if = "Option::is_none")]
    context_before: Option<Vec<String>>,
    /// Optional context lines after
    #[serde(skip_serializing_if = "Option::is_none")]
    context_after: Option<Vec<String>>,
}

/// Grep search response.
#[derive(Debug, Serialize)]
struct GrepResponse {
    /// Matching results
    matches: Vec<GrepMatch>,
    /// True if results were truncated due to max_matches
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
}

/// Web search request.
#[derive(Debug, Deserialize)]
struct WebSearchRequest {
    /// Search query
    query: String,
    /// Maximum number of results
    #[serde(default)]
    max_results: Option<usize>,
}

/// A single web search result.
#[derive(Debug, Serialize)]
struct WebSearchResult {
    /// Result title
    title: String,
    /// Result URL
    url: String,
    /// Result snippet/description
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<String>,
}

/// Web search response.
#[derive(Debug, Serialize)]
struct WebSearchResponse {
    /// Search results
    results: Vec<WebSearchResult>,
}

/// Request to escalate permissions for an agent.
#[derive(Debug, Deserialize)]
struct EscalateRequest {
    /// The requesting agent's SPIFFE trace chain (serialized).
    requestor_chain: SerializedTraceChain,
    /// The approver's SPIFFE trace chain (serialized).
    ///
    /// SECURITY: The approver MUST submit their full chain for proper verification.
    /// The server validates that:
    /// 1. The chain's leaf identity matches the mTLS authenticated identity
    /// 2. The chain is valid (non-expired, monotonically decreasing permissions)
    /// 3. The chain has no overlap with the requestor's chain (anti-self-escalation)
    approver_chain: SerializedTraceChain,
    /// Requested permission preset (e.g., "fix_issue", "permissive").
    requested_preset: String,
    /// Justification for the escalation.
    reason: String,
    /// TTL in seconds for the escalated permissions.
    ttl_seconds: u64,
    /// Unique nonce to prevent replay attacks.
    ///
    /// SECURITY: Required. Each escalation request must have a unique nonce.
    /// The server rejects requests with previously-seen nonces within the
    /// drand tolerance window (~60 seconds).
    nonce: String,
}

/// Serialized trace chain for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedTraceChain {
    /// Chain ID.
    id: String,
    /// Links in the chain.
    links: Vec<SerializedTraceLink>,
}

/// Serialized trace link for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedTraceLink {
    /// Link ID.
    id: String,
    /// SPIFFE ID.
    spiffe_id: String,
    /// Permission preset name (for reconstruction).
    preset: String,
    /// Drand round when created.
    drand_round: u64,
    /// Creation timestamp (Unix seconds).
    created_at: u64,
    /// Expiry timestamp (Unix seconds), if any.
    expires_at: Option<u64>,
    /// Reason for this link.
    reason: String,
}

/// Response from an escalation request.
#[derive(Debug, Serialize)]
struct EscalateResponse {
    /// Whether the escalation was granted.
    granted: bool,
    /// The grant ID (if granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_id: Option<String>,
    /// Granted permission preset (if granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    granted_preset: Option<String>,
    /// Expiry timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    /// Drand round of the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    drand_round: Option<u64>,
    /// Error message (if denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    /// Payment metadata for 402 responses (vendor-agnostic).
    #[serde(skip_serializing_if = "Option::is_none")]
    payment: Option<nucleus_spec::PaymentRequiredInfo>,
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
    #[error("escalation error: {0}")]
    Escalation(String),
    #[error("validation error: {0}")]
    Validation(#[from] validation::ValidationError),
    #[error("permission bid denied: insufficient value")]
    PermissionDenied(#[allow(unused)] nucleus_spec::PaymentRequiredInfo),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, kind, operation, payment) = match &self {
            ApiError::Nucleus(NucleusError::ApprovalRequired { operation }) => (
                StatusCode::FORBIDDEN,
                "approval_required",
                Some(operation.clone()),
                None,
            ),
            ApiError::Nucleus(NucleusError::BudgetExhausted {
                requested,
                remaining,
            }) => {
                let payment_info = nucleus_spec::PaymentRequiredInfo {
                    amount_usd: *requested,
                    reason: format!(
                        "budget exhausted: requested ${requested:.4}, remaining ${remaining:.4}"
                    ),
                    kind: nucleus_spec::PaymentRequiredKind::BudgetExhausted {
                        requested: *requested,
                        remaining: *remaining,
                    },
                    recipient: std::env::var("NUCLEUS_PAYMENT_RECIPIENT").ok(),
                    resource: None,
                };
                (
                    StatusCode::PAYMENT_REQUIRED,
                    "budget_exhausted",
                    None,
                    Some(payment_info),
                )
            }
            ApiError::Nucleus(NucleusError::CommandDenied { .. }) => {
                (StatusCode::FORBIDDEN, "command_denied", None, None)
            }
            ApiError::Nucleus(NucleusError::PathDenied { .. }) => {
                (StatusCode::FORBIDDEN, "path_denied", None, None)
            }
            ApiError::Nucleus(NucleusError::SandboxEscape { .. }) => {
                (StatusCode::FORBIDDEN, "sandbox_escape", None, None)
            }
            ApiError::Nucleus(NucleusError::Io(_)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None, None)
            }
            ApiError::Nucleus(NucleusError::TimeViolation { .. }) => {
                (StatusCode::REQUEST_TIMEOUT, "time_violation", None, None)
            }
            ApiError::Nucleus(NucleusError::TrifectaBlocked { .. }) => {
                (StatusCode::FORBIDDEN, "trifecta_blocked", None, None)
            }
            ApiError::Nucleus(NucleusError::InsufficientCapability { .. }) => {
                (StatusCode::FORBIDDEN, "insufficient_capability", None, None)
            }
            ApiError::Nucleus(NucleusError::InvalidApproval { operation }) => (
                StatusCode::FORBIDDEN,
                "invalid_approval",
                Some(operation.clone()),
                None,
            ),
            ApiError::Nucleus(NucleusError::InvalidCharge { .. }) => {
                (StatusCode::BAD_REQUEST, "invalid_charge", None, None)
            }
            ApiError::Spec(_) => (StatusCode::BAD_REQUEST, "spec_error", None, None),
            ApiError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None, None),
            ApiError::Serde(_) => (StatusCode::BAD_REQUEST, "serde_error", None, None),
            ApiError::Auth(_) => (StatusCode::UNAUTHORIZED, "auth_error", None, None),
            ApiError::Body(_) => (StatusCode::BAD_REQUEST, "body_error", None, None),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None, None),
            ApiError::WebFetch(_) => (StatusCode::BAD_GATEWAY, "web_fetch_error", None, None),
            ApiError::DnsNotAllowed(_) => (StatusCode::FORBIDDEN, "dns_not_allowed", None, None),
            ApiError::AttestationFailed(_) => {
                (StatusCode::FORBIDDEN, "attestation_failed", None, None)
            }
            ApiError::Escalation(_) => (StatusCode::FORBIDDEN, "escalation_denied", None, None),
            ApiError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error", None, None),
            ApiError::PermissionDenied(ref info) => (
                StatusCode::PAYMENT_REQUIRED,
                "permission_denied",
                None,
                Some(info.clone()),
            ),
        };

        // Sanitize error message to prevent information disclosure
        let sanitized_error = validation::sanitize_error_message(&self.to_string(), None);

        let body = Json(ErrorBody {
            error: sanitized_error,
            kind: kind.to_string(),
            operation,
            payment,
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

    // === Sandbox Proof Gate ===
    // Refuse to start unless we can cryptographically prove we're in a managed sandbox.
    let sandbox_proof_config = sandbox_proof::SandboxProofConfig {
        identity_cert_path: args.identity_cert.clone().or_else(|| args.tls_cert.clone()),
        spire_socket: args
            .spire_socket
            .clone()
            .or_else(|| std::env::var("SPIFFE_ENDPOINT_SOCKET").ok()),
        sandbox_token: std::env::var("NUCLEUS_SANDBOX_TOKEN").ok(),
        auth_secret: args.auth_secret.as_bytes().to_vec(),
    };
    let sandbox_proof = match sandbox_proof::verify_sandbox(&sandbox_proof_config).await {
        Ok(proof) => {
            info!(
                "sandbox proof verified: tier={} label={}",
                proof.tier(),
                proof.tier_label()
            );
            proof
        }
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(78); // EX_CONFIG
        }
    };

    let spec_contents = tokio::fs::read_to_string(&args.spec).await?;
    let spec: PodSpec =
        serde_yaml::from_str(&spec_contents).map_err(|e| ApiError::Spec(e.to_string()))?;

    let runtime = build_runtime(&spec)?;
    let approvals = Arc::new(ApprovalRegistry::default());

    // Load signed approval bundle if present
    if let Err(e) = load_approval_bundle(&spec_contents, &approvals, args.require_approval_bundle) {
        eprintln!("FATAL: {e}");
        std::process::exit(78);
    }

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

    // Build policy engine for identity-based authorization
    let policy_engine = if let Some(policy_path) = &args.policy_file {
        if !args.zero_prompt {
            warn!(
                "policy file specified but --zero-prompt not enabled; policy will not be enforced"
            );
        }
        let policy_config = policy::load_policy_file(policy_path).await.map_err(|e| {
            ApiError::Spec(format!(
                "failed to load policy file {}: {}",
                policy_path.display(),
                e
            ))
        })?;
        info!(
            "loaded policy file with {} rules (zero_prompt={})",
            policy_config.policies.len(),
            args.zero_prompt
        );
        if args.zero_prompt {
            PolicyEngine::from_config(&policy_config)
        } else {
            PolicyEngine::disabled()
        }
    } else {
        if args.zero_prompt {
            return Err(ApiError::Spec(
                "--zero-prompt requires --policy-file".to_string(),
            ));
        }
        PolicyEngine::disabled()
    };

    if args.zero_prompt && !args.mtls {
        return Err(ApiError::Spec(
            "--zero-prompt requires --mtls for identity-based authorization".to_string(),
        ));
    }

    if args.require_attestation
        && args.allowed_kernel_hashes.is_none()
        && args.allowed_rootfs_hashes.is_none()
    {
        warn!(
            "attestation required but no kernel/rootfs hash whitelist configured; \
             any attested VM will be accepted"
        );
    }

    // Build node client for pod management (orchestrator mode)
    let node_client = if args.enable_pod_mgmt {
        let node_url = args.node_url.as_deref().unwrap_or("http://127.0.0.1:3000");
        let node_secret = args
            .node_auth_secret
            .clone()
            .unwrap_or_else(|| args.auth_secret.clone());
        info!("pod management enabled (node_url={})", node_url);
        Some(Arc::new(node_client::NodeClient::new(
            node_url.to_string(),
            node_secret,
        )))
    } else {
        None
    };

    // Parse delegation ceiling for orchestrator mode
    let delegation_ceiling = if let Some(ref ceiling_json) = args.delegation_ceiling {
        let lattice: PermissionLattice = serde_json::from_str(ceiling_json)
            .map_err(|e| ApiError::Spec(format!("invalid delegation ceiling JSON: {e}")))?;
        Some(Arc::new(lattice))
    } else {
        None
    };

    // Load orchestrator credentials from environment for sub-pod injection
    let orchestrator_credentials = {
        let mut creds = std::collections::BTreeMap::new();
        for key in ["LLM_API_TOKEN", "GITHUB_TOKEN"] {
            if let Ok(val) = std::env::var(key) {
                creds.insert(key.to_string(), val);
            }
        }
        creds
    };

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
        policy_engine,
        node_client,
        delegation_ceiling,
        orchestrator_credentials,
        permission_market: Arc::new(Mutex::new(PermissionMarket::new())),
        sandbox_proof,
    };

    if let Err(err) = emit_boot_report(&state).await {
        warn!("failed to emit boot report: {err}");
    }

    // MCP server mode: serve Model Context Protocol over stdio instead of HTTP.
    #[cfg(feature = "mcp")]
    if args.mcp {
        return mcp::run_mcp_server(Arc::new(state)).await;
    }

    let mut app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/read", post(read_file))
        .route("/v1/write", post(write_file))
        .route("/v1/run", post(run_command))
        .route("/v1/web_fetch", post(web_fetch))
        .route("/v1/glob", post(glob_search))
        .route("/v1/grep", post(grep_search))
        .route("/v1/web_search", post(web_search))
        .route("/v1/approve", post(approve_operation))
        .route("/v1/escalate", post(escalate_permissions));

    // Conditionally add pod management routes for orchestrator mode
    if state.node_client.is_some() {
        app = app
            .route("/v1/pod/create", post(create_sub_pod))
            .route("/v1/pod/list", post(list_sub_pods))
            .route("/v1/pod/status", post(get_pod_status))
            .route("/v1/pod/logs", post(get_pod_logs))
            .route("/v1/pod/cancel", post(cancel_sub_pod));
    }

    // Keep references for the exit report after shutdown
    let exit_audit = state.audit.clone();
    let exit_work_dir = spec.spec.work_dir.clone();

    let app = app
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_middleware));

    if let Some(vsock) = resolve_vsock(&args, &spec)? {
        serve_vsock(app, vsock, args.announce_path).await?;
        write_exit_report(&exit_audit, &exit_work_dir).await;
        return Ok(());
    }

    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;

    if let Some(path) = args.announce_path.as_ref() {
        tokio::fs::write(path, addr.to_string()).await?;
    }

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown signal received, writing exit report");
    };

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
        .with_graceful_shutdown(shutdown)
        .await?;
    } else {
        info!("nucleus-tool-proxy listening on {}", addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await?;
    }

    write_exit_report(&exit_audit, &exit_work_dir).await;

    Ok(())
}

/// Write the exit report on shutdown.
async fn write_exit_report(audit: &AuditLog, work_dir_path: &Path) {
    let workspace_hash = match exit_report::hash_workspace(work_dir_path).await {
        Ok(h) => h,
        Err(e) => {
            warn!("failed to hash workspace for exit report: {e}");
            return;
        }
    };

    let (tail_hash, count) = audit.tail_hash_and_count();
    let report = exit_report::build_exit_report(workspace_hash, tail_hash, count);

    let report_path = work_dir_path.join(".nucleus-exit-report.json");
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            if let Err(e) = tokio::fs::write(&report_path, json).await {
                warn!(
                    "failed to write exit report to {}: {e}",
                    report_path.display()
                );
            } else {
                info!(
                    path = %report_path.display(),
                    entries = count,
                    event = "exit_report_written",
                    "exit report written"
                );
            }
        }
        Err(e) => warn!("failed to serialize exit report: {e}"),
    }
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
const HEADER_PERMISSION_BID: &str = "x-nucleus-permission-bid";

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

    // Try SPIFFE mTLS authentication first (most secure, no shared secrets)
    if let Some(spiffe_id) = auth::extract_spiffe_id_from_extensions(&parts.extensions) {
        tracing::info!(
            spiffe_id = %spiffe_id,
            path = %parts.uri.path(),
            method = %parts.method,
            event = "auth_spiffe_mtls",
            "request authenticated via SPIFFE mTLS"
        );
        let context = auth::verify_spiffe_mtls(&spiffe_id);
        let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
        req.extensions_mut().insert(context);
        return Ok(next.run(req).await);
    }

    // Fall back to HMAC-based authentication (legacy mode)
    if parts.uri.path() == APPROVE_PATH {
        // Use drand-aware verification for approval requests
        let context = auth::verify_http_with_drand(&parts.headers, &bytes, &state.approval_auth)?;
        if context.drand_round.is_some() {
            tracing::info!(
                drand_round = context.drand_round,
                auth_method = ?context.auth_method,
                "approval request verified with drand anchoring"
            );
        }
        let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
        req.extensions_mut().insert(context);
        return Ok(next.run(req).await);
    }

    let context = auth::verify_http(&parts.headers, &bytes, &state.auth)?;

    // Evaluate permission bid if present
    let permission_grant = evaluate_permission_bid(&parts.headers, &state);

    // If the bid was fully denied (no dimensions granted), return 402 with pricing
    if let Some(ref grant) = permission_grant {
        if !grant.denied.is_empty() && grant.granted.is_empty() {
            let total_price: f64 = grant.denied.iter().map(|d| d.price).sum();
            let denied_dims = grant
                .denied
                .iter()
                .map(|d| nucleus_spec::DeniedDimensionInfo {
                    dimension: d.dimension.label().to_string(),
                    price_usd: d.price,
                })
                .collect();
            let reason = grant
                .denied
                .iter()
                .map(|d| format!("{} λ={:.2}", d.dimension.label(), d.price))
                .collect::<Vec<_>>()
                .join(", ");
            let payment_info = nucleus_spec::PaymentRequiredInfo {
                amount_usd: total_price,
                reason,
                kind: nucleus_spec::PaymentRequiredKind::PermissionDenied {
                    denied_dimensions: denied_dims,
                },
                recipient: std::env::var("NUCLEUS_PAYMENT_RECIPIENT").ok(),
                resource: Some(parts.uri.path().to_string()),
            };
            return Err(ApiError::PermissionDenied(payment_info));
        }
    }

    let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(context);
    if let Some(grant) = permission_grant {
        req.extensions_mut().insert(grant);
    }
    Ok(next.run(req).await)
}

/// Parse and evaluate a permission bid from request headers.
///
/// Returns `Some(PermissionGrant)` if a valid bid was present, `None` otherwise.
/// Invalid bid JSON is silently ignored (logged at warn level).
fn evaluate_permission_bid(headers: &HeaderMap, state: &AppState) -> Option<PermissionGrant> {
    let bid_header = headers.get(HEADER_PERMISSION_BID)?;
    let bid_str = bid_header.to_str().ok()?;
    let bid: PermissionBid = match serde_json::from_str(bid_str) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "invalid permission bid header");
            return None;
        }
    };

    let market = state.permission_market.lock().unwrap();
    let grant = market.evaluate_bid(&bid);

    tracing::info!(
        skill_id = %bid.skill_id,
        granted = grant.granted.len(),
        denied = grant.denied.len(),
        total_cost = grant.total_cost,
        event = "permission_bid_evaluated",
        "permission market evaluated bid"
    );

    Some(grant)
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "sandbox_proof": {
            "tier": state.sandbox_proof.tier(),
            "label": state.sandbox_proof.tier_label(),
        }
    }))
}

/// Check if a SPIFFE identity has permission for an operation via policy.
/// Returns true if the operation should be auto-approved (zero-prompt).
fn check_identity_policy(
    state: &AppState,
    auth: Option<&auth::AuthContext>,
    operation: &str,
) -> bool {
    // Only check policy for SPIFFE mTLS authenticated requests
    let auth = match auth {
        Some(a) if a.auth_method == auth::AuthMethod::SpiffeMtls => a,
        _ => return false,
    };

    // Get SPIFFE ID
    let spiffe_id = match &auth.spiffe_id {
        Some(id) => id,
        None => return false,
    };

    // Check if policy engine is enabled and has a matching policy
    if !state.policy_engine.is_zero_prompt_enabled() {
        return false;
    }

    // Get permissions for this identity
    let permissions = match state.policy_engine.permissions_for(spiffe_id) {
        Some(p) => p,
        None => return false,
    };

    // Check capabilities based on operation type
    // This is a simplified check - a full implementation would parse the operation
    // and check specific capabilities and path patterns
    let requires_approval = match operation.split_whitespace().next() {
        Some("read") => {
            permissions.capabilities.read_files == CapabilityLevel::Never
                || permissions.requires_approval(Operation::ReadFiles)
        }
        Some("write") => {
            permissions.capabilities.write_files == CapabilityLevel::Never
                || permissions.requires_approval(Operation::WriteFiles)
        }
        Some("run") | Some("execute") => {
            permissions.capabilities.run_bash == CapabilityLevel::Never
                || permissions.requires_approval(Operation::RunBash)
        }
        Some("web_fetch") => {
            permissions.capabilities.web_fetch == CapabilityLevel::Never
                || permissions.requires_approval(Operation::WebFetch)
        }
        _ => true, // Unknown operations require approval
    };

    if !requires_approval {
        tracing::info!(
            spiffe_id = %spiffe_id,
            operation = %operation,
            event = "zero_prompt_authorized",
            "operation authorized via SPIFFE identity policy"
        );
    }

    !requires_approval
}

async fn read_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, ApiError> {
    // Validate inputs before any processing
    if let Err(e) = validation::validate_path(&req.path) {
        let audit_ctx = AuditContext::from_auth(auth.as_ref().map(|a| &a.0), &state);
        audit_failure(
            &state,
            &headers,
            "read",
            &req.path,
            "validation_error",
            audit_ctx,
        )
        .await;
        return Err(ApiError::Validation(e));
    }

    let path = req.path.clone();
    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    let contents = match state.runtime.sandbox().read_to_string(&path) {
        Ok(contents) => contents,
        Err(NucleusError::ApprovalRequired { operation }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(&state, auth_ctx.as_ref(), &format!("read {}", path))
                || state.approvals.consume(&operation)
            {
                let token = state
                    .runtime
                    .sandbox()
                    .request_approval(operation.clone())?;
                state
                    .runtime
                    .sandbox()
                    .read_to_string_approved(&path, &token)?
            } else {
                audit_failure(
                    &state,
                    &headers,
                    "read",
                    &path,
                    "approval_required",
                    audit_ctx.clone(),
                )
                .await;
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation,
                }));
            }
        }
        Err(err) => {
            audit_failure(
                &state,
                &headers,
                "read",
                &path,
                &format!("{:?}", err),
                audit_ctx.clone(),
            )
            .await;
            return Err(ApiError::Nucleus(err));
        }
    };

    audit_event_with_context(&state, &headers, "read", &path, "ok", audit_ctx).await?;
    Ok(Json(ReadResponse { contents }))
}

async fn write_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, ApiError> {
    // Validate inputs before any processing
    if let Err(e) = validation::validate_path(&req.path) {
        let audit_ctx = AuditContext::from_auth(auth.as_ref().map(|a| &a.0), &state);
        audit_failure(
            &state,
            &headers,
            "write",
            &req.path,
            "validation_error",
            audit_ctx,
        )
        .await;
        return Err(ApiError::Validation(e));
    }

    let path = req.path.clone();
    let contents = req.contents.clone();
    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    match state.runtime.sandbox().write(&path, contents.as_bytes()) {
        Ok(()) => {}
        Err(NucleusError::ApprovalRequired { operation }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(&state, auth_ctx.as_ref(), &format!("write {}", path))
                || state.approvals.consume(&operation)
            {
                let token = state
                    .runtime
                    .sandbox()
                    .request_approval(operation.clone())?;
                state
                    .runtime
                    .sandbox()
                    .write_approved(&path, contents.as_bytes(), &token)?;
            } else {
                audit_failure(
                    &state,
                    &headers,
                    "write",
                    &path,
                    "approval_required",
                    audit_ctx.clone(),
                )
                .await;
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation,
                }));
            }
        }
        Err(err) => {
            audit_failure(
                &state,
                &headers,
                "write",
                &path,
                &format!("{:?}", err),
                audit_ctx.clone(),
            )
            .await;
            return Err(ApiError::Nucleus(err));
        }
    }

    audit_event_with_context(&state, &headers, "write", &path, "ok", audit_ctx).await?;
    Ok(Json(WriteResponse { ok: true }))
}

async fn run_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, ApiError> {
    // Build display command for logging/auditing
    let display_command = req.args.join(" ");

    // Validate inputs before any processing
    if let Err(e) = validation::validate_command_args(&req.args) {
        let audit_ctx = AuditContext::from_auth(auth.as_ref().map(|a| &a.0), &state);
        audit_failure(
            &state,
            &headers,
            "run",
            &display_command,
            "validation_error",
            audit_ctx,
        )
        .await;
        return Err(ApiError::Validation(e));
    }
    if let Err(e) = validation::validate_stdin(req.stdin.as_deref()) {
        let audit_ctx = AuditContext::from_auth(auth.as_ref().map(|a| &a.0), &state);
        audit_failure(
            &state,
            &headers,
            "run",
            &display_command,
            "validation_error",
            audit_ctx,
        )
        .await;
        return Err(ApiError::Validation(e));
    }
    if let Some(ref dir) = req.directory {
        if let Err(e) = validation::validate_path(dir) {
            let audit_ctx = AuditContext::from_auth(auth.as_ref().map(|a| &a.0), &state);
            audit_failure(
                &state,
                &headers,
                "run",
                &display_command,
                "validation_error",
                audit_ctx,
            )
            .await;
            return Err(ApiError::Validation(e));
        }
    }

    let executor = state.runtime.executor();
    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    // Extract optional parameters
    let stdin = req.stdin.as_deref();
    let directory = req.directory.as_deref();

    let output = match executor.run_args(&req.args, stdin, directory) {
        Ok(output) => output,
        Err(NucleusError::ApprovalRequired { operation }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(
                &state,
                auth_ctx.as_ref(),
                &format!("execute {}", display_command),
            ) || state.approvals.consume(&operation)
            {
                let token = executor.request_approval(&operation)?;
                executor.run_args_with_approval(&req.args, stdin, directory, &token)?
            } else {
                audit_failure(
                    &state,
                    &headers,
                    "run",
                    &display_command,
                    "approval_required",
                    audit_ctx.clone(),
                )
                .await;
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation,
                }));
            }
        }
        Err(err) => {
            audit_failure(
                &state,
                &headers,
                "run",
                &display_command,
                &format!("{:?}", err),
                audit_ctx.clone(),
            )
            .await;
            return Err(ApiError::Nucleus(err));
        }
    };

    audit_event_with_context(&state, &headers, "run", &display_command, "ok", audit_ctx).await?;
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
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WebFetchRequest>,
) -> Result<Json<WebFetchResponse>, ApiError> {
    let url_str = req.url.clone();

    // Validate inputs before any processing
    if let Err(e) = validation::validate_url(&req.url) {
        let audit_ctx = AuditContext::from_auth(auth.as_ref().map(|a| &a.0), &state);
        audit_failure(
            &state,
            &headers,
            "web_fetch",
            &url_str,
            "validation_error",
            audit_ctx,
        )
        .await;
        return Err(ApiError::Validation(e));
    }

    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    // Check web_fetch capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.web_fetch;
    if level == CapabilityLevel::Never {
        audit_failure(
            &state,
            &headers,
            "web_fetch",
            &url_str,
            "insufficient_capability",
            audit_ctx.clone(),
        )
        .await;
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "web_fetch".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if trifecta requires approval for web_fetch
    if policy.requires_approval(Operation::WebFetch) {
        // Check if policy allows this operation (zero-prompt mode)
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("web_fetch {}", url_str));

        if !policy_allows && !state.approvals.consume("web_fetch") {
            audit_failure(
                &state,
                &headers,
                "web_fetch",
                &url_str,
                "approval_required",
                audit_ctx.clone(),
            )
            .await;
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

    audit_event_with_context(&state, &headers, "web_fetch", &url_str, "ok", audit_ctx).await?;
    Ok(Json(WebFetchResponse {
        status,
        headers: response_headers,
        body,
        truncated,
    }))
}

/// Glob pattern search within the sandbox.
async fn glob_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, ApiError> {
    // Validate inputs before any processing
    validation::validate_pattern(&req.pattern).map_err(ApiError::Validation)?;
    if let Some(ref dir) = req.directory {
        validation::validate_path(dir).map_err(ApiError::Validation)?;
    }

    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    // Check glob_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.glob_search;
    if level == CapabilityLevel::Never {
        audit_failure(
            &state,
            &headers,
            "glob",
            &req.pattern,
            "insufficient_capability",
            audit_ctx.clone(),
        )
        .await;
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "glob_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if trifecta requires approval
    if policy.requires_approval(Operation::GlobSearch) {
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("glob {}", req.pattern));
        if !policy_allows && !state.approvals.consume("glob_search") {
            audit_failure(
                &state,
                &headers,
                "glob",
                &req.pattern,
                "approval_required",
                audit_ctx.clone(),
            )
            .await;
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("glob {}", req.pattern),
            }));
        }
    }

    // Determine search root
    let sandbox_root = state.runtime.sandbox().root_path();
    let sandbox_canonical = sandbox_root
        .canonicalize()
        .map_err(|e| ApiError::Spec(format!("sandbox root not accessible: {e}")))?;

    let search_root = if let Some(ref dir) = req.directory {
        // Reject absolute paths immediately
        if Path::new(dir).is_absolute() {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: PathBuf::from(dir),
            }));
        }
        let resolved = sandbox_root.join(dir);
        // Canonicalize to resolve symlinks and .. components (path must exist)
        let canonical = resolved.canonicalize().map_err(|_| {
            ApiError::Nucleus(NucleusError::SandboxEscape {
                path: resolved.clone(),
            })
        })?;
        // Security: ensure canonicalized path is within sandbox
        if !canonical.starts_with(&sandbox_canonical) {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: resolved,
            }));
        }
        canonical
    } else {
        sandbox_canonical.clone()
    };

    // Build full glob pattern
    let full_pattern = search_root.join(&req.pattern);
    let pattern_str = full_pattern.to_string_lossy();

    // Perform glob search
    let max_results = req.max_results.unwrap_or(1000);
    let mut matches = Vec::new();
    let mut truncated = false;

    for entry in glob::glob(&pattern_str)
        .map_err(|e| ApiError::Spec(format!("invalid glob pattern: {e}")))?
    {
        match entry {
            Ok(path) => {
                // Security: canonicalize and verify path is within sandbox
                // This prevents symlink-based escapes
                let canonical = match path.canonicalize() {
                    Ok(c) => c,
                    Err(_) => continue, // Skip inaccessible paths
                };
                if !canonical.starts_with(&sandbox_canonical) {
                    continue;
                }
                // Convert to relative path (use canonical sandbox root)
                if let Ok(relative) = canonical.strip_prefix(&sandbox_canonical) {
                    matches.push(relative.to_string_lossy().to_string());
                    if matches.len() >= max_results {
                        truncated = true;
                        break;
                    }
                }
            }
            Err(_) => continue, // Skip inaccessible paths
        }
    }

    audit_event_with_context(&state, &headers, "glob", &req.pattern, "ok", audit_ctx).await?;
    Ok(Json(GlobResponse {
        matches,
        truncated: if truncated { Some(true) } else { None },
    }))
}

/// Grep (regex content search) within the sandbox.
async fn grep_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, ApiError> {
    use regex::RegexBuilder;
    use std::io::{BufRead, BufReader};
    use walkdir::WalkDir;

    // Validate inputs before any processing
    validation::validate_pattern(&req.pattern).map_err(ApiError::Validation)?;
    if let Some(ref path) = req.path {
        validation::validate_path(path).map_err(ApiError::Validation)?;
    }
    if let Some(ref glob_pattern) = req.file_glob {
        validation::validate_pattern(glob_pattern).map_err(ApiError::Validation)?;
    }

    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    // Check grep_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.grep_search;
    if level == CapabilityLevel::Never {
        audit_failure(
            &state,
            &headers,
            "grep",
            &req.pattern,
            "insufficient_capability",
            audit_ctx.clone(),
        )
        .await;
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "grep_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if trifecta requires approval
    if policy.requires_approval(Operation::GrepSearch) {
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("grep {}", req.pattern));
        if !policy_allows && !state.approvals.consume("grep_search") {
            audit_failure(
                &state,
                &headers,
                "grep",
                &req.pattern,
                "approval_required",
                audit_ctx.clone(),
            )
            .await;
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("grep {}", req.pattern),
            }));
        }
    }

    // Build regex
    let regex = RegexBuilder::new(&req.pattern)
        .case_insensitive(req.case_insensitive.unwrap_or(false))
        .build()
        .map_err(|e| ApiError::Spec(format!("invalid regex pattern: {e}")))?;

    let sandbox_root = state.runtime.sandbox().root_path();
    let sandbox_canonical = sandbox_root
        .canonicalize()
        .map_err(|e| ApiError::Spec(format!("sandbox root not accessible: {e}")))?;
    let max_matches = req.max_matches.unwrap_or(100);
    let context_lines = req.context_lines.unwrap_or(0);
    let mut matches = Vec::new();
    let mut truncated = false;

    // Collect files to search
    let files: Vec<std::path::PathBuf> = if let Some(ref path) = req.path {
        // Reject absolute paths immediately
        if Path::new(path).is_absolute() {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: PathBuf::from(path),
            }));
        }
        // Search single file
        let full_path = sandbox_root.join(path);
        // Canonicalize to verify we're within sandbox (handles symlinks and ..)
        let canonical = full_path.canonicalize().map_err(|_| {
            ApiError::Nucleus(NucleusError::SandboxEscape {
                path: full_path.clone(),
            })
        })?;
        if !canonical.starts_with(&sandbox_canonical) {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: full_path,
            }));
        }
        if canonical.is_file() {
            vec![canonical]
        } else {
            vec![]
        }
    } else {
        // Walk directory and optionally filter by glob
        let glob_pattern = req
            .file_glob
            .as_ref()
            .and_then(|g| glob::Pattern::new(g).ok());

        WalkDir::new(&sandbox_canonical)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            // Security: skip symlinks that could point outside sandbox
            .filter(|e| !e.file_type().is_symlink())
            .filter(|e| {
                // Double-check canonical path is within sandbox
                e.path()
                    .canonicalize()
                    .map(|c| c.starts_with(&sandbox_canonical))
                    .unwrap_or(false)
            })
            .filter(|e| {
                if let Some(ref pat) = glob_pattern {
                    pat.matches_path(e.path())
                } else {
                    true
                }
            })
            .map(|e| e.into_path())
            .collect()
    };

    // Search each file
    'outer: for file_path in files {
        let file = match std::fs::File::open(&file_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

        for (idx, line) in lines.iter().enumerate() {
            if regex.is_match(line) {
                let relative = file_path
                    .strip_prefix(&sandbox_canonical)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| file_path.to_string_lossy().to_string());

                let context_before = if context_lines > 0 {
                    let start = idx.saturating_sub(context_lines);
                    Some(lines[start..idx].to_vec())
                } else {
                    None
                };

                let context_after = if context_lines > 0 {
                    let end = (idx + 1 + context_lines).min(lines.len());
                    Some(lines[idx + 1..end].to_vec())
                } else {
                    None
                };

                matches.push(GrepMatch {
                    file: relative,
                    line: idx + 1, // 1-indexed
                    content: line.clone(),
                    context_before,
                    context_after,
                });

                if matches.len() >= max_matches {
                    truncated = true;
                    break 'outer;
                }
            }
        }
    }

    audit_event_with_context(&state, &headers, "grep", &req.pattern, "ok", audit_ctx).await?;
    Ok(Json(GrepResponse {
        matches,
        truncated: if truncated { Some(true) } else { None },
    }))
}

/// Web search using configured backend.
async fn web_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WebSearchRequest>,
) -> Result<Json<WebSearchResponse>, ApiError> {
    // Validate inputs before any processing
    validation::validate_query(&req.query).map_err(ApiError::Validation)?;

    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    // Check web_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.web_search;
    if level == CapabilityLevel::Never {
        audit_failure(
            &state,
            &headers,
            "web_search",
            &req.query,
            "insufficient_capability",
            audit_ctx.clone(),
        )
        .await;
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "web_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if trifecta requires approval
    if policy.requires_approval(Operation::WebSearch) {
        let policy_allows = check_identity_policy(
            &state,
            auth_ctx.as_ref(),
            &format!("web_search {}", req.query),
        );
        if !policy_allows && !state.approvals.consume("web_search") {
            audit_failure(
                &state,
                &headers,
                "web_search",
                &req.query,
                "approval_required",
                audit_ctx.clone(),
            )
            .await;
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("web_search {}", req.query),
            }));
        }
    }

    // Web search requires a configured backend URL
    // For now, return an error indicating the backend must be configured
    // A real implementation would read NUCLEUS_WEB_SEARCH_URL from env/config
    let search_url = std::env::var("NUCLEUS_WEB_SEARCH_URL").ok();

    if search_url.is_none() {
        return Err(ApiError::Spec(
            "web_search requires NUCLEUS_WEB_SEARCH_URL to be configured".to_string(),
        ));
    }

    let search_url = search_url.unwrap();

    // Check DNS allow list
    let url = url::Url::parse(&search_url)
        .map_err(|e| ApiError::Spec(format!("invalid search backend URL: {e}")))?;

    if !state.dns_allow.is_empty() {
        let host = url
            .host_str()
            .ok_or_else(|| ApiError::Spec("search URL has no host".into()))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let host_port = format!("{}:{}", host, port);

        let allowed = state.dns_allow.iter().any(|pattern| {
            pattern == &host_port || pattern == host || pattern.starts_with(&format!("{}:", host))
        });

        if !allowed {
            return Err(ApiError::DnsNotAllowed(host_port));
        }
    }

    // Perform search request
    let max_results = req.max_results.unwrap_or(10);
    let response = state
        .web_client
        .get(&search_url)
        .query(&[("q", &req.query), ("num", &max_results.to_string())])
        .send()
        .await
        .map_err(|e| ApiError::WebFetch(format!("search request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(ApiError::WebFetch(format!(
            "search backend returned status {}",
            response.status()
        )));
    }

    // Parse response - this is a generic JSON structure
    // Real implementations would adapt to specific search APIs
    let body = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| ApiError::WebFetch(format!("failed to parse search response: {e}")))?;

    // Try to extract results from common formats
    let results = if let Some(items) = body.get("results").and_then(|r| r.as_array()) {
        items
            .iter()
            .filter_map(|item| {
                Some(WebSearchResult {
                    title: item.get("title")?.as_str()?.to_string(),
                    url: item.get("url")?.as_str()?.to_string(),
                    snippet: item
                        .get("snippet")
                        .and_then(|s| s.as_str())
                        .map(String::from),
                })
            })
            .take(max_results)
            .collect()
    } else {
        Vec::new()
    };

    audit_event_with_context(&state, &headers, "web_search", &req.query, "ok", audit_ctx).await?;
    Ok(Json(WebSearchResponse { results }))
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

/// Escalate permissions for an agent using SPIFFE trace chains.
///
/// This endpoint allows agents to request elevated permissions, bounded by:
/// 1. The approver's ceiling (their trace chain's meet)
/// 2. The escalation policy's max_grant
/// 3. Time limits defined by the policy
///
/// The request must be made by an authenticated SPIFFE identity (via mTLS)
/// that matches an approver pattern in the escalation policy.
async fn escalate_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<EscalateRequest>,
) -> Result<Json<EscalateResponse>, ApiError> {
    // Rate limit escalation requests
    if !state.approval_rate_limiter.try_acquire() {
        return Err(ApiError::RateLimited);
    }

    // SECURITY: Validate nonce to prevent replay attacks
    // This is critical - without nonce protection, an attacker can replay
    // a captured escalation request within the drand tolerance window (~60s)
    if req.nonce.is_empty() {
        return Err(ApiError::Escalation(
            "escalation nonce required".to_string(),
        ));
    }

    let now = now_unix();
    // Use a longer expiry for escalation nonces (5 minutes) since escalations
    // are higher-value targets than regular approvals
    let nonce_expiry = now + 300; // 5 minutes
    if !state
        .approval_nonces
        .check_and_insert(&req.nonce, nonce_expiry, now)
    {
        tracing::warn!(
            nonce = %req.nonce,
            "REJECTING: escalation nonce already used (potential replay attack)"
        );
        return Err(ApiError::Escalation(
            "escalation nonce already used (potential replay attack)".to_string(),
        ));
    }

    // Check if escalation policies are configured
    if !state.policy_engine.has_escalation_policies() {
        return Err(ApiError::Escalation(
            "no escalation policies configured".to_string(),
        ));
    }

    // Extract approver's SPIFFE identity from mTLS
    let auth_ctx = auth.map(|e| e.0);
    let approver_spiffe_id = auth_ctx
        .as_ref()
        .and_then(|a| a.spiffe_id.clone())
        .ok_or_else(|| {
            ApiError::Escalation("escalation requires SPIFFE mTLS authentication".to_string())
        })?;

    // Reconstruct the requestor's trace chain
    let requestor_chain = deserialize_trace_chain(&req.requestor_chain)?;

    // Reconstruct the approver's trace chain from the request
    // SECURITY: The approver MUST submit their full chain - we don't construct it server-side
    let approver_chain = deserialize_trace_chain(&req.approver_chain)?;

    // SECURITY: Verify the submitted approver chain's leaf matches the mTLS identity
    // This prevents an attacker from submitting someone else's chain
    let approver_chain_leaf = approver_chain.current_spiffe_id().ok_or_else(|| {
        ApiError::Escalation("approver chain must have at least one link".to_string())
    })?;

    if approver_chain_leaf != approver_spiffe_id {
        tracing::warn!(
            submitted_leaf = %approver_chain_leaf,
            authenticated_id = %approver_spiffe_id,
            "approver chain leaf does not match authenticated identity"
        );
        return Err(ApiError::Escalation(
            "approver chain leaf must match authenticated SPIFFE identity".to_string(),
        ));
    }

    // SECURITY: Verify the approver chain is valid (non-expired, monotonic)
    if !approver_chain.verify() {
        let result = approver_chain.verify_detailed();
        let reason = match result {
            lattice_guard::escalation::ChainVerificationResult::Invalid { reason, .. } => reason,
            _ => "unknown".to_string(),
        };
        tracing::warn!(
            chain_id = %approver_chain.id,
            reason = %reason,
            "approver chain verification failed"
        );
        return Err(ApiError::Escalation(format!(
            "approver chain is invalid: {}",
            reason
        )));
    }

    // Get the requested permissions
    let requested = preset_to_permissions(&req.requested_preset);

    // Fetch current drand round for cryptographic timestamping
    let drand_round = if let Some(ref audit_log) = state.audit.drand_client {
        match audit_log.current_round().await {
            Ok(round) => round,
            Err(e) => {
                tracing::warn!("failed to fetch drand round for escalation: {e}");
                return Err(ApiError::Escalation(
                    "failed to fetch drand round for cryptographic timestamp".to_string(),
                ));
            }
        }
    } else {
        return Err(ApiError::Escalation(
            "drand anchoring required for escalation but not configured".to_string(),
        ));
    };

    // Create the escalation request
    let escalation_request = EscalationRequest::new(
        requestor_chain.clone(),
        requested,
        &req.reason,
        req.ttl_seconds,
    );

    // Validate against escalation policies
    let policy_result = state
        .policy_engine
        .escalation_policies()
        .validate_escalation(&escalation_request, &approver_chain);

    match policy_result {
        Ok(_policy) => {
            // Create the grant
            match EscalationGrant::new(&escalation_request, approver_chain, drand_round) {
                Ok(grant) => {
                    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);
                    let audit_subject = format!(
                        "escalation:{} -> {} (ttl={}s)",
                        requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                        req.requested_preset,
                        req.ttl_seconds
                    );
                    audit_event_with_context(
                        &state,
                        &headers,
                        "escalate",
                        &audit_subject,
                        "granted",
                        audit_ctx,
                    )
                    .await?;

                    tracing::info!(
                        requestor = %requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                        approver = %approver_spiffe_id,
                        preset = %req.requested_preset,
                        ttl_seconds = %req.ttl_seconds,
                        drand_round = %drand_round,
                        grant_id = %grant.id,
                        event = "escalation_granted",
                        "escalation request approved"
                    );

                    Ok(Json(EscalateResponse {
                        granted: true,
                        grant_id: Some(grant.id.to_string()),
                        granted_preset: Some(req.requested_preset.clone()),
                        expires_at: Some(grant.expires_at.timestamp() as u64),
                        drand_round: Some(drand_round),
                        error: None,
                    }))
                }
                Err(e) => {
                    let error_msg = escalation_error_to_string(&e);
                    tracing::warn!(
                        requestor = %requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                        approver = %approver_spiffe_id,
                        error = %error_msg,
                        event = "escalation_denied",
                        "escalation grant creation failed"
                    );

                    Ok(Json(EscalateResponse {
                        granted: false,
                        grant_id: None,
                        granted_preset: None,
                        expires_at: None,
                        drand_round: None,
                        error: Some(error_msg),
                    }))
                }
            }
        }
        Err(e) => {
            let error_msg = escalation_error_to_string(&e);
            let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);
            let audit_subject = format!(
                "escalation:{} -> {} (denied: {})",
                requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                req.requested_preset,
                error_msg
            );
            audit_event_with_context(
                &state,
                &headers,
                "escalate",
                &audit_subject,
                "denied",
                audit_ctx,
            )
            .await?;

            tracing::warn!(
                requestor = %requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                approver = %approver_spiffe_id,
                error = %error_msg,
                event = "escalation_denied",
                "escalation request denied by policy"
            );

            Ok(Json(EscalateResponse {
                granted: false,
                grant_id: None,
                granted_preset: None,
                expires_at: None,
                drand_round: None,
                error: Some(error_msg),
            }))
        }
    }
}

/// Deserialize a trace chain from the request format.
///
/// SECURITY: UUIDs are ALWAYS generated server-side. Client-provided IDs are
/// logged for audit purposes but never used. This prevents:
/// - Replay attacks using pre-computed IDs
/// - Collision attacks on chain/link identifiers
/// - ID prediction for future grants
fn deserialize_trace_chain(chain: &SerializedTraceChain) -> Result<SpiffeTraceChain, ApiError> {
    use chrono::{TimeZone, Utc};

    if chain.links.is_empty() {
        return Err(ApiError::Escalation(
            "trace chain must have at least one link".to_string(),
        ));
    }

    let first_link = &chain.links[0];
    let first_permissions = preset_to_permissions(&first_link.preset);
    let mut trace_chain = SpiffeTraceChain::new_root(
        &first_link.spiffe_id,
        first_permissions,
        first_link.drand_round,
    );

    // SECURITY: Log client-provided ID for audit but NEVER use it
    // Server always generates fresh UUIDs to prevent replay/collision attacks
    // NOTE: Logged at WARN level to ensure visibility in production logs
    if !chain.id.is_empty() {
        tracing::warn!(
            client_provided_chain_id = %chain.id,
            server_chain_id = %trace_chain.id,
            security_event = "client_id_ignored",
            "client provided chain ID ignored - using server-generated ID (potential attack indicator)"
        );
    }

    // Add remaining links
    for link in chain.links.iter().skip(1) {
        let permissions = preset_to_permissions(&link.preset);
        let mut trace_link = SpiffeTraceLink::new(&link.spiffe_id, permissions, link.drand_round)
            .with_reason(&link.reason);

        if let Some(expires_at) = link.expires_at {
            if let Some(dt) = Utc.timestamp_opt(expires_at as i64, 0).single() {
                trace_link = trace_link.with_expiry(dt);
            }
        }

        // SECURITY: Log client-provided ID for audit but NEVER use it
        // NOTE: Logged at WARN level to ensure visibility in production logs
        if !link.id.is_empty() {
            tracing::warn!(
                client_provided_link_id = %link.id,
                server_link_id = %trace_link.id,
                security_event = "client_id_ignored",
                "client provided link ID ignored - using server-generated ID (potential attack indicator)"
            );
        }

        trace_chain.extend(trace_link);
    }

    Ok(trace_chain)
}

/// Convert an EscalationError to a user-friendly string.
fn escalation_error_to_string(e: &EscalationError) -> String {
    match e {
        EscalationError::RequestExpired => "escalation request has expired".to_string(),
        EscalationError::InvalidRequestorChain => "requestor's trace chain is invalid".to_string(),
        EscalationError::InvalidApproverChain => "approver's trace chain is invalid".to_string(),
        EscalationError::ExceedsCeiling { requested, ceiling } => {
            format!(
                "requested '{}' exceeds approver's ceiling '{}'",
                requested, ceiling
            )
        }
        EscalationError::ExceedsPolicyMax => {
            "requested permissions exceed policy maximum".to_string()
        }
        EscalationError::TtlExceedsPolicy { requested, max } => {
            format!(
                "requested TTL ({} seconds) exceeds policy maximum ({} seconds)",
                requested, max
            )
        }
        EscalationError::NoMatchingPolicy => "no matching escalation policy found".to_string(),
        EscalationError::PolicyMismatch { reason } => format!("policy mismatch: {}", reason),
        EscalationError::SelfEscalation => "self-escalation not allowed".to_string(),
        EscalationError::InvalidTtl => "invalid TTL: must be positive".to_string(),
        EscalationError::ChainVerificationFailed { reason } => {
            format!("chain verification failed: {}", reason)
        }
        EscalationError::AttestationRequired { chain_type, status } => {
            format!(
                "attestation required: {} chain has status '{}' but full attestation is mandatory",
                chain_type, status
            )
        }
    }
}

/// Convert a preset name to a PermissionLattice (local helper, mirrors policy.rs).
fn preset_to_permissions(preset: &str) -> PermissionLattice {
    match preset.to_lowercase().as_str() {
        "codegen" => PermissionLattice::codegen(),
        "pr_review" | "pr-review" => PermissionLattice::pr_review(),
        "pr_approve" | "pr-approve" => PermissionLattice::pr_approve(),
        "code_review" | "code-review" => PermissionLattice::code_review(),
        "web_research" | "web-research" | "research" => PermissionLattice::web_research(),
        "restrictive" => PermissionLattice::restrictive(),
        "permissive" => PermissionLattice::permissive(),
        "network_only" | "network-only" => PermissionLattice::network_only(),
        "read_only" | "read-only" => PermissionLattice::read_only(),
        "filesystem_readonly" | "filesystem-readonly" => PermissionLattice::filesystem_readonly(),
        "edit_only" | "edit-only" => PermissionLattice::edit_only(),
        "local_dev" | "local-dev" => PermissionLattice::local_dev(),
        "fix_issue" | "fix-issue" => PermissionLattice::fix_issue(),
        "release" => PermissionLattice::release(),
        "database_client" | "database-client" => PermissionLattice::database_client(),
        "demo" => PermissionLattice::demo(),
        _ => PermissionLattice::restrictive(),
    }
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

// =============================================================================
// Pod Management Handlers (orchestrator mode)
// =============================================================================

#[derive(Debug, Deserialize)]
struct CreateSubPodRequest {
    /// PodSpec YAML for the sub-pod.
    spec_yaml: String,
    /// Reason for creating the sub-pod (audit trail).
    reason: String,
}

#[derive(Debug, Serialize)]
struct CreateSubPodResponse {
    pod_id: String,
    proxy_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PodIdRequest {
    pod_id: String,
}

/// Check that manage_pods capability is at least LowRisk.
fn check_manage_pods(state: &AppState) -> Result<(), ApiError> {
    let policy = state.runtime.policy();
    let level = policy.capabilities.manage_pods;
    if level == CapabilityLevel::Never {
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "manage_pods".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }
    Ok(())
}

async fn create_sub_pod(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<CreateSubPodRequest>,
) -> Result<Json<CreateSubPodResponse>, ApiError> {
    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    // 1. Check manage_pods capability
    check_manage_pods(&state)?;

    // 2. Parse requested PodSpec
    let mut spec: PodSpec = serde_yaml::from_str(&req.spec_yaml)
        .map_err(|e| ApiError::Spec(format!("invalid sub-pod spec: {e}")))?;

    // 3. Resolve requested policy → PermissionLattice
    let requested = spec
        .spec
        .resolve_policy()
        .map_err(|e| ApiError::Spec(format!("invalid sub-pod policy: {e}")))?;

    // 4. Enforce delegation ceiling via delegate_to()
    if let Some(ceiling) = state.delegation_ceiling.as_ref() {
        let delegated = ceiling
            .delegate_to(&requested, &req.reason)
            .map_err(|e| ApiError::Spec(format!("delegation failed: {e}")))?;

        // Replace policy with delegated (never exceeds parent)
        spec.spec.policy = nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(delegated),
        };
    }

    // 5. Inject credentials from orchestrator's env (transparent to agent)
    let mut creds = spec.spec.credentials.take().unwrap_or_default();
    for (key, val) in &state.orchestrator_credentials {
        if !creds.env.contains_key(key) {
            creds.env.insert(key.clone(), val.clone());
        }
    }
    if !creds.is_empty() {
        spec.spec.credentials = Some(creds);
    }

    // 6. Forward to nucleus-node
    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let spec_yaml = serde_yaml::to_string(&spec)
        .map_err(|e| ApiError::Spec(format!("failed to serialize sub-pod spec: {e}")))?;

    let result = node
        .create_pod(&spec_yaml)
        .await
        .map_err(|e| ApiError::Spec(format!("node create_pod failed: {e}")))?;

    // 7. Audit log
    audit_event_with_context(
        &state,
        &headers,
        "pod_create",
        &format!("sub-pod {} (reason: {})", result.id, req.reason),
        "created",
        audit_ctx,
    )
    .await?;

    Ok(Json(CreateSubPodResponse {
        pod_id: result.id.to_string(),
        proxy_addr: result.proxy_addr,
    }))
}

async fn list_sub_pods(
    State(state): State<AppState>,
    _headers: HeaderMap,
) -> Result<Json<Vec<node_client::PodInfo>>, ApiError> {
    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pods = node
        .list_pods()
        .await
        .map_err(|e| ApiError::Spec(format!("node list_pods failed: {e}")))?;

    Ok(Json(pods))
}

async fn get_pod_status(
    State(state): State<AppState>,
    Json(req): Json<PodIdRequest>,
) -> Result<Json<Vec<node_client::PodInfo>>, ApiError> {
    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pods = node
        .list_pods()
        .await
        .map_err(|e| ApiError::Spec(format!("node list_pods failed: {e}")))?;

    let filtered: Vec<_> = pods
        .into_iter()
        .filter(|p| p.id.to_string() == req.pod_id)
        .collect();

    Ok(Json(filtered))
}

async fn get_pod_logs(
    State(state): State<AppState>,
    Json(req): Json<PodIdRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pod_id: uuid::Uuid = req
        .pod_id
        .parse()
        .map_err(|e| ApiError::Spec(format!("invalid pod_id: {e}")))?;

    let logs = node
        .pod_logs(pod_id)
        .await
        .map_err(|e| ApiError::Spec(format!("node pod_logs failed: {e}")))?;

    Ok(Json(
        serde_json::json!({ "pod_id": req.pod_id, "logs": logs }),
    ))
}

async fn cancel_sub_pod(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<PodIdRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth_ctx = auth.map(|e| e.0);
    let audit_ctx = AuditContext::from_auth(auth_ctx.as_ref(), &state);

    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pod_id: uuid::Uuid = req
        .pod_id
        .parse()
        .map_err(|e| ApiError::Spec(format!("invalid pod_id: {e}")))?;

    node.cancel_pod(pod_id)
        .await
        .map_err(|e| ApiError::Spec(format!("node cancel_pod failed: {e}")))?;

    audit_event_with_context(
        &state,
        &headers,
        "pod_cancel",
        &format!("sub-pod {}", req.pod_id),
        "cancelled",
        audit_ctx,
    )
    .await?;

    Ok(Json(
        serde_json::json!({ "status": "cancelled", "pod_id": req.pod_id }),
    ))
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
    use nucleus_client::drand::{DrandClient, DrandConfig, DrandFailMode};

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

    // Set up drand client for cryptographic time anchoring if drand is enabled
    let drand_client = if args.drand_enabled {
        let fail_mode = match args.drand_fail_mode.to_lowercase().as_str() {
            "cached" => DrandFailMode::Cached,
            _ => DrandFailMode::Strict,
        };
        let config = DrandConfig {
            enabled: true,
            api_url: args.drand_url.clone(),
            round_tolerance: args.drand_tolerance,
            cache_ttl: Duration::from_secs(25),
            fail_mode,
            chain_hash: None, // Use default
            public_key: None, // Use default
        };
        info!(
            "drand anchoring enabled for audit logs (url={}, tolerance={})",
            args.drand_url, args.drand_tolerance
        );
        Some(Arc::new(DrandClient::new(config)))
    } else {
        None
    };

    Ok(Arc::new(AuditLog {
        path,
        secret,
        last_hash: Mutex::new(last_hash),
        entry_count: std::sync::atomic::AtomicU64::new(0),
        webhook,
        drand_client,
    }))
}

/// Extended audit context for richer logging.
#[derive(Clone)]
struct AuditContext {
    spiffe_id: Option<String>,
    policy_rule: Option<String>,
}

impl AuditContext {
    fn empty() -> Self {
        Self {
            spiffe_id: None,
            policy_rule: None,
        }
    }

    fn from_auth(auth: Option<&auth::AuthContext>, state: &AppState) -> Self {
        let spiffe_id = auth.and_then(|a| a.spiffe_id.clone());
        let policy_rule = spiffe_id.as_ref().and_then(|id| {
            state
                .policy_engine
                .matching_policy(id)
                .map(|p| p.pattern.clone())
        });
        Self {
            spiffe_id,
            policy_rule,
        }
    }
}

async fn audit_event(
    state: &AppState,
    headers: &HeaderMap,
    event: &str,
    subject: &str,
    result: &str,
) -> Result<(), ApiError> {
    audit_event_with_context(
        state,
        headers,
        event,
        subject,
        result,
        AuditContext::empty(),
    )
    .await
}

/// Log an audit event for a failed operation.
///
/// This is called when an operation fails due to policy denial, validation errors,
/// or other reasons. The error kind is included in the result field.
async fn audit_failure(
    state: &AppState,
    headers: &HeaderMap,
    event: &str,
    subject: &str,
    error_kind: &str,
    ctx: AuditContext,
) {
    // Failures are logged but we don't propagate audit errors for failed ops
    // (the original error takes precedence)
    let _ = audit_event_with_context(
        state,
        headers,
        event,
        subject,
        &format!("denied:{}", error_kind),
        ctx,
    )
    .await;
}

async fn audit_event_with_context(
    state: &AppState,
    headers: &HeaderMap,
    event: &str,
    subject: &str,
    result: &str,
    ctx: AuditContext,
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
            drand_round: None, // Will be filled by AuditLog::log
            spiffe_id: ctx.spiffe_id,
            policy_rule: ctx.policy_rule,
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
    let report = format!(
        "{} [sandbox_proof={}]",
        report,
        state.sandbox_proof.tier_label()
    );

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
            drand_round: None, // Will be filled by AuditLog::log
            spiffe_id: None,
            policy_rule: None,
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
    /// Drand round number for cryptographic time anchoring.
    #[serde(skip_serializing_if = "Option::is_none")]
    drand_round: Option<u64>,
    /// SPIFFE identity of the authenticated requester.
    #[serde(skip_serializing_if = "Option::is_none")]
    spiffe_id: Option<String>,
    /// Policy rule that authorized this operation (if zero-prompt).
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_rule: Option<String>,
}

struct AuditLog {
    path: PathBuf,
    secret: Vec<u8>,
    last_hash: Mutex<String>,
    entry_count: std::sync::atomic::AtomicU64,
    webhook: Option<WebhookSink>,
    /// Optional drand client for cryptographic time anchoring.
    drand_client: Option<Arc<nucleus_client::drand::DrandClient>>,
}

struct WebhookSink {
    url: String,
    client: reqwest::Client,
}

impl AuditLog {
    async fn log(&self, mut entry: AuditEntry) -> Result<(), ApiError> {
        // Fetch drand round for cryptographic time anchoring
        if let Some(ref drand) = self.drand_client {
            match drand.current_round().await {
                Ok(round) => {
                    entry.drand_round = Some(round);
                }
                Err(e) => {
                    tracing::warn!("failed to fetch drand round for audit: {e}");
                    // Continue without drand anchoring - don't block audit logging
                }
            }
        }

        let actor = entry.actor.clone().unwrap_or_default();
        let (prev_hash, hash, signature) = {
            let mut last_hash = self.last_hash.lock().unwrap();
            let prev_hash = last_hash.clone();
            // Include drand_round in message if available for stronger binding
            let drand_part = entry
                .drand_round
                .map(|r| format!("|drand:{}", r))
                .unwrap_or_default();
            let message = format!(
                "{}|{}|{}|{}|{}|{}{}",
                entry.timestamp_unix,
                actor,
                entry.event,
                entry.subject,
                entry.result,
                prev_hash,
                drand_part
            );
            let signature = auth::sign_message(&self.secret, message.as_bytes());
            let hash = sha256_hex(&format!("{}|{}", message, signature));
            *last_hash = hash.clone();
            (prev_hash, hash, signature)
        };
        entry.prev_hash = prev_hash;
        entry.signature = signature.clone();
        entry.hash = hash;
        self.entry_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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

    /// Get the current tail hash and entry count for the exit report.
    fn tail_hash_and_count(&self) -> (String, u64) {
        let hash = self.last_hash.lock().unwrap().clone();
        let count = self.entry_count.load(std::sync::atomic::Ordering::Relaxed);
        (hash, count)
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

    #[test]
    fn test_run_request_array_form() {
        let json = r#"{"args": ["ls", "-la", "/tmp"]}"#;
        let req: RunRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.args, vec!["ls", "-la", "/tmp"]);
        assert!(req.stdin.is_none());
        assert!(req.directory.is_none());
        assert!(req.timeout_seconds.is_none());
    }

    #[test]
    fn test_run_request_with_all_fields() {
        let json =
            r#"{"args": ["cat"], "stdin": "hello", "directory": "subdir", "timeout_seconds": 30}"#;
        let req: RunRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.args, vec!["cat"]);
        assert_eq!(req.stdin, Some("hello".to_string()));
        assert_eq!(req.directory, Some("subdir".to_string()));
        assert_eq!(req.timeout_seconds, Some(30));
    }

    #[test]
    fn test_glob_request_parsing() {
        let json = r#"{"pattern": "**/*.rs", "directory": "src", "max_results": 100}"#;
        let req: GlobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.pattern, "**/*.rs");
        assert_eq!(req.directory, Some("src".to_string()));
        assert_eq!(req.max_results, Some(100));
    }

    #[test]
    fn test_glob_request_minimal() {
        let json = r#"{"pattern": "*.txt"}"#;
        let req: GlobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.pattern, "*.txt");
        assert!(req.directory.is_none());
        assert!(req.max_results.is_none());
    }

    #[test]
    fn test_grep_request_parsing() {
        let json = r#"{"pattern": "fn main", "path": "src/main.rs", "context_lines": 2}"#;
        let req: GrepRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.pattern, "fn main");
        assert_eq!(req.path, Some("src/main.rs".to_string()));
        assert_eq!(req.context_lines, Some(2));
    }

    #[test]
    fn test_grep_request_with_glob() {
        let json = r#"{"pattern": "TODO", "glob": "**/*.rs", "case_insensitive": true}"#;
        let req: GrepRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.pattern, "TODO");
        assert_eq!(req.file_glob, Some("**/*.rs".to_string()));
        assert_eq!(req.case_insensitive, Some(true));
    }

    #[test]
    fn test_web_search_request_parsing() {
        let json = r#"{"query": "rust async await", "max_results": 5}"#;
        let req: WebSearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.query, "rust async await");
        assert_eq!(req.max_results, Some(5));
    }

    #[test]
    fn test_glob_response_serialization() {
        let resp = GlobResponse {
            matches: vec!["src/main.rs".to_string(), "src/lib.rs".to_string()],
            truncated: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("src/main.rs"));
        assert!(!json.contains("truncated"));
    }

    #[test]
    fn test_grep_match_serialization() {
        let m = GrepMatch {
            file: "src/main.rs".to_string(),
            line: 42,
            content: "fn main() {".to_string(),
            context_before: Some(vec!["// entry point".to_string()]),
            context_after: None,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("src/main.rs"));
        assert!(json.contains("42"));
        assert!(json.contains("entry point"));
    }

    // ── Approval Bundle Tests ──────────────────────────────────────────

    fn make_test_key() -> (Vec<u8>, nucleus_identity::did::JsonWebKey) {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pub_bytes = key_pair.public_key().as_ref();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
        let jwk = nucleus_identity::did::JsonWebKey::ec_p256(&x, &y);
        (pkcs8.as_ref().to_vec(), jwk)
    }

    #[test]
    fn test_approval_bundle_populates_registry() {
        let (pkcs8, _jwk) = make_test_key();
        let spec = "apiVersion: nucleus/v1\nkind: Pod\nspec:\n  work_dir: .";
        let manifest_hash = compute_manifest_hash(spec.as_bytes());

        let jws = nucleus_identity::approval_bundle::ApprovalBundleBuilder::new(
            "spiffe://test/human/alice",
        )
        .approve_operation("write_files")
        .approve_operation("run_bash")
        .manifest_hash(&manifest_hash)
        .ttl_seconds(3600)
        .build(&pkcs8)
        .unwrap();

        let registry = ApprovalRegistry::default();
        let result = verify_and_load_approval_bundle(&jws, spec, &registry);

        assert!(result.is_ok(), "verify_and_load failed: {:?}", result);
        assert!(
            registry.consume("write_files"),
            "write_files should be approved"
        );
        assert!(registry.consume("run_bash"), "run_bash should be approved");
        assert!(
            !registry.consume("web_fetch"),
            "web_fetch should NOT be approved"
        );
    }

    #[test]
    fn test_approval_bundle_wrong_manifest() {
        let (pkcs8, _jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"different-manifest");

        let jws = nucleus_identity::approval_bundle::ApprovalBundleBuilder::new(
            "spiffe://test/human/bob",
        )
        .approve_operation("read_files")
        .manifest_hash(&manifest_hash)
        .ttl_seconds(3600)
        .build(&pkcs8)
        .unwrap();

        let registry = ApprovalRegistry::default();
        let result = verify_and_load_approval_bundle(&jws, "actual-manifest-content", &registry);
        assert!(result.is_err(), "should fail with manifest hash mismatch");
    }

    #[test]
    fn test_approval_bundle_max_uses() {
        let (pkcs8, _jwk) = make_test_key();
        let spec = "spec: limited-use";
        let manifest_hash = compute_manifest_hash(spec.as_bytes());

        let jws = nucleus_identity::approval_bundle::ApprovalBundleBuilder::new(
            "spiffe://test/human/carol",
        )
        .approve_operation("write_files")
        .manifest_hash(&manifest_hash)
        .max_uses(2)
        .ttl_seconds(3600)
        .build(&pkcs8)
        .unwrap();

        let registry = ApprovalRegistry::default();
        verify_and_load_approval_bundle(&jws, spec, &registry).unwrap();

        // Should only allow 2 uses
        assert!(registry.consume("write_files"));
        assert!(registry.consume("write_files"));
        assert!(
            !registry.consume("write_files"),
            "third use should be denied"
        );
    }

    #[test]
    fn test_approval_bundle_invalid_jws() {
        let registry = ApprovalRegistry::default();
        let result = verify_and_load_approval_bundle("not.a.valid.jws", "spec", &registry);
        assert!(result.is_err());
    }
}
