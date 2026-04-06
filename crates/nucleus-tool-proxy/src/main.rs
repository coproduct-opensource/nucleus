#![allow(clippy::disallowed_types)] // #1216 exempt: pod setup, web client init, spec loading (infrastructure)
use std::collections::{BTreeMap, HashMap};
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
use nucleus::portcullis::escalation::{
    EscalationError, EscalationGrant, EscalationRequest, SpiffeTraceChain, SpiffeTraceLink,
};
use nucleus::portcullis::kernel::{Kernel, Verdict};
use nucleus::portcullis::{CapabilityLevel, Operation, PermissionLattice};
use nucleus::{ApprovalRequest, CallbackApprover, NucleusError, PodRuntime};
use nucleus_permission_market::{PermissionBid, PermissionGrant, PermissionMarket};
use nucleus_spec::PodSpec;
use portcullis::verdict_sink::{ActorIdentity, VerdictContext, VerdictOutcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

mod attestation;
mod auth;
mod cert_bridge;
mod exit_report;
mod identity_fusion;
mod lockdown_client;
#[cfg(feature = "mcp")]
mod mcp;
mod mtls;
mod node_client;
mod pod_mgmt;
mod policy;
mod sandbox_proof;
mod telemetry;
#[allow(dead_code)]
mod unicode_audit;
mod validation;
mod verdict_sink;
mod web_fetch_policy;

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
    /// S3 bucket for deletion-resistant audit storage.
    /// Each audit entry is stored as a separate object with `if_none_match("*")`
    /// to enforce append-only semantics. Compatible with AWS S3, MinIO, R2, Tigris.
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET")]
    audit_s3_bucket: Option<String>,
    /// Key prefix for audit objects in S3 (e.g. "audit/pod-name").
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX")]
    audit_s3_prefix: Option<String>,
    /// AWS region for the audit S3 bucket.
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_REGION")]
    audit_s3_region: Option<String>,
    /// Custom S3 endpoint URL (for MinIO, R2, Tigris, etc.).
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_ENDPOINT")]
    audit_s3_endpoint: Option<String>,
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

    /// gRPC endpoint of nucleus-node for streaming lockdown commands.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_NODE_GRPC_URL")]
    node_grpc_url: Option<String>,

    /// Delegation ceiling for sub-pod permissions (JSON-serialized PermissionLattice).
    /// Sub-pods cannot exceed this ceiling via delegate_to().
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_DELEGATION_CEILING")]
    delegation_ceiling: Option<String>,

    // === Delegation Certificate Configuration ===
    /// Hex-encoded Ed25519 public key of the root delegation authority.
    /// When set, the tool-proxy accepts `x-nucleus-delegation-cert` headers
    /// and verifies delegation certificates against this root key.
    #[arg(long, env = "NUCLEUS_CERT_ROOT_PUBKEY")]
    cert_root_pubkey: Option<String>,

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
    /// URL pattern allowlist for web_fetch. If non-empty, URLs must match.
    url_allow: Vec<String>,
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
    /// Root authority Ed25519 public key for delegation certificate verification.
    cert_root_pubkey: Option<Arc<Vec<u8>>>,
    /// Session exposure guard for exit report (set when MCP server starts).
    exposure_guard: Arc<std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>>,
    /// File-based lockdown flag. Set by the signal file watcher.
    file_lockdown: Arc<std::sync::atomic::AtomicBool>,
    /// gRPC stream-based lockdown flag. Set by the lockdown streaming client.
    stream_lockdown: Arc<std::sync::atomic::AtomicBool>,
    /// SHA-256 checksum of the permission lattice for telemetry correlation.
    /// Kept for future audit-log integration in VerdictSink (PR 3).
    #[allow(dead_code)]
    policy_checksum: String,
    /// Session ID (policy UUID) for telemetry grouping.
    /// Kept for future audit-log integration in VerdictSink (PR 3).
    #[allow(dead_code)]
    session_id: String,
    /// Shared verdict sink for lockdown + telemetry convergence (HTTP + MCP).
    pub(crate) verdict_sink: Arc<dyn portcullis::verdict_sink::VerdictSink>,
    /// Kernel decision engine for complete mediation (HTTP path).
    pub(crate) kernel: Arc<tokio::sync::Mutex<Kernel>>,
}

/// OR-semantics: locked if EITHER signal file OR gRPC stream says locked.
/// This prevents a race condition where one path could undo the other.
fn is_locked(state: &AppState) -> bool {
    state
        .file_lockdown
        .load(std::sync::atomic::Ordering::Acquire)
        || state
            .stream_lockdown
            .load(std::sync::atomic::Ordering::Acquire)
}

/// Extract an ActorIdentity from the auth context for verdict recording.
fn actor_from_auth(auth: Option<&auth::AuthContext>) -> ActorIdentity {
    if let Some(ctx) = auth {
        if let Some(ref spiffe_id) = ctx.spiffe_id {
            ActorIdentity::Authenticated {
                spiffe_id: spiffe_id.clone(),
            }
        } else {
            ActorIdentity::Unknown
        }
    } else {
        ActorIdentity::Unknown
    }
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

/// Simple URL glob matcher for `url_allow` patterns.
///
/// - `*` matches any sequence of characters except `/`
/// - `**` matches any sequence of characters including `/`
/// - All other characters match literally.
pub(crate) fn url_glob_match(pattern: &str, url: &str) -> bool {
    url_glob_match_inner(pattern.as_bytes(), url.as_bytes())
}

fn url_glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'*' {
        // `**` — match any number of chars (including `/`)
        let rest = &pattern[2..];
        for i in 0..=text.len() {
            if url_glob_match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if pattern[0] == b'*' {
        // `*` — match any number of non-`/` chars
        let rest = &pattern[1..];
        for i in 0..=text.len() {
            if i > 0 && text[i - 1] == b'/' {
                break;
            }
            if url_glob_match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pattern[0] == text[0] {
        return url_glob_match_inner(&pattern[1..], &text[1..]);
    }
    false
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
            ApiError::Nucleus(NucleusError::StateBlocked { .. }) => {
                (StatusCode::FORBIDDEN, "uninhabitable_blocked", None, None)
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
    // Install rustls crypto provider before any TLS connections (web_fetch, etc.).
    let _ = rustls::crypto::ring::default_provider().install_default();

    {
        use tracing_subscriber::prelude::*;

        #[cfg(feature = "otel")]
        let otel_layer = telemetry::init_otel_layer();
        #[cfg(not(feature = "otel"))]
        let otel_layer: Option<tracing_subscriber::layer::Identity> = None;

        tracing_subscriber::registry()
            .with(otel_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_filter(tracing_subscriber::EnvFilter::from_default_env()),
            )
            .init();
    }

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

    let runtime = pod_mgmt::build_runtime(&spec)?;
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

    let audit = build_audit_log(&args, &auth).await?;

    // Build HTTP client for web fetch
    let web_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.web_fetch_timeout_secs))
        .user_agent("nucleus-tool-proxy/0.1")
        .build()
        .map_err(|e| ApiError::Spec(format!("failed to build HTTP client: {e}")))?;

    // Extract DNS and URL allow lists from spec
    let dns_allow = spec
        .spec
        .network
        .as_ref()
        .map(|n| n.dns_allow.clone())
        .unwrap_or_default();
    let url_allow = spec
        .spec
        .network
        .as_ref()
        .map(|n| n.url_allow.clone())
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

    let policy_checksum = runtime.policy().checksum();
    let session_id = runtime.policy().id.to_string();

    // Pre-create shared state for lockdown + exposure so VerdictSink can share them.
    let file_lockdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stream_lockdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let exposure_guard: Arc<std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>> =
        Arc::new(std::sync::RwLock::new(None));

    let verdict_sink: Arc<dyn portcullis::verdict_sink::VerdictSink> =
        Arc::new(verdict_sink::ToolProxyVerdictSink::new(
            file_lockdown.clone(),
            stream_lockdown.clone(),
            runtime.policy().capabilities.clone(),
            exposure_guard.clone(),
            policy_checksum.clone(),
            session_id.clone(),
        ));

    let kernel = Arc::new(tokio::sync::Mutex::new(Kernel::new(
        runtime.policy().clone(),
    )));

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
        url_allow,
        attestation_verifier,
        policy_engine,
        node_client,
        delegation_ceiling,
        orchestrator_credentials,
        permission_market: Arc::new(Mutex::new(PermissionMarket::new())),
        sandbox_proof,
        cert_root_pubkey: args
            .cert_root_pubkey
            .as_deref()
            .and_then(|hex_str| hex::decode(hex_str).ok())
            .map(Arc::new),
        exposure_guard,
        file_lockdown,
        stream_lockdown,
        policy_checksum,
        session_id,
        verdict_sink,
        kernel,
    };

    if let Err(err) = emit_boot_report(&state).await {
        warn!("failed to emit boot report: {err}");
    }

    // Lockdown signal watcher: polls the signal file every 500ms.
    // Verifies HMAC before acting — prevents privilege escalation via
    // world-writable signal file (red team finding).
    {
        let lockdown_flag = state.file_lockdown.clone();
        tokio::spawn(async move {
            // Same path logic as the CLI
            let signal_path = dirs::runtime_dir()
                .or_else(dirs::data_local_dir)
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                .join("nucleus")
                .join("lockdown.json");

            // Fail-closed lockdown: on ANY verification failure (bad HMAC, parse
            // error, read error), preserve the current lockdown state rather than
            // defaulting to unlocked. Only a verified signal can change the state.
            loop {
                let current = lockdown_flag.load(std::sync::atomic::Ordering::Acquire);
                let should_lock = if signal_path.exists() {
                    match tokio::fs::read_to_string(&signal_path).await {
                        Ok(content) => parse_and_verify_lockdown_signal(&content, current),
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to read lockdown signal file — preserving current state"
                            );
                            current // fail-closed: preserve current state
                        }
                    }
                } else {
                    false // no file = no lockdown (file must exist to lock)
                };

                if should_lock != current {
                    lockdown_flag.store(should_lock, std::sync::atomic::Ordering::Release);
                    if should_lock {
                        tracing::warn!(
                            "LOCKDOWN ACTIVATED via verified signal file \
                             — meet(current, read_only) applied, forensic reads still allowed"
                        );
                    } else {
                        tracing::info!("Lockdown lifted via verified signal file");
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
    }

    // Streaming lockdown watcher: connects to nucleus-node gRPC and receives
    // LockdownCommand messages with sub-second latency.
    if let Some(ref grpc_url) = args.node_grpc_url {
        let stream_flag = state.stream_lockdown.clone();
        let auth_secret = args
            .node_auth_secret
            .clone()
            .unwrap_or_else(|| args.auth_secret.clone());
        let config = lockdown_client::LockdownWatcherConfig {
            node_grpc_url: grpc_url.clone(),
            auth_secret,
            proxy_id: format!(
                "{}:{}",
                whoami::hostname().unwrap_or_else(|_| "unknown".into()),
                std::process::id()
            ),
            pod_id: std::env::var("NUCLEUS_POD_ID").ok(),
        };
        tokio::spawn(async move {
            lockdown_client::run_lockdown_watcher(config, stream_flag).await;
        });
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
            .route("/v1/pod/create", post(pod_mgmt::create_sub_pod))
            .route("/v1/pod/list", post(pod_mgmt::list_sub_pods))
            .route("/v1/pod/status", post(pod_mgmt::get_pod_status))
            .route("/v1/pod/logs", post(pod_mgmt::get_pod_logs))
            .route("/v1/pod/cancel", post(pod_mgmt::cancel_sub_pod));
    }

    // Keep references for the exit report after shutdown
    let exit_audit = state.audit.clone();
    let exit_work_dir = spec.spec.work_dir.clone();
    let exit_exposure = state.exposure_guard.clone();

    let app = app
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_middleware));

    if let Some(vsock) = pod_mgmt::resolve_vsock(&args, &spec)? {
        pod_mgmt::serve_vsock(app, vsock, args.announce_path).await?;
        write_exit_report(&exit_audit, &exit_work_dir, &exit_exposure).await;
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

    write_exit_report(&exit_audit, &exit_work_dir, &exit_exposure).await;

    Ok(())
}

/// Write the exit report on shutdown (including verified exposure data).
async fn write_exit_report(
    audit: &AuditLog,
    work_dir_path: &Path,
    exposure_guard: &std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>,
) {
    let workspace_hash = match exit_report::hash_workspace(work_dir_path).await {
        Ok(h) => h,
        Err(e) => {
            warn!("failed to hash workspace for exit report: {e}");
            return;
        }
    };

    let (tail_hash, count) = audit.tail_hash_and_count();
    let mut report = exit_report::build_exit_report(workspace_hash, tail_hash, count, None);

    // Extract verified exposure from the session guard
    if let Ok(guard_opt) = exposure_guard.read() {
        if let Some(ref guard) = *guard_opt {
            let exposure = guard.exposure();
            if exposure.contains(portcullis::guard::ExposureLabel::PrivateData) {
                report
                    .observed_exposure_labels
                    .push("PrivateData".to_string());
            }
            if exposure.contains(portcullis::guard::ExposureLabel::UntrustedContent) {
                report
                    .observed_exposure_labels
                    .push("UntrustedContent".to_string());
            }
            if exposure.contains(portcullis::guard::ExposureLabel::ExfilVector) {
                report
                    .observed_exposure_labels
                    .push("ExfilVector".to_string());
            }
            report.uninhabitable_reached = exposure.is_uninhabitable();
            report.observed_risk_tier = match exposure.to_risk() {
                portcullis::StateRisk::Safe => "safe",
                portcullis::StateRisk::Low => "low",
                portcullis::StateRisk::Medium => "medium",
                portcullis::StateRisk::Uninhabitable => "critical",
            }
            .to_string();

            info!(
                exposure = ?report.observed_exposure_labels,
                risk = %report.observed_risk_tier,
                uninhabitable = report.uninhabitable_reached,
                "exit report: verified exposure captured"
            );
        }
    }

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

/// Check whether a request path maps to a read-only operation that is allowed
/// during lockdown.  This implements `meet(current, read_only)` semantics:
/// operations that would be permitted under `PermissionLattice::read_only()`
/// (i.e., `read_files`, `glob_search`, `grep_search` all at `Always`) pass
/// through, while every mutating operation is blocked.
fn is_allowed_during_lockdown(path: &str) -> bool {
    matches!(path, "/v1/read" | "/v1/glob" | "/v1/grep" | "/v1/health")
}

const HEADER_ATTESTATION: &str = "x-nucleus-attestation";
const HEADER_PERMISSION_BID: &str = "x-nucleus-permission-bid";
const HEADER_DELEGATION_CERT: &str = "x-nucleus-delegation-cert";

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

    // Emergency lockdown check — apply meet(current, read_only) semantics.
    // OR-semantics: locked if EITHER signal file OR gRPC stream says locked.
    // Read-only operations (read, glob, grep) continue working during lockdown
    // to enable forensic investigation. All mutating operations are blocked.
    if is_locked(&state) && !is_allowed_during_lockdown(parts.uri.path()) {
        return Err(ApiError::Body(
            "LOCKDOWN ACTIVE: mutating operations are blocked (read/glob/grep still allowed). \
             Use `nucleus lockdown --restore` to lift the lockdown."
                .to_string(),
        ));
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

    // Determine authentication context (unified flow — no early returns).
    // SPIFFE mTLS is most secure, then HMAC+drand for approvals, then HMAC.
    let mut context =
        if let Some(spiffe_id) = auth::extract_spiffe_id_from_extensions(&parts.extensions) {
            tracing::info!(
                spiffe_id = %spiffe_id,
                path = %parts.uri.path(),
                method = %parts.method,
                event = "auth_spiffe_mtls",
                "request authenticated via SPIFFE mTLS"
            );
            auth::verify_spiffe_mtls(&spiffe_id)
        } else if parts.uri.path() == APPROVE_PATH {
            let ctx = auth::verify_http_with_drand(&parts.headers, &bytes, &state.approval_auth)?;
            if ctx.drand_round.is_some() {
                tracing::info!(
                    drand_round = ctx.drand_round,
                    auth_method = ?ctx.auth_method,
                    "approval request verified with drand anchoring"
                );
            }
            ctx
        } else {
            auth::verify_http(&parts.headers, &bytes, &state.auth)?
        };

    // Extract client cert DER for Layer 3 (fused identity fingerprint extraction).
    let client_cert_der: Option<Vec<u8>> = parts
        .extensions
        .get::<MtlsConnectInfo>()
        .and_then(|info| info.client_cert.as_ref())
        .map(|cert| cert.cert_der.clone())
        .or_else(|| {
            parts
                .extensions
                .get::<ClientCertInfo>()
                .map(|cert| cert.cert_der.clone())
        });

    // Evaluate delegation certificate for ALL auth methods (not just HMAC).
    // This fixes the security gap where mTLS requests couldn't use delegation certs.
    // Identity binding: when mTLS is active, leaf_identity must match SPIFFE ID.
    let (permission_grant, certified_perms) = if let Some((grant, certified, fused)) =
        evaluate_delegation_cert_with_identity(
            &parts.headers,
            &state,
            context.spiffe_id.as_deref(),
            client_cert_der.as_deref(),
        ) {
        if let Some(ref fi) = fused {
            if fi.fingerprint_verified {
                context.identity_binding = auth::IdentityBinding::Fused {
                    permission_fingerprint: fi.permission_fingerprint,
                };
            } else {
                context.identity_binding = auth::IdentityBinding::DelegationVerified {
                    leaf_identity: certified.verified.leaf_identity.clone(),
                };
            }
        } else {
            context.identity_binding = auth::IdentityBinding::DelegationVerified {
                leaf_identity: certified.verified.leaf_identity.clone(),
            };
        }
        (Some(grant), Some(certified))
    } else {
        (evaluate_permission_bid(&parts.headers, &state), None)
    };

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
    if let Some(certified) = certified_perms {
        req.extensions_mut().insert(certified);
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

/// Verified delegation certificate permissions, inserted into request extensions.
/// Downstream handlers read these to enforce the intersection of
/// certificate attestation and market pricing.
#[derive(Clone)]
#[allow(dead_code)] // Fields consumed by downstream handlers
pub(crate) struct CertifiedPermissions {
    pub(crate) verified: portcullis::certificate::VerifiedPermissions,
    pub(crate) effective: PermissionLattice,
}

/// Parse, verify, and evaluate a delegation certificate from request headers,
/// enforcing identity binding when an authenticated SPIFFE ID is present.
///
/// Flow:
/// 1. Decode base64 certificate from `x-nucleus-delegation-cert`
/// 2. Verify Ed25519 chain against root public key
/// 3. **Identity binding**: if `authenticated_spiffe_id` is Some, reject if
///    `verified.leaf_identity != spiffe_id` (prevents privilege escalation)
/// 4. Convert `VerifiedPermissions` → `PermissionBid` via α
/// 5. Evaluate bid against market → `PermissionGrant`
/// 6. Intersect grant with certificate → effective `PermissionLattice`
fn evaluate_delegation_cert_with_identity(
    headers: &HeaderMap,
    state: &AppState,
    authenticated_spiffe_id: Option<&str>,
    client_cert_der: Option<&[u8]>,
) -> Option<(
    PermissionGrant,
    CertifiedPermissions,
    Option<identity_fusion::FusedIdentity>,
)> {
    let cert_header = headers.get(HEADER_DELEGATION_CERT)?;
    let cert_b64 = cert_header.to_str().ok()?;

    let root_pubkey = state.cert_root_pubkey.as_ref()?;

    let cert_bytes = match base64::engine::general_purpose::STANDARD.decode(cert_b64) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "invalid delegation cert base64");
            return None;
        }
    };

    let cert: portcullis::LatticeCertificate = match serde_json::from_slice(&cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "invalid delegation cert JSON");
            return None;
        }
    };

    let verified = match portcullis::verify_certificate(
        &cert,
        root_pubkey,
        chrono::Utc::now(),
        portcullis::certificate::DEFAULT_MAX_CHAIN_DEPTH,
    ) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "delegation cert verification failed");
            return None;
        }
    };

    // CRITICAL SECURITY CHECK (Layer 1): If we have an authenticated identity (mTLS),
    // verify that the delegation certificate's leaf identity matches.
    // This prevents privilege escalation where agent-A presents agent-B's cert.
    if let Some(spiffe_id) = authenticated_spiffe_id {
        if verified.leaf_identity != spiffe_id {
            tracing::warn!(
                authenticated_id = %spiffe_id,
                cert_leaf_id = %verified.leaf_identity,
                event = "identity_mismatch_rejected",
                "delegation cert leaf_identity does not match authenticated SPIFFE ID"
            );
            return None;
        }
    }

    // Layer 3: Extract fused identity from X.509 permission fingerprint extension.
    let mut fused = client_cert_der.and_then(|der| {
        authenticated_spiffe_id.and_then(|sid| identity_fusion::extract_fused_identity(der, sid))
    });

    let bid = cert_bridge::certificate_to_bid(&verified);

    let market = state.permission_market.lock().unwrap();
    let mut grant = market.evaluate_bid(&bid);

    // Layer 3: If fused identity present, verify fingerprint and elevate trust.
    if let Some(ref mut fi) = fused {
        if identity_fusion::verify_delegation_against_fingerprint(fi, &cert, &verified) {
            grant = identity_fusion::elevate_grant_trust(&grant);
        }
    }

    let effective = cert_bridge::intersect_grant_with_certificate(&grant, &verified);

    tracing::info!(
        leaf_identity = %verified.leaf_identity,
        chain_depth = verified.chain_depth,
        trust_tier = ?bid.trust_tier,
        granted = grant.granted.len(),
        denied = grant.denied.len(),
        total_cost = grant.total_cost,
        identity_verified = authenticated_spiffe_id.is_some(),
        fused_verified = fused.as_ref().is_some_and(|f| f.fingerprint_verified),
        event = "delegation_cert_evaluated",
        "delegation certificate verified and evaluated against market"
    );

    Some((
        grant,
        CertifiedPermissions {
            verified,
            effective,
        },
        fused,
    ))
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

#[allow(deprecated)] // Migration to decide_term tracked in #1194
async fn read_file(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::ReadFiles;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    if let Err(e) = validation::validate_path(&req.path) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.path.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }

    // Kernel mediation — obtain DecisionToken for sandbox I/O
    let decision_token = {
        let mut kernel = state.kernel.lock().await;
        let (decision, token) = kernel.decide(operation, &req.path);
        match decision.verdict {
            Verdict::Allow => token.expect("Allow verdict always produces token"),
            Verdict::Deny(_) => {
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
            Verdict::RequiresApproval => {
                info!(
                    ?operation,
                    subject = %req.path,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval"
                );
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
        }
    };

    let path = req.path.clone();

    let contents = match state
        .runtime
        .sandbox()
        .read_to_string(&path, &decision_token)
    {
        Ok(contents) => contents,
        Err(NucleusError::ApprovalRequired { operation: op }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(&state, auth_ctx.as_ref(), &format!("read {}", path))
                || state.approvals.consume(&op)
            {
                let approval = state.runtime.sandbox().request_approval(op.clone())?;
                let approved_dt = {
                    let mut kernel = state.kernel.lock().await;
                    kernel.issue_approved_token(operation, &format!("approved: read {}", path))
                };
                state
                    .runtime
                    .sandbox()
                    .read_to_string_approved(&path, &approved_dt, &approval)?
            } else {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: path.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: "approval_required".to_string(),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation: op,
                }));
            }
        }
        Err(err) => {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: path.clone(),
                outcome: VerdictOutcome::Error {
                    error: format!("{err:?}"),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(err));
        }
    };

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: path,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(ReadResponse { contents }))
}

#[allow(deprecated)] // Migration to decide_term tracked in #1194
async fn write_file(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::WriteFiles;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    if let Err(e) = validation::validate_path(&req.path) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.path.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }

    // Kernel mediation — obtain DecisionToken for sandbox I/O
    let decision_token = {
        let mut kernel = state.kernel.lock().await;
        let (decision, token) = kernel.decide(operation, &req.path);
        match decision.verdict {
            Verdict::Allow => token.expect("Allow verdict always produces token"),
            Verdict::Deny(_) => {
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
            Verdict::RequiresApproval => {
                info!(
                    ?operation,
                    subject = %req.path,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval"
                );
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
        }
    };

    let path = req.path.clone();
    let contents = req.contents.clone();

    match state
        .runtime
        .sandbox()
        .write(&path, contents.as_bytes(), &decision_token)
    {
        Ok(()) => {}
        Err(NucleusError::ApprovalRequired { operation: op }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(&state, auth_ctx.as_ref(), &format!("write {}", path))
                || state.approvals.consume(&op)
            {
                let approval = state.runtime.sandbox().request_approval(op.clone())?;
                let approved_dt = {
                    let mut kernel = state.kernel.lock().await;
                    kernel.issue_approved_token(operation, &format!("approved: write {}", path))
                };
                state.runtime.sandbox().write_approved(
                    &path,
                    contents.as_bytes(),
                    &approved_dt,
                    &approval,
                )?;
            } else {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: path.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: "approval_required".to_string(),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation: op,
                }));
            }
        }
        Err(err) => {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: path.clone(),
                outcome: VerdictOutcome::Error {
                    error: format!("{err:?}"),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(err));
        }
    }

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: path,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(WriteResponse { ok: true }))
}

#[allow(deprecated)] // Migration to decide_term tracked in #1194
async fn run_command(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::RunBash;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Build display command for logging/auditing
    let display_command = req.args.join(" ");

    // Validate inputs before any processing
    if let Err(e) = validation::validate_command_args(&req.args) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: display_command.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }
    if let Err(e) = validation::validate_stdin(req.stdin.as_deref()) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: display_command.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }
    if let Some(ref dir) = req.directory {
        if let Err(e) = validation::validate_path(dir) {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: display_command.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: format!("validation: {e}"),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Validation(e));
        }
    }

    // Kernel mediation — obtain DecisionToken for executor I/O
    let decision_token = {
        let mut kernel = state.kernel.lock().await;
        let (decision, token) = kernel.decide(operation, &display_command);
        match decision.verdict {
            Verdict::Allow => token.expect("Allow verdict always produces token"),
            Verdict::Deny(_) => {
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
            Verdict::RequiresApproval => {
                info!(
                    ?operation,
                    subject = %display_command,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval"
                );
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
        }
    };

    let executor = state.runtime.executor();

    // Extract optional parameters
    let stdin = req.stdin.as_deref();
    let directory = req.directory.as_deref();

    let output = match executor.run_args(&req.args, stdin, directory, &decision_token) {
        Ok(output) => output,
        Err(NucleusError::ApprovalRequired { operation: op }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(
                &state,
                auth_ctx.as_ref(),
                &format!("execute {}", display_command),
            ) || state.approvals.consume(&op)
            {
                let approval = executor.request_approval(&op)?;
                let approved_dt = {
                    let mut kernel = state.kernel.lock().await;
                    kernel.issue_approved_token(
                        operation,
                        &format!("approved: execute {}", display_command),
                    )
                };
                executor.run_args_with_approval(
                    &req.args,
                    stdin,
                    directory,
                    &approved_dt,
                    &approval,
                )?
            } else {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: display_command.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: "approval_required".to_string(),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation: op,
                }));
            }
        }
        Err(err) => {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: display_command.clone(),
                outcome: VerdictOutcome::Error {
                    error: format!("{err:?}"),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(err));
        }
    };

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: display_command,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(RunResponse {
        status: output.status.code().unwrap_or(-1),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }))
}

#[allow(deprecated)] // Migration to decide_term tracked in #1194
async fn web_fetch(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WebFetchRequest>,
) -> Result<Json<WebFetchResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::WebFetch;
    let url_str = req.url.clone();
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    if let Err(e) = validation::validate_url(&req.url) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: url_str.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }

    // Kernel mediation
    {
        let mut kernel = state.kernel.lock().await;
        let (decision, _decision_token) = kernel.decide(operation, &url_str);
        match decision.verdict {
            Verdict::Allow => {}
            Verdict::Deny(_) => {
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
            Verdict::RequiresApproval => {
                info!(
                    ?operation,
                    subject = %url_str,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval"
                );
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
        }
    }

    // Check web_fetch capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.web_fetch;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: url_str.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "web_fetch".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval for web_fetch
    if policy.requires_approval(Operation::WebFetch) {
        // Check if policy allows this operation (zero-prompt mode)
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("web_fetch {}", url_str));

        if !policy_allows && !state.approvals.consume("web_fetch") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: url_str.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("web_fetch {}", url_str),
            }));
        }
    }

    // Parse and validate URL
    let url =
        url::Url::parse(&url_str).map_err(|e| ApiError::WebFetch(format!("invalid URL: {e}")))?;

    // Check DNS allow list (if configured) — shared with MCP path
    {
        let host = url
            .host_str()
            .ok_or_else(|| ApiError::WebFetch("URL has no host".into()))?;
        let port = url.port_or_known_default().unwrap_or(443);
        web_fetch_policy::check_dns_allowlist(&state.dns_allow, host, port)
            .map_err(ApiError::DnsNotAllowed)?;
    }

    // Check URL allow list (if configured) — shared with MCP path
    web_fetch_policy::check_url_allowlist(&state.url_allow, url.as_str())
        .map_err(ApiError::WebFetch)?;

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

    // Verify the final URL after redirects is still in the allowlist.
    // Prevents open-redirect bypass attacks on allowlisted domains.
    let final_url = response.url().clone();
    web_fetch_policy::check_redirect_target(&state.dns_allow, &state.url_allow, &final_url)
        .map_err(|e| ApiError::WebFetch(format!("redirect target blocked: {e}")))?;

    // MIME type gating — shared with MCP path
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    web_fetch_policy::check_mime_type(content_type).map_err(ApiError::WebFetch)?;

    // Collect response headers + add exposure metadata
    let mut response_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect();

    // Exposure provenance: mark all web-fetched content as untrusted.
    // Downstream tool calls can use these headers for exposure tracking.
    response_headers.insert(
        "x-nucleus-exposure".to_string(),
        "UntrustedContent".to_string(),
    );
    if let Some(host) = url::Url::parse(&url_str)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
    {
        response_headers.insert("x-nucleus-source-domain".to_string(), host);
    }

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

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: url_str,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(WebFetchResponse {
        status,
        headers: response_headers,
        body,
        truncated,
    }))
}

/// Glob pattern search within the sandbox.
#[allow(deprecated)] // Migration to decide_term tracked in #1194
async fn glob_search(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::GlobSearch;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    validation::validate_pattern(&req.pattern).map_err(ApiError::Validation)?;
    if let Some(ref dir) = req.directory {
        validation::validate_path(dir).map_err(ApiError::Validation)?;
    }

    // Kernel mediation
    {
        let mut kernel = state.kernel.lock().await;
        let (decision, _decision_token) = kernel.decide(operation, &req.pattern);
        match decision.verdict {
            Verdict::Allow => {}
            Verdict::Deny(_) => {
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
            Verdict::RequiresApproval => {
                info!(
                    ?operation,
                    subject = %req.pattern,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval"
                );
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
        }
    }

    // Check glob_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.glob_search;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.pattern.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "glob_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval
    if policy.requires_approval(Operation::GlobSearch) {
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("glob {}", req.pattern));
        if !policy_allows && !state.approvals.consume("glob_search") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: req.pattern.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
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

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: req.pattern,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(GlobResponse {
        matches,
        truncated: if truncated { Some(true) } else { None },
    }))
}

/// Grep (regex content search) within the sandbox.
#[allow(deprecated)] // Migration to decide_term tracked in #1194
async fn grep_search(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, ApiError> {
    use regex::RegexBuilder;
    use std::io::{BufRead, BufReader};
    use walkdir::WalkDir;

    let sink = &state.verdict_sink;
    let operation = Operation::GrepSearch;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    validation::validate_pattern(&req.pattern).map_err(ApiError::Validation)?;
    if let Some(ref path) = req.path {
        validation::validate_path(path).map_err(ApiError::Validation)?;
    }
    if let Some(ref glob_pattern) = req.file_glob {
        validation::validate_pattern(glob_pattern).map_err(ApiError::Validation)?;
    }

    // Kernel mediation
    {
        let mut kernel = state.kernel.lock().await;
        let (decision, _decision_token) = kernel.decide(operation, &req.pattern);
        match decision.verdict {
            Verdict::Allow => {}
            Verdict::Deny(_) => {
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
            Verdict::RequiresApproval => {
                info!(
                    ?operation,
                    subject = %req.pattern,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval"
                );
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
        }
    }

    // Check grep_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.grep_search;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.pattern.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "grep_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval
    if policy.requires_approval(Operation::GrepSearch) {
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("grep {}", req.pattern));
        if !policy_allows && !state.approvals.consume("grep_search") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: req.pattern.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
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

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: req.pattern,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(GrepResponse {
        matches,
        truncated: if truncated { Some(true) } else { None },
    }))
}

/// Web search using configured backend.
#[allow(deprecated)] // Migration to decide_term tracked in #1194
async fn web_search(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WebSearchRequest>,
) -> Result<Json<WebSearchResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::WebSearch;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    validation::validate_query(&req.query).map_err(ApiError::Validation)?;

    // Kernel mediation
    {
        let mut kernel = state.kernel.lock().await;
        let (decision, _decision_token) = kernel.decide(operation, &req.query);
        match decision.verdict {
            Verdict::Allow => {}
            Verdict::Deny(_) => {
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
            Verdict::RequiresApproval => {
                info!(
                    ?operation,
                    subject = %req.query,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval"
                );
                return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
                    capability: format!("{operation:?}"),
                    actual: CapabilityLevel::Never,
                    required: CapabilityLevel::LowRisk,
                }));
            }
        }
    }

    // Check web_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.web_search;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.query.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "web_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval
    if policy.requires_approval(Operation::WebSearch) {
        let policy_allows = check_identity_policy(
            &state,
            auth_ctx.as_ref(),
            &format!("web_search {}", req.query),
        );
        if !policy_allows && !state.approvals.consume("web_search") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: req.query.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
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

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: req.query,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(WebSearchResponse { results }))
}

async fn approve_operation(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    let sink = &state.verdict_sink;

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
    if let Err(e) = sink.record(VerdictContext {
        operation: Operation::ManagePods, // meta-operation: approval grant
        subject: req.operation,
        outcome: VerdictOutcome::Allow,
        actor: ActorIdentity::Unknown,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
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
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<EscalateRequest>,
) -> Result<Json<EscalateResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::ManagePods; // meta-operation: escalation
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

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
            portcullis::escalation::ChainVerificationResult::Invalid { reason, .. } => reason,
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

    let escalation_subject = format!(
        "escalation:{} -> {} (ttl={}s)",
        requestor_chain.current_spiffe_id().unwrap_or("unknown"),
        req.requested_preset,
        req.ttl_seconds
    );

    match policy_result {
        Ok(_policy) => {
            // Create the grant
            match EscalationGrant::new(&escalation_request, approver_chain, drand_round) {
                Ok(grant) => {
                    if let Err(e) = sink.record(VerdictContext {
                        operation,
                        subject: escalation_subject,
                        outcome: VerdictOutcome::Allow,
                        actor,
                        policy_rule: None,
                        extensions: BTreeMap::new(),
                    }) {
                        warn!(error = %e, "verdict recording failed -- audit gap");
                    }

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

                    if let Err(e) = sink.record(VerdictContext {
                        operation,
                        subject: escalation_subject,
                        outcome: VerdictOutcome::Deny {
                            reason: error_msg.clone(),
                        },
                        actor,
                        policy_rule: None,
                        extensions: BTreeMap::new(),
                    }) {
                        warn!(error = %e, "verdict recording failed -- audit gap");
                    }

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

            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: escalation_subject,
                outcome: VerdictOutcome::Deny {
                    reason: error_msg.clone(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }

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

// Pod management handlers live in pod_mgmt.rs

async fn build_audit_log(args: &Args, auth: &AuthConfig) -> Result<Arc<AuditLog>, ApiError> {
    use nucleus_client::drand::{DrandClient, DrandConfig, DrandFailMode};

    let path = args.audit_log.clone();

    // Ensure parent directory exists (e.g., /var/log/nucleus/ or the pod state dir).
    // Without this, the first write silently fails when the parent is missing.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ApiError::Spec(format!(
                    "failed to create audit log directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }

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

    // Set up S3 sink for deletion-resistant audit storage
    #[cfg(feature = "remote-audit")]
    let s3_sink = if let Some(bucket) = args.audit_s3_bucket.as_ref() {
        let region = args.audit_s3_region.as_deref().unwrap_or("us-east-1");
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(endpoint) = args.audit_s3_endpoint.as_ref() {
            config_loader = config_loader.endpoint_url(endpoint);
        }
        let sdk_config = config_loader.load().await;
        let s3_client = aws_sdk_s3::Client::new(&sdk_config);
        let prefix = args
            .audit_s3_prefix
            .clone()
            .unwrap_or_else(|| "audit".to_string());
        info!(
            "S3 audit sink configured: bucket={}, prefix={}",
            bucket, prefix
        );
        Some(Arc::new(S3Sink {
            client: s3_client,
            bucket: bucket.clone(),
            prefix,
        }))
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
        #[cfg(feature = "remote-audit")]
        s3_sink,
    }))
}

/// Parse and verify a lockdown signal file. Returns the desired lockdown state.
///
/// FAIL-CLOSED: on any verification failure (bad HMAC, malformed JSON, missing
/// fields), returns `current_state` to preserve the existing lockdown. Only a
/// verified, well-formed signal can change the state. This prevents an attacker
/// from unlocking the system by corrupting or forging the signal file.
fn parse_and_verify_lockdown_signal(content: &str, current_state: bool) -> bool {
    let envelope: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!("Lockdown signal file has invalid JSON — preserving current state");
            return current_state;
        }
    };

    let signal = match envelope.get("signal") {
        Some(s) => s,
        None => {
            tracing::warn!(
                "Lockdown signal file missing 'signal' field — preserving current state"
            );
            return current_state;
        }
    };

    let claimed_hmac = envelope.get("hmac").and_then(|h| h.as_str()).unwrap_or("");

    let body = serde_json::to_string_pretty(signal).unwrap_or_default();

    // HMAC key: hostname:username. This is a tamper-detection mechanism against
    // casual local attacks, not a cryptographic secret. For production fleet
    // lockdown, use the gRPC streaming path with proper HMAC auth.
    let key_material = format!(
        "nucleus-lockdown-{}:{}",
        whoami::hostname().unwrap_or_else(|_| "unknown".to_string()),
        whoami::username().unwrap_or_else(|_| "unknown".to_string()),
    );

    use hmac::{digest::KeyInit, Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key_material.as_bytes()).expect("hmac");
    mac.update(body.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    if expected != claimed_hmac {
        tracing::warn!(
            "Lockdown signal HMAC mismatch — preserving current state (possible tampering)"
        );
        return current_state; // fail-closed: preserve current state
    }

    // Verified signal — extract desired state
    signal
        .get("restore")
        .and_then(|r| r.as_bool())
        .map(|restore| !restore)
        .unwrap_or(true) // signal without "restore" field = lockdown active
}

async fn emit_boot_report(state: &AppState) -> Result<(), ApiError> {
    // Always emit boot report — this is the first entry in the audit chain.
    // Optional env var adds a custom message; otherwise use a default.
    let message = std::env::var("NUCLEUS_TOOL_PROXY_BOOT_REPORT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "tool-proxy started".to_string());
    let actor = std::env::var("NUCLEUS_TOOL_PROXY_BOOT_ACTOR").ok();
    let report = format!(
        "{} [sandbox_proof={}]",
        message,
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
    /// Optional S3-compatible sink for deletion-resistant audit storage.
    #[cfg(feature = "remote-audit")]
    s3_sink: Option<Arc<S3Sink>>,
}

struct WebhookSink {
    url: String,
    client: reqwest::Client,
}

/// S3-compatible append-only audit sink.
///
/// Each audit entry is stored as a separate S3 object. The `if_none_match("*")`
/// precondition prevents overwriting existing entries. Combined with a bucket
/// policy that denies `s3:DeleteObject`, this provides a deletion-resistant
/// audit trail that a compromised pod cannot erase.
#[cfg(feature = "remote-audit")]
struct S3Sink {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

#[cfg(feature = "remote-audit")]
impl S3Sink {
    /// Put a single audit line as an S3 object.
    ///
    /// Key format: `{prefix}/{timestamp_unix}-{hash_prefix}.jsonl`
    /// Uses `if_none_match("*")` for append-only semantics: S3 returns 412
    /// if an object with this key already exists.
    async fn put_entry(&self, timestamp_unix: u64, hash: &str, line: &str) {
        let hash_prefix = if hash.len() >= 8 { &hash[..8] } else { hash };
        let key = format!("{}/{}-{}.jsonl", self.prefix, timestamp_unix, hash_prefix);

        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(line.as_bytes().to_vec().into())
            .content_type("application/jsonl")
            .if_none_match("*")
            .send()
            .await;

        if let Err(e) = result {
            tracing::warn!("failed to write audit entry to S3 (key={key}): {e}");
        }
    }
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

        // Send to S3 if configured (fire-and-forget, like webhook)
        #[cfg(feature = "remote-audit")]
        if let Some(s3) = &self.s3_sink {
            let s3 = Arc::clone(s3);
            let body = line.clone();
            let ts = entry.timestamp_unix;
            let h = entry.hash.clone();
            tokio::spawn(async move {
                s3.put_entry(ts, &h, &body).await;
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
#[path = "tests_main.rs"]
mod tests;
