use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use clap::Parser;
use nucleus::{
    ApprovalRequest, BudgetModel, CallbackApprover, NucleusError, PodRuntime,
    PodSpec as RuntimePodSpec,
};
use nucleus_spec::{BudgetModelSpec, PodSpec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::info;

mod auth;
use auth::{AuthConfig, AuthError};

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
    auth_secret: Option<String>,
    /// Maximum allowed clock skew (seconds) for signed requests.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_AUTH_MAX_SKEW_SECS",
        default_value_t = 60
    )]
    auth_max_skew_secs: u64,
    /// Optional audit log path.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_LOG")]
    audit_log: Option<PathBuf>,
    /// Optional audit log signing secret (defaults to auth secret if omitted).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_SECRET")]
    audit_secret: Option<String>,
    /// Optional approval authority secret (separate from tool auth).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET")]
    approval_secret: Option<String>,
}

#[derive(Clone)]
struct AppState {
    runtime: Arc<PodRuntime>,
    approvals: Arc<ApprovalRegistry>,
    audit: Option<Arc<AuditLog>>,
    auth: Option<AuthConfig>,
    approval_auth: Option<AuthConfig>,
    approval_nonces: Arc<ApprovalNonceCache>,
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

    let auth = args.auth_secret.as_ref().map(|secret| {
        AuthConfig::new(
            secret.as_bytes(),
            Duration::from_secs(args.auth_max_skew_secs),
        )
    });
    let approval_auth = args.approval_secret.as_ref().map(|secret| {
        AuthConfig::new(
            secret.as_bytes(),
            Duration::from_secs(args.auth_max_skew_secs),
        )
    });

    if auth.is_none() {
        info!("nucleus-tool-proxy auth disabled (set NUCLEUS_TOOL_PROXY_AUTH_SECRET to enable)");
    }

    let audit = build_audit_log(&args, auth.as_ref())?;

    let state = AppState {
        runtime: Arc::new(runtime),
        approvals,
        audit,
        auth,
        approval_auth,
        approval_nonces: Arc::new(ApprovalNonceCache::default()),
    };

    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/read", post(read_file))
        .route("/v1/write", post(write_file))
        .route("/v1/run", post(run_command))
        .route("/v1/approve", post(approve_operation))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_middleware));

    if let Some(vsock) = resolve_vsock(&args, &spec)? {
        serve_vsock(app, vsock, args.announce_path).await?;
        return Ok(());
    }

    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;

    if let Some(path) = args.announce_path {
        tokio::fs::write(path, addr.to_string()).await?;
    }

    info!("nucleus-tool-proxy listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

const MAX_AUTH_BODY_BYTES: usize = 10 * 1024 * 1024;
const APPROVE_PATH: &str = "/v1/approve";

async fn auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_AUTH_BODY_BYTES)
        .await
        .map_err(|e| ApiError::Body(e.to_string()))?;

    if parts.uri.path() == APPROVE_PATH {
        if let Some(approval_auth) = state.approval_auth.as_ref() {
            let context = auth::verify_http(&parts.headers, &bytes, approval_auth)?;
            let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
            req.extensions_mut().insert(context);
            return Ok(next.run(req).await);
        }
    }

    if let Some(auth) = state.auth.as_ref() {
        let context = auth::verify_http(&parts.headers, &bytes, auth)?;
        let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
        req.extensions_mut().insert(context);
        Ok(next.run(req).await)
    } else {
        Ok(next
            .run(axum::http::Request::from_parts(parts, Body::from(bytes)))
            .await)
    }
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

async fn approve_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    let now = now_unix();
    let expires_at =
        resolve_approval_expiry(state.approval_auth.as_ref(), req.expires_at_unix, now)?;
    if state.approval_auth.is_some() {
        let nonce = req
            .nonce
            .as_deref()
            .ok_or_else(|| ApiError::Spec("approval nonce required".to_string()))?;
        let expiry = expires_at.unwrap_or(now + MAX_APPROVAL_TTL_SECS);
        if !state.approval_nonces.check_and_insert(nonce, expiry, now) {
            return Err(ApiError::Spec("approval nonce replayed".to_string()));
        }
    }
    state
        .approvals
        .approve(&req.operation, req.count, expires_at);
    audit_event(&state, &headers, "approve", &req.operation, "ok").await?;
    Ok(Json(ApproveResponse { ok: true }))
}

fn resolve_approval_expiry(
    approval_auth: Option<&AuthConfig>,
    expires_at_unix: Option<u64>,
    now: u64,
) -> Result<Option<u64>, ApiError> {
    let require_expiry = approval_auth.is_some();
    if require_expiry {
        let requested = expires_at_unix.unwrap_or(now + MAX_APPROVAL_TTL_SECS);
        if requested < now {
            return Err(ApiError::Spec("approval expiry is in the past".to_string()));
        }
        let max_allowed = now + MAX_APPROVAL_TTL_SECS;
        return Ok(Some(requested.min(max_allowed)));
    }
    Ok(expires_at_unix)
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

fn build_audit_log(
    args: &Args,
    auth: Option<&AuthConfig>,
) -> Result<Option<Arc<AuditLog>>, ApiError> {
    let path = match args.audit_log.as_ref() {
        Some(path) => path.clone(),
        None => return Ok(None),
    };

    let secret = if let Some(secret) = args.audit_secret.as_ref() {
        secret.as_bytes().to_vec()
    } else if let Some(auth) = auth {
        auth.secret().to_vec()
    } else {
        return Err(ApiError::Spec(
            "audit log requires audit secret or auth secret".to_string(),
        ));
    };

    let last_hash = load_last_hash(&path).unwrap_or_default();
    Ok(Some(Arc::new(AuditLog {
        path,
        secret,
        last_hash: Mutex::new(last_hash),
    })))
}

async fn audit_event(
    state: &AppState,
    headers: &HeaderMap,
    event: &str,
    subject: &str,
    result: &str,
) -> Result<(), ApiError> {
    if let Some(ref audit) = state.audit {
        let actor = headers
            .get("x-nucleus-actor")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        audit
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
    }
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
}

impl AuditLog {
    async fn log(&self, mut entry: AuditEntry) -> Result<(), ApiError> {
        let actor = entry.actor.clone().unwrap_or_default();
        let mut last_hash = self.last_hash.lock().unwrap();
        let prev_hash = last_hash.clone();
        let message = format!(
            "{}|{}|{}|{}|{}|{}",
            entry.timestamp_unix, actor, entry.event, entry.subject, entry.result, prev_hash
        );
        entry.prev_hash = prev_hash;
        entry.signature = auth::sign_message(&self.secret, message.as_bytes());
        entry.hash = sha256_hex(&format!("{}|{}", message, entry.signature));
        *last_hash = entry.hash.clone();

        let line = serde_json::to_string(&entry).map_err(|e| ApiError::Spec(e.to_string()))?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
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
