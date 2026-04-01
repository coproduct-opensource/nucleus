use anyhow::{anyhow, Context, Result};
use clap::Parser;
use nucleus_client::sign_http_headers;
use nucleus_spec::PodSpec;
use portcullis::kernel::{Decision, DenyReason, Kernel, Verdict};
use portcullis::{CapabilityLevel, Operation, PermissionLattice};
use portcullis_core::flow::NodeKind;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "nucleus-mcp")]
#[command(about = "MCP server that bridges Claude Code to nucleus-tool-proxy")]
struct Args {
    /// Tool proxy base URL (ex: http://127.0.0.1:12345).
    #[arg(long, env = "NUCLEUS_MCP_PROXY_URL")]
    proxy_url: String,
    /// Optional auth secret for signing tool-proxy requests.
    #[arg(long, env = "NUCLEUS_MCP_AUTH_SECRET")]
    auth_secret: Option<String>,
    /// Actor identifier used in HMAC signatures.
    #[arg(long, env = "NUCLEUS_MCP_ACTOR", default_value = "nucleus-mcp")]
    actor: String,
    /// Optional pod spec for filtering visible tools.
    #[arg(long, env = "NUCLEUS_MCP_SPEC")]
    spec: Option<PathBuf>,
    /// Separate auth secret for the /v1/approve endpoint.
    /// The tool proxy authenticates approval requests with a different secret
    /// than regular tool calls, enforcing privilege separation.
    #[arg(long, env = "NUCLEUS_MCP_APPROVAL_SECRET")]
    approval_secret: Option<String>,
    /// Prompt on approval-required operations (uses /dev/tty).
    #[arg(long, default_value_t = true)]
    approval_prompt: bool,
    /// Session ID for audit correlation (UUID v7 format). Auto-generated if not provided.
    /// All tool calls within this MCP session will include this ID for tracing.
    #[arg(long, env = "NUCLEUS_MCP_SESSION_ID")]
    session_id: Option<String>,
    /// Path to write kernel decision trace in JSONL format.
    /// Each line is a JSON-serialized `Decision` from the portcullis kernel.
    /// A summary line is written on session close.
    #[arg(long, env = "NUCLEUS_MCP_KERNEL_TRACE")]
    kernel_trace: Option<PathBuf>,
    /// Sandbox token for authenticating with the tool proxy.
    /// Proves this MCP bridge is running inside a managed sandbox.
    #[arg(long, env = "NUCLEUS_MCP_SANDBOX_TOKEN")]
    sandbox_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Serialize)]
struct ToolDefinition {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReadRequest {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ReadResponse {
    contents: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct WriteRequest {
    path: String,
    contents: String,
}

#[derive(Debug, Deserialize)]
struct WriteResponse {
    ok: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct RunRequest {
    command: String,
}

#[derive(Debug, Deserialize)]
struct RunResponse {
    status: i32,
    success: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct WebFetchRequest {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebFetchResponse {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: String,
    #[serde(default)]
    truncated: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
struct GlobRequest {
    pattern: String,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    max_results: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct GlobResponse {
    matches: Vec<String>,
    #[serde(default)]
    truncated: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
struct GrepRequest {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default, rename = "glob")]
    file_glob: Option<String>,
    #[serde(default)]
    context_lines: Option<usize>,
    #[serde(default)]
    max_matches: Option<usize>,
    #[serde(default)]
    case_insensitive: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GrepMatch {
    file: String,
    line: usize,
    content: String,
    #[serde(default)]
    context_before: Option<Vec<String>>,
    #[serde(default)]
    context_after: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct GrepResponse {
    matches: Vec<GrepMatch>,
    #[serde(default)]
    truncated: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
struct WebSearchRequest {
    query: String,
    #[serde(default)]
    max_results: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct WebSearchResult {
    title: String,
    url: String,
    #[serde(default)]
    snippet: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebSearchResponse {
    results: Vec<WebSearchResult>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct ApproveResponse {
    ok: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreatePodRequest {
    spec_yaml: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct CreatePodResponseBody {
    pod_id: String,
    #[serde(default)]
    proxy_addr: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PodIdRequest {
    pod_id: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PodInfoResponse {
    id: String,
    #[serde(default)]
    name: Option<String>,
    state: String,
    #[serde(default)]
    proxy_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PodLogsResponse {
    logs: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CancelPodResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: String,
    kind: String,
    #[serde(default)]
    operation: Option<String>,
}

#[derive(Debug)]
struct ProxyError {
    kind: String,
    message: String,
    operation: Option<String>,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ProxyError {}

struct ProxyClient {
    base_url: String,
    auth_secret: Option<Vec<u8>>,
    /// Separate secret for /v1/approve requests (privilege separation).
    approval_secret: Option<Vec<u8>>,
    actor: Option<String>,
    /// Session ID for audit correlation across tool calls.
    session_id: String,
}

impl ProxyClient {
    fn new(
        base_url: String,
        auth_secret: Option<String>,
        approval_secret: Option<String>,
        actor: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        // Use provided session ID or generate UUID v7 for time-ordering
        let session_id = session_id.unwrap_or_else(|| {
            // Generate UUID v7 (time-ordered) for session correlation
            // Falls back to v4 if v7 generation fails
            generate_session_id()
        });
        Self {
            base_url,
            auth_secret: auth_secret.map(|s| s.into_bytes()),
            approval_secret: approval_secret.map(|s| s.into_bytes()),
            actor,
            session_id,
        }
    }

    /// Returns the session ID for this client.
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ProxyError> {
        self.post_json_with_secret(path, body, self.auth_secret.as_ref())
    }

    /// POST to /v1/approve using the approval secret (privilege separation).
    /// Falls back to auth_secret if no approval_secret is configured.
    fn post_approve<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ProxyError> {
        let secret = self.approval_secret.as_ref().or(self.auth_secret.as_ref());
        self.post_json_with_secret(path, body, secret)
    }

    fn post_json_with_secret<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
        secret: Option<&Vec<u8>>,
    ) -> Result<R, ProxyError> {
        let body_bytes = serde_json::to_vec(body).map_err(|e| ProxyError {
            kind: "client_error".to_string(),
            message: e.to_string(),
            operation: None,
        })?;
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut request = ureq::post(&url)
            .header("content-type", "application/json")
            // Always include session ID for audit correlation
            .header("x-nucleus-session-id", &self.session_id);

        if let Some(secret) = secret {
            let signed = sign_http_headers(secret, self.actor.as_deref(), &body_bytes);
            for (key, value) in signed.headers {
                request = request.header(&key, &value);
            }
        }

        match request.send(&body_bytes) {
            Ok(mut response) => {
                if response.status().as_u16() >= 400 {
                    // Try to parse error body
                    match response.body_mut().read_json::<ErrorBody>() {
                        Ok(body) => Err(ProxyError {
                            kind: body.kind,
                            message: body.error,
                            operation: body.operation,
                        }),
                        Err(err) => Err(ProxyError {
                            kind: "http_error".to_string(),
                            message: format!("status {}: {}", response.status(), err),
                            operation: None,
                        }),
                    }
                } else {
                    response
                        .body_mut()
                        .read_json::<R>()
                        .map_err(|e| ProxyError {
                            kind: "decode_error".to_string(),
                            message: e.to_string(),
                            operation: None,
                        })
                }
            }
            Err(err) => Err(ProxyError {
                kind: "http_error".to_string(),
                message: err.to_string(),
                operation: None,
            }),
        }
    }
}

/// Generates a session ID using UUID v7 format for time-ordering.
///
/// UUID v7 embeds a Unix timestamp in the first 48 bits, enabling:
/// - Natural chronological sorting of sessions
/// - Rough timestamp extraction from the ID
/// - Global uniqueness without coordination
fn generate_session_id() -> String {
    // UUID v7 implementation: timestamp_ms (48 bits) + version (4 bits) + random (12 bits) + variant (2 bits) + random (62 bits)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let timestamp_ms = now.as_millis() as u64;

    // Build UUID v7 bytes
    let mut bytes = [0u8; 16];

    // First 6 bytes: timestamp in milliseconds (big-endian)
    bytes[0] = (timestamp_ms >> 40) as u8;
    bytes[1] = (timestamp_ms >> 32) as u8;
    bytes[2] = (timestamp_ms >> 24) as u8;
    bytes[3] = (timestamp_ms >> 16) as u8;
    bytes[4] = (timestamp_ms >> 8) as u8;
    bytes[5] = timestamp_ms as u8;

    // Random bytes for uniqueness
    let random = Uuid::new_v4();
    let random_bytes = random.as_bytes();

    // Bytes 6-7: version (7) + random
    bytes[6] = 0x70 | (random_bytes[6] & 0x0f); // version 7
    bytes[7] = random_bytes[7];

    // Bytes 8-15: variant (RFC 4122) + random
    bytes[8] = 0x80 | (random_bytes[8] & 0x3f); // variant bits
    bytes[9..16].copy_from_slice(&random_bytes[9..16]);

    Uuid::from_bytes(bytes).to_string()
}

/// Map MCP tool names to portcullis `Operation` variants for exposure classification.
///
/// Returns `None` for tools that don't map to exposure-relevant operations
/// (e.g., pod management, which is classified as ManagePods but has no exposure
/// contribution in the current exposure_core model).
/// Map an Operation to the NodeKind for flow graph observations.
fn operation_to_node_kind(op: Operation) -> NodeKind {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => NodeKind::FileRead,
        Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
        _ => NodeKind::OutboundAction,
    }
}

fn tool_to_operation(tool_name: &str) -> Option<Operation> {
    match tool_name {
        "read" => Some(Operation::ReadFiles),
        "write" => Some(Operation::WriteFiles),
        "run" => Some(Operation::RunBash),
        "web_fetch" => Some(Operation::WebFetch),
        "glob" => Some(Operation::GlobSearch),
        "grep" => Some(Operation::GrepSearch),
        "web_search" => Some(Operation::WebSearch),
        "create_pod" | "list_pods" | "pod_status" | "pod_logs" | "cancel_pod" => {
            Some(Operation::ManagePods)
        }
        _ => None,
    }
}

/// Session-scoped exposure accumulator.
///
/// Tracks the monotone exposure state across tool calls within a single MCP session.
/// Exposure can only increase (union) — it never decreases. When all three exposure
/// Extract the subject string from a tool call's arguments.
///
/// The subject is the primary target of the operation — a file path, URL,
/// command, query, etc. The Kernel uses this for path-based access control,
/// command restrictions, and audit trace recording.
fn extract_subject(tool_name: &str, arguments: &Value) -> String {
    match tool_name {
        "read" | "write" => arguments
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "run" => arguments
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "web_fetch" => arguments
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "glob" => arguments
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "grep" => arguments
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "web_search" => arguments
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => tool_name.to_string(),
    }
}

/// Format a DenyReason for human-readable error messages.
fn format_deny_reason(reason: &DenyReason) -> String {
    match reason {
        DenyReason::InsufficientCapability => "insufficient capability".to_string(),
        DenyReason::BudgetExhausted { remaining_usd } => {
            format!("budget exhausted (remaining: ${remaining_usd})")
        }
        DenyReason::TimeExpired { expired_at } => format!("session expired at {expired_at}"),
        DenyReason::PathBlocked { path } => format!("path blocked: {path}"),
        DenyReason::CommandBlocked { command } => format!("command blocked: {command}"),
        DenyReason::IsolationInsufficient { required, actual } => {
            format!("isolation insufficient: required {required}, got {actual}")
        }
        DenyReason::IsolationGated { dimension } => {
            format!("isolation gated: {dimension}")
        }
        DenyReason::FlowViolation { rule, .. } => {
            format!("flow violation: {rule}")
        }
        DenyReason::EgressBlocked {
            host,
            policy_reason,
        } => {
            format!("egress blocked: {host} — {policy_reason}")
        }
        DenyReason::PolicyDenied {
            rule_name,
            sink_class,
        } => {
            format!("policy denied: rule '{rule_name}' blocked sink {sink_class}")
        }
        DenyReason::EnterpriseBlocked { sink_class, detail } => {
            format!("enterprise blocked: {detail} (sink: {sink_class})")
        }
    }
}

/// Per-operation cost estimates for budget tracking.
///
/// These are policy-level costs representing the relative expense and risk
/// of each operation class. They are NOT LLM API costs (which are tracked
/// by the orchestrator). Costs are calibrated so that a $1.00 budget allows
/// roughly 100 file reads, 50 writes, 20 shell commands, or 10 web fetches.
fn operation_cost(op: Operation) -> Decimal {
    match op {
        // Read-only operations: low cost
        Operation::ReadFiles => Decimal::new(1, 2), // $0.01
        Operation::GlobSearch => Decimal::new(1, 2), // $0.01
        Operation::GrepSearch => Decimal::new(1, 2), // $0.01
        // Write operations: moderate cost
        Operation::WriteFiles => Decimal::new(2, 2), // $0.02
        Operation::EditFiles => Decimal::new(2, 2),  // $0.02
        // Execution: higher cost (side effects)
        Operation::RunBash => Decimal::new(5, 2), // $0.05
        // Network: higher cost (external interaction)
        Operation::WebSearch => Decimal::new(5, 2), // $0.05
        Operation::WebFetch => Decimal::new(10, 2), // $0.10
        // Git operations: moderate cost
        Operation::GitCommit => Decimal::new(2, 2), // $0.02
        // Publish operations: high cost (irreversible)
        Operation::GitPush => Decimal::new(25, 2), // $0.25
        Operation::CreatePr => Decimal::new(25, 2), // $0.25
        // Pod management: high cost
        Operation::ManagePods => Decimal::new(50, 2), // $0.50
        Operation::SpawnAgent => Decimal::new(50, 2), // $0.50
    }
}

/// Appends kernel decisions to a JSONL file for post-hoc audit.
///
/// Each line is a JSON-serialized [`Decision`]. When the session ends,
/// [`TraceWriter::finish`] writes a summary object with session statistics.
struct TraceWriter {
    file: Option<std::cell::RefCell<io::BufWriter<fs::File>>>,
}

impl TraceWriter {
    /// Open a trace file for writing. Returns a no-op writer if `path` is `None`.
    fn open(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                let file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .with_context(|| {
                        format!("failed to open kernel trace file: {}", p.display())
                    })?;
                Ok(Self {
                    file: Some(std::cell::RefCell::new(io::BufWriter::new(file))),
                })
            }
            None => Ok(Self { file: None }),
        }
    }

    /// Write a single decision as a JSONL line.
    fn record(&self, decision: &Decision) {
        if let Some(ref f) = self.file {
            if let Ok(line) = serde_json::to_string(decision) {
                let mut writer = f.borrow_mut();
                let _ = writeln!(writer, "{line}");
                let _ = writer.flush();
            }
        }
    }

    /// Write a summary line and flush on session end.
    fn finish(&self, kernel: &Kernel) {
        if let Some(ref f) = self.file {
            let summary = json!({
                "type": "session_summary",
                "session_id": kernel.session_id().to_string(),
                "decisions": kernel.decision_count(),
                "consumed_usd": kernel.consumed_usd().to_string(),
                "remaining_usd": kernel.remaining_usd().to_string(),
                "initial_hash": kernel.initial_hash(),
            });
            if let Ok(line) = serde_json::to_string(&summary) {
                let mut writer = f.borrow_mut();
                let _ = writeln!(writer, "{line}");
                let _ = writer.flush();
            }
        }
    }
}

fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS connections (via ureq).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let policy = match args.spec.as_ref() {
        Some(path) => Some(load_policy(path)?),
        None => None,
    };
    let tools = build_tool_defs(policy.as_ref());
    let client = ProxyClient::new(
        args.proxy_url.clone(),
        args.auth_secret.clone(),
        args.approval_secret.clone(),
        Some(args.actor.clone()),
        args.session_id.clone(),
    );
    // Initialize the kernel decision engine.
    // If a policy is loaded (--spec), the kernel enforces it with monotone session
    // state. Otherwise, use a permissive lattice (proxy handles enforcement).
    let kernel_lattice = policy.clone().unwrap_or_else(PermissionLattice::permissive);
    let mut kernel = Kernel::new(kernel_lattice);
    kernel.enable_flow_graph();

    // Track the last flow graph node ID for causal chaining.
    // Each allowed operation produces an observation node; the next operation's
    // parents are the prior observations, giving session-level flow tracking.
    let mut last_flow_node: Option<u64> = None;

    // Open kernel trace file (JSONL) if --kernel-trace is specified.
    let trace = TraceWriter::open(args.kernel_trace.as_deref())?;
    if let Some(ref trace_path) = args.kernel_trace {
        eprintln!("[nucleus-mcp] kernel trace: {}", trace_path.display());
    }

    // Log session ID to stderr for debugging/correlation
    eprintln!(
        "[nucleus-mcp] session_id={} actor={}",
        client.session_id(),
        args.actor
    );

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(err) => {
                write_error(&mut stdout, None, -32700, &err.to_string())?;
                continue;
            }
        };

        let method = value.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let id = value.get("id").cloned();
        let params = value.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "initialize" => {
                let protocol = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2025-11-25");
                let result = json!({
                    "protocolVersion": protocol,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "nucleus-mcp", "version": env!("CARGO_PKG_VERSION") }
                });
                write_result(&mut stdout, id, result)?;
            }
            "notifications/initialized" => {
                // No response for notifications.
            }
            "tools/list" => {
                let result = json!({ "tools": tools });
                write_result(&mut stdout, id, result)?;
            }
            "tools/call" => {
                let call: ToolCallParams = match serde_json::from_value(params) {
                    Ok(call) => call,
                    Err(err) => {
                        write_error(&mut stdout, id, -32602, &err.to_string())?;
                        continue;
                    }
                };
                let result = match call_tool(
                    &client,
                    &call,
                    args.approval_prompt,
                    &mut kernel,
                    &trace,
                    &mut last_flow_node,
                ) {
                    Ok(text) => json!({
                        "content": [{ "type": "text", "text": text }],
                        "isError": false
                    }),
                    Err(err) => json!({
                        "content": [{ "type": "text", "text": err.to_string() }],
                        "isError": true
                    }),
                };
                write_result(&mut stdout, id, result)?;
            }
            "ping" => {
                write_result(&mut stdout, id, json!({}))?;
            }
            _ => {
                if id.is_some() {
                    write_error(&mut stdout, id, -32601, "method not found")?;
                }
            }
        }
    }

    // Write session summary to trace file on clean exit.
    trace.finish(&kernel);

    Ok(())
}

fn load_policy(path: &Path) -> Result<PermissionLattice> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read pod spec from {}", path.display()))?;
    let spec: PodSpec = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse pod spec {}", path.display()))?;
    let policy = spec
        .spec
        .resolve_policy()
        .map_err(|e| anyhow!("policy resolve failed: {e}"))?;
    Ok(policy)
}

fn build_tool_defs(policy: Option<&PermissionLattice>) -> Vec<ToolDefinition> {
    let mut tools = Vec::new();
    let allow_read = policy
        .map(|p| p.capabilities.read_files >= CapabilityLevel::LowRisk)
        .unwrap_or(true);
    let allow_write = policy
        .map(|p| {
            p.capabilities.write_files >= CapabilityLevel::LowRisk
                || p.capabilities.edit_files >= CapabilityLevel::LowRisk
        })
        .unwrap_or(true);
    let allow_run = policy
        .map(|p| {
            p.capabilities.run_bash >= CapabilityLevel::LowRisk
                || p.capabilities.git_commit >= CapabilityLevel::LowRisk
                || p.capabilities.git_push >= CapabilityLevel::LowRisk
                || p.capabilities.create_pr >= CapabilityLevel::LowRisk
        })
        .unwrap_or(true);
    let allow_web_fetch = policy
        .map(|p| p.capabilities.web_fetch >= CapabilityLevel::LowRisk)
        .unwrap_or(true);
    let allow_glob = policy
        .map(|p| p.capabilities.glob_search >= CapabilityLevel::LowRisk)
        .unwrap_or(true);
    let allow_grep = policy
        .map(|p| p.capabilities.grep_search >= CapabilityLevel::LowRisk)
        .unwrap_or(true);
    let allow_web_search = policy
        .map(|p| p.capabilities.web_search >= CapabilityLevel::LowRisk)
        .unwrap_or(false);
    let allow_manage_pods = policy
        .map(|p| p.capabilities.manage_pods >= CapabilityLevel::LowRisk)
        .unwrap_or(false);

    if allow_read {
        tools.push(ToolDefinition {
            name: "read".to_string(),
            description: "Read a file within the sandbox".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
        });
    }
    if allow_write {
        tools.push(ToolDefinition {
            name: "write".to_string(),
            description: "Write a file within the sandbox".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "contents": { "type": "string" }
                },
                "required": ["path", "contents"]
            }),
        });
    }
    if allow_run {
        tools.push(ToolDefinition {
            name: "run".to_string(),
            description: "Run a command within the sandbox".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "command": { "type": "string" } },
                "required": ["command"]
            }),
        });
    }
    if allow_web_fetch {
        tools.push(ToolDefinition {
            name: "web_fetch".to_string(),
            description: "Fetch a URL (respects dns_allow policy)".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL to fetch" },
                    "method": { "type": "string", "description": "HTTP method (default: GET)" },
                    "headers": { "type": "object", "description": "Optional request headers" },
                    "body": { "type": "string", "description": "Optional request body" }
                },
                "required": ["url"]
            }),
        });
    }

    if allow_glob {
        tools.push(ToolDefinition {
            name: "glob".to_string(),
            description: "Search for files matching a glob pattern within the sandbox".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Glob pattern (e.g. \"**/*.rs\", \"src/*.json\")" },
                    "directory": { "type": "string", "description": "Directory to search in (relative to sandbox root)" },
                    "max_results": { "type": "integer", "description": "Maximum number of results" }
                },
                "required": ["pattern"]
            }),
        });
    }
    if allow_grep {
        tools.push(ToolDefinition {
            name: "grep".to_string(),
            description: "Search file contents with regex within the sandbox".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Regex pattern to search for" },
                    "path": { "type": "string", "description": "File or directory to search in" },
                    "glob": { "type": "string", "description": "Glob pattern to filter files" },
                    "context_lines": { "type": "integer", "description": "Context lines before/after match" },
                    "max_matches": { "type": "integer", "description": "Maximum number of matches" },
                    "case_insensitive": { "type": "boolean", "description": "Case-insensitive search" }
                },
                "required": ["pattern"]
            }),
        });
    }
    if allow_web_search {
        tools.push(ToolDefinition {
            name: "web_search".to_string(),
            description: "Search the web for information".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query" },
                    "max_results": { "type": "integer", "description": "Maximum number of results" }
                },
                "required": ["query"]
            }),
        });
    }

    if allow_manage_pods {
        tools.push(ToolDefinition {
            name: "create_pod".to_string(),
            description: "Create a sub-pod from a PodSpec YAML definition. The sub-pod's permissions are bounded by the delegation ceiling.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "spec_yaml": { "type": "string", "description": "PodSpec YAML for the sub-pod" },
                    "reason": { "type": "string", "description": "Why this sub-pod is being created" }
                },
                "required": ["spec_yaml", "reason"]
            }),
        });
        tools.push(ToolDefinition {
            name: "list_pods".to_string(),
            description: "List all sub-pods managed by this orchestrator.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        });
        tools.push(ToolDefinition {
            name: "pod_status".to_string(),
            description: "Get the current status of a sub-pod.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pod_id": { "type": "string", "description": "UUID of the sub-pod" }
                },
                "required": ["pod_id"]
            }),
        });
        tools.push(ToolDefinition {
            name: "pod_logs".to_string(),
            description: "Get logs from a sub-pod.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pod_id": { "type": "string", "description": "UUID of the sub-pod" }
                },
                "required": ["pod_id"]
            }),
        });
        tools.push(ToolDefinition {
            name: "cancel_pod".to_string(),
            description: "Cancel a running sub-pod.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pod_id": { "type": "string", "description": "UUID of the sub-pod" },
                    "reason": { "type": "string", "description": "Why the pod is being cancelled" }
                },
                "required": ["pod_id", "reason"]
            }),
        });
    }

    tools
}

fn call_tool(
    client: &ProxyClient,
    call: &ToolCallParams,
    approval_prompt: bool,
    kernel: &mut Kernel,
    trace: &TraceWriter,
    last_flow_node: &mut Option<u64>,
) -> Result<String> {
    // Route every operation through the kernel decision engine.
    // The kernel provides: capability checks, monotone session state,
    // exposure tracking, budget tracking, time-based expiry, path/command
    // restrictions, flow control (IFC labels), and complete audit trace.
    if let Some(op) = tool_to_operation(&call.name) {
        let subject = extract_subject(&call.name, &call.arguments);
        // Use decide_with_parents for flow-aware decisions.
        // Each operation's parents are the prior observations in the session.
        let parents: Vec<u64> = (*last_flow_node).into_iter().collect();
        let (decision, _token) = kernel.decide_with_parents(op, &subject, &parents);
        trace.record(&decision);

        match &decision.verdict {
            Verdict::Allow => {
                // Observe the allowed operation in the flow graph for causal tracking.
                let obs_kind = operation_to_node_kind(op);
                let obs_parents: Vec<u64> = (*last_flow_node).into_iter().collect();
                if let Ok(node_id) = kernel.observe(obs_kind, &obs_parents) {
                    *last_flow_node = Some(node_id);
                }

                // Log exposure transitions
                let tt = &decision.exposure_transition;
                if tt.pre_count != tt.post_count {
                    eprintln!(
                        "[nucleus-mcp] exposure: {}/{} legs (tool={}, subject={})",
                        tt.post_count, 3, call.name, subject
                    );
                }
            }
            Verdict::RequiresApproval => {
                eprintln!(
                    "[nucleus-mcp] approval required: tool={} subject={}",
                    call.name, subject
                );
                // Prompt the human for approval before proceeding.
                if approval_prompt {
                    let msg = if decision.exposure_transition.dynamic_gate_applied {
                        format!(
                            "uninhabitable_state({}) — exposure gate requires approval",
                            call.name
                        )
                    } else {
                        format!("approval required for {}", call.name)
                    };
                    if !prompt_approval(&msg)? {
                        return Err(anyhow!(
                            "operation denied: {} requires approval but was rejected. \
                             Subject: {}",
                            call.name,
                            subject
                        ));
                    }
                    eprintln!("[nucleus-mcp] approved by human: tool={}", call.name);
                    // Grant a one-time approval and re-decide
                    kernel.grant_approval(op, 1);
                    let (retry, _token) = kernel.decide_with_parents(op, &subject, &parents);
                    trace.record(&retry);
                    if !matches!(retry.verdict, Verdict::Allow) {
                        return Err(anyhow!(
                            "operation denied after approval: {} — {:?}",
                            call.name,
                            retry.verdict
                        ));
                    }
                } else {
                    return Err(anyhow!(
                        "operation denied: {} requires approval but no prompt available. \
                         Subject: {}",
                        call.name,
                        subject
                    ));
                }
            }
            Verdict::Deny(reason) => {
                eprintln!(
                    "[nucleus-mcp] denied: tool={} reason={}",
                    call.name,
                    format_deny_reason(reason)
                );
                return Err(anyhow!(
                    "operation denied: {} — {}",
                    call.name,
                    format_deny_reason(reason)
                ));
            }
        }
    }

    // Execute the tool call (the proxy provides additional enforcement)
    let result = call_tool_inner(client, call, approval_prompt)?;

    // Charge budget after successful execution.
    // The cost is charged post-execution because:
    // 1. We only charge for operations that actually complete
    // 2. The NEXT kernel.decide() will see the updated budget and deny if exhausted
    if let Some(op) = tool_to_operation(&call.name) {
        let cost = operation_cost(op);
        match kernel.charge(cost) {
            Ok(remaining) => {
                eprintln!("[nucleus-mcp] budget: charged ${cost}, remaining ${remaining}");
            }
            Err(_) => {
                eprintln!(
                    "[nucleus-mcp] budget: exhausted after tool={} (charged ${cost})",
                    call.name
                );
            }
        }
    }

    Ok(result)
}

fn call_tool_inner(
    client: &ProxyClient,
    call: &ToolCallParams,
    approval_prompt: bool,
) -> Result<String> {
    match call.name.as_str() {
        "read" => {
            let req: ReadRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid read args: {e}"))?;
            let response: ReadResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/read", &req),
                || {
                    let req = ReadRequest {
                        path: req.path.clone(),
                    };
                    client.post_json("/v1/read", &req)
                },
            )?;
            Ok(response.contents)
        }
        "write" => {
            let req: WriteRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid write args: {e}"))?;
            let response: WriteResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/write", &req),
                || {
                    let req = WriteRequest {
                        path: req.path.clone(),
                        contents: req.contents.clone(),
                    };
                    client.post_json("/v1/write", &req)
                },
            )?;
            Ok(format!("write ok: {}", response.ok))
        }
        "run" => {
            let req: RunRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid run args: {e}"))?;
            let response: RunResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/run", &req),
                || {
                    let req = RunRequest {
                        command: req.command.clone(),
                    };
                    client.post_json("/v1/run", &req)
                },
            )?;
            Ok(format!(
                "status: {}\nsuccess: {}\nstdout:\n{}\nstderr:\n{}",
                response.status, response.success, response.stdout, response.stderr
            ))
        }
        "web_fetch" => {
            let req: WebFetchRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid web_fetch args: {e}"))?;
            let response: WebFetchResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/web_fetch", &req),
                || {
                    let req = WebFetchRequest {
                        url: req.url.clone(),
                        method: req.method.clone(),
                        headers: req.headers.clone(),
                        body: req.body.clone(),
                    };
                    client.post_json("/v1/web_fetch", &req)
                },
            )?;
            let truncated_note = if response.truncated == Some(true) {
                " (truncated)"
            } else {
                ""
            };
            Ok(format!(
                "status: {}{}\nheaders: {:?}\nbody:\n{}",
                response.status, truncated_note, response.headers, response.body
            ))
        }
        "glob" => {
            let req: GlobRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid glob args: {e}"))?;
            let response: GlobResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/glob", &req),
                || {
                    let req = GlobRequest {
                        pattern: req.pattern.clone(),
                        directory: req.directory.clone(),
                        max_results: req.max_results,
                    };
                    client.post_json("/v1/glob", &req)
                },
            )?;
            let truncated_note = if response.truncated == Some(true) {
                " (truncated)"
            } else {
                ""
            };
            Ok(format!(
                "{} matches{}\n{}",
                response.matches.len(),
                truncated_note,
                response.matches.join("\n")
            ))
        }
        "grep" => {
            let req: GrepRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid grep args: {e}"))?;
            let response: GrepResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/grep", &req),
                || {
                    let req = GrepRequest {
                        pattern: req.pattern.clone(),
                        path: req.path.clone(),
                        file_glob: req.file_glob.clone(),
                        context_lines: req.context_lines,
                        max_matches: req.max_matches,
                        case_insensitive: req.case_insensitive,
                    };
                    client.post_json("/v1/grep", &req)
                },
            )?;
            let truncated_note = if response.truncated == Some(true) {
                " (truncated)"
            } else {
                ""
            };
            let mut out = format!("{} matches{}\n", response.matches.len(), truncated_note);
            for m in &response.matches {
                out.push_str(&format!("{}:{}: {}\n", m.file, m.line, m.content));
            }
            Ok(out)
        }
        "web_search" => {
            let req: WebSearchRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid web_search args: {e}"))?;
            let response: WebSearchResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/web_search", &req),
                || {
                    let req = WebSearchRequest {
                        query: req.query.clone(),
                        max_results: req.max_results,
                    };
                    client.post_json("/v1/web_search", &req)
                },
            )?;
            let mut out = format!("{} results\n", response.results.len());
            for r in &response.results {
                out.push_str(&format!("- {} ({})\n", r.title, r.url));
                if let Some(ref snippet) = r.snippet {
                    out.push_str(&format!("  {}\n", snippet));
                }
            }
            Ok(out)
        }
        "create_pod" => {
            let req: CreatePodRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid create_pod args: {e}"))?;
            let response: CreatePodResponseBody = client.post_json("/v1/pod/create", &req)?;
            let addr_info = response
                .proxy_addr
                .map(|a| format!("\nproxy_addr: {}", a))
                .unwrap_or_default();
            Ok(format!("pod_id: {}{}", response.pod_id, addr_info))
        }
        "list_pods" => {
            let response: Vec<PodInfoResponse> = client.post_json("/v1/pod/list", &json!({}))?;
            if response.is_empty() {
                Ok("No sub-pods found.".to_string())
            } else {
                let mut out = String::new();
                for pod in &response {
                    let name = pod.name.as_deref().unwrap_or("(unnamed)");
                    out.push_str(&format!("- {} [{}] state={}\n", pod.id, name, pod.state));
                }
                Ok(out)
            }
        }
        "pod_status" => {
            let req: PodIdRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid pod_status args: {e}"))?;
            let response: PodInfoResponse = client.post_json("/v1/pod/status", &req)?;
            let name = response.name.as_deref().unwrap_or("(unnamed)");
            Ok(format!(
                "pod_id: {}\nname: {}\nstate: {}",
                response.id, name, response.state
            ))
        }
        "pod_logs" => {
            let req: PodIdRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid pod_logs args: {e}"))?;
            let response: PodLogsResponse = client.post_json("/v1/pod/logs", &req)?;
            Ok(response.logs)
        }
        "cancel_pod" => {
            let req: PodIdRequest = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid cancel_pod args: {e}"))?;
            let _response: CancelPodResponse = client.post_json("/v1/pod/cancel", &req)?;
            Ok(format!("Pod {} cancelled.", req.pod_id))
        }
        other => Err(anyhow!("unknown tool: {other}")),
    }
}

fn call_with_approval<F, R, Retry>(
    client: &ProxyClient,
    approval_prompt: bool,
    call: F,
    retry: Retry,
) -> Result<R>
where
    F: FnOnce() -> Result<R, ProxyError>,
    Retry: FnOnce() -> Result<R, ProxyError>,
{
    match call() {
        Ok(response) => Ok(response),
        Err(err) => {
            if err.kind == "approval_required" && approval_prompt {
                if let Some(operation) = err.operation.as_ref() {
                    if prompt_approval(operation)? {
                        let nonce = uuid::Uuid::new_v4().to_string();
                        let approve = ApproveRequest {
                            operation: operation.clone(),
                            count: 1,
                            expires_at_unix: None,
                            nonce: Some(nonce),
                        };
                        let _resp: ApproveResponse =
                            client.post_approve("/v1/approve", &approve)?;
                        let _ = _resp.ok;
                        return retry().map_err(|err| anyhow!("{}: {}", err.kind, err.message));
                    }
                }
            }
            Err(anyhow!("{}: {}", err.kind, err.message))
        }
    }
}

fn prompt_approval(operation: &str) -> Result<bool> {
    let tty = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(tty) => tty,
        Err(_) => return Ok(false),
    };
    let mut writer = io::BufWriter::new(tty.try_clone()?);
    write!(writer, "Approve operation '{}'? [y/N] ", operation)?;
    writer.flush()?;
    let mut reader = io::BufReader::new(tty);
    let mut input = String::new();
    reader.read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

fn write_result(stdout: &mut impl Write, id: Option<Value>, result: Value) -> Result<()> {
    if id.is_none() {
        return Ok(());
    }
    let message = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    });
    writeln!(stdout, "{}", serde_json::to_string(&message)?)?;
    stdout.flush()?;
    Ok(())
}

fn write_error(stdout: &mut impl Write, id: Option<Value>, code: i64, message: &str) -> Result<()> {
    if id.is_none() {
        return Ok(());
    }
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    });
    writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approve_request_with_nonce() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let req = ApproveRequest {
            operation: "read /etc/passwd".to_string(),
            count: 1,
            expires_at_unix: Some(1234567890),
            nonce: Some(nonce.clone()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(&nonce));
        assert!(json.contains("read /etc/passwd"));
    }

    #[test]
    fn test_approve_request_nonce_uniqueness() {
        let nonce1 = uuid::Uuid::new_v4().to_string();
        let nonce2 = uuid::Uuid::new_v4().to_string();
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 36); // UUID v4 format
    }

    #[test]
    fn test_tool_call_params_parsing() {
        let json = r#"{"name": "read", "arguments": {"path": "/tmp/test"}}"#;
        let params: ToolCallParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "read");
        assert_eq!(params.arguments["path"], "/tmp/test");
    }

    #[test]
    fn test_tool_call_params_default_arguments() {
        let json = r#"{"name": "run"}"#;
        let params: ToolCallParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "run");
        assert!(params.arguments.is_null());
    }

    #[test]
    fn test_build_tool_defs_permissive() {
        let tools = build_tool_defs(None);
        // No policy = defaults: read, write, run, web_fetch, glob, grep (web_search defaults off)
        assert_eq!(tools.len(), 6);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"read"));
        assert!(names.contains(&"write"));
        assert!(names.contains(&"run"));
        assert!(names.contains(&"web_fetch"));
        assert!(names.contains(&"glob"));
        assert!(names.contains(&"grep"));
        assert!(!names.contains(&"web_search")); // defaults to false
    }

    #[test]
    fn test_write_result_format() {
        let mut output = Vec::new();
        write_result(&mut output, Some(json!(1)), json!({"status": "ok"})).unwrap();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["jsonrpc"], "2.0");
        assert_eq!(result["id"], 1);
        assert_eq!(result["result"]["status"], "ok");
    }

    #[test]
    fn test_write_error_format() {
        let mut output = Vec::new();
        write_error(&mut output, Some(json!(42)), -32601, "method not found").unwrap();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["jsonrpc"], "2.0");
        assert_eq!(result["id"], 42);
        assert_eq!(result["error"]["code"], -32601);
        assert_eq!(result["error"]["message"], "method not found");
    }

    #[test]
    fn test_write_result_skips_notification() {
        let mut output = Vec::new();
        write_result(&mut output, None, json!({"data": "test"})).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_generate_session_id_format() {
        let session_id = generate_session_id();
        // Should be a valid UUID format (36 chars with hyphens)
        assert_eq!(session_id.len(), 36);
        assert!(session_id.chars().filter(|&c| c == '-').count() == 4);
        // Should parse as valid UUID
        let parsed = Uuid::parse_str(&session_id).unwrap();
        // Should be version 7
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[test]
    fn test_generate_session_id_uniqueness() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, id2, "session IDs should be unique");
    }

    #[test]
    fn test_generate_session_id_ordering() {
        // UUID v7 should be time-ordered
        let id1 = generate_session_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = generate_session_id();

        // When sorted lexicographically, id1 should come before id2
        // (because UUID v7 puts timestamp in most significant bits)
        assert!(
            id1 < id2,
            "UUID v7 should be time-ordered: {} should < {}",
            id1,
            id2
        );
    }

    #[test]
    fn test_proxy_client_session_id_provided() {
        let client = ProxyClient::new(
            "http://localhost:8080".to_string(),
            None,
            None,
            Some("test-actor".to_string()),
            Some("custom-session-123".to_string()),
        );
        assert_eq!(client.session_id(), "custom-session-123");
    }

    #[test]
    fn test_build_tool_defs_orchestrator() {
        let policy = PermissionLattice::orchestrator();
        let tools = build_tool_defs(Some(&policy));
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        // Orchestrator has read/glob/grep (LowRisk) but no write/run/web
        assert!(names.contains(&"read"));
        assert!(!names.contains(&"write"));
        assert!(!names.contains(&"run"));
        assert!(!names.contains(&"web_fetch"));
        // Orchestrator has manage_pods: Always
        assert!(names.contains(&"create_pod"));
        assert!(names.contains(&"list_pods"));
        assert!(names.contains(&"pod_status"));
        assert!(names.contains(&"pod_logs"));
        assert!(names.contains(&"cancel_pod"));
    }

    #[test]
    fn test_build_tool_defs_no_pod_mgmt_by_default() {
        // Without a policy, manage_pods defaults to false
        let tools = build_tool_defs(None);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"create_pod"));
    }

    #[test]
    fn test_build_tool_defs_search_tools_with_policy() {
        // Restrictive already has read/glob/grep at Always, so add web_search
        let mut policy = PermissionLattice::restrictive();
        policy.capabilities.web_search = CapabilityLevel::LowRisk;

        let tools = build_tool_defs(Some(&policy));
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"glob"));
        assert!(names.contains(&"grep"));
        assert!(names.contains(&"web_search"));
        assert!(names.contains(&"read")); // restrictive allows read
                                          // Restrictive denies write/run
        assert!(!names.contains(&"write"));
        assert!(!names.contains(&"run"));
    }

    #[test]
    fn test_build_tool_defs_never_hides_search() {
        // All capabilities at Never → no tools exposed
        let mut policy = PermissionLattice::restrictive();
        policy.capabilities.read_files = CapabilityLevel::Never;
        policy.capabilities.glob_search = CapabilityLevel::Never;
        policy.capabilities.grep_search = CapabilityLevel::Never;
        policy.capabilities.web_search = CapabilityLevel::Never;
        let tools = build_tool_defs(Some(&policy));
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"glob"));
        assert!(!names.contains(&"grep"));
        assert!(!names.contains(&"web_search"));
        assert!(!names.contains(&"read"));
    }

    #[test]
    fn test_glob_request_serialization() {
        let req = GlobRequest {
            pattern: "**/*.rs".to_string(),
            directory: Some("src".to_string()),
            max_results: Some(100),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("**/*.rs"));
        assert!(json.contains("src"));
    }

    #[test]
    fn test_grep_request_serialization() {
        let req = GrepRequest {
            pattern: "fn main".to_string(),
            path: None,
            file_glob: Some("*.rs".to_string()),
            context_lines: Some(2),
            max_matches: Some(50),
            case_insensitive: Some(true),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("fn main"));
        assert!(json.contains("*.rs"));
    }

    #[test]
    fn test_web_search_request_serialization() {
        let req = WebSearchRequest {
            query: "rust async".to_string(),
            max_results: Some(10),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("rust async"));
    }

    #[test]
    fn test_proxy_client_approval_secret_separate() {
        let client = ProxyClient::new(
            "http://localhost:8080".to_string(),
            Some("auth-secret-abc".to_string()),
            Some("approval-secret-xyz".to_string()),
            Some("actor".to_string()),
            None,
        );
        // Auth and approval secrets should be stored separately
        assert_ne!(client.auth_secret, client.approval_secret);
        assert_eq!(
            client.auth_secret.as_deref(),
            Some(b"auth-secret-abc".as_slice())
        );
        assert_eq!(
            client.approval_secret.as_deref(),
            Some(b"approval-secret-xyz".as_slice())
        );
    }

    #[test]
    fn test_proxy_client_approval_secret_fallback() {
        // When no approval_secret is given, post_approve falls back to auth_secret
        let client = ProxyClient::new(
            "http://localhost:8080".to_string(),
            Some("shared-secret".to_string()),
            None,
            Some("actor".to_string()),
            None,
        );
        assert!(client.approval_secret.is_none());
        // The fallback logic is in post_approve: it uses approval_secret.or(auth_secret)
    }

    #[test]
    fn test_proxy_client_session_id_generated() {
        let client = ProxyClient::new(
            "http://localhost:8080".to_string(),
            None,
            None,
            Some("test-actor".to_string()),
            None,
        );
        // Should auto-generate a UUID v7
        let session_id = client.session_id();
        assert_eq!(session_id.len(), 36);
        let parsed = Uuid::parse_str(session_id).unwrap();
        assert_eq!(parsed.get_version_num(), 7);
    }

    // --- Session exposure tracking tests ---

    #[test]
    fn test_tool_to_operation_mapping() {
        assert_eq!(tool_to_operation("read"), Some(Operation::ReadFiles));
        assert_eq!(tool_to_operation("write"), Some(Operation::WriteFiles));
        assert_eq!(tool_to_operation("run"), Some(Operation::RunBash));
        assert_eq!(tool_to_operation("web_fetch"), Some(Operation::WebFetch));
        assert_eq!(tool_to_operation("glob"), Some(Operation::GlobSearch));
        assert_eq!(tool_to_operation("grep"), Some(Operation::GrepSearch));
        assert_eq!(tool_to_operation("web_search"), Some(Operation::WebSearch));
        assert_eq!(tool_to_operation("create_pod"), Some(Operation::ManagePods));
        assert_eq!(tool_to_operation("cancel_pod"), Some(Operation::ManagePods));
        assert_eq!(tool_to_operation("unknown_tool"), None);
    }

    // ── Kernel decision engine tests ───────────────────────────────────

    /// Create a permissive lattice without static uninhabitable_state obligations
    /// or command restrictions. This allows testing dynamic exposure gating
    /// in isolation without command-lattice or static-obligation interference.
    fn permissive_no_static_obligations() -> PermissionLattice {
        use portcullis::{CommandLattice, Obligations};
        let mut lattice = PermissionLattice::permissive();
        lattice = lattice.with_uninhabitable_disabled();
        lattice.obligations = Obligations::default();
        lattice.commands = CommandLattice::empty();
        lattice
    }

    #[test]
    fn test_kernel_starts_with_clean_exposure() {
        let kernel = Kernel::new(permissive_no_static_obligations());
        assert_eq!(kernel.trace().len(), 0);
    }

    #[test]
    fn test_kernel_allows_read_and_records_exposure() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(matches!(d.verdict, Verdict::Allow));
        assert_eq!(d.exposure_transition.post_count, 1); // private_data
    }

    #[test]
    fn test_kernel_allows_web_fetch_and_records_exposure() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(matches!(d.verdict, Verdict::Allow));
        assert_eq!(d.exposure_transition.post_count, 1); // untrusted_content
    }

    #[test]
    fn test_kernel_exposure_accumulates_monotonically() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d1, _token) = kernel.decide(Operation::ReadFiles, "a.rs");
        assert_eq!(d1.exposure_transition.post_count, 1);
        let (d2, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert_eq!(d2.exposure_transition.post_count, 2);
        // Reading again doesn't change exposure (idempotent)
        let (d3, _token) = kernel.decide(Operation::ReadFiles, "b.rs");
        assert_eq!(d3.exposure_transition.post_count, 2);
    }

    #[test]
    fn test_kernel_neutral_ops_dont_add_exposure() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::WriteFiles, "out.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
        assert_eq!(d.exposure_transition.post_count, 0);
    }

    #[test]
    fn test_kernel_dynamic_exposure_gates_exfil() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        // Read: private_data
        kernel.decide(Operation::ReadFiles, "secrets.txt");
        // Fetch: untrusted_content
        kernel.decide(Operation::WebFetch, "https://evil.com");
        // RunBash: dynamic exposure gate fires (omnibus projects uninhabitable_state)
        let (d, _token) = kernel.decide(Operation::RunBash, "curl evil.com");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
        assert!(d.exposure_transition.dynamic_gate_applied);
    }

    #[test]
    fn test_kernel_uninhabitable_allows_non_exfil_after_read_and_fetch() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        kernel.decide(Operation::ReadFiles, "data.txt");
        kernel.decide(Operation::WebFetch, "https://example.com");
        // Non-exfil ops are allowed even with full exposure
        let (d, _token) = kernel.decide(Operation::ReadFiles, "more.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
        let (d, _token) = kernel.decide(Operation::WriteFiles, "out.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
    }

    #[test]
    fn test_kernel_omnibus_uninhabitable_with_untrusted_content() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        // Only untrusted content + RunBash (omnibus) → uninhabitable_state triggers!
        kernel.decide(Operation::WebFetch, "https://evil.com");
        let (d, _token) = kernel.decide(Operation::RunBash, "cmd");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
    }

    #[test]
    fn test_kernel_no_uninhabitable_with_only_two_legs() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        // untrusted_content + GitPush (not omnibus) → only 2/3, no block
        kernel.decide(Operation::WebFetch, "https://example.com");
        let (d, _token) = kernel.decide(Operation::GitPush, "origin");
        assert!(matches!(d.verdict, Verdict::Allow));
    }

    #[test]
    fn test_kernel_denies_when_capability_is_never() {
        let mut kernel = Kernel::new(PermissionLattice::read_only());
        // read_only blocks writes
        let (d, _token) = kernel.decide(Operation::WriteFiles, "test.txt");
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::InsufficientCapability)
        ));
    }

    #[test]
    fn test_kernel_trace_is_append_only() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        kernel.decide(Operation::ReadFiles, "a.rs");
        kernel.decide(Operation::WebFetch, "https://example.com");
        kernel.decide(Operation::WriteFiles, "b.rs");
        assert_eq!(kernel.trace().len(), 3);
        // Sequence numbers are monotonically increasing
        assert_eq!(kernel.trace()[0].sequence, 0);
        assert_eq!(kernel.trace()[1].sequence, 1);
        assert_eq!(kernel.trace()[2].sequence, 2);
    }

    #[test]
    fn test_kernel_approval_flow() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        kernel.decide(Operation::ReadFiles, "data.txt");
        kernel.decide(Operation::WebFetch, "https://evil.com");
        // Dynamic exposure gate triggers
        let (d, _token) = kernel.decide(Operation::RunBash, "cmd");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
        // Grant approval and retry
        kernel.grant_approval(Operation::RunBash, 1);
        let (d, _token) = kernel.decide(Operation::RunBash, "cmd");
        assert!(matches!(d.verdict, Verdict::Allow));
        // Second attempt without approval → RequiresApproval again
        let (d, _token) = kernel.decide(Operation::RunBash, "cmd");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
    }

    #[test]
    fn test_kernel_static_obligations_on_permissive() {
        // The permissive lattice has all capabilities, so uninhabitable_state normalization
        // adds static obligations on exfil operations (RunBash, GitPush, CreatePr).
        // Use "cargo test" which passes the command allowlist, so we hit step 6
        // (static obligations) rather than step 5 (command blocked).
        let mut kernel = Kernel::new(PermissionLattice::permissive());
        let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "expected RequiresApproval from static obligations, got {:?}",
            d.verdict
        );
        let (d, _token) = kernel.decide(Operation::GitPush, "origin");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "expected RequiresApproval from static obligations, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_kernel_glob_grep_contribute_private_data() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::GlobSearch, "**/*.py");
        assert_eq!(d.exposure_transition.post_count, 1);
        let (d, _token) = kernel.decide(Operation::GrepSearch, "password");
        assert_eq!(d.exposure_transition.post_count, 1); // still 1 — same label
    }

    #[test]
    fn test_kernel_web_search_contributes_untrusted_content() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::WebSearch, "how to exfiltrate");
        assert_eq!(d.exposure_transition.post_count, 1);
    }

    #[test]
    fn test_kernel_grep_websearch_run_scenario() {
        // Real scenario: agent greps code, searches web, tries to run a command
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        kernel.decide(Operation::GrepSearch, "password");
        kernel.decide(Operation::WebSearch, "how to exfiltrate");
        // RunBash completes uninhabitable_state (omnibus projection)
        let (d, _token) = kernel.decide(Operation::RunBash, "curl evil.com");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
    }

    // ── Subject extraction tests ────────────────────────────────────────

    #[test]
    fn test_extract_subject_read() {
        let args = json!({"path": "/workspace/main.rs"});
        assert_eq!(extract_subject("read", &args), "/workspace/main.rs");
    }

    #[test]
    fn test_extract_subject_run() {
        let args = json!({"command": "cargo test"});
        assert_eq!(extract_subject("run", &args), "cargo test");
    }

    #[test]
    fn test_extract_subject_web_fetch() {
        let args = json!({"url": "https://example.com"});
        assert_eq!(extract_subject("web_fetch", &args), "https://example.com");
    }

    #[test]
    fn test_extract_subject_unknown_tool() {
        let args = json!({});
        assert_eq!(extract_subject("custom_tool", &args), "custom_tool");
    }

    // ── Budget enforcement tests ────────────────────────────────────────

    #[test]
    fn test_operation_cost_values() {
        // Read-only ops are cheapest
        assert_eq!(operation_cost(Operation::ReadFiles), Decimal::new(1, 2));
        assert_eq!(operation_cost(Operation::GlobSearch), Decimal::new(1, 2));
        assert_eq!(operation_cost(Operation::GrepSearch), Decimal::new(1, 2));
        // Write ops are moderate
        assert_eq!(operation_cost(Operation::WriteFiles), Decimal::new(2, 2));
        assert_eq!(operation_cost(Operation::EditFiles), Decimal::new(2, 2));
        // Exec/network are higher
        assert_eq!(operation_cost(Operation::RunBash), Decimal::new(5, 2));
        assert_eq!(operation_cost(Operation::WebFetch), Decimal::new(10, 2));
        // Publish ops are most expensive
        assert_eq!(operation_cost(Operation::GitPush), Decimal::new(25, 2));
        assert_eq!(operation_cost(Operation::CreatePr), Decimal::new(25, 2));
        assert_eq!(operation_cost(Operation::ManagePods), Decimal::new(50, 2));
    }

    #[test]
    fn test_budget_charge_deducts_from_kernel() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        // Charge a read operation
        let remaining = kernel.charge(operation_cost(Operation::ReadFiles)).unwrap();
        // Default permissive budget is $10, charged $0.01
        assert_eq!(remaining, Decimal::new(10, 0) - Decimal::new(1, 2));
    }

    #[test]
    fn test_budget_exhaustion_denies_next_operation() {
        use portcullis::BudgetLattice;
        // Create a lattice with a tiny budget ($0.05)
        let mut lattice = permissive_no_static_obligations();
        lattice.budget = BudgetLattice {
            max_cost_usd: Decimal::new(5, 2), // $0.05
            ..lattice.budget
        };
        let mut kernel = Kernel::new(lattice);

        // First read is allowed ($0.01 cost)
        let (d, _token) = kernel.decide(Operation::ReadFiles, "a.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
        kernel.charge(operation_cost(Operation::ReadFiles)).unwrap();

        // Second read is allowed ($0.02 total)
        let (d, _token) = kernel.decide(Operation::ReadFiles, "b.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
        kernel.charge(operation_cost(Operation::ReadFiles)).unwrap();

        // Third read still allowed ($0.03 total)
        let (d, _token) = kernel.decide(Operation::ReadFiles, "c.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
        kernel.charge(operation_cost(Operation::ReadFiles)).unwrap();

        // RunBash costs $0.05, which would bring total to $0.08 > $0.05 budget
        // But decide() checks consumed_usd ($0.03) < max ($0.05), so it allows
        let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
        assert!(matches!(d.verdict, Verdict::Allow));
        // Charge fails because $0.03 + $0.05 = $0.08 > $0.05
        assert!(kernel.charge(operation_cost(Operation::RunBash)).is_err());

        // Next decide() sees consumed ($0.03) < max ($0.05), but if we force
        // another charge to push over: charge 3 more reads to reach $0.06
        kernel.charge(operation_cost(Operation::ReadFiles)).unwrap(); // $0.04
        kernel.charge(operation_cost(Operation::ReadFiles)).unwrap(); // $0.05

        // Now decide() should deny (consumed $0.05 >= max $0.05)
        let (d, _token) = kernel.decide(Operation::ReadFiles, "d.txt");
        assert!(
            matches!(d.verdict, Verdict::Deny(DenyReason::BudgetExhausted { .. })),
            "expected BudgetExhausted, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_budget_zero_cost_is_no_op() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        // Charging zero should succeed and not change budget
        let remaining = kernel.charge(Decimal::ZERO).unwrap();
        assert_eq!(remaining, Decimal::new(10, 0));
    }

    #[test]
    fn test_all_operations_have_nonzero_cost() {
        // Every operation should have a positive cost
        let ops = [
            Operation::ReadFiles,
            Operation::WriteFiles,
            Operation::EditFiles,
            Operation::RunBash,
            Operation::GlobSearch,
            Operation::GrepSearch,
            Operation::WebSearch,
            Operation::WebFetch,
            Operation::GitCommit,
            Operation::GitPush,
            Operation::CreatePr,
            Operation::ManagePods,
        ];
        for op in &ops {
            assert!(
                operation_cost(*op) > Decimal::ZERO,
                "operation {:?} should have positive cost",
                op
            );
        }
    }

    // ── Trace writer tests ──────────────────────────────────────────────

    #[test]
    fn test_trace_writer_none_is_noop() {
        let trace = TraceWriter::open(None).unwrap();
        assert!(trace.file.is_none());
        // record/finish should not panic when no file is configured
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (decision, _token) = kernel.decide(Operation::ReadFiles, "/tmp/test");
        trace.record(&decision);
        trace.finish(&kernel);
    }

    #[test]
    fn test_trace_writer_records_decisions_as_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.jsonl");
        let trace = TraceWriter::open(Some(&path)).unwrap();

        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d1, _token) = kernel.decide(Operation::ReadFiles, "/tmp/a");
        let (d2, _token) = kernel.decide(Operation::WriteFiles, "/tmp/b");
        trace.record(&d1);
        trace.record(&d2);

        // Read back and verify JSONL
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON with expected fields
        let parsed: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["operation"], "read_files");
        assert_eq!(parsed["subject"], "/tmp/a");
        assert_eq!(parsed["verdict"]["type"], "allow");

        let parsed: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed["operation"], "write_files");
        assert_eq!(parsed["subject"], "/tmp/b");
    }

    #[test]
    fn test_trace_writer_finish_writes_summary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.jsonl");
        let trace = TraceWriter::open(Some(&path)).unwrap();

        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/tmp/test");
        trace.record(&d);
        kernel.charge(Decimal::new(5, 2)).unwrap(); // $0.05
        trace.finish(&kernel);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2); // 1 decision + 1 summary

        let summary: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(summary["type"], "session_summary");
        assert_eq!(summary["decisions"], 1);
        assert_eq!(summary["consumed_usd"], "0.05");
    }

    #[test]
    fn test_trace_writer_denied_operations_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.jsonl");
        let trace = TraceWriter::open(Some(&path)).unwrap();

        // Use restrictive lattice where write is denied
        let mut kernel = Kernel::new(PermissionLattice::restrictive());
        let (d, _token) = kernel.decide(Operation::WriteFiles, "/tmp/test");
        trace.record(&d);

        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["verdict"]["type"], "deny");
    }

    #[test]
    fn test_trace_writer_appends_to_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.jsonl");

        // Write first session
        {
            let trace = TraceWriter::open(Some(&path)).unwrap();
            let mut kernel = Kernel::new(permissive_no_static_obligations());
            let (d, _token) = kernel.decide(Operation::ReadFiles, "/tmp/first");
            trace.record(&d);
            trace.finish(&kernel);
        }

        // Write second session — should append, not overwrite
        {
            let trace = TraceWriter::open(Some(&path)).unwrap();
            let mut kernel = Kernel::new(permissive_no_static_obligations());
            let (d, _token) = kernel.decide(Operation::ReadFiles, "/tmp/second");
            trace.record(&d);
            trace.finish(&kernel);
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        // 2 decisions + 2 summaries = 4 lines
        assert_eq!(lines.len(), 4);
    }
}
