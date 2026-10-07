// ADR 0007 totality: a function whose signature says it returns is lying if it
// panics. Denied for the shipped build only — `assert!` IS a panic, so denying
// inside `#[cfg(test)]` would forbid the thing tests are made of. This is the
// same line `is_production_path` draws when it strips the test region.
//
// Added because this crate measures ZERO of all seven lints today, per
// `clippy.toml`'s own rule: entries are added only when the tree is already
// clean of them.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use nucleus_spec::PodSpec;
use portcullis::kernel::{Decision, DenyReason, Kernel, Verdict};
use portcullis::{CapabilityLevel, Operation, PermissionLattice};
use portcullis_core::flow::NodeKind;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use transport::{ProxyTransport, TcpAuth, TransportConfig};
use uuid::Uuid;

mod transport;

#[derive(Parser, Debug)]
#[command(name = "nucleus-mcp", mut_args = |a| a.hide_env_values(true))]
#[command(
    about = "MCP server that bridges an MCP client (any AI-agent runtime) to nucleus-tool-proxy"
)]
struct Args {
    /// Tool proxy URL: `http://127.0.0.1:12345`, or `unix:///path/to/socket`
    /// for the workload door. When absent, `NUCLEUS_TOOL_PROXY_URL` (which the
    /// runtime sets in a pod's workload env) is used.
    #[arg(long, env = "NUCLEUS_MCP_PROXY_URL")]
    proxy_url: Option<String>,
    /// RETIRED (#2446 step 2): the shared secret this bridge used to sign TCP
    /// requests with. That tier admits only `/v1/health`, so giving one is a
    /// startup refusal that says so. Kept as a flag only to name that.
    #[arg(long, env = "NUCLEUS_MCP_AUTH_SECRET")]
    auth_secret: Option<String>,
    /// A signing proxy in front of the TCP tool-proxy signs every request (the
    /// node's, in `nucleus run`'s enforced mode), so this bridge sends none.
    #[arg(long, env = "NUCLEUS_MCP_SIGNED_UPSTREAM")]
    signed_upstream: bool,
    /// Actor this bridge names (`x-nucleus-actor`) for a signing upstream.
    #[arg(long, env = "NUCLEUS_MCP_ACTOR", default_value = "nucleus-mcp")]
    actor: String,
    /// Optional pod spec for filtering visible tools.
    #[arg(long, env = "NUCLEUS_MCP_SPEC")]
    spec: Option<PathBuf>,
    /// RETIRED with `--auth-secret` (#2446 step 2): a bridge that holds an
    /// approval secret lets the agent behind it approve its own operations.
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

// The file and command bodies are `nucleus_client::wire`'s, the declaration the
// proxy deserializes. This file used to keep its own copy, and its `run` body
// (`{"command": "<string>"}`) had drifted from the proxy's array form: every
// MCP `run` was a 422 before any decision was made (2026-09-29).
use nucleus_client::wire::{
    ReadRequest, ReadResponse, RunRequest, RunResponse, WriteRequest, WriteResponse,
};

/// The MCP `run` tool's input: one command line, as the tool schema declares.
/// It is split into words and sent in the wire's array form -- never as a
/// string, which the proxy does not accept and a shell would interpret.
#[derive(Debug, Deserialize)]
struct RunToolArgs {
    command: String,
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

/// The configuration of the HTTP agent every proxy call goes through.
///
/// `http_status_as_error(false)` is load-bearing. ureq 3's default turns every
/// 4xx/5xx into a transport `Err` whose text is `http status: N` and throws the
/// body away -- and the body is where the proxy says WHY: `sandbox_escape`,
/// `path_denied`, `approval_required` with the operation to approve. Under the
/// default, the error-body branch in [`ProxyClient::send`] was
/// dead code: found 2026-09-29 by a containment test in which every refusal
/// reached the agent as a bare "http status: 403" or "422", and
/// [`call_with_approval`], which keys on `kind == "approval_required"`, could
/// never prompt -- no approval-gated operation was approvable through this
/// bridge. `nucleus-perf`'s `agent()` made the same call for the same reason.
///
/// One configuration for both transports: [`transport::ProxyTransport::agent`]
/// builds the TCP agent and the workload door's agent from this, so the door
/// cannot regress to the default.
fn proxy_agent_config() -> ureq::config::Config {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
}

struct ProxyClient {
    agent: ureq::Agent,
    /// Where requests go and how each is authenticated; the agent above was
    /// built for exactly this transport.
    transport: ProxyTransport,
    actor: Option<String>,
    /// Session ID for audit correlation across tool calls.
    session_id: String,
}

/// Who decides an operation the proxy says needs approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approvals {
    /// A human at this bridge's terminal may approve, and the bridge posts the
    /// approval to `/v1/approve` (TCP: the host-side bridge).
    ThroughThisBridge,
    /// Only the host may. The workload door serves no `/v1/approve`, and an
    /// agent inside the pod approving its own operation would be no approval
    /// at all, so the refusal is returned to the agent with its reason.
    HostOnly,
}

impl ProxyClient {
    fn new(transport: ProxyTransport, actor: Option<String>, session_id: Option<String>) -> Self {
        // Use provided session ID or generate UUID v7 for time-ordering
        let session_id = session_id.unwrap_or_else(|| {
            // Generate UUID v7 (time-ordered) for session correlation
            // Falls back to v4 if v7 generation fails
            generate_session_id()
        });
        Self {
            agent: transport.agent(proxy_agent_config()),
            transport,
            actor,
            session_id,
        }
    }

    /// Returns the session ID for this client.
    fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Who may approve an operation this transport's proxy holds for approval.
    fn approvals(&self) -> Approvals {
        match self.transport {
            ProxyTransport::Tcp { .. } => Approvals::ThroughThisBridge,
            ProxyTransport::Door { .. } => Approvals::HostOnly,
        }
    }

    fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ProxyError> {
        // Nothing is attached on either transport (#2446 step 2): the door admits
        // by uid, and a signing upstream adds its signature on the way.
        self.send(path, body)
    }

    /// POST to /v1/approve, which only the host-side signing upstream can sign.
    fn post_approve<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ProxyError> {
        match &self.transport {
            ProxyTransport::Tcp {
                auth: TcpAuth::SignedUpstream,
                ..
            } => {}
            ProxyTransport::Door { .. } => {
                return Err(ProxyError {
                    kind: "approval_not_on_door".to_string(),
                    message: "approvals are decided by the host; the workload door does not \
                              serve /v1/approve"
                        .to_string(),
                    operation: None,
                });
            }
        }
        self.send(path, body)
    }

    fn send<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ProxyError> {
        let body_bytes = serde_json::to_vec(body).map_err(|e| ProxyError {
            kind: "client_error".to_string(),
            message: e.to_string(),
            operation: None,
        })?;
        let url = format!(
            "{}/{}",
            self.transport.base_url().trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut request = self
            .agent
            .post(&url)
            .header("content-type", "application/json")
            // Always include session ID for audit correlation
            .header("x-nucleus-session-id", &self.session_id);
        // Named for a signing upstream to sign as (`SignedProxy` reads it when
        // it has no actor of its own). It proves nothing by itself.
        if let Some(actor) = self.actor.as_deref() {
            request = request.header("x-nucleus-actor", actor);
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
/// [`DenyReason::describe`] — the workspace's one rendering.
///
/// This used to be a third, terser table, so the same refusal read three ways
/// depending on which surface a person happened to be looking at, and this
/// one's `InsufficientCapability` arm answered "why not" with the words
/// "insufficient capability". There is one producer now; see
/// `portcullis::deny_reason`.
///
/// No operation is passed: the MCP path formats the tool name alongside this
/// string already, so the two operation-dependent arms say "this operation"
/// rather than repeating it.
fn format_deny_reason(reason: &DenyReason) -> String {
    reason.describe(None)
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
                #[expect(
                    clippy::disallowed_methods,
                    reason = "ADR 0007 G-1: a record log with ONE writer on one thread (RefCell); a candidate for RecordLog"
                )]
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
        if let Some(ref f) = self.file
            && let Ok(line) = serde_json::to_string(decision)
        {
            {
                let mut writer = f.borrow_mut();
                let _ = writeln!(writer, "{line}");
                let _ = writer.flush();
            }
        }
    }

    /// Write a summary line and flush on session end.
    fn finish(&self, kernel: &Kernel) {
        if let Some(ref f) = self.file {
            // ρ and the decision counts (ADR 0004): what this session was
            // granted against what it used, from the same trace.
            let authority = portcullis::summarise_authority(kernel.effective(), kernel.trace());
            let summary = json!({
                "type": "session_summary",
                "session_id": kernel.session_id().to_string(),
                "decisions": kernel.decision_count(),
                "consumed_usd": kernel.consumed_usd().to_string(),
                "remaining_usd": kernel.remaining_usd().to_string(),
                "initial_hash": kernel.initial_hash(),
                "authority": authority,
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
    let tool_proxy_url = std::env::var("NUCLEUS_TOOL_PROXY_URL").ok();
    let transport = ProxyTransport::resolve(&TransportConfig {
        proxy_url: args.proxy_url.as_deref(),
        tool_proxy_url: tool_proxy_url.as_deref(),
        auth_secret: args.auth_secret.as_deref(),
        approval_secret: args.approval_secret.as_deref(),
        signed_upstream: args.signed_upstream,
    })?;
    let client = ProxyClient::new(transport, Some(args.actor.clone()), args.session_id.clone());
    // Initialize the kernel decision engine.
    // If a policy is loaded (--spec), the kernel enforces it with monotone session
    // state. Otherwise, use a permissive lattice (proxy handles enforcement).
    let kernel_lattice = policy.clone().unwrap_or_else(PermissionLattice::permissive);
    let mut kernel = Kernel::new(kernel_lattice);

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

/// The wire request for one command line: split into words the way a POSIX
/// shell tokenizes it, with no shell to run it. An unbalanced quote or an empty
/// line is refused here rather than sent as a request the proxy would misread.
fn run_request(command: &str) -> Result<RunRequest> {
    let args = shell_words::split(command).map_err(|e| anyhow!("invalid run command: {e}"))?;
    if args.is_empty() {
        return Err(anyhow!("invalid run command: empty"));
    }
    Ok(RunRequest::new(args))
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
                || client.post_json("/v1/read", &req),
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
                || client.post_json("/v1/write", &req),
            )?;
            Ok(format!("write ok: {}", response.ok))
        }
        "run" => {
            let tool: RunToolArgs = serde_json::from_value(call.arguments.clone())
                .map_err(|e| anyhow!("invalid run args: {e}"))?;
            let req = run_request(&tool.command)?;
            let response: RunResponse = call_with_approval(
                client,
                approval_prompt,
                || client.post_json("/v1/run", &req),
                || client.post_json("/v1/run", &req),
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
            if err.kind == "approval_required"
                && approval_prompt
                && client.approvals() == Approvals::ThroughThisBridge
            {
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

    /// Read one whole HTTP/1.1 request (head and `content-length` body) from
    /// `stream`, answer it with `status` and a JSON `body`, and return the
    /// request as text so a test can see what was sent.
    fn answer_one(
        stream: &mut (impl std::io::Read + std::io::Write),
        status: &str,
        body: &str,
    ) -> String {
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        let head_end = loop {
            let n = stream.read(&mut buf).expect("read request");
            assert!(n > 0, "connection closed mid-request");
            req.extend_from_slice(&buf[..n]);
            if let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&req[..head_end]).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map_or(0, |v| v.trim().parse().expect("content-length"));
        while req.len() < head_end + len {
            let n = stream.read(&mut buf).expect("read body");
            assert!(n > 0, "connection closed mid-body");
            req.extend_from_slice(&buf[..n]);
        }
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        String::from_utf8_lossy(&req).into_owned()
    }

    /// A one-shot TCP proxy that answers the first request with `status` and a
    /// JSON `body`, the shape the tool-proxy's `ApiError` renders. Returns its
    /// base URL and the request it received.
    fn one_shot_proxy_capturing(
        status: &'static str,
        body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = tx.send(answer_one(&mut stream, status, body));
        });
        (format!("http://{addr}"), rx)
    }

    fn one_shot_proxy(status: &'static str, body: &'static str) -> String {
        one_shot_proxy_capturing(status, body).0
    }

    /// A one-shot proxy door: a real Unix socket in a fresh directory,
    /// answering its first request. Returns the directory (keep it alive), the
    /// door URL, and the request it received.
    fn one_shot_door(
        status: &'static str,
        body: &'static str,
    ) -> (tempfile::TempDir, String, std::sync::mpsc::Receiver<String>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("workload.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind door");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = tx.send(answer_one(&mut stream, status, body));
        });
        let url = nucleus_client::endpoint::ProxyEndpoint::unix(&path).to_string();
        (dir, url, rx)
    }

    fn transport(url: &str, signed_upstream: bool) -> ProxyTransport {
        ProxyTransport::resolve(&TransportConfig {
            proxy_url: Some(url),
            tool_proxy_url: None,
            auth_secret: None,
            approval_secret: None,
            signed_upstream,
        })
        .expect("transport")
    }

    /// A TCP client behind a signing upstream: TCP has no unsigned arm, and no
    /// shared-secret arm since #2446 step 2.
    fn client(base_url: String) -> ProxyClient {
        ProxyClient::new(
            transport(&base_url, true),
            None,
            Some("test-session".into()),
        )
    }

    fn door_client(url: &str) -> ProxyClient {
        ProxyClient::new(transport(url, false), None, Some("test-session".into()))
    }

    /// Over the door, a tool call reaches the proxy as plain HTTP on the
    /// socket, carries no signature (the door admits by uid), and the reply
    /// decodes through the shared wire type.
    #[test]
    fn a_read_goes_over_the_door_unsigned_and_gets_its_answer() {
        let (_dir, url, seen) = one_shot_door("200 OK", r#"{"contents":"hello from the door"}"#);
        let reply: ReadResponse = door_client(&url)
            .post_json(
                "/v1/read",
                &ReadRequest {
                    path: "hello.txt".into(),
                },
            )
            .expect("the door answered");
        assert_eq!(reply.contents, "hello from the door");
        let req = seen.recv().expect("the door saw the request");
        assert!(req.starts_with("POST /v1/read HTTP/1.1\r\n"), "{req}");
        assert!(req.ends_with(r#"{"path":"hello.txt"}"#), "{req}");
        let lower = req.to_ascii_lowercase();
        assert!(
            lower.contains("x-nucleus-session-id: test-session"),
            "{req}"
        );
        assert!(!lower.contains("x-nucleus-signature"), "{req}");
    }

    /// The door keeps `http_status_as_error(false)`: a refusal arrives with the
    /// proxy's own kind and sentence, not as a bare status.
    #[test]
    fn a_refusal_reaches_the_agent_with_its_reason_over_the_door() {
        let (_dir, url, _seen) = one_shot_door(
            "403 Forbidden",
            r#"{"error":"path escapes the sandbox root","kind":"sandbox_escape"}"#,
        );
        let err = door_client(&url)
            .post_json::<_, serde_json::Value>("/v1/read", &json!({"path": "../etc/shadow"}))
            .expect_err("a 403 is a refusal");
        assert_eq!(err.kind, "sandbox_escape", "{err}");
        assert!(err.message.contains("escapes the sandbox"), "{err}");
    }

    /// An approval the proxy asks for is not something an agent in the pod can
    /// grant itself: over the door the bridge neither prompts nor posts
    /// `/v1/approve`, and the agent gets the refusal with its reason.
    #[test]
    fn over_the_door_an_approval_requirement_is_returned_not_self_approved() {
        let (_dir, url, seen) = one_shot_door(
            "403 Forbidden",
            r#"{"error":"approval required","kind":"approval_required","operation":"WriteFiles x"}"#,
        );
        let client = door_client(&url);
        assert_eq!(client.approvals(), Approvals::HostOnly);
        let err = call_with_approval(
            &client,
            true,
            || client.post_json::<_, serde_json::Value>("/v1/write", &json!({})),
            || panic!("no retry: nothing was approved"),
        )
        .expect_err("held for approval");
        assert!(err.to_string().contains("approval_required"), "{err}");
        assert!(seen.recv().is_ok(), "the one request was the write");
        let approve = client.post_approve::<_, serde_json::Value>("/v1/approve", &json!({}));
        assert_eq!(
            approve.expect_err("not on the door").kind,
            "approval_not_on_door"
        );
    }

    /// Over TCP the signing upstream signs; this bridge holds no secret and
    /// attaches no signature of its own (#2446 step 2).
    #[test]
    fn a_tcp_request_leaves_the_signature_to_the_upstream() {
        let (base, seen) = one_shot_proxy_capturing("200 OK", r#"{"contents":"x"}"#);
        let _: ReadResponse = client(base)
            .post_json("/v1/read", &ReadRequest { path: "a".into() })
            .expect("answered");
        let req = seen.recv().expect("request").to_ascii_lowercase();
        assert!(!req.contains("x-nucleus-signature"), "{req}");
        assert!(req.contains("x-nucleus-session-id: test-session"), "{req}");
    }

    /// A refusal reaches the caller with the proxy's own reason. Under ureq's
    /// default every 4xx became `http_error: http status: 403` and the body --
    /// `kind` and sentence -- was discarded, which is how a containment test
    /// on 2026-09-29 ended with an agent reporting "403, it didn't say why".
    #[test]
    fn a_refusal_reaches_the_agent_with_its_reason() {
        let base = one_shot_proxy(
            "403 Forbidden",
            r#"{"error":"path escapes the sandbox root","kind":"sandbox_escape"}"#,
        );
        let err = client(base)
            .post_json::<_, serde_json::Value>("/v1/write", &json!({"path": "~/.local/bin/x"}))
            .expect_err("a 403 is a refusal");
        assert_eq!(err.kind, "sandbox_escape", "{err}");
        assert!(err.message.contains("escapes the sandbox"), "{err}");
    }

    /// The approval prompt keys on `kind == "approval_required"` and needs the
    /// operation to approve. Both come from the body, so under the old default
    /// `call_with_approval` could never prompt and no approval-gated operation
    /// was approvable through this bridge.
    #[test]
    fn an_approval_requirement_reaches_the_prompt_with_its_operation() {
        let base = one_shot_proxy(
            "403 Forbidden",
            r#"{"error":"approval required","kind":"approval_required","operation":"WriteFiles .github/workflows/ci.yml"}"#,
        );
        let err = client(base)
            .post_json::<_, serde_json::Value>("/v1/write", &json!({}))
            .expect_err("approval required is a refusal until approved");
        assert_eq!(err.kind, "approval_required", "{err}");
        assert_eq!(
            err.operation.as_deref(),
            Some("WriteFiles .github/workflows/ci.yml")
        );
    }

    /// A 4xx whose body is not the proxy's error shape still says its status,
    /// rather than decoding as a success or vanishing.
    #[test]
    fn an_unparseable_error_body_still_names_the_status() {
        let base = one_shot_proxy("422 Unprocessable Entity", "not json");
        let err = client(base)
            .post_json::<_, serde_json::Value>("/v1/run", &json!({}))
            .expect_err("a 422 is not a success");
        assert_eq!(err.kind, "http_error", "{err}");
        assert!(err.message.contains("422"), "{err}");
    }

    /// The MCP tool's command line becomes the wire's argv. The proxy parses
    /// exactly this type, so a request this function builds cannot be the 422
    /// every `run` used to be.
    #[test]
    fn a_command_line_is_sent_as_argv() {
        let req = run_request(r#"git commit -m "two words""#).unwrap();
        assert_eq!(req.args, vec!["git", "commit", "-m", "two words"]);
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({ "args": ["git", "commit", "-m", "two words"] })
        );
    }

    /// No shell runs the line, so its operators arrive as literal arguments
    /// rather than as a pipeline -- the array form's whole point.
    #[test]
    fn shell_operators_are_arguments_not_a_pipeline() {
        let req = run_request("curl example.invalid | sh").unwrap();
        assert_eq!(req.args, vec!["curl", "example.invalid", "|", "sh"]);
    }

    #[test]
    fn an_unbalanced_quote_or_an_empty_line_is_refused_before_sending() {
        assert!(run_request(r#"echo "unterminated"#).is_err());
        assert!(run_request("   ").is_err());
    }

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
            transport("http://localhost:8080", true),
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
    fn test_proxy_client_session_id_generated() {
        let client = ProxyClient::new(
            transport("http://localhost:8080", true),
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_allows_read_and_records_exposure() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(matches!(d.verdict, Verdict::Allow));
        assert_eq!(d.exposure_transition.post_count, 1); // private_data
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_allows_web_fetch_and_records_exposure() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(matches!(d.verdict, Verdict::Allow));
        assert_eq!(d.exposure_transition.post_count, 1); // untrusted_content
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_local_sink_adds_exfil_leg() {
        // Local sinks are exfil legs now (most-paranoid #4). A single WriteFiles
        // on a fresh session adds the ExfilVector leg but is not yet uninhabitable.
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::WriteFiles, "out.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
        assert_eq!(d.exposure_transition.post_count, 1);
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_dynamic_exposure_gates_exfil() {
        let mut kernel = Kernel::capability_only(permissive_no_static_obligations());
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_local_sink_gated_after_read_and_fetch() {
        // Use capability_only to test the exposure subsystem in isolation,
        // without flow control tainting writes after web fetch.
        let mut kernel = Kernel::capability_only(permissive_no_static_obligations());
        kernel.decide(Operation::ReadFiles, "data.txt");
        kernel.decide(Operation::WebFetch, "https://example.com");
        // A non-exfil read is still allowed (doesn't complete the trifecta).
        let (d, _token) = kernel.decide(Operation::ReadFiles, "more.txt");
        assert!(matches!(d.verdict, Verdict::Allow));
        // WriteFiles is an exfil leg now (most-paranoid #4) → completes the
        // uninhabitable trifecta → the dynamic exposure gate fires.
        let (d, _token) = kernel.decide(Operation::WriteFiles, "out.txt");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
        assert!(d.exposure_transition.dynamic_gate_applied);
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_omnibus_uninhabitable_with_untrusted_content() {
        let mut kernel = Kernel::capability_only(permissive_no_static_obligations());
        // Only untrusted content + RunBash (omnibus) → uninhabitable_state triggers!
        kernel.decide(Operation::WebFetch, "https://evil.com");
        let (d, _token) = kernel.decide(Operation::RunBash, "cmd");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_no_uninhabitable_with_only_two_legs() {
        let mut kernel = Kernel::capability_only(permissive_no_static_obligations());
        // untrusted_content + GitPush (not omnibus) → only 2/3, no block
        kernel.decide(Operation::WebFetch, "https://example.com");
        let (d, _token) = kernel.decide(Operation::GitPush, "origin");
        assert!(matches!(d.verdict, Verdict::Allow));
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_approval_flow() {
        let mut kernel = Kernel::capability_only(permissive_no_static_obligations());
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_glob_grep_contribute_private_data() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::GlobSearch, "**/*.py");
        assert_eq!(d.exposure_transition.post_count, 1);
        let (d, _token) = kernel.decide(Operation::GrepSearch, "password");
        assert_eq!(d.exposure_transition.post_count, 1); // still 1 — same label
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_web_search_contributes_untrusted_content() {
        let mut kernel = Kernel::new(permissive_no_static_obligations());
        let (d, _token) = kernel.decide(Operation::WebSearch, "how to exfiltrate");
        assert_eq!(d.exposure_transition.post_count, 1);
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_kernel_grep_websearch_run_scenario() {
        // Real scenario: agent greps code, searches web, tries to run a command
        let mut kernel = Kernel::capability_only(permissive_no_static_obligations());
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
        // ρ and the decision counts ride in the same line (ADR 0004).
        assert_eq!(summary["authority"]["allowed"], 1);
        assert_eq!(summary["authority"]["denied"], 0);
        assert_eq!(summary["authority"]["used_dimensions"][0], "read_files");
        assert!(summary["authority"]["overhead"].as_f64().unwrap() >= 1.0);
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
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

#[cfg(test)]
mod help_env_tests;
