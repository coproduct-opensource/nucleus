use anyhow::{anyhow, Context, Result};
use clap::Parser;
use lattice_guard::{CapabilityLevel, PermissionLattice};
use nucleus_client::sign_http_headers;
use nucleus_spec::PodSpec;
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
    /// Prompt on approval-required operations (uses /dev/tty).
    #[arg(long, default_value_t = true)]
    approval_prompt: bool,
    /// Session ID for audit correlation (UUID v7 format). Auto-generated if not provided.
    /// All tool calls within this MCP session will include this ID for tracing.
    #[arg(long, env = "NUCLEUS_MCP_SESSION_ID")]
    session_id: Option<String>,
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
    actor: Option<String>,
    /// Session ID for audit correlation across tool calls.
    session_id: String,
}

impl ProxyClient {
    fn new(
        base_url: String,
        auth_secret: Option<String>,
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

        if let Some(secret) = self.auth_secret.as_ref() {
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

fn main() -> Result<()> {
    let args = Args::parse();
    let policy = match args.spec.as_ref() {
        Some(path) => Some(load_policy(path)?),
        None => None,
    };
    let tools = build_tool_defs(policy.as_ref());
    let client = ProxyClient::new(
        args.proxy_url.clone(),
        args.auth_secret.clone(),
        Some(args.actor.clone()),
        args.session_id.clone(),
    );

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
                let result = match call_tool(&client, &call, args.approval_prompt) {
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

fn call_tool(client: &ProxyClient, call: &ToolCallParams, approval_prompt: bool) -> Result<String> {
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
                        let _resp: ApproveResponse = client.post_json("/v1/approve", &approve)?;
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
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"read"));
        assert!(names.contains(&"write"));
        assert!(names.contains(&"run"));
        assert!(names.contains(&"web_fetch"));
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
    fn test_proxy_client_session_id_generated() {
        let client = ProxyClient::new(
            "http://localhost:8080".to_string(),
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
}
