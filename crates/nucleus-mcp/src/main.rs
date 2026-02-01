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
}

impl ProxyClient {
    fn new(base_url: String, auth_secret: Option<String>, actor: Option<String>) -> Self {
        Self {
            base_url,
            auth_secret: auth_secret.map(|s| s.into_bytes()),
            actor,
        }
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
        let mut request = ureq::post(&url).set("content-type", "application/json");

        if let Some(secret) = self.auth_secret.as_ref() {
            let signed = sign_http_headers(secret, self.actor.as_deref(), &body_bytes);
            for (key, value) in signed.headers {
                request = request.set(&key, &value);
            }
        }

        match request.send_bytes(&body_bytes) {
            Ok(response) => response.into_json::<R>().map_err(|e| ProxyError {
                kind: "decode_error".to_string(),
                message: e.to_string(),
                operation: None,
            }),
            Err(ureq::Error::Status(_, response)) => {
                let parsed = response.into_json::<ErrorBody>();
                match parsed {
                    Ok(body) => Err(ProxyError {
                        kind: body.kind,
                        message: body.error,
                        operation: body.operation,
                    }),
                    Err(err) => Err(ProxyError {
                        kind: "http_error".to_string(),
                        message: err.to_string(),
                        operation: None,
                    }),
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
                        let approve = ApproveRequest {
                            operation: operation.clone(),
                            count: 1,
                            expires_at_unix: None,
                            nonce: None,
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
