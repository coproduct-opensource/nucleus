//! MCP server mode for nucleus-tool-proxy.
//!
//! When `--mcp` is passed, the tool-proxy serves the Model Context Protocol
//! over stdio instead of HTTP. Each MCP tool maps 1:1 to an existing
//! tool-proxy operation. The same sandbox enforcement and audit logging apply.
//!
//! Auth: stdio transport implies the client is the pod's guest process —
//! already authenticated by sandbox proof. HMAC auth is skipped.

use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter, handler::server::wrapper::Parameters, model::*,
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::AppState;

// ---------------------------------------------------------------------------
// Tool parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadParams {
    /// File path to read (relative to workspace root).
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteParams {
    /// File path to write (relative to workspace root).
    pub path: String,
    /// File contents to write.
    pub contents: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunParams {
    /// Command and arguments (first element is the binary).
    pub args: Vec<String>,
    /// Optional stdin input.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Optional working directory.
    #[serde(default)]
    pub directory: Option<String>,
    /// Timeout in seconds (default: 30).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GlobParams {
    /// Glob pattern to match files (e.g. "**/*.rs").
    pub pattern: String,
    /// Root directory to search from (defaults to workspace root).
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GrepParams {
    /// Regex pattern to search for.
    pub pattern: String,
    /// Root directory or file to search in.
    #[serde(default)]
    pub path: Option<String>,
    /// File glob filter (e.g. "*.rs").
    #[serde(default)]
    pub include: Option<String>,
    /// Number of context lines.
    #[serde(default)]
    pub context_lines: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WebFetchParams {
    /// URL to fetch.
    pub url: String,
    /// HTTP method (default: GET).
    #[serde(default)]
    pub method: Option<String>,
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct NucleusMcpServer {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

fn work_dir(state: &AppState) -> String {
    state
        .runtime
        .sandbox()
        .root_path()
        .to_string_lossy()
        .to_string()
}

#[tool_router]
impl NucleusMcpServer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Read a file from the pod workspace")]
    async fn read(
        &self,
        Parameters(params): Parameters<ReadParams>,
    ) -> Result<CallToolResult, McpError> {
        let root = self.state.runtime.sandbox().root_path();
        let full_path = root.join(&params.path);

        match tokio::fs::read_to_string(&full_path).await {
            Ok(contents) => Ok(CallToolResult::success(vec![Content::text(contents)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "read failed: {e}"
            ))])),
        }
    }

    #[tool(description = "Write contents to a file in the pod workspace")]
    async fn write(
        &self,
        Parameters(params): Parameters<WriteParams>,
    ) -> Result<CallToolResult, McpError> {
        let root = self.state.runtime.sandbox().root_path();
        let full_path = root.join(&params.path);

        match tokio::fs::write(&full_path, &params.contents).await {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text("ok")])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "write failed: {e}"
            ))])),
        }
    }

    #[tool(
        description = "Execute a command in the pod sandbox (array-based args, no shell injection)"
    )]
    async fn run(
        &self,
        Parameters(params): Parameters<RunParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.args.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "args must not be empty",
            )]));
        }

        let dir = params
            .directory
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| self.state.runtime.sandbox().root_path().to_path_buf());

        let timeout = std::time::Duration::from_secs(params.timeout_seconds.unwrap_or(30));

        let mut cmd = tokio::process::Command::new(&params.args[0]);
        cmd.args(&params.args[1..]);
        cmd.current_dir(&dir);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output_future = async {
            if let Some(ref stdin_data) = params.stdin {
                cmd.stdin(std::process::Stdio::piped());
                let mut child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
                if let Some(mut stdin) = child.stdin.take() {
                    use tokio::io::AsyncWriteExt;
                    let _ = stdin.write_all(stdin_data.as_bytes()).await;
                    drop(stdin);
                }
                child
                    .wait_with_output()
                    .await
                    .map_err(|e| format!("wait failed: {e}"))
            } else {
                cmd.output().await.map_err(|e| format!("run failed: {e}"))
            }
        };

        match tokio::time::timeout(timeout, output_future).await {
            Ok(Ok(output)) => {
                let result = RunResult {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                };
                let json = serde_json::to_string_pretty(&result).unwrap_or_default();
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Ok(Err(msg)) => Ok(CallToolResult::error(vec![Content::text(msg)])),
            Err(_) => Ok(CallToolResult::error(vec![Content::text(format!(
                "command timed out after {timeout:?}"
            ))])),
        }
    }

    #[tool(description = "Search for files matching a glob pattern")]
    async fn glob(
        &self,
        Parameters(params): Parameters<GlobParams>,
    ) -> Result<CallToolResult, McpError> {
        let root = params.root.unwrap_or_else(|| work_dir(&self.state));
        let pattern = format!("{}/{}", root, params.pattern);

        match glob::glob(&pattern) {
            Ok(paths) => {
                let results: Vec<String> = paths
                    .filter_map(|p| p.ok())
                    .map(|p| p.display().to_string())
                    .collect();
                Ok(CallToolResult::success(vec![Content::text(
                    results.join("\n"),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "glob error: {e}"
            ))])),
        }
    }

    #[tool(description = "Search file contents with regex")]
    async fn grep(
        &self,
        Parameters(params): Parameters<GrepParams>,
    ) -> Result<CallToolResult, McpError> {
        let search_path = params.path.unwrap_or_else(|| work_dir(&self.state));

        let mut cmd = tokio::process::Command::new("grep");
        cmd.arg("-rn");
        cmd.arg("--color=never");
        if let Some(ref include) = params.include {
            cmd.arg("--include").arg(include);
        }
        if let Some(ctx) = params.context_lines {
            cmd.arg(format!("-C{ctx}"));
        }
        cmd.arg(&params.pattern).arg(&search_path);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        match cmd.output().await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(CallToolResult::success(vec![Content::text(
                    stdout.to_string(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "grep failed: {e}"
            ))])),
        }
    }

    #[tool(description = "Fetch a URL (HTTP GET/POST/PUT/DELETE)")]
    async fn web_fetch(
        &self,
        Parameters(params): Parameters<WebFetchParams>,
    ) -> Result<CallToolResult, McpError> {
        let method = params.method.as_deref().unwrap_or("GET");
        let client = &self.state.web_client;

        let request = match method.to_uppercase().as_str() {
            "GET" => client.get(&params.url),
            "POST" => client.post(&params.url),
            "PUT" => client.put(&params.url),
            "DELETE" => client.delete(&params.url),
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "unsupported method: {method}"
                ))]))
            }
        };

        match request.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                match resp.text().await {
                    Ok(body) => Ok(CallToolResult::success(vec![Content::text(format!(
                        "HTTP {status}\n\n{body}"
                    ))])),
                    Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                        "body read failed: {e}"
                    ))])),
                }
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "fetch failed: {e}"
            ))])),
        }
    }
}

#[tool_handler]
impl ServerHandler for NucleusMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "nucleus-tool-proxy".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                title: None,
                description: None,
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "Nucleus tool-proxy MCP server. Operations enforced by the permission lattice."
                    .into(),
            ),
        }
    }
}

/// Run the MCP server on stdin/stdout.
pub async fn run_mcp_server(state: Arc<AppState>) -> Result<(), crate::ApiError> {
    info!("starting MCP server mode (stdio transport)");

    let server = NucleusMcpServer::new(state);
    let service = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| crate::ApiError::Spec(format!("MCP server init failed: {e}")))?;

    service
        .waiting()
        .await
        .map_err(|e| crate::ApiError::Spec(format!("MCP server error: {e}")))?;

    Ok(())
}
