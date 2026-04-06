#![allow(clippy::disallowed_types)] // #1216 MIGRATION TARGET: agent-facing file/glob I/O (#1273)
//! MCP server mode for nucleus-tool-proxy.
//!
//! When `--mcp` is passed, the tool-proxy serves the Model Context Protocol
//! over stdio instead of HTTP. Each MCP tool maps 1:1 to an existing
//! tool-proxy operation, enforced through the same sandbox and permission
//! lattice as the HTTP API.
//!
//! Auth: stdio transport implies the client is the pod's guest process —
//! already authenticated by sandbox proof. HMAC auth is skipped.

use std::collections::BTreeMap;
use std::sync::Arc;

use portcullis::action_term::ActionTerm;
use portcullis::kernel::{Kernel, Verdict};
use portcullis::verdict_sink::{ActorIdentity, VerdictContext, VerdictOutcome, VerdictSink};
use portcullis::{CapabilityLevel, GradedExposureGuard, Operation, ToolCallGuard};
use rmcp::{
    handler::server::router::tool::ToolRouter, handler::server::wrapper::Parameters, model::*,
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::AppState;

// ---------------------------------------------------------------------------
// Tool parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
/// Parameters for the read tool.
pub struct ReadParams {
    /// File path to read (relative to workspace root).
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
/// Parameters for the write tool.
pub struct WriteParams {
    /// File path to write (relative to workspace root).
    pub path: String,
    /// File contents to write.
    pub contents: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
/// Parameters for the run tool.
pub struct RunParams {
    /// Command and arguments (first element is the binary).
    pub args: Vec<String>,
    /// Optional stdin input.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Optional working directory.
    #[serde(default)]
    pub directory: Option<String>,
    /// Timeout in seconds (ignored — Executor enforces pod-level budget).
    #[serde(default)]
    pub _timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
/// Result of a run command.
pub struct RunResult {
    /// Exit code of the process.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
/// Parameters for the glob tool.
pub struct GlobParams {
    /// Glob pattern to match files (e.g. "**/*.rs").
    pub pattern: String,
    /// Root directory to search from (defaults to workspace root).
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
/// Parameters for the grep tool.
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
/// Parameters for the web_fetch tool.
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
/// MCP server with session-scoped uninhabitable_state guard and schema pinning.
pub struct NucleusMcpServer {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
    /// Session-scoped exposure-tracking guard (graded monad).
    guard: Arc<GradedExposureGuard>,
    /// Shared verdict sink for lockdown enforcement + telemetry.
    sink: Arc<dyn VerdictSink>,
    /// Kernel decision engine for complete mediation.
    kernel: Arc<tokio::sync::Mutex<Kernel>>,
}

/// Convert a tool-level error into a CallToolResult error.
fn err_result(msg: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![Content::text(format!("{msg}"))])
}

#[tool_router]
impl NucleusMcpServer {
    /// Create a new MCP server with session-scoped security enforcement.
    pub fn new(state: Arc<AppState>, sink: Arc<dyn VerdictSink>) -> Self {
        let tool_router = Self::tool_router();

        // Schema pinning: hash the tool list at session start for rug-pull detection
        let tool_schemas = format!("{:?}", tool_router.list_all());
        let policy = state.runtime.policy().clone();

        let kernel = Arc::new(tokio::sync::Mutex::new(Kernel::new(policy.clone())));

        let guard = Arc::new(GradedExposureGuard::new(policy, &tool_schemas));

        // Store guard reference in AppState for exit report exposure extraction
        if let Ok(mut slot) = state.exposure_guard.write() {
            *slot = Some(guard.clone());
        }

        Self {
            state,
            tool_router,
            guard,
            sink,
            kernel,
        }
    }

    /// Check the kernel for a decision on the given operation/subject.
    ///
    /// Constructs an [`ActionTerm`] and routes through [`Kernel::decide_term`],
    /// which runs obligation discharge, task scope checking, and causal ancestry
    /// validation (#1187). The old `Kernel::decide()` path is bypassed entirely.
    async fn kernel_decide(
        &self,
        operation: Operation,
        subject: &str,
    ) -> Result<portcullis::kernel::DecisionToken, CallToolResult> {
        let term = build_action_term(operation, subject);
        let mut kernel = self.kernel.lock().await;
        let (decision, token) = kernel.decide_term(term);
        match decision.verdict {
            Verdict::Allow => Ok(token.expect("Allow verdict always produces token")),
            Verdict::Deny(ref reason) => {
                warn!(
                    ?operation,
                    subject,
                    ?reason,
                    exposure = decision.exposure_transition.post_count,
                    "kernel denied MCP operation"
                );
                Err(err_result(format!("kernel denied: {reason:?}")))
            }
            Verdict::RequiresApproval => {
                warn!(
                    ?operation,
                    subject,
                    exposure = decision.exposure_transition.post_count,
                    "kernel requires approval for MCP operation (no approval channel)"
                );
                Err(err_result(
                    "kernel requires approval (no MCP approval channel)",
                ))
            }
        }
    }

    /// Record a verdict through the sink (best-effort -- never panics).
    ///
    /// SECURITY: errors are logged at warn level so audit gaps are visible
    /// in telemetry. Previously errors were silently discarded with `let _ =`,
    /// making audit backend failures invisible (Trail of Bits finding #3).
    fn record_verdict(&self, operation: Operation, subject: &str, outcome: VerdictOutcome) {
        if let Err(e) = self.sink.record(VerdictContext {
            operation,
            subject: subject.to_string(),
            outcome,
            actor: ActorIdentity::StdioGuest,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, ?operation, subject, "verdict recording failed — audit gap");
        }
    }

    // -----------------------------------------------------------------------
    // read — uses Sandbox.read_to_string (cap-std kernel protection)
    // -----------------------------------------------------------------------

    #[tool(description = "Read a file from the pod workspace")]
    async fn read(
        &self,
        Parameters(params): Parameters<ReadParams>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.sink.preflight(Operation::ReadFiles) {
            self.record_verdict(
                Operation::ReadFiles,
                &params.path,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        let decision_token = match self.kernel_decide(Operation::ReadFiles, &params.path).await {
            Ok(dt) => dt,
            Err(result) => return Ok(result),
        };

        let proof = match self.guard.check(Operation::ReadFiles) {
            Ok(p) => p,
            Err(e) => {
                self.record_verdict(
                    Operation::ReadFiles,
                    &params.path,
                    VerdictOutcome::Deny {
                        reason: format!("{e}"),
                    },
                );
                return Ok(err_result(e));
            }
        };

        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(|| {
                self.state
                    .runtime
                    .sandbox()
                    .read_to_string(&params.path, &decision_token)
            })
        }) {
            Ok(contents) => {
                self.record_verdict(Operation::ReadFiles, &params.path, VerdictOutcome::Allow);
                Ok(CallToolResult::success(vec![Content::text(contents)]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::ReadFiles,
                    &params.path,
                    VerdictOutcome::Error {
                        error: format!("{e}"),
                    },
                );
                Ok(err_result(e))
            }
        }
    }

    // -----------------------------------------------------------------------
    // write — uses Sandbox.write (cap-std kernel protection)
    // -----------------------------------------------------------------------

    #[tool(description = "Write contents to a file in the pod workspace")]
    async fn write(
        &self,
        Parameters(params): Parameters<WriteParams>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.sink.preflight(Operation::WriteFiles) {
            self.record_verdict(
                Operation::WriteFiles,
                &params.path,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        let decision_token = match self
            .kernel_decide(Operation::WriteFiles, &params.path)
            .await
        {
            Ok(dt) => dt,
            Err(result) => return Ok(result),
        };

        let proof = match self.guard.check(Operation::WriteFiles) {
            Ok(p) => p,
            Err(e) => {
                self.record_verdict(
                    Operation::WriteFiles,
                    &params.path,
                    VerdictOutcome::Deny {
                        reason: format!("{e}"),
                    },
                );
                return Ok(err_result(e));
            }
        };

        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(|| {
                self.state.runtime.sandbox().write(
                    &params.path,
                    params.contents.as_bytes(),
                    &decision_token,
                )
            })
        }) {
            Ok(()) => {
                self.record_verdict(Operation::WriteFiles, &params.path, VerdictOutcome::Allow);
                Ok(CallToolResult::success(vec![Content::text("ok")]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::WriteFiles,
                    &params.path,
                    VerdictOutcome::Error {
                        error: format!("{e}"),
                    },
                );
                Ok(err_result(e))
            }
        }
    }

    // -----------------------------------------------------------------------
    // run — uses Executor.run_args (capability + command policy + env isolation)
    // -----------------------------------------------------------------------

    #[tool(
        description = "Execute a command in the pod sandbox (array-based args, no shell injection)"
    )]
    async fn run(
        &self,
        Parameters(params): Parameters<RunParams>,
    ) -> Result<CallToolResult, McpError> {
        let subject = params.args.join(" ");

        if let Err(e) = self.sink.preflight(Operation::RunBash) {
            self.record_verdict(
                Operation::RunBash,
                &subject,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        let decision_token = match self.kernel_decide(Operation::RunBash, &subject).await {
            Ok(dt) => dt,
            Err(result) => return Ok(result),
        };

        if params.args.is_empty() {
            self.record_verdict(
                Operation::RunBash,
                &subject,
                VerdictOutcome::Deny {
                    reason: "args must not be empty".to_string(),
                },
            );
            return Ok(err_result("args must not be empty"));
        }

        let proof = match self.guard.check(Operation::RunBash) {
            Ok(p) => p,
            Err(e) => {
                self.record_verdict(
                    Operation::RunBash,
                    &subject,
                    VerdictOutcome::Deny {
                        reason: format!("{e}"),
                    },
                );
                return Ok(err_result(e));
            }
        };

        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(|| {
                self.state.runtime.executor().run_args(
                    &params.args,
                    params.stdin.as_deref(),
                    params.directory.as_deref(),
                    &decision_token,
                )
            })
        }) {
            Ok(output) => {
                self.record_verdict(Operation::RunBash, &subject, VerdictOutcome::Allow);
                let run_result = RunResult {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                };
                let json = serde_json::to_string_pretty(&run_result).unwrap_or_default();
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::RunBash,
                    &subject,
                    VerdictOutcome::Error {
                        error: format!("{e}"),
                    },
                );
                Ok(err_result(e))
            }
        }
    }

    // -----------------------------------------------------------------------
    // glob — sandbox boundary enforcement with canonicalization
    // -----------------------------------------------------------------------

    #[tool(description = "Search for files matching a glob pattern")]
    async fn glob(
        &self,
        Parameters(params): Parameters<GlobParams>,
    ) -> Result<CallToolResult, McpError> {
        let subject = params.pattern.clone();

        if let Err(e) = self.sink.preflight(Operation::GlobSearch) {
            self.record_verdict(
                Operation::GlobSearch,
                &subject,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        match self.kernel_decide(Operation::GlobSearch, &subject).await {
            Ok(_decision_token) => {} // glob doesn't go through Sandbox I/O
            Err(result) => return Ok(result),
        }

        let proof = match self.guard.check(Operation::GlobSearch) {
            Ok(p) => p,
            Err(e) => {
                self.record_verdict(
                    Operation::GlobSearch,
                    &subject,
                    VerdictOutcome::Deny {
                        reason: format!("{e}"),
                    },
                );
                return Ok(err_result(e));
            }
        };

        // Check capability level
        let level = self.state.runtime.policy().capabilities.glob_search;
        if level == CapabilityLevel::Never {
            self.record_verdict(
                Operation::GlobSearch,
                &subject,
                VerdictOutcome::Deny {
                    reason: "glob_search capability is disabled".to_string(),
                },
            );
            return Ok(err_result("glob_search capability is disabled"));
        }

        let state = self.state.clone();
        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(move || -> Result<Vec<String>, String> {
                let sandbox_root = state.runtime.sandbox().root_path();
                let sandbox_canonical = sandbox_root
                    .canonicalize()
                    .map_err(|e| format!("sandbox root error: {e}"))?;

                // Resolve search root within sandbox
                let search_root = if let Some(ref root) = params.root {
                    let root_path = std::path::Path::new(root);
                    if root_path.is_absolute() {
                        return Err(format!("absolute paths not allowed: {root}"));
                    }
                    let resolved = sandbox_root.join(root);
                    let canonical = resolved
                        .canonicalize()
                        .map_err(|e| format!("path resolution error: {e}"))?;
                    if !canonical.starts_with(&sandbox_canonical) {
                        return Err(format!("path escapes sandbox: {root}"));
                    }
                    canonical
                } else {
                    sandbox_canonical.clone()
                };

                let full_pattern = search_root.join(&params.pattern);
                let pattern_str = full_pattern.to_string_lossy();

                let mut results = Vec::new();
                let entries =
                    glob::glob(&pattern_str).map_err(|e| format!("invalid glob pattern: {e}"))?;

                for entry in entries {
                    if let Ok(path) = entry {
                        if let Ok(canonical) = path.canonicalize() {
                            if canonical.starts_with(&sandbox_canonical) {
                                if let Ok(relative) = canonical.strip_prefix(&sandbox_canonical) {
                                    results.push(relative.to_string_lossy().to_string());
                                }
                            }
                        }
                    }
                    if results.len() >= 1000 {
                        break;
                    }
                }
                Ok(results)
            })
        }) {
            Ok(paths) => {
                self.record_verdict(Operation::GlobSearch, &subject, VerdictOutcome::Allow);
                Ok(CallToolResult::success(vec![Content::text(
                    paths.join("\n"),
                )]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::GlobSearch,
                    &subject,
                    VerdictOutcome::Error {
                        error: format!("{e}"),
                    },
                );
                Ok(err_result(e))
            }
        }
    }

    // -----------------------------------------------------------------------
    // grep — regex + walkdir (no subprocess), skip symlinks, boundary check
    // -----------------------------------------------------------------------

    #[tool(description = "Search file contents with regex")]
    async fn grep(
        &self,
        Parameters(params): Parameters<GrepParams>,
    ) -> Result<CallToolResult, McpError> {
        let subject = params.pattern.clone();

        if let Err(e) = self.sink.preflight(Operation::GrepSearch) {
            self.record_verdict(
                Operation::GrepSearch,
                &subject,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        match self.kernel_decide(Operation::GrepSearch, &subject).await {
            Ok(_decision_token) => {} // grep doesn't go through Sandbox I/O
            Err(result) => return Ok(result),
        }

        let proof = match self.guard.check(Operation::GrepSearch) {
            Ok(p) => p,
            Err(e) => {
                self.record_verdict(
                    Operation::GrepSearch,
                    &subject,
                    VerdictOutcome::Deny {
                        reason: format!("{e}"),
                    },
                );
                return Ok(err_result(e));
            }
        };

        let level = self.state.runtime.policy().capabilities.grep_search;
        if level == CapabilityLevel::Never {
            self.record_verdict(
                Operation::GrepSearch,
                &subject,
                VerdictOutcome::Deny {
                    reason: "grep_search capability is disabled".to_string(),
                },
            );
            return Ok(err_result("grep_search capability is disabled"));
        }

        let state = self.state.clone();
        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(move || -> Result<String, String> {
                let sandbox_root = state.runtime.sandbox().root_path();
                let sandbox_canonical = sandbox_root
                    .canonicalize()
                    .map_err(|e| format!("sandbox root error: {e}"))?;

                // Resolve search path within sandbox
                let search_path = if let Some(ref path) = params.path {
                    let p = std::path::Path::new(path);
                    if p.is_absolute() {
                        return Err(format!("absolute paths not allowed: {path}"));
                    }
                    let resolved = sandbox_root.join(path);
                    let canonical = resolved
                        .canonicalize()
                        .map_err(|e| format!("path resolution error: {e}"))?;
                    if !canonical.starts_with(&sandbox_canonical) {
                        return Err(format!("path escapes sandbox: {path}"));
                    }
                    canonical
                } else {
                    sandbox_canonical.clone()
                };

                let re = regex::Regex::new(&params.pattern)
                    .map_err(|e| format!("invalid regex: {e}"))?;

                let include_glob = params.include.as_deref();
                let ctx = params.context_lines.unwrap_or(0) as usize;
                let mut output = String::new();
                let mut match_count = 0usize;
                const MAX_MATCHES: usize = 5000;

                for entry in walkdir::WalkDir::new(&search_path)
                    .follow_links(false) // Never follow symlinks
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    // Skip symlinks explicitly
                    if entry.file_type().is_symlink() {
                        continue;
                    }
                    if !entry.file_type().is_file() {
                        continue;
                    }

                    // Verify canonical path is within sandbox
                    let canonical = match entry.path().canonicalize() {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    if !canonical.starts_with(&sandbox_canonical) {
                        continue;
                    }

                    // Apply include filter
                    if let Some(glob_pat) = include_glob {
                        let name = entry.file_name().to_string_lossy();
                        if !glob::Pattern::new(glob_pat)
                            .map(|p| p.matches(&name))
                            .unwrap_or(false)
                        {
                            continue;
                        }
                    }

                    // Read via sandbox cap-std (not raw std::fs) — #1273
                    let relative = match canonical.strip_prefix(&sandbox_canonical) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    let contents = match state.runtime.sandbox().read_to_string_for_search(relative)
                    {
                        Ok(c) => c,
                        Err(_) => continue, // Skip binary/unreadable files
                    };

                    let lines: Vec<&str> = contents.lines().collect();

                    for (i, line) in lines.iter().enumerate() {
                        if re.is_match(line) {
                            // Print context lines
                            let start = i.saturating_sub(ctx);
                            let end = std::cmp::min(i + ctx + 1, lines.len());
                            for (j, line_text) in lines[start..end].iter().enumerate() {
                                let abs_j = start + j;
                                let sep = if abs_j == i { ':' } else { '-' };
                                output.push_str(&format!(
                                    "{}{}{}:{}\n",
                                    relative.display(),
                                    sep,
                                    abs_j + 1,
                                    line_text
                                ));
                            }
                            if ctx > 0 && end < lines.len() {
                                output.push_str("--\n");
                            }
                            match_count += 1;
                            if match_count >= MAX_MATCHES {
                                output.push_str(&format!(
                                    "\n(truncated at {} matches)\n",
                                    MAX_MATCHES
                                ));
                                return Ok(output);
                            }
                        }
                    }
                }

                Ok(output)
            })
        }) {
            Ok(matches) => {
                self.record_verdict(Operation::GrepSearch, &subject, VerdictOutcome::Allow);
                Ok(CallToolResult::success(vec![Content::text(matches)]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::GrepSearch,
                    &subject,
                    VerdictOutcome::Error {
                        error: format!("{e}"),
                    },
                );
                Ok(err_result(e))
            }
        }
    }

    // -----------------------------------------------------------------------
    // web_fetch — unified security controls (identical to HTTP path)
    //
    // Enforces: URL validation, DNS allowlist, URL allowlist, MIME gating,
    // redirect target verification, and uninhabitable_state gate via GradedExposureGuard.
    // -----------------------------------------------------------------------

    #[tool(description = "Fetch a URL (HTTP GET/POST/PUT/DELETE)")]
    async fn web_fetch(
        &self,
        Parameters(params): Parameters<WebFetchParams>,
    ) -> Result<CallToolResult, McpError> {
        let subject = params.url.clone();

        if let Err(e) = self.sink.preflight(Operation::WebFetch) {
            self.record_verdict(
                Operation::WebFetch,
                &subject,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        match self.kernel_decide(Operation::WebFetch, &subject).await {
            Ok(_decision_token) => {} // web_fetch doesn't go through Sandbox I/O
            Err(result) => return Ok(result),
        }

        let proof = match self.guard.check(Operation::WebFetch) {
            Ok(p) => p,
            Err(e) => {
                self.record_verdict(
                    Operation::WebFetch,
                    &subject,
                    VerdictOutcome::Deny {
                        reason: format!("{e}"),
                    },
                );
                return Ok(err_result(e));
            }
        };

        let level = self.state.runtime.policy().capabilities.web_fetch;
        if level == CapabilityLevel::Never {
            self.record_verdict(
                Operation::WebFetch,
                &subject,
                VerdictOutcome::Deny {
                    reason: "web_fetch capability is disabled".to_string(),
                },
            );
            return Ok(err_result("web_fetch capability is disabled"));
        }

        // Input validation (scheme, length, null bytes) — shared with HTTP path
        if let Err(e) = crate::web_fetch_policy::validate_url(&params.url) {
            self.record_verdict(
                Operation::WebFetch,
                &subject,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        // Parse URL
        let parsed_url = match url::Url::parse(&params.url) {
            Ok(u) => u,
            Err(e) => {
                let msg = format!("invalid URL: {e}");
                self.record_verdict(
                    Operation::WebFetch,
                    &subject,
                    VerdictOutcome::Deny {
                        reason: msg.clone(),
                    },
                );
                return Ok(err_result(msg));
            }
        };

        // DNS allowlist — shared with HTTP path (fixed port-matching logic)
        {
            let host = match parsed_url.host_str() {
                Some(h) => h,
                None => {
                    self.record_verdict(
                        Operation::WebFetch,
                        &subject,
                        VerdictOutcome::Deny {
                            reason: "URL has no host".to_string(),
                        },
                    );
                    return Ok(err_result("URL has no host"));
                }
            };
            let port = parsed_url.port_or_known_default().unwrap_or(443);
            if let Err(e) =
                crate::web_fetch_policy::check_dns_allowlist(&self.state.dns_allow, host, port)
            {
                warn!(host = host, port = port, "DNS not in allow-list");
                self.record_verdict(
                    Operation::WebFetch,
                    &subject,
                    VerdictOutcome::Deny {
                        reason: e.to_string(),
                    },
                );
                return Ok(err_result(e));
            }
        }

        // URL allowlist — shared with HTTP path (was missing from MCP)
        if let Err(e) =
            crate::web_fetch_policy::check_url_allowlist(&self.state.url_allow, parsed_url.as_str())
        {
            self.record_verdict(
                Operation::WebFetch,
                &subject,
                VerdictOutcome::Deny {
                    reason: e.to_string(),
                },
            );
            return Ok(err_result(e));
        }

        let method = params.method.as_deref().unwrap_or("GET");
        let client = &self.state.web_client;

        let request = match method.to_uppercase().as_str() {
            "GET" => client.get(&params.url),
            "POST" => client.post(&params.url),
            "PUT" => client.put(&params.url),
            "DELETE" => client.delete(&params.url),
            _ => {
                let msg = format!("unsupported method: {method}");
                self.record_verdict(
                    Operation::WebFetch,
                    &subject,
                    VerdictOutcome::Deny {
                        reason: msg.clone(),
                    },
                );
                return Ok(err_result(msg));
            }
        };

        // Perform async fetch with full security controls.
        // NOTE: The fetch happens before execute_and_record() intentionally.
        // execute_and_record's purpose is TOCTOU detection (checking if exposure
        // changed between check() and record). The closure runs WITHOUT holding
        // locks, so completing the async I/O first minimizes the TOCTOU window.
        let max_bytes = self.state.web_fetch_max_bytes;
        let dns_allow = self.state.dns_allow.clone();
        let url_allow = self.state.url_allow.clone();
        let fetch_result: Result<String, String> = async {
            let resp = request
                .send()
                .await
                .map_err(|e| format!("fetch failed: {e}"))?;
            let status = resp.status().as_u16();

            // Verify redirect target is still in allowlist
            let final_url = resp.url().clone();
            crate::web_fetch_policy::check_redirect_target(&dns_allow, &url_allow, &final_url)
                .map_err(|e| format!("redirect target blocked: {e}"))?;

            // MIME type gating — was missing from MCP path
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            crate::web_fetch_policy::check_mime_type(content_type)?;

            let bytes = resp
                .bytes()
                .await
                .map_err(|e| format!("body read failed: {e}"))?;
            let truncated = bytes.len() > max_bytes;
            let body = String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), max_bytes)]);
            let suffix = if truncated { "\n(truncated)" } else { "" };
            Ok(format!("HTTP {status}\n\n{body}{suffix}"))
        }
        .await;

        match self.guard.execute_and_record(proof, || fetch_result) {
            Ok(response) => {
                self.record_verdict(Operation::WebFetch, &subject, VerdictOutcome::Allow);
                Ok(CallToolResult::success(vec![Content::text(response)]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::WebFetch,
                    &subject,
                    VerdictOutcome::Error {
                        error: format!("{e}"),
                    },
                );
                Ok(err_result(e))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for NucleusMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_server_info(Implementation::new(
                "nucleus-tool-proxy",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Nucleus tool-proxy MCP server. Operations enforced by the permission lattice.",
            )
    }
}

/// Run the MCP server on stdin/stdout.
pub async fn run_mcp_server(state: Arc<AppState>) -> Result<(), crate::ApiError> {
    info!("starting MCP server mode (stdio transport)");

    let sink = state.verdict_sink.clone();
    let server = NucleusMcpServer::new(state, sink);
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

/// Build an [`ActionTerm`] from an `(Operation, subject)` pair.
///
/// Delegates to the canonical [`ActionTerm::from_operation`] (#1292).
fn build_action_term(operation: Operation, subject: &str) -> ActionTerm {
    ActionTerm::from_operation(operation, subject)
}
