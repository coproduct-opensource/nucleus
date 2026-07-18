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
use portcullis::{
    CapabilityLevel, FlowTracker, GradedExposureGuard, NodeKind, Operation, ToolCallGuard,
};
// Sealed discharge preflight (#2038): the live RunBash path must mint a
// `DischargedBundle` before it may spawn. The bundle-minting itself
// (`preflight_runbash`) now lives in `crate::run_gate` (shared with the HTTP
// handler); here we only need the result/bundle types it returns.
use nucleus_ifc_kernel::discharge::PreflightResult;
// Sealed net-egress effect home (B5): the `.fetch()` trait method that performs
// the one raw reqwest send lives behind this trait in `portcullis-effects`.
use portcullis_effects::NetEffect;
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
    // rmcp 1.6's `#[tool_router]` macro stopped reading this field directly;
    // it's still required for the macro's `Self::tool_router()` ctor to bind.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    /// Session-scoped exposure-tracking guard (graded monad).
    guard: Arc<GradedExposureGuard>,
    /// Shared verdict sink for lockdown enforcement + telemetry.
    sink: Arc<dyn VerdictSink>,
    /// Kernel decision engine for complete mediation.
    kernel: Arc<tokio::sync::Mutex<Kernel>>,
    /// Session-scoped information-flow tracker (#1633). Tool entry points
    /// `observe` the data they bring in (`web_fetch` ⇒ `WebContent`,
    /// `read`/`glob`/`grep` ⇒ `FileRead`); the kernel consults it via
    /// `decide_term_with_flow` so that once adversarial (web) content is in the
    /// session, outbound actions are denied with `IfcUnsafe` — the lethal
    /// trifecta, enforced in the live Rust runtime (parity with the Python SDK).
    flow_tracker: Arc<tokio::sync::Mutex<FlowTracker>>,
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
            flow_tracker: Arc::new(tokio::sync::Mutex::new(FlowTracker::new())),
        }
    }

    /// Observe a data-ingest node in the session flow tracker (#1633).
    ///
    /// Called by input tool entry points after a successful fetch/read so the
    /// kernel's `decide_term_with_flow` consult sees the taint on subsequent
    /// outbound actions. FAIL-CLOSED (most-paranoid #3): if the observation
    /// fails, the data-ingest node would be silently dropped — leaving taint
    /// untracked — so we poison the session instead, causing every subsequent
    /// kernel decision to deny until a human-authorized cleanse.
    ///
    /// InputsAuthorized brick 3: the caller passes the *actual ingested bytes*.
    /// Their SHA-256 is recomputed here (never read from an agent field) and
    /// recorded on the node via `observe_with_content_hash`. Label/taint behaviour
    /// is identical to the old bare `observe` — only the content hash is added.
    async fn observe_flow(&self, kind: NodeKind, bytes: &[u8]) {
        let hash = crate::ingest_content_hash(bytes);
        let mut flow = self.flow_tracker.lock().await;
        if let Err(e) = flow.observe_with_content_hash(kind, hash) {
            flow.poison();
            warn!(?kind, error = %e, "flow-tracker observe failed — session poisoned (fail-closed)");
        }
    }

    /// Taint a tool RESULT as adversarial (most-paranoid next-bet #2): an
    /// embedded instruction in the result then cannot drive a subsequent
    /// privileged action (the next `run`/`git push`/`write`/`create_pr` hits the
    /// IFC egress gate, since `McpToolResult` is `Adversarial` ⇒ `is_tainted`).
    ///
    /// **Opt-in** via `NUCLEUS_PARANOID_TOOL_IO=1`. Off by default because
    /// blanket-tainting the proxy's own command output makes a session
    /// "one privileged action then locked" (run-tests → can't commit) — a policy
    /// choice an operator should make deliberately. The human-authorized
    /// `cleanse` path clears the taint when on.
    ///
    /// Brick 3: `result_bytes` are the *actual tool-result bytes* ingested into
    /// the session; their SHA-256 is content-addressed onto the `McpToolResult`
    /// node (recomputed from the real bytes, never an agent field).
    async fn observe_tool_result(&self, result_bytes: &[u8]) {
        let paranoid = std::env::var("NUCLEUS_PARANOID_TOOL_IO")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if paranoid {
            self.observe_flow(NodeKind::McpToolResult, result_bytes)
                .await;
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
        // Consult the session information-flow tracker (#1633): once the
        // session has ingested adversarial (web) content, outbound operations
        // are denied with `IfcUnsafe` before the normal decision path.
        let flow = self.flow_tracker.lock().await;
        let (decision, token) = kernel.decide_term_with_flow(term, Some(&flow));
        drop(flow);
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
        self.record_verdict_ext(operation, subject, outcome, BTreeMap::new());
    }

    /// Record a verdict with domain-specific `extensions` metadata.
    ///
    /// Used by the live RunBash gate (#2038) to thread the sealed
    /// `DischargedBundle` witness into the audit record so the bundle is consumed
    /// (not dead) and the discharge proof is durable in telemetry.
    fn record_verdict_ext(
        &self,
        operation: Operation,
        subject: &str,
        outcome: VerdictOutcome,
        extensions: BTreeMap<String, String>,
    ) {
        if let Err(e) = self.sink.record(VerdictContext {
            operation,
            subject: subject.to_string(),
            outcome,
            actor: ActorIdentity::StdioGuest,
            policy_rule: None,
            extensions,
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
                // IFC: a file read brings data into the session (Trusted
                // integrity — does not by itself taint, but contributes to the
                // confidentiality ceiling). (#1633)
                // Brick 3: content-address the exact bytes read.
                self.observe_flow(NodeKind::FileRead, contents.as_bytes())
                    .await;
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

        // ─── Sealed discharge gate (#2038, F8/F9/F6 dual-stack) ──────────────
        // PRECONDITION for `run_args`: mint the sealed 8-witness `DischargedBundle`.
        // Fail-closed on a Missing/Invalid session task token (verified_scope
        // None ⇒ InScopeWithTask denies) — never substitutes a permissive scope.
        // This runs ALONGSIDE the sink/kernel/guard checks above (not instead of
        // them). The `DischargedBundle` can only be built by `preflight_action`,
        // so reaching `run_args` past the `Allowed` arm is a compile-time-checked
        // authorization proof.
        let (discharge_note, discharge_bundle) = {
            let verified_scope = self.state.session_task_token.verified_scope();
            let run_bash_ceiling = self.state.runtime.policy().capabilities.run_bash;
            let flow = self.flow_tracker.lock().await;
            let result = preflight_runbash(verified_scope, run_bash_ceiling, &subject, &flow);
            drop(flow);
            match result {
                PreflightResult::Allowed(bundle) => {
                    // Keep the sealed bundle ALIVE: it is now the type-level proof
                    // required by `run_args` (executor-proof gate), and its
                    // `#[must_use]` is satisfied by both the audit witness and the
                    // spawn call below. Record the durable witness, then hand the
                    // bundle down to the spawn.
                    let note = discharge_witness(&bundle);
                    (note, bundle)
                }
                PreflightResult::Denied { reason, .. } => {
                    warn!(
                        subject = %subject,
                        %reason,
                        "discharge preflight DENIED RunBash — no run_args"
                    );
                    self.record_verdict(
                        Operation::RunBash,
                        &subject,
                        VerdictOutcome::Deny {
                            reason: format!("discharge denied: {reason}"),
                        },
                    );
                    return Ok(err_result(format!("discharge denied: {reason}")));
                }
                PreflightResult::RequiresApproval { reason } => {
                    warn!(
                        subject = %subject,
                        %reason,
                        "discharge preflight requires approval for RunBash — no run_args"
                    );
                    self.record_verdict(
                        Operation::RunBash,
                        &subject,
                        VerdictOutcome::Deny {
                            reason: format!("discharge requires approval: {reason}"),
                        },
                    );
                    return Ok(err_result(format!("discharge requires approval: {reason}")));
                }
            }
        };

        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(|| {
                self.state.runtime.executor().run_args(
                    &params.args,
                    params.stdin.as_deref(),
                    params.directory.as_deref(),
                    &decision_token,
                    // Executor-proof gate (#2038 → PR-2): the sealed bundle minted
                    // by `preflight_runbash` above is the type-level authorization.
                    // Reaching this spawn requires it, so no un-preflighted spawn
                    // can compile.
                    &discharge_bundle,
                )
            })
        }) {
            Ok(output) => {
                self.record_verdict_ext(
                    Operation::RunBash,
                    &subject,
                    VerdictOutcome::Allow,
                    BTreeMap::from([("discharge_bundle".to_string(), discharge_note.clone())]),
                );
                let run_result = RunResult {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                };
                let json = serde_json::to_string_pretty(&run_result).unwrap_or_default();
                // Most-paranoid #2: command output may carry injected instructions;
                // taint it (opt-in) so it can't drive a later privileged action.
                // Brick 3: content-address the exact tool-result bytes ingested.
                self.observe_tool_result(json.as_bytes()).await;
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => {
                self.record_verdict_ext(
                    Operation::RunBash,
                    &subject,
                    VerdictOutcome::Error {
                        error: format!("{e}"),
                    },
                    BTreeMap::from([("discharge_bundle".to_string(), discharge_note)]),
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
                // Brick 3: content-address the exact match listing ingested.
                let listing = paths.join("\n");
                self.observe_flow(NodeKind::FileRead, listing.as_bytes())
                    .await; // (#1633)
                Ok(CallToolResult::success(vec![Content::text(listing)]))
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
                // Brick 3: content-address the exact grep output ingested.
                self.observe_flow(NodeKind::FileRead, matches.as_bytes())
                    .await; // (#1633)
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
        let req_method = match method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
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

        // ─── Sealed discharge gate (B5, parity with the MCP RunBash handler) ──
        // PRECONDITION for the sealed `NetEffect::fetch`: mint the sealed
        // 8-witness `DischargedBundle` via `preflight_web`. Fail closed — a
        // Missing/Invalid session task token gives `verified_scope == None` ⇒
        // `InScopeWithTask` denies; an out-of-scope op denies. No bundle ⇒ the
        // handler returns its error and NEVER fetches (no wire egress).
        let discharge_bundle = {
            let verified_scope = self.state.session_task_token.verified_scope();
            let web_ceiling = self.state.runtime.policy().capabilities.web_fetch;
            let flow = self.flow_tracker.lock().await;
            let result = preflight_web(
                Operation::WebFetch,
                verified_scope,
                web_ceiling,
                &subject,
                &flow,
            );
            drop(flow);
            match result {
                PreflightResult::Allowed(bundle) => bundle,
                PreflightResult::Denied { reason, .. }
                | PreflightResult::RequiresApproval { reason } => {
                    warn!(subject = %subject, %reason, "discharge preflight DENIED web_fetch — no fetch");
                    self.record_verdict(
                        Operation::WebFetch,
                        &subject,
                        VerdictOutcome::Deny {
                            reason: format!("discharge denied: {reason}"),
                        },
                    );
                    return Ok(err_result(format!("discharge denied: {reason}")));
                }
            }
        };
        let _discharge_note = discharge_witness(&discharge_bundle);

        // Perform async fetch with full security controls.
        // NOTE: The fetch happens before execute_and_record() intentionally.
        // execute_and_record's purpose is TOCTOU detection (checking if exposure
        // changed between check() and record). The closure runs WITHOUT holding
        // locks, so completing the async I/O first minimizes the TOCTOU window.
        let max_bytes = self.state.web_fetch_max_bytes;
        let dns_allow = self.state.dns_allow.clone();
        let url_allow = self.state.url_allow.clone();
        // The raw reqwest send now lives in the sealed home (`NetEffect::fetch`);
        // the bundle minted above is the type-level authorization, and
        // `PolicyEnforced` re-checks `web_fetch` inside it.
        let effects = portcullis_effects::production_effects_concrete(crate::core_capabilities(
            &self.state.runtime.policy().capabilities,
        ));
        let fetch_result: Result<String, String> = async {
            let resp = effects
                .fetch(
                    &self.state.web_client,
                    portcullis_effects::NetCapability::WebFetch,
                    req_method,
                    parsed_url,
                    &[],
                    None,
                    None,
                    &discharge_bundle,
                )
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

            // Bounded streaming read: never allocate the whole upstream body, so a
            // malicious page cannot OOM-kill the enforcement process (audit H-1).
            let (bytes, truncated) = crate::read_body_capped(resp, max_bytes)
                .await
                .map_err(|e| format!("body read failed: {e}"))?;
            let body = String::from_utf8_lossy(&bytes);
            let suffix = if truncated { "\n(truncated)" } else { "" };
            Ok(format!("HTTP {status}\n\n{body}{suffix}"))
        }
        .await;

        match self.guard.execute_and_record(proof, || fetch_result) {
            Ok(response) => {
                self.record_verdict(Operation::WebFetch, &subject, VerdictOutcome::Allow);
                // IFC: web content is adversarial-integrity — observing it
                // taints the session, so subsequent outbound actions are denied
                // with `IfcUnsafe` (lethal-trifecta guard). (#1633)
                // Brick 3: content-address the exact fetched response ingested.
                self.observe_flow(NodeKind::WebContent, response.as_bytes())
                    .await;
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

// The sealed discharge preflight (`preflight_runbash`) and its audit-witness
// helper (`discharge_witness`) now live in the always-compiled `crate::run_gate`
// module, so the non-feature-gated HTTP `/v1/run` handler can share them with
// this feature-gated MCP handler. Re-imported here so the local call sites and
// the `#[cfg(test)]` module below resolve them unchanged.
use crate::run_gate::{discharge_witness, preflight_runbash, preflight_web};

// ═══════════════════════════════════════════════════════════════════════════
// Tests — enforcement boundary coverage (#1295)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    // The `preflight_runbash` scope tests build `TokenScope`s directly; its home
    // crate import is test-only now that the mint helper moved to `run_gate`.
    use nucleus_provenance_memory::TokenScope;

    // ── build_action_term coverage ──────────────────────────────────────

    #[test]
    fn build_term_read_files() {
        let term = build_action_term(Operation::ReadFiles, "/workspace/main.rs");
        assert_eq!(term.operation(), Operation::ReadFiles);
        assert_eq!(term.subject(), "/workspace/main.rs");
    }

    #[test]
    fn build_term_write_files() {
        let term = build_action_term(Operation::WriteFiles, "/workspace/output.txt");
        assert_eq!(term.operation(), Operation::WriteFiles);
    }

    #[test]
    fn build_term_run_bash() {
        let term = build_action_term(Operation::RunBash, "cargo test");
        assert_eq!(term.operation(), Operation::RunBash);
        assert_eq!(term.subject(), "cargo test");
    }

    #[test]
    fn build_term_web_fetch() {
        let term = build_action_term(Operation::WebFetch, "https://example.com");
        assert_eq!(term.operation(), Operation::WebFetch);
    }

    #[test]
    fn build_term_git_push() {
        let term = build_action_term(Operation::GitPush, "origin");
        assert_eq!(term.operation(), Operation::GitPush);
    }

    #[test]
    fn build_term_git_commit() {
        let term = build_action_term(Operation::GitCommit, "fix: update config");
        assert_eq!(term.operation(), Operation::GitCommit);
    }

    #[test]
    fn build_term_glob_search() {
        let term = build_action_term(Operation::GlobSearch, "src/**/*.rs");
        assert_eq!(term.operation(), Operation::GlobSearch);
    }

    #[test]
    fn build_term_grep_search_maps_to_glob() {
        // GrepSearch maps to GlobSearch PrimitiveAction (same file-pattern semantic)
        let term = build_action_term(Operation::GrepSearch, "TODO");
        assert_eq!(term.operation(), Operation::GlobSearch);
    }

    #[test]
    fn build_term_create_pr() {
        let term = build_action_term(Operation::CreatePr, "feat: add feature");
        assert_eq!(term.operation(), Operation::CreatePr);
    }

    #[test]
    fn build_term_spawn_agent() {
        let term = build_action_term(Operation::SpawnAgent, "http://child-agent");
        assert_eq!(term.operation(), Operation::SpawnAgent);
    }

    #[test]
    fn build_term_manage_pods() {
        let term = build_action_term(Operation::ManagePods, "pod-123");
        assert_eq!(term.operation(), Operation::SpawnAgent); // ManagePods maps to SpawnAgent
    }

    // ── ActionTerm derives correct obligations ─────────────────────────

    #[test]
    fn read_term_derives_path_allowed() {
        let term = build_action_term(Operation::ReadFiles, "/workspace/file.rs");
        let obs = term.derive_obligations();
        assert!(
            obs.iter()
                .any(|o| matches!(o, portcullis::action_term::ProofObligation::FsPathAllowed)),
            "ReadFiles should derive FsPathAllowed"
        );
    }

    #[test]
    fn web_fetch_term_does_not_derive_path_allowed() {
        let term = build_action_term(Operation::WebFetch, "https://example.com");
        let obs = term.derive_obligations();
        assert!(
            !obs.iter()
                .any(|o| matches!(o, portcullis::action_term::ProofObligation::FsPathAllowed)),
            "WebFetch should NOT derive FsPathAllowed"
        );
    }

    #[test]
    fn all_terms_derive_delegation_ceiling() {
        // Every operation should derive WithinDelegationCeiling
        let ops = [
            Operation::ReadFiles,
            Operation::WriteFiles,
            Operation::RunBash,
            Operation::WebFetch,
            Operation::GitPush,
            Operation::GitCommit,
            Operation::GlobSearch,
            Operation::GrepSearch,
            Operation::CreatePr,
            Operation::SpawnAgent,
        ];
        for op in ops {
            let term = build_action_term(op, "test");
            let obs = term.derive_obligations();
            assert!(
                obs.iter().any(|o| matches!(
                    o,
                    portcullis::action_term::ProofObligation::WithinDelegationCeiling
                )),
                "{op:?} should derive WithinDelegationCeiling"
            );
        }
    }

    // ── Live RunBash discharge gate (#2038) ─────────────────────────────────
    //
    // `preflight_runbash` is the sole precondition standing between a RunBash
    // request and `Executor::run_args`: the handler only spawns past its
    // `Allowed` arm. Anything other than `Allowed` means the handler returns
    // early and NEVER calls `run_args` (no process is spawned). These tests
    // exercise that decision directly at all three cases. A clean session
    // (`FlowTracker::new()`) is used so the five original obligations are
    // vacuously satisfied and `InScopeWithTask` is the discriminating gate.

    /// The RunBash policy ceiling supplied by the handler; its exact value is
    /// immaterial to these tests because `requested == ceiling` (honest
    /// no-escalation) makes `WithinDelegationCeiling` pass for any level.
    const RUN_BASH_CEILING: CapabilityLevel = CapabilityLevel::LowRisk;

    // (a) Missing/Invalid session token ⇒ verified_scope() is None ⇒ the gate
    //     DENIES fail-closed (no-vacuous-witness) ⇒ run_args is never reached.
    #[test]
    fn runbash_denies_when_session_token_missing_or_invalid() {
        let flow = FlowTracker::new();
        // `SessionTaskToken::Missing` and `::Invalid` both return `None` from
        // `verified_scope()` (see session_token.rs) — modeled here as `None`.
        let result = preflight_runbash(None, RUN_BASH_CEILING, "rm -rf /", &flow);
        assert!(
            result.is_denied(),
            "no verified scope must DENY RunBash (fail-closed), got {result:?}"
        );
        assert!(
            result.denial_reason().unwrap().contains("InScopeWithTask"),
            "denial must be the InScopeWithTask no-vacuous-witness guard: {result:?}"
        );
        assert!(!result.is_allowed(), "must not mint a bundle ⇒ no run_args");
    }

    // (b) A verified token whose scope does NOT include RunBash ⇒ InScopeWithTask
    //     DENIES ⇒ run_args is never reached.
    #[test]
    fn runbash_denies_when_out_of_token_scope() {
        let flow = FlowTracker::new();
        // Verified, but RunBash ∉ allowed_operations.
        let scope = TokenScope::new(
            vec![Operation::ReadFiles, Operation::GlobSearch],
            vec!["/workspace/**".to_string()],
        );
        let result = preflight_runbash(Some(&scope), RUN_BASH_CEILING, "cargo test", &flow);
        assert!(
            result.is_denied(),
            "RunBash out of token scope must DENY, got {result:?}"
        );
        assert!(
            result.denial_reason().unwrap().contains("InScopeWithTask"),
            "denial must be InScopeWithTask: {result:?}"
        );
        assert!(!result.is_allowed(), "must not mint a bundle ⇒ no run_args");
    }

    // (c) A verified, in-scope token ⇒ the gate ALLOWS and mints the sealed
    //     `DischargedBundle` ⇒ the handler proceeds to run_args.
    #[test]
    fn runbash_succeeds_with_valid_in_scope_token() {
        let flow = FlowTracker::new();
        let scope = TokenScope::new(
            vec![Operation::RunBash, Operation::ReadFiles],
            vec!["/workspace/**".to_string()],
        );
        let result = preflight_runbash(Some(&scope), RUN_BASH_CEILING, "cargo test", &flow);
        assert!(
            result.is_allowed(),
            "valid in-scope token must ALLOW RunBash (reach run_args), got {result:?}"
        );
        // The Allowed bundle is the sealed 8-witness proof the handler consumes.
        let bundle = result.unwrap_bundle();
        assert!(
            discharge_witness(&bundle).contains("in_scope_with_task"),
            "bundle must carry the InScopeWithTask witness"
        );
    }
}
