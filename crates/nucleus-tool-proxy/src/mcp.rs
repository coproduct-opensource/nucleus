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
//!
//! # Why there is no per-request certificate attenuation here (#2784-adjacent, ADR 0006 C2.0)
//!
//! The HTTP path narrows every gate by the delegation certificate the request
//! carried: `AppState::ceiling` folds `CertifiedPermissions` into a three-way
//! meet (boot ∧ market-effective ∧ chain-verified). This path does not, and
//! that is a property of the transport rather than an omission.
//!
//! A delegation certificate is only honoured on a tier that binds an identity
//! for its leaf to be checked against. `pod_cert::delegation_authority` returns
//! `Bound` for `AuthMethod::SpiffeMtls` and nothing else, and
//! `evaluate_request_cert` refuses a certificate on any unbound tier — "no
//! identity to bind it to" (#2427). stdio has no `AuthMethod` at all: its trust
//! story is the sandbox proof established at boot, and every verdict here is
//! recorded against the fixed `ActorIdentity::StdioGuest`.
//!
//! So threading a certificate through would not be wiring an argument that was
//! forgotten; it would be honouring a certificate on an unbound tier, which is
//! exactly what #2427 deleted. The ceiling this path uses is therefore the boot
//! ceiling, obtained through [`stdio_ceiling`] so the decision is named in one
//! place. `stdio_has_no_bound_tier_to_attenuate_against` pins the premise: the
//! day stdio gains a bound tier, that test fails and this reasoning expires
//! loudly rather than silently going stale.
//!
//! This says nothing about the gates that are *not* identity-dependent. Those
//! were plain wiring gaps, and both are now closed: `validation::` runs here
//! too (the validator section below, pinned by
//! `http_and_stdio_validate_the_same_inputs`), and so does
//! `effect_gate::admit_http_recorded`, ADR 0004's per-effect
//! method+host+path gate (pinned by `http_and_stdio_web_fetch_run_the_same_gates`).
//! Neither needed an identity: the effect gate is a boot-time object built
//! from the pod's own certificate, not from a per-request one.

use std::collections::BTreeMap;
use std::sync::Arc;

use portcullis::action_term::ActionTerm;
use portcullis::flow_graph::FlowGraph;
use portcullis::kernel::{Kernel, Verdict};
use portcullis::verdict_sink::{ActorIdentity, VerdictContext, VerdictOutcome, VerdictSink};
use portcullis::{
    Act, Argv, CapabilityLevel, Endpoint, FilePath, GradedExposureGuard, NodeKind, Operation,
    Pattern, ReadSink, ToolCallGuard, WriteSink,
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
    ErrorData as McpError, ServerHandler, ServiceExt, handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, tool, tool_handler, tool_router,
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
    /// Session-scoped information-flow graph (#1633) — the single authoritative
    /// graph the kernel consults via `decide_term_with_flow`. Tool entry points
    /// `observe` the data they bring in (`web_fetch` ⇒ `WebContent`,
    /// `read`/`glob`/`grep` ⇒ `FileRead`); once adversarial (web) content is in
    /// the session, outbound actions are denied with `IfcUnsafe` — the lethal
    /// trifecta, enforced in the live Rust runtime. The MCP transport's own
    /// per-session graph, mirroring the HTTP path's `AppState::flow_graph` (Phase 2
    /// retirement: the former `FlowTracker` oracle is gone).
    flow_graph: Arc<tokio::sync::Mutex<FlowGraph>>,
}

/// Convert a tool-level error into a CallToolResult error.
fn err_result(msg: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![Content::text(format!("{msg}"))])
}

// ---------------------------------------------------------------------------
// Input validation (ADR 0006 C2.0)
// ---------------------------------------------------------------------------
//
// `crate::validation` is the tool-proxy's bound on unbounded input: pattern
// length and catastrophic backtracking, path length, argument count and total
// command size, stdin size, and null bytes anywhere. Every HTTP handler runs
// it "before any processing" — ahead of the kernel consult, the guard and the
// sandbox. This transport ran none of it, so the same tool reached the same
// sandbox with input the HTTP handler refuses: a multi-megabyte stdin, ten
// thousand argv entries, a path carrying an interior NUL, an `(a+)+` regex.
//
// Each function below is the check list of the HTTP handler it names, applied
// to this transport's parameter struct. The field names differ — `root` is
// glob's `directory`, `include` is grep's `file_glob` — but the checks do not.
//
// They run first in each handler, ahead of `sink.preflight`, matching HTTP's
// "before any processing" placement. Order is free here: `preflight` is a pure
// lockdown query with no snapshot and no state, so nothing downstream depends
// on having been asked first. What the choice buys is an accurate audit
// reason — a malformed call is recorded as `validation:`, not as a lockdown
// denial that happens to have been malformed too.
//
// They are free functions rather than handler-inline code so the property is
// testable without an `AppState`, which `tests/memory_ifc_e2e.rs` documents
// avoiding because it needs a sandbox/runtime.
//
// `http_and_stdio_validate_the_same_inputs` derives both check lists from
// source and asserts they are equal, in both directions. A check added to one
// path and not the other then fails rather than drifting apart quietly, which
// is how this gap opened. It compares the *set* of checks, not the number of
// call sites — grep runs `validate_pattern` twice on both paths, on `pattern`
// and on the file glob, and the set collapses that. The per-field behaviour is
// what the `stdio_*_refuses_what_http_*_refuses` tests cover.
//
// `validate_query` has no row: it belongs to `web_search`, which is an HTTP
// endpoint with no tool on this transport.
//
// `web_fetch` is the one tool that was already covered: it calls
// `web_fetch_policy::validate_url`, a one-line delegation to
// `validation::validate_url`. `web_fetch_was_already_covered` pins that
// delegation so the coverage stays real.

/// The input checks `read_file` runs before any gate.
fn validate_read_params(p: &ReadParams) -> Result<(), crate::validation::ValidationError> {
    crate::validation::validate_path(&p.path)
}

/// The input checks `write_file` runs before any gate.
///
/// `contents` is unbounded on both paths — the write size limit is the
/// sandbox's, not this module's.
fn validate_write_params(p: &WriteParams) -> Result<(), crate::validation::ValidationError> {
    crate::validation::validate_path(&p.path)
}

/// The input checks `run_command` runs before any gate.
fn validate_run_params(p: &RunParams) -> Result<(), crate::validation::ValidationError> {
    crate::validation::validate_command_args(&p.args)?;
    crate::validation::validate_stdin(p.stdin.as_deref())?;
    if let Some(directory) = &p.directory {
        crate::validation::validate_path(directory)?;
    }
    Ok(())
}

/// The input checks `glob_search` runs before any gate.
///
/// `GlobParams::root` is `GlobRequest::directory` under another name.
fn validate_glob_params(p: &GlobParams) -> Result<(), crate::validation::ValidationError> {
    crate::validation::validate_pattern(&p.pattern)?;
    if let Some(root) = &p.root {
        crate::validation::validate_path(root)?;
    }
    Ok(())
}

/// The input checks `grep_search` runs before any gate.
///
/// `GrepParams::include` is `GrepRequest::file_glob` under another name, and
/// is a pattern rather than a path on both paths.
fn validate_grep_params(p: &GrepParams) -> Result<(), crate::validation::ValidationError> {
    crate::validation::validate_pattern(&p.pattern)?;
    if let Some(path) = &p.path {
        crate::validation::validate_path(path)?;
    }
    if let Some(include) = &p.include {
        crate::validation::validate_pattern(include)?;
    }
    Ok(())
}

#[tool_router]
impl NucleusMcpServer {
    /// Create a new MCP server with session-scoped security enforcement.
    pub fn new(state: Arc<AppState>, sink: Arc<dyn VerdictSink>) -> Self {
        let tool_router = Self::tool_router();

        // Schema pinning: hash the tool list at session start for rug-pull detection
        let tool_schemas = format!("{:?}", tool_router.list_all());
        let policy = state.runtime.policy().clone();

        let kernel = Arc::new(tokio::sync::Mutex::new({
            let mut k = Kernel::new(policy.clone());
            // Same NUCLEUS_DLC_* provisioning as the HTTP path's kernel —
            // verified admission gates both transports or neither.
            if let Some(admission) = crate::dlc_admission::provision_from_env() {
                k.set_dlc_admission(admission);
            }
            // Same governor declassification keys as the HTTP path: the token
            // path is live on both transports or neither. Node-controlled env
            // only; absent ⇒ fail-closed refusal of every token.
            let governor_keys = crate::declassify::governor_keys_from_env(
                std::env::var("NUCLEUS_DECLASSIFY_TRUSTED_KEYS")
                    .ok()
                    .as_deref(),
            );
            if !governor_keys.is_empty() {
                k.set_trusted_keys(governor_keys);
            }
            k
        }));

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
            flow_graph: Arc::new(tokio::sync::Mutex::new(FlowGraph::new())),
        }
    }

    /// Observe a data-ingest node in the session flow graph (#1633).
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
        // Single authoritative write onto the graph the egress verdict reads. MCP
        // ingests are always parent-less data sources. Fail-closed: a dropped
        // observe poisons the session so every subsequent decision denies (see
        // `ingest::observe_into_graph`).
        crate::ingest::observe_into_graph(&self.flow_graph, kind, false, hash).await;
    }

    /// Taint a tool RESULT as adversarial (most-paranoid next-bet #2): an
    /// embedded instruction in the result then cannot drive a subsequent
    /// privileged action (the next `run`/`git push`/`write`/`create_pr` hits the
    /// IFC egress gate, since `McpToolResult` is `Adversarial` ⇒ `is_tainted`).
    ///
    /// Tainted by DEFAULT when `command` could reach the network — see
    /// [`crate::ingest::command_output_is_external`] — and ALWAYS under
    /// `NUCLEUS_PARANOID_TOOL_IO=1`.
    ///
    /// The old default was off, because blanket-tainting the proxy's own command
    /// output makes a session "one privileged action then locked" (run-tests →
    /// can't commit). But that left `curl` inside `run` as an unmediated ingest,
    /// which is the most obvious one an agent has. Classifying per command pays
    /// the lock-out cost only where bytes actually came from outside. The
    /// human-authorized `cleanse` path clears the taint.
    ///
    /// Kept in lockstep with the HTTP twin `ingest::http_observe_command_output`:
    /// the two transports enforcing different policies under the same flag was a
    /// real defect once, and it is worth not reintroducing.
    ///
    /// Brick 3: `result_bytes` are the *actual tool-result bytes* ingested into
    /// the session; their SHA-256 is content-addressed onto the `McpToolResult`
    /// node (recomputed from the real bytes, never an agent field).
    async fn observe_tool_result(&self, command: &str, result_bytes: &[u8]) {
        if crate::ingest::should_observe_command_output(command) {
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
        // The live egress verdict reads the single authoritative `FlowGraph` (its
        // session aggregates). Once adversarial (web) content is in the session,
        // outbound operations are denied with `IfcUnsafe` before the normal
        // decision path.
        let graph = self.flow_graph.lock().await;
        let (decision, token) = kernel.decide_term_with_flow(term, Some(&*graph));
        drop(graph);
        drop(kernel);

        // ★ Record the kernel decision — allows AND refusals — BEFORE the match
        // below returns. The HTTP path had the same hole: every refusal returned
        // early, so the sink observed successes only and any evidence built on
        // it would have shown an all-allow history.
        crate::verdict_sink::record_kernel_decision(
            self.sink.as_ref(),
            &decision,
            operation,
            subject,
            ActorIdentity::StdioGuest,
            "mcp",
        );

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

    /// Refuse a call whose inputs the HTTP path would have refused.
    ///
    /// The HTTP handlers record a `Deny` verdict carrying the validation
    /// reason before returning, so a refused call is in the audit trail and
    /// not only in the client's response. This does the same, against this
    /// transport's fixed `ActorIdentity::StdioGuest`.
    fn refuse_invalid(
        &self,
        operation: Operation,
        subject: &str,
        e: crate::validation::ValidationError,
    ) -> CallToolResult {
        self.record_verdict(
            operation,
            subject,
            VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
        );
        err_result(e)
    }

    // -----------------------------------------------------------------------
    // read — uses Sandbox.read_to_string (cap-std kernel protection)
    // -----------------------------------------------------------------------

    #[tool(description = "Read a file from the pod workspace")]
    async fn read(
        &self,
        Parameters(params): Parameters<ReadParams>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = validate_read_params(&params) {
            return Ok(self.refuse_invalid(Operation::ReadFiles, &params.path, e));
        }

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

        // The guard now decides on the act, not the verb. `sink` says where
        // the read lands: this transport records every read on the verdict
        // sink, and nothing here persists it to memory or a cache.
        let act = Act::Read {
            path: FilePath::new(&params.path),
            sink: ReadSink::AuditLog,
        };
        let proof = match self.guard.check(&act) {
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

        // Discharge the eight obligations for the read. Previously this path
        // went straight to the sandbox with only the guard proof, so a read
        // never cleared the obligations `FileEffect::read` enforces.
        let read_bundle = {
            let verified_scope = self.state.session_task_token.verified_scope();
            let fs_ceiling = stdio_ceiling(&self.state, Operation::ReadFiles);
            let flow = self.flow_graph.lock().await;
            let result =
                crate::run_gate::preflight_read_fs(verified_scope, fs_ceiling, &params.path, &flow);
            drop(flow);
            match result {
                PreflightResult::Allowed(bundle) => bundle,
                PreflightResult::Denied { reason, .. }
                | PreflightResult::RequiresApproval { reason } => {
                    warn!(path = %params.path, %reason, "discharge preflight DENIED read — no read");
                    self.record_verdict(
                        Operation::ReadFiles,
                        &params.path,
                        VerdictOutcome::Deny {
                            reason: format!("discharge denied: {reason}"),
                        },
                    );
                    return Ok(err_result(format!("discharge denied: {reason}")));
                }
            }
        };
        let read_authority = portcullis_effects::authority::Authority::new(read_bundle);

        // The audit subject, taken from the proof before
        // `execute_and_record` consumes it: the record below names what the
        // guard decided on, not a string that travelled beside the decision.
        let checked = proof.subject();

        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(|| {
                self.state.runtime.sandbox().read_to_string(
                    &checked,
                    &decision_token,
                    read_authority,
                )
            })
        }) {
            Ok(contents) => {
                self.record_verdict(Operation::ReadFiles, &checked, VerdictOutcome::Allow);
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
                    &checked,
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
        if let Err(e) = validate_write_params(&params) {
            return Ok(self.refuse_invalid(Operation::WriteFiles, &params.path, e));
        }

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

        // `sink` says where the write lands: the pod workspace, through the
        // cap-std sandbox below. A write outside it is `WriteSink::System`,
        // which this handler cannot reach and therefore does not name.
        let act = Act::Write {
            path: FilePath::new(&params.path),
            sink: WriteSink::Workspace,
        };
        let proof = match self.guard.check(&act) {
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

        // ─── Sealed discharge gate (B6, parity with the MCP RunBash/web handlers)
        // PRECONDITION for the `_proof`-gated `Sandbox::write`: mint the sealed
        // 8-witness `DischargedBundle` via `preflight_fs`. Fail closed — a
        // Missing/Invalid session task token gives `verified_scope == None` ⇒
        // `InScopeWithTask` denies; an out-of-scope op denies. No bundle ⇒ the
        // handler returns its error and NEVER writes (cap-std is never reached).
        let discharge_bundle = {
            let verified_scope = self.state.session_task_token.verified_scope();
            let fs_ceiling = stdio_ceiling(&self.state, Operation::WriteFiles);
            let flow = self.flow_graph.lock().await;
            let result = preflight_fs(
                Operation::WriteFiles,
                verified_scope,
                fs_ceiling,
                &params.path,
                &flow,
            );
            drop(flow);
            match result {
                PreflightResult::Allowed(bundle) => bundle,
                PreflightResult::Denied { reason, .. }
                | PreflightResult::RequiresApproval { reason } => {
                    warn!(path = %params.path, %reason, "discharge preflight DENIED write — no write");
                    self.record_verdict(
                        Operation::WriteFiles,
                        &params.path,
                        VerdictOutcome::Deny {
                            reason: format!("discharge denied: {reason}"),
                        },
                    );
                    return Ok(err_result(format!("discharge denied: {reason}")));
                }
            }
        };
        let _discharge_note = discharge_witness(&discharge_bundle);

        // The audit subject, taken from the proof before
        // `execute_and_record` consumes it: the record below names what the
        // guard decided on, not a string that travelled beside the decision.
        let checked = proof.subject();

        match self.guard.execute_and_record(proof, || {
            tokio::task::block_in_place(|| {
                self.state.runtime.sandbox().write(
                    &checked,
                    params.contents.as_bytes(),
                    &decision_token,
                    portcullis_effects::authority::Authority::new(discharge_bundle),
                )
            })
        }) {
            Ok(()) => {
                self.record_verdict(Operation::WriteFiles, &checked, VerdictOutcome::Allow);
                Ok(CallToolResult::success(vec![Content::text("ok")]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::WriteFiles,
                    &checked,
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

        if let Err(e) = validate_run_params(&params) {
            return Ok(self.refuse_invalid(Operation::RunBash, &subject, e));
        }

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

        // The argv, not the joined string: the guard sees the command as it
        // will be spawned, with no shell-quoting round trip in between.
        let act = Act::Run {
            argv: Argv::new(params.args.clone()),
        };
        let proof = match self.guard.check(&act) {
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
            let run_bash_ceiling = stdio_ceiling(&self.state, Operation::RunBash);
            let flow = self.flow_graph.lock().await;
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

        // The audit subject, taken from the proof before
        // `execute_and_record` consumes it: the record below names what the
        // guard decided on, not a string that travelled beside the decision.
        let checked = proof.subject();

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
                    portcullis_effects::authority::Authority::new(discharge_bundle),
                )
            })
        }) {
            Ok(output) => {
                self.record_verdict_ext(
                    Operation::RunBash,
                    &checked,
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
                self.observe_tool_result(&checked, json.as_bytes()).await;
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => {
                self.record_verdict_ext(
                    Operation::RunBash,
                    &checked,
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

        if let Err(e) = validate_glob_params(&params) {
            return Ok(self.refuse_invalid(Operation::GlobSearch, &subject, e));
        }

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

        let act = Act::Glob {
            pattern: Pattern::new(&params.pattern),
            sink: ReadSink::AuditLog,
        };
        let proof = match self.guard.check(&act) {
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

        // The audit subject, taken from the proof before
        // `execute_and_record` consumes it: the record below names what the
        // guard decided on, not a string that travelled beside the decision.
        let checked = proof.subject();

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
                self.record_verdict(Operation::GlobSearch, &checked, VerdictOutcome::Allow);
                // Brick 3: content-address the exact match listing ingested.
                let listing = paths.join("\n");
                self.observe_flow(NodeKind::FileRead, listing.as_bytes())
                    .await; // (#1633)
                Ok(CallToolResult::success(vec![Content::text(listing)]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::GlobSearch,
                    &checked,
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

        if let Err(e) = validate_grep_params(&params) {
            return Ok(self.refuse_invalid(Operation::GrepSearch, &subject, e));
        }

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

        let act = Act::Grep {
            pattern: Pattern::new(&params.pattern),
            sink: ReadSink::AuditLog,
        };
        let proof = match self.guard.check(&act) {
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
        // The graph this transport actually writes. `observe_flow` records into
        // `self.flow_graph`, and every other preflight on this path reads it;
        // the closure below is `move` and would otherwise only have `state`.
        // The audit subject, taken from the proof before
        // `execute_and_record` consumes it: the record below names what the
        // guard decided on, not a string that travelled beside the decision.
        let checked = proof.subject();

        let flow_graph = self.flow_graph.clone();
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
                    // One discharge per file: an `Authority` buys one read, so a
                    // search over N files needs N of them. Minting outside the
                    // loop would be the replay the by-value cutover removed.
                    let search_authority = {
                        let verified_scope = state.session_task_token.verified_scope();
                        let ceiling = stdio_ceiling(&state, Operation::GrepSearch);
                        // `blocking_lock` rather than `.await`: this loop runs
                        // inside `block_in_place`, which exists precisely to allow
                        // blocking calls off the async executor.
                        //
                        // `flow_graph`, NOT `state.flow_graph`. This is the one
                        // site on the MCP path that read the latter, and under
                        // `--mcp` no HTTP handler ever runs, so that graph is
                        // permanently empty and `NoAdversarialAncestry` below was
                        // vacuous — grep was the only MCP effect whose taint check
                        // could not fire. Same class as the Phase 4.5 re-home in
                        // `declassify.rs`: "the graph the live egress verdict reads
                        // — not the kernel's separate, never-populated one".
                        let flow = flow_graph.blocking_lock();
                        let r = crate::run_gate::preflight_grep_fs(
                            verified_scope,
                            ceiling,
                            &relative.display().to_string(),
                            &flow,
                        );
                        drop(flow);
                        match r {
                            PreflightResult::Allowed(b) => {
                                portcullis_effects::authority::Authority::new(b)
                            }
                            // A file this session may not read is skipped, exactly
                            // as an unreadable one is — the search returns fewer
                            // hits rather than failing the whole request.
                            _ => continue,
                        }
                    };
                    let contents = match state
                        .runtime
                        .sandbox()
                        .read_to_string_for_search(relative, search_authority)
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
                self.record_verdict(Operation::GrepSearch, &checked, VerdictOutcome::Allow);
                // Brick 3: content-address the exact grep output ingested.
                self.observe_flow(NodeKind::FileRead, matches.as_bytes())
                    .await; // (#1633)
                Ok(CallToolResult::success(vec![Content::text(matches)]))
            }
            Err(e) => {
                self.record_verdict(
                    Operation::GrepSearch,
                    &checked,
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

        // ─── The endpoint, parsed once ──────────────────────────────────────
        //
        // Everything above this line established the components: the scheme
        // and host and port and path from one `Url::parse`, the method from
        // one `from_bytes`. `Endpoint` carries that result, and the gates
        // below read it instead of re-deriving it from the string — which is
        // the whole reason `Act` exists. `Act::Fetch`'s sink is not a choice:
        // a fetch is `HTTPEgress`, and no other sink is representable for it.
        //
        // The guard check moved down to here from above the parse. It has
        // always been a decision about a request; before, all it was told was
        // that *a* fetch was happening, and the URL travelled past it into the
        // audit record. Nothing between the old position and this one touches
        // the wire — the allowlists and the per-effect gate below are refusals,
        // and the fetch itself happens inside `execute_and_record`, whose
        // TOCTOU window is measured from this check and is unchanged.
        let act = Act::Fetch {
            endpoint: Endpoint::new(
                req_method.as_str(),
                parsed_url.scheme(),
                parsed_url.host_str().unwrap_or_default(),
                parsed_url.port_or_known_default().unwrap_or(443),
                parsed_url.path(),
                // The raw form is `params.url`, not `parsed_url.as_str()`.
                // `Url::parse` normalises — lower-casing the host, adding a
                // trailing slash — and the audit trail should say what the
                // client asked for. The gates read the parsed components
                // above; only the record reads this.
                &subject,
            ),
        };
        let proof = match self.guard.check(&act) {
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

        // Per-effect gate (ADR 0004): when the pod's certificate carries an
        // effect dimension, a granted effect must vouch for method + host +
        // path, not merely the host — a grant of `read-ci-logs` must not open
        // a pull request. Refused here, before any discharge is minted, which
        // is where the HTTP handler refuses it too.
        //
        // Nothing about this gate is per-request. `EffectGate::new` reads the
        // pod's own certificate once, at `AppState` construction; the object
        // in `self.state` is the same one the HTTP handler consults. That is
        // what separates it from the per-request attenuation the module header
        // declines: this needed an argument threaded, not an identity this
        // transport does not have.
        //
        // `admit_http_recorded` records the refusal on the sink itself, with
        // `policy_rule = EFFECT_NOT_GRANTED`, so this arm must not record a
        // second verdict for the same call.
        if let Err(e) = self.state.effect_gate.admit_http_recorded(
            req_method.as_str(),
            &parsed_url,
            self.sink.as_ref(),
            ActorIdentity::StdioGuest,
        ) {
            return Ok(err_result(e));
        }

        // ─── Sealed discharge gate (B5, parity with the MCP RunBash handler) ──
        // PRECONDITION for the sealed `NetEffect::fetch`: mint the sealed
        // 8-witness `DischargedBundle` via `preflight_web`. Fail closed — a
        // Missing/Invalid session task token gives `verified_scope == None` ⇒
        // `InScopeWithTask` denies; an out-of-scope op denies. No bundle ⇒ the
        // handler returns its error and NEVER fetches (no wire egress).
        let discharge_bundle = {
            let verified_scope = self.state.session_task_token.verified_scope();
            let web_ceiling = stdio_ceiling(&self.state, Operation::WebFetch);
            let flow = self.flow_graph.lock().await;
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
                    portcullis_effects::authority::Authority::new(discharge_bundle),
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
            crate::web_fetch_policy::check_mime_type(
                content_type,
                self.state.web_fetch_mime_allow.as_deref(),
            )?;

            // Bounded streaming read: never allocate the whole upstream body, so a
            // malicious page cannot OOM-kill the enforcement process (audit H-1).
            let (bytes, truncated) = crate::web_fetch_policy::read_body_capped(resp, max_bytes)
                .await
                .map_err(|e| format!("body read failed: {e}"))?;
            let body = String::from_utf8_lossy(&bytes);
            let suffix = if truncated { "\n(truncated)" } else { "" };
            Ok(format!("HTTP {status}\n\n{body}{suffix}"))
        }
        .await;

        // The audit subject, taken from the proof before
        // `execute_and_record` consumes it: the record below names what the
        // guard decided on, not a string that travelled beside the decision.
        let checked = proof.subject();

        match self.guard.execute_and_record(proof, || fetch_result) {
            Ok(response) => {
                self.record_verdict(Operation::WebFetch, &checked, VerdictOutcome::Allow);
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
                    &checked,
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
use crate::run_gate::{discharge_witness, preflight_fs, preflight_runbash, preflight_web};

// ═══════════════════════════════════════════════════════════════════════════
// Tests — enforcement boundary coverage (#1295)
// ═══════════════════════════════════════════════════════════════════════════

/// The gate ceiling for `op` on the stdio transport.
///
/// The `None` is the decision, not an oversight: there is no per-request
/// delegation certificate on this transport to attenuate against, and there
/// cannot be one until stdio gains a tier that binds an identity. See the
/// module header. Named so the argument carries its reason, rather than
/// appearing five times as a literal someone might take for an omission.
fn stdio_ceiling(state: &crate::AppState, op: Operation) -> crate::run_gate::GateLevels {
    crate::run_gate::levels_for(state, op, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    // The `preflight_runbash` scope tests build `TokenScope`s directly; its home
    // crate import is test-only now that the mint helper moved to `run_gate`.
    use nucleus_provenance_memory::TokenScope;

    // ── the premise behind `stdio_ceiling` ──────────────────────────────

    /// The module header argues this transport *cannot* carry per-request
    /// certificate attenuation, because a delegation certificate is only
    /// honoured on a tier that binds an identity and stdio has no tier at all.
    ///
    /// That argument is only sound while `SpiffeMtls` is the sole bound tier.
    /// If a future tier becomes `Bound` — a signed stdio handshake, a peer-cred
    /// socket promoted to carry identity — then `stdio_ceiling`'s `None` stops
    /// being a property of the transport and becomes a real gap. This fails on
    /// that day, so the reasoning expires loudly instead of quietly going
    /// stale, which is the failure mode `law-mechanisms-manifest.txt` exists
    /// for: a stated reason nothing rechecks.
    ///
    /// Exhaustive over `AuthMethod` on purpose: a new variant that is `Bound`
    /// must be considered here, and a new `Unbound` one costs a line.
    #[test]
    fn stdio_has_no_bound_tier_to_attenuate_against() {
        use crate::auth::AuthMethod;
        use crate::pod_cert::{DelegationAuthority, delegation_authority};

        for method in [
            AuthMethod::Hmac,
            AuthMethod::HmacDrand,
            AuthMethod::HostVsock,
            AuthMethod::Ed25519Drand,
        ] {
            assert_eq!(
                delegation_authority(&method),
                DelegationAuthority::Unbound,
                "{method:?} became a bound tier. If stdio can now reach it, \
                 `stdio_ceiling`'s `None` is no longer a property of the \
                 transport and the module header's reasoning must be revisited"
            );
        }

        assert_eq!(
            delegation_authority(&AuthMethod::SpiffeMtls),
            DelegationAuthority::Bound,
            "non-vacuity: if nothing is Bound, the loop above proves nothing"
        );
    }

    // ── input validation parity with the HTTP path ──────────────────────

    /// Strip `//` lines, then collect every `validate_*` reached through the
    /// `validation::` module in `body`.
    ///
    /// Comments go first because the doc blocks on both paths name these
    /// functions in prose — the same false positive `.dead-code-ratchet.toml`
    /// records its counter hitting inside string literals.
    fn validation_calls(body: &str) -> std::collections::BTreeSet<String> {
        const PREFIX: &str = "validation::";
        let code = code_of(body);

        let mut found = std::collections::BTreeSet::new();
        let mut rest = code.as_str();
        while let Some(i) = rest.find(PREFIX) {
            let after = &rest[i + PREFIX.len()..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.starts_with("validate_") {
                found.insert(name);
            }
            rest = after;
        }
        found
    }

    /// Take the body of `head`, stopping at whichever `terminator` comes first.
    fn body_after<'a>(src: &'a str, head: &str, terminators: &[&str]) -> &'a str {
        let start = src
            .split(head)
            .nth(1)
            .unwrap_or_else(|| panic!("`{head}` must exist"));
        let end = terminators
            .iter()
            .filter_map(|t| start.find(t))
            .min()
            .unwrap_or(start.len());
        &start[..end]
    }

    /// `body` with `//` lines removed, so a comment naming a gate does not
    /// count as a call to it.
    fn code_of(body: &str) -> String {
        body.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The two transports must refuse the same inputs.
    ///
    /// Both check lists are derived from source and compared as sets, in both
    /// directions. Neither is written down twice, so this cannot pass by a
    /// stale copy of one of them; and a check added to `read_file` but not to
    /// `validate_read_params` (or the reverse) fails here rather than leaving
    /// one transport quietly weaker — which is exactly how the gap this closes
    /// opened, `mcp.rs` having reached the same sandbox with zero of these
    /// bounds applied.
    #[test]
    fn http_and_stdio_validate_the_same_inputs() {
        let http = include_str!("main.rs");
        let stdio = include_str!("mcp.rs");

        for (http_fn, stdio_fn) in [
            ("async fn read_file(", "fn validate_read_params("),
            ("async fn write_file(", "fn validate_write_params("),
            ("async fn run_command(", "fn validate_run_params("),
            ("async fn glob_search(", "fn validate_glob_params("),
            ("async fn grep_search(", "fn validate_grep_params("),
        ] {
            let http_calls = validation_calls(body_after(http, http_fn, &["\nasync fn "]));
            let stdio_calls = validation_calls(body_after(stdio, stdio_fn, &["\n}"]));

            assert!(
                !http_calls.is_empty(),
                "non-vacuity: `{http_fn}` must still validate its inputs. If it \
                 stopped, this test would pass by both sides being empty"
            );
            assert_eq!(
                http_calls, stdio_calls,
                "`{http_fn}` and `{stdio_fn}` must apply the same bounds; the \
                 field names differ between the request and parameter structs, \
                 the checks must not"
            );
        }
    }

    #[test]
    fn stdio_read_refuses_what_http_read_refuses() {
        let long = ReadParams {
            path: "a".repeat(crate::validation::MAX_PATH_LENGTH + 1),
        };
        assert!(validate_read_params(&long).is_err(), "over-long path");

        let nul = ReadParams {
            path: "/workspace/ok\0/etc/passwd".to_string(),
        };
        assert!(validate_read_params(&nul).is_err(), "interior NUL");

        let ok = ReadParams {
            path: "/workspace/main.rs".to_string(),
        };
        assert!(validate_read_params(&ok).is_ok(), "non-vacuity");
    }

    #[test]
    fn stdio_write_refuses_what_http_write_refuses() {
        let nul = WriteParams {
            path: "/workspace/ok\0.txt".to_string(),
            contents: "hello".to_string(),
        };
        assert!(validate_write_params(&nul).is_err(), "interior NUL");

        let ok = WriteParams {
            path: "/workspace/out.txt".to_string(),
            contents: "hello".to_string(),
        };
        assert!(validate_write_params(&ok).is_ok(), "non-vacuity");
    }

    #[test]
    fn stdio_run_refuses_what_http_run_refuses() {
        let base = || RunParams {
            args: vec!["echo".to_string(), "hi".to_string()],
            stdin: None,
            directory: None,
            _timeout_seconds: None,
        };
        assert!(validate_run_params(&base()).is_ok(), "non-vacuity");

        let mut too_many = base();
        too_many.args = vec!["x".to_string(); crate::validation::MAX_COMMAND_ARGS + 1];
        assert!(validate_run_params(&too_many).is_err(), "argv count");

        let mut too_long = base();
        too_long.args = vec!["y".repeat(crate::validation::MAX_COMMAND_LENGTH + 1)];
        assert!(validate_run_params(&too_long).is_err(), "argv bytes");

        let mut nul_arg = base();
        nul_arg.args = vec!["echo".to_string(), "a\0b".to_string()];
        assert!(validate_run_params(&nul_arg).is_err(), "NUL in an argument");

        let mut big_stdin = base();
        big_stdin.stdin = Some("z".repeat(crate::validation::MAX_STDIN_LENGTH + 1));
        assert!(validate_run_params(&big_stdin).is_err(), "stdin size");

        let mut bad_dir = base();
        bad_dir.directory = Some("/workspace\0".to_string());
        assert!(validate_run_params(&bad_dir).is_err(), "working directory");
    }

    #[test]
    fn stdio_glob_refuses_what_http_glob_refuses() {
        let ok = GlobParams {
            pattern: "**/*.rs".to_string(),
            root: Some("/workspace".to_string()),
        };
        assert!(
            validate_glob_params(&ok).is_ok(),
            "non-vacuity: `**` is a glob"
        );

        let backtracking = GlobParams {
            pattern: "(a+)+".to_string(),
            root: None,
        };
        assert!(
            validate_glob_params(&backtracking).is_err(),
            "nested quantifier"
        );

        let bad_root = GlobParams {
            pattern: "*.rs".to_string(),
            root: Some("a".repeat(crate::validation::MAX_PATH_LENGTH + 1)),
        };
        assert!(validate_glob_params(&bad_root).is_err(), "over-long root");
    }

    #[test]
    fn stdio_grep_refuses_what_http_grep_refuses() {
        let ok = GrepParams {
            pattern: "TODO".to_string(),
            path: Some("/workspace".to_string()),
            include: Some("*.rs".to_string()),
            context_lines: None,
        };
        assert!(validate_grep_params(&ok).is_ok(), "non-vacuity");

        let long_pattern = GrepParams {
            pattern: "p".repeat(crate::validation::MAX_PATTERN_LENGTH + 1),
            path: None,
            include: None,
            context_lines: None,
        };
        assert!(
            validate_grep_params(&long_pattern).is_err(),
            "pattern length"
        );

        let bad_path = GrepParams {
            pattern: "TODO".to_string(),
            path: Some("/workspace\0".to_string()),
            include: None,
            context_lines: None,
        };
        assert!(validate_grep_params(&bad_path).is_err(), "NUL in path");

        let bad_include = GrepParams {
            pattern: "TODO".to_string(),
            path: None,
            include: Some("(a+)+".to_string()),
            context_lines: None,
        };
        assert!(
            validate_grep_params(&bad_include).is_err(),
            "`include` is a pattern, and gets the pattern checks"
        );
    }

    /// `web_fetch` must run the same policy gates on both transports, in the
    /// order that matters.
    ///
    /// The set below is the egress policy: what the URL may be, what host it
    /// may reach, what the allowlist says, what a granted effect vouches for,
    /// where a redirect may land, and what content type may come back.
    /// `admit_http_recorded` was the one this transport did not run, so a pod
    /// whose certificate granted `github/read-ci-logs` could `POST` a pull
    /// request over stdio and be refused only by the host allowlist — the
    /// exact widening ADR 0004 milestone 6 exists to close.
    ///
    /// The ordering assertion is the security property, not a style rule:
    /// "refused before any discharge is minted". A gate that runs after
    /// `preflight_web` refuses a request whose authorization witness has
    /// already been built.
    #[test]
    fn http_and_stdio_web_fetch_run_the_same_gates() {
        const GATES: [&str; 6] = [
            "validate_url",
            "check_dns_allowlist",
            "check_url_allowlist",
            "admit_http_recorded",
            "check_redirect_target",
            "check_mime_type",
        ];

        let http = code_of(body_after(
            include_str!("main.rs"),
            "async fn web_fetch(",
            &["\nasync fn "],
        ));
        let stdio = code_of(body_after(
            include_str!("mcp.rs"),
            "async fn web_fetch(",
            &["\n    #[tool", "\n}"],
        ));

        // Both slices must stop at their own handler. A terminator that stops
        // matching would widen the slice to the rest of the file and make
        // every `contains` below trivially true.
        for (transport, body) in [("HTTP", &http), ("stdio", &stdio)] {
            assert!(
                !body.contains("async fn "),
                "{transport}: the `web_fetch` slice ran past its own handler, so \
                 the assertions below would be reading someone else's gates"
            );
            assert!(
                body.contains("Operation::WebFetch"),
                "{transport}: the `web_fetch` slice does not look like `web_fetch`"
            );
        }

        for gate in GATES {
            assert!(
                http.contains(gate),
                "non-vacuity: the HTTP `web_fetch` must still run `{gate}`. If it \
                 stopped, the stdio assertion below would be measuring nothing"
            );
            assert!(
                stdio.contains(gate),
                "the stdio `web_fetch` must run `{gate}` too — it reaches the same \
                 wire through the same `NetEffect::fetch`"
            );
        }

        for (transport, body) in [("HTTP", &http), ("stdio", &stdio)] {
            let admit = body
                .find("admit_http_recorded")
                .expect("asserted present above");
            let discharge = body
                .find("preflight_web")
                .unwrap_or_else(|| panic!("{transport} `web_fetch` must mint a discharge bundle"));
            assert!(
                admit < discharge,
                "{transport}: the per-effect gate must refuse before the discharge \
                 bundle is minted, not after"
            );
        }
    }

    /// `web_fetch` was the one tool already covered, indirectly.
    ///
    /// It calls `web_fetch_policy::validate_url`, which is a one-line
    /// delegation to `validation::validate_url` — the check the HTTP handler
    /// runs directly. Pin the delegation: if that wrapper ever stops
    /// delegating, `web_fetch` silently joins the gap the rest of this section
    /// closes, and nothing else would notice.
    #[test]
    fn web_fetch_was_already_covered() {
        let long = format!(
            "https://example.com/{}",
            "a".repeat(crate::validation::MAX_PATH_LENGTH)
        );
        assert!(
            crate::web_fetch_policy::validate_url(&long).is_err(),
            "length bound"
        );
        assert!(
            crate::web_fetch_policy::validate_url("file:///etc/passwd").is_err(),
            "scheme bound"
        );
        assert!(
            crate::web_fetch_policy::validate_url("https://example.com/ok").is_ok(),
            "non-vacuity"
        );
    }

    // ── the proof names what was checked (ADR 0006, C2.2) ───────────────

    /// The audit subject is byte-identical to the string the handlers used to
    /// pass alongside the verb.
    ///
    /// `guard.check` now takes an `Act`, and every verdict recorded after the
    /// check reads `proof.subject()` instead of a local. That was meant to
    /// change *where the string comes from* — from the decision rather than
    /// beside it — and nothing else. This pins that: each case is the
    /// expression the handler used before.
    ///
    /// `web_fetch` is the one that could have drifted. `Url::parse`
    /// normalises — it lower-cases the host and adds a trailing slash — so
    /// building the `Endpoint`'s raw form from `parsed_url.as_str()` would
    /// have quietly started auditing a URL the client never typed. It is built
    /// from `params.url`, and this is what says so.
    #[test]
    fn the_checked_subject_is_what_the_handler_used_to_pass() {
        let path = "/workspace/main.rs";
        assert_eq!(
            Act::Read {
                path: FilePath::new(path),
                sink: ReadSink::AuditLog,
            }
            .subject(),
            path
        );
        assert_eq!(
            Act::Write {
                path: FilePath::new(path),
                sink: WriteSink::Workspace,
            }
            .subject(),
            path
        );

        let args = vec!["cargo".to_string(), "test".to_string()];
        assert_eq!(
            Act::Run {
                argv: Argv::new(args.clone()),
            }
            .subject(),
            args.join(" "),
            "`run`'s subject was `params.args.join(\" \")`"
        );

        let pattern = "**/*.rs";
        assert_eq!(
            Act::Glob {
                pattern: Pattern::new(pattern),
                sink: ReadSink::AuditLog,
            }
            .subject(),
            pattern
        );
        assert_eq!(
            Act::Grep {
                pattern: Pattern::new(pattern),
                sink: ReadSink::AuditLog,
            }
            .subject(),
            pattern
        );

        // As the client typed it: an upper-case host and no trailing slash,
        // both of which `Url::parse` would rewrite.
        let raw = "https://API.Example.COM/v1";
        let normalised = url::Url::parse(raw).expect("valid").to_string();
        assert_ne!(
            raw, normalised,
            "non-vacuity: if parsing left this alone the assertion below would \
             hold for either choice and prove nothing"
        );
        assert_eq!(
            Act::Fetch {
                endpoint: Endpoint::new("GET", "https", "api.example.com", 443, "/v1", raw),
            }
            .subject(),
            raw,
            "`web_fetch`'s subject was `params.url`, before any parse"
        );
    }

    // ── the graph grep actually consults ────────────────────────────────

    /// `grep` was the one MCP effect whose taint check could not fire.
    ///
    /// `NucleusMcpServer` keeps the transport's own per-session `flow_graph`,
    /// and `observe_flow` records into it. Five of the six preflights on this
    /// path locked that graph; the per-file preflight inside `grep` locked
    /// `state.flow_graph` instead. Under `--mcp`, `main` returns before
    /// `Router::new()`, so no HTTP handler ever runs and `AppState`'s graph
    /// stays empty for the life of the process — making the
    /// `NoAdversarialAncestry` obligation in `preflight_grep_fs` vacuous.
    ///
    /// This is the same class `declassify.rs` records fixing in Phase 4.5:
    /// a scope landing on "the kernel's separate, never-populated
    /// `flow_graph`" rather than the one the live verdict reads.
    ///
    /// A behavioural test would need a full `AppState`, which
    /// `tests/memory_ifc_e2e.rs` documents avoiding because it "needs a
    /// sandbox/runtime". So this pins the property syntactically, with a
    /// non-vacuity assertion so it cannot pass by the preflight being deleted.
    #[test]
    fn grep_consults_the_graph_this_transport_writes() {
        let src = include_str!("mcp.rs");
        let handler = src
            .split("async fn grep(")
            .nth(1)
            .expect("the grep handler must exist");
        // Stop at the next `#[tool …]` so this reads only grep's own body.
        let body = &handler[..handler.find("\n    #[tool").unwrap_or(handler.len())];
        // Comments stripped first. The fix's own explanatory comment names the
        // wrong handle in order to say "not this one", and the first version of
        // this test failed on that prose — the same false positive
        // `.dead-code-ratchet.toml` records its counter hitting inside string
        // literals, "including the gate's own test fixtures".
        let code: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !code.contains("state.flow_graph"),
            "grep's per-file preflight must read the graph `observe_flow` writes \
             (`self.flow_graph`, captured as `flow_graph`), not `AppState`'s — \
             under --mcp the latter is never written, so the taint check is vacuous"
        );
        assert!(
            code.contains("flow_graph.blocking_lock()"),
            "non-vacuity: grep must still lock a flow graph and run the per-file \
             preflight. Deleting the preflight would satisfy the assertion above \
             while removing the check entirely"
        );
    }

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
    fn build_term_grep_search_stays_grep_search() {
        // This asserted `GlobSearch`, on the reasoning that grep and glob share
        // a file-pattern semantic. They do not share an AUTHORITY: the profiles
        // grant `grep_search` and `glob_search` separately, and
        // `WithinDelegationCeiling` compares a term's own operation against the
        // one its authority names. Lowering grep to a glob primitive made those
        // two disagree for every grep, so grep was denied under `codegen`, which
        // grants `grep_search: always` (#2790).
        let term = build_action_term(Operation::GrepSearch, "TODO");
        assert_eq!(term.operation(), Operation::GrepSearch);
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
    fn build_term_manage_pods_stays_manage_pods() {
        // Same collapse as grep above, and the same consequence: `manage_pods`
        // and `spawn_agent` are separately granted, so a ManagePods term whose
        // action reported `SpawnAgent` could not pass the ceiling check against
        // its own authority (#2790).
        let term = build_action_term(Operation::ManagePods, "pod-123");
        assert_eq!(term.operation(), Operation::ManagePods);
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
    // (`FlowGraph::new()`) is used so the five original obligations are
    // vacuously satisfied and `InScopeWithTask` is the discriminating gate.

    /// The RunBash policy ceiling supplied by the handler; its exact value is
    /// immaterial to these tests because `requested == ceiling` (honest
    /// no-escalation) makes `WithinDelegationCeiling` pass for any level.
    const RUN_BASH_CEILING: CapabilityLevel = CapabilityLevel::LowRisk;

    // (a) Missing/Invalid session token ⇒ verified_scope() is None ⇒ the gate
    //     DENIES fail-closed (no-vacuous-witness) ⇒ run_args is never reached.
    #[test]
    fn runbash_denies_when_session_token_missing_or_invalid() {
        let flow = FlowGraph::new();
        // `SessionTaskToken::Missing` and `::Invalid` both return `None` from
        // `verified_scope()` (see session_token.rs) — modeled here as `None`.
        let result = preflight_runbash(
            None,
            crate::run_gate::GateLevels::honest(RUN_BASH_CEILING),
            "rm -rf /",
            &flow,
        );
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
        let flow = FlowGraph::new();
        // Verified, but RunBash ∉ allowed_operations.
        let scope = TokenScope::new(
            vec![Operation::ReadFiles, Operation::GlobSearch],
            vec!["/workspace/**".to_string()],
        );
        let result = preflight_runbash(
            Some(&scope),
            crate::run_gate::GateLevels::honest(RUN_BASH_CEILING),
            "cargo test",
            &flow,
        );
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
        let flow = FlowGraph::new();
        let scope = TokenScope::new(
            vec![Operation::RunBash, Operation::ReadFiles],
            vec!["/workspace/**".to_string()],
        );
        let result = preflight_runbash(
            Some(&scope),
            crate::run_gate::GateLevels::honest(RUN_BASH_CEILING),
            "cargo test",
            &flow,
        );
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
