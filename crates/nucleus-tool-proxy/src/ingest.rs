//! Ingest observation — where external bytes become flow-graph nodes.
//!
//! Extracted from `main.rs` to stay under the line ratchet, and because these
//! belong together: every one of them answers "what node does this content
//! become, and what does it derive from?".
//!
//! The provenance parent is derived INSIDE `http_observe_authored` rather than
//! at the call site. That is deliberate — when the caller supplied it, a
//! perturbation replacing it with `None` left every test green, because the unit
//! tests drive the `FlowTracker` directly and the handlers need a live sandbox to
//! exercise. Making the omission unrepresentable is the fix; a better test is
//! not available at this layer.

use nucleus::portcullis::NodeKind;
use tracing::warn;

use crate::{ingest_content_hash, AppState};

/// Observe a data-ingest node in the session flow tracker after a *successful*
/// read/fetch (#1633), mirroring the MCP server. `WebContent` is an adversarial
/// taint source; `FileRead` contributes to the confidentiality ceiling. Must be
/// called only on success paths so a denied/failed op never leaks taint.
///
/// InputsAuthorized brick 3: the caller passes the *actual ingested bytes*, whose
/// recomputed SHA-256 is recorded on the node via `observe_with_content_hash`.
/// Label/taint behaviour is identical to the old bare `observe` — only the hash
/// is added.
pub(crate) async fn http_observe_flow(
    state: &AppState,
    kind: NodeKind,
    bytes: &[u8],
) -> Option<u64> {
    http_observe_flow_from(state, kind, bytes, &[]).await
}

/// Observe an ingest with explicit PARENTS, returning the new node's id.
///
/// The id used to be discarded, which is why the flow graph was edgeless in
/// production: `observe_with_content_hash` passes `&[]` and nothing kept the
/// handle needed to reference a node later. Both halves are fixed here.
///
/// Uses the hashing variant: `scripts/check-ingest-hashed.sh` fails the build on
/// a non-hashing observe in the agent path, because a node with no content hash
/// is a node whose bytes were never witnessed.
/// Observe content the AGENT AUTHORED, deriving the provenance parent here
/// rather than at the call site.
///
/// The derivation is inside this function on purpose. When the caller passed
/// parents in, a perturbation that replaced them with `None` left every test
/// green — the unit tests drive the `FlowTracker` directly, so they prove the
/// mechanism works, not that the handler uses it, and the handler needs a live
/// sandbox to exercise. Same shape as #2127: the fix is not a better test, it is
/// making the omission unrepresentable. A caller can no longer forget the edge,
/// because it does not supply it.
pub(crate) async fn http_observe_authored(
    state: &AppState,
    kind: NodeKind,
    bytes: &[u8],
) -> Option<u64> {
    // Conservative: the proxy cannot know which prior nodes influenced what the
    // agent wrote, so it attaches the latest adversarial one and
    // over-approximates. Over-approximation only ever ADDS taint.
    let parent = state.flow_tracker.lock().await.latest_adversarial_node();
    let parents: Vec<u64> = parent.into_iter().collect();
    http_observe_flow_from(state, kind, bytes, &parents).await
}

pub(crate) async fn http_observe_flow_from(
    state: &AppState,
    kind: NodeKind,
    bytes: &[u8],
    parents: &[u64],
) -> Option<u64> {
    let hash = ingest_content_hash(bytes);
    let mut flow = state.flow_tracker.lock().await;
    match flow.observe_with_parents_and_hash(kind, parents, Some(hash)) {
        Ok(id) => Some(id),
        Err(e) => {
            warn!(?kind, error = %e, "flow-tracker observe failed");
            None
        }
    }
}

/// The flow node kind command output is observed as.
///
/// Extracted to a constant so the CHOICE is pinned by a test rather than
/// inferred. A test asserting that `McpToolResult` is adversarial, plus a test
/// that an `McpToolResult` observation trips the gate, BOTH pass even if this
/// call site observes something weaker — verified by perturbation: swapping in
/// `ToolResponse` (Untrusted, not Adversarial) failed nothing until this
/// constant existed to assert against.
pub(crate) const COMMAND_OUTPUT_NODE_KIND: NodeKind = NodeKind::McpToolResult;

/// Taint COMMAND OUTPUT as adversarial — the HTTP twin of
/// `mcp::Server::observe_tool_result`.
///
/// `/v1/run` returns arbitrary subprocess stdout/stderr to the agent, which is
/// external bytes by any definition: `curl` through bash is an ingest the proxy
/// cannot distinguish from `ls`. Every other HTTP handler that returns external
/// bytes observes them (`read_file`, `web_fetch`, `glob_search`, `grep_search`,
/// `web_search`); this one did not, so bash-fetched content entered the session
/// with no flow node at all.
///
/// The asymmetry was the real defect. `NUCLEUS_PARANOID_TOOL_IO=1` has always
/// covered the MCP transport (`mcp.rs:675`) and never covered HTTP, so an
/// operator who enabled it got partial coverage with nothing to indicate half
/// their surface was uncovered — worse than the flag not existing, because it
/// reads as a decision that was made.
///
/// Same env var, same default (OFF), same node kind, and the same reason for the
/// default that `observe_tool_result` documents: blanket-tainting the proxy's own
/// command output makes a session "one privileged action then locked"
/// (run-tests → cannot commit). That is an operator's policy call, not ours.
///
/// Observed regardless of exit status: a failing command's stderr is still bytes
/// the agent read. Called only after the command actually RAN, so a denied
/// operation still leaks no taint.
pub(crate) async fn http_observe_command_output(state: &AppState, stdout: &[u8], stderr: &[u8]) {
    let paranoid = std::env::var("NUCLEUS_PARANOID_TOOL_IO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !paranoid {
        return;
    }
    // Both streams in one node: they are one ingest event, and content-addressing
    // them separately would imply two independent sources.
    let mut bytes = Vec::with_capacity(stdout.len() + stderr.len());
    bytes.extend_from_slice(stdout);
    bytes.extend_from_slice(stderr);
    http_observe_flow(state, COMMAND_OUTPUT_NODE_KIND, &bytes).await;
}
