//! Ingest observation — where external bytes become flow-graph nodes.
//!
//! Extracted from `main.rs` to stay under the line ratchet, and because these
//! belong together: every one of them answers "what node does this content
//! become, and what does it derive from?".
//!
//! The provenance parent is derived INSIDE `http_observe_authored` rather than
//! at the call site. That is deliberate — when the caller supplied it, a
//! perturbation replacing it with `None` left every test green, because the unit
//! tests drive the flow graph directly and the handlers need a live sandbox to
//! exercise. Making the omission unrepresentable is the fix; a better test is
//! not available at this layer.
//!
//! Phase 2 retirement: the single authoritative graph is the kernel's
//! [`FlowGraph`] (the egress verdict reads it). The retired `FlowTracker`
//! oracle no longer shadows these writes — there is one graph, so ingest writes
//! land directly on the graph the verdict consults, fail-closed on drop.

use nucleus::portcullis::NodeKind;
use portcullis::flow_graph::{FlowGraph, FlowGraphError};
use tokio::sync::Mutex;
use tracing::warn;

use crate::{ingest_content_hash, AppState};

/// Observe a data-ingest node in the session flow graph after a *successful*
/// read/fetch (#1633), mirroring the MCP server. `WebContent` is an adversarial
/// taint source; `FileRead` contributes to the confidentiality ceiling. Must be
/// called only on success paths so a denied/failed op never leaks taint.
///
/// InputsAuthorized brick 3: the caller passes the *actual ingested bytes*, whose
/// recomputed SHA-256 is recorded on the node via `observe_with_content_hash`.
pub(crate) async fn http_observe_flow(
    state: &AppState,
    kind: NodeKind,
    bytes: &[u8],
) -> Option<u64> {
    http_observe_flow_from(state, kind, bytes, &[]).await
}

/// Observe content the AGENT AUTHORED, deriving the provenance parent here
/// rather than at the call site.
///
/// The derivation is inside this function on purpose. When the caller passed
/// parents in, a perturbation that replaced them with `None` left every test
/// green — the unit tests drive the graph directly, so they prove the mechanism
/// works, not that the handler uses it, and the handler needs a live sandbox to
/// exercise. Same shape as #2127: the fix is not a better test, it is making the
/// omission unrepresentable. A caller can no longer forget the edge, because it
/// does not supply it. Returns the new node's graph id so a later read of the
/// same path can attach it as a provenance parent (`path_provenance`).
pub(crate) async fn http_observe_authored(
    state: &AppState,
    kind: NodeKind,
    bytes: &[u8],
) -> Option<u64> {
    // Conservative: the proxy cannot know which prior nodes influenced what the
    // agent wrote, so it attaches the latest adversarial one and
    // over-approximates. Over-approximation only ever ADDS taint.
    observe_into_graph(&state.flow_graph, kind, true, ingest_content_hash(bytes)).await
}

/// Observe an ingest with explicit PARENTS on the authoritative graph, returning
/// the new node's id.
///
/// The explicit-parent channel carries the read-derives-from-write edge (#2135):
/// a path the proxy wrote is recorded in `path_provenance` by its graph node id,
/// and a later read of that path passes that id here so the read derives from
/// the write — a round-trip through disk cannot strip the taint. `observe_with_
/// content_hash` validates the parent ids and joins their labels; an invalid
/// parent errors, which fails closed (poison) below.
pub(crate) async fn http_observe_flow_from(
    state: &AppState,
    kind: NodeKind,
    bytes: &[u8],
    parents: &[u64],
) -> Option<u64> {
    let hash = ingest_content_hash(bytes);
    let mut fg = state.flow_graph.lock().await;
    let now = observe_now();
    let result = fg.observe_with_content_hash(kind, parents, now, hash);
    finish_observe(&mut fg, kind, result)
}

/// Write one ingest observation into the authoritative [`FlowGraph`], deriving
/// the parent from the graph's OWN `latest_adversarial_node()` when the ingest
/// derives from prior session content.
///
/// Node population is **server-computed**, never client-declared: the parent is
/// the graph's latest adversarial node (the same conservative over-approximation
/// the HTTP authored path uses), not a client-supplied lineage. Shared by the
/// MCP transport (`mcp::observe_flow`, always parent-less) and the HTTP authored
/// path.
///
/// FAIL-CLOSED + DETECTABLE: a dropped observe must never silently no-op (that
/// would leave taint untracked — a fail-OPEN — and the egress verdict reads this
/// graph). So [`finish_observe`] POISONS the session, which the egress poison
/// gate turns into a deny and a test can observe via `FlowGraph::is_poisoned()`.
pub(crate) async fn observe_into_graph(
    graph: &Mutex<FlowGraph>,
    kind: NodeKind,
    derives_from_session: bool,
    hash: nucleus_ifc_kernel::ContentHash,
) -> Option<u64> {
    let mut fg = graph.lock().await;
    let now = observe_now();
    let parents: Vec<u64> = if derives_from_session {
        fg.latest_adversarial_node().into_iter().collect()
    } else {
        Vec::new()
    };
    let result = fg.observe_with_content_hash(kind, &parents, now, hash);
    finish_observe(&mut fg, kind, result)
}

/// Fail-closed completion for a graph observe: on a dropped write POISON the
/// session so every subsequent egress decision denies until a human-authorized
/// cleanse, and the drop is detectable via `FlowGraph::is_poisoned()`. Extracted
/// so the fail-closed branch is unit-testable without provoking a live error.
fn finish_observe(
    fg: &mut FlowGraph,
    kind: NodeKind,
    result: Result<u64, FlowGraphError>,
) -> Option<u64> {
    match result {
        Ok(id) => Some(id),
        Err(e) => {
            warn!(
                ?kind,
                error = ?e,
                "flow-graph observe dropped — poisoning session (fail-closed for the \
                 live egress verdict)"
            );
            fg.poison();
            None
        }
    }
}

/// Wall-clock seconds for an observation. Feeds only the node label's freshness
/// metadata, never the exfiltration verdict (which reads the monotonic session
/// aggregates), so its exact value is immaterial.
fn observe_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

#[cfg(test)]
mod graph_ingest_tests {
    //! Phase 2 retirement evidence: the ingest chokepoint writes directly to the
    //! single authoritative `FlowGraph` (the graph the egress verdict reads), the
    //! graph is actually populated in production (the bug the switch closed), and
    //! a dropped write is DETECTABLE and FAIL-CLOSED (poisons the session). The
    //! anti-laundering-under-compaction invariant lives in the retained
    //! `flowgraph_flowtracker_parity` differential harness.
    use super::*;
    use portcullis::flow_graph::FlowGraph;
    use tokio::sync::Mutex;

    fn hash_of(bytes: &[u8]) -> nucleus_ifc_kernel::ContentHash {
        ingest_content_hash(bytes)
    }

    /// A single ingest populates the authoritative graph — the minimal
    /// live-population property (the bug this phase closed: the tool-proxy never
    /// populated the graph, so declassification resolved against an empty graph).
    #[tokio::test]
    async fn single_ingest_populates_the_graph() {
        let graph = Mutex::new(FlowGraph::new());
        assert!(graph.lock().await.is_empty(), "fresh graph is empty");
        let id = observe_into_graph(&graph, NodeKind::WebContent, false, hash_of(b"x")).await;
        assert!(id.is_some(), "a clean observe returns the new node id");
        let fg = graph.lock().await;
        assert_eq!(fg.len(), 1, "one observe → one node");
        assert!(!fg.is_poisoned(), "a clean observe must not poison");
    }

    /// The adversarial ingest genuinely trips the session taint the egress verdict
    /// reads — the equality-with-teeth the parity harness relied on, now asserted
    /// directly on the one graph.
    #[tokio::test]
    async fn an_adversarial_ingest_taints_the_authoritative_graph() {
        let graph = Mutex::new(FlowGraph::new());
        observe_into_graph(&graph, NodeKind::WebContent, false, hash_of(b"<injected>")).await;
        let fg = graph.lock().await;
        assert!(
            fg.is_tainted(),
            "an adversarial (web) ingest must taint the graph the verdict reads"
        );
        assert!(
            fg.content_hash(1).is_some(),
            "the ingest node must content-address the exact bytes"
        );
    }

    /// **The fail-closed regression guard.** A dropped graph write POISONS the
    /// session so the drop is detectable and every subsequent egress decision
    /// denies — a silently-dropped ingest would leave taint untracked (fail-OPEN)
    /// on the graph the verdict now reads. This is the check the task requires:
    /// a dropped check must red.
    #[test]
    fn dropped_graph_write_poisons_the_session() {
        let mut fg = FlowGraph::new();
        // Provoke a real drop: reference a non-existent parent node.
        let dropped = fg.observe_with_content_hash(NodeKind::WebContent, &[9999], 0, hash_of(b"x"));
        assert!(
            dropped.is_err(),
            "precondition: an invalid parent must error"
        );
        let out = finish_observe(&mut fg, NodeKind::WebContent, dropped);
        assert!(out.is_none(), "a dropped write returns no node id");
        assert!(
            fg.is_poisoned(),
            "a dropped ingest must poison the session so it is detectable and fail-closed"
        );
    }

    /// The complement: a landed write does not poison — the fail-closed branch is
    /// not fired spuriously (guards against a poison-always that denies everything).
    #[test]
    fn landed_graph_write_does_not_poison() {
        let mut fg = FlowGraph::new();
        let landed = fg.observe_with_content_hash(NodeKind::WebContent, &[], 0, hash_of(b"x"));
        assert!(landed.is_ok());
        let out = finish_observe(&mut fg, NodeKind::WebContent, landed);
        assert!(out.is_some(), "a landed observe returns the node id");
        assert!(!fg.is_poisoned(), "a landed observe must not poison");
        assert_eq!(fg.len(), 1);
    }
}
