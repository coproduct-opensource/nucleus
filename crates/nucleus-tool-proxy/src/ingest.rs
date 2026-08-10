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
use portcullis::flow_graph::{FlowGraph, FlowGraphError};
use tokio::sync::Mutex;
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
    // Authoritative FlowTracker write — this alone governs the live egress
    // verdict (`kernel/ifc.rs` reads `flow_tracker`). Behaviour UNCHANGED.
    let observed = {
        let mut flow = state.flow_tracker.lock().await;
        match flow.observe_with_parents_and_hash(kind, parents, Some(hash)) {
            Ok(id) => Some(id),
            Err(e) => {
                warn!(?kind, error = %e, "flow-tracker observe failed");
                None
            }
        }
    };
    // Phase 2 SHADOW dual-write into the kernel `FlowGraph`. Not yet read by
    // egress, so verdict-neutral. Only mirrored when the authoritative write
    // landed, keeping the two graphs node-for-node aligned on this chokepoint
    // (the k-of-n memory path observes into the tracker only and is a separate,
    // later step — the shadow legitimately lags there until then).
    if observed.is_some() {
        shadow_observe(&state.flow_graph, kind, !parents.is_empty(), hash).await;
    }
    observed
}

/// Dual-write one ingest observation into the SHADOW [`FlowGraph`] (Phase 2).
///
/// This is the FlowGraph half of the tool-proxy ingest chokepoint. It is called
/// only after the authoritative `FlowTracker` write succeeded, so the two stay
/// aligned. It NEVER touches the `FlowTracker` and is NEVER consulted by the
/// egress verdict yet, so it cannot change any live decision — it exists to make
/// the later, boot-gated egress switch provably safe (the differential canary)
/// and to make `FlowGraph` actually non-empty in production (the bug being
/// closed: the tool-proxy never populated it, so declassification resolved
/// against an empty graph).
///
/// Node population is **server-computed**, never client-declared: the parent is
/// derived here from the shadow graph's OWN `latest_adversarial_node()` — the
/// same conservative over-approximation `http_observe_authored` uses on the
/// tracker — rather than by translating a `FlowTracker` id (the two graphs are
/// not id-locked, because the k-of-n memory path advances the tracker alone).
/// This preserves the taint STRUCTURE without a hand-maintained id map, and is
/// verdict-neutral by construction: the egress gate reads only the session
/// aggregates (`is_tainted`, `is_poisoned`, `session_exfiltration_check`), which
/// accumulate monotonically at the source node — a parent edge only ever adds
/// taint that the source already contributed, so the aggregate is invariant to
/// which specific edge is attached (see `flowgraph_flowtracker_parity`).
///
/// FAIL-CLOSED + DETECTABLE: if the shadow write is dropped it must NOT weaken
/// the tracker (it does not — it never touches it), and it must NOT silently
/// no-op (that would make the later egress switch fail OPEN). So it POISONS the
/// shadow, which the future switch's poison gate turns into a fail-closed deny,
/// and which a test can observe via `FlowGraph::is_poisoned()`.
pub(crate) async fn shadow_observe(
    graph: &Mutex<FlowGraph>,
    kind: NodeKind,
    derives_from_session: bool,
    hash: nucleus_ifc_kernel::ContentHash,
) {
    let mut fg = graph.lock().await;
    let now = shadow_now();
    let parents: Vec<u64> = if derives_from_session {
        fg.latest_adversarial_node().into_iter().collect()
    } else {
        Vec::new()
    };
    let result = fg.observe_with_content_hash(kind, &parents, now, hash);
    poison_shadow_if_dropped(&mut fg, kind, result);
}

/// Fail-closed handler for a dropped shadow dual-write: poison the shadow graph
/// so the drop is detectable (and the later egress switch fails closed), logging
/// the cause. Extracted so the fail-closed branch is unit-testable without
/// having to provoke a live `FlowGraph` error.
fn poison_shadow_if_dropped(
    fg: &mut FlowGraph,
    kind: NodeKind,
    result: Result<u64, FlowGraphError>,
) {
    if let Err(e) = result {
        warn!(
            ?kind,
            error = ?e,
            "flow-graph shadow dual-write dropped; poisoning shadow (fail-closed \
             for the later egress switch; live verdict still reads FlowTracker)"
        );
        fg.poison();
    }
}

/// Wall-clock seconds for a shadow observation. Feeds only the node label's
/// freshness metadata, never the exfiltration verdict (which reads the session
/// aggregates), so its exact value is immaterial to parity — mirrors
/// `FlowTracker`'s internal clock use.
fn shadow_now() -> u64 {
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
mod shadow_dual_write_tests {
    //! Phase 2 dual-write evidence: the SHADOW `FlowGraph`, populated by the real
    //! `shadow_observe` chokepoint, agrees with the live `FlowTracker` on every
    //! egress-relevant aggregate for the actual production ingest sequence — the
    //! in-tree twin of the `flowgraph_flowtracker_parity` differential harness
    //! (#2229), but now driven by the production dual-write path rather than a
    //! synthetic one. Plus: the graph is actually non-empty in production (the bug
    //! being closed), and a dropped dual-write is detectable and fail-closed.
    use super::*;
    use portcullis::flow_graph::FlowGraph;
    use portcullis_core::ifc_api::FlowTracker;
    use portcullis_core::ConfLevel;
    use tokio::sync::Mutex;

    fn hash_of(bytes: &[u8]) -> nucleus_ifc_kernel::ContentHash {
        ingest_content_hash(bytes)
    }

    /// Drive one ingest through BOTH halves exactly as `http_observe_flow_from`
    /// does: the authoritative tracker write, then the shadow dual-write.
    async fn dual(
        tracker: &Mutex<FlowTracker>,
        graph: &Mutex<FlowGraph>,
        kind: NodeKind,
        bytes: &[u8],
        parents: &[u64],
    ) {
        let h = hash_of(bytes);
        {
            let mut ft = tracker.lock().await;
            ft.observe_with_parents_and_hash(kind, parents, Some(h))
                .expect("tracker observe");
        }
        shadow_observe(graph, kind, !parents.is_empty(), h).await;
    }

    /// The four aggregates the live egress verdict reads off the session tracker
    /// (`exposure_core::ifc_egress_verdict` + the `kernel/ifc.rs` poison gate).
    /// If these agree, switching egress from the tracker to the graph on this
    /// sequence is verdict-neutral.
    fn assert_aggregates_agree(ft: &FlowTracker, fg: &FlowGraph, ctx: &str) {
        assert_eq!(
            ft.is_tainted(),
            fg.is_tainted(),
            "{ctx}: is_tainted diverged"
        );
        assert_eq!(
            ft.session_taint_ceiling(),
            fg.session_taint_ceiling(),
            "{ctx}: session_taint_ceiling diverged"
        );
        for sink in [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret] {
            assert_eq!(
                ft.session_exfiltration_check(sink).is_safe(),
                fg.session_exfiltration_check(sink).is_safe(),
                "{ctx}: session_exfiltration_check({sink:?}) diverged"
            );
        }
        assert_eq!(
            ft.is_poisoned(),
            fg.is_poisoned(),
            "{ctx}: is_poisoned diverged"
        );
    }

    /// The dual-write is verdict-neutral on the real ingest sequence, AND the
    /// shadow graph is actually populated (the property that makes the later
    /// egress switch meaningful).
    #[tokio::test]
    async fn shadow_matches_tracker_on_a_production_ingest_sequence() {
        let tracker = Mutex::new(FlowTracker::new());
        let graph = Mutex::new(FlowGraph::new());

        // A realistic mixed HTTP-path sequence: a confidential file read, an
        // adversarial web fetch (trips is_tainted), a derived read (non-empty
        // tracker parents — the authored/laundered-path edge), and more web.
        dual(&tracker, &graph, NodeKind::FileRead, b"secret config", &[]).await;
        dual(&tracker, &graph, NodeKind::WebContent, b"<injected>", &[]).await;
        dual(
            &tracker,
            &graph,
            NodeKind::FileRead,
            b"derived-from-web",
            &[1],
        )
        .await;
        dual(&tracker, &graph, NodeKind::WebContent, b"more web", &[]).await;

        let ft = tracker.lock().await;
        let fg = graph.lock().await;
        assert_aggregates_agree(&ft, &fg, "production sequence");

        // Non-vacuity: the sequence is not the trivial all-false — it genuinely
        // trips integrity taint on BOTH trackers, so the equality above has teeth.
        assert!(
            ft.is_tainted(),
            "sequence must trip is_tainted (non-vacuous)"
        );
        assert!(
            fg.is_tainted(),
            "shadow must also see the taint (non-vacuous)"
        );

        // The bug this phase closes: on the tool-proxy the FlowGraph was empty, so
        // declassification resolved against an empty graph. It is now populated.
        assert!(
            !fg.is_empty(),
            "shadow FlowGraph must be non-empty after ingest"
        );
        assert_eq!(fg.len(), 4, "one shadow node per mirrored ingest");
    }

    /// Parity holds at EVERY prefix, not just the end (matches #2229's discipline).
    #[tokio::test]
    async fn shadow_matches_tracker_at_every_prefix() {
        let seq: &[(NodeKind, &[u8])] = &[
            (NodeKind::UserPrompt, b"hi"),
            (NodeKind::FileRead, b"file"),
            (NodeKind::WebContent, b"web"),
            (NodeKind::EnvVar, b"SECRET=1"),
        ];
        let tracker = Mutex::new(FlowTracker::new());
        let graph = Mutex::new(FlowGraph::new());
        for (i, (kind, bytes)) in seq.iter().enumerate() {
            dual(&tracker, &graph, *kind, bytes, &[]).await;
            let ft = tracker.lock().await;
            let fg = graph.lock().await;
            assert_aggregates_agree(&ft, &fg, &format!("prefix len {}", i + 1));
        }
    }

    /// A single ingest populates the shadow graph — the minimal live-population
    /// property.
    #[tokio::test]
    async fn single_ingest_populates_the_shadow_graph() {
        let graph = Mutex::new(FlowGraph::new());
        assert!(graph.lock().await.is_empty(), "fresh graph is empty");
        shadow_observe(&graph, NodeKind::WebContent, false, hash_of(b"x")).await;
        let fg = graph.lock().await;
        assert_eq!(fg.len(), 1, "one observe → one shadow node");
        assert!(!fg.is_poisoned(), "a clean observe must not poison");
    }

    /// Fail-closed: a dropped shadow dual-write poisons the SHADOW (so it is
    /// detectable and the later egress switch fails closed) and NEVER touches the
    /// `FlowTracker` that still governs the live verdict.
    #[test]
    fn dropped_shadow_write_poisons_the_shadow_never_the_tracker() {
        let mut fg = FlowGraph::new();
        let control_tracker = FlowTracker::new();
        // Provoke a real drop: reference a non-existent parent node.
        let dropped = fg.observe_with_content_hash(NodeKind::WebContent, &[9999], 0, hash_of(b"x"));
        assert!(
            dropped.is_err(),
            "precondition: an invalid parent must error"
        );

        poison_shadow_if_dropped(&mut fg, NodeKind::WebContent, dropped);

        assert!(
            fg.is_poisoned(),
            "a dropped shadow dual-write must poison the shadow so it is detectable"
        );
        assert!(
            !control_tracker.is_poisoned(),
            "a shadow drop must never poison or weaken the FlowTracker"
        );
    }

    /// The complement: a landed shadow write does not poison — the poison branch
    /// is not fired spuriously (guards against a fail-closed that denies always).
    #[test]
    fn landed_shadow_write_does_not_poison() {
        let mut fg = FlowGraph::new();
        let landed = fg.observe_with_content_hash(NodeKind::WebContent, &[], 0, hash_of(b"x"));
        assert!(landed.is_ok());
        poison_shadow_if_dropped(&mut fg, NodeKind::WebContent, landed);
        assert!(!fg.is_poisoned(), "a landed observe must not poison");
        assert_eq!(fg.len(), 1);
    }
}
