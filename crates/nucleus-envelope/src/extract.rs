//! Subgraph extraction — pulling a session's edges out of a [`LineageSink`].

use nucleus_lineage::{CallSpiffeId, LineageEdge, LineageSink, SinkError};

/// A session's lineage edges, in chain order.
///
/// "Chain order" means: ascending by edge timestamp, with ties broken by
/// the order they were emitted into the source sink. This ordering must
/// match the order [`nucleus_lineage::verify_chain`] expects — each edge's
/// `proof.prev_hash` is computed from the previous edge in the slice.
#[derive(Debug, Clone)]
pub struct SessionSubgraph {
    /// The pod / session-root SPIFFE id that defines membership.
    pub root: CallSpiffeId,
    /// Edges belonging to this session, in chain order.
    pub edges: Vec<LineageEdge>,
}

/// Pull every edge under `root` from `sink`.
///
/// Membership rule: an edge is in the session iff its `child` equals
/// `root` (the pod-admit edge) OR its `child` URI begins with
/// `root_uri + "/"`. This relies on the SPIFFE structural derivation rule
/// — `pod.derive_tool(...)` and friends always produce a child whose URI
/// is `pod_uri + "/call/..."`. Edges produced by foreign pods (different
/// URI prefix) are excluded.
///
/// Edges are returned in chain order: ascending `ts`, with ties broken by
/// insertion order from the underlying sink. The hash chain in
/// `proof.prev_hash` was computed in emission order, so chain verification
/// requires preserving it.
pub fn extract_session_subgraph(
    root: &CallSpiffeId,
    sink: &dyn LineageSink,
) -> Result<SessionSubgraph, SinkError> {
    let mut indexed: Vec<(usize, LineageEdge)> = sink
        .iter()?
        .into_iter()
        .enumerate()
        .filter(|(_, e)| is_under_root(&e.child, root))
        .collect();

    // Sort by (timestamp, original-insertion-index). The original index is
    // the tiebreaker so two edges with identical timestamps preserve the
    // hash-chain order the sink emitted them in.
    indexed.sort_by(|(ai, a), (bi, b)| a.ts.cmp(&b.ts).then_with(|| ai.cmp(bi)));

    let edges = indexed.into_iter().map(|(_, e)| e).collect();

    Ok(SessionSubgraph {
        root: root.clone(),
        edges,
    })
}

/// True iff `child` is `root` or structurally derived from `root` (its
/// URI starts with `root_uri + "/"`). The trailing slash is required so
/// `spiffe://x/ns/a/sa/b` is NOT considered a child of `spiffe://x/ns/a/sa/b2`.
pub(crate) fn is_under_root(child: &CallSpiffeId, root: &CallSpiffeId) -> bool {
    if child == root {
        return true;
    }
    let child_uri = child.as_str();
    let root_uri = root.as_str();
    child_uri.len() > root_uri.len()
        && child_uri.starts_with(root_uri)
        && child_uri.as_bytes()[root_uri.len()] == b'/'
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::{EdgeKind, InMemorySink};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
    }

    fn other_pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "other").unwrap()
    }

    #[test]
    fn empty_sink_yields_empty_subgraph() {
        let sink = InMemorySink::new();
        let g = extract_session_subgraph(&pod(), &sink).unwrap();
        assert!(g.edges.is_empty());
        assert_eq!(g.root, pod());
    }

    #[test]
    fn pod_admit_is_included() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let g = extract_session_subgraph(&p, &sink).unwrap();
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].child, p);
    }

    #[test]
    fn derived_calls_are_included() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let tool = p.derive_tool("Read", Some(b"x")).unwrap();
        sink.emit(LineageEdge::from_parent(
            tool.clone(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        let leaf = tool.derive_artifact(b"output").unwrap();
        sink.emit(LineageEdge::from_parent(
            leaf,
            tool,
            EdgeKind::ArtifactProduced,
        ))
        .unwrap();

        let g = extract_session_subgraph(&p, &sink).unwrap();
        assert_eq!(g.edges.len(), 3);
    }

    #[test]
    fn other_pods_are_excluded() {
        let sink = InMemorySink::new();
        let mine = pod();
        let theirs = other_pod();
        sink.emit(LineageEdge::pod_admit(mine.clone())).unwrap();
        sink.emit(LineageEdge::pod_admit(theirs.clone())).unwrap();
        sink.emit(LineageEdge::from_parent(
            theirs.derive_tool("Read", Some(b"x")).unwrap(),
            theirs,
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        sink.emit(LineageEdge::from_parent(
            mine.derive_tool("Read", Some(b"y")).unwrap(),
            mine.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();

        let g = extract_session_subgraph(&mine, &sink).unwrap();
        assert_eq!(g.edges.len(), 2); // pod_admit(mine) + tool(mine)
        for e in &g.edges {
            assert!(is_under_root(&e.child, &mine));
        }
    }

    #[test]
    fn prefix_match_requires_slash_boundary() {
        // A pod named "coder2" should NOT be matched by root "coder".
        let coder = CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap();
        let coder2 = CallSpiffeId::pod("prod.example.com", "agents", "coder2").unwrap();
        assert!(!is_under_root(&coder2, &coder));
        // But a child of coder IS matched.
        let child = coder.derive_tool("Read", None).unwrap();
        assert!(is_under_root(&child, &coder));
    }

    #[test]
    fn edges_are_returned_in_chain_order() {
        let sink = InMemorySink::new();
        let p = pod();
        let e1 = LineageEdge::pod_admit(p.clone());
        let e2 = LineageEdge::from_parent(
            p.derive_tool("Read", Some(b"a")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        );
        let e3 = LineageEdge::from_parent(
            p.derive_tool("Read", Some(b"b")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        );
        sink.emit(e1.clone()).unwrap();
        sink.emit(e2.clone()).unwrap();
        sink.emit(e3.clone()).unwrap();

        let g = extract_session_subgraph(&p, &sink).unwrap();
        assert_eq!(g.edges.len(), 3);
        assert_eq!(g.edges[0].child, e1.child);
        assert_eq!(g.edges[1].child, e2.child);
        assert_eq!(g.edges[2].child, e3.child);
    }
}
