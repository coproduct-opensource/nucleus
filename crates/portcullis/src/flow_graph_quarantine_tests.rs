//! Quarantine tests split from `flow_graph_tests.rs` (SECURITY_TODO #18).
//!
//! Split for a mundane reason worth recording: appending the eviction
//! regression pushed `flow_graph_tests.rs` to 2548 lines, past the line
//! ratchet's 2500 default. That ratchet only shrinks, so giving the file a
//! bespoke higher ceiling would be the wrong direction — the test moves
//! instead. `flow_graph.rs` includes this alongside its sibling.

use super::*;

// ── SECURITY_TODO #18: quarantine is not evicted ────────────────────────────

/// Quarantine used to evict oldest-first at a 4096 ceiling. That took the
/// SMALLEST `NodeId` — the most ancestral node, the one whose removal un-taints
/// the most future descendants — with no tombstone and no audit record, ten
/// lines above `release_quarantine`, which demands a principal and a reason for
/// exactly this act.
///
/// `maybe_compact` goes out of its way to PRESERVE quarantined nodes ("they
/// carry security-critical state"). The same set cannot be must-preserve in one
/// place and disposable in another.
#[test]
fn quarantine_is_not_evicted_past_the_old_ceiling() {
    let mut g = FlowGraph::new();

    // The node whose taint must survive: the first quarantined, i.e. the
    // smallest NodeId, which is precisely what the old eviction dropped.
    let first = g
        .insert_action(Operation::ReadFiles, &[], 0)
        .expect("root action")
        .node_id;
    assert!(g.quarantine(first), "the node is newly quarantined");

    // Push well past the old MAX_QUARANTINED_NODES ceiling of 4096. Stays under
    // MAX_GRAPH_NODES (10_000) so compaction is not what is being measured.
    for _ in 0..5_000 {
        let n = g
            .insert_action(Operation::ReadFiles, &[], 0)
            .expect("filler action")
            .node_id;
        g.quarantine(n);
    }

    assert!(
        g.is_quarantined(first),
        "the earliest quarantined node was forgotten — taint was discarded to save 8 bytes"
    );

    // The consequence that actually bites: a node created AFTER the eviction
    // would no longer inherit the taint, because `is_quarantined` resolves
    // descendants by walking ancestry against this set.
    let descendant = g
        .insert_action(Operation::WriteFiles, &[first], 0)
        .expect("child of the quarantined node")
        .node_id;
    assert!(
        g.is_quarantined(descendant),
        "a descendant of a quarantined node escaped quarantine"
    );
}
