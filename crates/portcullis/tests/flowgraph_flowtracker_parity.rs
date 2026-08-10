//! Phase 1 evidence for the declassification-unification arc: the kernel's
//! proven `FlowGraph` is a **superset** of the tool-proxy's `FlowTracker` for
//! every aggregate the live egress gate consults.
//!
//! The live egress verdict (`exposure_core::ifc_egress_verdict`,
//! `kernel/ifc.rs`) reads exactly three things off the session tracker:
//! `is_tainted()`, `is_poisoned()`, and `session_exfiltration_check(sink)`
//! (plus per-node `content_hash` for the value-binding to come). Before Phase 2
//! can switch the tool-proxy from `FlowTracker` onto `FlowGraph`, those answers
//! must agree on identical ingest sequences. These tests are that proof — and a
//! regression guard: if the two implementations ever diverge, Phase 2 is unsafe.
//!
//! Node ids deliberately are NOT compared: `FlowTracker` ids are 1-based dense,
//! `FlowGraph` ids are sentinel-offset — an internal representation difference,
//! not a semantic one. Only the egress-relevant *answers* are asserted equal.

use portcullis::flow_graph::FlowGraph;
use portcullis_core::flow::NodeKind;
use portcullis_core::ifc_api::FlowTracker;
use portcullis_core::{ConfLevel, ContentHash};

const NOW: u64 = 42;

/// Drive the same observe sequence through both trackers and return their
/// egress-relevant aggregate answers side by side.
fn observe_both(kinds: &[NodeKind]) -> (FlowTracker, FlowGraph) {
    let mut ft = FlowTracker::new();
    let mut fg = FlowGraph::new();
    for &k in kinds {
        ft.observe_with_parents(k, &[])
            .expect("flow_tracker observe");
        fg.insert_observation(k, &[], NOW)
            .expect("flow_graph observe");
    }
    (ft, fg)
}

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

#[test]
fn aggregate_parity_across_an_observe_sequence() {
    // A mixed sequence that exercises every axis: a clean prompt, an AI-derived
    // Internal write, an ADVERSARIAL web-content node (trips is_tainted), and a
    // SECRET env var (raises the confidentiality ceiling to Secret).
    let seq = [
        NodeKind::UserPrompt,
        NodeKind::MemoryWrite,
        NodeKind::WebContent,
        NodeKind::EnvVar,
    ];

    // Parity must hold at EVERY prefix, not just the end.
    for len in 0..=seq.len() {
        let (ft, fg) = observe_both(&seq[..len]);
        assert_aggregates_agree(&ft, &fg, &format!("prefix len {len}"));
    }

    // Non-vacuity: the sequence actually flips each axis on BOTH trackers, so
    // the equalities above are not the trivial "both always false/safe".
    let (empty_ft, empty_fg) = observe_both(&[]);
    assert!(
        !empty_ft.is_tainted() && !empty_fg.is_tainted(),
        "empty untainted"
    );
    assert!(
        empty_ft
            .session_exfiltration_check(ConfLevel::Public)
            .is_safe()
            && empty_fg
                .session_exfiltration_check(ConfLevel::Public)
                .is_safe(),
        "empty session may exfiltrate to a Public sink"
    );

    let (adv_ft, adv_fg) = observe_both(&[NodeKind::WebContent]);
    assert!(
        adv_ft.is_tainted() && adv_fg.is_tainted(),
        "web content taints both"
    );

    let (sec_ft, sec_fg) = observe_both(&[NodeKind::EnvVar]);
    assert!(
        !sec_ft
            .session_exfiltration_check(ConfLevel::Public)
            .is_safe()
            && !sec_fg
                .session_exfiltration_check(ConfLevel::Public)
                .is_safe(),
        "a Secret env var must block a Public-sink exfiltration on BOTH trackers"
    );
    assert!(
        sec_ft
            .session_exfiltration_check(ConfLevel::Secret)
            .is_safe()
            && sec_fg
                .session_exfiltration_check(ConfLevel::Secret)
                .is_safe(),
        "a Secret sink still admits Secret data on BOTH trackers"
    );
}

#[test]
fn content_hash_records_and_matches_flowtracker() {
    let hash = ContentHash::from_bytes([7u8; 32]);
    let mut ft = FlowTracker::new();
    let mut fg = FlowGraph::new();

    let ft_id = ft
        .observe_with_content_hash(NodeKind::WebContent, hash)
        .expect("ft observe_with_content_hash");
    let fg_id = fg
        .observe_with_content_hash(NodeKind::WebContent, &[], NOW, hash)
        .expect("fg observe_with_content_hash");

    assert_eq!(ft.content_hash(ft_id), Some(hash));
    assert_eq!(fg.content_hash(fg_id), Some(hash));
    assert_eq!(
        ft.content_hash(ft_id),
        fg.content_hash(fg_id),
        "content hash must round-trip identically on both trackers"
    );

    // A plain observation records no hash on either.
    let mut ft2 = FlowTracker::new();
    let mut fg2 = FlowGraph::new();
    let a = ft2.observe(NodeKind::UserPrompt).expect("ft observe");
    let b = fg2
        .insert_observation(NodeKind::UserPrompt, &[], NOW)
        .expect("fg observe");
    assert_eq!(ft2.content_hash(a), None);
    assert_eq!(fg2.content_hash(b), None);
}

#[test]
fn poison_parity() {
    let (mut ft, mut fg) = observe_both(&[NodeKind::UserPrompt]);
    assert!(
        !ft.is_poisoned() && !fg.is_poisoned(),
        "clean session is unpoisoned"
    );
    ft.poison();
    fg.poison();
    assert!(
        ft.is_poisoned() && fg.is_poisoned(),
        "poison sets the fail-closed flag on both"
    );
}

/// The load-bearing anti-laundering test. `FlowGraph` compacts (tombstones old
/// nodes) at `MAX_GRAPH_NODES = 10_000`; `FlowTracker` never does. If
/// `is_tainted`/`session_taint_ceiling` were a scan of *live* nodes, compaction
/// would silently launder a past adversarial ingest to `false`. Because they
/// are monotonic ratchet fields, the taint survives. This test fails the moment
/// anyone "simplifies" the aggregates back to a live-node scan.
#[test]
fn taint_survives_compaction_the_ratchet_beats_a_live_scan() {
    let mut fg = FlowGraph::new();

    // One adversarial ingest at the very start.
    fg.insert_observation(NodeKind::WebContent, &[], NOW)
        .expect("adversarial observe");
    assert!(fg.is_tainted(), "adversarial node taints the session");

    // Bury it under enough clean nodes to force compaction to tombstone it.
    for _ in 0..(10_000 + 200) {
        fg.insert_observation(NodeKind::UserPrompt, &[], NOW)
            .expect("clean observe");
    }

    // Guard against vacuity: the test only distinguishes a ratchet from a
    // live-node scan if the adversarial node (id 1) was actually tombstoned.
    // If it were still live, a scan would pass too and prove nothing.
    assert!(
        fg.get(1).is_none(),
        "compaction must have tombstoned the adversarial node for this test to bite"
    );

    // The original adversarial node is now tombstoned, yet the taint persists.
    assert!(
        fg.is_tainted(),
        "is_tainted must survive compaction — the ratchet, not a live-node scan"
    );
    assert!(
        !fg.session_exfiltration_check(ConfLevel::Public).is_safe()
            || fg.session_taint_ceiling() != portcullis_core::DerivationClass::Deterministic,
        "session taint ceiling must also survive compaction"
    );
}
