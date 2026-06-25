//! Parity: runtime IFC confidentiality-downflow enforcement ≡ an independent
//! join-of-intrinsic-labels oracle.
//!
//! # Why this exists (closing "proven ≠ enforced", confidentiality axis)
//!
//! The runtime exfiltration gate (`FlowTracker` graph: `observe` →
//! `check_confidentiality_flow`, the engine `nucleus-ifc::FlowDeclaration::decide`
//! runs) and the algebraic flow relation (`flow_algebra::FlowState::flows_to`,
//! whose axioms mirror the Lean model) are two *separate* code paths in this
//! crate, with no test tying them. This test ties the **confidentiality
//! downflow** axis — the secret→public exfiltration axis behind EchoLeak-class
//! incidents — by checking the graph engine's verdict against an independent
//! oracle computed directly from `intrinsic_label` joins.
//!
//! It is EXHAUSTIVE over every subset of the confidentiality-bearing node kinds
//! × every sink confidentiality ceiling (≈1.5k cases), so it is a proof over the
//! finite input space, not a sample.
//!
//! Scope (honest): confidentiality axis only. Integrity-upflow and authority
//! parity are a documented follow-on — `flow_algebra`'s concrete `SinkClass`
//! taxonomy and the graph's `(requires_authority, sink_max_conf)` sink
//! parameterization need an explicit correspondence first.

use portcullis_core::ConfLevel;
use portcullis_core::flow::{NodeKind, intrinsic_label};
use portcullis_core::ifc_api::FlowTracker;

/// Freshness clock for intrinsic labels — irrelevant to confidentiality, fixed
/// so the test is deterministic and recompute-stable.
const NOW: u64 = 0;

/// The confidentiality-bearing source kinds a call may declare (mirrors
/// `nucleus_ifc::DeclaredInput`). `OutboundAction` is the sink, handled separately.
const SOURCES: &[NodeKind] = &[
    NodeKind::UserPrompt,
    NodeKind::WebContent,
    NodeKind::ToolResponse,
    NodeKind::FileRead,
    NodeKind::EnvVar,
    NodeKind::Secret,
    NodeKind::DatabaseRow,
    NodeKind::MemoryRead,
    NodeKind::HTTPResponse,
];

const SINK_CEILINGS: &[ConfLevel] = &[ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];

/// The engine bounds parent fan-in (`observe_with_parents` rejects >8). The
/// confidentiality join is idempotent over levels, so every reachable joined
/// confidentiality is already covered by the ≤8-source subsets — we exhaust those.
const MAX_PARENTS: usize = 8;

/// Independent oracle: the confidentiality the sink node carries is the join
/// (= max, BLP-covariant) of its own intrinsic confidentiality and that of every
/// parent source. Computed straight from `intrinsic_label`, no graph machinery.
fn expected_sink_conf(sources: &[NodeKind]) -> ConfLevel {
    let mut conf = intrinsic_label(NodeKind::OutboundAction, NOW).confidentiality;
    for &s in sources {
        conf = conf.max(intrinsic_label(s, NOW).confidentiality);
    }
    conf
}

/// Run the runtime graph path: observe the sources, observe the outbound sink
/// with those parents, ask the engine whether the confidentiality downflow is safe.
fn graph_conf_safe(sources: &[NodeKind], sink_max_conf: ConfLevel) -> bool {
    let mut tracker = FlowTracker::new();
    let parents: Vec<u64> = sources
        .iter()
        .map(|&k| tracker.observe(k).expect("observe source"))
        .collect();
    let sink = tracker
        .observe_with_parents(NodeKind::OutboundAction, &parents)
        .expect("observe sink");
    tracker
        .check_confidentiality_flow(sink, sink_max_conf)
        .is_safe()
}

#[test]
fn runtime_confidentiality_enforcement_matches_intrinsic_join_oracle() {
    let n = SOURCES.len();
    let mut checked = 0u64;
    // Exhaustive over every subset of SOURCES.
    for mask in 0u32..(1u32 << n) {
        let subset: Vec<NodeKind> = (0..n)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| SOURCES[i])
            .collect();
        if subset.len() > MAX_PARENTS {
            continue; // engine fan-in bound; joined conf already covered by smaller subsets
        }
        let expected_conf = expected_sink_conf(&subset);
        for &ceiling in SINK_CEILINGS {
            // Oracle: downflow is safe iff the joined confidentiality fits the ceiling.
            let oracle_safe = expected_conf <= ceiling;
            let graph_safe = graph_conf_safe(&subset, ceiling);
            assert_eq!(
                graph_safe, oracle_safe,
                "confidentiality parity broke: sources={subset:?} ceiling={ceiling:?} \
                 (joined conf={expected_conf:?}); graph said safe={graph_safe}, oracle={oracle_safe}"
            );
            checked += 1;
        }
    }
    // All subsets except the single full-9 one (which exceeds the fan-in bound).
    assert_eq!(checked, ((1u64 << n) - 1) * SINK_CEILINGS.len() as u64);
}

/// Spot-check the exfil-critical direction explicitly (defense in depth + doc):
/// a Secret source can never flow to a Public sink, and a Public source always can.
#[test]
fn secret_never_flows_public_public_always_does() {
    assert!(
        !graph_conf_safe(&[NodeKind::Secret], ConfLevel::Public),
        "secret -> public egress must be denied (the EchoLeak exfil direction)"
    );
    assert!(
        graph_conf_safe(&[NodeKind::WebContent], ConfLevel::Public),
        "public web content -> public sink is a safe downflow"
    );
}
