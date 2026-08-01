//! The `ZkFlowInput` producer, exercised through the public API.
//!
//! These live outside `src/` on purpose. `flow.rs` is kernel and the boundary
//! ratchet (`kernel_boundary_ratchet.rs`) forbids it from reaching up to
//! `FlowTracker` — including from its own `#[cfg(test)]` module. An integration
//! test is also the honest place for them: it composes the two halves exactly as
//! a real producer must, across the same public surface.
//!
//! The point of the suite is **non-vacuity**. `ZkFlowInput` had a verifier and a
//! zkVM guest and no producer, and the obvious producer — hand the verifier the
//! session's graph — confirms `Allow` for every session that has ever run. The
//! first test pins that failure mode so the rest are known to be testing
//! something.

use nucleus_ifc_kernel::IntegLevel;
use nucleus_ifc_kernel::flow::{
    FlowVerdict, NodeId, NodeKind, VerificationResult, ZkFlowInput, check_flow,
    verify_noninterference,
};
use nucleus_ifc_kernel::ifc_api::FlowTracker;
use nucleus_ifc_kernel::{Operation, SinkClass};

// ═══════════════════════════════════════════════════════════════════════
// ZkFlowInput::for_action — the producer, and its non-vacuity
// ═══════════════════════════════════════════════════════════════════════

/// **The vacuity this constructor exists to avoid.** A `ZkFlowInput` built
/// from a snapshot ALONE confirms `Allow` for any session, however tainted,
/// because every node a `FlowTracker` holds is an observation and
/// `check_flow` returns `Allow` for `operation: None`.
///
/// This test asserts the failure mode is real. If it ever REDs, the claim in
/// `FlowTracker::snapshot`'s doc comment is wrong and `for_action` may no
/// longer be load-bearing.
#[test]
fn a_snapshot_alone_would_confirm_allow_for_a_maximally_tainted_session() {
    let mut tracker = FlowTracker::new();
    let adversarial = tracker
        .observe(NodeKind::WebContent)
        .expect("observe web content");
    assert_eq!(
        tracker.snapshot()[(adversarial - 1) as usize]
            .label
            .integrity,
        IntegLevel::Adversarial,
        "fixture must actually be tainted"
    );

    let snapshot = tracker.snapshot();
    let last = snapshot.last().unwrap().id;
    let vacuous = ZkFlowInput {
        action_node_id: last,
        expected_verdict: FlowVerdict::Allow,
        nodes: snapshot,
    };
    assert_eq!(
        verify_noninterference(&vacuous),
        VerificationResult::Confirmed,
        "a snapshot-only input is expected to confirm Allow vacuously; \
         if this changed, revisit FlowTracker::snapshot's documented caveat"
    );
}

/// **The refutable witness.** The same tainted session, with the action the
/// kernel would actually be authorising attached, must NOT confirm `Allow`.
/// This is the assertion that distinguishes a real producer from the vacuous
/// one above.
#[test]
fn for_action_refuses_to_confirm_allow_on_a_tainted_exfil_action() {
    let mut tracker = FlowTracker::new();
    let tainted = tracker.observe(NodeKind::WebContent).expect("observe");

    let input = ZkFlowInput::for_action(
        tracker.snapshot(),
        Operation::WebFetch,
        Some(SinkClass::HTTPEgress),
        &[tainted],
        FlowVerdict::Allow,
    );

    assert!(
        matches!(
            verify_noninterference(&input),
            VerificationResult::Mismatch { .. }
        ),
        "adversarial content flowing to an exfil sink must not verify as Allow; got {:?}",
        verify_noninterference(&input)
    );
}

/// **The satisfiable witness.** The producer must also be able to confirm a
/// verdict — a constructor that only ever mismatches proves nothing either.
#[test]
fn for_action_confirms_the_deny_the_kernel_would_reach() {
    let mut tracker = FlowTracker::new();
    let tainted = tracker.observe(NodeKind::WebContent).expect("observe");

    let action_node = ZkFlowInput::for_action(
        tracker.snapshot(),
        Operation::WebFetch,
        Some(SinkClass::HTTPEgress),
        &[tainted],
        FlowVerdict::Allow,
    );
    // Ask the kernel what the verdict actually is, then assert the producer
    // confirms THAT — rather than hard-coding a reason this test would keep
    // asserting after the policy changed underneath it.
    let action = action_node
        .nodes
        .iter()
        .find(|n| n.id == action_node.action_node_id)
        .unwrap();
    let real_verdict = check_flow(action, 0);
    assert!(
        matches!(real_verdict, FlowVerdict::Deny(_)),
        "fixture should be denied, got {real_verdict:?}"
    );

    let honest = ZkFlowInput::for_action(
        tracker.snapshot(),
        Operation::WebFetch,
        Some(SinkClass::HTTPEgress),
        &[tainted],
        real_verdict,
    );
    assert_eq!(
        verify_noninterference(&honest),
        VerificationResult::Confirmed
    );
}

/// A clean session taking an ordinary action confirms `Allow` — so the
/// producer is not simply denying everything.
#[test]
fn for_action_confirms_allow_on_a_clean_session() {
    let mut tracker = FlowTracker::new();
    let clean = tracker.observe(NodeKind::UserPrompt).expect("observe");

    let input = ZkFlowInput::for_action(
        tracker.snapshot(),
        Operation::ReadFiles,
        Some(SinkClass::WorkspaceWrite),
        &[clean],
        FlowVerdict::Allow,
    );
    assert_eq!(
        verify_noninterference(&input),
        VerificationResult::Confirmed
    );
}

/// The action's label must be DERIVED from its parents, not accepted from a
/// caller. Attaching a tainted parent must change the action's label, or the
/// verifier is re-checking a label the prover chose.
#[test]
fn the_action_label_is_derived_from_its_parents() {
    let mut tracker = FlowTracker::new();
    let clean = tracker.observe(NodeKind::UserPrompt).expect("observe");
    let tainted = tracker.observe(NodeKind::WebContent).expect("observe");

    let label_of = |parents: &[NodeId]| {
        let i = ZkFlowInput::for_action(
            tracker.snapshot(),
            Operation::WebFetch,
            Some(SinkClass::HTTPEgress),
            parents,
            FlowVerdict::Allow,
        );
        i.nodes
            .iter()
            .find(|n| n.id == i.action_node_id)
            .unwrap()
            .label
    };

    assert_ne!(
        label_of(&[clean]).integrity,
        label_of(&[tainted]).integrity,
        "the action's label did not move with its parents -- it is not being propagated"
    );
}

/// Parent references must point at nodes that exist, or
/// `verify_noninterference` reports `BrokenParentRef` and the whole input is
/// unusable. This pins the 1-based id convention shared with `observe*`.
#[test]
fn snapshot_ids_line_up_with_observe_ids() {
    let mut tracker = FlowTracker::new();
    let a = tracker.observe(NodeKind::UserPrompt).expect("observe");
    let b = tracker
        .observe_with_parents(NodeKind::DeterministicBind, &[a])
        .expect("observe with parent");

    let input = ZkFlowInput::for_action(
        tracker.snapshot(),
        Operation::ReadFiles,
        None,
        &[b],
        FlowVerdict::Allow,
    );
    assert_ne!(
        verify_noninterference(&input),
        VerificationResult::BrokenParentRef {
            node_id: b,
            parent_id: a
        },
        "snapshot ids must match the ids observe() handed out"
    );
    assert_eq!(
        verify_noninterference(&input),
        VerificationResult::Confirmed
    );
}
