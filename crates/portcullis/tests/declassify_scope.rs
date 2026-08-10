//! Pointwise graph binding for sink-scoped declassification.
//!
//! The extracted decision layer (`nucleus-ifc-kernel::extracted::declassify`)
//! is bound to `allows_sink` by an exhaustive 2^13 × 13 parity sweep in
//! portcullis-core. This test binds the OTHER end: that `FlowGraph` verdicts
//! actually route through that layer — the same binding layer FM-5 uses for
//! its spawn path.
//!
//! Shape: one graph carries a signed-shape token scoped to a subset of sinks;
//! two ORACLE graphs bracket it — the strict oracle (no token at all) and the
//! released oracle (the parent's label force-lowered globally, the historical
//! behavior). For every one of the 13 operations:
//!
//!   * in-mask   ⇒ the token graph's verdict equals the RELEASED oracle's;
//!   * off-mask  ⇒ the token graph's verdict equals the STRICT oracle's.
//!
//! Plus the executable two-run statement: off-mask verdicts are IDENTICAL to
//! a run in which the token never existed — a token scoped to one sink is
//! unobservable at every other sink. Non-vacuity: the oracles must differ on
//! at least one operation, or every assertion above is comparing equal
//! things and the test proves nothing.

use portcullis::flow_graph::FlowGraph;
use portcullis_core::declassify::{
    DeclassificationRule, DeclassificationToken, DeclassifyAction, TokenApplyResult,
};
use portcullis_core::flow::NodeKind;
use portcullis_core::{ConfLevel, Operation};

const NOW: u64 = 1000;

/// A graph with one Secret-confidentiality source node (`EnvVar` intrinsic:
/// Secret / Trusted / SYSTEM / NoAuthority / Deterministic).
fn graph_with_secret_source() -> (FlowGraph, u64) {
    let mut g = FlowGraph::new();
    let src = g.insert_observation(NodeKind::EnvVar, &[], NOW).unwrap();
    assert_eq!(
        g.get(src).unwrap().label.confidentiality,
        ConfLevel::Secret,
        "test premise: the source must start Secret"
    );
    (g, src)
}

fn lower_conf_token(target: u64, sinks: Vec<Operation>) -> DeclassificationToken {
    DeclassificationToken::new(
        target,
        DeclassificationRule {
            action: DeclassifyAction::LowerConfidentiality {
                from: ConfLevel::Secret,
                to: ConfLevel::Internal,
            },
            justification: "sink-scope binding test".to_string(),
        },
        sinks,
        NOW + 3600,
        "sink-scope binding test".to_string(),
    )
}

#[test]
fn graph_verdicts_match_the_extracted_decision_pointwise() {
    // The granted sinks: one exfil-class operation (where the conf axis is
    // decision-relevant) and one mutation operation.
    let granted = vec![Operation::WebFetch, Operation::WriteFiles];

    // Token graph: scoped release on the source.
    let (mut g_token, src_t) = graph_with_secret_source();
    let apply = g_token.apply_token(&lower_conf_token(src_t, granted.clone()), NOW);
    assert!(
        matches!(apply, TokenApplyResult::Applied { .. }),
        "token failed to apply: {apply:?}"
    );

    // Strict oracle: no token ever existed.
    let (mut g_strict, src_s) = graph_with_secret_source();

    // Released oracle: the historical global lowering, forced.
    let (mut g_released, src_r) = graph_with_secret_source();
    let released_label = {
        let mut l = g_released.get(src_r).unwrap().label;
        l.confidentiality = ConfLevel::Internal;
        l
    };
    g_released.modify_label_forced(src_r, released_label);

    let mut oracle_divergence_seen = false;

    for op in Operation::ALL {
        let v_token = g_token.insert_action(op, &[src_t], NOW).unwrap().verdict;
        let v_strict = g_strict.insert_action(op, &[src_s], NOW).unwrap().verdict;
        let v_released = g_released.insert_action(op, &[src_r], NOW).unwrap().verdict;

        if v_strict != v_released {
            oracle_divergence_seen = true;
        }

        if granted.contains(&op) {
            assert_eq!(
                v_token, v_released,
                "in-mask operation {op:?} did not see the released view"
            );
        } else {
            assert_eq!(
                v_token, v_strict,
                "off-mask operation {op:?} diverged from the token-free run — \
                 the release leaked outside its signed sink mask"
            );
        }
    }

    assert!(
        oracle_divergence_seen,
        "the strict and released oracles never differed — every comparison \
         above was vacuous and this test proved nothing"
    );

    // The differential is visible where it should be: WebFetch is granted
    // and exfil-class, so the released view must change its verdict.
    let (mut g2_strict, s2) = graph_with_secret_source();
    let (mut g2_token, t2) = graph_with_secret_source();
    g2_token.apply_token(&lower_conf_token(t2, vec![Operation::WebFetch]), NOW);
    let strict_fetch = g2_strict
        .insert_action(Operation::WebFetch, &[s2], NOW)
        .unwrap();
    let token_fetch = g2_token
        .insert_action(Operation::WebFetch, &[t2], NOW)
        .unwrap();
    assert_ne!(
        strict_fetch.verdict, token_fetch.verdict,
        "non-vacuity: releasing Secret→Internal for WebFetch must change \
         the WebFetch verdict (rule 1 no longer fires)"
    );
}

#[test]
fn stored_labels_and_decision_labels_stay_strict() {
    // The release must be invisible in everything that persists: the stored
    // node label, the FlowDecision label (what the kernel joins into the
    // session flow cache), and the receipt's recomputed verdict must all be
    // derived from the same stored state.
    let (mut g, src) = graph_with_secret_source();
    g.apply_token(&lower_conf_token(src, vec![Operation::WriteFiles]), NOW);

    let decision = g.insert_action(Operation::WriteFiles, &[src], NOW).unwrap();

    // The action node's stored label is the strict join — Secret.
    assert_eq!(
        g.get(decision.node_id).unwrap().label.confidentiality,
        ConfLevel::Secret,
        "the stored action label was laundered by the release"
    );
    // FlowDecision.label — the value the kernel accumulates into session
    // taint — is the strict one too: a token never cleanses a session.
    assert_eq!(
        decision.label.confidentiality,
        ConfLevel::Secret,
        "FlowDecision.label was laundered by the release"
    );

    // Receipt recomputation agrees with the insert-time verdict: the scope
    // is stored state, so the one verdict path serves both.
    let receipt = g.build_receipt_for(decision.node_id, NOW).unwrap();
    assert_eq!(
        receipt.verdict(),
        decision.verdict,
        "receipt recomputation disagreed with the insert-time verdict"
    );
}

#[test]
fn inherited_scope_intersects_toward_strict() {
    // Two declassified parents with DISJOINT masks: the child's mask is the
    // intersection — empty — so the child is strict everywhere, even for
    // operations each parent granted individually. The deliberate sound
    // over-approximation.
    let mut g = FlowGraph::new();
    let a = g.insert_observation(NodeKind::EnvVar, &[], NOW).unwrap();
    let b = g.insert_observation(NodeKind::EnvVar, &[], NOW).unwrap();
    assert!(matches!(
        g.apply_token(&lower_conf_token(a, vec![Operation::WebFetch]), NOW),
        TokenApplyResult::Applied { .. }
    ));
    assert!(matches!(
        g.apply_token(&lower_conf_token(b, vec![Operation::WriteFiles]), NOW),
        TokenApplyResult::Applied { .. }
    ));

    let child = g
        .insert_observation(NodeKind::ModelPlan, &[a, b], NOW)
        .unwrap();
    for op in [Operation::WebFetch, Operation::WriteFiles] {
        assert_eq!(
            g.effective_label(child, op).unwrap().confidentiality,
            ConfLevel::Secret,
            "disjoint parent masks must intersect to strict for {op:?}"
        );
    }

    // Overlapping masks DO survive: a child of two parents that both grant
    // WriteFiles keeps the release for WriteFiles and only WriteFiles.
    let mut g2 = FlowGraph::new();
    let c = g2.insert_observation(NodeKind::EnvVar, &[], NOW).unwrap();
    let d = g2.insert_observation(NodeKind::EnvVar, &[], NOW).unwrap();
    g2.apply_token(
        &lower_conf_token(c, vec![Operation::WriteFiles, Operation::WebFetch]),
        NOW,
    );
    g2.apply_token(
        &lower_conf_token(d, vec![Operation::WriteFiles, Operation::GitCommit]),
        NOW,
    );
    let child2 = g2
        .insert_observation(NodeKind::ModelPlan, &[c, d], NOW)
        .unwrap();
    assert_eq!(
        g2.effective_label(child2, Operation::WriteFiles)
            .unwrap()
            .confidentiality,
        ConfLevel::Internal,
        "a jointly granted sink must keep the release in the child"
    );
    for op in [Operation::WebFetch, Operation::GitCommit] {
        assert_eq!(
            g2.effective_label(child2, op).unwrap().confidentiality,
            ConfLevel::Secret,
            "a sink granted by only one parent must be strict in the child"
        );
    }
}

#[test]
fn causal_label_for_honors_the_scope() {
    let (mut g, src) = graph_with_secret_source();
    g.apply_token(&lower_conf_token(src, vec![Operation::WriteFiles]), NOW);

    // The op-aware prospective label sees the release exactly in-mask…
    assert_eq!(
        g.causal_label_for(&[src], Operation::WriteFiles, NOW)
            .unwrap()
            .confidentiality,
        ConfLevel::Internal
    );
    assert_eq!(
        g.causal_label_for(&[src], Operation::GitPush, NOW)
            .unwrap()
            .confidentiality,
        ConfLevel::Secret
    );
    // …and the op-blind causal_label stays strict (it answers "what taint
    // does this ancestry carry", not "may this specific action run").
    assert_eq!(
        g.causal_label(&[src], NOW).unwrap().confidentiality,
        ConfLevel::Secret
    );
}

/// **Phase 4 parity: the shared governed-release value-binding equals the
/// extracted decision `value_authorized`.** Both mint policies (Ed25519 token,
/// k-of-n threshold) route their value-binding through
/// `FlowGraph::authorize_release`; this binds its runtime decision to the proven
/// scalar core `bound ∧ present ∧ equal`, so the runtime equals the algebra for
/// the unified path — and exercises the one-shot burn (a replay is refused).
#[test]
fn authorize_release_value_binding_matches_the_extracted_decision() {
    use portcullis::flow_graph::ReleaseAuth;
    use portcullis_core::extracted::declassify::value_authorized;
    use portcullis_core::IFCLabel;

    // The released label is irrelevant to the value-binding / one-shot decision.
    let released = IFCLabel::bottom();
    // Opaque 32-byte value identities; the scalar model tags them by first byte.
    let v = |b: u8| {
        let mut a = [0u8; 32];
        a[0] = b;
        a
    };
    let tag = |a: &[u8; 32]| a[0] as u64;

    // committed == recorded (both non-zero) ⇒ Authorized AND value_authorized true.
    for (committed, recorded) in [(v(7), v(7)), (v(7), v(9)), (v(9), v(7))] {
        let mut g = FlowGraph::new();
        let out = g.authorize_release(committed, recorded, released, u16::MAX, [1u8; 32]);
        let model = value_authorized(
            committed != [0u8; 32],
            true,
            tag(&committed),
            tag(&recorded),
        );
        assert_eq!(
            matches!(out, ReleaseAuth::Authorized(_)),
            model,
            "authorize_release value-binding must equal the extracted decision"
        );
    }

    // One-shot: the burned id is refused as Replayed on the second call.
    let mut g = FlowGraph::new();
    assert!(matches!(
        g.authorize_release(v(7), v(7), released, u16::MAX, [2u8; 32]),
        ReleaseAuth::Authorized(_)
    ));
    assert_eq!(
        g.authorize_release(v(7), v(7), released, u16::MAX, [2u8; 32]),
        ReleaseAuth::Replayed,
        "a replayed authorization id is refused (one-shot burn)"
    );
    // An empty sink mask releases to nothing.
    assert_eq!(
        FlowGraph::new().authorize_release(v(7), v(7), released, 0, [3u8; 32]),
        ReleaseAuth::EmptyMask,
    );
}
