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
//!
//! Every token here goes through the ONLY public apply path: a governor kernel
//! signs it, `Kernel::verify_declassification` mints the witness, and
//! `FlowGraph::apply_verified` spends it. Until 2026-09-27 these tests called the
//! unsigned `FlowGraph::apply_token` directly — which compiling from an external
//! test crate proved any caller could do. That primitive is now `pub(crate)`,
//! and the sources are observed with a content hash the tokens commit to, so the
//! value binding holds and the sink-scope property is measured on the real path.

#![cfg(feature = "crypto")]

use portcullis::flow_graph::FlowGraph;
use portcullis::kernel::Kernel;
use portcullis::token_sign;
use portcullis::PermissionLattice;
use portcullis_core::declassify::{
    DeclassificationRule, DeclassificationToken, DeclassifyAction, TokenApplyResult,
};
use portcullis_core::flow::NodeKind;
use portcullis_core::{ConfLevel, ContentHash, Operation};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const NOW: u64 = 1000;

/// The monitor-recorded content identity every source carries and every token
/// commits to (non-zero, so the tokens are value-bound).
const VALUE_ID: [u8; 32] = [0x5Au8; 32];

/// A governor: a signing key and a kernel that trusts it.
struct Governor {
    key: Ed25519KeyPair,
    kernel: Kernel,
}

fn governor() -> Governor {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(key.public_key().as_ref());
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.set_trusted_keys(vec![pk]);
    Governor { key, kernel }
}

/// A Secret env-var observation carrying [`VALUE_ID`] as its recorded content.
fn secret_source(g: &mut FlowGraph) -> u64 {
    g.observe_with_content_hash(
        NodeKind::EnvVar,
        &[],
        NOW,
        ContentHash::from_bytes(VALUE_ID),
    )
    .unwrap()
}

/// A graph with one Secret-confidentiality source node (`EnvVar` intrinsic:
/// Secret / Trusted / SYSTEM / NoAuthority / Deterministic).
fn graph_with_secret_source() -> (FlowGraph, u64) {
    let mut g = FlowGraph::new();
    let src = secret_source(&mut g);
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
    .with_content_commitment(VALUE_ID)
}

/// Release `target` for `sinks` the only way a caller outside the crate can:
/// sign, verify (mint the witness), spend it on `g`.
fn release(g: &mut FlowGraph, target: u64, sinks: Vec<Operation>) -> TokenApplyResult {
    let gov = governor();
    let mut token = lower_conf_token(target, sinks);
    token_sign::sign_token(&mut token, &gov.key);
    let v = gov
        .kernel
        .verify_declassification(&token)
        .expect("a governor-signed token verifies");
    g.apply_verified(v, NOW)
        .expect("a fresh token is not a replay")
}

#[test]
fn graph_verdicts_match_the_extracted_decision_pointwise() {
    // The granted sinks: one exfil-class operation (where the conf axis is
    // decision-relevant) and one mutation operation.
    let granted = vec![Operation::WebFetch, Operation::WriteFiles];

    // Token graph: scoped release on the source.
    let (mut g_token, src_t) = graph_with_secret_source();
    let apply = release(&mut g_token, src_t, granted.clone());
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
    release(&mut g2_token, t2, vec![Operation::WebFetch]);
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
    release(&mut g, src, vec![Operation::WriteFiles]);

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
    let a = secret_source(&mut g);
    let b = secret_source(&mut g);
    assert!(matches!(
        release(&mut g, a, vec![Operation::WebFetch]),
        TokenApplyResult::Applied { .. }
    ));
    assert!(matches!(
        release(&mut g, b, vec![Operation::WriteFiles]),
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
    let c = secret_source(&mut g2);
    let d = secret_source(&mut g2);
    release(&mut g2, c, vec![Operation::WriteFiles, Operation::WebFetch]);
    release(
        &mut g2,
        d,
        vec![Operation::WriteFiles, Operation::GitCommit],
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
    release(&mut g, src, vec![Operation::WriteFiles]);

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
    let tag = |a: &[u8; 32]| u64::from(a[0]);

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

/// **Phase 5 — four-run VALUE robustness: the released value is not
/// attacker-steerable.** The executable image of
/// `DeclassifySinkScopeExtracted::four_run_value_robustness`. A governor signs ONE
/// value commitment (attacker-independent); the node's recorded content identity
/// is a MONITOR-recorded fact derived from the (attacker-influenced) workload.
/// Over four runs that vary ONLY that attacker-controlled recorded content, each
/// run either RELEASES exactly the committed value or DENIES (`ValueMismatch`) —
/// no attacker input releases a different value. Bound to the extracted
/// `value_authorized` decision, and non-vacuous: one arm releases, one denies, and
/// every released value provably equals the governor commitment.
#[test]
fn four_run_released_value_is_not_attacker_steerable() {
    use portcullis::flow_graph::ReleaseAuth;
    use portcullis_core::extracted::declassify::value_authorized;
    use portcullis_core::IFCLabel;

    let released_label = IFCLabel::bottom();
    let v = |b: u8| {
        let mut a = [0u8; 32];
        a[0] = b;
        a
    };
    let tag = |a: &[u8; 32]| u64::from(a[0]);

    // Governor-signed commitment — fixed across all runs (attacker-independent).
    let committed = v(7);

    // What a run egresses: on Authorized, the node's recorded content (the value
    // that physically leaves the boundary); None on any deny. Mirrors Lean
    // `runValue`, which releases the RECORDED content — the value-binding check is
    // what forces it to equal the commitment.
    let run = |recorded: [u8; 32], burn: [u8; 32]| -> Option<[u8; 32]> {
        let mut g = FlowGraph::new();
        match g.authorize_release(committed, recorded, released_label, u16::MAX, burn) {
            ReleaseAuth::Authorized(_) => Some(recorded),
            _ => None,
        }
    };

    // Two attacker-controlled recorded identities: one matches the commitment, one
    // substitutes a different value. Four runs = 2 identities × 2 independent
    // attacker attempts (distinct burn ids, fresh graph each, so the one-shot
    // ledger never confounds the value axis).
    let attacker_recorded = [v(7), v(9)];
    let mut released_values: Vec<[u8; 32]> = Vec::new();
    let mut any_release = false;
    let mut any_deny = false;

    for (i, rec) in attacker_recorded.iter().enumerate() {
        for attempt in 0u8..2 {
            let mut burn = [0u8; 32];
            burn[0] = 10 + attempt;
            burn[1] = i as u8;
            let out = run(*rec, burn);

            // Parity: the runtime authorize decision equals the extracted model.
            let model = value_authorized(committed != [0u8; 32], true, tag(&committed), tag(rec));
            assert_eq!(
                out.is_some(),
                model,
                "runtime authorize_release disagreed with the extracted value_authorized \
                 (recorded {rec:?})"
            );

            match out {
                Some(value) => {
                    any_release = true;
                    // Teeth: a release egresses exactly the governor commitment,
                    // never the attacker's substituted value.
                    assert_eq!(
                        value, committed,
                        "a release egressed a value the governor did not commit — value steered"
                    );
                    released_values.push(value);
                }
                None => any_deny = true,
            }
        }
    }

    // Four-run non-steering: every released value is identical (all == commitment).
    for w in released_values.windows(2) {
        assert_eq!(
            w[0], w[1],
            "two runs with different attacker input released different values"
        );
    }

    // Non-vacuity: the attacker inputs genuinely differ AND both arms are
    // reachable — one run RELEASED (recorded matched the commitment) and one
    // DENIED (recorded was substituted). Without both, the assertions above would
    // be vacuous.
    assert_ne!(
        attacker_recorded[0], attacker_recorded[1],
        "test premise: attacker inputs must actually differ"
    );
    assert!(
        any_release,
        "non-vacuity: no run ever released — the gate denies everything"
    );
    assert!(
        any_deny,
        "non-vacuity: no run ever denied — value-binding is not enforced"
    );
}
