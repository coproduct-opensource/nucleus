//! Phase 4.5 — scope-honoring egress on the LIVE graph + the re-homed Ed25519
//! apply.
//!
//! These tests pin the two-part change end to end **on ONE `FlowGraph`** (the
//! bug the re-home fixes was that the apply wrote to a *separate*, never-read
//! graph):
//!
//! * **C4 flip-back** — a Secret env-var node denies `GitPush`; a governor-signed,
//!   value-bound, `GitPush`-scoped token applied to that same graph flips the
//!   verdict to `Pass`, and ONLY for the signed sink and the committed value.
//! * **Fail-open boundary matrix** — every adversarial variant (substituted
//!   value, an unsigned sink, replay, a second undeclassified secret, poison)
//!   stays `Deny`/refused AFTER the apply. This is the load-bearing direction:
//!   the refinement may only ever *lower* under full visibility, never open a
//!   hole the ratchet would have closed.

#![cfg(feature = "crypto")]

use portcullis::exposure_core::{ifc_egress_verdict, EgressVerdict};
use portcullis::flow_graph::FlowGraph;
use portcullis::kernel::{DenyReason, Kernel};
use portcullis::token_sign;
use portcullis::{Operation, PermissionLattice};
use portcullis_core::declassify::{
    DeclassificationRule, DeclassificationToken, DeclassifyAction, TokenApplyResult,
};
use portcullis_core::flow::NodeKind;
use portcullis_core::{ConfLevel, ContentHash};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// The recorded content identity a value-bound token commits to (non-zero so the
/// token is value-bound). `H` in the directive.
const H: [u8; 32] = [0x5Au8; 32];
/// A DIFFERENT value identity — a substituted value the governor did NOT sign.
const OTHER: [u8; 32] = [0xA5u8; 32];

fn test_key() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn public_key_bytes(key: &Ed25519KeyPair) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(key.public_key().as_ref());
    bytes
}

/// A governor kernel trusting `key`. It never holds the session graph — the
/// re-home means it applies onto whatever graph the caller passes.
fn governor_kernel(key: &Ed25519KeyPair) -> Kernel {
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.set_trusted_keys(vec![public_key_bytes(key)]);
    kernel
}

/// A Secret env-var observation carrying `hash` as its monitor-recorded content
/// identity, on a standalone graph.
fn observe_secret(g: &mut FlowGraph, hash: [u8; 32]) -> u64 {
    g.observe_with_content_hash(NodeKind::EnvVar, &[], 0, ContentHash::from_bytes(hash))
        .expect("observe secret env var")
}

/// A signed, value-bound `Secret -> Public` token scoped to `sinks`, committing
/// to `commitment`.
fn signed_token(
    key: &Ed25519KeyPair,
    node_id: u64,
    sinks: Vec<Operation>,
    commitment: [u8; 32],
) -> DeclassificationToken {
    let mut token = DeclassificationToken::new(
        node_id,
        DeclassificationRule {
            action: DeclassifyAction::LowerConfidentiality {
                from: ConfLevel::Secret,
                to: ConfLevel::Public,
            },
            justification: "governor releases the env var for the signed sink".to_string(),
        },
        sinks,
        u64::MAX,
        "released env var".to_string(),
    )
    .with_content_commitment(commitment);
    token_sign::sign_token(&mut token, key);
    token
}

/// The LIVE gate as `ifc_flow_gate` composes it: poison denies everything, else
/// the scope-aware egress verdict decides. `ifc_egress_verdict` alone does not
/// consult poison (by design — poison is a separate, broader gate), so the poison
/// boundary case must go through this.
fn gate_denies(g: &FlowGraph, op: Operation) -> bool {
    if g.is_poisoned() {
        return true;
    }
    matches!(
        ifc_egress_verdict(g, op, NodeKind::OutboundAction, false),
        EgressVerdict::Deny(_)
    )
}

fn is_deny(g: &FlowGraph, op: Operation) -> bool {
    matches!(
        ifc_egress_verdict(g, op, NodeKind::OutboundAction, false),
        EgressVerdict::Deny(_)
    )
}

fn is_pass(g: &FlowGraph, op: Operation) -> bool {
    matches!(
        ifc_egress_verdict(g, op, NodeKind::OutboundAction, false),
        EgressVerdict::Pass
    )
}

// ── C4 flip-back ───────────────────────────────────────────────────────────

#[test]
fn c4_flip_back_on_one_graph() {
    let key = test_key();
    let kernel = governor_kernel(&key);
    let mut g = FlowGraph::new();

    // A Secret env-var node with recorded content hash H.
    let node = observe_secret(&mut g, H);

    // Before: a secret-bearing session cannot push (Secret > Internal).
    assert!(
        is_deny(&g, Operation::GitPush),
        "a secret env var must deny git push before declassification"
    );

    // A governor signs a value-bound, GitPush-scoped Secret->Public token and
    // applies it TO THIS SAME GRAPH (the re-home).
    let token = signed_token(&key, node, vec![Operation::GitPush], H);
    let result = kernel
        .apply_declassification_token_on(&mut g, &token)
        .expect("verified apply must not error");
    assert!(
        matches!(result, TokenApplyResult::Applied { .. }),
        "expected Applied, got {result:?}"
    );

    // After: the verdict flips to Pass — the released view opens exactly this
    // node, for this sink, for the committed value.
    assert!(
        is_pass(&g, Operation::GitPush),
        "git push must PASS after the scoped release lands on the live graph"
    );
}

// ── Fail-open boundary matrix — each must stay Deny/refused AFTER apply ───────

/// (a) Substituted value: a token committing to OTHER (≠ H) is refused
/// `ContentMismatch` and the verdict stays Deny — no scope was recorded.
#[test]
fn boundary_a_substituted_value_content_mismatch_stays_deny() {
    let key = test_key();
    let kernel = governor_kernel(&key);
    let mut g = FlowGraph::new();
    let node = observe_secret(&mut g, H);

    let token = signed_token(&key, node, vec![Operation::GitPush], OTHER);
    let result = kernel
        .apply_declassification_token_on(&mut g, &token)
        .expect("verified apply must not error");
    assert_eq!(
        result,
        TokenApplyResult::ContentMismatch,
        "a substituted value must be refused ContentMismatch"
    );
    assert!(
        is_deny(&g, Operation::GitPush),
        "verdict must stay Deny when the value did not match"
    );
}

/// (b) Unsigned sink: a token scoped ONLY to GitPush leaves CreatePr denied —
/// the scope clears its node for the signed sink and no other.
#[test]
fn boundary_b_unsigned_sink_stays_deny() {
    let key = test_key();
    let kernel = governor_kernel(&key);
    let mut g = FlowGraph::new();
    let node = observe_secret(&mut g, H);

    let token = signed_token(&key, node, vec![Operation::GitPush], H);
    let result = kernel
        .apply_declassification_token_on(&mut g, &token)
        .expect("verified apply must not error");
    assert!(matches!(result, TokenApplyResult::Applied { .. }));

    // GitPush opens (the signed sink)…
    assert!(is_pass(&g, Operation::GitPush), "signed sink opens");
    // …but CreatePr (Internal cap, NOT in the mask) stays denied.
    assert!(
        is_deny(&g, Operation::CreatePr),
        "an unsigned sink must stay Deny after a scoped release"
    );
}

/// (c) Replay: a second apply of the same token is refused
/// `DeclassificationReplayed`, and the burn is on THIS graph's ledger.
#[test]
fn boundary_c_second_apply_replayed_burn_on_same_graph() {
    let key = test_key();
    let kernel = governor_kernel(&key);
    let mut g = FlowGraph::new();
    let node = observe_secret(&mut g, H);

    let token = signed_token(&key, node, vec![Operation::GitPush], H);
    let first = kernel
        .apply_declassification_token_on(&mut g, &token)
        .expect("first apply must not error");
    assert!(matches!(first, TokenApplyResult::Applied { .. }));

    // The one-shot burn landed on THIS graph's shared ledger.
    let burn_id = {
        use sha2::{Digest, Sha256};
        let mut hsh = Sha256::new();
        hsh.update(b"nucleus.declassify.token.v1");
        hsh.update(token.signature);
        let out: [u8; 32] = hsh.finalize().into();
        out
    };
    assert!(
        g.is_release_burned(&burn_id),
        "the one-shot burn must be recorded on the graph the apply wrote to"
    );

    // Replaying the SAME token is refused with the dedicated replay verdict.
    let second = kernel.apply_declassification_token_on(&mut g, &token);
    assert!(
        matches!(second, Err(DenyReason::DeclassificationReplayed { .. })),
        "a replayed token must be refused, got {second:?}"
    );
    // GitPush stays open only because the FIRST release stands — the replay
    // neither re-ran nor un-did anything.
    assert!(is_pass(&g, Operation::GitPush));
}

/// (c') A DIFFERENT signed token targeting the already-declassified node is
/// refused `AlreadyDeclassified` (a node is declassified at most once).
#[test]
fn boundary_c_prime_already_declassified() {
    let key = test_key();
    let kernel = governor_kernel(&key);
    let mut g = FlowGraph::new();
    let node = observe_secret(&mut g, H);

    let t1 = signed_token(&key, node, vec![Operation::GitPush], H);
    assert!(matches!(
        kernel.apply_declassification_token_on(&mut g, &t1),
        Ok(TokenApplyResult::Applied { .. })
    ));

    // A fresh token (different signature ⇒ different burn id, so it clears the
    // replay ledger) still cannot re-declassify the node.
    let t2 = signed_token(&key, node, vec![Operation::CreatePr], H);
    let r2 = kernel
        .apply_declassification_token_on(&mut g, &t2)
        .expect("apply must not error");
    assert_eq!(
        r2,
        TokenApplyResult::AlreadyDeclassified,
        "a node is declassified at most once"
    );
}

/// (d) A SECOND, non-declassified Secret node keeps GitPush denied — one scoped
/// release must not clear the whole session's confidentiality ceiling.
#[test]
fn boundary_d_second_secret_node_keeps_deny() {
    let key = test_key();
    let kernel = governor_kernel(&key);
    let mut g = FlowGraph::new();

    let node1 = observe_secret(&mut g, H);
    // A second secret node, committed to a DIFFERENT identity, left undeclassified.
    let _node2 = observe_secret(&mut g, OTHER);

    let token = signed_token(&key, node1, vec![Operation::GitPush], H);
    assert!(matches!(
        kernel.apply_declassification_token_on(&mut g, &token),
        Ok(TokenApplyResult::Applied { .. })
    ));

    // node1 is released, but node2's strict Secret still tops the effective
    // ceiling — GitPush must stay Deny.
    assert!(
        is_deny(&g, Operation::GitPush),
        "a single scoped release must not clear a still-secret second node"
    );
}

/// (e) Poison denies regardless — even after a successful release that made
/// GitPush Pass.
#[test]
fn boundary_e_poison_denies_regardless() {
    let key = test_key();
    let kernel = governor_kernel(&key);
    let mut g = FlowGraph::new();
    let node = observe_secret(&mut g, H);

    let token = signed_token(&key, node, vec![Operation::GitPush], H);
    assert!(matches!(
        kernel.apply_declassification_token_on(&mut g, &token),
        Ok(TokenApplyResult::Applied { .. })
    ));
    assert!(is_pass(&g, Operation::GitPush), "release opened git push");

    // Poison the session: a dropped observation makes taint unprovable.
    g.poison();
    assert!(
        gate_denies(&g, Operation::GitPush),
        "poison must deny regardless of a standing release"
    );
}

// ── No-scope parity (property test) ──────────────────────────────────────────
//
// For graphs with NO scopes and NO compaction, the effective aggregates must
// equal the plain session aggregates for every operation — proving the
// refinement only ever *lowers* under full visibility (it never raises, and with
// nothing to lower it is byte-identical to the historical gate).

use proptest::prelude::*;

/// A small alphabet of observation kinds spanning the confidentiality/integrity
/// corners the aggregates care about.
fn obs_kind(i: u8) -> NodeKind {
    match i % 6 {
        0 => NodeKind::WebContent,    // Public, Adversarial
        1 => NodeKind::EnvVar,        // Secret, Trusted
        2 => NodeKind::Secret,        // Secret, ...
        3 => NodeKind::FileRead,      // Internal
        4 => NodeKind::UserPrompt,    // trusted
        _ => NodeKind::McpToolResult, // Public, Adversarial
    }
}

fn op_of(i: u8) -> Operation {
    Operation::ALL[(i as usize) % Operation::ALL.len()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn no_scope_no_compaction_parity(
        obs in proptest::collection::vec(0u8..6, 0..40),
        acts in proptest::collection::vec(0u8..13, 0..20),
    ) {
        let mut g = FlowGraph::new();
        // Observations only — NO tokens, so no declass scope is ever recorded.
        for &o in &obs {
            g.insert_observation(obs_kind(o), &[], 0).unwrap();
        }
        // A few actions (no parents) exercise action nodes too; still no scopes.
        for &a in &acts {
            let _ = g.insert_action(op_of(a), &[], 0);
        }
        // Well under MAX_GRAPH_NODES, so nothing compacted.

        for op in Operation::ALL {
            prop_assert_eq!(
                g.effective_exfiltration_check(op, portcullis::exposure_core::sink_max_conf_for(op)),
                g.session_exfiltration_check(portcullis::exposure_core::sink_max_conf_for(op)),
                "effective_exfiltration_check diverged from session for {:?}", op
            );
            prop_assert_eq!(
                g.effective_is_tainted(op),
                g.is_tainted(),
                "effective_is_tainted diverged from is_tainted for {:?}", op
            );
        }
    }
}
