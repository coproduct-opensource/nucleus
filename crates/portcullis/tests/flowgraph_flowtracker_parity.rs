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

// ═══════════════════════════════════════════════════════════════════════════
// Phase 2 preconditions (additive, no egress path touched):
//   (1) parity for the two behaviors Phase 1 did not cover —
//       `latest_adversarial_node` (edge-attach) and the token-gated cleanse
//       `reset_session_ceiling`; and
//   (2) a reusable differential harness that runs identical observe/decide
//       sequences through BOTH trackers and asserts the live-gate egress
//       verdict is byte-identical at every step — the evidence the later
//       (separately boot-gated) egress switch is safe.
// ═══════════════════════════════════════════════════════════════════════════

use portcullis::exposure_core::{
    graded_taint_response, ifc_egress_verdict, sink_max_conf_for, EgressVerdict, TaintResponse,
};
use portcullis_core::discharge::test_helpers::allowed_bundle;
use portcullis_core::ifc_api::SessionCleanseToken;
use portcullis_core::{default_sink_class, DerivationClass, Operation};

// ── Behavior 1: latest_adversarial_node (edge-attach) ──────────────────────

/// Pre-compaction, the edge-attach query agrees on PRESENCE (Some/None) on both
/// trackers, and the node it returns actually propagates `Adversarial` to a
/// child on the `FlowGraph` — which is the property egress relies on. The raw id
/// VALUE is deliberately not compared (it is an internal representation detail;
/// see the file header and the method doc).
#[test]
fn latest_adversarial_node_presence_parity_and_edge_propagates() {
    // Clean session: neither has an adversarial node to attach.
    let (clean_ft, clean_fg) = observe_both(&[NodeKind::UserPrompt, NodeKind::MemoryWrite]);
    assert_eq!(
        clean_ft.latest_adversarial_node().is_some(),
        clean_fg.latest_adversarial_node().is_some(),
        "clean session: edge-attach presence must agree (both None)"
    );
    assert!(
        clean_fg.latest_adversarial_node().is_none(),
        "clean session has no adversarial node to attach"
    );

    // Adversarial ingest: both now have an edge to attach.
    let (adv_ft, adv_fg) = observe_both(&[
        NodeKind::UserPrompt,
        NodeKind::WebContent,
        NodeKind::MemoryWrite,
    ]);
    assert_eq!(
        adv_ft.latest_adversarial_node().is_some(),
        adv_fg.latest_adversarial_node().is_some(),
        "after adversarial ingest: edge-attach presence must agree (both Some)"
    );
    let adv_id = adv_fg
        .latest_adversarial_node()
        .expect("FlowGraph must surface the adversarial node for edge-attach");

    // The behavior that MATTERS for egress: attaching that node as a parent of a
    // freshly authored node makes the child Adversarial — so downstream egress
    // of agent-authored content inherits the taint.
    let mut fg = adv_fg;
    let child = fg
        .insert_observation(NodeKind::MemoryWrite, &[adv_id], NOW)
        .expect("attach edge to latest adversarial node");
    assert_eq!(
        fg.get(child).expect("child node exists").label.integrity,
        portcullis_core::IntegLevel::Adversarial,
        "the edge-attach must taint the child — the whole point of the query"
    );
}

/// The fail-CLOSED divergence, made explicit. After compaction tombstones the
/// adversarial node, `FlowGraph::latest_adversarial_node` may go `None` (the
/// node is gone) where `FlowTracker`'s never-compacting scan still returns
/// `Some`. This is safe ONLY because the `is_tainted` ratchet — the real egress
/// backstop — survives compaction. This test proves the edge going stale never
/// opens egress: the verdict-driving aggregate still denies.
#[test]
fn latest_adversarial_node_may_go_none_after_compaction_but_ratchet_backstops() {
    let mut fg = FlowGraph::new();
    fg.insert_observation(NodeKind::WebContent, &[], NOW)
        .expect("adversarial observe");
    assert!(
        fg.latest_adversarial_node().is_some(),
        "pre-compaction the adversarial node is attachable"
    );

    for _ in 0..(10_000 + 200) {
        fg.insert_observation(NodeKind::UserPrompt, &[], NOW)
            .expect("clean observe");
    }

    // The adversarial node (id 1) was tombstoned — otherwise this proves nothing.
    assert!(
        fg.get(1).is_none(),
        "compaction must have tombstoned the adversarial node for this test to bite"
    );
    // The edge-attach query legitimately goes None (the node is gone)...
    assert!(
        fg.latest_adversarial_node().is_none(),
        "a tombstoned adversarial node is no longer attachable — expected"
    );
    // ...but the LOAD-BEARING backstop, the ratchet, still denies egress.
    assert!(
        fg.is_tainted(),
        "the is_tainted ratchet — not the edge — is what keeps egress closed post-compaction"
    );
}

// ── Behavior 2: reset_session_ceiling (token-gated cleanse) ─────────────────

/// The cleanse mirrors `FlowTracker::reset_session_ceiling` EXACTLY: same sealed
/// `SessionCleanseToken` (identical type ⇒ identical, unforgeable gating), same
/// two effects (lower the derivation ceiling, clear poison), and — critically —
/// same NON-effects (conf ceiling and integrity taint are left untouched).
/// Mirroring more than FlowTracker does would be a silent behavior change, not
/// parity, so the non-effects are asserted too.
#[test]
fn cleanse_parity_ceiling_and_poison() {
    // Drive both to an identical dirtied state: adversarial (AIDerived/opaque)
    // ingest raises the derivation ceiling and sets integrity taint; a Secret
    // env var raises the conf ceiling; then poison both.
    let seq = [NodeKind::WebContent, NodeKind::EnvVar];
    let (mut ft, mut fg) = observe_both(&seq);
    ft.poison();
    fg.poison();

    // Preconditions agree before the cleanse.
    assert_aggregates_agree(&ft, &fg, "pre-cleanse");
    assert!(
        ft.is_poisoned() && fg.is_poisoned(),
        "both poisoned pre-cleanse"
    );
    assert_ne!(
        ft.session_taint_ceiling(),
        DerivationClass::Deterministic,
        "derivation ceiling is raised pre-cleanse (non-vacuity)"
    );

    // The SAME sealed token authorizes both cleanses. Minting requires a
    // DischargedBundle — proof the policy pipeline ran; unforgeable otherwise.
    let bundle = allowed_bundle();
    let ft_token = SessionCleanseToken::authorize("parity: cleanse ft", &bundle);
    let fg_token = SessionCleanseToken::authorize("parity: cleanse fg", &bundle);
    ft.reset_session_ceiling(DerivationClass::Deterministic, &ft_token);
    fg.reset_session_ceiling(DerivationClass::Deterministic, &fg_token);

    // Effect 1: derivation ceiling lowered on both.
    assert_eq!(ft.session_taint_ceiling(), DerivationClass::Deterministic);
    assert_eq!(fg.session_taint_ceiling(), DerivationClass::Deterministic);
    // Effect 2: poison cleared on both (the fail-closed flag).
    assert!(!ft.is_poisoned(), "cleanse clears poison on FlowTracker");
    assert!(!fg.is_poisoned(), "cleanse clears poison on FlowGraph");

    // Non-effects: the cleanse must NOT touch the conf ceiling or integrity
    // taint — FlowTracker doesn't, so FlowGraph mustn't either. These stay
    // whatever they were, and stay EQUAL across the two trackers.
    assert_aggregates_agree(&ft, &fg, "post-cleanse");
    assert_eq!(
        ft.is_tainted(),
        fg.is_tainted(),
        "integrity taint is a cleanse non-effect and must still agree"
    );
    // Non-vacuity for the non-effect: the Secret conf ceiling really did survive
    // the cleanse on both, so a Public sink is still denied.
    assert!(
        !ft.session_exfiltration_check(ConfLevel::Public).is_safe()
            && !fg.session_exfiltration_check(ConfLevel::Public).is_safe(),
        "conf ceiling survives the derivation cleanse on BOTH trackers"
    );
}

// ── The differential egress-verdict harness ────────────────────────────────

/// The three session aggregates the LIVE gate consults (`kernel/ifc.rs` +
/// `exposure_core::ifc_egress_verdict`), abstracted so ONE verdict routine runs
/// over both trackers. If Phase 2 retires `FlowTracker`, these are exactly the
/// answers that must not change.
trait EgressState {
    fn is_poisoned(&self) -> bool;
    fn is_tainted(&self) -> bool;
    fn exfil_denied(&self, sink_max_conf: ConfLevel) -> bool;
}
impl EgressState for FlowTracker {
    fn is_poisoned(&self) -> bool {
        FlowTracker::is_poisoned(self)
    }
    fn is_tainted(&self) -> bool {
        FlowTracker::is_tainted(self)
    }
    fn exfil_denied(&self, s: ConfLevel) -> bool {
        self.session_exfiltration_check(s).is_denied()
    }
}
impl EgressState for FlowGraph {
    fn is_poisoned(&self) -> bool {
        FlowGraph::is_poisoned(self)
    }
    fn is_tainted(&self) -> bool {
        FlowGraph::is_tainted(self)
    }
    fn exfil_denied(&self, s: ConfLevel) -> bool {
        self.session_exfiltration_check(s).is_denied()
    }
}

/// Which live-gate check to DROP — used only to prove each check is load-bearing
/// and fail-closed (a dropped check must flip a Deny to a Pass, i.e. RED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropCheck {
    None,
    Poison,
    Taint,
    Exfil,
}

/// Variant-level egress verdict (Pass/Deny/RequireApproval). Detail strings
/// legitimately differ between the two trackers, so only the DECISION is
/// compared — that is what a sink actually sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    Pass,
    Deny,
    RequireApproval,
}

/// Replicates the live gate: `ifc_flow_gate`'s poison-denies-everything rule,
/// then `ifc_egress_verdict`'s integrity + confidentiality egress checks. Reuses
/// the PRODUCTION `graded_taint_response`/`sink_max_conf_for`/`default_sink_class`
/// so the graded and sink-classification logic cannot drift. Faithfulness to
/// production is separately anchored below against `ifc_egress_verdict` itself.
fn gate_verdict<S: EgressState>(
    s: &S,
    op: Operation,
    kind: NodeKind,
    graded: bool,
    drop: DropCheck,
) -> Gate {
    // Poison gate (#3): deny EVERY operation, not just outbound.
    if drop != DropCheck::Poison && s.is_poisoned() {
        return Gate::Deny;
    }
    let is_outbound = kind == NodeKind::OutboundAction;
    let carries_out = is_outbound || default_sink_class(op).is_exfil_vector();
    if !carries_out {
        return Gate::Pass;
    }
    // Integrity egress gate.
    if drop != DropCheck::Taint && is_outbound && s.is_tainted() {
        if !graded {
            return Gate::Deny;
        }
        match graded_taint_response(op) {
            TaintResponse::Deny => return Gate::Deny,
            TaintResponse::RequireApproval => return Gate::RequireApproval,
            TaintResponse::Allow => {}
        }
    }
    // Confidentiality egress gate.
    if drop != DropCheck::Exfil && s.exfil_denied(sink_max_conf_for(op)) {
        return Gate::Deny;
    }
    Gate::Pass
}

/// The production reference for `FlowTracker`: poison gate + the real
/// `ifc_egress_verdict`. `gate_verdict(ft, .., None)` must equal this for every
/// probe — that anchor is what makes the replicated routine trustworthy.
fn production_gate(ft: &FlowTracker, op: Operation, kind: NodeKind, graded: bool) -> Gate {
    if ft.is_poisoned() {
        return Gate::Deny;
    }
    match ifc_egress_verdict(ft, op, kind, graded) {
        EgressVerdict::Pass => Gate::Pass,
        EgressVerdict::Deny(_) => Gate::Deny,
        EgressVerdict::RequireApproval(_) => Gate::RequireApproval,
    }
}

const ALL_OPS: [Operation; 13] = [
    Operation::ReadFiles,
    Operation::WriteFiles,
    Operation::EditFiles,
    Operation::RunBash,
    Operation::GlobSearch,
    Operation::GrepSearch,
    Operation::WebSearch,
    Operation::WebFetch,
    Operation::GitCommit,
    Operation::GitPush,
    Operation::CreatePr,
    Operation::ManagePods,
    Operation::SpawnAgent,
];

/// For every (op, kind, graded) probe: (a) anchor the replicated routine to
/// production on the FlowTracker, then (b) assert FlowGraph's verdict is
/// identical. Returns the number of probes that decided Deny/RequireApproval, so
/// callers can assert non-vacuity (the sequence really exercises denials).
fn assert_verdicts_identical(ft: &FlowTracker, fg: &FlowGraph, ctx: &str) -> usize {
    let mut consequential = 0usize;
    for &kind in &[NodeKind::OutboundAction, NodeKind::UserPrompt] {
        for &op in &ALL_OPS {
            for &graded in &[false, true] {
                let ref_v = production_gate(ft, op, kind, graded);
                let ft_v = gate_verdict(ft, op, kind, graded, DropCheck::None);
                assert_eq!(
                    ft_v, ref_v,
                    "{ctx}: replicated gate drifted from production ifc_egress_verdict \
                     (op={op:?}, kind={kind:?}, graded={graded})"
                );
                let fg_v = gate_verdict(fg, op, kind, graded, DropCheck::None);
                assert_eq!(
                    ft_v, fg_v,
                    "{ctx}: egress verdict DIVERGED FlowTracker vs FlowGraph \
                     (op={op:?}, kind={kind:?}, graded={graded})"
                );
                if fg_v != Gate::Pass {
                    consequential += 1;
                }
            }
        }
    }
    consequential
}

/// The headline evidence for the later egress switch: an identical
/// observe/decide sequence — clean ingest, adversarial ingest, secret ingest,
/// exfiltration probes, poison, token cleanse, and compaction past
/// MAX_GRAPH_NODES — yields the SAME egress verdict on every step through both
/// trackers. This is the boot-canary's in-tree twin.
#[test]
fn differential_egress_verdicts_identical_across_full_sequence() {
    let mut ft = FlowTracker::new();
    let mut fg = FlowGraph::new();

    // A closure would borrow ft/fg mutably+immutably awkwardly; inline the probe.
    let mut total_consequential = 0usize;

    // Step 0: empty session.
    total_consequential += assert_verdicts_identical(&ft, &fg, "step0-empty");

    // Step 1: a clean prompt — still no denials for a Public flow.
    ft.observe(NodeKind::UserPrompt).unwrap();
    fg.insert_observation(NodeKind::UserPrompt, &[], NOW)
        .unwrap();
    total_consequential += assert_verdicts_identical(&ft, &fg, "step1-clean");

    // Step 2: ADVERSARIAL ingest (web content) — outbound actions must now deny.
    ft.observe(NodeKind::WebContent).unwrap();
    fg.insert_observation(NodeKind::WebContent, &[], NOW)
        .unwrap();
    let c2 = assert_verdicts_identical(&ft, &fg, "step2-adversarial");
    assert!(
        c2 > 0,
        "adversarial ingest must produce denials on BOTH trackers"
    );
    total_consequential += c2;

    // Step 3: SECRET ingest (env var) — confidentiality exfiltration now denies.
    ft.observe(NodeKind::EnvVar).unwrap();
    fg.insert_observation(NodeKind::EnvVar, &[], NOW).unwrap();
    total_consequential += assert_verdicts_identical(&ft, &fg, "step3-secret");

    // Step 4: POISON — the fail-closed gate denies EVERY op on both.
    ft.poison();
    fg.poison();
    let c4 = assert_verdicts_identical(&ft, &fg, "step4-poison");
    // Poison denies all data-carrying AND non-carrying probes; every probe with
    // a consequential verdict here is the poison gate firing identically.
    assert!(c4 > 0, "poison must deny on BOTH trackers");
    total_consequential += c4;

    // Step 5: token-gated CLEANSE — poison cleared, derivation ceiling lowered,
    // on both. Verdicts must re-converge to the (still-Secret, still-tainted)
    // post-cleanse state identically.
    let bundle = allowed_bundle();
    let ft_tok = SessionCleanseToken::authorize("harness cleanse ft", &bundle);
    let fg_tok = SessionCleanseToken::authorize("harness cleanse fg", &bundle);
    ft.reset_session_ceiling(DerivationClass::Deterministic, &ft_tok);
    fg.reset_session_ceiling(DerivationClass::Deterministic, &fg_tok);
    assert!(
        !ft.is_poisoned() && !fg.is_poisoned(),
        "cleanse cleared poison on both"
    );
    total_consequential += assert_verdicts_identical(&ft, &fg, "step5-post-cleanse");

    // Step 6: COMPACTION past MAX_GRAPH_NODES on the FlowGraph (FlowTracker never
    // compacts). The anti-laundering property: the adversarial ingest at step 2
    // gets tombstoned in the graph, yet the ratchet keeps is_tainted true, so the
    // egress verdicts STAY identical to the never-compacting FlowTracker.
    for _ in 0..(10_000 + 200) {
        ft.observe(NodeKind::UserPrompt).unwrap();
        fg.insert_observation(NodeKind::UserPrompt, &[], NOW)
            .unwrap();
    }
    // Confirm the graph actually compacted the STEP-2 adversarial node (id 2:
    // UserPrompt=1, WebContent=2, EnvVar=3). `node_count()` counts total slots
    // incl. tombstones, so it is the wrong probe; a tombstoned adversarial node
    // is exactly what makes this an anti-laundering test.
    assert!(
        fg.get(2).is_none(),
        "compaction must have tombstoned the step-2 adversarial node (id 2);          live count={}",
        fg.len()
    );
    let c6 = assert_verdicts_identical(&ft, &fg, "step6-post-compaction");
    assert!(
        c6 > 0,
        "post-compaction the session is STILL tainted+secret: denials must persist \
         identically — the ratchet, not a live scan, drives the verdict"
    );
    total_consequential += c6;

    assert!(
        total_consequential > 0,
        "vacuity guard: the differential sequence must have exercised real denials"
    );
}

/// Fail-closed proof: each of the three live-gate checks is load-bearing.
/// Dropping any one must flip a Deny to a Pass (RED) on BOTH trackers — a
/// regression that silently removed a check would open egress, and this catches
/// it. Directly enforces the "a dropped check reds" constraint.
#[test]
fn dropping_any_gate_check_opens_egress_on_both_trackers() {
    // Each check is isolated on a purpose-built SINGLE-AXIS session, so dropping
    // that one check is the ONLY thing standing between Deny and Pass. (A
    // maximally-dirty session hides this: the other checks would still deny.)

    // ── Poison isolation: clean session, poisoned. A benign non-carrying op is
    // denied ONLY by the fail-closed poison gate. ──
    let (mut p_ft, mut p_fg) = observe_both(&[NodeKind::UserPrompt]);
    p_ft.poison();
    p_fg.poison();
    for (name, t) in [
        ("ft", &p_ft as &dyn EgressState),
        ("fg", &p_fg as &dyn EgressState),
    ] {
        assert_eq!(
            gate_verdict_dyn(
                t,
                Operation::ReadFiles,
                NodeKind::UserPrompt,
                false,
                DropCheck::None
            ),
            Gate::Deny,
            "{name}: poison denies a benign op"
        );
        assert_eq!(
            gate_verdict_dyn(
                t,
                Operation::ReadFiles,
                NodeKind::UserPrompt,
                false,
                DropCheck::Poison
            ),
            Gate::Pass,
            "{name}: dropping the poison check RE-OPENS a benign op (fail-open) — must be red"
        );
    }

    // ── Taint isolation: adversarial web content only (Public confidentiality),
    // so the exfil check passes and integrity is the sole denier of an outbound
    // op. ──
    let (t_ft, t_fg) = observe_both(&[NodeKind::WebContent]);
    for (name, t) in [
        ("ft", &t_ft as &dyn EgressState),
        ("fg", &t_fg as &dyn EgressState),
    ] {
        assert_eq!(
            gate_verdict_dyn(
                t,
                Operation::WebSearch,
                NodeKind::OutboundAction,
                false,
                DropCheck::None
            ),
            Gate::Deny,
            "{name}: integrity taint denies the outbound op"
        );
        assert_eq!(
            gate_verdict_dyn(
                t,
                Operation::WebSearch,
                NodeKind::OutboundAction,
                false,
                DropCheck::Taint
            ),
            Gate::Pass,
            "{name}: dropping the integrity taint check RE-OPENS the outbound op \
             (fail-open) — must be red"
        );
    }

    // ── Exfil isolation: a Secret env var only (trusted integrity), consumed via
    // a non-outbound kind so the integrity branch never applies — confidentiality
    // is the sole denier of an exfil-vector op capped below Secret. ──
    let (e_ft, e_fg) = observe_both(&[NodeKind::EnvVar]);
    for (name, t) in [
        ("ft", &e_ft as &dyn EgressState),
        ("fg", &e_fg as &dyn EgressState),
    ] {
        assert_eq!(
            gate_verdict_dyn(
                t,
                Operation::WebFetch,
                NodeKind::UserPrompt,
                false,
                DropCheck::None
            ),
            Gate::Deny,
            "{name}: the Secret ceiling denies the exfil-vector op"
        );
        assert_eq!(
            gate_verdict_dyn(
                t,
                Operation::WebFetch,
                NodeKind::UserPrompt,
                false,
                DropCheck::Exfil
            ),
            Gate::Pass,
            "{name}: dropping the confidentiality exfil check RE-OPENS the op \
             (fail-open) — must be red"
        );
    }
}

/// Object-safe shim so the drop-check test can iterate both trackers behind
/// `&dyn EgressState`.
fn gate_verdict_dyn(
    s: &dyn EgressState,
    op: Operation,
    kind: NodeKind,
    graded: bool,
    drop: DropCheck,
) -> Gate {
    if drop != DropCheck::Poison && s.is_poisoned() {
        return Gate::Deny;
    }
    let is_outbound = kind == NodeKind::OutboundAction;
    let carries_out = is_outbound || default_sink_class(op).is_exfil_vector();
    if !carries_out {
        return Gate::Pass;
    }
    if drop != DropCheck::Taint && is_outbound && s.is_tainted() {
        if !graded {
            return Gate::Deny;
        }
        match graded_taint_response(op) {
            TaintResponse::Deny => return Gate::Deny,
            TaintResponse::RequireApproval => return Gate::RequireApproval,
            TaintResponse::Allow => {}
        }
    }
    if drop != DropCheck::Exfil && s.exfil_denied(sink_max_conf_for(op)) {
        return Gate::Deny;
    }
    Gate::Pass
}
