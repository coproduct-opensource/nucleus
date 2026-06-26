//! Empirical attack-corpus A/B — the end-to-end complement to the algebraic proofs.
//!
//! The Lean proofs + the exhaustive parity test (portcullis-core ifc_algebra_groundtruth.rs)
//! establish that the IFC algebra is closed and that the runtime matches the model. They do
//! NOT, by themselves, give *empirical end-to-end evidence* that concrete attacks are blocked
//! — that is what an attack corpus provides (cf. MVAR's ADVERSARIAL_EVAL A/B, adopted here).
//! Each vector is a tainted flow (NodeKind sources → SinkClass sink) run through the REAL IFC
//! gate (`intrinsic_label` → `FlowState::flows_to`). We report the bypass rate under two
//! policies — baseline (no gate, everything allowed) vs enforced (the IFC gate) — plus the
//! benign false-positive rate. The corpus is MVAR-community schema compatible so external
//! red-team vectors can be ingested.
//!
//! HONESTY: this is EVIDENCE over a finite, extensible corpus, not a proof — it characterizes
//! behavior under the tested vectors, not all possible attacks (cf. MVAR DISCLAIMERS). It also
//! probes ONE layer (the IFC flows_to relation); a vector marked `known_gap` is a tracked
//! finding where that layer does not yet match the intended policy.

use portcullis_core::flow::{intrinsic_label, NodeKind};
use portcullis_core::flow_algebra::FlowState;
use portcullis_core::SinkClass;
use serde::Deserialize;

const NOW: u64 = 1_900_000_000; // fixed; flows_to (not flows_to_at) ignores freshness

#[derive(Deserialize)]
struct Corpus {
    suite_name: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    description: String,
    sources: Vec<String>,
    sink: String,
    intent: String,
    status: String,
}

fn node_kind(s: &str) -> NodeKind {
    match s {
        "UserPrompt" => NodeKind::UserPrompt,
        "ToolResponse" => NodeKind::ToolResponse,
        "WebContent" => NodeKind::WebContent,
        "McpToolResult" => NodeKind::McpToolResult,
        "MemoryRead" => NodeKind::MemoryRead,
        "FileRead" => NodeKind::FileRead,
        "EnvVar" => NodeKind::EnvVar,
        "ModelPlan" => NodeKind::ModelPlan,
        "OutboundAction" => NodeKind::OutboundAction,
        "Secret" => NodeKind::Secret,
        other => panic!("attack_corpus.json: unknown NodeKind {other:?}"),
    }
}

fn sink_class(s: &str) -> SinkClass {
    match s {
        "WorkspaceWrite" => SinkClass::WorkspaceWrite,
        "BashExec" => SinkClass::BashExec,
        "HTTPEgress" => SinkClass::HTTPEgress,
        "GitPush" => SinkClass::GitPush,
        "PRCommentWrite" => SinkClass::PRCommentWrite,
        "EmailSend" => SinkClass::EmailSend,
        "MemoryPersist" => SinkClass::MemoryPersist,
        "AgentSpawn" => SinkClass::AgentSpawn,
        "CloudMutation" => SinkClass::CloudMutation,
        other => panic!("attack_corpus.json: unknown SinkClass {other:?}"),
    }
}

/// The real IFC-flow verdict for a vector: ALLOW iff the accumulated source label
/// flows to the sink. The flow ORIGINATES at its first source's label (cf. the
/// real `flow_algebra` tests: `FlowState::from_label(trusted())` then join taint)
/// and accumulates the rest — `bottom()` is wrong here, as it is min-privilege
/// (NoAuthority) and the contravariant join would pin authority to the floor.
fn enforced_verdict(v: &Vector) -> &'static str {
    let mut srcs = v.sources.iter();
    let first = srcs.next().expect("vector needs at least one source");
    let mut fs = FlowState::from_label(intrinsic_label(node_kind(first), NOW));
    for s in srcs {
        fs.join(intrinsic_label(node_kind(s), NOW));
    }
    if fs.flows_to(sink_class(&v.sink)) {
        "ALLOW"
    } else {
        "BLOCK"
    }
}

#[test]
fn attack_corpus_ab_bypass_rate() {
    let corpus: Corpus =
        serde_json::from_str(include_str!("attack_corpus.json")).expect("parse attack_corpus.json");

    let mut attacks = 0usize; // intent == BLOCK
    let mut benign = 0usize; // intent == ALLOW
    let mut enforced_bypass = 0usize; // attack the enforced gate let through
    let mut false_positives = 0usize; // benign the gate blocked
    let mut gaps: Vec<String> = Vec::new(); // known_gap vectors (tracked findings)
    let mut regressions: Vec<String> = Vec::new(); // enforced vectors no longer matching intent

    println!(
        "\nattack corpus '{}' ({} vectors)",
        corpus.suite_name,
        corpus.vectors.len()
    );
    println!(
        "  {:<24} {:<7} {:<6} {:<10} {}",
        "id", "intent", "gate", "status", ""
    );
    for v in &corpus.vectors {
        let got = enforced_verdict(v);
        let matches_intent = got == v.intent;
        println!(
            "  {:<24} {:<7} {:<6} {:<10} {}",
            v.id, v.intent, got, v.status, v.description
        );
        match v.intent.as_str() {
            "BLOCK" => attacks += 1,
            "ALLOW" => benign += 1,
            other => panic!("vector {}: bad intent {other:?}", v.id),
        }
        match v.status.as_str() {
            "enforced" => {
                if !matches_intent {
                    regressions.push(format!("{} (intent {}, gate {})", v.id, v.intent, got));
                    if v.intent == "BLOCK" {
                        enforced_bypass += 1;
                    } else {
                        false_positives += 1;
                    }
                }
            }
            "known_gap" => {
                // Tracked: the gate is expected NOT to match intent yet. Assert it
                // really is still a gap, so the corpus notices when a fix lands.
                gaps.push(v.id.clone());
                assert!(
                    !matches_intent,
                    "vector {} is marked known_gap but the gate now MATCHES intent — \
                     promote it to status=enforced",
                    v.id
                );
            }
            other => panic!("vector {}: bad status {other:?}", v.id),
        }
    }

    let enforced_attacks = attacks - gaps.len();
    let baseline_bypass_rate = 100.0; // no gate: every attack lands
    let enforced_bypass_rate = 100.0 * enforced_bypass as f64 / enforced_attacks.max(1) as f64;
    let fp_rate = 100.0 * false_positives as f64 / benign.max(1) as f64;
    println!("  --");
    println!(
        "  attacks={attacks} ({} enforced, {} known-gap) benign={benign}",
        enforced_attacks,
        gaps.len()
    );
    println!("  baseline (no gate)  bypass rate: {baseline_bypass_rate:.1}%");
    println!("  enforced (IFC gate) bypass rate: {enforced_bypass_rate:.1}% over enforced attacks");
    println!("  enforced (IFC gate) false-pos rate: {fp_rate:.1}%");
    if !gaps.is_empty() {
        println!("  KNOWN GAPS (tracked findings): {gaps:?}");
    }
    println!();

    assert!(
        regressions.is_empty(),
        "IFC gate regressed on {} enforced vector(s): {:?}",
        regressions.len(),
        regressions
    );
}
