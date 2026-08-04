//! Does the Python exposure mirror agree with the kernel nucleus actually runs?
//!
//! The in-tree AgentDojo adapter shipped a "pure-Python mirror of
//! `portcullis/src/exposure_core.rs`" and claimed parity via a test file that
//! never executed any Rust. Two things were wrong with that:
//!
//! 1. `exposure_core::should_deny` — the function it mirrors — has **no
//!    live-path callers**. Only the CTF engine and conformance tests call it.
//!    The production IFC gate is `ifc_egress_denial`, reached through
//!    `Kernel::decide_term_with_flow` → `ifc_flow_gate`.
//! 2. The mirror's policy did not match `should_deny` either: it ignores
//!    `requires_approval` and `uninhabitable_constraint`, and adds a two-label
//!    rule (Exfil + Untrusted) that the Rust function does not have.
//!
//! So a benchmark number from that adapter would describe a policy nucleus does
//! not run. This test settles that with evidence instead of code-reading:
//! replay the same corpus through the real kernel and diff.
//!
//! `mirror-verdicts.json` is a frozen fixture — the mirror was deleted once it
//! was captured, because keeping a misleading reimplementation alive to test
//! against would perpetuate the defect.

use std::collections::BTreeMap;

use nucleus_flow_replay::{parse_corpus, replay};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MirrorFixture {
    traces: Vec<MirrorTrace>,
}

#[derive(Debug, Deserialize)]
struct MirrorTrace {
    trace: usize,
    verdicts: Vec<MirrorVerdict>,
}

#[derive(Debug, Deserialize)]
struct MirrorVerdict {
    step: usize,
    tool: String,
    verdict: String,
}

fn corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

/// Compare the kernel against the frozen mirror verdicts, step by step.
///
/// Returns `(agreements, disagreements, per-shape breakdown)`.
#[allow(clippy::type_complexity)]
fn diff() -> (usize, usize, BTreeMap<String, usize>) {
    let corpus_src = std::fs::read_to_string(corpus_dir().join("corpus.jsonl"))
        .expect("corpus.jsonl — regenerate with benchmarks/agentdojo/make_divergence_corpus.py");
    let fixture_src = std::fs::read_to_string(corpus_dir().join("mirror-verdicts.json"))
        .expect("mirror-verdicts.json");

    let traces = parse_corpus(&corpus_src).expect("parse corpus");
    let fixture: MirrorFixture = serde_json::from_str(&fixture_src).expect("parse fixture");

    assert_eq!(
        traces.len(),
        fixture.traces.len(),
        "corpus and fixture are out of sync — regenerate both together"
    );

    let (mut agree, mut disagree) = (0usize, 0usize);
    let mut shapes: BTreeMap<String, usize> = BTreeMap::new();

    for (t, mt) in traces.iter().zip(fixture.traces.iter()) {
        assert_eq!(t.trace, mt.trace, "trace ids misaligned");
        let (outcomes, _) = replay(&t.steps);
        assert_eq!(outcomes.len(), mt.verdicts.len(), "step count misaligned");

        for (o, mv) in outcomes.iter().zip(mt.verdicts.iter()) {
            assert_eq!(o.step, mv.step);
            assert_eq!(o.tool, mv.tool);
            // Collapse the kernel's three-valued verdict onto the mirror's
            // binary one: the mirror has no notion of deferring to a human, so
            // `requires_approval` is compared as "not allowed".
            let kernel_allowed = o.verdict == "allow";
            let mirror_allowed = mv.verdict == "allow";
            if kernel_allowed == mirror_allowed {
                agree += 1;
            } else {
                disagree += 1;
                let shape = format!(
                    "{}: kernel={} mirror={}{}",
                    mv.tool,
                    o.verdict,
                    mv.verdict,
                    o.deny_code
                        .as_deref()
                        .map(|c| format!(" ({c})"))
                        .unwrap_or_default()
                );
                *shapes.entry(shape).or_insert(0) += 1;
            }
        }
    }
    (agree, disagree, shapes)
}

/// **The finding.** The mirror and the shipped kernel decide differently. If
/// this test ever passes with zero disagreements, the premise of deleting the
/// mirror is wrong and this file should be revisited — which is exactly why the
/// assertion is on the disagreement count and not merely on a report.
#[test]
fn mirror_and_kernel_disagree() {
    let (agree, disagree, shapes) = diff();
    let total = agree + disagree;

    eprintln!("\nkernel vs. deleted Python mirror over {total} decisions:");
    eprintln!("  agree:    {agree}");
    eprintln!(
        "  disagree: {disagree}  ({:.1}%)",
        100.0 * disagree as f64 / total as f64
    );
    for (shape, n) in &shapes {
        eprintln!("    {n:>4}  {shape}");
    }

    assert!(total > 0, "empty comparison is not evidence");
    assert!(
        disagree > 0,
        "expected the mirror to diverge from the kernel; it agreed on all \
         {total} decisions. Either the mirror was faithful after all, or the \
         corpus does not reach the divergent region."
    );
}

/// The disagreements must not be an artifact of comparing nothing: the corpus
/// has to exercise both outcomes on both sides, or a 100% disagreement rate
/// could just mean one side denies everything.
#[test]
fn both_sides_both_decide_both_ways() {
    let corpus_src = std::fs::read_to_string(corpus_dir().join("corpus.jsonl")).unwrap();
    let fixture_src = std::fs::read_to_string(corpus_dir().join("mirror-verdicts.json")).unwrap();
    let traces = parse_corpus(&corpus_src).unwrap();
    let fixture: MirrorFixture = serde_json::from_str(&fixture_src).unwrap();

    let (mut k_allow, mut k_deny) = (0, 0);
    for t in &traces {
        for o in replay(&t.steps).0 {
            if o.verdict == "allow" {
                k_allow += 1
            } else {
                k_deny += 1
            }
        }
    }
    let m_allow = fixture
        .traces
        .iter()
        .flat_map(|t| &t.verdicts)
        .filter(|v| v.verdict == "allow")
        .count();
    let m_deny = fixture
        .traces
        .iter()
        .flat_map(|t| &t.verdicts)
        .filter(|v| v.verdict == "deny")
        .count();

    assert!(
        k_allow > 0 && k_deny > 0,
        "kernel: {k_allow} allow / {k_deny} deny"
    );
    assert!(
        m_allow > 0 && m_deny > 0,
        "mirror: {m_allow} allow / {m_deny} deny"
    );
}

/// The baseline this instrument exists to produce: how many of the kernel's
/// refusals are charged to the session-wide ceiling rather than to the action's
/// own derivation. With every production flow node carrying zero parents, the
/// gate cannot distinguish the two — so this is the upper bound on what
/// per-node lineage could recover.
#[test]
fn report_ceiling_attributable_baseline() {
    let corpus_src = std::fs::read_to_string(corpus_dir().join("corpus.jsonl")).unwrap();
    let traces = parse_corpus(&corpus_src).unwrap();

    let (mut steps, mut denied, mut ceiling) = (0usize, 0usize, 0usize);
    let mut codes: BTreeMap<String, usize> = BTreeMap::new();
    for t in &traces {
        let (_, s) = replay(&t.steps);
        steps += s.steps;
        denied += s.denied;
        ceiling += s.ceiling_attributable;
        for (c, n) in s.deny_codes {
            *codes.entry(c).or_insert(0) += n;
        }
    }

    eprintln!(
        "\nkernel baseline over {steps} decisions in {} traces:",
        traces.len()
    );
    eprintln!("  denied:               {denied}");
    eprintln!("  ceiling-attributable: {ceiling}");
    for (c, n) in &codes {
        eprintln!("    {n:>4}  {c}");
    }

    assert!(steps > 0);
    // A ceiling count of zero would mean the corpus never reaches a tainted
    // session, so the baseline would be measuring nothing.
    assert!(
        ceiling > 0,
        "corpus never produced a ceiling-attributable denial — it does not \
         exercise the session-taint path this baseline is about"
    );
}
