//! How do the IFC gate's refusals split across sink consequence?
//!
//! The baseline established that **100% of refusals are attributable to the
//! session-wide taint ceiling** — once any adversarial content is observed, all
//! outbound actions are denied regardless of what they would do.
//!
//! That is only a problem worth fixing if the denials fall on *cheap* sinks. If
//! they concentrate on expensive, hard-to-revoke ones (publishing, pushing,
//! infrastructure mutation), then blocking is cheap insurance and the ceiling
//! is doing its job. If they fall on local reversible writes, the gate is
//! costing utility to prevent little.
//!
//! The classification is **nucleus's own**, not one invented here:
//! `SinkClass::is_exfil_vector` and `SinkClass::requires_verified_derivation`
//! (whose docstring describes it as covering "externally-visible, hard-to-revoke
//! artifacts"). Inventing a consequence scheme to measure against would make the
//! answer a function of the scheme.
//!
//! Each sink is measured twice: once with the session tainted first, once clean.
//! Without the clean control a denial cannot be attributed to the taint rather
//! than to the operation being disallowed outright.

use std::collections::BTreeMap;

use nucleus_flow_replay::{parse_corpus, replay, StepOutcome};

fn sweep() -> Vec<nucleus_flow_replay::Trace> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join("sink-sweep.jsonl");
    let src = std::fs::read_to_string(&path).expect(
        "sink-sweep.jsonl — regenerate with \
         `python3 benchmarks/agentdojo/make_divergence_corpus.py --mode sink-sweep`",
    );
    parse_corpus(&src).expect("parse sink sweep")
}

/// Split every step into (tainted-session, clean-control) buckets keyed by the
/// action's sink, so the taint's marginal effect is visible per sink.
#[allow(clippy::type_complexity)]
fn measure() -> (Vec<StepOutcome>, Vec<StepOutcome>) {
    let (mut tainted, mut clean) = (Vec::new(), Vec::new());
    for t in sweep() {
        // A 2-step trace taints first; a 1-step trace is the control.
        let is_tainted_run = t.steps.len() > 1;
        let (outcomes, _) = replay(&t.steps);
        // The action under test is the LAST step; earlier steps set up the taint.
        if let Some(action) = outcomes.last() {
            if is_tainted_run {
                tainted.push(action.clone());
            } else {
                clean.push(action.clone());
            }
        }
    }
    (tainted, clean)
}

#[test]
fn report_refusal_split_by_sink_consequence() {
    let (tainted, clean) = measure();
    assert!(!tainted.is_empty() && !clean.is_empty(), "sweep is empty");

    // A refusal counts as caused by the taint only if the SAME action succeeds
    // in a clean session. Otherwise it was disallowed on its own merits and
    // says nothing about the ceiling.
    let clean_verdict: BTreeMap<&str, &str> = clean
        .iter()
        .map(|o| (o.tool.as_str(), o.verdict.as_str()))
        .collect();

    let mut rows: Vec<(&StepOutcome, bool)> = Vec::new();
    for o in &tainted {
        let allowed_when_clean = clean_verdict.get(o.tool.as_str()) == Some(&"allow");
        rows.push((o, o.verdict != "allow" && allowed_when_clean));
    }

    let caused: Vec<&StepOutcome> = rows.iter().filter(|(_, c)| *c).map(|(o, _)| *o).collect();

    eprintln!("\n╔══ refusals CAUSED by session taint, split by sink consequence ══");
    eprintln!("║ sinks measured: {}", tainted.len());
    eprintln!(
        "║ refused only because the session was tainted: {}",
        caused.len()
    );
    eprintln!("╠══ by consequence class");
    let expensive: Vec<_> = caused
        .iter()
        .filter(|o| o.is_exfil_vector || o.hard_to_revoke)
        .collect();
    let cheap: Vec<_> = caused
        .iter()
        .filter(|o| !o.is_exfil_vector && !o.hard_to_revoke)
        .collect();
    eprintln!(
        "║ expensive (exfil vector OR hard-to-revoke): {}",
        expensive.len()
    );
    eprintln!(
        "║ cheap (local, reversible):                  {}",
        cheap.len()
    );
    eprintln!("╠══ detail");
    for (o, c) in &rows {
        eprintln!(
            "║ {:<26} {:<18} exfil={:<5} hard_revoke={:<5} req_integ={:<9} tainted={:<8} clean={:<6} {}",
            o.tool,
            o.sink_class,
            o.is_exfil_vector,
            o.hard_to_revoke,
            o.required_integrity,
            o.verdict,
            clean_verdict.get(o.tool.as_str()).copied().unwrap_or("?"),
            if *c { "<-- CAUSED BY TAINT" } else { "" }
        );
    }
    eprintln!("╚═══════════════════════════════════════════════════════════════");

    // The measurement is only meaningful if the sweep actually reaches both
    // kinds of sink; otherwise the split is an artifact of what was sampled.
    assert!(
        tainted
            .iter()
            .any(|o| o.is_exfil_vector || o.hard_to_revoke),
        "sweep never reaches an expensive sink"
    );
    assert!(
        tainted
            .iter()
            .any(|o| !o.is_exfil_vector && !o.hard_to_revoke),
        "sweep never reaches a cheap sink"
    );
}

/// **What Option C would change.** For every refusal caused by session taint,
/// what does the graded policy say instead? This is the utility recovery,
/// measured before anything is wired — the policy is a pure function, so it can
/// be evaluated against the same corpus the ceiling was measured on.
#[test]
fn report_what_grading_would_change() {
    use portcullis::exposure_core::{graded_taint_response, TaintResponse};

    let (tainted, clean) = measure();
    let clean_verdict: BTreeMap<&str, &str> = clean
        .iter()
        .map(|o| (o.tool.as_str(), o.verdict.as_str()))
        .collect();

    let (mut denied, mut approval, mut allowed) = (0usize, 0usize, 0usize);
    eprintln!("\n╔══ what the graded policy would do with taint-caused refusals ══");
    for o in &tainted {
        let caused = o.verdict != "allow" && clean_verdict.get(o.tool.as_str()) == Some(&"allow");
        if !caused {
            continue;
        }
        let graded = graded_taint_response(o.operation);
        match graded {
            TaintResponse::Deny => denied += 1,
            TaintResponse::RequireApproval => approval += 1,
            TaintResponse::Allow => allowed += 1,
        }
        eprintln!(
            "║ {:<24} {:<16} today=deny  graded={:?}",
            o.tool, o.sink_class, graded
        );
    }
    eprintln!("╠═══════════════════════════════════════════════════════════════");
    eprintln!("║ still denied outright:        {denied}");
    eprintln!("║ deferred to a human:          {approval}");
    eprintln!("║ permitted:                    {allowed}");
    eprintln!("╚═══════════════════════════════════════════════════════════════");

    // Grading must change SOMETHING, or it is the same gate with extra steps.
    assert!(
        approval + allowed > 0,
        "graded policy denies everything the ceiling denies — no recovery"
    );
    // And it must not become a rubber stamp.
    assert!(
        denied + approval > 0,
        "graded policy permits everything — protection lost"
    );
}
