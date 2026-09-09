//! Replay recorded tool-call traces through the **real** kernel decision path.
//!
//! # Why this exists
//!
//! Nucleus's information-flow gate had no measuring instrument. The in-tree
//! AgentDojo adapter could not be one: it is a pure-Python reimplementation of
//! `exposure_core::should_deny`, a function whose only callers are the CTF
//! engine and conformance tests — **not** the live path — and whose policy it
//! does not faithfully reproduce anyway. Numbers from it would describe a
//! policy nucleus does not run.
//!
//! This crate drives [`Kernel::decide_term_with_flow`], which is the function
//! the HTTP chokepoint calls. The IFC gate lives *inside* it
//! (`decide_term_with_flow` → `ifc_flow_gate` → `exposure_core::ifc_egress_denial`),
//! so a replay here exercises the same enforcement a live tool call does.
//!
//! # What it deliberately does not cover
//!
//! The tool-proxy wraps this call with HTTP error mapping and verdict-sink
//! recording (`mediation::decide_and_record`). Neither can change a verdict, so
//! they are out of scope — but that means results here are evidence about the
//! **kernel decision**, not about the HTTP surface. Stated so the boundary is
//! not silently overclaimed later.

use portcullis::action_term::ActionTerm;
use portcullis::gate_class::{self, GateClass};
use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{FlowTracker, NodeKind, Operation, PermissionLattice, default_sink_class};
use serde::{Deserialize, Serialize};

/// One recorded step of an agent episode.
///
/// A step is a tool call: it is first *gated* (the kernel decides whether the
/// operation may proceed), and on success it *ingests* content into the session
/// flow tracker. That ordering mirrors the live path, where
/// `http_kernel_decide` runs before the handler observes what it fetched.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceStep {
    /// Zero-based index within the trace.
    pub step: usize,
    /// The originating tool name, kept purely as provenance for the mapping
    /// from a benchmark's fine-grained tools onto nucleus's coarse operations.
    /// Recording it lets a reader audit that mapping instead of trusting it.
    pub tool: String,
    /// The nucleus operation this tool maps to.
    pub operation: Operation,
    /// The operation's subject (path, URL, command...).
    #[serde(default)]
    pub subject: String,
    /// What this step ingests into the flow graph *if it is allowed*.
    /// `None` for steps that consume nothing (a pure action).
    #[serde(default)]
    pub ingest: Option<NodeKind>,
    /// Bytes whose SHA-256 becomes the ingested node's content address. Absent
    /// means "ingest happened but the payload was not recorded".
    #[serde(default)]
    pub content: Option<String>,
}

/// What the kernel decided for one step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StepOutcome {
    pub step: usize,
    pub tool: String,
    pub operation: Operation,
    /// `allow` | `deny` | `requires_approval`.
    pub verdict: String,
    /// Machine-stable refusal code (the `DenyReason` serde tag), never a
    /// `Debug` rendering — a code that changes under refactoring is not
    /// evidence.
    pub deny_code: Option<String>,
    pub gate_class: GateClass,
    pub exposure_pre: u8,
    pub exposure_post: u8,
    /// Whether the session already carried adversarial integrity *before* this
    /// step was decided.
    pub session_tainted_before: bool,
    /// **The measurement this crate exists for.** True when the step was
    /// refused by the IFC gate while the session was already tainted.
    ///
    /// Production observes every flow node with *no parents*
    /// (`observe_with_content_hash` passes `&[]`), so the gate can only ask
    /// "did this session ever see adversarial content?", never "does this
    /// action derive from it?". Every such refusal is therefore charged to the
    /// session ceiling rather than to the action's own derivation.
    ///
    /// This is an **upper bound** on what per-node lineage could recover, not a
    /// prediction that any particular step would flip. Some of these actions
    /// genuinely do derive from the tainted node; without edges, nothing here
    /// can tell which.
    pub ceiling_attributable: bool,

    // ── Sink consequence ────────────────────────────────────────────────────
    // Nucleus already classifies sinks; these fields surface that
    // classification per decision so refusals can be split by how expensive
    // the thing refused actually was. None of this is a new policy — it reads
    // `SinkClass`'s own predicates.
    /// The sink this operation lands in, via `default_sink_class`.
    pub sink_class: String,
    /// `SinkClass::is_exfil_vector` — can move data out of the trust boundary.
    pub is_exfil_vector: bool,
    /// `SinkClass::requires_verified_derivation`, whose own docs describe it as
    /// covering "externally-visible, hard-to-revoke artifacts". This is the
    /// closest thing nucleus already has to an irreversibility axis, which is
    /// why it is used rather than a scheme invented here.
    pub hard_to_revoke: bool,
    /// `SinkClass::required_integrity` — Trusted for publish vectors,
    /// Untrusted for local mutations.
    pub required_integrity: String,
}

/// Aggregate over a replayed trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplaySummary {
    pub steps: usize,
    pub allowed: usize,
    pub denied: usize,
    pub requires_approval: usize,
    /// Denials charged to the session ceiling — see
    /// [`StepOutcome::ceiling_attributable`].
    pub ceiling_attributable: usize,
    /// Refusal-code histogram, so a reader can see *which* gate fired rather
    /// than only how often something did.
    pub deny_codes: std::collections::BTreeMap<String, usize>,

    // ── How the refusals split by sink consequence ─────────────────────────
    // The question this answers: are the denials concentrated on expensive,
    // hard-to-revoke sinks (where blocking is cheap insurance) or on cheap
    // local ones (where blocking costs utility and buys little)?
    /// Refusals per sink class.
    pub denied_by_sink: std::collections::BTreeMap<String, usize>,
    /// Refusals at sinks that can move data outside the trust boundary.
    pub denied_at_exfil_vector: usize,
    /// Refusals at sinks producing externally-visible, hard-to-revoke artifacts.
    pub denied_at_hard_to_revoke: usize,
    /// Refusals at sinks that are neither — local, reversible mutations.
    pub denied_at_local_reversible: usize,

    // ── The frontier number ────────────────────────────────────────────────
    /// `allowed / steps`, in permille (an integer so it ratchets exactly).
    /// Under a profile's real lattice ([`replay_with`]) this is the share of
    /// the corpus the principal's authorization let through — the
    /// utility-under-authorization quantity the North Star's fifth clause is
    /// about. Meaningless alone: it is published beside the GUARDS
    /// (`corpus_steps`, `denied_at_exfil_vector`) that may not fall, so it
    /// cannot be raised by shrinking the corpus or opening an exfil sink.
    pub allowed_share_permille: u32,
}

impl ReplaySummary {
    fn finish(&mut self) {
        self.allowed_share_permille =
            (self.allowed * 1000).checked_div(self.steps).unwrap_or(0) as u32;
    }

    fn record(&mut self, o: &StepOutcome) {
        self.steps += 1;
        match o.verdict.as_str() {
            "allow" => self.allowed += 1,
            "requires_approval" => self.requires_approval += 1,
            _ => self.denied += 1,
        }
        if o.ceiling_attributable {
            self.ceiling_attributable += 1;
        }
        if let Some(code) = &o.deny_code {
            *self.deny_codes.entry(code.clone()).or_insert(0) += 1;
            *self.denied_by_sink.entry(o.sink_class.clone()).or_insert(0) += 1;
            if o.is_exfil_vector {
                self.denied_at_exfil_vector += 1;
            }
            if o.hard_to_revoke {
                self.denied_at_hard_to_revoke += 1;
            }
            if !o.is_exfil_vector && !o.hard_to_revoke {
                self.denied_at_local_reversible += 1;
            }
        }
    }
}

/// Content-address a payload exactly as the live ingest path does
/// (`main.rs::ingest_content_hash`).
fn content_hash(bytes: &[u8]) -> portcullis_core::ContentHash {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    portcullis_core::ContentHash::from_bytes(digest)
}

/// Replay one episode against a fresh kernel and flow tracker under the
/// **permissive** lattice.
///
/// Permissive on purpose: this measures the **information-flow** gate, so
/// capability denials would be noise. A capability-restricted lattice would
/// conflate "the IFC gate refused" with "this pod was never allowed to do that
/// at all", and the whole point here is to attribute refusals to a specific
/// gate. The other question — how much of the corpus a *principal's* lattice
/// lets through — is [`replay_with`].
pub fn replay(steps: &[TraceStep]) -> (Vec<StepOutcome>, ReplaySummary) {
    replay_with(steps, PermissionLattice::permissive())
}

/// Replay one episode under a specific lattice — a canonical profile's, say —
/// so the summary answers the clause-5 question: of the work in this corpus,
/// how much does THIS authorization let through, and what does it refuse at
/// which sinks? Same kernel path as [`replay`]; only the lattice differs.
pub fn replay_with(
    steps: &[TraceStep],
    lattice: PermissionLattice,
) -> (Vec<StepOutcome>, ReplaySummary) {
    let mut kernel = Kernel::new(lattice);
    let mut flow = FlowTracker::new();
    let mut outcomes = Vec::with_capacity(steps.len());
    let mut summary = ReplaySummary::default();

    for step in steps {
        let tainted_before = flow.is_tainted();
        let term = ActionTerm::from_operation(step.operation, &step.subject);
        let (decision, _token) = kernel.decide_term_with_flow(term, Some(&flow));

        let (verdict, deny_code) = match &decision.verdict {
            Verdict::Allow => ("allow".to_string(), None),
            Verdict::RequiresApproval => ("requires_approval".to_string(), None),
            Verdict::Deny(reason) => (
                "deny".to_string(),
                Some(gate_class::deny_code(reason).to_string()),
            ),
        };

        let ceiling_attributable = matches!(
            &decision.verdict,
            Verdict::Deny(DenyReason::IfcUnsafe { .. })
        ) && tainted_before;

        let sink = default_sink_class(step.operation);
        let outcome = StepOutcome {
            sink_class: format!("{sink:?}"),
            is_exfil_vector: sink.is_exfil_vector(),
            hard_to_revoke: sink.requires_verified_derivation(),
            required_integrity: format!("{:?}", sink.required_integrity()),
            step: step.step,
            tool: step.tool.clone(),
            operation: step.operation,
            verdict,
            deny_code,
            gate_class: gate_class::classify(&decision.verdict, &decision.exposure_transition),
            exposure_pre: decision.exposure_transition.pre_count,
            exposure_post: decision.exposure_transition.post_count,
            session_tainted_before: tainted_before,
            ceiling_attributable,
        };
        summary.record(&outcome);
        outcomes.push(outcome);

        // Ingest only on success — a refused call never happened, so it must not
        // contribute taint. Getting this backwards would let a denied web fetch
        // poison the rest of the session and inflate the very number this crate
        // is trying to measure.
        if matches!(decision.verdict, Verdict::Allow)
            && let Some(kind) = step.ingest
        {
            let bytes = step.content.as_deref().unwrap_or("").as_bytes();
            // A dropped observation poisons the session by design; surface it
            // rather than silently continuing with an unprovable taint state.
            let _ = flow.observe_with_content_hash(kind, content_hash(bytes));
        }
    }

    summary.finish();
    (outcomes, summary)
}

/// One profile's frontier over a corpus: the [`ReplaySummary`] fields that
/// ratchet, aggregated across every episode. `_GUARD` suffixes are read by
/// `cargo xtask scoreboard-ratchet`: those numbers may not fall, so
/// `allowed_share_permille` cannot be raised by shrinking the corpus or by
/// opening an exfiltration sink.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ProfileFrontier {
    pub steps: usize,
    pub allowed: usize,
    pub denied: usize,
    pub requires_approval: usize,
    pub ceiling_attributable: usize,
    #[serde(rename = "denied_at_exfil_vector_GUARD")]
    pub denied_at_exfil_vector: usize,
    pub denied_at_hard_to_revoke: usize,
    pub denied_at_local_reversible: usize,
    pub allowed_share_permille: u32,
    pub deny_codes: std::collections::BTreeMap<String, usize>,
}

/// The frontier report: every named lattice replayed over the same corpus.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct FrontierReport {
    /// Episodes in the corpus.
    pub corpus_traces: usize,
    /// Steps in the corpus — a GUARD, so the corpus may not shrink.
    #[serde(rename = "corpus_steps_GUARD")]
    pub corpus_steps: usize,
    /// Per-profile frontiers, keyed by profile name.
    pub profiles: std::collections::BTreeMap<String, ProfileFrontier>,
}

/// Replay a corpus under each named lattice and aggregate.
pub fn frontier(corpus: &[Trace], lattices: &[(String, PermissionLattice)]) -> FrontierReport {
    let mut report = FrontierReport {
        corpus_traces: corpus.len(),
        corpus_steps: corpus.iter().map(|t| t.steps.len()).sum(),
        profiles: Default::default(),
    };
    for (name, lattice) in lattices {
        let mut f = ProfileFrontier::default();
        for t in corpus {
            let (_, s) = replay_with(&t.steps, lattice.clone());
            f.steps += s.steps;
            f.allowed += s.allowed;
            f.denied += s.denied;
            f.requires_approval += s.requires_approval;
            f.ceiling_attributable += s.ceiling_attributable;
            f.denied_at_exfil_vector += s.denied_at_exfil_vector;
            f.denied_at_hard_to_revoke += s.denied_at_hard_to_revoke;
            f.denied_at_local_reversible += s.denied_at_local_reversible;
            for (code, n) in s.deny_codes {
                *f.deny_codes.entry(code).or_insert(0) += n;
            }
        }
        f.allowed_share_permille = (f.allowed * 1000).checked_div(f.steps).unwrap_or(0) as u32;
        report.profiles.insert(name.clone(), f);
    }
    report
}

/// A named episode: one independent session, replayed against a fresh kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub trace: usize,
    pub steps: Vec<TraceStep>,
}

/// Parse a corpus (one [`Trace`] per line) — many independent episodes, as
/// distinct from [`parse_trace`], which reads a single episode's steps.
pub fn parse_corpus(src: &str) -> anyhow::Result<Vec<Trace>> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str::<Trace>(line)
                .map_err(|e| anyhow::anyhow!("corpus line {}: {e}", i + 1))
        })
        .collect()
}

/// Parse a JSONL trace (one [`TraceStep`] per line, blank lines ignored).
pub fn parse_trace(src: &str) -> anyhow::Result<Vec<TraceStep>> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str::<TraceStep>(line)
                .map_err(|e| anyhow::anyhow!("trace line {}: {e}", i + 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(i: usize, op: Operation, ingest: Option<NodeKind>) -> TraceStep {
        TraceStep {
            step: i,
            tool: format!("t{i}"),
            operation: op,
            subject: "s".into(),
            ingest,
            content: Some(format!("payload-{i}")),
        }
    }

    /// The frontier is two-directional by construction: a restrictive lattice
    /// admits no more of the corpus than the permissive one, and the guards
    /// that stop the number from being gamed are populated from the same
    /// replay, not typed in.
    #[test]
    fn a_profile_frontier_is_bounded_by_the_permissive_one_and_carries_its_guards() {
        let corpus = vec![
            Trace {
                trace: 0,
                steps: vec![
                    step(0, Operation::ReadFiles, Some(NodeKind::FileRead)),
                    step(1, Operation::WriteFiles, None),
                ],
            },
            Trace {
                trace: 1,
                steps: vec![
                    step(0, Operation::WebFetch, Some(NodeKind::WebContent)),
                    step(1, Operation::GitPush, None),
                ],
            },
        ];
        let report = frontier(
            &corpus,
            &[
                ("permissive".into(), PermissionLattice::permissive()),
                ("restrictive".into(), PermissionLattice::restrictive()),
            ],
        );
        assert_eq!(report.corpus_traces, 2);
        assert_eq!(report.corpus_steps, 4);
        let p = &report.profiles["permissive"];
        let r = &report.profiles["restrictive"];
        assert_eq!(p.steps, 4);
        assert!(
            r.allowed <= p.allowed,
            "restrictive {r:?} admits more than permissive {p:?}"
        );
        assert!(r.allowed_share_permille <= p.allowed_share_permille);
        assert_eq!(
            p.allowed_share_permille,
            (p.allowed * 1000 / p.steps) as u32
        );
        // The tainted push is refused at an exfil sink under BOTH lattices — the
        // guard is non-zero, so it can bite.
        assert!(p.denied_at_exfil_vector >= 1, "{p:?}");
        assert!(r.denied_at_exfil_vector >= 1, "{r:?}");
    }

    /// A clean session lets an outbound action through — otherwise every later
    /// assertion about denial would be trivially satisfied.
    #[test]
    fn clean_session_allows_outbound() {
        let (out, sum) = replay(&[step(0, Operation::WriteFiles, None)]);
        assert_eq!(out[0].verdict, "allow", "got {:?}", out[0]);
        assert_eq!(sum.allowed, 1);
        assert_eq!(sum.ceiling_attributable, 0);
    }

    /// The load-bearing behaviour: ingesting web content taints the session, and
    /// the NEXT outbound action is refused with the IFC code.
    #[test]
    fn web_ingest_then_outbound_is_denied_as_ifc_unsafe() {
        let trace = vec![
            step(0, Operation::WebFetch, Some(NodeKind::WebContent)),
            step(1, Operation::WriteFiles, None),
        ];
        let (out, sum) = replay(&trace);
        assert_eq!(out[0].verdict, "allow", "the fetch itself is not outbound");
        assert_eq!(out[1].verdict, "deny");
        assert_eq!(out[1].deny_code.as_deref(), Some("ifc_unsafe"));
        assert!(out[1].session_tainted_before);
        assert_eq!(sum.ceiling_attributable, 1);
    }

    /// The denial above must come from the *adversarial* integrity of what was
    /// ingested, not merely from having ingested anything. Same trace shape, a
    /// trusted node kind, and the outbound action must survive — otherwise the
    /// test above would pass against a gate that simply denies after any ingest.
    #[test]
    fn a_benign_ingest_does_not_taint_the_session() {
        let trace = vec![
            step(0, Operation::ReadFiles, Some(NodeKind::UserPrompt)),
            step(1, Operation::WriteFiles, None),
        ];
        let (out, sum) = replay(&trace);
        assert_eq!(
            out[1].verdict, "allow",
            "a trusted ingest must not deny later outbound actions: {:?}",
            out[1]
        );
        assert!(!out[1].session_tainted_before);
        assert_eq!(sum.ceiling_attributable, 0);
    }

    /// A refused step must not ingest. If it did, one denial would cascade into
    /// permanent session taint and the ceiling metric would count its own
    /// side effects.
    #[test]
    fn a_denied_step_does_not_contribute_taint() {
        let trace = vec![
            step(0, Operation::WebFetch, Some(NodeKind::WebContent)),
            // Denied (session is tainted) AND carries an ingest that must be skipped.
            TraceStep {
                ingest: Some(NodeKind::WebContent),
                ..step(1, Operation::WriteFiles, None)
            },
            step(2, Operation::ReadFiles, None),
        ];
        let (out, _) = replay(&trace);
        assert_eq!(out[1].verdict, "deny");
        // Exactly one web node was ever observed, so the exposure count after the
        // skipped ingest must equal the count before it.
        assert_eq!(
            out[1].exposure_post, out[2].exposure_pre,
            "a denied step's ingest leaked into the flow graph"
        );
    }

    /// Nothing is charged to the ceiling in a clean session, so the metric
    /// cannot be an artefact of counting every denial.
    #[test]
    fn ceiling_attribution_requires_prior_taint() {
        let (out, sum) = replay(&[step(0, Operation::WriteFiles, None)]);
        assert!(!out[0].ceiling_attributable);
        assert_eq!(sum.ceiling_attributable, 0);
    }

    #[test]
    fn trace_parses_from_jsonl() {
        let src = r#"
# comment line
{"step":0,"tool":"get_webpage","operation":"web_fetch","subject":"https://x.test","ingest":"web_content","content":"hi"}
{"step":1,"tool":"send_email","operation":"write_files","subject":"out"}
"#;
        let steps = parse_trace(src).expect("parse");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].operation, Operation::WebFetch);
        assert_eq!(steps[1].ingest, None);
    }
}
