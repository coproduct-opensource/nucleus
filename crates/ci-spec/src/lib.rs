//! `ci-spec` — the CI configuration as a typed model, and the invariants the
//! merge queue silently relies on as decision procedures over it.
//!
//! # Why this exists
//!
//! On 2026-09-05 an inventory of this repository's CI found required status
//! checks that were green by construction: a proof-count ratchet whose
//! operand was empty (`[ "" -lt 72 ]` errors, and an erroring `[` reads as
//! false, so the gate passed); coverage thresholds piped into `tee` under a
//! shell without `pipefail`; one required context produced by four jobs in two
//! twin pairs; twin `paths-ignore` lists that had drifted from the real
//! twin's `paths`; seven required contexts hanging off two NON-required
//! detector jobs, so a red detector reported them all as SKIPPED — which the
//! merge rollup counts as passed. None of those invariants was written down
//! anywhere. This crate writes them down as code, with a fixture for each
//! founding defect that must go red.
//!
//! # The shape
//!
//! `loader` → [`model::Model`] → `invariants::*` → [`Report`]. The invariants
//! are pure functions over the model, so every one is testable from an
//! in-memory fixture. Observation (reading GitHub's live state) is NOT here;
//! it belongs to `gh` in a workflow, per the xtask convention that only the
//! decision is Rust.
//!
//! # Exit discipline
//!
//! `0` clean, `1` a violation, `2` could not look. The third is load-bearing:
//! an expression the evaluator does not understand, a ledger that parsed
//! empty, a tree with one workflow — each is reported as *unmeasured*, never
//! as *fine*. Reporting "we could not look" as a pass is the exact vacuity
//! the invariants exist to find.
//!
//! # What this does NOT claim
//!
//! - It reads YAML; it does not run anything. A gate can be structurally
//!   sound and assert the wrong thing.
//! - Gate detection is a heuristic (`exit 1` / `::error::`), inherited from
//!   proofcard and stated as such.
//! - The expression evaluator covers the subset this repository uses; the
//!   rest is exit 2, by design.
//! - The Lean model (`ci/lean`) proves that the invariants imply the
//!   properties; this crate only decides the invariants.

#![forbid(unsafe_code)]

use serde::Serialize;

pub mod expr;
pub mod golden;
pub mod invariants;
pub mod live;
pub mod loader;
pub mod model;
pub mod queue;
pub mod trace;

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The property is violated in a way that makes a required check vacuous.
    Critical,
    /// A plausible failure passes silently.
    High,
    /// Weakens a gate without an evident path to a false pass.
    Medium,
    /// Worth knowing; does not fail the check.
    Info,
    /// The checker could not decide. Fails with exit 2, never reads as a pass.
    Undecided,
}

/// One violated (or undecidable) invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable rule id: `CI-I1-PATHS`, `GI003`, ...
    pub rule: &'static str,
    pub severity: Severity,
    /// Repo-relative file.
    pub file: String,
    /// 1-indexed line, or 0 when the finding is about the file as a whole.
    pub line: usize,
    /// The job / step / context the finding is about.
    pub subject: String,
    /// What goes wrong, concretely.
    pub why: String,
    /// What to do about it.
    pub fix: String,
    /// The job the finding is about, when it is about one (empty otherwise).
    /// Used to scope severity: High/Medium findings on jobs that produce no
    /// required context are reported as Info rather than failing the check.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub job: String,
}

impl Finding {
    /// Attribute the finding to a job.
    #[must_use]
    pub fn in_job(mut self, job: &str) -> Self {
        self.job = job.to_string();
        self
    }

    /// The key an allowlist entry uses: `RULE file::subject`.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{} {}::{}", self.rule, self.file, self.subject)
    }
}

/// What was examined and what was found.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub workflows: usize,
    pub jobs: usize,
    pub gates: usize,
    pub required_contexts: usize,
    pub findings: Vec<Finding>,
}

impl Report {
    /// `0` clean, `1` violation, `2` could not look.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        let violated = self.findings.iter().any(|f| {
            matches!(
                f.severity,
                Severity::Critical | Severity::High | Severity::Medium
            )
        });
        let undecided = self
            .findings
            .iter()
            .any(|f| f.severity == Severity::Undecided);
        if violated {
            1
        } else if undecided {
            2
        } else {
            0
        }
    }

    /// Rule ids present, sorted and deduplicated.
    #[must_use]
    pub fn rules(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.findings.iter().map(|f| f.rule).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Human-readable rendering.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(
            s,
            "ci-spec: {} workflows, {} jobs, {} inline gates, {} required contexts",
            self.workflows, self.jobs, self.gates, self.required_contexts
        );
        for f in &self.findings {
            let sev = match f.severity {
                Severity::Critical => "CRITICAL",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Info => "info",
                Severity::Undecided => "UNDECIDED",
            };
            let _ = writeln!(
                s,
                "  {sev:<9} [{}] {}:{} {}\n            {}\n            fix: {}",
                f.rule, f.file, f.line, f.subject, f.why, f.fix
            );
        }
        let _ = writeln!(
            s,
            "{}",
            match self.exit_code() {
                0 => "ok: every invariant holds".to_string(),
                1 => format!(
                    "VIOLATION: {} finding(s)",
                    self.findings
                        .iter()
                        .filter(|f| f.severity != Severity::Info)
                        .count()
                ),
                _ => "UNDECIDED: could not evaluate part of the configuration — this is not a pass"
                    .to_string(),
            }
        );
        s
    }
}

/// Run every invariant over the model.
#[must_use]
pub fn check(m: &model::Model) -> Report {
    let mut findings = Vec::new();

    // I9 — non-vacuity of the model itself, first: nothing below may run
    // over an empty domain and report it as clean.
    findings.extend(invariants::vacuity::check(m));

    findings.extend(invariants::twins::check(m));
    findings.extend(invariants::producers::check(m));
    findings.extend(invariants::merge_group::check(m));
    findings.extend(invariants::concurrency::check(m));
    findings.extend(invariants::scope::check(m));
    findings.extend(invariants::gates::check(m));
    findings.extend(invariants::timeouts::check(m));
    findings.extend(invariants::wired::check(m));

    // Severity scoping. A gate inside a job that produces NO required context
    // cannot make a merge vacuous; its High/Medium findings are reported (so
    // the inline-gate ledger can ratchet them) but do not fail the check.
    // Critical stays Critical everywhere: a gate that cannot fail is a false
    // claim wherever it sits. Workflow-level findings (I4) are scoped by
    // whether ANY job in the file produces a required context.
    let required_jobs: std::collections::BTreeSet<(String, String)> = m
        .workflows
        .iter()
        .flat_map(|w| {
            w.jobs.iter().filter_map(move |j| {
                if j.contexts().iter().any(|c| m.is_required(c)) {
                    Some((w.path.clone(), j.id.clone()))
                } else {
                    None
                }
            })
        })
        .collect();
    let required_files: std::collections::BTreeSet<&str> =
        required_jobs.iter().map(|(p, _)| p.as_str()).collect();
    for f in &mut findings {
        if !matches!(f.severity, Severity::High | Severity::Medium) {
            continue;
        }
        let in_scope = if f.job.is_empty() {
            !f.file.starts_with(".github/workflows/") || required_files.contains(f.file.as_str())
        } else {
            required_jobs.contains(&(f.file.clone(), f.job.clone()))
        };
        if !in_scope {
            f.severity = Severity::Info;
        }
    }

    // Allowlist: entries carry a reason and are checked for staleness both
    // ways — an allowed finding that no longer fires is itself a finding.
    let mut used = std::collections::BTreeSet::new();
    findings.retain(|f| {
        let k = f.key();
        if m.allowlist.entries.contains_key(&k) {
            used.insert(k);
            false
        } else {
            true
        }
    });
    for (k, reason) in &m.allowlist.entries {
        if !used.contains(k) {
            findings.push(Finding {
                rule: "CI-ALLOW-STALE",
                severity: Severity::Medium,
                file: "ci/gate-integrity-allowlist.txt".into(),
                line: 0,
                subject: k.clone(),
                why: format!(
                    "allowlisted finding no longer fires (reason on record: {reason:?}); a stale \
                     entry would silently allow the next real instance"
                ),
                fix: "remove the entry".into(),
                job: String::new(),
            });
        }
    }

    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    Report {
        workflows: m.workflows.len(),
        jobs: m.workflows.iter().map(|w| w.jobs.len()).sum(),
        gates: m
            .workflows
            .iter()
            .flat_map(|w| w.jobs.iter())
            .flat_map(|j| j.steps.iter())
            .filter(|s| s.is_gate())
            .count(),
        required_contexts: m.ledger.contexts.len(),
        findings,
    }
}
