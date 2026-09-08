//! I8 — every gate is wired, and every inline gate is accounted for.
//!
//! Two domains, both DERIVED rather than declared:
//!
//! - every `scripts/check-*.sh` and `ci/*.sh` on disk is invoked by some
//!   workflow (`check-test-helpers-not-in-production.sh` once shipped invoked
//!   by zero workflows; `scripts/check-gates-can-fail.sh` catches the first
//!   directory, this catches both);
//! - every inline gate step (a `run:` containing `exit 1` / `::error::`) is
//!   listed in `ci/inline-gates.txt` with the job or probe that falsifies it,
//!   or as `UNCOVERED: <reason>` under a shrink-only ceiling. The gate of
//!   gates covers `scripts/check-*.sh` only; every vacuous required gate the
//!   2026-09-05 inventory found was an inline step, outside its domain.

use std::collections::BTreeSet;

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

/// The inventory key of a step.
#[must_use]
pub fn gate_key(workflow: &str, job: &str, step: &str) -> String {
    let wf = workflow.rsplit('/').next().unwrap_or(workflow);
    format!("{wf}::{job}::{step}")
}

/// Every inline gate in the tree, in inventory order.
#[must_use]
pub fn inline_gates(m: &Model) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for w in &m.workflows {
        for j in &w.jobs {
            for s in &j.steps {
                if s.is_gate() {
                    out.push((gate_key(&w.path, &j.id, &s.name), s.line, w.path.clone()));
                }
            }
        }
    }
    out
}

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();

    for script in &m.gate_scripts {
        let mentioned = m.workflows.iter().any(|w| w.raw.contains(script.as_str()));
        if !mentioned {
            out.push(finding(
                "CI-I8-UNWIRED",
                Severity::High,
                script,
                0,
                script,
                "no workflow invokes this gate script; it can fail locally and never run. A gate \
                 CI does not call enforces nothing, however carefully it is written"
                    .into(),
                "invoke it from a workflow, or delete it",
            ));
        }
    }

    let tree: Vec<(String, usize, String)> = inline_gates(m);
    let tree_keys: BTreeSet<&str> = tree.iter().map(|(k, _, _)| k.as_str()).collect();
    let listed: BTreeSet<&str> = m.inline_gates.entries.keys().map(String::as_str).collect();

    if tree.len() < 2 {
        out.push(finding(
            "CI-I8-VACUOUS",
            Severity::Undecided,
            "ci/inline-gates.txt",
            0,
            "inline gates",
            format!(
                "{} inline gate(s) found in the tree — the detector examined nothing",
                tree.len()
            ),
            "check the gate heuristic",
        ));
        return out;
    }

    for (k, line, path) in &tree {
        if !listed.contains(k.as_str()) {
            out.push(finding(
                "CI-I8-UNLISTED",
                Severity::High,
                path,
                *line,
                k,
                "inline gate step not in ci/inline-gates.txt: nothing records what falsifies it, \
                 so it can be green because it cannot fail and nobody would know"
                    .into(),
                "add it with its falsifier (a `*-falsifier` job or a gates-can-fail probe), or \
                 as `UNCOVERED: <reason>` and raise the ceiling in the same change",
            ));
        }
    }
    for k in listed.difference(&tree_keys) {
        out.push(finding(
            "CI-I8-STALE",
            Severity::Medium,
            "ci/inline-gates.txt",
            0,
            k,
            "listed inline gate no longer exists in the tree (renamed, moved, or its `exit 1` \
             is gone — which might mean it stopped being a gate)"
                .into(),
            "update or remove the entry",
        ));
    }
    let uncovered = m
        .inline_gates
        .entries
        .values()
        .filter(|v| v.starts_with("UNCOVERED"))
        .count();
    match m.inline_gates.uncovered_ceiling {
        None => out.push(finding(
            "CI-I8-CEILING",
            Severity::Undecided,
            "ci/inline-gates.txt",
            0,
            "UNCOVERED_CEILING",
            "no `# UNCOVERED_CEILING = N` header; the uncovered count is not ratcheted".into(),
            "add the header at the current count; it may only shrink",
        )),
        Some(c) if uncovered > c => out.push(finding(
            "CI-I8-CEILING",
            Severity::Critical,
            "ci/inline-gates.txt",
            0,
            "UNCOVERED_CEILING",
            format!("{uncovered} UNCOVERED inline gates, ceiling {c}: the ratchet only shrinks"),
            "give the new gate a falsifier instead of listing it uncovered",
        )),
        Some(_) => {}
    }
    for (k, v) in &m.inline_gates.entries {
        if v.is_empty() {
            out.push(finding(
                "CI-I8-EMPTY",
                Severity::Medium,
                "ci/inline-gates.txt",
                0,
                k,
                "entry has no falsifier and no UNCOVERED reason".into(),
                "name the falsifier or the reason",
            ));
        }
    }
    out
}
