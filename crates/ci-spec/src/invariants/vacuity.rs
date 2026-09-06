//! I9 — the model itself is non-vacuous.
//!
//! A checker over an empty domain reports "every invariant holds" having
//! examined nothing. Founding defect: `check-lean-libs-built.sh`'s first
//! version used `declare -A` under bash 3.2, errored per library, and still
//! exited 0 — "a false green in the gate written to find false greens".

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    if m.workflows.len() < 2 {
        out.push(finding(
            "CI-I9-WORKFLOWS",
            Severity::Undecided,
            ".github/workflows",
            0,
            "workflow set",
            format!(
                "{} workflow(s) parsed — the domain is wrong, so nothing below examined anything",
                m.workflows.len()
            ),
            "point the checker at a repository with its workflows",
        ));
    }
    if m.ledger.contexts.len() < 2 {
        out.push(finding(
            "CI-I9-LEDGER",
            Severity::Undecided,
            "ci/required-checks.txt",
            0,
            "required-check ledger",
            format!(
                "{} required context(s) parsed — an empty ledger makes every producer check vacuous",
                m.ledger.contexts.len()
            ),
            "populate ci/required-checks.txt from branch protection",
        ));
    }
    match m.ledger.pinned {
        None => out.push(finding(
            "CI-I9-PIN",
            Severity::Undecided,
            "ci/required-checks.txt",
            0,
            "population pin",
            "no `# PINNED = N` header — a deletable population rewards deleting rows".into(),
            "add `# PINNED = <count>`; it may only grow",
        )),
        Some(p) if p != m.ledger.contexts.len() => out.push(finding(
            "CI-I9-PIN",
            Severity::Critical,
            "ci/required-checks.txt",
            0,
            "population pin",
            format!(
                "ledger lists {} contexts but PINNED = {p}; a row was added without raising the \
                 pin, or removed to dodge a red",
                m.ledger.contexts.len()
            ),
            "raise the pin in the same change that adds a context; a removal is an owner \
             decision recorded as dated prose in the file",
        )),
        Some(_) => {}
    }
    let mut seen = std::collections::BTreeSet::new();
    for c in &m.ledger.contexts {
        if !seen.insert(c) {
            out.push(finding(
                "CI-I9-DUP",
                Severity::Critical,
                "ci/required-checks.txt",
                0,
                c,
                "context listed twice — double-counted coverage".into(),
                "list each context once",
            ));
        }
    }
    out
}
