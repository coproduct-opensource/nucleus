//! I2 — producer injectivity.
//!
//! Each required context is produced by exactly one twin pair. GitHub matches
//! required checks by name; two jobs in different workflows with the same
//! `name:` produce two same-named check runs, and the rollup takes whichever
//! it takes — one gate's result can stand in for the other's.
//!
//! Founding defect: `Scoped Aeneas (Rust → Lean 4) + parity tests` was
//! produced by four jobs — the IFC pair and the OIDC→SPIFFE pair (verified
//! live on PR #2641: two check runs with that exact name).

use std::collections::BTreeSet;

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    for ctx in &m.ledger.contexts {
        let producers = m.producers(ctx);
        if producers.is_empty() {
            out.push(finding(
                "CI-I2-NONE",
                Severity::Critical,
                "ci/required-checks.txt",
                0,
                ctx,
                "required context has no producing job in any workflow: every PR waits on it \
                 forever (or, if branch protection was edited to match, the ledger is stale)"
                    .into(),
                "add the producing job, or remove the context from branch protection AND the \
                 ledger (an owner decision, recorded)",
            ));
            continue;
        }
        let pairs: BTreeSet<String> = producers
            .iter()
            .map(|(wi, _)| m.workflows[*wi].pair_key())
            .collect();
        if pairs.len() > 1 {
            let where_: Vec<String> = producers
                .iter()
                .map(|(wi, ji)| {
                    format!(
                        "{}:{}",
                        m.workflows[*wi].path, m.workflows[*wi].jobs[*ji].id
                    )
                })
                .collect();
            out.push(finding(
                "CI-I2-DUP",
                Severity::Critical,
                &m.workflows[producers[0].0].path,
                m.workflows[producers[0].0].jobs[producers[0].1].line,
                ctx,
                format!(
                    "produced by {} jobs across {} twin pairs ({where_:?}): same-named check runs, \
                     so either gate's verdict can stand in for the other's",
                    producers.len(),
                    pairs.len()
                ),
                "give each pair a distinct job `name:` and register both contexts",
            ));
        }
        // Within one pair, more than two producers (e.g. a matrix without a
        // per-leg name) is also ambiguous.
        for pair in &pairs {
            let n = producers
                .iter()
                .filter(|(wi, _)| m.workflows[*wi].pair_key() == *pair)
                .count();
            if n > 2 {
                out.push(finding(
                    "CI-I2-DUP",
                    Severity::High,
                    &m.workflows[producers[0].0].path,
                    0,
                    ctx,
                    format!("{n} jobs in pair `{pair}` share this name"),
                    "one job per context per twin",
                ));
            }
        }
    }
    out
}
