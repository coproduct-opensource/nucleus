//! I3 — every required context is reported under `merge_group`, and cannot
//! be SKIPPED there.
//!
//! GitHub counts a skipped required job as passed. A required job is skipped
//! when its `if:` is false, or when any job in its `needs:` did not succeed
//! (unless the `if:` uses `always()`). So two obligations:
//!
//! 1. the real producer's workflow has `merge_group:` in `on:`, and its
//!    job-level `if:` is not false under that event;
//! 2. every job the producer `needs:` is itself a required context, so a red
//!    upstream BLOCKS instead of vacating — or the producer's `if:` uses
//!    `always()` and reads the upstream result explicitly.
//!
//! Founding defect: Tests, Fuzz, OWASP (ci.yml) and llvm-cov, Mutation
//! Testing, Proof Count Ratchet (coverage-matrix.yml) all `need` a detector
//! job (`Detect changed crates` / `Detect Changed Crates`) that was not a
//! required context, whose `git fetch … || true` could fail the job.

use crate::expr::{self, Event, Tri};
use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    for ctx in &m.ledger.contexts {
        let producers = m.producers(ctx);
        let reals: Vec<_> = producers
            .iter()
            .filter(|(wi, _)| !m.workflows[*wi].is_noop())
            .collect();
        if producers.is_empty() {
            continue; // I2 reports it.
        }
        if reals.is_empty() {
            out.push(finding(
                "CI-I3-NOMG",
                Severity::Critical,
                &m.workflows[producers[0].0].path,
                0,
                ctx,
                "only a noop twin produces this context; nothing checks it in the queue".into(),
                "add the real workflow with a merge_group trigger",
            ));
            continue;
        }
        for (wi, ji) in reals {
            let w = &m.workflows[*wi];
            let j = &w.jobs[*ji];
            if !w.triggers.merge_group {
                out.push(finding(
                    "CI-I3-NOMG",
                    Severity::Critical,
                    &w.path,
                    j.line,
                    ctx,
                    "the producing workflow has no `merge_group:` trigger: the context is never \
                     reported on the queue branch, so the entry waits until the queue timeout \
                     ejects it (or, if the PR's own run is reused, the merged result was never \
                     tested against main)"
                        .into(),
                    "add `merge_group:` to `on:`",
                ));
            }
            if let Some(cond) = &j.if_expr {
                match expr::eval(cond, Event::MergeGroup) {
                    Err(e) => out.push(finding(
                        "CI-I3-UNDECIDED",
                        Severity::Undecided,
                        &w.path,
                        j.line,
                        ctx,
                        format!(
                            "job `if:` {e} — the checker cannot tell whether this required \
                                 job can be skipped in the queue"
                        ),
                        "simplify the condition to the modelled subset, or extend ci-spec::expr",
                    )),
                    Ok(ev) => {
                        if ev.value == Tri::False {
                            out.push(finding(
                                "CI-I3-SKIP",
                                Severity::Critical,
                                &w.path,
                                j.line,
                                ctx,
                                format!(
                                    "job `if: {cond}` is FALSE under merge_group: the required \
                                     job is skipped in the queue, and skipped counts as passed"
                                ),
                                "make the job unconditional under merge_group",
                            ));
                        }
                        // `needs` referenced in the condition are covered by
                        // the needs check below; `always()` is what exempts.
                        if !ev.always {
                            for n in &j.needs {
                                needs_check(m, w, j, ctx, n, &mut out);
                            }
                        }
                    }
                }
            } else {
                for n in &j.needs {
                    needs_check(m, w, j, ctx, n, &mut out);
                }
            }
        }
    }
    out
}

fn needs_check(
    m: &Model,
    w: &crate::model::Workflow,
    j: &crate::model::Job,
    ctx: &str,
    needed_id: &str,
    out: &mut Vec<Finding>,
) {
    let Some(up) = w.jobs.iter().find(|x| x.id == needed_id) else {
        out.push(finding(
            "CI-I3-NEEDS",
            Severity::Critical,
            &w.path,
            j.line,
            ctx,
            format!("`needs: {needed_id}` names a job that does not exist in this workflow"),
            "fix the job id",
        ));
        return;
    };
    if !m.is_required(up.display_name()) {
        out.push(finding(
            "CI-I3-NEEDS",
            Severity::Critical,
            &w.path,
            j.line,
            ctx,
            format!(
                "required job `needs: {needed_id}` (`{}`), which is NOT a required context. If \
                 that job fails or is cancelled this one is SKIPPED, and a skipped required \
                 check counts as passed: a red upstream vacates the gate instead of blocking",
                up.display_name()
            ),
            "add the upstream job's name to branch protection and ci/required-checks.txt, or \
             use `if: always()` and assert the upstream result explicitly",
        ));
    }
}
