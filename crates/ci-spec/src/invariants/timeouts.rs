//! I7 — timeouts fit the queue.
//!
//! The merge queue waits `check_response_timeout_minutes` for every required
//! check on a group, then assumes failure and ejects the entry. A job that
//! can legitimately run longer than that — or a `needs:` chain whose
//! timeouts sum past it — is an ejection waiting for a slow day. A job with
//! no `timeout-minutes` gets GitHub's default of 360, which is the whole
//! budget on its own.
//!
//! Founding defect: the 2026-09-04/05 stall — the queue timeout was 60 min
//! while Mutation Testing ran 30–45 min after a queue wait, and entries were
//! ejected by timeout rather than by any red check.

use std::collections::BTreeMap;

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    let budget = m.queue.check_response_timeout_minutes;
    for w in m.workflows.iter().filter(|w| w.triggers.merge_group) {
        let by_id: BTreeMap<&str, &crate::model::Job> =
            w.jobs.iter().map(|j| (j.id.as_str(), j)).collect();
        for j in &w.jobs {
            let Some(t) = j.timeout_minutes else {
                out.push(
                    finding(
                        "CI-I7-NOTIMEOUT",
                        Severity::Medium,
                        &w.path,
                        j.line,
                        j.display_name(),
                        format!(
                            "no `timeout-minutes`; GitHub's default is 360, which equals the \
                             queue's {budget}-minute check budget, so a hung job ejects the entry"
                        ),
                        "declare a timeout below the queue budget",
                    )
                    .in_job(&j.id),
                );
                continue;
            };
            if t > budget {
                out.push(
                    finding(
                        "CI-I7-EXCEEDS",
                        Severity::High,
                        &w.path,
                        j.line,
                        j.display_name(),
                        format!(
                            "timeout-minutes {t} > queue check budget {budget}: a slow run is \
                             ejected by the queue before the job's own timeout fires"
                        ),
                        "lower the timeout or raise the ruleset budget (ci/merge-queue.toml)",
                    )
                    .in_job(&j.id),
                );
            }
            // Critical path through needs.
            let path = critical_path(&by_id, &j.id, 0);
            if path > budget {
                out.push(
                    finding(
                        "CI-I7-PATH",
                        Severity::High,
                        &w.path,
                        j.line,
                        j.display_name(),
                        format!(
                            "the `needs:` chain ending here can take {path} min of timeouts, over \
                             the queue's {budget}-minute budget"
                        ),
                        "shorten the chain or its timeouts",
                    )
                    .in_job(&j.id),
                );
            }
        }
    }
    out
}

fn critical_path(by_id: &BTreeMap<&str, &crate::model::Job>, id: &str, depth: usize) -> u64 {
    if depth > 32 {
        return 0; // cyclic; actionlint rejects those anyway
    }
    let Some(j) = by_id.get(id) else { return 0 };
    let own = j.timeout_minutes.unwrap_or(360);
    let up = j
        .needs
        .iter()
        .map(|n| critical_path(by_id, n, depth + 1))
        .max()
        .unwrap_or(0);
    own + up
}
