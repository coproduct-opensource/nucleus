//! I4 — concurrency groups.
//!
//! No two workflow files resolve to the same concurrency group (after
//! substituting `${{ github.workflow }}` with each file's `name:`), and
//! `cancel-in-progress` is never true under `merge_group` or `push`:
//! cancelling a merge_group run ejects the queue entry mid-flight, and
//! cancelling a push-to-main run drops the signal for a commit that already
//! landed.
//!
//! Founding defects: all ten twin pairs once shared `${{ github.workflow }}-…`
//! and cancelled each other on every PR (#2399); `zizmor.yml` had
//! `cancel-in-progress: true`, `feature-matrix.yml` had
//! `github.ref != 'refs/heads/main'` — true for a queue ref.

use std::collections::BTreeMap;

use crate::expr::{self, Event, Tri};
use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut groups: BTreeMap<String, Vec<(&str, usize)>> = BTreeMap::new();
    for w in &m.workflows {
        let Some(c) = &w.concurrency else { continue };
        let resolved = c.group.replace("${{ github.workflow }}", &w.name);
        groups
            .entry(resolved)
            .or_default()
            .push((w.path.as_str(), c.line));

        for ev in [Event::MergeGroup, Event::Push] {
            let applies = match ev {
                Event::MergeGroup => w.triggers.merge_group,
                Event::Push => w.triggers.push.is_some(),
                Event::PullRequest => false,
            };
            if !applies {
                continue;
            }
            let v = c.cancel_in_progress.trim();
            let val = match v {
                "true" => Ok(Tri::True),
                "false" => Ok(Tri::False),
                other => expr::eval(other, ev).map(|e| e.value),
            };
            match val {
                Ok(Tri::True) => out.push(finding(
                    "CI-I4-CANCEL",
                    Severity::High,
                    &w.path,
                    c.line,
                    &w.name,
                    format!(
                        "`cancel-in-progress: {v}` is TRUE under {}: a newer run in the group \
                         cancels this one, {}",
                        match ev {
                            Event::MergeGroup => "merge_group",
                            _ => "push",
                        },
                        match ev {
                            Event::MergeGroup =>
                                "which aborts a queue entry mid-flight and ejects it",
                            _ => "which drops the CI signal for a commit already on main",
                        }
                    ),
                    "use `cancel-in-progress: ${{ github.event_name == 'pull_request' }}`",
                )),
                Ok(_) => {}
                Err(e) => out.push(finding(
                    "CI-I4-UNDECIDED",
                    Severity::Undecided,
                    &w.path,
                    c.line,
                    &w.name,
                    format!("`cancel-in-progress` {e}"),
                    "use the house expression",
                )),
            }
        }
    }
    for (g, files) in groups {
        if files.len() > 1 {
            let names: Vec<&str> = files.iter().map(|(p, _)| *p).collect();
            out.push(finding(
                "CI-I4-SHARED",
                Severity::Critical,
                files[0].0,
                files[0].1,
                &g,
                format!(
                    "{} workflows resolve to the same concurrency group {names:?}: whichever \
                     starts second cancels the first, and a CANCELLED check-run turns the PR \
                     rollup red for a check that never ran",
                    files.len()
                ),
                "give each file a distinct literal prefix in its group",
            ));
        }
    }
    out
}
