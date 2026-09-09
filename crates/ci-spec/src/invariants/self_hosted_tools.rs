//! I10 — a job routed to a self-hosted runner may not silently assume a tool the image provides.
//!
//! The shape. A workflow installs a toolchain behind
//! `if: runner.environment == 'github-hosted'`, because on the self-hosted fleet the image is
//! supposed to bake it. That conditional is a CONTRACT WITH AN IMAGE, and nothing checks it: if
//! the image does not have the tool, the step is skipped, the job runs anyway, and the command
//! fails with `exit 127`. On a required context that is a `failed` verdict indistinguishable from
//! the gate's own answer — it ejects the merge-queue entry and invalidates every group behind it.
//!
//! Founding defects, all on 2026-09-09, all the same class, found one at a time over six hours
//! while the queue produced one merge:
//!
//! * `lake: command not found` — the new worker image had no elan, so five Lean lanes failed.
//! * `ENOSPC` and `ld terminated with signal 7` — the same contract for a RESOURCE rather than a
//!   binary: build machines without a volume, `cargo test --all-features` filling an 8 GB root
//!   filesystem. Four required contexts failed at once because they relay one job.
//! * `Scoped Aeneas`, `charon+aeneas drift` — the image had no aeneas/charon.
//!
//! Each was repaired on its own and the class recurred anyway, which is the argument for this
//! file. gatehouse states the same property as A-10 ("in the declared environment") and now
//! enforces it at admission for gates; nucleus's own CI is not a gatehouse tenant yet, so it
//! needs its own.
//!
//! What is checked. The population of image-dependent jobs — routed to a self-hosted label AND
//! carrying a hosted-only install step — is PINNED both ways in `ci/image-dependent-jobs.txt`. A
//! new one is a finding, because somebody must confirm the runner image provides the tool before
//! the job can rely on it; a stale entry is a finding too, so the file cannot rot into a list
//! nobody reads. This does not prove the image has the tool — nothing in this repository can see
//! inside the image — it makes the assumption VISIBLE and dated, which is what was missing.

use std::collections::BTreeSet;

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

/// Where the population lives, relative to the repository root.
pub const INVENTORY: &str = "ci/image-dependent-jobs.txt";

/// The routing variables that send a job to a self-hosted pool.
const SELF_HOSTED_VARS: [&str; 3] = [
    "vars.CI_RUNNER",
    "vars.CI_BUILD_RUNNER",
    "vars.ARM64_METAL_RUNNER",
];

/// The marker that says "the image is expected to have this".
const HOSTED_ONLY: &str = "runner.environment == 'github-hosted'";

fn routed_self_hosted(runs_on: &str) -> bool {
    SELF_HOSTED_VARS.iter().any(|v| runs_on.contains(v))
}

/// A step that DOES something behind the hosted-only guard. A cache step is not a contract with
/// the image — a cache miss costs time, not a verdict — so only steps that run a command or use
/// an action that is not a cache count.
fn is_install(step: &crate::model::Step) -> bool {
    if step
        .if_expr
        .as_deref()
        .is_none_or(|e| !e.contains(HOSTED_ONLY))
    {
        return false;
    }
    let name = step.name.to_ascii_lowercase();
    !name.contains("cache")
}

/// `workflow/job` for every job that is routed to a self-hosted runner and carries a hosted-only
/// install step.
#[must_use]
pub fn population(m: &Model) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for w in &m.workflows {
        for j in &w.jobs {
            if routed_self_hosted(&j.runs_on) && j.steps.iter().any(is_install) {
                let stem = std::path::Path::new(&w.path)
                    .file_stem()
                    .map_or_else(|| w.path.clone(), |s| s.to_string_lossy().into_owned());
                out.insert(format!("{stem}/{}", j.id));
            }
        }
    }
    out
}

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    let live = population(m);
    let pin = m.image_dependent_pinned.clone();

    for job in live.difference(&pin) {
        let (wf, id) = job.split_once('/').unwrap_or((job.as_str(), ""));
        let (path, line) = m
            .workflows
            .iter()
            .find(|w| w.path.contains(wf))
            .and_then(|w| {
                w.jobs
                    .iter()
                    .find(|j| j.id == id)
                    .map(|j| (w.path.clone(), j.line))
            })
            .unwrap_or_else(|| (INVENTORY.to_string(), 0));
        out.push(
            finding(
                "CI-I10-UNPINNED",
                Severity::High,
                &path,
                line,
                job,
                "runs on a self-hosted label and installs a tool only when hosted, so it ASSUMES \
                 the runner image provides that tool — and nothing here can see inside the image. \
                 Unprovided, the step is skipped and the command fails with exit 127, which on a \
                 required context ejects the merge-queue entry"
                    .to_string(),
                &format!(
                    "confirm the runner image (ci/fly-runner/Dockerfile, docker/Dockerfile.runner) \
                     provides it, then add `{job}` to {INVENTORY}"
                ),
            )
            .in_job(id),
        );
    }

    for job in pin.difference(&live) {
        out.push(finding(
            "CI-I10-STALE",
            Severity::Info,
            INVENTORY,
            0,
            job,
            "pinned as image-dependent, but no such job routes to a self-hosted runner with a \
             hosted-only install step any more"
                .to_string(),
            &format!("remove `{job}` from {INVENTORY}"),
        ));
    }
    out
}
