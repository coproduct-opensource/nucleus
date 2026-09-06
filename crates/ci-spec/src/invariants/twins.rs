//! I1 — twin completeness.
//!
//! A path-filtered workflow `X.yml` that produces a required context is
//! paired with `X-noop.yml`: same workflow `name:`, same job names, and a
//! `paths-ignore` that is EXACTLY the real twin's `paths`, so that on every
//! pull request exactly one of the two reports the context. The complement
//! lemma (`ci/lean/CiSpec/Pipeline.lean`, T2) needs set equality; anything
//! else fires both twins or neither.
//!
//! Founding defects: `aeneas-ifc-scoped-noop.yml` ignored a 24-file strict
//! subset of the real twin's two globs (both twins fired on
//! `nucleus-ifc-kernel/src/lib.rs`); `aeneas-oidc-spiffe-noop.yml` was
//! missing one file; `kani-nightly-noop.yml`'s header records the same scar.

use std::collections::BTreeSet;

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    for noop in m.workflows.iter().filter(|w| w.is_noop()) {
        let key = noop.pair_key();
        let Some(real) = m
            .workflows
            .iter()
            .find(|w| !w.is_noop() && w.pair_key() == key)
        else {
            out.push(finding(
                "CI-I1-ORPHAN",
                Severity::Critical,
                &noop.path,
                0,
                &key,
                "a `-noop` twin with no real twin: the context it reports is never actually \
                 checked"
                    .into(),
                "delete the twin or restore the real workflow",
            ));
            continue;
        };

        // The real twin must be path-filtered on pull_request (otherwise the
        // pair fires both on every PR) and the noop must use paths-ignore.
        let real_paths: BTreeSet<&str> = real
            .triggers
            .pull_request
            .as_ref()
            .map(|p| p.paths.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let noop_ignore: BTreeSet<&str> = noop
            .triggers
            .pull_request
            .as_ref()
            .map(|p| p.paths_ignore.iter().map(String::as_str).collect())
            .unwrap_or_default();

        if real_paths.is_empty() {
            out.push(finding(
                "CI-I1-UNFILTERED",
                Severity::Critical,
                &real.path,
                0,
                &key,
                "the real twin has no `pull_request.paths` filter, so both twins fire on every \
                 PR and the context is reported twice"
                    .into(),
                "filter the real twin, or delete the noop",
            ));
        }
        if real_paths != noop_ignore {
            let missing: Vec<&&str> = real_paths.difference(&noop_ignore).collect();
            let extra: Vec<&&str> = noop_ignore.difference(&real_paths).collect();
            out.push(finding(
                "CI-I1-PATHS",
                Severity::Critical,
                &noop.path,
                0,
                &key,
                format!(
                    "`paths-ignore` ≠ real twin's `paths`. Missing from the noop: {missing:?}; \
                     extra in the noop: {extra:?}. A change matching a missing entry fires BOTH \
                     twins under one context name; an extra entry can leave a change with \
                     NEITHER"
                ),
                "make the noop's paths-ignore the real twin's paths, verbatim",
            ));
        }
        if noop.name != real.name {
            out.push(finding(
                "CI-I1-NAME",
                Severity::High,
                &noop.path,
                0,
                &key,
                format!(
                    "workflow name {:?} ≠ real twin's {:?}; the checks UI and `github.workflow` \
                     treat them as different workflows",
                    noop.name, real.name
                ),
                "give both twins the same `name:`",
            ));
        }
        let real_jobs: BTreeSet<String> = real.jobs.iter().flat_map(|j| j.contexts()).collect();
        let noop_jobs: BTreeSet<String> = noop.jobs.iter().flat_map(|j| j.contexts()).collect();
        // Every noop job must exist in the real twin; the real twin may have
        // extra (non-required) jobs, but every REQUIRED job of the real twin
        // must be mirrored, or a PR outside the paths never reports it.
        for j in noop_jobs.difference(&real_jobs) {
            out.push(finding(
                "CI-I1-JOBS",
                Severity::High,
                &noop.path,
                0,
                j,
                "noop job with no counterpart in the real twin: a context that is only ever \
                 vacuously green"
                    .into(),
                "mirror the real twin's job names exactly",
            ));
        }
        for j in real_jobs.difference(&noop_jobs) {
            if m.is_required(j) {
                out.push(finding(
                    "CI-I1-JOBS",
                    Severity::Critical,
                    &noop.path,
                    0,
                    j,
                    "required context produced by the real twin has no noop mirror: a PR \
                     outside the paths never reports it and blocks forever"
                        .into(),
                    "add the job to the noop twin with the same `name:`",
                ));
            }
        }
        if let (Some(a), Some(b)) = (&real.concurrency, &noop.concurrency) {
            if a.group == b.group {
                out.push(finding(
                    "CI-I1-GROUP",
                    Severity::Critical,
                    &noop.path,
                    b.line,
                    &key,
                    "twins share a concurrency group: when both fire (a PR touching a filtered \
                     and an unfiltered path) whichever starts second cancels the first, and a \
                     CANCELLED check-run makes the PR rollup FAILURE (#2399)"
                        .into(),
                    "give the twins distinct literal group prefixes",
                ));
            }
        }
        if noop.triggers.merge_group {
            // Critical only when a REQUIRED context would get the vacuous
            // green; a non-required twin that covers the queue on purpose
            // (quickstart-boot, whose real job needs KVM the queue lacks)
            // is reported, not failed.
            let required = noop_jobs.iter().any(|j| m.is_required(j));
            out.push(finding(
                "CI-I1-NOOP-MG",
                if required {
                    Severity::Critical
                } else {
                    Severity::Info
                },
                &noop.path,
                0,
                &key,
                "the noop twin runs on merge_group: the queue gets a vacuous green for the \
                 context alongside (or instead of) the real check"
                    .into(),
                "trigger the noop on pull_request only; the real twin runs unfiltered in the queue",
            ));
        }
    }
    out
}
