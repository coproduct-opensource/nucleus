//! I5 — merge-group scope gates agree with their declared paths.
//!
//! `paths:` under `merge_group:` parses and is then ignored by GitHub, so a
//! path-filtered workflow re-implements its scope as a regex in a step with
//! `id: scope` and `env.PATTERN`. Two copies of one fact drift: widen
//! `paths:` and forget the regex, and the queue silently stops running a
//! proof the PR still runs (#2358). Every declared path prefix must be
//! matched by PATTERN, and there must be at least one declared path — a gate
//! whose paths cannot be read is vacuous here.
//!
//! This is the second, independent declaration of what
//! `ci/merge-group-scope-parity.sh` checks; the shell script stays.
//!
//! # Decided scope (`env.SCOPE_PATHS`)
//!
//! The PATTERN shape keeps GitHub's `paths:` filter on pull requests, which is what forces a
//! `-noop` twin for a required context — and a pull request touching one file inside the
//! paths and one outside fires BOTH twins under one name (`twin_both_iff`; #3329 carried a
//! 17-minute boot and a 2-second no-op for the same context). A step that instead names a scope
//! list in `env.SCOPE_PATHS` hands every event to `ci-scope`, so the workflow needs no filter
//! and no twin. What that shape must hold:
//!
//! * CI-I5-SCOPE-LIST — the list exists and parses with `ci-scope`'s own parser;
//! * CI-I5-SCOPE-RUN — the step runs `ci-scope` (a list nobody reads decides nothing);
//! * CI-I5-SCOPE-SELF — the list covers the workflow and itself, so narrowing either runs the
//!   job that would notice;
//! * CI-I5-SCOPE-FILTER — the workflow has no `pull_request` path filter: a filtered workflow
//!   never reports the context on a pull request outside the filter, and a twin added to cover
//!   that is the straddle this shape exists to remove.

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = decided(m);
    for w in &m.workflows {
        for j in &w.jobs {
            for s in &j.steps {
                if s.id.as_deref() != Some("scope") {
                    continue;
                }
                let Some(pattern) = s.env.get("PATTERN") else {
                    out.push(finding(
                        "CI-I5-NOPATTERN",
                        Severity::Critical,
                        &w.path,
                        s.line,
                        &j.id,
                        "`id: scope` step with no `env.PATTERN`".into(),
                        "declare PATTERN derived from the pull_request paths",
                    ));
                    continue;
                };
                let re = match regex::Regex::new(pattern) {
                    Ok(r) => r,
                    Err(e) => {
                        out.push(finding(
                            "CI-I5-REGEX",
                            Severity::Critical,
                            &w.path,
                            s.line,
                            &j.id,
                            format!("PATTERN does not compile: {e}"),
                            "fix the regex",
                        ));
                        continue;
                    }
                };
                let paths: Vec<&str> = w
                    .triggers
                    .pull_request
                    .as_ref()
                    .map(|p| p.paths.iter().map(String::as_str).collect())
                    .unwrap_or_default();
                if paths.is_empty() {
                    out.push(finding(
                        "CI-I5-VACUOUS",
                        Severity::Critical,
                        &w.path,
                        s.line,
                        &j.id,
                        "scope-gated workflow declares no pull_request paths — the parity check \
                         has nothing to compare and the gate is vacuous"
                            .into(),
                        "declare the paths, or remove the scope gate",
                    ));
                }
                for p in paths {
                    let probe = p.split('*').next().unwrap_or(p);
                    if probe.is_empty() {
                        continue;
                    }
                    if !re.is_match(probe) {
                        out.push(finding(
                            "CI-I5-PARITY",
                            Severity::Critical,
                            &w.path,
                            s.line,
                            &j.id,
                            format!(
                                "declared path {p:?} is not matched by PATTERN {pattern:?}: a \
                                 change there runs the proof on the PR but NOT in the merge queue"
                            ),
                            "extend PATTERN to cover every declared path",
                        ));
                    }
                }
            }
        }
    }
    out
}

/// The `env.SCOPE_PATHS` shape: see the module docs.
fn decided(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    for w in &m.workflows {
        let mut uses_a_list = false;
        for j in &w.jobs {
            for s in &j.steps {
                let Some(list_path) = s.env.get("SCOPE_PATHS") else {
                    continue;
                };
                uses_a_list = true;
                if !s.run.as_deref().is_some_and(|r| r.contains("ci-scope")) {
                    out.push(finding(
                        "CI-I5-SCOPE-RUN",
                        Severity::Critical,
                        &w.path,
                        s.line,
                        &j.id,
                        format!(
                            "the step names the scope list {list_path:?} but does not run                              `ci-scope`: nothing decides from that list"
                        ),
                        "run `cargo run -q --locked -p ci-scope` in the step",
                    ));
                }
                let list = match m.scope_lists.get(list_path) {
                    Some(Ok(list)) => list,
                    Some(Err(why)) => {
                        out.push(finding(
                            "CI-I5-SCOPE-LIST",
                            Severity::Critical,
                            &w.path,
                            s.line,
                            &j.id,
                            format!("scope list {list_path:?} is unusable: {why}"),
                            "fix the list; the decider refuses it the same way",
                        ));
                        continue;
                    }
                    None => {
                        out.push(finding(
                            "CI-I5-SCOPE-LIST",
                            Severity::Critical,
                            &w.path,
                            s.line,
                            &j.id,
                            format!("scope list {list_path:?} was not read"),
                            "check the model from a repository checkout",
                        ));
                        continue;
                    }
                };
                for must in [w.path.as_str(), list_path.as_str()] {
                    if !list.covers(must) {
                        out.push(finding(
                            "CI-I5-SCOPE-SELF",
                            Severity::Critical,
                            &w.path,
                            s.line,
                            &j.id,
                            format!(
                                "scope list {list_path:?} does not cover {must:?}: a change that                                  narrows the scope or the workflow would skip the job that                                  checks it"
                            ),
                            "add the path to the list",
                        ));
                    }
                }
            }
        }
        let filtered = w
            .triggers
            .pull_request
            .as_ref()
            .is_some_and(|p| !p.paths.is_empty() || !p.paths_ignore.is_empty());
        if uses_a_list && filtered {
            out.push(finding(
                "CI-I5-SCOPE-FILTER",
                Severity::Critical,
                &w.path,
                0,
                &w.name,
                "the workflow decides scope with `ci-scope` AND filters pull_request paths: a                  pull request outside the filter never reports the context"
                    .into(),
                "drop the pull_request `paths:`/`paths-ignore:`; the scope list is the one copy",
            ));
        }
    }
    out
}
