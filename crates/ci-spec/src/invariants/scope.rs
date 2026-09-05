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

use crate::model::Model;
use crate::{Finding, Severity};

use super::finding;

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
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
