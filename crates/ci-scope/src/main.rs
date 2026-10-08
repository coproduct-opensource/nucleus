//! `ci-scope` — the first step of a path-scoped job. Writes `relevant=true|false` to
//! `$GITHUB_OUTPUT`; the job's later steps run only when it is `true`.
//!
//! Environment (never interpolate `${{ }}` into a run script; pass it here):
//!
//! * `SCOPE_PATHS` — the repo-relative scope list (`ci/scope/<job>.paths`);
//! * `EVENT` — `github.event_name`;
//! * `BASE`, `HEAD` — the range a `pull_request` or `merge_group` event compares;
//! * `GITHUB_OUTPUT` — set by the runner.
//!
//! Exit 0 with a decision, or exit 2 when the step itself is misconfigured (no list, a list
//! that does not parse, no output file). Misconfiguration fails the job — red, never skipped.

// ADR 0007 totality: a decider that panics would fail the job for a reason that names nothing.
// Denied for the shipped build only -- `assert!` is a panic, and tests are made of it.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use std::io::Write as _;
use std::process::{Command, ExitCode};

use ci_scope::{Decision, Event, Range, RunBecause, ScopeList, decide, split_nul};

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn required(name: &str) -> Result<String, String> {
    var(name)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("`{name}` is not set"))
}

/// `git diff --name-only` over the merge base, with renames split into a deletion and an
/// addition so a file moved OUT of the scope still counts as touching it.
fn changed_files(range: &Range) -> Result<Vec<String>, String> {
    let out = Command::new("git")
        .args(["diff", "--name-only", "--no-renames", "-z"])
        .arg(format!("{}...{}", range.base(), range.head()))
        .output()
        .map_err(|e| format!("could not start git: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("git diff exited {}: {}", out.status, stderr.trim()));
    }
    Ok(split_nul(&out.stdout))
}

fn run() -> Result<Decision, String> {
    let list_path = required("SCOPE_PATHS")?;
    let text = std::fs::read_to_string(&list_path)
        .map_err(|e| format!("reading the scope list `{list_path}`: {e}"))?;
    let scope = ScopeList::parse(&text).map_err(|e| format!("`{list_path}`: {e}"))?;
    let event = Event::from_name(&required("EVENT")?);
    let output = required("GITHUB_OUTPUT")?;

    let range = Range::new(var("BASE").as_deref(), var("HEAD").as_deref());
    let decision = decide(&event, range.as_ref(), changed_files, &scope);

    // One line, one write: the runner's own `key=value` step-output file, not a record log, and
    // nothing else writes it while this step runs.
    #[expect(
        clippy::disallowed_methods,
        reason = "GITHUB_OUTPUT is the runner's step-output file, appended once per step"
    )]
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&output)
        .map_err(|e| format!("opening GITHUB_OUTPUT `{output}`: {e}"))?;
    f.write_all(format!("relevant={}\n", decision.relevant()).as_bytes())
        .map_err(|e| format!("writing GITHUB_OUTPUT `{output}`: {e}"))?;
    Ok(decision)
}

fn main() -> ExitCode {
    match run() {
        Ok(decision) => {
            if let Decision::Run(RunBecause::DiffFailed(_) | RunBecause::NoRange) = &decision {
                println!("::warning::ci-scope {decision}");
            } else {
                println!("ci-scope {decision}");
            }
            ExitCode::SUCCESS
        }
        Err(why) => {
            println!("::error::ci-scope: {why}");
            ExitCode::from(2)
        }
    }
}
