//! The two CI pullers, locked to a recorded GitHub response.
//!
//! **Why these goldens exist.** `ci_timings` and `ci_otel` each carried their own copy of the
//! Actions API shapes, `gh api`, and the RFC 3339 parser, and were folded onto one
//! `crate::gh_actions`. That fold is only worth doing if it changed no answer, and "I read the
//! diff and it looked mechanical" is not a check — two `Deserialize` structs can differ in which
//! fields they demand, and a missing field is a silent `None` in a subtraction, not an error.
//!
//! So the extraction was verified by running the OLD binary and the NEW one over the same
//! recorded response and diffing: `ci-timings` byte-identical in both its report and its `--json`
//! mode, `ci-otel --dry-run` identical once the wall-clock stamps it necessarily carries are
//! normalized away. These files are the durable half of that check — the old binary is gone, but
//! a future change to either puller now has to explain itself against a fixed answer.
//!
//! **What `GH_API_FIXTURES` is for.** `gh_api` shells out to the GitHub CLI, so before this every
//! line of both commands was unrunnable without an authenticated `gh` and a network, and the
//! numbers they produced could not be reproduced by a reader. Pointed at a directory, `gh_api`
//! reads `fixture_name(path)` out of it instead. That is what makes this test hermetic and what
//! makes `ci-facts ingest` developable off a runner.
//!
//! **What this does NOT establish.** The fixture is hand-written, not a capture of a real
//! response, so it pins the *derivation* and not the field names GitHub actually sends. A
//! renamed field in the real API would break the live commands with this test still green. The
//! compensating control is that both commands fail loudly on a parse error rather than
//! substituting a default — every field here is required except the four that GitHub genuinely
//! omits.

use std::process::Command;

fn fixtures() -> String {
    format!("{}/tests/fixtures/gh-actions", env!("CARGO_MANIFEST_DIR"))
}

fn golden(name: &str) -> String {
    std::fs::read_to_string(format!("{}/{name}", fixtures())).expect("read golden")
}

/// `cargo xtask ci-timings --sha aaaa111` over the recorded response.
fn run(extra: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["ci-timings", "--sha", "aaaa111"])
        .args(extra)
        .env("GH_API_FIXTURES", fixtures())
        .output()
        .expect("run xtask ci-timings");
    assert!(
        out.status.success(),
        "ci-timings failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8")
}

#[test]
fn the_report_is_what_it_was_before_the_pullers_were_folded_together() {
    assert_eq!(run(&[]), golden("ci-timings.golden.txt"));
}

/// The `--json` mode is the one `ci-facts ingest` will read, so it is pinned separately: a change
/// that only moved the *report* is allowed to move this file only on purpose.
#[test]
fn the_json_mode_is_what_it_was_before_the_pullers_were_folded_together() {
    assert_eq!(run(&["--json"]), golden("ci-timings.golden.json"));
}

/// **The fixture has to exercise the branches, or the goldens prove nothing.** A response where
/// every job succeeded with every timestamp present would pin the happy path and leave the three
/// `Option` subtractions — the exact place a wrong `Deserialize` shows up — untouched.
#[test]
fn the_fixture_covers_the_cases_that_make_the_goldens_worth_having() {
    let report = run(&[]);
    for (what, needle) in [
        ("a job that never started", "still pending: 1"),
        ("a job that failed", "Assurance / ledger"),
        ("more than one runner label", "nucleus-fly-gate"),
        ("both legs", "merge_group=1, pull_request=1"),
        ("the setup-vs-work split", "setup vs work"),
    ] {
        assert!(
            report.contains(needle),
            "the fixture must cover {what}:\n{report}"
        );
    }
}

/// A path with no recorded response must SAY so. The first version of the fixture loader returned
/// the raw `io::Error` — "No such file or directory (os error 2)" — with no path in it, which
/// turns a one-line fix into a hunt.
#[test]
fn a_missing_fixture_names_the_path_it_wanted() {
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["ci-timings", "--sha", "nosuchsha"])
        .env("GH_API_FIXTURES", fixtures())
        .output()
        .expect("run xtask ci-timings");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("nosuchsha") && err.contains("GH_API_FIXTURES"),
        "the error must name the missing path and why it was looked for: {err}"
    );
}
