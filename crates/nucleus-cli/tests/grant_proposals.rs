//! Denials become proposals, and a proposal becomes a grant with one command
//! (ADR 0004, milestone 4), at the CLI boundary: `nucleus grant propose`
//! reads a run's trace and names the minimum; `nucleus grant widen` re-seals
//! the grant with exactly that, under the same ceiling; what the ceiling
//! clips is named, never granted.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='x'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::create_dir_all(root.join(".github/workflows")).unwrap();
    fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(
        root.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://github.com/acme/widgets.git\n",
    )
    .unwrap();
    dir
}

fn nucleus(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nucleus"));
    c.env("HOME", home);
    c
}

/// Seal "run the tests" under safe-pr-fixer: read + run_bash, no git.
fn seal(home: &Path, repo: &Path, out: &Path) {
    let res = nucleus(home)
        .args([
            "grant",
            "seal",
            "--goal",
            "run the tests",
            "--ceiling",
            "safe-pr-fixer",
            "--yes",
        ])
        .arg("-o")
        .arg(out)
        .arg("-d")
        .arg(repo)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "seal failed:\n{}",
        String::from_utf8_lossy(&res.stderr)
    );
}

/// A kernel trace with one allowed read and two denials: a commit (inside
/// the ceiling) and a push (outside it). Written in the kernel's own
/// `Decision` shape, as `--kernel-trace` produces.
fn trace_with_denials() -> String {
    let base = |op: &str, subject: &str, verdict: &str| {
        format!(
            r#"{{"id":"00000000-0000-0000-0000-000000000000","sequence":0,"operation":"{op}","subject":"{subject}","verdict":{verdict},"timestamp":"2026-09-08T22:00:00Z","pre_permissions_hash":"","post_permissions_hash":"","exposure_transition":{{"pre_count":0,"post_count":0,"contributed_label":null,"state_uninhabitable":false,"dynamic_gate_applied":false}}}}"#
        )
    };
    [
        base("read_files", "src/main.rs", r#"{"type":"allow"}"#),
        base(
            "git_commit",
            "-m fix",
            r#"{"type":"deny","reason":"insufficient_capability"}"#,
        ),
        base(
            "git_push",
            "origin main",
            r#"{"type":"deny","reason":"insufficient_capability"}"#,
        ),
    ]
    .join("\n")
}

#[test]
fn denials_become_proposals_and_a_proposal_becomes_a_grant_with_one_command() {
    let dir = repo();
    let home = tempfile::tempdir().unwrap();
    let grant = dir.path().join("tests.grant");
    seal(home.path(), dir.path(), &grant);
    let trace = dir.path().join("trace.jsonl");
    fs::write(&trace, trace_with_denials()).unwrap();

    let out = nucleus(home.path())
        .args(["grant", "propose", "--grant"])
        .arg(&grant)
        .arg("--input")
        .arg(&trace)
        .arg("-d")
        .arg(dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    // The commit: inside the ceiling, one command grants it.
    assert!(stdout.contains("denied:  git_commit `-m fix`"), "{stdout}");
    assert!(stdout.contains("minimum: git/commit"), "{stdout}");
    assert!(stdout.contains("git_commit: never → low_risk"), "{stdout}");
    assert!(
        stdout.contains("nucleus grant widen --grant") && stdout.contains("--effects git/commit"),
        "{stdout}"
    );
    // The push: safe-pr-fixer never pushes; nothing is offered, the ceiling is named.
    assert!(
        stdout.contains("denied:  git_push `origin main`"),
        "{stdout}"
    );
    assert!(stdout.contains("outside ceiling safe-pr-fixer"), "{stdout}");
    assert!(!stdout.contains("--effects git/push-branch"), "{stdout}");

    // JSON form carries the same, structured.
    let out = nucleus(home.path())
        .args(["grant", "propose", "--json", "--grant"])
        .arg(&grant)
        .arg("--input")
        .arg(&trace)
        .arg("-d")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["blocked"]["code"], "insufficient_capability");
    assert_eq!(arr[0]["scopes"][0]["scope"], "always");
    assert_eq!(arr[1]["outside_ceiling"], "safe-pr-fixer");
    assert!(arr[1]["scopes"].as_array().unwrap().is_empty());

    // Run the one command. The widened grant carries git/commit; the push,
    // asked for too, stays clipped and is said so.
    let widened = dir.path().join("widened.grant");
    let out = nucleus(home.path())
        .args(["grant", "widen", "--grant"])
        .arg(&grant)
        .args(["--effects", "git/commit,git/push-branch", "--yes", "-o"])
        .arg(&widened)
        .arg("-d")
        .arg(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stderr.contains("adds git/commit"), "{stderr}");
    assert!(
        stderr.contains("git/push-branch stay outside ceiling safe-pr-fixer"),
        "{stderr}"
    );
    assert!(stdout.contains("commit changes locally"), "{stdout}");

    // The widened grant verifies and runs with no prompt, like any sealed grant.
    let out = nucleus(home.path())
        .args(["run", "--grant"])
        .arg(&widened)
        .args(["--dry-run", "--local", "-d"])
        .arg(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("verified"), "{stdout}");
    assert!(stdout.contains("commit changes locally"), "{stdout}");
    assert!(!stdout.contains("push to remote branches (outside") || stdout.contains("Cannot:"));

    // Widening with nothing to add is refused, not a no-op that re-signs.
    let out = nucleus(home.path())
        .args(["grant", "widen", "--grant"])
        .arg(&grant)
        .args(["--yes", "-d"])
        .arg(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing to widen"));
}

#[test]
fn a_trace_without_denials_proposes_nothing() {
    let dir = repo();
    let home = tempfile::tempdir().unwrap();
    let grant = dir.path().join("tests.grant");
    seal(home.path(), dir.path(), &grant);
    let trace = dir.path().join("trace.jsonl");
    fs::write(
        &trace,
        r#"{"operation":"read_files","subject":"src/main.rs","succeeded":true}"#,
    )
    .unwrap();
    let out = nucleus(home.path())
        .args(["grant", "propose", "--grant"])
        .arg(&grant)
        .arg("--input")
        .arg(&trace)
        .arg("-d")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("no denials"));
}
