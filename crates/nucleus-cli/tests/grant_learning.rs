//! The learning loop at the CLI boundary (ADR 0004, milestone 3): a run's
//! trace attributed to its grant, a narrower profile that stays within the
//! grant, and user profiles that `--profile` / `--ceiling` find but that can
//! never widen a canonical name.

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
    // Everything host-side (grant key, profiles, traces) lives under HOME.
    c.env("HOME", home);
    c
}

fn seal(home: &Path, repo: &Path, out: &Path) {
    let res = nucleus(home)
        .args([
            "grant",
            "seal",
            "--goal",
            "fix the failing CI build",
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

const TRACE: &str = r#"{"operation":"read_files","subject":"src/main.rs","succeeded":true}
{"operation":"grep_search","subject":"fn main","succeeded":true}
{"operation":"run_bash","subject":"cargo test --workspace","succeeded":true}
{"operation":"git_push","subject":"origin main","succeeded":false}
"#;

#[test]
fn a_trace_is_attributed_to_the_grant_and_narrows_into_a_usable_profile() {
    let dir = repo();
    let home = tempfile::tempdir().unwrap();
    let grant = dir.path().join("ci.grant");
    seal(home.path(), dir.path(), &grant);
    let trace = dir.path().join("trace.jsonl");
    fs::write(&trace, TRACE).unwrap();

    // Usage report, and a narrowed profile installed under HOME.
    let out = nucleus(home.path())
        .args(["observe", "--grant"])
        .arg(&grant)
        .arg("--input")
        .arg(&trace)
        .args(["--narrow", "ci-tests", "--save", "-d"])
        .arg(dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("authority: used 2 of"), "{stdout}");
    assert!(stdout.contains("ρ = "), "{stdout}");
    assert!(stdout.contains("run the test suite (1)"), "{stdout}");
    assert!(stdout.contains("unused:"), "{stdout}");
    assert!(
        stdout.contains("denied:  git_push origin main (1)"),
        "{stdout}"
    );
    assert!(stderr.contains("installed at"), "{stderr}");

    let installed = home.path().join(".config/nucleus/profiles/ci-tests.yaml");
    let yaml = fs::read_to_string(&installed).unwrap();
    assert!(yaml.contains("name: ci-tests"), "{yaml}");
    assert!(yaml.contains("web_fetch: never"), "{yaml}");
    assert!(yaml.contains("git_commit: never"), "{yaml}");
    assert!(!yaml.contains("run_bash: never"), "{yaml}");

    // The installed profile is a profile like any other …
    let out = nucleus(home.path())
        .args(["run", "--profile", "ci-tests", "--dry-run", "--local", "-d"])
        .arg(dir.path())
        .arg("rerun the tests")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ci-tests"));

    // … and a ceiling: a goal compiled under it cannot exceed what was used.
    let out = nucleus(home.path())
        .args([
            "run",
            "--goal",
            "fix the failing CI build",
            "--ceiling",
            "ci-tests",
            "--dry-run",
            "--local",
            "-d",
        ])
        .arg(dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("outside ceiling ci-tests"),
        "the unused effects are clipped under the learned ceiling:\n{stdout}"
    );
}

#[test]
fn a_user_profile_cannot_widen_a_canonical_name() {
    let dir = repo();
    let home = tempfile::tempdir().unwrap();
    let profiles = home.path().join(".config/nucleus/profiles");
    fs::create_dir_all(&profiles).unwrap();
    // A "read-only" that pushes: wider than the canonical read-only.
    fs::write(
        profiles.join("read-only.yaml"),
        "name: read-only\ncapabilities:\n  git_push: always\n  run_bash: always\n",
    )
    .unwrap();
    let out = nucleus(home.path())
        .args([
            "run",
            "--profile",
            "read-only",
            "--dry-run",
            "--local",
            "--explain",
            "technical",
            "-d",
        ])
        .arg(dir.path())
        .arg("look around")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("wider than the canonical"), "{stderr}");
    assert!(
        !stdout.contains("git_push: always")
            && !stdout.to_lowercase().contains("git_push       always"),
        "the canonical read-only won:\n{stdout}"
    );
}
