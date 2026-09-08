//! `nucleus run --goal` end to end at the CLI boundary: the preview renders
//! the five lines, and an unattended run without `--yes` refuses before it
//! spawns anything.

use std::fs;
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

fn nucleus() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nucleus"))
}

#[test]
fn dry_run_prints_the_five_lines() {
    let dir = repo();
    let out = nucleus()
        .args([
            "run",
            "--goal",
            "fix the failing CI build",
            "--dry-run",
            "--local",
            "--ceiling",
            "safe-pr-fixer",
            "-d",
        ])
        .arg(dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    assert!(lines[0].starts_with("Goal:    fix the failing CI build"));
    assert!(lines[1].contains("read CI logs"), "{stdout}");
    assert!(lines[2].contains("push to remote branches"), "{stdout}");
    assert!(lines[3].starts_with("Limits:"));
    assert!(lines[4].starts_with("Risk:"));
}

#[test]
fn technical_disclosure_adds_the_grid() {
    let dir = repo();
    let out = nucleus()
        .args([
            "run",
            "--goal",
            "fix the failing CI build",
            "--dry-run",
            "--local",
            "--explain",
            "technical",
            "-d",
        ])
        .arg(dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("Capabilities (ceiling: codegen)"),
        "{stdout}"
    );
    assert!(stdout.contains("read_files:"), "{stdout}");
}

#[test]
fn without_a_tty_and_without_yes_it_refuses_before_running() {
    let dir = repo();
    let out = nucleus()
        .args([
            "run",
            "--goal",
            "fix the failing CI build",
            "--local",
            "--tool-proxy-path",
            "/definitely/not/a/binary",
            "-d",
        ])
        .arg(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Goal:    fix the failing CI build"),
        "{stderr}"
    );
    assert!(stderr.contains("--yes"), "{stderr}");
}

#[test]
fn an_unrecognised_goal_fails_closed() {
    let dir = repo();
    let out = nucleus()
        .args(["run", "--goal", "hello there", "--dry-run", "--local", "-d"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("nothing in the goal was recognised"),
        "{stderr}"
    );
}
