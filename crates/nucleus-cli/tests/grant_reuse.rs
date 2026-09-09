//! A sealed grant runs again with no confirmation, and only as sealed:
//! `nucleus grant seal` → `nucleus run --grant` at the CLI boundary, plus
//! the refusals that make the zero-prompt path safe (edited file, wrong
//! signer, different repository).

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

fn nucleus() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nucleus"))
}

/// Seal "run the tests" in `repo` with the key at `key`, writing `out`.
fn seal(repo: &Path, key: &Path, out: &Path) {
    let res = nucleus()
        .args(["grant", "seal", "--goal", "run the tests", "--yes"])
        .arg("--grant-key")
        .arg(key)
        .arg("-o")
        .arg(out)
        .arg("-d")
        .arg(repo)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "seal failed:\n{}\n{}",
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(key.exists(), "the grant key is created on first use");
    assert!(out.exists());
}

fn run_grant(repo: &Path, key: &Path, grant: &Path) -> std::process::Output {
    nucleus()
        .args(["run", "--grant"])
        .arg(grant)
        .args(["--dry-run", "--local", "--grant-key"])
        .arg(key)
        .arg("-d")
        .arg(repo)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn a_sealed_grant_runs_again_without_a_confirmation() {
    let dir = repo();
    let key = dir.path().join("grant-signer.pem");
    let grant = dir.path().join("tests.grant");
    seal(dir.path(), &key, &grant);

    // No TTY, no --yes: --goal would exit 2 here. --grant does not ask.
    let out = run_grant(dir.path(), &key, &grant);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("verified") && stdout.contains("no confirmation needed"),
        "{stdout}"
    );
    assert!(stdout.contains("Goal:    run the tests"), "{stdout}");
    assert!(stdout.contains("run the test suite"), "{stdout}");

    // `grant show` says the same.
    let out = nucleus()
        .args(["grant", "show"])
        .arg(&grant)
        .arg("--grant-key")
        .arg(&key)
        .arg("-d")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("verified"));
}

#[test]
fn an_edited_grant_is_refused() {
    let dir = repo();
    let key = dir.path().join("grant-signer.pem");
    let grant = dir.path().join("tests.grant");
    seal(dir.path(), &key, &grant);

    // Widen the readable lattice: the signed one disagrees.
    let text = fs::read_to_string(&grant).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json["grant"]["lattice"]["capabilities"]["git_push"] = serde_json::json!("always");
    fs::write(&grant, serde_json::to_string(&json).unwrap()).unwrap();
    let out = run_grant(dir.path(), &key, &grant);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refused"), "{stderr}");
    assert!(stderr.contains("does not match the signed"), "{stderr}");

    // Rewrite the goal instead.
    let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json["grant"]["goal"] = serde_json::json!("delete the production database");
    fs::write(&grant, serde_json::to_string(&json).unwrap()).unwrap();
    let out = run_grant(dir.path(), &key, &grant);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("goal"), "{stderr}");
}

#[test]
fn a_grant_sealed_by_another_key_is_refused_unless_that_signer_is_trusted() {
    let dir = repo();
    let theirs = dir.path().join("their-key.pem");
    let mine = dir.path().join("my-key.pem");
    let grant = dir.path().join("tests.grant");
    seal(dir.path(), &theirs, &grant);

    // My key is not theirs: refused before any signature is checked.
    let out = run_grant(dir.path(), &mine, &grant);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("trust"), "{stderr}");

    // Trusting their public key by hex (what a CI job would carry) admits it.
    let text = fs::read_to_string(&grant).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let root_key: Vec<u8> = json["token"]["root_public_key"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| u8::try_from(b.as_u64().unwrap()).unwrap())
        .collect();
    let out = nucleus()
        .args(["run", "--grant"])
        .arg(&grant)
        .args(["--dry-run", "--local", "--grant-signer"])
        .arg(hex::encode(root_key))
        .arg("--grant-key")
        .arg(&mine)
        .arg("-d")
        .arg(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_grant_is_bound_to_the_repository_it_was_approved_in() {
    let dir = repo();
    let key = dir.path().join("grant-signer.pem");
    let grant = dir.path().join("tests.grant");
    seal(dir.path(), &key, &grant);

    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("package.json"), "{}").unwrap();
    let out = run_grant(other.path(), &key, &grant);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("repository changed"), "{stderr}");
}

#[test]
fn save_grant_needs_an_accepted_grant_not_a_dry_run() {
    let dir = repo();
    let out = nucleus()
        .args([
            "run",
            "--goal",
            "run the tests",
            "--dry-run",
            "--local",
            "--save-grant",
        ])
        .arg(dir.path().join("x.grant"))
        .arg("-d")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ACCEPTED"));
}
