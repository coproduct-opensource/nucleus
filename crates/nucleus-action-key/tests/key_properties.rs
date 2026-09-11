//! The three properties that decide whether a receipt keyed on this is sound.
//!
//! 1. A file **inside** the declared read-set moves the key.
//! 2. A file **outside** it does not — that is the whole point; without it
//!    every new tree is a cold cache, which is the state gatehouse's
//!    `docs/hard-cut.md` §6 records for its own receipts.
//! 3. **The gate's own code moves the key.** Without this a gate that was
//!    *weakened* keeps answering green out of its stronger self's history,
//!    which is the one failure that makes a receipt store worse than no cache.
//!
//! Each runs against a real git repository in a tempdir, because the read-set
//! is enumerated with `git ls-files` and a fixture that stubbed that out would
//! be testing a different function.

use nucleus_action_key::derive;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The merge-queue constants `ci-spec`'s model requires. Values are irrelevant
/// here — this crate never reads them — but the struct has no defaults, and a
/// model that will not build is a "could not look", not a fixture.
const QUEUE_FIXTURE: &str = "\
ruleset_id = 1
check_response_timeout_minutes = 360
max_entries_to_build = 1
max_entries_to_merge = 1
min_entries_to_merge = 1
min_entries_to_merge_wait_minutes = 1
grouping_strategy = \"ALLGREEN\"
merge_method = \"SQUASH\"
strict = true
";

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

/// A minimal repository with one required context, produced by one job whose
/// workflow declares `src/**` as its read-set.
fn fixture() -> PathBuf {
    // Named by pid and a counter rather than the clock: #2825 was a flake
    // caused by nine tests sharing a wall-clock-nanos tempdir name.
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "nucleus-action-key-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    git(&root, &["init", "-q"]);
    write(
        &root,
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"1.95\"\n",
    );
    write(&root, "src/lib.rs", "fn a() {}\n");
    write(&root, "docs/readme.md", "unrelated\n");
    write(
        &root,
        ".github/workflows/gate.yml",
        r#"name: Gate
on:
  pull_request:
    paths:
      - "src/**"
      - ".github/workflows/gate.yml"
  merge_group:
jobs:
  gate:
    name: The Gate
    runs-on: ubuntu-latest
    steps:
      - run: scripts/check-thing.sh
"#,
    );
    write(&root, "scripts/check-thing.sh", "#!/bin/sh\nexit 0\n");
    git(&root, &["add", "-A"]);
    root
}

fn key_of(root: &Path) -> String {
    // `from_parts` rather than `from_repo`: the ledger, queue, inline-gate and
    // allowlist files are `ci-spec`'s subject, not this crate's, and a fixture
    // that had to carry all of them would be testing the loader.
    let wf = (
        ".github/workflows/gate.yml".to_string(),
        std::fs::read_to_string(root.join(".github/workflows/gate.yml")).unwrap(),
    );
    let model = ci_spec::loader::from_parts(
        std::slice::from_ref(&wf),
        "# PINNED = 1\nThe Gate\n",
        QUEUE_FIXTURE,
        "",
        "",
        vec!["scripts/check-thing.sh".to_string()],
    )
    .expect("model");
    derive::key_for(root, &model, "The Gate")
        .expect("could look")
        .expect("has a key")
        .to_hex()
}

#[test]
fn a_file_inside_the_read_set_moves_the_key() {
    let root = fixture();
    let before = key_of(&root);
    write(&root, "src/lib.rs", "fn a() { let _ = 1; }\n");
    git(&root, &["add", "-A"]);
    assert_ne!(before, key_of(&root));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_file_outside_the_read_set_does_not_move_the_key() {
    let root = fixture();
    let before = key_of(&root);
    write(&root, "docs/readme.md", "still unrelated, but different\n");
    git(&root, &["add", "-A"]);
    assert_eq!(
        before,
        key_of(&root),
        "a change outside the declared read-set moved the key; every tree would be a cold cache"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A file ADDED outside the read-set must not move it either. This is the one
/// a `paths-ignore:`-only filter cannot give you, and why `Refusal::IgnoreOnly`
/// exists.
#[test]
fn a_file_added_outside_the_read_set_does_not_move_the_key() {
    let root = fixture();
    let before = key_of(&root);
    write(&root, "docs/another.md", "new file\n");
    git(&root, &["add", "-A"]);
    assert_eq!(before, key_of(&root));
    let _ = std::fs::remove_dir_all(&root);
}

/// **The one that catches a weakened gate.** The script the workflow runs is
/// the gate; change it with every declared input untouched, and the key must
/// move — or the receipt from the stronger version keeps answering.
#[test]
fn changing_the_gate_script_moves_the_key_with_no_input_changed() {
    let root = fixture();
    let before = key_of(&root);
    write(
        &root,
        "scripts/check-thing.sh",
        "#!/bin/sh\n# gate weakened\nexit 0\n",
    );
    git(&root, &["add", "-A"]);
    assert_ne!(
        before,
        key_of(&root),
        "the gate's own code is not in the key: a weakened gate answers green from its stronger \
         self's history"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The toolchain is part of the gate. The same `cargo clippy` under two
/// compilers is two gates, and a receipt that does not say which is a receipt
/// about nothing in particular.
#[test]
fn changing_the_toolchain_moves_the_key() {
    let root = fixture();
    let before = key_of(&root);
    write(
        &root,
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"1.96\"\n",
    );
    git(&root, &["add", "-A"]);
    assert_ne!(before, key_of(&root));
    let _ = std::fs::remove_dir_all(&root);
}

/// Untracked files must not enter the key: a build artefact that happened to
/// match the filter would make the key depend on the machine.
#[test]
fn an_untracked_file_in_the_read_set_does_not_move_the_key() {
    let root = fixture();
    let before = key_of(&root);
    write(&root, "src/scratch.rs", "// not added to git\n");
    assert_eq!(before, key_of(&root));
    let _ = std::fs::remove_dir_all(&root);
}
