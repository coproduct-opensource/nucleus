//! The property that makes a closure key sound, and the one that makes it worth
//! having.
//!
//! **Sound:** a change anywhere in a crate's closure moves its key. If it did
//! not, a receipt would be reused for a crate whose dependency changed
//! underneath it — a green check for work nobody did on the code in question,
//! which is the one failure that makes a receipt store worse than no cache.
//!
//! **Worth having:** a change OUTSIDE the closure does not move it. Without
//! that, every merge-group entry is a cold cache and the whole design buys
//! nothing — which is the state gatehouse's `docs/hard-cut.md` §6 records for
//! its own receipts today.
//!
//! Both run against a real cargo workspace in a tempdir. A fixture that stubbed
//! `cargo metadata` would be testing a different function: the graph is exactly
//! the thing being trusted here.

use nucleus_action_key::{closure, derive};
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(dir: &Path, prog: &str, args: &[&str]) {
    let out = Command::new(prog)
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .expect("spawns");
    assert!(
        out.status.success(),
        "{prog} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().expect("has a parent")).expect("mkdir");
    std::fs::write(p, body).expect("write");
}

/// Three crates: `leaf`, `mid` (depends on leaf), `far` (depends on neither).
/// The shape that distinguishes "in the closure" from "in the workspace".
fn fixture() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "nucleus-closure-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("mkdir");

    write(
        &root,
        "Cargo.toml",
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/leaf\", \"crates/mid\", \"crates/far\"]\n",
    );
    for (name, dep) in [("leaf", None), ("mid", Some("leaf")), ("far", None)] {
        let d = dep.map_or(String::new(), |d| {
            format!("\n[dependencies]\n{d} = {{ path = \"../{d}\" }}\n")
        });
        write(
            &root,
            &format!("crates/{name}/Cargo.toml"),
            &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{d}"),
        );
        write(
            &root,
            &format!("crates/{name}/src/lib.rs"),
            "pub fn f() {}\n",
        );
    }
    write(
        &root,
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"stable\"\n",
    );
    write(&root, "docs/unrelated.md", "not a crate\n");

    run(&root, "git", &["init", "-q", "-b", "main"]);
    run(&root, "cargo", &["generate-lockfile", "--offline"]);
    run(&root, "git", &["add", "-A"]);
    root
}

fn key(root: &Path, name: &str) -> String {
    let ws = closure::load(root).expect("metadata");
    let tracked = derive::tracked_files(root).expect("git ls-files");
    closure::key_for_crate(&ws, root, &tracked, name, "clippy", &[])
        .expect("key")
        .to_hex()
}

#[test]
fn the_closure_is_the_crate_and_what_it_depends_on() {
    let root = fixture();
    let ws = closure::load(&root).expect("metadata");
    let c = |n: &str| {
        let mut v: Vec<String> = ws.closures.get(n).expect("crate").iter().cloned().collect();
        v.sort();
        v
    };
    assert_eq!(c("leaf"), vec!["leaf"]);
    assert_eq!(c("mid"), vec!["leaf", "mid"]);
    assert_eq!(c("far"), vec!["far"]);
    let _ = std::fs::remove_dir_all(&root);
}

/// **Sound.** A dependency changing must move the dependent's key, or a receipt
/// outlives the code it was about.
#[test]
fn a_change_to_a_dependency_moves_the_dependents_key() {
    let root = fixture();
    let before = key(&root, "mid");
    write(
        &root,
        "crates/leaf/src/lib.rs",
        "pub fn f() { let _ = 1; }\n",
    );
    run(&root, "git", &["add", "-A"]);
    assert_ne!(
        before,
        key(&root, "mid"),
        "leaf changed and mid's key did not move: mid would reuse a receipt taken before its \
         dependency changed"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// **Worth having.** A crate outside the closure must NOT move it — this is the
/// entire payoff, and without it every merge-group entry is a cold cache.
#[test]
fn a_change_to_an_unrelated_crate_does_not_move_the_key() {
    let root = fixture();
    let before = key(&root, "mid");
    write(
        &root,
        "crates/far/src/lib.rs",
        "pub fn f() { let _ = 2; }\n",
    );
    run(&root, "git", &["add", "-A"]);
    assert_eq!(
        before,
        key(&root, "mid"),
        "an unrelated crate moved mid's key"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A non-crate file — a workflow, a doc, a script — must not move any key.
/// This is the 33%: a third of merges to main touch nothing else.
#[test]
fn a_change_outside_every_crate_moves_no_key() {
    let root = fixture();
    let before: Vec<String> = ["leaf", "mid", "far"]
        .iter()
        .map(|n| key(&root, n))
        .collect();
    write(
        &root,
        "docs/unrelated.md",
        "still not a crate, but different\n",
    );
    write(&root, ".github/workflows/ci.yml", "name: CI\n");
    run(&root, "git", &["add", "-A"]);
    let after: Vec<String> = ["leaf", "mid", "far"]
        .iter()
        .map(|n| key(&root, n))
        .collect();
    assert_eq!(before, after, "a CI-only change invalidated a crate key");
    let _ = std::fs::remove_dir_all(&root);
}

/// The direction that must NOT hold: a dependent changing must not move its
/// dependency's key. `leaf` does not read `mid`, so `leaf`'s receipt stands.
#[test]
fn a_change_to_a_dependent_does_not_move_the_dependencys_key() {
    let root = fixture();
    let before = key(&root, "leaf");
    write(
        &root,
        "crates/mid/src/lib.rs",
        "pub fn f() { let _ = 3; }\n",
    );
    run(&root, "git", &["add", "-A"]);
    assert_eq!(
        before,
        key(&root, "leaf"),
        "a dependent moved its dependency's key"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `Cargo.lock` and the toolchain are in EVERY closure: an external dependency
/// or a compiler moving changes what every crate compiles to. That is the 13%
/// of merges which legitimately invalidate everything.
///
/// Asserted as membership rather than by perturbing the lockfile, because
/// `cargo metadata` REWRITES `Cargo.lock` — a test that appended a comment
/// measured cargo normalising it away, not the key. The claim is that the file
/// is committed to; making cargo fight the fixture tests something else.
#[test]
fn every_closure_contains_the_lockfile_and_the_toolchain() {
    let root = fixture();
    let ws = closure::load(&root).expect("metadata");
    let tracked = derive::tracked_files(&root).expect("git ls-files");
    for name in ["leaf", "mid", "far"] {
        let paths: Vec<String> = ws
            .read_set(&root, &tracked, name)
            .expect("read set")
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(
            paths.contains(&"Cargo.lock".to_string()),
            "{name} omits Cargo.lock"
        );
        assert!(
            paths.contains(&"rust-toolchain.toml".to_string()),
            "{name} omits the toolchain"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The read-set must actually contain the closure's sources. The first version
/// of `from_metadata` produced read-sets of exactly two files for every crate —
/// a `strip_prefix` that failed on macOS's `/var` symlink and left the
/// directories absolute — and four of six tests still passed, because "nothing
/// changed" is the easy half of every property here.
#[test]
fn the_read_set_contains_the_closures_sources() {
    let root = fixture();
    let ws = closure::load(&root).expect("metadata");
    let tracked = derive::tracked_files(&root).expect("git ls-files");
    let paths: Vec<String> = ws
        .read_set(&root, &tracked, "mid")
        .expect("read set")
        .into_iter()
        .map(|e| e.path)
        .collect();
    assert!(
        paths.contains(&"crates/mid/src/lib.rs".to_string()),
        "{paths:?}"
    );
    assert!(
        paths.contains(&"crates/leaf/src/lib.rs".to_string()),
        "{paths:?}"
    );
    assert!(
        !paths.contains(&"crates/far/src/lib.rs".to_string()),
        "{paths:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
