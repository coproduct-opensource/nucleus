//! `cargo xtask lockfiles [--fix] [--root DIR]` — every tracked `Cargo.lock` agrees with its manifests.
//!
//! A `Cargo.lock` is derived from the manifests in its path closure. This repository keeps
//! twenty-one of them, one per workspace (the root, `sdks/verifier-js`, `sdks/verifier-py`, the
//! examples, the fuzz crates, the dylint tools), and a manifest change in a shared crate moves
//! the requirement for all of them at once. A bot that updates only the root lock leaves the
//! others stale, and the first thing to notice is a gate's `--locked` input preparation:
//!
//! ```text
//! nucleus #3574 (2026-11-23, 35 dependency bumps): all ten required gates failed, exit 65,
//!   preparation-refused:lockfile_needs_update:sdks/verifier-js/Cargo.lock
//! ```
//!
//! Ten red gates for one fact about the tree. Worse, main itself carried two stale locks
//! (`examples/a2a-server`, `crates/portcullis-python`) for weeks, because CI built those crates
//! without `--locked` and so silently re-resolved them on every run.
//!
//! # What decides this
//!
//! cargo, asked to resolve and not to build: `cargo metadata --locked` refuses a lock that would
//! need updating and runs no build script. A lock cargo could not look at (no network, an
//! unreadable manifest) is [`Lock::CouldNotLook`], never fresh — ADR 0007 A-2.
//!
//! `--fix` regenerates each stale lock with the same command minus `--locked` (cargo's minimal
//! update: it re-resolves only what the manifests no longer admit) and then asks again: a lock
//! that is still not fresh after its fix is a failure, not a pass.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// One lockfile's state. Three arms, no default (ADR 0007 A-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lock {
    /// cargo resolved the manifests to exactly this lock.
    Fresh,
    /// cargo would have to update the lock to resolve the manifests.
    Stale,
    /// cargo could not answer; the reason is its own first error line.
    CouldNotLook(String),
}

/// The marker cargo prints when `--locked` forbade an update it needed. Matched on the stderr of
/// a FAILED run only, so its absence there is a could-not-look, never a pass.
const LOCKED_REFUSAL: &str = "because --locked was passed";

/// Every tracked `Cargo.lock` under `root`, as paths relative to it.
pub fn lockfiles(root: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--", "*Cargo.lock", "Cargo.lock"])
        .output()
        .context("git ls-files")?;
    if !out.status.success() {
        bail!(
            "git ls-files: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut all: Vec<PathBuf> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(String::from_utf8_lossy(p).into_owned()))
        .filter(|p| !p.components().any(|c| c.as_os_str() == "target"))
        .collect();
    all.sort();
    all.dedup();
    if all.is_empty() {
        bail!(
            "no tracked Cargo.lock under {}: nothing was looked at",
            root.display()
        );
    }
    Ok(all)
}

fn metadata(dir: &Path, locked: bool) -> Result<std::process::Output> {
    let mut cmd = Command::new("cargo");
    cmd.arg("metadata");
    if locked {
        cmd.arg("--locked");
    }
    cmd.args(["--format-version", "1"])
        .current_dir(dir)
        .stdout(Stdio::null())
        .output()
        .with_context(|| format!("cargo metadata in {}", dir.display()))
}

/// Ask cargo whether the lock in `dir` is the resolution of its manifests.
pub fn probe(dir: &Path) -> Lock {
    match metadata(dir, true) {
        Err(e) => Lock::CouldNotLook(format!("{e:#}")),
        Ok(o) if o.status.success() => Lock::Fresh,
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains(LOCKED_REFUSAL) {
                Lock::Stale
            } else {
                let first = err
                    .lines()
                    .find(|l| l.starts_with("error"))
                    .unwrap_or("cargo failed with no error line");
                Lock::CouldNotLook(first.to_owned())
            }
        }
    }
}

/// Regenerate the lock in `dir` (cargo's minimal update), then require it fresh.
pub fn regenerate(dir: &Path) -> Result<()> {
    let o = metadata(dir, false)?;
    if !o.status.success() {
        bail!(
            "cargo could not regenerate {}: {}",
            dir.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    match probe(dir) {
        Lock::Fresh => Ok(()),
        other => bail!("{} is {other:?} after regenerating it", dir.display()),
    }
}

/// The verdict over every lockfile. Exit codes: 0 every lock fresh; 1 a lock is stale (or a fix
/// did not freshen it); 2 a lock could not be looked at.
pub fn run(root: &Path, fix: bool) -> Result<i32> {
    let mut stale = 0_usize;
    let mut blind = 0_usize;
    for lock in lockfiles(root)? {
        let dir = root.join(lock.parent().unwrap_or(Path::new("")));
        let state = probe(&dir);
        match &state {
            Lock::Fresh => println!("fresh  {}", lock.display()),
            Lock::Stale if fix => match regenerate(&dir) {
                Ok(()) => println!("FIXED  {}", lock.display()),
                Err(e) => {
                    println!("STALE  {} (fix failed: {e:#})", lock.display());
                    stale += 1;
                }
            },
            Lock::Stale => {
                println!(
                    "STALE  {} (run `cargo xtask lockfiles --fix`)",
                    lock.display()
                );
                stale += 1;
            }
            Lock::CouldNotLook(why) => {
                println!("BLIND  {}: {why}", lock.display());
                blind += 1;
            }
        }
    }
    Ok(if blind > 0 {
        2
    } else if stale > 0 {
        1
    } else {
        0
    })
}

/// What `--push` did with the locks `--fix` regenerated. Three arms (ADR 0007 A-1): nothing to
/// push is not the same as having been unable to push.
#[derive(Debug, PartialEq, Eq)]
pub enum Pushed {
    /// No lockfile changed.
    Nothing,
    /// The regenerated locks were committed and pushed to the branch.
    Sent,
    /// They changed, and no credential that triggers CI was supplied: nothing was pushed.
    Withheld,
}

fn git_in(root: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .with_context(|| format!("git {}", args.first().unwrap_or(&"")))?;
    if !o.status.success() {
        bail!(
            "git {}: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Commit every lockfile `--fix` changed and push it to `branch`, with its own credential.
///
/// The credential is `LOCKFILES_TOKEN`, never the job's `GITHUB_TOKEN`: a commit pushed with
/// that one triggers no `pull_request` workflow, so the pull request would sit on a head no
/// required check ever ran on. Without the token this pushes nothing and says so -- the stale
/// lock still reds Manifest Guards, which is the change's own defect, not the world's.
pub fn push(root: &Path, branch: &str) -> Result<Pushed> {
    let changed = git_in(
        root,
        &["status", "--porcelain", "--", "*Cargo.lock", "Cargo.lock"],
    )?;
    if changed.trim().is_empty() {
        return Ok(Pushed::Nothing);
    }
    let token = std::env::var("LOCKFILES_TOKEN").unwrap_or_default();
    let repo = std::env::var("GITHUB_REPOSITORY").unwrap_or_default();
    if token.is_empty() || repo.is_empty() {
        return Ok(Pushed::Withheld);
    }
    git_in(root, &["add", "--", "*Cargo.lock", "Cargo.lock"])?;
    git_in(
        root,
        &[
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit",
            "-q",
            "-m",
            "Regenerate the lockfiles this change left behind (cargo xtask lockfiles --fix)",
        ],
    )?;
    let url = format!("https://x-access-token:{token}@github.com/{repo}.git");
    git_in(
        root,
        &["push", "-q", &url, &format!("HEAD:refs/heads/{branch}")],
    )?;
    Ok(Pushed::Sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-crate workspace with path dependencies only, so cargo needs no network.
    fn workspace(dir: &Path) {
        let w = |p: &str, b: &str| {
            let f = dir.join(p);
            std::fs::create_dir_all(f.parent().expect("parent")).expect("mkdir");
            std::fs::write(f, b).expect("write");
        };
        w(
            "Cargo.toml",
            "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"2\"\n",
        );
        w(
            "a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        w("a/src/lib.rs", "");
        w(
            "b/Cargo.toml",
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        w("b/src/lib.rs", "");
    }

    fn git(dir: &Path, args: &[&str]) {
        let o = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("git");
        assert!(
            o.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    /// Red first (A-19): a manifest gains a dependency the committed lock never resolved — the
    /// shape of #3574 — and the gate says STALE; `--fix` regenerates it and the gate says fresh.
    #[test]
    fn a_lock_left_behind_by_a_manifest_change_is_stale_and_fix_freshens_it() {
        let d = tempfile::tempdir().expect("tempdir");
        workspace(d.path());
        regenerate(d.path()).expect("initial lock");
        git(d.path(), &["init", "-q"]);
        git(d.path(), &["add", "-A"]);
        assert_eq!(run(d.path(), false).expect("run"), 0);

        let b = d.path().join("b/Cargo.toml");
        let mut m = std::fs::read_to_string(&b).expect("read");
        m.push_str("\n[dependencies]\na = { path = \"../a\" }\n");
        std::fs::write(&b, m).expect("write");
        assert_eq!(probe(d.path()), Lock::Stale);
        assert_eq!(run(d.path(), false).expect("run"), 1);

        assert_eq!(run(d.path(), true).expect("fix"), 0);
        assert_eq!(probe(d.path()), Lock::Fresh);
    }

    /// `--push` distinguishes "nothing to push" from "could not push": a fresh tree is Nothing,
    /// a regenerated lock without LOCKFILES_TOKEN is Withheld (never a push with a token whose
    /// commit no CI would run on). Assumes the test environment has no LOCKFILES_TOKEN.
    #[test]
    fn push_reports_nothing_on_fresh_locks_and_withholds_without_its_token() {
        if std::env::var_os("LOCKFILES_TOKEN").is_some() {
            return;
        }
        let d = tempfile::tempdir().expect("tempdir");
        workspace(d.path());
        regenerate(d.path()).expect("initial lock");
        git(d.path(), &["init", "-q"]);
        git(d.path(), &["add", "-A"]);
        git(
            d.path(),
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "-m",
                "base",
            ],
        );
        assert_eq!(push(d.path(), "x").expect("push"), Pushed::Nothing);

        let b = d.path().join("b/Cargo.toml");
        let mut m = std::fs::read_to_string(&b).expect("read");
        m.push_str("\n[dependencies]\na = { path = \"../a\" }\n");
        std::fs::write(&b, m).expect("write");
        assert_eq!(run(d.path(), true).expect("fix"), 0);
        assert_eq!(push(d.path(), "x").expect("push"), Pushed::Withheld);
    }

    /// Fail closed: a manifest cargo cannot read is BLIND (exit 2), never fresh.
    #[test]
    fn probe_an_unreadable_manifest_is_could_not_look() {
        let d = tempfile::tempdir().expect("tempdir");
        workspace(d.path());
        regenerate(d.path()).expect("initial lock");
        git(d.path(), &["init", "-q"]);
        git(d.path(), &["add", "-A"]);
        std::fs::write(d.path().join("a/Cargo.toml"), "[package\nname = ").expect("write");
        assert!(matches!(probe(d.path()), Lock::CouldNotLook(_)));
        assert_eq!(run(d.path(), false).expect("run"), 2);
    }

    /// No lockfile at all is not "all fresh": nothing was looked at.
    #[test]
    fn probe_a_tree_with_no_lockfile_is_an_error() {
        let d = tempfile::tempdir().expect("tempdir");
        git(d.path(), &["init", "-q"]);
        assert!(lockfiles(d.path()).is_err());
    }
}
