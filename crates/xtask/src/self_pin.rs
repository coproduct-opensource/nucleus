//! `cargo xtask self-pin` — when the repo pins a SHA of itself, that SHA must still be us.
//!
//! `.github/workflows/scan.yml` runs the repository's own composite action by full SHA:
//!
//! ```yaml
//! uses: coproduct-opensource/nucleus/scan@a8ae0edb20d9182718632606cf0c83f5d881450a
//! ```
//!
//! Pinning by SHA is right — it is what every other `uses:` here does, and what Scorecard
//! asks for. But a pin to *someone else's* repo and a pin to *your own* differ in one way
//! that matters: the working tree also contains that action, and the two can drift. When
//! they do, the integration test exercises a copy of the action that nobody ships, and
//! passes. The gate goes on being green while testing the past.
//!
//! Today the pinned tree and `scan/` agree. The pin is **404 commits and six weeks** old,
//! and nothing noticed either fact. That is the same shape as every other pin this repo
//! gates: one thing written twice, agreeing now, with nothing keeping it that way.
//!
//! # What decides this
//!
//! Git objects already in the repository, and the workflow file. No network when the
//! commit is present, no toolchain, no source build. A commit that is genuinely absent
//! (a shallow clone) is reported as **could not look**, never as a pass — the distinction
//! `scripts/check-ci-spec.sh` also makes, "exit 0 clean, 1 a violation, 2 could not look —
//! the third is never a pass."

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

const OWNER_REPO: &str = "coproduct-opensource/nucleus";

/// What the check concluded. `CouldNotLook` is NOT a pass and NOT a violation: the third
/// state `scripts/check-ci-spec.sh` insists on ("exit 0 clean, 1 a violation, 2 could not
/// look — the third is never a pass"). It is returned rather than exited on, because
/// `check` is called from a unit test and a library function that kills the process kills
/// the test harness with it — which is exactly how this gate first broke CI.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every self-pin matches the tree.
    Clean,
    /// A pinned commit is genuinely unavailable, even after a targeted fetch.
    CouldNotLook,
}

/// One `uses: <owner>/<repo>/<subdir>@<sha>` naming this very repository.
#[derive(Debug, PartialEq, Eq)]
pub struct SelfPin {
    pub workflow: String,
    pub subdir: String,
    pub sha: String,
}

pub fn find(workflows: &[(String, String)]) -> Vec<SelfPin> {
    let needle = format!("{OWNER_REPO}/");
    let mut out = Vec::new();
    for (name, text) in workflows {
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with('#') {
                continue;
            }
            let Some(i) = t.find("uses:") else { continue };
            let rest = t[i + 5..].trim();
            let Some(rest) = rest.strip_prefix(&needle) else {
                continue;
            };
            let Some((subdir, sha)) = rest.split_once('@') else {
                continue;
            };
            let sha = sha.split_whitespace().next().unwrap_or(sha);
            if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.push(SelfPin {
                    workflow: name.clone(),
                    subdir: subdir.to_string(),
                    sha: sha.to_string(),
                });
            }
        }
    }
    out
}

fn git(root: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .with_context(|| format!("git {}", args.join(" ")))
}

pub fn check(root: &Path) -> Result<Outcome> {
    let dir = root.join(".github/workflows");
    let mut workflows: Vec<(String, String)> = Vec::new();
    for e in std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            let name = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .to_string();
            workflows.push((name, std::fs::read_to_string(&p)?));
        }
    }
    workflows.sort();

    let pins = find(&workflows);
    if pins.is_empty() {
        // Not a pass. If the `uses:` line is reworded or the action moves, this gate would
        // go quiet exactly when it stopped watching anything.
        bail!(
            "no `uses: {OWNER_REPO}/<dir>@<sha>` found in .github/workflows. Either the \
             self-pin was removed — in which case delete this gate — or its shape changed \
             and the gate is now watching nothing."
        );
    }

    let mut drifted = 0usize;
    for pin in &pins {
        let mut present = git(
            root,
            &["cat-file", "-e", &format!("{}^{{commit}}", pin.sha)],
        )?
        .status
        .success();
        if !present {
            // CI checks out shallow on purpose -- #2748 removed 3.3 GiB of dead history
            // fetching -- so the pinned commit is normally absent. Deepening the whole
            // clone to read one blob would hand that win straight back, so fetch exactly
            // the one commit instead: depth 1 on a single sha is a few KB.
            let _ = git(root, &["fetch", "--depth", "1", "origin", &pin.sha]);
            present = git(
                root,
                &["cat-file", "-e", &format!("{}^{{commit}}", pin.sha)],
            )?
            .status
            .success();
        }
        if !present {
            // Exit 2 semantics: could not look is never a pass.
            eprintln!(
                "could not look: {} pins {} at {}, which is not in this clone.\n\
                 A targeted `git fetch --depth 1 origin {}` did not produce it either; a missing commit \
                 is not agreement.",
                pin.workflow, pin.subdir, pin.sha, pin.sha
            );
            return Ok(Outcome::CouldNotLook);
        }
        let out = git(
            root,
            &["diff", "--name-only", &pin.sha, "HEAD", "--", &pin.subdir],
        )?;
        let changed = String::from_utf8_lossy(&out.stdout);
        let changed: Vec<&str> = changed.lines().filter(|l| !l.is_empty()).collect();
        if changed.is_empty() {
            let behind = git(
                root,
                &["rev-list", "--count", &format!("{}..HEAD", pin.sha)],
            )?;
            let behind = String::from_utf8_lossy(&behind.stdout).trim().to_string();
            println!(
                "ok: {} pins {}/ at {} — identical to HEAD ({behind} commits back)",
                pin.workflow,
                pin.subdir,
                &pin.sha[..12]
            );
        } else {
            drifted += 1;
            eprintln!(
                "DRIFT: {} runs {}/ from {}, which differs from HEAD:",
                pin.workflow,
                pin.subdir,
                &pin.sha[..12]
            );
            for f in changed {
                eprintln!("    {f}");
            }
            eprintln!(
                "  The integration test is exercising a copy of the action that is not the \
                 one this repo ships, and passing. Re-pin to a commit whose {}/ matches, or \
                 revert the change.",
                pin.subdir
            );
        }
    }

    if drifted > 0 {
        bail!("{drifted} self-pinned action(s) differ from the working tree");
    }
    Ok(Outcome::Clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_self_pin_matches_or_says_it_cannot_look() {
        // Must not assert Clean: on a shallow clone with no network the honest answer is
        // CouldNotLook. What it must never do is report drift, and it must never kill the
        // test binary -- an earlier version called `std::process::exit(2)` here, which
        // took the whole xtask test harness down with it in CI.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        match check(&root) {
            Ok(Outcome::Clean | Outcome::CouldNotLook) => {}
            Err(e) => panic!("the self-pin drifted from HEAD: {e}"),
        }
    }

    #[test]
    fn parses_a_self_pin() {
        let w = vec![(
            "w.yml".to_string(),
            format!("        uses: {OWNER_REPO}/scan@{}\n", "a".repeat(40)),
        )];
        let p = find(&w);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].subdir, "scan");
    }

    #[test]
    fn a_tag_is_not_a_pin() {
        let w = vec![("w.yml".to_string(), format!("uses: {OWNER_REPO}/scan@v1\n"))];
        assert!(find(&w).is_empty(), "only a 40-char sha counts as pinned");
    }

    #[test]
    fn a_third_party_action_is_not_a_self_pin() {
        let w = vec![(
            "w.yml".to_string(),
            format!("uses: actions/checkout@{}\n", "b".repeat(40)),
        )];
        assert!(find(&w).is_empty());
    }

    #[test]
    fn a_commented_out_pin_is_not_a_pin() {
        let w = vec![(
            "w.yml".to_string(),
            format!("# uses: {OWNER_REPO}/scan@{}\n", "c".repeat(40)),
        )];
        assert!(find(&w).is_empty());
    }
}
