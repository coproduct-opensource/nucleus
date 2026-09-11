//! `cargo xtask push-auth` — a workflow that pushes must carry its own credential.
//!
//! `actions/checkout` leaves a credential behind for later `git` commands. Since v7 it does
//! that **indirectly**: the token goes in a temp file and the repository config gains
//!
//! ```text
//! includeIf.gitdir:/home/runner/_work/<owner>/<repo>/.git.path = .../git-credentials-<uuid>.config
//! ```
//!
//! `includeIf.gitdir` matches on the **path the git directory is reached by**, and the two
//! spellings of one directory do not both match. Reproduced 2026-09-11: a pattern written
//! against a symlinked path applies when the repo is reached through the symlink and does
//! **not** apply when the same repo is reached by its real path.
//!
//! nucleus's self-hosted runners make exactly those two spellings. `ci/fly-runner/entrypoint.sh`
//! puts the workspace on the mounted volume:
//!
//! ```text
//! rm -rf /home/runner/_work
//! ln -s /data/work /home/runner/_work
//! ```
//!
//! so `/home/runner/_work/...` and `/data/work/...` are one directory under two names, the
//! credential is wired against the first, and a `git push` that resolves the second finds no
//! credential at all:
//!
//! ```text
//! fatal: could not read Username for 'https://github.com': No such device or address
//! ```
//!
//! Measured 2026-09-11: **34 consecutive failures** of `clippy-ratchet.yml` on `push` to main
//! since the last success at 2026-09-11T00:49:30Z — every run that had work to do. The job
//! measured the improvement it could not record: ceiling **345**, actual **338**. Runs on
//! `pull_request` and `merge_group` were all green throughout, because the pushing job is
//! `if:`-gated to `push` and was simply skipped. **A workflow can be green on every PR and
//! totally broken on main.**
//!
//! # The rule
//!
//! A `run:` step containing `git push` must authenticate explicitly — a remote URL carrying a
//! token, or an `http.extraheader` passed to git — rather than relying on the credential
//! `actions/checkout` happened to leave. Ambient credentials are a property of the runner's
//! filesystem layout; an explicit one is a property of the workflow.
//!
//! This is deliberately NOT restricted to jobs whose `runs-on` names the self-hosted pool.
//! `runs-on` here is `${{ vars.CI_BUILD_RUNNER || vars.CI_RUNNER || 'ubuntu-latest' }}` — a
//! repository *variable*, changeable in the GitHub UI with no commit. A gate whose verdict
//! depends on a value not in the tree would go quietly wrong the moment someone flipped it,
//! which is the failure this family exists to refuse. Every push is required to carry its own
//! credential, on every runner.
//!
//! # What decides this
//!
//! The committed workflow files. No source tree, no toolchain, no network.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

const DIR: &str = ".github/workflows";

/// Ways a step can carry its own credential. Any one of these on the same `run:` block as the
/// push is enough.
const AUTHENTICATED: [&str; 4] = [
    "x-access-token:",
    "http.extraheader",
    "@github.com/",
    "GIT_ASKPASS",
];

/// One `git push` and whether its `run:` block authenticates it.
#[derive(Debug, PartialEq, Eq)]
pub struct Push {
    pub line: usize,
    pub authenticated: bool,
}

/// Every `git push` in a `run:` block, with whether that block authenticates.
///
/// A `run:` block is the unit, not the whole file: a token set up in a different step does not
/// reach this one's git invocation, and a file-wide search would call a push safe because some
/// unrelated job mentioned a token.
pub fn pushes(workflow_src: &str) -> Vec<Push> {
    let lines: Vec<&str> = workflow_src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let t = line.trim_start();
        let t = t.strip_prefix("- ").unwrap_or(t);
        // `run: |`, `run: >`, or a one-liner.
        if !t.starts_with("run:") {
            i += 1;
            continue;
        }
        let run_indent = line.len() - line.trim_start().len();
        let mut block = vec![t.trim_start_matches("run:").to_string()];
        let start = i;
        let mut j = i + 1;
        while j < lines.len() {
            let l = lines[j];
            if l.trim().is_empty() {
                block.push(String::new());
                j += 1;
                continue;
            }
            if l.len() - l.trim_start().len() <= run_indent {
                break;
            }
            block.push(l.to_string());
            j += 1;
        }
        let text = block.join("\n");
        for (k, bl) in text.lines().enumerate() {
            // A comment explaining a push is not a push. This matters here: both offending
            // workflows carry long comments ABOUT pushing directly above the command.
            let code = bl.trim_start();
            if code.starts_with('#') {
                continue;
            }
            if !code.contains("git push") {
                continue;
            }
            out.push(Push {
                line: start + k + 1,
                authenticated: AUTHENTICATED.iter().any(|a| text.contains(a)),
            });
        }
        i = j;
    }
    out
}

pub fn check(root: &Path) -> Result<()> {
    let dir = root.join(DIR);
    let mut files: Vec<_> = fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "yml"))
        .collect();
    files.sort();
    if files.is_empty() {
        bail!("{DIR}: no workflows found — a sweep that reads nothing passes everything");
    }

    let mut total = 0usize;
    let mut bad = Vec::new();
    for f in &files {
        let src = fs::read_to_string(f)?;
        let rel = format!("{DIR}/{}", f.file_name().unwrap().to_string_lossy());
        for p in pushes(&src) {
            total += 1;
            if p.authenticated {
                println!("  ok   {rel}:{} authenticates its push", p.line);
            } else {
                bad.push(format!("{rel}:{}", p.line));
            }
        }
    }

    // Non-vacuity: this repo pushes from CI, and a parser that stopped seeing any push would
    // report a clean sweep. The floor is 1 rather than the current count, per the asymmetry
    // gatehouse F-47 records — a floor at its exact value turns "find the pushes" into
    // "lower the floor".
    if total == 0 {
        bail!(
            "found no `git push` in any workflow. This repository pushes from CI (the clippy \
             ratchet and the aeneas extraction both do), so the parser has stopped seeing them."
        );
    }

    if !bad.is_empty() {
        bail!(
            "{} `git push` step(s) rely on the credential `actions/checkout` left behind:\n  {}\n\
             That credential is wired with `includeIf.gitdir`, which matches on the PATH the git \
             directory is reached by. `ci/fly-runner/entrypoint.sh` symlinks the workspace onto \
             the mounted volume, so the same directory has two names and the push can resolve the \
             one the credential was not written for:\n\
             \x20 fatal: could not read Username for 'https://github.com'\n\
             Give the push its own credential — a remote URL carrying the token, or \
             `http.extraheader` — so it does not depend on the runner's filesystem layout.",
            bad.len(),
            bad.join("\n  ")
        );
    }
    println!("ok: all {total} `git push` step(s) carry their own credential");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unauthenticated_push_is_found() {
        let wf = "jobs:\n  j:\n    steps:\n      - name: x\n        run: |\n          git push -f -u origin \"$BRANCH\"\n";
        let p = pushes(wf);
        assert_eq!(p.len(), 1);
        assert!(!p[0].authenticated);
    }

    #[test]
    fn a_token_url_in_the_same_block_counts() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: |\n          git remote set-url origin \"https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git\"\n          git push -f -u origin \"$BRANCH\"\n";
        let p = pushes(wf);
        assert_eq!(p.len(), 1);
        assert!(p[0].authenticated);
    }

    /// A token set up in a DIFFERENT step does not reach this one's git.
    #[test]
    fn a_token_in_another_step_does_not_count() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: echo https://x-access-token:abc@github.com/o/r.git\n      - run: git push origin HEAD\n";
        let p = pushes(wf);
        assert_eq!(p.len(), 1);
        assert!(!p[0].authenticated, "credentials do not cross steps");
    }

    /// Both offending workflows carry prose about pushing directly above the command.
    #[test]
    fn a_comment_about_pushing_is_not_a_push() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: |\n          # git push here is rejected by branch protection\n          echo hi\n";
        assert!(pushes(wf).is_empty());
    }

    #[test]
    fn the_real_workflows_contain_pushes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut n = 0;
        for e in fs::read_dir(root.join(DIR)).unwrap().flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "yml") {
                n += pushes(&fs::read_to_string(&p).unwrap()).len();
            }
        }
        assert!(n > 0, "the shipped workflows push from CI");
    }
}
