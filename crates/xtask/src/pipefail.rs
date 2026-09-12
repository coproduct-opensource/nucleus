//! `cargo xtask pipefail` — a `run:` block that pipes without `pipefail` discards the exit
//! status of every command but the last.
//!
//! This is the repository's own first rule about reading CI, turned into a gate. `cmd | tail -n`
//! reports `tail`'s status; so does `cmd | tee log`, `cmd | grep -q x`, and
//! `X="$(find … | wc -l)"`. Under `set -e` the step then continues, and a command that failed
//! is indistinguishable from one that succeeded and printed nothing.
//!
//! # Why it is not already handled
//!
//! GitHub runs a `run:` block under **two different shells** depending on a key that is easy to
//! omit:
//!
//! ```text
//! run: |            →  bash -e {0}                           no pipefail
//! shell: bash       →  bash --noprofile --norc -eo pipefail {0}   pipefail
//! ```
//!
//! So `shell: bash` — which reads like a no-op restating the default — is the difference between
//! a pipeline whose failure is seen and one whose failure is not. Measured 2026-09-12: **none of
//! this repository's 73 workflows sets `defaults.run.shell`,** so every block that omits the key
//! runs without pipefail.
//!
//! # What this counts, and what it does not claim
//!
//! A pipeline in a block with neither `shell: bash` nor `set -o pipefail`. That is a *candidate*,
//! not a defect: `ls | tr '\n' ','` inside an echo cannot fail in a way anyone cares about, and
//! `FILES=$(find … | wc -l)` followed by a floor check is already defended. **Calling the count
//! a defect count would be the error this gate exists to refuse** — so it is a shrink-only
//! ratchet over candidates. Growth is a decision; each site is examined once and either fixed or
//! left with the population pinned one lower.
//!
//! Two parse traps are handled because both are live in this tree:
//!
//! * `case "$X" in a|b) … ;;` uses `|` for ALTERNATION. Counting those found 63 sites where
//!   there are 44; `ci.yml`'s relay jobs are nothing but case arms.
//! * `||` is not a pipe, and neither is `|&`.
//!
//! # What decides this
//!
//! Workflow YAML and nothing else. No toolchain, no network, no source tree — gatehouse
//! `docs/tiering.md` calls this the cheapest shape there is.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The pin on how many unguarded pipeline sites this repository still carries. Shrink-only.
const PIN: &str = "ci/pipefail-unguarded.txt";

/// Measured 2026-09-12: 262 `run:` blocks across workflows and composite actions. A scan that
/// finds far fewer has stopped reading the tree, and every verdict would then be about nothing.
const MIN_BLOCKS: usize = 200;

/// One `run:` block, with what decides whether its pipelines are guarded.
#[derive(Debug)]
pub struct Block {
    pub file: String,
    pub line: usize,
    pub body: String,
    /// The step's `shell:` value, when it has one.
    pub shell: Option<String>,
}

impl Block {
    /// `shell: bash` gets `-eo pipefail`; an explicit `set -o pipefail` does it by hand.
    pub fn guarded(&self) -> bool {
        self.shell.as_deref().is_some_and(|s| s.contains("bash")) || self.body.contains("pipefail")
    }

    /// The lines of this block that are a real pipeline.
    pub fn pipelines(&self) -> Vec<String> {
        self.body
            .lines()
            .filter(|l| is_pipeline(l))
            .map(str::to_string)
            .collect()
    }
}

/// Does this line pipe? `||` is not a pipe, `|&` is not one here, and a `case` arm's `|` is
/// alternation.
pub fn is_pipeline(line: &str) -> bool {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') {
        return false;
    }
    // `case X in`, and an arm `pat) … ;;` — both spell alternation with `|`.
    if s.starts_with("case ")
        || s.ends_with(" in")
        || (s.contains(')') && s.trim_end().ends_with(";;"))
    {
        return false;
    }
    let stripped = s.replace("||", "").replace("|&", "");
    stripped.contains('|')
}

fn yaml_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [".github/workflows", ".github/actions"] {
        collect(&root.join(dir), &mut out);
    }
    out.sort();
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            out.push(p);
        }
    }
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Every `run: |` block, with the `shell:` of the step that owns it.
///
/// `shell:` is a SIBLING of `run:`, and may come before or after it, so both directions are
/// searched at the key's own indent. Looking only forward misses every step that declares the
/// shell first, which is how most of them are written.
pub fn blocks(root: &Path) -> Result<Vec<Block>> {
    let mut out = Vec::new();
    for path in yaml_files(root) {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&path).with_context(|| format!("reading {rel}"))?;
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0usize;
        while i < lines.len() {
            let t = lines[i].trim_start();
            if !(t.starts_with("run: |") || t.starts_with("run: >")) {
                i += 1;
                continue;
            }
            let ind = indent(lines[i]);
            let mut body = Vec::new();
            let mut j = i + 1;
            while j < lines.len() {
                let b = lines[j];
                if b.trim().is_empty() || indent(b) > ind {
                    body.push(b);
                    j += 1;
                } else {
                    break;
                }
            }
            let mut shell = None;
            // Backwards to the start of this step, then forwards to its end.
            for k in (0..i).rev() {
                let bt = lines[k].trim_start();
                if indent(lines[k]) == ind && bt.starts_with("shell:") {
                    shell = Some(bt.to_string());
                    break;
                }
                if lines[k].trim().is_empty() {
                    continue;
                }
                if indent(lines[k]) < ind || bt.starts_with("- ") {
                    break;
                }
            }
            if shell.is_none() {
                for l in lines.iter().skip(j) {
                    let bt = l.trim_start();
                    if l.trim().is_empty() {
                        continue;
                    }
                    if indent(l) < ind || bt.starts_with("- ") {
                        break;
                    }
                    if indent(l) == ind && bt.starts_with("shell:") {
                        shell = Some(bt.to_string());
                        break;
                    }
                }
            }
            out.push(Block {
                file: rel.clone(),
                line: i + 1,
                body: body.join("\n"),
                shell,
            });
            i = j;
        }
    }
    Ok(out)
}

fn pin(root: &Path) -> Result<usize> {
    let text = fs::read_to_string(root.join(PIN))
        .with_context(|| format!("{PIN} is missing — nothing pins the population"))?;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some(v) = t.strip_prefix("UNGUARDED=") else {
            bail!("{PIN}: not `UNGUARDED=<n>`: {t}");
        };
        return v
            .trim()
            .parse()
            .with_context(|| format!("{PIN}: {t} is not a number"));
    }
    bail!("{PIN}: no `UNGUARDED=` line")
}

pub fn check(root: &Path) -> Result<()> {
    let blocks = blocks(root)?;
    if blocks.len() < MIN_BLOCKS {
        bail!(
            "found {} `run:` block(s), floor {MIN_BLOCKS} — the scan is wrong, so a clean verdict \
             here would be about nothing",
            blocks.len()
        );
    }

    let mut unguarded: Vec<&Block> = Vec::new();
    let mut piped = 0usize;
    for b in &blocks {
        if b.pipelines().is_empty() {
            continue;
        }
        piped += 1;
        if !b.guarded() {
            unguarded.push(b);
        }
    }

    // Non-vacuity the other way: if NOTHING pipes, the pipeline detector is broken and every
    // block passes by not being looked at.
    if piped == 0 {
        bail!(
            "{} `run:` block(s) and not one pipeline — the detector matched nothing, so the pin \
             below is a pin on zero",
            blocks.len()
        );
    }

    let pinned = pin(root)?;
    println!(
        "{} `run:` block(s), {piped} containing a pipeline, {} of those unguarded (pin {pinned})",
        blocks.len(),
        unguarded.len()
    );

    if unguarded.len() > pinned {
        println!("  the sites past the pin, and every site for context:");
        for b in &unguarded {
            println!(
                "    {}:{}  {}",
                b.file,
                b.line,
                b.pipelines()
                    .first()
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default()
            );
        }
        bail!(
            "{} unguarded pipeline site(s), pin {pinned} — a `run:` block without `shell: bash` \
             runs as `bash -e {{0}}`, no pipefail, so every command but the last in a pipeline can \
             fail unseen. Add `shell: bash` to the step, or `set -o pipefail` to the block. The \
             pin may only SHRINK: raising it blesses a site where an exit status is discarded.",
            unguarded.len()
        );
    }
    if unguarded.len() < pinned {
        bail!(
            "{} unguarded site(s) but the pin is {pinned} — lower it in the same change that fixed \
             one, or the ratchet stops ratcheting",
            unguarded.len()
        );
    }
    println!("ok: the unguarded population is exactly its pin");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `case "$JOB" in skipped) exit 0;; success) ;; *) … ;; esac` — nucleus's relay jobs are
    /// nothing but these, and counting their `|` as pipes put 19 phantom sites in the census.
    #[test]
    fn a_case_arm_is_alternation_not_a_pipe() {
        assert!(!is_pipeline(
            r#"case "$STEP:$STEP2" in success:success|success:skipped|skipped:success) exit 0;; *) exit 1;; esac"#
        ));
        assert!(!is_pipeline(r#"case "$JOB" in"#));
    }

    #[test]
    fn or_else_is_not_a_pipe() {
        assert!(!is_pipeline("cargo build || exit 1"));
        assert!(!is_pipeline("  grep -q x foo || echo no"));
    }

    #[test]
    fn a_real_pipeline_is_one() {
        assert!(is_pipeline("cargo test 2>&1 | tee /tmp/out.txt"));
        assert!(is_pipeline(r#"FILES=$(find . -name '*.rs' | wc -l)"#));
    }

    #[test]
    fn a_comment_mentioning_a_pipe_is_not_one() {
        assert!(!is_pipeline("# cmd | tail -n reports tail's status"));
    }

    /// `shell: bash` gets `-eo pipefail` from GitHub; an explicit `set -o pipefail` does it by
    /// hand. Either is a guard, and neither present is not.
    #[test]
    fn both_ways_of_guarding_count() {
        let mk = |shell: Option<&str>, body: &str| Block {
            file: "w.yml".into(),
            line: 1,
            body: body.into(),
            shell: shell.map(str::to_string),
        };
        assert!(mk(Some("shell: bash"), "a | b").guarded());
        assert!(mk(None, "set -o pipefail\na | b").guarded());
        assert!(mk(None, "set -eo pipefail\na | b").guarded());
        assert!(!mk(None, "a | b").guarded());
        // A non-bash shell does NOT get pipefail.
        assert!(!mk(Some("shell: python"), "a | b").guarded());
    }

    /// The shipped tree, read the way the gate reads it.
    #[test]
    fn the_scan_reaches_the_whole_workflow_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bs = blocks(&root).expect("the workflows parse");
        assert!(
            bs.len() >= MIN_BLOCKS,
            "found {} `run:` blocks, floor {MIN_BLOCKS}",
            bs.len()
        );
        assert!(
            bs.iter().any(|b| !b.pipelines().is_empty()),
            "not one pipeline found — the detector is broken"
        );
        // `shell:` is a SIBLING and may come BEFORE `run:`; a forward-only search finds none.
        assert!(
            bs.iter().any(|b| b.shell.is_some()),
            "no block found a `shell:` — the sibling search is looking the wrong way"
        );
    }
}
