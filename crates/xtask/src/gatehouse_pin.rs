//! `cargo xtask gatehouse-pin` — every name nucleus gives gatehouse must resolve to the
//! same gatehouse.
//!
//! nucleus names gatehouse several times over, and the names have to agree:
//!
//! * `.gatehouse/pipeline.writ` imports the `ci` prelude **by digest**
//!   (`import "sha256:…" as ci`), which is what makes the plan hermetic;
//! * `.github/workflows/gatehouse-plan.yml` pins `GATEHOUSE_REF` to the gatehouse
//!   commit whose `gate` binary checks that plan;
//! * `.github/workflows/gatehouse-shadow.yml` pins its OWN `GATEHOUSE_REF`, and must
//!   name the same commit — a shadow built from a different gatehouse than the plan
//!   check is comparing two things that were never the same;
//! * every OTHER `GATEHOUSE_REF` under `.github/`, discovered rather than listed;
//! * and the gatehouse a step actually RUNS, which is not always one of the above.
//!
//! # The population is discovered, not listed
//!
//! This gate named its two workflows in a constant, so the rule it enforced was "these two
//! agree" and not "the pins agree". A third workflow pinning `GATEHOUSE_REF` would have been
//! outside the gate entirely, and the gate would have stayed green while saying something
//! narrower than its own message claims. That is the same defect as a `head -1`: a check whose
//! subject is the first N of something rather than all of it. The refs are now found by
//! walking `.github/`, so a new pin joins the population by existing.
//!
//! # A step can run a gatehouse no pin names
//!
//! `GATEHOUSE_REF` pins a gatehouse to BUILD. The action does not have to build one: with
//! `bin-dir` empty — its default — it downloads the release named by its own `version` input
//! (`v0.1.0`) from `binaries`, and that release is a fourth gatehouse that no pin in this
//! repository mentions. A step that omits `bin-dir` therefore runs a gatehouse chosen by an
//! action default while the workflow one line above it pins a commit, and both look pinned.
//!
//! So every step using the action must set `bin-dir`. This is not hypothetical prevention of
//! a defect that cannot happen: `bin-dir` is optional, its default is the download path, and
//! nucleus's one step sets it — which means the day a second step is written the easy way, the
//! shadow lane compares a gate built from `GATEHOUSE_REF` against one downloaded from `v0.1.0`
//! and reports agreement between them as a fact.
//!
//! The import digest must be the SHA-256 of `prelude/ci.writ` **at that ref**. The
//! workflow already says so in a comment — "its embedded prelude must match the import
//! hash in .gatehouse/pipeline.writ" — and nothing checked it, which is the difference
//! between a convention and a gate.
//!
//! # Why this exists
//!
//! Bumping one pin alone breaks the plan check, and the failure is remote and slow: the
//! job spends ~3 minutes building gatehouse before `gate` reports `no library for import`.
//! Worse, reading that message from the *wrong* side is how a working pin gets mistaken
//! for a stale one — a pin refusing a library the pinned build does not have is the pin
//! doing its job. That mistake was made against this exact pair (gatehouse `FINDINGS.md`
//! F-21) and produced a PR that moved one pin alone.
//!
//! # What decides this
//!
//! All three operands are declarations: a workflow `env` value, an import line, and a file
//! in a repository pinned by SHA. Nothing here reads nucleus's source tree, nothing needs a
//! toolchain, and the verdict is the same against an empty checkout of nucleus. See
//! gatehouse `docs/tiering.md` — this is the shape that gate is cheapest.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

const PIPELINE: &str = ".gatehouse/pipeline.writ";
/// Both workflows that build gatehouse pin the ref they build it at. The plan lane's
/// pin is the one the import digest must agree with; the shadow lane's is checked for
/// agreement with it, because a shadow running a DIFFERENT gatehouse than the plan
/// check is comparing two things that were never the same.
/// The plan lane. Its pin is the one the import digest must agree with; every other pin is
/// checked for agreement with it. This is the only workflow named here — the rest are found.
const WORKFLOW: &str = ".github/workflows/gatehouse-plan.yml";
/// Where pins and action users live. Walked, not listed.
const GITHUB_DIR: &str = ".github";
/// The action path as a workflow step spells it.
const ACTION_USES: &str = "./.github/actions/gatehouse";
const PRELUDE: &str = "prelude/ci.writ";

/// The `sha256:…` an `import` line names, as lowercase hex without the prefix.
pub fn imported_digest(pipeline_src: &str) -> Result<String> {
    for line in pipeline_src.lines() {
        let line = line.trim_start();
        if !line.starts_with("import ") {
            continue;
        }
        // `import "sha256:<64 hex>" as ci`
        let Some(open) = line.find('"') else { continue };
        let Some(close) = line[open + 1..].find('"') else {
            continue;
        };
        let quoted = &line[open + 1..open + 1 + close];
        let Some(hex) = quoted.strip_prefix("sha256:") else {
            bail!("{PIPELINE}: import {quoted:?} is not a sha256: digest");
        };
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{PIPELINE}: import digest {hex:?} is not 64 hex characters");
        }
        // The plan imports one library today. If it ever imports several this must name
        // WHICH, rather than silently checking the first — the `head -1` failure that
        // .line-ratchet.toml already paid for once.
        return Ok(hex.to_ascii_lowercase());
    }
    bail!("{PIPELINE}: no `import \"sha256:…\"` line")
}

/// `GATEHOUSE_REF` as the workflow declares it.
pub fn pinned_ref(workflow_src: &str) -> Result<String> {
    for line in workflow_src.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("GATEHOUSE_REF:") {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            if v.len() != 40 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("{WORKFLOW}: GATEHOUSE_REF {v:?} is not a 40-character commit sha");
            }
            return Ok(v.to_ascii_lowercase());
        }
    }
    bail!("{WORKFLOW}: no GATEHOUSE_REF")
}

/// Every file under `.github/` — workflows, composite actions, anything. A pin is a pin
/// wherever it is written, and the population this gate checks is the one that exists.
fn github_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join(GITHUB_DIR), &mut out);
    out
}

/// One `GATEHOUSE_REF: <sha>` as written somewhere under `.github/`.
#[derive(Debug, PartialEq, Eq)]
pub struct Pin {
    /// Repo-relative, so the message names a file a reader can open.
    pub file: String,
    pub line: usize,
    pub sha: String,
}

/// Find every pin. A `${{ env.GATEHOUSE_REF }}` USE is not a pin — only an assignment of a
/// literal is — so the scan takes lines whose key is `GATEHOUSE_REF` and whose value parses.
///
/// A malformed pin is an error rather than a skip. Skipping one would let `GATEHOUSE_REF: main`
/// leave the population silently, which is the shape of exemption this file exists to refuse.
pub fn pins(root: &Path) -> Result<Vec<Pin>> {
    let mut out = Vec::new();
    for path in github_files(root) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue; // a binary or unreadable file under .github/ carries no pin
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with('#') {
                continue;
            }
            let Some(v) = t.strip_prefix("GATEHOUSE_REF:") else {
                continue;
            };
            let sha = v.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
            if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!(
                    "{rel}:{}: GATEHOUSE_REF {sha:?} is not a 40-character commit sha. A branch \
                     name is not a pin: it names whatever that branch points at when the job \
                     runs, which is a different gatehouse on different days.",
                    i + 1
                );
            }
            out.push(Pin {
                file: rel.clone(),
                line: i + 1,
                sha,
            });
        }
    }
    Ok(out)
}

/// A step in some workflow that uses the gatehouse action, and whether it said which gatehouse
/// binaries to run.
#[derive(Debug, PartialEq, Eq)]
pub struct ActionStep {
    pub file: String,
    pub line: usize,
    pub bin_dir: Option<String>,
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Every `uses: ./.github/actions/gatehouse` step, with its `bin-dir` if it set one.
///
/// `with:` is a SIBLING of `uses:`, not a child, so the block this reads runs from the step's
/// list marker to the next line indented no deeper than the `uses` KEY. Reading it as a child
/// finds no inputs at all and calls every step compliant.
pub fn action_steps(text: &str, file: &str) -> Vec<ActionStep> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        let v = t
            .strip_prefix("- uses:")
            .or_else(|| t.strip_prefix("uses:"))
            .map(str::trim);
        if v != Some(ACTION_USES) {
            continue;
        }
        // The key's own indent, which for `- uses:` is past the list marker.
        let key_indent = indent(line) + if t.starts_with("- ") { 2 } else { 0 };
        let mut bin_dir = None;
        for l in &lines[i + 1..] {
            if l.trim().is_empty() {
                continue;
            }
            if indent(l) < key_indent {
                break;
            }
            if let Some(v) = l.trim_start().strip_prefix("bin-dir:") {
                bin_dir = Some(v.trim().trim_matches('"').to_string());
            }
        }
        out.push(ActionStep {
            file: file.to_string(),
            line: i + 1,
            bin_dir,
        });
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Check the pins. `gatehouse` is a checkout of `coproduct-private/gatehouse`; without one
/// only the two nucleus-side declarations can be read, which is reported rather than
/// treated as a pass.
pub fn check(root: &Path, gatehouse: Option<PathBuf>) -> Result<()> {
    let pipeline =
        fs::read_to_string(root.join(PIPELINE)).with_context(|| format!("reading {PIPELINE}"))?;
    let workflow =
        fs::read_to_string(root.join(WORKFLOW)).with_context(|| format!("reading {WORKFLOW}"))?;

    let want = imported_digest(&pipeline)?;
    let gh_ref = pinned_ref(&workflow)?;
    println!("{PIPELINE} imports sha256:{want}");
    println!("{WORKFLOW} pins    GATEHOUSE_REF {gh_ref}");

    // The rest of the population, FOUND. gatehouse-shadow.yml builds gatehouse too, at its
    // own GATEHOUSE_REF, and nothing said the two had to be the same commit. They were not:
    // the plan lane ran 4d42510 while the shadow lane ran 7326bfa9, a descendant — so the
    // shadow was comparing a gate built from one gatehouse against a plan checked by another,
    // and calling agreement between them meaningful. Naming those two files in a constant
    // fixed that instance and left the rule narrower than the message: the third pin to be
    // written would have sat outside the gate.
    let all = pins(root)?;
    if all.is_empty() {
        bail!(
            "no GATEHOUSE_REF found anywhere under {GITHUB_DIR}/. {WORKFLOW} was read and \
             parsed, so the walk is what came back empty — a population check over nothing \
             passes every time."
        );
    }
    let mut disagree: Vec<&Pin> = all.iter().filter(|p| p.sha != gh_ref).collect();
    disagree.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    if !disagree.is_empty() {
        let mut msg =
            format!("the pins name different gatehouses.\n\x20 {WORKFLOW} pins {gh_ref}, and:\n");
        for p in &disagree {
            msg.push_str(&format!("\x20 {}:{} pins {}\n", p.file, p.line, p.sha));
        }
        msg.push_str(
            "Each of these builds gatehouse at the commit it names. The shadow gate exists to \
             say whether gatehouse's verdict agrees with GitHub's; run against a different \
             gatehouse than the plan check, it answers a question nobody asked. If the skew is \
             deliberate, say so at every site; otherwise move them together.",
        );
        bail!("{msg}");
    }
    println!(
        "ok: {} GATEHOUSE_REF pin(s) under {GITHUB_DIR}/, all naming {gh_ref}",
        all.len()
    );

    // And the gatehouse a step RUNS, which is a separate fact from the one it builds. With
    // `bin-dir` empty the action downloads its own `version` default instead — a gatehouse no
    // pin here names, under a workflow that pins one two lines above.
    let mut unpinned: Vec<ActionStep> = Vec::new();
    let mut steps = 0usize;
    for path in github_files(root) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for st in action_steps(&text, &rel) {
            steps += 1;
            if st.bin_dir.as_deref().unwrap_or("").is_empty() {
                unpinned.push(st);
            }
        }
    }
    if !unpinned.is_empty() {
        let mut msg = String::from("a step runs a gatehouse no pin names.\n");
        for st in &unpinned {
            msg.push_str(&format!(
                "\x20 {}:{} uses {ACTION_USES} with no `bin-dir`\n",
                st.file, st.line
            ));
        }
        msg.push_str(&format!(
            "`bin-dir` is optional and its default is the DOWNLOAD path: with it empty the \
             action fetches the release its own `version` input names (see \
             {GITHUB_DIR}/actions/gatehouse/action.yml) rather than the commit this workflow \
             pins. Both look pinned and they are different gatehouses. Build gatehouse at \
             GATEHOUSE_REF and point `bin-dir` at the build, as gatehouse-shadow.yml does."
        ));
        bail!("{msg}");
    }
    println!("ok: {steps} step(s) using the action, all running a build this repo pins");

    let Some(dir) = gatehouse else {
        println!(
            "no --gatehouse checkout given: the remaining operand is {PRELUDE} at {gh_ref}, \
             which lives in another repository. Everything above was decided from this tree's \
             declarations alone and stands; the import digest was not compared."
        );
        return Ok(());
    };

    // The checkout must BE the pinned ref, or this compares against the wrong side — the
    // exact mistake F-21 records.
    let head = std::process::Command::new("git")
        .args(["-C", &dir.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .with_context(|| format!("git rev-parse in {}", dir.display()))?;
    let head = String::from_utf8_lossy(&head.stdout)
        .trim()
        .to_ascii_lowercase();
    if head != gh_ref {
        bail!(
            "the gatehouse checkout at {} is {head}, but {WORKFLOW} pins {gh_ref}.\n\
             Comparing the prelude against the wrong commit answers a different question \
             than the one this gate asks.",
            dir.display()
        );
    }

    let prelude = fs::read(dir.join(PRELUDE))
        .with_context(|| format!("reading {PRELUDE} from {}", dir.display()))?;
    let got = sha256_hex(&prelude);
    if got != want {
        bail!(
            "the two pins disagree.\n\
             \x20 {PIPELINE} imports          sha256:{want}\n\
             \x20 {PRELUDE} at {gh_ref} is sha256:{got}\n\
             They must move together: bumping GATEHOUSE_REF without the import digest (or the \
             reverse) makes `gate plan check` fail with `no library for import`, ~3 minutes into \
             a build. If gatehouse's prelude changed deliberately, bump BOTH in one change, and \
             re-check the plan is still admissible rather than merely parseable."
        );
    }
    println!("ok: {PRELUDE} at {gh_ref} hashes to the digest the plan imports");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A throwaway root. Named by test so two tests never share one.
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nucleus-gatehouse-pin-{tag}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join(".github")).expect("create test root");
        d
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().expect("has a parent")).expect("mkdir");
        fs::write(p, body).expect("write");
    }

    #[test]
    fn reads_the_real_declarations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pipeline = fs::read_to_string(root.join(PIPELINE)).unwrap();
        let workflow = fs::read_to_string(root.join(WORKFLOW)).unwrap();
        let d = imported_digest(&pipeline).expect("the shipped plan names a digest");
        let r = pinned_ref(&workflow).expect("the shipped workflow pins a ref");
        assert_eq!(d.len(), 64);
        assert_eq!(r.len(), 40);
    }

    #[test]
    fn a_tag_shaped_import_is_refused() {
        assert!(imported_digest("import \"rust:1.96\" as ci\n").is_err());
    }

    #[test]
    fn a_truncated_digest_is_refused() {
        assert!(imported_digest("import \"sha256:abc123\" as ci\n").is_err());
    }

    #[test]
    fn a_branch_name_is_not_a_pin() {
        assert!(pinned_ref("    GATEHOUSE_REF: main\n").is_err());
    }

    /// The population is what exists, not what a constant lists. The shipped tree has two
    /// pins today; the assertion is that the walk FOUND them rather than that there are two.
    #[test]
    fn the_pins_are_found_by_walking() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let found = pins(&root).expect("the shipped tree's pins parse");
        assert!(
            found.len() >= 2,
            "the walk found {} pin(s); it is meant to find every GATEHOUSE_REF under .github/",
            found.len()
        );
        let files: BTreeSet<&str> = found.iter().map(|p| p.file.as_str()).collect();
        assert!(files.contains(".github/workflows/gatehouse-plan.yml"));
        assert!(files.contains(".github/workflows/gatehouse-shadow.yml"));
        assert!(found.iter().all(|p| p.sha.len() == 40));
    }

    /// A `${{ env.GATEHOUSE_REF }}` use is not an assignment, and counting it as one would put
    /// a pin in the population for every line that mentions the name.
    #[test]
    fn using_the_env_var_is_not_a_pin() {
        let d = tmp("use");
        write(
            &d,
            ".github/workflows/w.yml",
            "    steps:\n      - with:\n          ref: ${{ env.GATEHOUSE_REF }}\n",
        );
        assert!(pins(&d).expect("parses").is_empty());
    }

    /// A commented-out pin is not a pin. `.line-ratchet.toml` paid for the opposite reading
    /// once already.
    #[test]
    fn a_commented_pin_is_not_a_pin() {
        let d = tmp("comment");
        write(
            &d,
            ".github/workflows/w.yml",
            "      # GATEHOUSE_REF: main\n",
        );
        assert!(pins(&d).expect("parses").is_empty());
    }

    /// A malformed pin is an ERROR, not a skip: skipping it is how `GATEHOUSE_REF: main`
    /// leaves the population without anything saying so.
    #[test]
    fn a_branch_name_under_github_is_refused_not_skipped() {
        let d = tmp("branch");
        write(&d, ".github/workflows/w.yml", "      GATEHOUSE_REF: main\n");
        let e = pins(&d).expect_err("a branch name is not a pin");
        assert!(
            e.to_string().contains("not a 40-character commit sha"),
            "{e}"
        );
    }

    /// A third pin joins the population by existing, and disagreeing is what this catches.
    #[test]
    fn a_third_file_joins_the_population() {
        let d = tmp("third");
        write(
            &d,
            ".github/workflows/a.yml",
            &format!("      GATEHOUSE_REF: {}\n", "a".repeat(40)),
        );
        write(
            &d,
            ".github/actions/x/action.yml",
            &format!("      GATEHOUSE_REF: {}\n", "b".repeat(40)),
        );
        let found = pins(&d).expect("parses");
        assert_eq!(found.len(), 2, "an action.yml pin counts: {found:?}");
        assert_ne!(found[0].sha, found[1].sha);
    }

    /// `with:` is a SIBLING of `uses:`. Reading it as a child finds no `bin-dir` on any step
    /// and calls every step compliant — a gate that passes by seeing nothing.
    #[test]
    fn bin_dir_is_read_from_the_sibling_with_block() {
        let wf = "jobs:\n  j:\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          run: cargo test\n          bin-dir: gatehouse/target/debug\n";
        let st = action_steps(wf, "w.yml");
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].bin_dir.as_deref(), Some("gatehouse/target/debug"));
    }

    /// The default is the download path, so an omitted `bin-dir` is the defect.
    #[test]
    fn an_omitted_bin_dir_is_seen_as_omitted() {
        let wf = "jobs:\n  j:\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          run: cargo test\n";
        let st = action_steps(wf, "w.yml");
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].bin_dir, None);
    }

    /// An empty `bin-dir` is the same thing written longhand.
    #[test]
    fn an_empty_bin_dir_is_not_a_directory() {
        let wf = "jobs:\n  j:\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          bin-dir: \"\"\n";
        let st = action_steps(wf, "w.yml");
        assert_eq!(st[0].bin_dir.as_deref(), Some(""));
    }

    /// The block must END at the next step, or a later step's `bin-dir` covers an earlier
    /// step that has none.
    #[test]
    fn a_later_steps_bin_dir_does_not_cover_an_earlier_one() {
        let wf = "jobs:\n  j:\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          run: a\n      - uses: ./.github/actions/gatehouse\n        with:\n          bin-dir: d\n";
        let st = action_steps(wf, "w.yml");
        assert_eq!(st.len(), 2);
        assert_eq!(st[0].bin_dir, None, "the first step set no bin-dir");
        assert_eq!(st[1].bin_dir.as_deref(), Some("d"));
    }

    /// A different action is not this one.
    #[test]
    fn another_action_is_not_the_gatehouse_action() {
        let wf =
            "    steps:\n      - uses: actions/checkout@v4\n        with:\n          bin-dir: x\n";
        assert!(action_steps(wf, "w.yml").is_empty());
    }

    #[test]
    fn the_digest_is_plain_sha256_of_the_file_bytes() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
