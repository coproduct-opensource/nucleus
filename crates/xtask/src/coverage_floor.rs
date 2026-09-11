//! `cargo xtask coverage-floor` — a coverage threshold may not move without saying so.
//!
//! `coverage-matrix.yml` enforces two floors with `cargo llvm-cov --fail-under-lines`. Both
//! live inside a `run:` block, where a threshold is a digit in the middle of a shell command
//! and a change to it looks like any other diff.
//!
//! The workspace floor has moved **85 → 83 → 82.5** (2026-03-05 `bb459c502`, 2026-09-06
//! `f1c74241b`, 2026-09-10 `ebda64aad`). Every one was deliberate, and the last says so in its
//! own title — *"give the workspace coverage floor headroom, deliberately and downward"*
//! (#2777). **That is the practice working, and this gate is not a complaint about it.**
//!
//! It is about what held it up: a convention. Nothing required the next lowering to be
//! recorded at all, and the pressure to take it is ordinary rather than exotic. On 2026-09-11
//! a PR missed the workspace floor by **0.02 points** (82.48 against 82.5) and the
//! one-character fix was sitting in the workflow. The right answer was to test the new module,
//! and that is what happened — but a gate is what makes the right answer the EASY one rather
//! than the virtuous one. `ci/required-checks.txt` already applies exactly this idiom to the
//! required-context set, for exactly this reason.
//!
//! # The rule
//!
//! Every `--fail-under-lines` in the workflow must EQUAL the value pinned in
//! `ci/coverage-floor.txt`, **in both directions** — a pinned name with no threshold is as
//! much a violation as a threshold with no pin. So changing a floor means editing the pin file
//! in the same commit, where the reason is a line of prose in review rather than a digit
//! inside a shell command.
//!
//! Deliberately NOT "the floor may only grow". A shrink-only ratchet on a number that has
//! legitimately shrunk three times would be a gate that reds on the honest case and teaches
//! people to route around it. Equality asks only that the change be *visible*, which is the
//! property that was actually missing.
//!
//! # The number is not the only lever
//!
//! Two other flags on the same command move the floor without touching it:
//!
//! ```text
//! --exclude nucleus-verifier-service
//! --ignore-filename-regex '(tests/|kani\.rs|main\.rs)'
//! ```
//!
//! Widen the regex or exclude another crate and the threshold still reads 82.5 while meaning
//! less. **That is the sharper hatch of the two**, because a changed digit is legible in
//! review and `|src/` appended inside a quoted regex is not. So the pin covers all three —
//! the value, the ignore pattern, and the exclusions — and the same equality rule applies to
//! each.
//!
//! # What decides this
//!
//! Two committed files. No coverage run, no source tree, no toolchain, no network — this gate
//! deliberately does not measure coverage, which is the expensive half.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

const WORKFLOW: &str = ".github/workflows/coverage-matrix.yml";
const PIN: &str = "ci/coverage-floor.txt";
const FLAG: &str = "--fail-under-lines";
const IGNORE_FLAG: &str = "--ignore-filename-regex";

/// Which floor a threshold belongs to, taken from the `-p <crate>` on the same command.
/// `--workspace` is the workspace floor; `-p portcullis` is portcullis's.
/// The single-quoted argument of `flag`, or `"none"`. Single quotes because that is how the
/// workflow writes a regex; a bare one would be split by the shell.
fn single_quoted(command: &str, flag: &str) -> String {
    command
        .split(flag)
        .nth(1)
        .and_then(|r| r.trim_start().strip_prefix('\''))
        .and_then(|r| r.split_once('\''))
        .map(|(v, _)| v.to_string())
        .unwrap_or_else(|| "none".to_string())
}

/// Every `--exclude <crate>`, sorted and comma-joined, or `"none"`. Sorted so reordering the
/// flags is not a diff, and joined so one pin line covers the whole set.
fn excludes(command: &str) -> String {
    let mut v: Vec<&str> = command
        .split("--exclude ")
        .skip(1)
        .filter_map(|r| r.split_whitespace().next())
        .collect();
    if v.is_empty() {
        return "none".to_string();
    }
    v.sort_unstable();
    v.dedup();
    v.join(",")
}

fn name_for(command: &str) -> String {
    for (flag, name) in [
        ("-p portcullis", "portcullis"),
        ("--workspace", "workspace"),
    ] {
        if command.contains(flag) {
            return name.to_string();
        }
    }
    "unknown".to_string()
}

/// Every `--fail-under-lines` in the workflow, keyed by which floor it is.
///
/// A `cargo llvm-cov` invocation is a multi-line continued command, so the value and the
/// `-p`/`--workspace` that names it are on different lines. The unit is therefore the whole
/// `run:` block, and a block carrying two invocations would collide — which [`check`] reports
/// rather than silently keeping one.
pub fn thresholds(workflow_src: &str) -> Result<BTreeMap<String, String>> {
    let lines: Vec<&str> = workflow_src.lines().collect();
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let t = t.strip_prefix("- ").unwrap_or(t);
        if !t.starts_with("run:") {
            i += 1;
            continue;
        }
        let run_indent = lines[i].len() - lines[i].trim_start().len();
        let mut block = vec![t.trim_start_matches("run:").to_string()];
        let mut j = i + 1;
        while j < lines.len() {
            let l = lines[j];
            if !l.trim().is_empty() && l.len() - l.trim_start().len() <= run_indent {
                break;
            }
            block.push(l.to_string());
            j += 1;
        }
        let text = block.join("\n");
        for bl in text.lines() {
            let code = bl.trim_start();
            if code.starts_with('#') {
                continue;
            }
            let Some(rest) = code.split(FLAG).nth(1) else {
                continue;
            };
            let value = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            if value.is_empty() {
                bail!("{WORKFLOW}: a bare `{FLAG}` with no value");
            }
            let name = name_for(&text);
            // The two flags that move the floor without touching it.
            out.insert(format!("{name}.ignore"), single_quoted(&text, IGNORE_FLAG));
            out.insert(format!("{name}.exclude"), excludes(&text));
            if let Some(prev) = out.insert(name.clone(), value.clone()) {
                bail!(
                    "{WORKFLOW}: two thresholds resolve to the floor {name:?} ({prev} and \
                     {value}). This gate keys a threshold by the `-p`/`--workspace` on its own \
                     command; give them distinguishable commands, or teach `name_for` the new \
                     shape — keeping one silently would pin half of what runs."
                );
            }
        }
        i = j;
    }
    Ok(out)
}

/// `name = value` lines, `#` comments ignored.
pub fn pinned(pin_src: &str) -> BTreeMap<String, String> {
    pin_src
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

pub fn check(root: &Path) -> Result<()> {
    let wf =
        fs::read_to_string(root.join(WORKFLOW)).with_context(|| format!("reading {WORKFLOW}"))?;
    let pin_src = fs::read_to_string(root.join(PIN)).with_context(|| format!("reading {PIN}"))?;

    let found = thresholds(&wf)?;
    let want = pinned(&pin_src);

    if found.is_empty() {
        bail!(
            "{WORKFLOW}: no `{FLAG}` found. Either the coverage gate stopped enforcing a floor, \
             or this parser stopped seeing it — and a gate that compares nothing agrees with \
             everything."
        );
    }
    if want.is_empty() {
        bail!("{PIN}: no `name = value` lines — an empty pin agrees with any threshold");
    }

    let mut failures = Vec::new();
    for (name, value) in &found {
        match want.get(name) {
            None => failures.push(format!(
                "{WORKFLOW} enforces {name} = {value}, and {PIN} does not pin it. Add it, so the \
                 next change to it has to be written down."
            )),
            Some(w) if w != value => failures.push(format!(
                "{name}: {WORKFLOW} enforces {value}, {PIN} pins {w}. One fact, two values. \
                 Move the pin in the SAME change and record why, dated. Widening an `.ignore` \
                 or adding an `.exclude` lowers the floor as surely as lowering the number, \
                 and is harder to see — so all three are owner decisions."
            )),
            Some(_) => println!("  ok   {name} = {value}"),
        }
    }
    for name in want.keys() {
        if !found.contains_key(name) {
            failures.push(format!(
                "{PIN} pins {name}, and no `{FLAG}` in {WORKFLOW} enforces it. A pinned floor \
                 nothing applies reads as protection that is not there."
            ));
        }
    }

    if !failures.is_empty() {
        bail!(
            "{} coverage floor(s) disagree:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
    println!("ok: all {} coverage floor(s) match their pin", found.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_shipped_workflow_and_pin_agree() {
        check(&root()).expect("the committed floors must match their pin");
    }

    #[test]
    fn the_shipped_workflow_has_both_floors() {
        let wf = fs::read_to_string(root().join(WORKFLOW)).unwrap();
        let t = thresholds(&wf).unwrap();
        assert!(t.contains_key("workspace"), "{t:?}");
        assert!(t.contains_key("portcullis"), "{t:?}");
    }

    #[test]
    fn a_threshold_is_keyed_by_its_own_command() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: |\n          cargo llvm-cov --workspace --fail-under-lines 82.5\n      - run: |\n          cargo llvm-cov -p portcullis --fail-under-lines 87\n";
        let t = thresholds(wf).unwrap();
        assert_eq!(t.get("workspace").map(String::as_str), Some("82.5"));
        assert_eq!(t.get("portcullis").map(String::as_str), Some("87"));
    }

    #[test]
    fn two_thresholds_for_one_floor_are_refused() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: |\n          cargo llvm-cov --workspace --fail-under-lines 82.5\n          cargo llvm-cov --workspace --fail-under-lines 70\n";
        assert!(
            thresholds(wf).is_err(),
            "keeping one silently pins half of what runs"
        );
    }

    #[test]
    fn a_commented_threshold_is_not_a_threshold() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: |\n          # --fail-under-lines 99 was tried and reverted\n          echo hi\n";
        assert!(thresholds(wf).unwrap().is_empty());
    }

    #[test]
    fn pinned_ignores_comments_and_blanks() {
        let p = pinned("# a note\n\nworkspace = 82.5\nportcullis = 87\n");
        assert_eq!(p.len(), 2);
        assert_eq!(p.get("workspace").map(String::as_str), Some("82.5"));
    }

    // ---- the other two levers ------------------------------------------------------

    #[test]
    fn the_ignore_regex_and_excludes_are_captured_per_floor() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: |\n          cargo llvm-cov --workspace --exclude a-crate --fail-under-lines 82.5 --ignore-filename-regex '(tests/|kani\\.rs)'\n";
        let t = thresholds(wf).unwrap();
        assert_eq!(
            t.get("workspace.ignore").map(String::as_str),
            Some("(tests/|kani\\.rs)")
        );
        assert_eq!(
            t.get("workspace.exclude").map(String::as_str),
            Some("a-crate")
        );
    }

    /// An absent flag is `none`, not a missing key — otherwise removing the flag would look
    /// like the pin going stale rather than the floor widening.
    #[test]
    fn an_absent_flag_reads_as_none() {
        let wf = "jobs:\n  j:\n    steps:\n      - run: |\n          cargo llvm-cov --workspace --fail-under-lines 82.5\n";
        let t = thresholds(wf).unwrap();
        assert_eq!(t.get("workspace.ignore").map(String::as_str), Some("none"));
        assert_eq!(t.get("workspace.exclude").map(String::as_str), Some("none"));
    }

    /// Sorted and deduped, so reordering the flags is not a diff.
    #[test]
    fn excludes_are_sorted_and_joined() {
        assert_eq!(
            excludes("cargo --exclude zed --exclude alpha --exclude zed x"),
            "alpha,zed"
        );
        assert_eq!(excludes("cargo llvm-cov --workspace"), "none");
    }

    #[test]
    fn single_quoted_reads_only_the_quoted_argument() {
        assert_eq!(single_quoted("a --flag 'x|y' --other z", "--flag"), "x|y");
        assert_eq!(single_quoted("a --other z", "--flag"), "none");
    }

    /// The live hatch: widen the regex, leave the number alone.
    #[test]
    fn widening_the_ignore_regex_is_refused() {
        let wf = WF_OK.replace("(tests/)", "(tests/|src/)");
        let d = tmp("widened", &wf, PIN_OK);
        let e = check(&d).expect_err("a widened ignore must red");
        assert!(e.to_string().contains("workspace.ignore"), "{e}");
    }

    #[test]
    fn adding_an_exclude_is_refused() {
        let wf = WF_OK.replace("--workspace", "--workspace --exclude something");
        let d = tmp("excluded", &wf, PIN_OK);
        let e = check(&d).expect_err("a new exclusion must red");
        assert!(e.to_string().contains("workspace.exclude"), "{e}");
    }

    // ---- `check` against a temp tree ------------------------------------------------

    fn tmp(tag: &str, wf: &str, pin: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("xtask-cov-floor-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join(".github/workflows")).unwrap();
        fs::create_dir_all(d.join("ci")).unwrap();
        fs::write(d.join(WORKFLOW), wf).unwrap();
        fs::write(d.join(PIN), pin).unwrap();
        d
    }

    const WF_OK: &str = "jobs:\n  j:\n    steps:\n      - run: |\n          cargo llvm-cov --workspace --fail-under-lines 82.5 --ignore-filename-regex '(tests/)'\n      - run: |\n          cargo llvm-cov -p portcullis --fail-under-lines 87\n";
    const PIN_OK: &str = "workspace = 82.5\nworkspace.ignore = (tests/)\nworkspace.exclude = none\nportcullis = 87\nportcullis.ignore = none\nportcullis.exclude = none\n";

    #[test]
    fn check_passes_when_they_agree() {
        let d = tmp("ok", WF_OK, PIN_OK);
        check(&d).unwrap();
    }

    /// The live temptation: lower the floor rather than test the new code.
    #[test]
    fn check_fails_when_a_floor_is_quietly_lowered() {
        let wf = WF_OK.replace("82.5", "82.4");
        let d = tmp("lowered", &wf, PIN_OK);
        let e = check(&d).expect_err("a lowered floor must red");
        assert!(e.to_string().contains("One fact, two values"), "{e}");
    }

    /// Raising is allowed, but the pin must follow, or it stops meaning anything.
    #[test]
    fn check_fails_when_a_floor_is_raised_without_the_pin() {
        let wf = WF_OK.replace("82.5", "90");
        let d = tmp("raised", &wf, PIN_OK);
        assert!(
            check(&d).is_err(),
            "an unpinned improvement leaves a stale pin"
        );
    }

    #[test]
    fn check_fails_on_an_unpinned_threshold() {
        let d = tmp("unpinned", WF_OK, "workspace = 82.5\n");
        let e = check(&d).expect_err("portcullis is unpinned");
        assert!(e.to_string().contains("does not pin it"), "{e}");
    }

    #[test]
    fn check_fails_on_a_pin_nothing_enforces() {
        let d = tmp(
            "stale",
            WF_OK,
            "workspace = 82.5\nportcullis = 87\nghost = 99\n",
        );
        let e = check(&d).expect_err("a pin with no enforcer is not protection");
        assert!(e.to_string().contains("reads as protection"), "{e}");
    }

    #[test]
    fn check_refuses_a_workflow_with_no_threshold() {
        let d = tmp(
            "none",
            "jobs:\n  j:\n    steps:\n      - run: echo hi\n",
            "workspace = 82.5\n",
        );
        let e = check(&d).expect_err("finding no floor is not a pass");
        assert!(e.to_string().contains("compares nothing"), "{e}");
    }

    #[test]
    fn check_refuses_an_empty_pin() {
        let d = tmp("emptypin", WF_OK, "# only comments\n");
        let e = check(&d).expect_err("an empty pin agrees with anything");
        assert!(e.to_string().contains("empty pin"), "{e}");
    }

    #[test]
    fn check_errors_when_a_file_is_missing() {
        let d = std::env::temp_dir().join(format!("xtask-cov-floor-absent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        assert!(check(&d).is_err());
    }
}
