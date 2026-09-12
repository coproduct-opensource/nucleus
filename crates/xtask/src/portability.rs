//! `cargo xtask portability` — shell constructs that mean different things on the platform
//! CI runs and the platform this is written on.
//!
//! nucleus's CI is Linux (GNU coreutils). Its developers are on macOS (BSD). A handful of
//! everyday flags differ between the two **without erroring in a way anyone reads**, so the
//! script works where it was written and does something else where it runs.
//!
//! # The one that paid for this gate
//!
//! `mktemp -t NAME`. BSD takes `NAME` as a prefix and returns an absolute path under
//! `$TMPDIR`; GNU treats it as a TEMPLATE and refuses one without `XXXXXX`. So
//!
//! ```text
//! "$(mktemp -t scoreboard).json"
//! ```
//!
//! is `/var/folders/…/scoreboard.29stdWORbi.json` on a Mac and — the command substitution
//! having produced nothing — the bare string `.json` on a runner. `scripts/check-gates-can-fail.sh`
//! then wrote a probe's input to `./.json` in the repository root on **every CI run since the
//! probe was added**, and `.json` is not gitignored. It never bit because CI checks out fresh
//! each time, so the dirty-tree guard at the top of that same script never met the leftover.
//! On a machine that reuses a working tree it refuses to start, with a message about a dirty
//! tree and nothing connecting it to the cause. Recorded as gatehouse F-141.
//!
//! # Why the population is zero and stays zero
//!
//! There is no allowlist. Every construct below has a portable spelling that is no harder to
//! write, so "blessed exception" would mean "this one site may silently do the wrong thing on
//! one of the two platforms we use". Zero hits is the passing state, which means a live hit
//! cannot be what keeps this gate honest — the A-19 probe is, by reintroducing one.
//!
//! # What decides this
//!
//! The text of the shell this repository ships. No toolchain, no network, no source tree.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;

/// One construct, why it diverges, and what to write instead.
struct Divergence {
    /// Matched against a line of shell.
    pattern: &'static str,
    what: &'static str,
    instead: &'static str,
}

/// Measured 2026-09-12 against this repository: every entry is at zero except `mktemp -t`,
/// which this change also fixes. They are listed anyway — a gate that only forbids the defect
/// already found is a gate that learns nothing from it.
const DIVERGENCES: &[Divergence] = &[
    Divergence {
        pattern: r"\bmktemp\s+-t\s",
        what: "BSD reads the argument as a PREFIX and returns an absolute path; GNU reads it \
               as a template and refuses one without XXXXXX, so the substitution yields nothing",
        instead: r#"mktemp "${TMPDIR:-/tmp}/NAME.XXXXXX""#,
    },
    Divergence {
        // `sed -i` with no suffix: BSD consumes the NEXT word as the backup suffix.
        pattern: r"\bsed\s+(-[a-zA-Z]*\s+)*-i\s+(-e\s|'|\x22|/|\$)",
        what: "BSD `sed -i` REQUIRES a backup suffix and will eat the next argument as one; \
               GNU treats the suffix as optional",
        instead: "sed -i.bak … && rm -f file.bak",
    },
    Divergence {
        pattern: r"\breadlink\s+-f\b",
        what: "absent from macOS's readlink before Ventura's coreutils",
        instead: "cd \"$(dirname \"$p\")\" && pwd -P, or python3 -c os.path.realpath",
    },
    Divergence {
        pattern: r"\bgrep\s+(-[a-zA-Z]*\s+)*-P\b|\bgrep\s+-[a-zA-Z]*P\b",
        what: "BSD grep has no PCRE mode",
        instead: "grep -E",
    },
    Divergence {
        pattern: r"\bxargs\s+(-[a-zA-Z]*\s+)*-r\b",
        what: "BSD xargs has no --no-run-if-empty; it already skips an empty input",
        instead: "drop -r",
    },
    Divergence {
        pattern: r"\bstat\s+-c\b|\bstat\s+-f\s+%",
        what: "`stat -c` is GNU and `stat -f %…` is BSD; each is an error on the other",
        instead: "wc -c < file, or ls -l, or python3 -c os.stat",
    },
    Divergence {
        pattern: r"\bdate\s+-d\s|\bdate\s+-v[-+]",
        what: "`date -d` is GNU and `date -v` is BSD",
        instead: "date -u +%s arithmetic, or python3",
    },
    Divergence {
        pattern: r"\bfind\s+[^|;&]*-printf\b",
        what: "`-printf` is a GNU find extension",
        instead: "find … -exec printf, or -print0 | xargs -0",
    },
];

/// A scan that reaches far fewer has stopped reading the tree, and a zero-hit verdict would
/// then mean nothing. Measured 2026-09-12 against `scripts/` and `ci/`.
const MIN_FILES: usize = 30;

fn shell_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // `scripts/` and `ci/` ONLY, and the omission is the point.
    //
    // A workflow's `run:` block executes on the runner and nowhere else, so a GNU-only
    // construct there is correct by construction -- flagging it would be asking this
    // repository to write worse shell to satisfy a rule about a platform the code never
    // meets. What diverges is shell a PERSON runs: the gate harness, prepush, the check-*
    // family, the experiments. Those run on a developer's Mac and on a Linux runner, and
    // the same line has to mean the same thing in both.
    for (dir, exts) in [("scripts", &["sh"][..]), ("ci", &["sh"][..])] {
        collect(&root.join(dir), exts, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

fn collect(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect(&p, exts, out);
        } else if p
            .extension()
            .is_some_and(|x| exts.contains(&&*x.to_string_lossy()))
        {
            out.push(p);
        }
    }
}

/// A comment is not a call site — the same rule the gate harness records for shell gates, and
/// this file's own doc comment would otherwise be a hit on three of the patterns below.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('#') || t.starts_with("//") || t.starts_with("//!")
}

pub fn check(root: &Path) -> Result<()> {
    let files = shell_files(root);
    if files.len() < MIN_FILES {
        bail!(
            "found {} shell/workflow file(s), floor {MIN_FILES} — the scan is wrong, so a \
             zero-hit verdict would be about nothing",
            files.len()
        );
    }

    let res: Vec<Regex> = DIVERGENCES
        .iter()
        .map(|d| Regex::new(d.pattern).with_context(|| format!("pattern {}", d.pattern)))
        .collect::<Result<_>>()?;

    let mut hits = 0usize;
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for (d, re) in DIVERGENCES.iter().zip(&res) {
                if re.is_match(line) {
                    println!("  FAIL  {rel}:{}: {}", n + 1, line.trim());
                    println!("        {}", d.what);
                    println!("        write instead: {}", d.instead);
                    hits += 1;
                }
            }
        }
    }

    if hits > 0 {
        bail!(
            "{hits} construct(s) that behave differently on the platform CI runs and the one \
             this was written on. There is no allowlist: each has a portable spelling that is \
             no harder to write, and a blessed exception would mean one site may silently do \
             the wrong thing on one of the two platforms in use."
        );
    }
    println!(
        "ok: {} shell/workflow file(s), none using a construct that differs between BSD and GNU",
        files.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(line: &str) -> usize {
        DIVERGENCES
            .iter()
            .filter(|d| Regex::new(d.pattern).expect("compiles").is_match(line))
            .count()
    }

    /// The defect this gate was written for, in the spelling it actually had.
    #[test]
    fn the_mktemp_that_wrote_dot_json_is_caught() {
        assert_eq!(
            hits(r#"    "scoreboard.json" "$(mktemp -t scoreboard).json" \"#),
            1
        );
    }

    /// ...and the portable spelling it was replaced with is not.
    #[test]
    fn the_portable_mktemp_is_not_a_hit() {
        assert_eq!(
            hits(r#""$(mktemp "${TMPDIR:-/tmp}/scoreboard.XXXXXX").json""#),
            0
        );
        assert_eq!(hits(r#"RESTORE_FROM="$(mktemp)""#), 0);
    }

    /// `sed -i.bak` is the portable form this repository already uses ten times over; flagging
    /// it would make the gate refuse the fix it asks for.
    #[test]
    fn the_portable_sed_is_not_a_hit() {
        assert_eq!(hits(r#"sed -i.bak 's/a/b/' "$1" && rm -f "$1.bak""#), 0);
    }

    #[test]
    fn a_suffixless_sed_i_is_a_hit() {
        assert!(hits(r#"sed -i 's/a/b/' file"#) >= 1);
    }

    /// Every pattern must catch its own construct, or an entry is decoration.
    #[test]
    fn each_divergence_catches_something() {
        for (d, sample) in DIVERGENCES.iter().zip([
            "x=$(mktemp -t foo)",
            "sed -i 's/a/b/' f",
            "p=$(readlink -f \"$1\")",
            "grep -P '\\d' f",
            "printf '' | xargs -r rm",
            "stat -c %s f",
            "date -d @123",
            "find . -printf '%p\\n'",
        ]) {
            assert!(
                Regex::new(d.pattern).expect("compiles").is_match(sample),
                "pattern {:?} does not match its own sample {sample:?}",
                d.pattern
            );
        }
    }

    /// A comment mentioning a construct is not a use of it — this file's own header would
    /// otherwise red the gate, which is how the last three of these were found.
    #[test]
    fn a_comment_is_not_a_call_site() {
        assert!(is_comment("# mktemp -t NAME is BSD-only"));
        assert!(is_comment(
            "//! `mktemp -t NAME`. BSD takes NAME as a prefix"
        ));
        assert!(!is_comment("x=$(mktemp -t foo)"));
    }

    /// The shipped tree, read the way the gate reads it.
    #[test]
    fn the_scan_reaches_the_shell_this_repo_ships() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let f = shell_files(&root);
        assert!(f.len() >= MIN_FILES, "found {} file(s)", f.len());
    }
}
