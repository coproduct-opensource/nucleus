//! `cargo xtask prepush` — the cheap tree-only gates, run before a push instead of in the queue.
//!
//! Owner decision 2026-10-02. On that day four gates that need nothing but the tree broke `main`
//! or ejected merge-queue groups, each one decidable in seconds on the author's machine:
//!
//! * the exemplar ratchet (`xtask scoreboard-ratchet`, measuring the tree in process);
//! * `cargo audit --deny warnings` (a new RUSTSEC advisory against the lockfile);
//! * `xtask scorecard`;
//! * `xtask line-ratchet --strict`.
//!
//! Every gate gets a typed [`Verdict`]: `Pass`, `Fail(reason)` or `CouldNotRun(reason)`.
//! `CouldNotRun` is never a pass (ADR 0007 A): a missing `cargo-audit` is a red with the install
//! command in it, not a skip. The run exits non-zero on any verdict that is not `Pass`.
//!
//! Each gate is a child process whose exit status is read directly — never through a pipe, so the
//! status is the gate's own and not `tail`'s. The gates are independent and read-only on the
//! tree, so they run in parallel; the wall clock is the slowest gate, not the sum.

use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use anyhow::Result;

/// The pinned cargo-audit, matching `.github/workflows/audit.yml` and the Fly runner image.
const AUDIT_INSTALL: &str =
    "cargo +stable install cargo-audit --version 0.22.0 --locked --no-default-features";

/// How many lines of a red gate's output to show. Printed by this binary from the captured
/// output — the gate's exit status was read before any of it was trimmed.
const SHOWN_LINES: usize = 25;

/// One gate's outcome. There is no `Skipped`: a gate either decided or could not.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    Pass,
    Fail(String),
    CouldNotRun(String),
}

/// The run as a whole. `Vacuous` exists so that a gate list that came out empty is a red rather
/// than "no gate failed".
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Overall {
    Green,
    Red { failed: usize, could_not_run: usize },
    Vacuous,
}

impl Overall {
    /// 0 green; 1 any gate failed; 2 nothing failed but something could not run (the repo's
    /// "could not look" code). Every arm but `Green` is non-zero.
    pub fn exit_code(&self) -> i32 {
        match self {
            Overall::Green => 0,
            Overall::Red { failed, .. } if *failed > 0 => 1,
            Overall::Red { .. } | Overall::Vacuous => 2,
        }
    }
}

/// Fold the verdicts. Only `Pass` counts toward green.
pub fn overall<'a>(verdicts: impl IntoIterator<Item = &'a Verdict>) -> Overall {
    let (mut seen, mut failed, mut could_not_run) = (0usize, 0usize, 0usize);
    for v in verdicts {
        seen += 1;
        match v {
            Verdict::Pass => {}
            Verdict::Fail(_) => failed += 1,
            Verdict::CouldNotRun(_) => could_not_run += 1,
        }
    }
    match (seen, failed + could_not_run) {
        (0, _) => Overall::Vacuous,
        (_, 0) => Overall::Green,
        _ => Overall::Red {
            failed,
            could_not_run,
        },
    }
}

/// The last `n` lines of `s`, done here rather than by piping the gate into `tail`.
fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn combined(out: &Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

/// An xtask gate's exit status: 0 passes, 2 is the repo's "could not look", a signal is a gate
/// that never finished, and any other code is the gate's own red.
fn classify_xtask(code: Option<i32>, output: &str) -> Verdict {
    match code {
        Some(0) => Verdict::Pass,
        Some(2) => Verdict::CouldNotRun(format!("exit 2 (could not look)\n{output}")),
        Some(c) => Verdict::Fail(format!("exit {c}\n{output}")),
        None => Verdict::CouldNotRun(format!("killed by a signal\n{output}")),
    }
}

/// cargo-audit exits 1 both for a finding and for "could not fetch the advisory database". A
/// finding always ends in `… found!`; anything else non-zero is a run that did not decide. Both
/// are red either way — the split only makes the reason honest.
fn classify_audit(code: Option<i32>, output: &str) -> Verdict {
    match code {
        Some(0) => Verdict::Pass,
        Some(c) if output.contains("found!") => Verdict::Fail(format!("exit {c}\n{output}")),
        Some(c) => Verdict::CouldNotRun(format!("exit {c} without a finding\n{output}")),
        None => Verdict::CouldNotRun(format!("killed by a signal\n{output}")),
    }
}

fn run_child(mut cmd: Command, root: &Path) -> std::io::Result<Output> {
    cmd.current_dir(root).output()
}

/// This binary, re-invoked as `xtask <args>`: no nested `cargo run`, so no second build lock.
fn xtask_gate(root: &Path, args: &[&str]) -> Verdict {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return Verdict::CouldNotRun(format!("cannot locate the xtask binary: {e}")),
    };
    let mut cmd = Command::new(exe);
    cmd.args(args);
    match run_child(cmd, root) {
        Ok(out) => classify_xtask(out.status.code(), &combined(&out)),
        Err(e) => Verdict::CouldNotRun(format!("spawning xtask {}: {e}", args.join(" "))),
    }
}

fn exemplar_ratchet(root: &Path) -> Verdict {
    xtask_gate(
        root,
        &[
            "scoreboard-ratchet",
            "--baseline",
            "scripts/exemplar-baseline.json",
        ],
    )
}

fn cargo_audit(root: &Path) -> Verdict {
    let mut probe = Command::new("cargo");
    probe.args(["audit", "--version"]);
    match run_child(probe, root) {
        Ok(out) if out.status.success() => {}
        Ok(_) | Err(_) => {
            return Verdict::CouldNotRun(format!("cargo-audit is not installed: {AUDIT_INSTALL}"));
        }
    }
    let mut cmd = Command::new("cargo");
    cmd.args(["audit", "--deny", "warnings"]);
    match run_child(cmd, root) {
        Ok(out) => classify_audit(out.status.code(), &combined(&out)),
        Err(e) => Verdict::CouldNotRun(format!("spawning cargo audit: {e}")),
    }
}

/// The gates, by name. A fn pointer per gate so the list is data and the runner is one loop.
type Gate = (&'static str, fn(&Path) -> Verdict);

const GATES: &[Gate] = &[
    ("exemplar ratchet", exemplar_ratchet),
    ("cargo-audit (RUSTSEC)", cargo_audit),
    ("scorecard", |root| xtask_gate(root, &["scorecard"])),
    ("line ratchet --strict", |root| {
        xtask_gate(root, &["line-ratchet", "--strict"])
    }),
];

fn reason(v: &Verdict) -> Option<&str> {
    match v {
        Verdict::Pass => None,
        Verdict::Fail(r) | Verdict::CouldNotRun(r) => Some(r),
    }
}

pub fn run(root: &Path) -> Result<i32> {
    let start = Instant::now();
    println!(
        "prepush: {} tree-only gates, in parallel, at {}",
        GATES.len(),
        root.display()
    );
    let results: Vec<(&str, Verdict, Duration)> = std::thread::scope(|s| {
        let handles: Vec<_> = GATES
            .iter()
            .map(|(name, gate)| {
                s.spawn(move || {
                    let t = Instant::now();
                    let v = gate(root);
                    (*name, v, t.elapsed())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| {
                    (
                        "a gate thread",
                        Verdict::CouldNotRun("panicked".to_string()),
                        Duration::ZERO,
                    )
                })
            })
            .collect()
    });

    for (name, v, took) in &results {
        let tag = match v {
            Verdict::Pass => "PASS         ",
            Verdict::Fail(_) => "FAIL         ",
            Verdict::CouldNotRun(_) => "COULD NOT RUN",
        };
        println!("  {tag}  {name:<24} {:>6.1}s", took.as_secs_f64());
        if let Some(r) = reason(v) {
            for l in last_lines(r, SHOWN_LINES).lines() {
                println!("        {l}");
            }
        }
    }
    let total = start.elapsed().as_secs_f64();
    let verdict = overall(results.iter().map(|(_, v, _)| v));
    match &verdict {
        Overall::Green => println!("prepush: all {} gates pass in {total:.1}s", results.len()),
        Overall::Red {
            failed,
            could_not_run,
        } => println!(
            "prepush: {failed} failed, {could_not_run} could not run, of {} gates, in \
             {total:.1}s — fix before pushing (could-not-run is not a pass)",
            results.len()
        ),
        Overall::Vacuous => println!("prepush: no gate ran — that is not a pass"),
    }
    Ok(verdict.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail() -> Verdict {
        Verdict::Fail("red".into())
    }
    fn cnr() -> Verdict {
        Verdict::CouldNotRun("no binary".into())
    }

    #[test]
    fn all_pass_is_green_and_exits_zero() {
        let o = overall(&[Verdict::Pass, Verdict::Pass]);
        assert_eq!(o, Overall::Green);
        assert_eq!(o.exit_code(), 0);
    }

    #[test]
    fn a_could_not_run_gate_fails_the_run() {
        // ADR 0007 A: "could not look" is never "looked and it was fine".
        let o = overall(&[Verdict::Pass, cnr(), Verdict::Pass]);
        assert_eq!(
            o,
            Overall::Red {
                failed: 0,
                could_not_run: 1
            }
        );
        assert_ne!(o.exit_code(), 0);
        assert_eq!(o.exit_code(), 2);
    }

    #[test]
    fn a_failing_gate_fails_the_run_with_exit_one() {
        let o = overall(&[fail(), cnr(), Verdict::Pass]);
        assert_eq!(
            o,
            Overall::Red {
                failed: 1,
                could_not_run: 1
            }
        );
        assert_eq!(o.exit_code(), 1);
    }

    #[test]
    fn no_gates_is_not_green() {
        let o = overall(&[]);
        assert_eq!(o, Overall::Vacuous);
        assert_ne!(o.exit_code(), 0);
    }

    #[test]
    fn xtask_exit_codes_map_to_verdicts() {
        assert_eq!(classify_xtask(Some(0), ""), Verdict::Pass);
        assert!(matches!(classify_xtask(Some(1), "x"), Verdict::Fail(_)));
        assert!(matches!(
            classify_xtask(Some(2), "x"),
            Verdict::CouldNotRun(_)
        ));
        assert!(matches!(classify_xtask(None, "x"), Verdict::CouldNotRun(_)));
        assert!(matches!(classify_xtask(Some(101), "x"), Verdict::Fail(_)));
    }

    #[test]
    fn audit_findings_fail_and_fetch_errors_could_not_run() {
        assert_eq!(classify_audit(Some(0), ""), Verdict::Pass);
        assert!(matches!(
            classify_audit(Some(1), "error: 1 vulnerability found!"),
            Verdict::Fail(_)
        ));
        assert!(matches!(
            classify_audit(Some(1), "error: 2 denied warnings found!"),
            Verdict::Fail(_)
        ));
        assert!(matches!(
            classify_audit(Some(1), "error: couldn't fetch advisory database"),
            Verdict::CouldNotRun(_)
        ));
        assert!(matches!(classify_audit(None, ""), Verdict::CouldNotRun(_)));
    }

    #[test]
    fn last_lines_keeps_the_tail_and_tolerates_short_input() {
        assert_eq!(last_lines("a\nb\nc\n", 2), "b\nc");
        assert_eq!(last_lines("a", 5), "a");
        assert_eq!(last_lines("", 5), "");
    }

    #[test]
    fn the_four_owner_named_gates_are_all_listed() {
        let names: Vec<&str> = GATES.iter().map(|(n, _)| *n).collect();
        for want in ["exemplar", "cargo-audit", "scorecard", "line ratchet"] {
            assert!(
                names.iter().any(|n| n.contains(want)),
                "{want} missing from {names:?}"
            );
        }
    }
}
