//! `cargo xtask gate-budget` — a gate's own timeout must be able to fire before the job
//! running it is killed.
//!
//! `.github/workflows/gatehouse-shadow.yml` runs each gate through the one-step gatehouse
//! action, which takes a `timeout` (seconds the command may take) and enforces it. The job
//! around it carries GitHub's `timeout-minutes`. Those are two clocks over the same work,
//! and only one of them can be first.
//!
//! When GitHub's is first, the runner never reports. The job ends `cancelled`, which is the
//! same conclusion an infrastructure fault produces, and the one mechanism that would have
//! said *"this gate exceeded its budget"* is preempted by the mechanism that says nothing at
//! all. A verdict becomes a cancellation, and a cancellation is not a finding.
//!
//! That is not hypothetical. Measured 2026-09-11, the clippy entry declared:
//!
//! ```text
//! timeout-minutes: 45          # the job
//! timeout: "2700"              # the action — 45 minutes, the same number
//! compare:                     # unset, so the action's default `true` applies
//! ```
//!
//! `compare` runs the command a SECOND time, plainly, to produce the agreement line that is
//! the whole point of shadow mode. So the declared need is `2 x 2700 = 5400` seconds inside a
//! 2700-second job — and even one run of 2700 does not fit, because setup consumes some of the
//! job's budget before the gate step starts (43 seconds, measured on run 34625269465).
//!
//! The observable consequence: **304 runs between 2026-09-09T11:46Z and 2026-09-11T18:00Z
//! produced no verdict at all**, and 14 of 20 sampled cancelled runs had spent the full 45
//! minutes to produce it. The gate had not been failing. It had not been running.
//!
//! # The rule
//!
//! For every step using the gatehouse action:
//!
//! ```text
//! runs * timeout_s + SETUP_ALLOWANCE_S  <  timeout-minutes * 60
//! ```
//!
//! where `runs` is 2 when `compare` is on and 1 otherwise. Strict: equality is the defect
//! above, not the boundary case that just fits.
//!
//! Both defaults — `timeout` and `compare` — are read from `.github/actions/gatehouse/action.yml`
//! rather than repeated here. A second copy of a default is a second thing to drift, which is
//! the failure this family of gates exists to refuse; `fly_pools.rs` calls the manager's own
//! validator for the same reason.
//!
//! # What decides this
//!
//! Two committed YAML files. No source tree, no toolchain, no network, and the same verdict
//! against an empty checkout of nucleus. See gatehouse `docs/tiering.md`.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

const ACTION: &str = ".github/actions/gatehouse/action.yml";
/// Workflows that run a gate through the action. A workflow added here is checked without
/// further code; one that uses the action and is NOT here is caught by [`unlisted_users`].
const WORKFLOWS: [&str; 1] = [".github/workflows/gatehouse-shadow.yml"];
/// The action path as a workflow step spells it.
const USES: &str = "./.github/actions/gatehouse";

/// Setup before the gate step starts: two checkouts, the toolchain, and the gatehouse build.
/// Measured 43s on run 34625269465 (job started 17:07:42Z, gate step 17:08:25Z); 60 rounds it
/// up. This is an allowance, not a ceiling — a job that fits only because setup was fast is
/// the shape this gate refuses.
const SETUP_ALLOWANCE_S: u64 = 60;

/// One `uses: ./.github/actions/gatehouse` step, with the job budget around it.
#[derive(Debug, PartialEq, Eq)]
pub struct Site {
    pub job_budget_s: u64,
    pub timeout_s: u64,
    pub compare: bool,
    /// For the message: which `timeout-minutes` line this step was measured against.
    pub line: usize,
}

impl Site {
    pub fn runs(&self) -> u64 {
        if self.compare { 2 } else { 1 }
    }
    pub fn need_s(&self) -> u64 {
        self.runs() * self.timeout_s + SETUP_ALLOWANCE_S
    }
    pub fn fits(&self) -> bool {
        self.need_s() < self.job_budget_s
    }
}

/// Indentation of a YAML line, in spaces. Tabs are not legal YAML indentation.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// A scalar `key: value`, unquoted. A leading `- ` is stripped first: in a step list the
/// FIRST key of an item carries the item marker (`- uses: ...`), and a parser that misses that
/// form sees no step at all — which is the vacuous pass this gate exists to refuse.
fn scalar<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let t = line.trim();
    let t = t.strip_prefix("- ").unwrap_or(t);
    let rest = t.strip_prefix(key)?.strip_prefix(':')?;
    Some(rest.trim().trim_matches(|c| c == '"' || c == '\''))
}

/// Indentation of the KEY on a line, which is two deeper than the line's own when that line
/// carries a list marker.
fn key_indent(line: &str) -> usize {
    let i = indent(line);
    if line.trim_start().starts_with("- ") {
        i + 2
    } else {
        i
    }
}

/// The `default:` of an input in the action definition. `inputs:` is a mapping of name to a
/// mapping carrying `default:`, so the default sought is the first one at a deeper indent
/// after the named key.
pub fn action_default(action_src: &str, input: &str) -> Result<String> {
    let mut lines = action_src.lines().enumerate();
    let mut at = None;
    for (i, l) in lines.by_ref() {
        if scalar(l, input) == Some("") && indent(l) > 0 {
            at = Some((i, indent(l)));
            break;
        }
    }
    let Some((_, key_indent)) = at else {
        bail!("{ACTION}: no input {input:?}");
    };
    for (_, l) in lines {
        if l.trim().is_empty() {
            continue;
        }
        if indent(l) <= key_indent {
            break;
        }
        if let Some(v) = scalar(l, "default") {
            return Ok(v.to_string());
        }
    }
    bail!("{ACTION}: input {input:?} declares no default")
}

/// Every gatehouse-action step in one workflow, paired with the `timeout-minutes` of the job
/// it sits in.
///
/// Line-oriented on purpose: the same shape `gatehouse_pin.rs` and `fly_pools.rs` use, and it
/// keeps the gate free of a YAML dependency for a file whose relevant lines are flat scalars.
/// A `timeout-minutes` is attributed to the most recent one seen above the step, which is the
/// job's because a step-level one would be nearer — and a step-level `timeout-minutes` is
/// STRICTER than the job's, so taking the nearest is the conservative reading either way.
pub fn sites(workflow_src: &str, default_timeout_s: u64, default_compare: bool) -> Vec<Site> {
    let lines: Vec<&str> = workflow_src.lines().collect();
    let mut out = Vec::new();
    let mut budget: Option<(u64, usize)> = None;

    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(v) = scalar(line, "timeout-minutes")
            && let Ok(m) = v.parse::<u64>()
        {
            budget = Some((m * 60, i + 1));
        }
        if scalar(line, "uses") != Some(USES) {
            continue;
        }
        let Some((job_budget_s, line_no)) = budget else {
            continue;
        };
        // The rest of this step. `with:` is a SIBLING of `uses:`, not a child, so the block
        // runs to the first line shallower than the step's own keys — the next list item's
        // marker. Breaking at `<=` instead stopped at `with:` and read neither input, which is
        // how this gate first reported the action's defaults over a step that overrode them.
        let step_indent = key_indent(line);
        let mut timeout_s = default_timeout_s;
        let mut compare = default_compare;
        for l in &lines[i + 1..] {
            if l.trim().is_empty() || l.trim_start().starts_with('#') {
                continue;
            }
            // The next list item's marker sits SHALLOWER than the keys it introduces, so
            // the raw indent is what ends the step; comparing key indents would tie with the
            // next `- name:` and run the two steps together.
            if indent(l) < step_indent {
                break;
            }
            if let Some(v) = scalar(l, "timeout")
                && let Ok(s) = v.parse::<u64>()
            {
                timeout_s = s;
            }
            if let Some(v) = scalar(l, "compare") {
                compare = v != "false";
            }
        }
        out.push(Site {
            job_budget_s,
            timeout_s,
            compare,
            line: line_no,
        });
    }
    out
}

/// Workflows that use the action but are not in [`WORKFLOWS`]. A gate this file does not know
/// about is a gate it silently exempts — the shape `check-gates-can-fail.sh` exists to refuse.
fn unlisted_users(root: &Path) -> Result<Vec<String>> {
    let dir = root.join(".github/workflows");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let p = entry?.path();
        if p.extension().is_none_or(|e| e != "yml") {
            continue;
        }
        let Ok(src) = fs::read_to_string(&p) else {
            continue;
        };
        let uses = src
            .lines()
            .any(|l| !l.trim_start().starts_with('#') && scalar(l, "uses") == Some(USES));
        if !uses {
            continue;
        }
        let rel = format!(
            ".github/workflows/{}",
            p.file_name().unwrap().to_string_lossy()
        );
        if !WORKFLOWS.contains(&rel.as_str()) {
            out.push(rel);
        }
    }
    out.sort();
    Ok(out)
}

pub fn check(root: &Path) -> Result<()> {
    let action =
        fs::read_to_string(root.join(ACTION)).with_context(|| format!("reading {ACTION}"))?;
    let default_timeout_s: u64 = action_default(&action, "timeout")?
        .parse()
        .context("the action's default timeout is not a number of seconds")?;
    let default_compare = action_default(&action, "compare")? != "false";
    println!("{ACTION} defaults: timeout {default_timeout_s}s, compare {default_compare}");

    let extra = unlisted_users(root)?;
    if !extra.is_empty() {
        bail!(
            "these workflows run a gate through {USES} but are not checked here: {}.\n\
             Add them to WORKFLOWS. A budget this gate does not read is a budget nothing \
             compares.",
            extra.join(", ")
        );
    }

    let mut total = 0usize;
    let mut bad = Vec::new();
    for wf in WORKFLOWS {
        let src = fs::read_to_string(root.join(wf)).with_context(|| format!("reading {wf}"))?;
        let sites = sites(&src, default_timeout_s, default_compare);
        if sites.is_empty() {
            bail!(
                "{wf}: found no `uses: {USES}` step under a `timeout-minutes`. Either the \
                 workflow stopped using the action, or this parser stopped seeing it — and a \
                 gate that measures nothing passes everything."
            );
        }
        for s in &sites {
            total += 1;
            let verdict = if s.fits() { "ok  " } else { "FAIL" };
            println!(
                "  {verdict} {wf}:{}  job {}s, gate {}s x{} + {SETUP_ALLOWANCE_S}s setup = {}s",
                s.line,
                s.job_budget_s,
                s.timeout_s,
                s.runs(),
                s.need_s()
            );
            if !s.fits() {
                bad.push(format!(
                    "{wf}:{}: the job allows {}s; the gate declares {}s and runs it {} time(s) \
                     ({}), needing {}s with setup.\n\
                     \x20 The runner's timeout can never fire first, so a gate that overruns is \
                     killed by GitHub and reported as `cancelled` — indistinguishable from an \
                     infrastructure fault, and carrying no verdict. Lower the action's `timeout` \
                     so it fits, or raise `timeout-minutes` so the runner reports before GitHub \
                     does.",
                    s.line,
                    s.job_budget_s,
                    s.timeout_s,
                    s.runs(),
                    if s.compare {
                        "compare is on, so the command runs twice"
                    } else {
                        "compare off"
                    },
                    s.need_s()
                ));
            }
        }
    }

    if !bad.is_empty() {
        bail!(
            "{} gate budget(s) cannot fire:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }
    println!("ok: all {total} gate budget(s) leave room for the runner to report first");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn reads_the_real_action_defaults() {
        let action = fs::read_to_string(root().join(ACTION)).unwrap();
        assert!(
            action_default(&action, "timeout")
                .unwrap()
                .parse::<u64>()
                .is_ok()
        );
        let c = action_default(&action, "compare").unwrap();
        assert!(c == "true" || c == "false", "compare default {c:?}");
    }

    #[test]
    fn the_real_workflow_has_sites() {
        let src = fs::read_to_string(root().join(WORKFLOWS[0])).unwrap();
        assert!(
            !sites(&src, 3600, true).is_empty(),
            "the parser must see the shipped step"
        );
    }

    /// The measured defect, frozen: 45 minutes of job, 45 minutes of gate, compare on.
    #[test]
    fn the_2026_09_11_shape_does_not_fit() {
        let s = Site {
            job_budget_s: 45 * 60,
            timeout_s: 2700,
            compare: true,
            line: 1,
        };
        assert_eq!(s.runs(), 2);
        assert_eq!(s.need_s(), 5460);
        assert!(!s.fits());
    }

    /// Equality is a failure, not a pass: setup alone pushes it over.
    #[test]
    fn exactly_the_job_budget_does_not_fit() {
        let s = Site {
            job_budget_s: 2700,
            timeout_s: 2700,
            compare: false,
            line: 1,
        };
        assert!(!s.fits());
    }

    #[test]
    fn room_for_two_runs_and_setup_fits() {
        let s = Site {
            job_budget_s: 45 * 60,
            timeout_s: 1200,
            compare: true,
            line: 1,
        };
        assert_eq!(s.need_s(), 2460);
        assert!(s.fits());
    }

    /// `compare: false` halves the need, and the parser must see it.
    #[test]
    fn compare_false_is_read_from_the_step() {
        let wf = "jobs:\n  j:\n    timeout-minutes: 10\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          timeout: \"500\"\n          compare: \"false\"\n";
        let s = sites(wf, 3600, true);
        assert_eq!(s.len(), 1);
        assert!(!s[0].compare);
        assert_eq!(s[0].timeout_s, 500);
        assert!(s[0].fits());
    }

    /// An omitted `timeout` takes the action's default, which is larger than most jobs.
    #[test]
    fn an_omitted_timeout_takes_the_action_default() {
        let wf = "jobs:\n  j:\n    timeout-minutes: 45\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          run: cargo test\n";
        let s = sites(wf, 3600, true);
        assert_eq!(s[0].timeout_s, 3600);
        assert!(!s[0].fits(), "3600s twice cannot fit a 45-minute job");
    }

    /// A commented-out step is not a step.
    #[test]
    fn commented_lines_are_not_sites() {
        let wf = "jobs:\n  j:\n    timeout-minutes: 45\n    steps:\n      # - uses: ./.github/actions/gatehouse\n";
        assert!(sites(wf, 3600, true).is_empty());
    }

    // ---- `check` end to end, against a temp tree -------------------------------------
    //
    // `check` takes its root as an argument, so the whole verdict — including the two
    // refusals that have no live subject to perturb — can be exercised without the real
    // repository. These were written because the module shipped at 66% line coverage and
    // the untested third was `check` itself: the part that decides.

    const ACTION_YML: &str = "\
inputs:
  timeout:
    description: \"Seconds.\"
    required: false
    default: \"3600\"
  compare:
    description: \"Run it plainly too.\"
    required: false
    default: \"true\"
";

    fn tree(dir: &Path, action: &str, workflows: &[(&str, &str)]) {
        fs::create_dir_all(dir.join(".github/actions/gatehouse")).unwrap();
        fs::create_dir_all(dir.join(".github/workflows")).unwrap();
        fs::write(dir.join(ACTION), action).unwrap();
        for (name, body) in workflows {
            fs::write(dir.join(".github/workflows").join(name), body).unwrap();
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("xtask-gate-budget-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn shadow(job_minutes: u32, timeout: &str) -> String {
        format!(
            "jobs:\n  shadow:\n    timeout-minutes: {job_minutes}\n    steps:\n      - name: gate\n        uses: {USES}\n        with:\n          run: cargo clippy\n          timeout: \"{timeout}\"\n"
        )
    }

    #[test]
    fn check_passes_when_the_runner_reports_first() {
        let d = tmp("ok");
        tree(
            &d,
            ACTION_YML,
            &[("gatehouse-shadow.yml", &shadow(45, "1200"))],
        );
        check(&d).expect("1200 x2 + setup fits inside 45 minutes");
    }

    #[test]
    fn check_fails_on_the_measured_defect() {
        let d = tmp("defect");
        tree(
            &d,
            ACTION_YML,
            &[("gatehouse-shadow.yml", &shadow(45, "2700"))],
        );
        let e = check(&d).expect_err("2700 x2 cannot fit a 2700s job");
        let msg = e.to_string();
        assert!(msg.contains("cannot fire"), "{msg}");
    }

    /// The action's own default applies when the step omits `timeout`, and 3600 twice
    /// cannot fit any job this repository declares.
    #[test]
    fn check_uses_the_action_default_when_the_step_is_silent() {
        let d = tmp("default");
        let wf = format!(
            "jobs:\n  shadow:\n    timeout-minutes: 45\n    steps:\n      - uses: {USES}\n        with:\n          run: cargo clippy\n"
        );
        tree(&d, ACTION_YML, &[("gatehouse-shadow.yml", &wf)]);
        assert!(
            check(&d).is_err(),
            "the 3600s default must be read and refused"
        );
    }

    /// A workflow using the action but not listed is a budget nothing compares.
    #[test]
    fn check_refuses_an_unlisted_user_of_the_action() {
        let d = tmp("unlisted");
        tree(
            &d,
            ACTION_YML,
            &[
                ("gatehouse-shadow.yml", &shadow(45, "1200")),
                ("sneaky.yml", &shadow(45, "1200")),
            ],
        );
        let e = check(&d).expect_err("an unlisted workflow must red");
        assert!(e.to_string().contains("sneaky.yml"), "{e}");
    }

    /// A gate that measures nothing passes everything, so finding no site is a refusal.
    #[test]
    fn check_refuses_a_workflow_with_no_site() {
        let d = tmp("nosite");
        tree(
            &d,
            ACTION_YML,
            &[(
                "gatehouse-shadow.yml",
                "jobs:\n  shadow:\n    timeout-minutes: 45\n    steps:\n      - run: echo hi\n",
            )],
        );
        let e = check(&d).expect_err("no site is not a pass");
        assert!(e.to_string().contains("found no"), "{e}");
    }

    #[test]
    fn check_reports_a_missing_action_definition() {
        let d = tmp("noaction");
        fs::create_dir_all(d.join(".github/workflows")).unwrap();
        assert!(
            check(&d).is_err(),
            "an absent action definition is not a pass"
        );
    }

    #[test]
    fn an_input_without_a_default_is_an_error() {
        let src = "inputs:\n  timeout:\n    description: \"no default here\"\n";
        assert!(action_default(src, "timeout").is_err());
        assert!(action_default(src, "nonexistent").is_err());
    }
}
