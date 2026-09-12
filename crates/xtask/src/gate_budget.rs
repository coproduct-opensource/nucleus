//! `cargo xtask gate-budget` — a gate's own timeout must be able to fire before the job
//! running it is killed.
//!
//! `.github/workflows/gatehouse-shadow.yml` runs each gate through the one-step gatehouse
//! action, which takes a `timeout` (seconds the command may take) and is supposed to enforce
//! it. The job
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
//! runs * timeout_s + OUTER_SLACK_S + SETUP_ALLOWANCE_S  <  timeout-minutes * 60
//! ```
//!
//! where `runs` is 2 when `compare` is on and 1 otherwise. Strict: equality is the defect
//! above, not the boundary case that just fits.
//!
//! `OUTER_SLACK_S` is not decoration. The action does not bound the runner at `timeout_s`; it
//! bounds it at `timeout_s + 120`, deliberately, so the runner can hit its OWN deadline first
//! and write an honest `errored` receipt instead of being killed mid-write. That slack is real
//! wall time and the job must hold it, so the arithmetic that claims to describe a bound has to
//! contain it. Counting `runs * timeout_s` alone described a bound 120 seconds tighter than the
//! one the action actually enforces — the same shape of error, one level down, as declaring a
//! budget the runner never honoured.
//!
//! Both defaults — `timeout` and `compare` — are read from `.github/actions/gatehouse/action.yml`
//! rather than repeated here. A second copy of a default is a second thing to drift, which is
//! the failure this family of gates exists to refuse; `fly_pools.rs` calls the manager's own
//! validator for the same reason.
//!
//! # What this gate does NOT fix, measured
//!
//! Lowering the declared timeout so it fits is necessary and **not sufficient**. Measured
//! 2026-09-11 on run `34637222980`, with `timeout: "1200"` confirmed reaching the runner as
//! `GH_TIMEOUT: 1200`: the gate step ran **44m35s** and was killed by the job's 45-minute cap
//! with no verdict — `duration_ms=2675520`, against `2676029` for the original 2700s run.
//! **Half a second apart.** The runner produced nothing after its tenant line in either case,
//! and the only occurrences of "timeout" in 998 log lines are the input and env echoes.
//!
//! So the runner does not enforce its own declared timeout, and no value of `timeout` makes it
//! report first. That is a defect one level below this gate, in gatehouse's runner rather than
//! in nucleus's declarations.
//!
//! This gate is still right, and the distinction matters: it decides whether the DECLARATIONS
//! are coherent, and a budget that cannot fit inside the job running it is incoherent whether
//! or not the runner would have honoured it. What must not be claimed is that fixing the
//! arithmetic makes an overrun report — it did not, and the first version of this module said
//! it would.
//!
//! # The second conjunct: a job with no budget at all
//!
//! `timeout-minutes` is optional, and a job that omits it inherits GitHub's default of
//! **360 minutes** — six hours of a runner held by a job that has hung. On a self-hosted
//! pool already measured starving (gatehouse F-79), that is the cost that matters.
//!
//! **What already existed, and what this adds.** `ci-spec`'s `CI-I7-NOTIMEOUT`
//! (`crates/ci-spec/src/invariants/timeouts.rs`) already finds untimed jobs, and its rationale
//! is sharper than this one: it filters to workflows triggered by `merge_group`, because those
//! are the jobs whose 360-minute default equals the queue's own `check_response_timeout_minutes`
//! and therefore ejects a queue entry. It founds that on a real stall (2026-09-04/05). It
//! reports **5** such jobs at `Severity::Medium`, which prints as `info` and does **not** fail.
//!
//! So this conjunct is not the first to look. It differs in two ways worth stating plainly:
//! it covers every workflow rather than only `merge_group` ones (23 against those 5, which are
//! a strict subset), and being a pinned population it **fails** rather than advising, so the
//! set cannot grow while the 23 individual judgements are made.
//!
//! A correction belongs here too, because the wrong belief is more useful than the fix: two
//! loops before this was written I tested the 360-minute tie, asked whether any REQUIRED
//! context came from an untimed job, found none, and concluded it was not live. The right
//! population was `merge_group`-triggered jobs, not required contexts — there are 5, and
//! `CI-I7` had been saying so. Checking the wrong set and reading the empty answer as absence
//! is the same error as trusting a gate's name over its log.
//!
//! Measured 2026-09-11: **147 jobs, 124 declaring a timeout, 23 not.** None of the 23
//! produces a required context, so a hang there cannot block the merge queue on a required
//! check — which is why this is a ratchet (`ci/untimed-jobs.txt`, shrink-only) rather than a
//! repair. The repair is 23 separate judgements about the right timeout for each job, and a
//! wrong number fails honest jobs. The ratchet buys the thing that is urgent: the population
//! cannot GROW while those judgements are made.
//!
//! # What decides this
//!
//! Two committed YAML files. No source tree, no toolchain, no network, and the same verdict
//! against an empty checkout of nucleus. See gatehouse `docs/tiering.md`.

use std::collections::BTreeSet;
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

/// The action's outer deadline sits this far above the gate's own `timeout`, so the runner gets
/// to fire first and report. `.github/actions/gatehouse/gatehouse.sh`, the `timeout --kill-after`
/// around `$RUNNER`: `$(( GH_TIMEOUT + 120 ))`. Applied once, not per run — only the gatehouse
/// run carries it; the plain `compare` run is bounded at `GH_TIMEOUT` exactly, because it has no
/// receipt to write and nothing to wait for.
const OUTER_SLACK_S: u64 = 120;

/// Jobs allowed to declare no `timeout-minutes`. Shrink-only.
const UNTIMED_PIN: &str = "ci/untimed-jobs.txt";
/// What GitHub gives a job that declares none.
const GITHUB_DEFAULT_MINUTES: u64 = 360;

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
    /// How many times the command runs under `timeout_s`.
    ///
    /// **This counts on something the action must do, and saying so here is the point.**
    /// `runs = 2` is only arithmetic about a real bound if BOTH invocations are actually
    /// bounded — the runner AND the plain `compare` run. `gatehouse.sh` bounds both, and
    /// that change shipped in the same pull request as this gate purely because one author
    /// wrote both. They are separate facts.
    ///
    /// If the compare run ever loses its bound, this stays green while the second run is
    /// unbounded — the gate would be checking an arithmetic whose operands no longer
    /// describe anything, which is the failure gatehouse F-103 records after nucleus #2856
    /// arrived with a better outer-deadline fix that did not bound the compare run.
    ///
    /// A reader who changes `gatehouse.sh` should change this model with it, or explain why
    /// it still holds.
    pub fn runs(&self) -> u64 {
        if self.compare { 2 } else { 1 }
    }
    pub fn need_s(&self) -> u64 {
        self.runs() * self.timeout_s + OUTER_SLACK_S + SETUP_ALLOWANCE_S
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

/// Every job in one workflow that declares no job-level `timeout-minutes`.
///
/// A job key sits at indent 2 under a column-0 `jobs:`; its own keys are at indent 4. A
/// `timeout-minutes` deeper than that belongs to a STEP, and a step's timeout does not bound
/// the job — so the match is anchored to indent 4 exactly.
pub fn jobs_without_timeout(workflow_src: &str) -> Vec<String> {
    let lines: Vec<&str> = workflow_src.lines().collect();
    let Some(start) = lines.iter().position(|l| l.trim_end() == "jobs:") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut current: Option<(String, bool)> = None;
    for l in &lines[start + 1..] {
        if !l.is_empty() && !l.starts_with(' ') && !l.starts_with('#') {
            break;
        }
        let job_key = l
            .strip_prefix("  ")
            .filter(|r| !r.starts_with(' ') && !r.starts_with('#'))
            .and_then(|r| r.strip_suffix(':'))
            .filter(|n| !n.is_empty());
        if let Some(name) = job_key {
            if let Some((n, seen)) = current.take()
                && !seen
            {
                out.push(n);
            }
            current = Some((name.to_string(), false));
        } else if l.starts_with("    timeout-minutes:")
            && let Some((_, seen)) = current.as_mut()
        {
            *seen = true;
        }
    }
    if let Some((n, seen)) = current
        && !seen
    {
        out.push(n);
    }
    out
}

/// `file.yml:job` lines, `#` comments ignored.
pub fn untimed_pin(src: &str) -> Vec<String> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// The second conjunct. Returns failure messages; empty when it holds.
fn check_untimed(root: &Path) -> Result<Vec<String>> {
    let pin_src = fs::read_to_string(root.join(UNTIMED_PIN))
        .with_context(|| format!("reading {UNTIMED_PIN}"))?;
    let allowed: BTreeSet<String> = untimed_pin(&pin_src).into_iter().collect();
    // An empty pin is NOT refused: it is where a shrink-only ratchet is trying to get, and
    // a gate that reds on its own success state teaches people to keep a spare entry. The
    // non-vacuity that matters is the file existing at all, which `read_to_string` enforces
    // above, plus the stale-entry direction below.

    let dir = root.join(".github/workflows");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "yml"))
        .collect();
    files.sort();
    if files.is_empty() {
        bail!(".github/workflows: no workflows read — a sweep of nothing allows everything");
    }

    let mut found = BTreeSet::new();
    for f in &files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        for job in jobs_without_timeout(&fs::read_to_string(f)?) {
            found.insert(format!("{name}:{job}"));
        }
    }

    let mut out = Vec::new();
    for j in found.difference(&allowed) {
        out.push(format!(
            "{j} declares no `timeout-minutes`, so it inherits GitHub's {GITHUB_DEFAULT_MINUTES}-minute default — six hours of a runner for a job that has hung. Give it a timeout; if it genuinely needs none, add it to {UNTIMED_PIN} and say why, dated."
        ));
    }
    for j in allowed.difference(&found) {
        out.push(format!(
            "{UNTIMED_PIN} lists {j}, which now declares a timeout or no longer exists. Delete the line — this list may only shrink, and a stale entry is slack the next job inherits."
        ));
    }
    // Only when it HOLDS. Printing "all pinned" beside a failure is a gate reporting the
    // opposite of its own verdict, which is the shape this whole family exists to refuse.
    if out.is_empty() {
        println!(
            "  ok   {} job(s) without a timeout, all pinned",
            found.len()
        );
    }
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
                "  {verdict} {wf}:{}  job {}s, gate {}s x{} + {OUTER_SLACK_S}s slack + {SETUP_ALLOWANCE_S}s setup = {}s",
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

    bad.extend(check_untimed(root)?);

    if !bad.is_empty() {
        bail!("{} budget problem(s):\n{}", bad.len(), bad.join("\n"));
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
        assert_eq!(s.need_s(), 5580);
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
        assert_eq!(s.need_s(), 2580);
        assert!(s.fits());
    }

    /// The outer slack has to change a verdict somewhere, or it is a constant that costs nothing
    /// and proves nothing. 1300s twice is 2600s, and 2660s with setup — inside a 2700s job. The
    /// action's deadline is 1420s, not 1300s, so the real worst case is 2780s and the job kills
    /// it. Without `OUTER_SLACK_S` this site passes, and the pass is wrong.
    #[test]
    fn the_outer_slack_is_what_decides_this_site() {
        let s = Site {
            job_budget_s: 2700,
            timeout_s: 1300,
            compare: true,
            line: 1,
        };
        assert_eq!(s.runs() * s.timeout_s + SETUP_ALLOWANCE_S, 2660);
        assert_eq!(s.need_s(), 2780);
        assert!(!s.fits());
    }

    /// `compare: false` halves the need, and the parser must see it.
    #[test]
    fn compare_false_is_read_from_the_step() {
        let wf = "jobs:\n  j:\n    timeout-minutes: 15\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          timeout: \"500\"\n          compare: \"false\"\n";
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
        fs::create_dir_all(dir.join("ci")).unwrap();
        fs::write(dir.join(ACTION), action).unwrap();
        for (name, body) in workflows {
            fs::write(dir.join(".github/workflows").join(name), body).unwrap();
        }
        // Every job in these fixtures declares a timeout, so the pin is legitimately empty.
        fs::write(dir.join(UNTIMED_PIN), "# no untimed jobs in this fixture\n").unwrap();
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
        // Assert on the per-site explanation, not the summary line: the summary counts
        // problems from both conjuncts and its wording is not this conjunct's claim.
        assert!(msg.contains("can never fire first"), "{msg}");
        assert!(msg.contains("5580s"), "the arithmetic must be shown: {msg}");
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

    // ---- the second conjunct: jobs with no budget at all ---------------------------

    #[test]
    fn a_job_without_a_timeout_is_found() {
        let wf = "jobs:\n  a:\n    runs-on: x\n  b:\n    timeout-minutes: 5\n    runs-on: x\n";
        assert_eq!(jobs_without_timeout(wf), vec!["a".to_string()]);
    }

    /// A STEP's timeout does not bound the job, so it must not count as one.
    #[test]
    fn a_step_level_timeout_does_not_count_for_the_job() {
        let wf = "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n        timeout-minutes: 5\n";
        assert_eq!(jobs_without_timeout(wf), vec!["a".to_string()]);
    }

    /// The `jobs:` mapping ends at the next column-0 key; nothing after it is a job.
    #[test]
    fn keys_after_the_jobs_mapping_are_not_jobs() {
        let wf = "jobs:\n  a:\n    timeout-minutes: 5\n    runs-on: x\nconcurrency:\n  group: g\n";
        assert!(jobs_without_timeout(wf).is_empty());
    }

    #[test]
    fn a_workflow_with_no_jobs_key_yields_nothing() {
        assert!(jobs_without_timeout("name: x\non: push\n").is_empty());
    }

    #[test]
    fn the_last_job_is_not_dropped() {
        let wf = "jobs:\n  a:\n    timeout-minutes: 5\n  b:\n    runs-on: x\n";
        assert_eq!(jobs_without_timeout(wf), vec!["b".to_string()]);
    }

    #[test]
    fn the_pin_ignores_comments_and_blanks() {
        let p = untimed_pin("# note\n\na.yml:one\nb.yml:two\n");
        assert_eq!(p, vec!["a.yml:one".to_string(), "b.yml:two".to_string()]);
    }

    /// The shipped tree: the pin and the sweep agree, in both directions.
    #[test]
    fn the_shipped_pin_matches_the_shipped_workflows() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let problems = check_untimed(&root).expect("the pin must be readable");
        assert!(
            problems.is_empty(),
            "the shipped pin and the shipped workflows disagree:\n  {}",
            problems.join("\n  ")
        );
    }

    #[test]
    fn an_input_without_a_default_is_an_error() {
        let src = "inputs:\n  timeout:\n    description: \"no default here\"\n";
        assert!(action_default(src, "timeout").is_err());
        assert!(action_default(src, "nonexistent").is_err());
    }
}
