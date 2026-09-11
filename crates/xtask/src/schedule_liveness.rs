//! `cargo xtask schedule-liveness` — a gate that is not running looks exactly
//! like a gate that is passing.
//!
//! `ci-assurance.yml` is `cron: "17,47 * * * *"`. On 2026-09-09 its scheduled
//! runs stopped firing for roughly four hours — about seven runs that were **not
//! failed, not cancelled: never created**. GitHub's scheduled runs share a
//! queued infrastructure and a run is dropped entirely under heavy load, with no
//! run, no error and no notification.
//!
//! So the drift detector goes quiet precisely when the repository is busiest,
//! which is when a pin is most likely to be changed. #2652 records it, and names
//! the remedy this module implements: *if the newest conclusion is older than
//! some multiple of the period, that is itself a finding.*
//!
//! ADR 0007 **A-5**: absence is a third value, never a pass. The whole family of
//! "did every declared thing report?" questions is a set difference over the
//! declared set, never a conjunction over what happened to arrive — and here the
//! declared set has exactly one member and it still went unnoticed.
//!
//! # What is pure and what is not
//!
//! The decision is pure: [`Period::from_cron`] reads the schedule out of the
//! workflow, and [`verdict`] compares an age against a tolerance. Both are
//! tested without a network. Only fetching the newest run touches GitHub, and it
//! reuses [`crate::ci_spec::CouldNotLook`] so "could not ask" keeps saying which
//! thing to fix rather than collapsing into a pass.

use std::time::Duration;

/// How often the schedule is declared to fire.
///
/// Read from the workflow rather than restated here (ADR 0007 F-3 and G-1: a
/// count is never written a second time beside the thing it counts). The
/// tolerance is derived from this, so a schedule change moves the gate with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Period {
    /// The largest gap between consecutive firings.
    Every(Duration),
    /// A cron this does not interpret.
    ///
    /// Refusing is the point. Inventing a default tolerance for a schedule we
    /// cannot read would produce a staleness verdict that means nothing — the
    /// exact vacuity this gate exists to remove (A-2).
    Unsupported { cron: String, why: String },
}

impl Period {
    /// Derive the period from a five-field cron expression.
    ///
    /// Only the shape this repository actually uses is interpreted: a minute
    /// field that is a comma list or a `*/n` step, with the remaining four
    /// fields `*`. Anything else is [`Period::Unsupported`] by name.
    pub fn from_cron(cron: &str) -> Self {
        let unsupported = |why: &str| Period::Unsupported {
            cron: cron.to_string(),
            why: why.to_string(),
        };
        let fields: Vec<&str> = cron.split_whitespace().collect();
        if fields.len() != 5 {
            return unsupported("not five fields");
        }
        if fields[1..].iter().any(|f| *f != "*") {
            return unsupported(
                "hour/day/month/weekday are not all `*`; the gap between firings is not \
                 determined by the minute field alone",
            );
        }
        let minute = fields[0];

        let mut firings: Vec<u32> = Vec::new();
        if let Some(step) = minute.strip_prefix("*/") {
            let Ok(n) = step.parse::<u32>() else {
                return unsupported("step is not a number");
            };
            if n == 0 || n > 59 {
                return unsupported("step out of range");
            }
            firings.extend((0..60).step_by(n as usize));
        } else if minute == "*" {
            firings.extend(0..60);
        } else {
            for part in minute.split(',') {
                let Ok(m) = part.trim().parse::<u32>() else {
                    return unsupported("minute list holds something that is not a number");
                };
                if m > 59 {
                    return unsupported("minute out of range");
                }
                firings.push(m);
            }
        }
        if firings.is_empty() {
            return unsupported("no firings");
        }
        firings.sort_unstable();
        firings.dedup();

        // The LARGEST gap, not the average: the tolerance has to cover the
        // longest legitimate quiet stretch or the gate cries wolf every hour.
        // Wrapping across the hour boundary is a real gap and is included.
        let mut largest = 0u32;
        for pair in firings.windows(2) {
            largest = largest.max(pair[1] - pair[0]);
        }
        let wrap = 60 - firings[firings.len() - 1] + firings[0];
        largest = largest.max(wrap);
        Period::Every(Duration::from_secs(u64::from(largest) * 60))
    }
}

/// Whether the schedule was observed to have run recently enough.
///
/// Three states, not a `bool` (A-1). `NeverRan` is kept apart from `Stale`
/// because they are different findings: one says the schedule stopped, the other
/// says it never started, and a repository that has just enabled a workflow is
/// in the second state legitimately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    Fresh { age: Duration, tolerance: Duration },
    Stale { age: Duration, tolerance: Duration },
    NeverRan { tolerance: Duration },
}

/// Compare the newest run's age against the tolerance.
///
/// `multiple` is how many periods may pass before absence is a finding. It is a
/// parameter rather than a constant because the right value is a judgement about
/// how flaky the shared cron queue is, and that belongs at the call site where
/// it can be written down.
pub fn verdict(newest_age: Option<Duration>, period: Duration, multiple: u32) -> Liveness {
    let tolerance = period * multiple;
    match newest_age {
        None => Liveness::NeverRan { tolerance },
        Some(age) if age > tolerance => Liveness::Stale { age, tolerance },
        Some(age) => Liveness::Fresh { age, tolerance },
    }
}

/// Render a verdict and give the exit code. 0 clean, 1 a finding, 2 could not
/// look — the third is never a pass.
pub fn report(liveness: &Liveness, workflow: &str) -> i32 {
    let mins = |d: Duration| d.as_secs() / 60;
    match liveness {
        Liveness::Fresh { age, tolerance } => {
            println!(
                "ok: `{workflow}` last concluded {}m ago (tolerance {}m)",
                mins(*age),
                mins(*tolerance)
            );
            0
        }
        Liveness::Stale { age, tolerance } => {
            eprintln!(
                "::error::`{workflow}` has not concluded for {}m, tolerance is {}m.",
                mins(*age),
                mins(*tolerance)
            );
            eprintln!(
                "  A scheduled run that is never CREATED is not failed and not cancelled -- \
                 GitHub drops them under load, with no run and no notification. Nothing else \
                 in this repository notices, which is why this check exists (#2652).\n  \
                 fix: dispatch it manually to confirm it still works, then decide whether the \
                 schedule needs an external trigger rather than the shared cron queue."
            );
            1
        }
        Liveness::NeverRan { tolerance } => {
            eprintln!(
                "::error::`{workflow}` has no recorded conclusion at all (tolerance {}m).",
                mins(*tolerance)
            );
            eprintln!(
                "  Distinct from stale on purpose: this says the schedule never started, not \
                 that it stopped. If the workflow was just added, run it once."
            );
            1
        }
    }
}

/// Ask GitHub when `workflow` last concluded, and judge it.
///
/// The I/O boundary, deliberately thin: everything above this is pure and
/// tested without a network. A failure to ask reuses [`CouldNotLook`] so it
/// still names which thing to fix, and exits 2 — never a pass.
pub fn run(repo: &str, workflow: &str, multiple: u32) -> i32 {
    let root = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("::error::schedule-liveness could not look: cwd: {e}");
            return 2;
        }
    };
    let wf = root.join(".github/workflows").join(workflow);
    let text = match std::fs::read_to_string(&wf) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "::error::schedule-liveness could not look: {}: {e}",
                wf.display()
            );
            eprintln!("  fix: name a workflow file that exists under .github/workflows");
            return 2;
        }
    };
    let Some(cron) = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("- cron:"))
        .map(|c| c.trim().trim_matches('"').trim_matches('\'').to_string())
    else {
        eprintln!("::error::schedule-liveness could not look: {workflow} declares no `cron:`");
        eprintln!(
            "  fix: this gate is for scheduled workflows; a workflow with no schedule has nothing to be stale about"
        );
        return 2;
    };

    let period = match Period::from_cron(&cron) {
        Period::Every(d) => d,
        Period::Unsupported { cron, why } => {
            eprintln!("::error::schedule-liveness could not look: cron `{cron}` -- {why}");
            eprintln!(
                "  fix: extend `Period::from_cron`. Defaulting the tolerance would make the \
                 verdict a guess wearing a measurement's clothes."
            );
            return 2;
        }
    };

    let out = std::process::Command::new("gh")
        .args([
            "api",
            &format!("repos/{repo}/actions/workflows/{workflow}/runs?status=completed&per_page=1"),
            "--jq",
            ".workflow_runs[0].updated_at // empty",
        ])
        .output();
    let newest = match out {
        Err(e) => {
            let e = crate::ci_spec::CouldNotLook::ToolMissing {
                tool: "gh".to_string(),
                detail: e.to_string(),
            };
            eprintln!("::error::schedule-liveness could not look: {e}");
            eprintln!("  fix: {}", e.repair());
            return 2;
        }
        Ok(o) if !o.status.success() => {
            let e = crate::ci_spec::CouldNotLook::from_gh_failure(
                &format!("repos/{repo}/actions/workflows/{workflow}/runs"),
                &String::from_utf8_lossy(&o.stderr),
            );
            eprintln!("::error::schedule-liveness could not look: {e}");
            eprintln!("  fix: {}", e.repair());
            return 2;
        }
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
    };

    let age = if newest.is_empty() {
        None
    } else {
        match chrono::DateTime::parse_from_rfc3339(&newest) {
            Ok(t) => {
                let secs = (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds();
                Some(Duration::from_secs(secs.max(0) as u64))
            }
            Err(e) => {
                eprintln!(
                    "::error::schedule-liveness could not look: `{newest}` is not RFC3339: {e}"
                );
                eprintln!(
                    "  fix: GitHub changed the run timestamp format; that is a code change here"
                );
                return 2;
            }
        }
    };

    report(&verdict(age, period, multiple), workflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real schedule in `ci-assurance.yml`. Two firings an hour, 30 minutes
    /// apart both ways, so the period is 30 minutes.
    #[test]
    fn the_ci_assurance_cron_is_every_thirty_minutes() {
        assert_eq!(
            Period::from_cron("17,47 * * * *"),
            Period::Every(Duration::from_secs(30 * 60))
        );
    }

    /// The gap that wraps midnight is a real gap. `5,10` fires twice in six
    /// minutes and then waits fifty-five, and a tolerance built from the small
    /// gap would red every hour.
    #[test]
    fn the_gap_that_wraps_the_hour_is_the_one_that_counts() {
        assert_eq!(
            Period::from_cron("5,10 * * * *"),
            Period::Every(Duration::from_secs(55 * 60)),
        );
    }

    #[test]
    fn a_step_and_a_bare_star_are_both_read() {
        assert_eq!(
            Period::from_cron("*/15 * * * *"),
            Period::Every(Duration::from_secs(15 * 60))
        );
        assert_eq!(
            Period::from_cron("* * * * *"),
            Period::Every(Duration::from_secs(60))
        );
        assert_eq!(
            Period::from_cron("0 * * * *"),
            Period::Every(Duration::from_secs(60 * 60))
        );
    }

    /// A-2. A cron we cannot read must not acquire a default tolerance: the
    /// verdict would look like a measurement and be a guess.
    #[test]
    fn a_cron_this_cannot_read_is_refused_not_defaulted() {
        for cron in ["0 3 * * 1", "17,47 * * *", "nonsense", "*/0 * * * *"] {
            assert!(
                matches!(Period::from_cron(cron), Period::Unsupported { .. }),
                "{cron} must be refused, not given a tolerance"
            );
        }
    }

    /// THE regression. Four hours of silence on a 30-minute schedule is the
    /// 2026-09-09 outage, and it must be a finding.
    #[test]
    fn four_hours_of_silence_on_a_thirty_minute_schedule_is_a_finding() {
        let period = Duration::from_secs(30 * 60);
        let v = verdict(Some(Duration::from_secs(4 * 3600)), period, 3);
        assert!(matches!(v, Liveness::Stale { .. }), "{v:?}");
    }

    /// Non-vacuity: the test above would pass against a check that called
    /// everything stale. One missed run inside the tolerance is not a finding,
    /// because the shared cron queue is late often enough that it would be noise.
    #[test]
    fn one_late_run_inside_the_tolerance_is_not_a_finding() {
        let period = Duration::from_secs(30 * 60);
        let v = verdict(Some(Duration::from_secs(40 * 60)), period, 3);
        assert!(matches!(v, Liveness::Fresh { .. }), "{v:?}");
    }

    /// `NeverRan` is not `Stale`. A workflow just added has no conclusion and
    /// has not stopped; collapsing them would send the reader hunting an outage
    /// that never happened.
    #[test]
    fn never_ran_is_its_own_answer() {
        let v = verdict(None, Duration::from_secs(30 * 60), 3);
        assert!(matches!(v, Liveness::NeverRan { .. }), "{v:?}");
    }

    /// The boundary is inclusive on the fresh side, so a run exactly at the
    /// tolerance does not flap between verdicts on successive checks.
    #[test]
    fn exactly_at_the_tolerance_is_still_fresh() {
        let period = Duration::from_secs(30 * 60);
        let v = verdict(Some(Duration::from_secs(90 * 60)), period, 3);
        assert!(matches!(v, Liveness::Fresh { .. }), "{v:?}");
    }

    /// The gate reads the schedule out of the workflow rather than restating it,
    /// so a change to the cron moves the tolerance with it (F-3). This is the
    /// test that would fail if someone hardcoded 30 minutes here.
    #[test]
    fn the_period_comes_from_the_workflow_file_not_from_this_source() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root");
        let text = std::fs::read_to_string(root.join(".github/workflows/ci-assurance.yml"))
            .expect("ci-assurance.yml");
        let cron = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("- cron:"))
            .expect("a cron line")
            .trim()
            .trim_matches('"');
        assert!(
            matches!(Period::from_cron(cron), Period::Every(_)),
            "the committed schedule must be one this gate can read: {cron}"
        );
    }

    // ── `report` — the verdict-to-exit-code half ────────────────────────────
    //
    // Untested until now, which the coverage gate found before a reader did:
    // 91 of this file's lines were uncovered and `report` was most of them.
    // Its three arms are the whole reason the enum has three variants, so a
    // test per arm is the minimum that makes the distinction load-bearing.

    /// Fresh is the only arm that passes, and it passes with 0.
    #[test]
    fn a_fresh_schedule_exits_zero() {
        let fresh = Liveness::Fresh {
            age: Duration::from_secs(10 * 60),
            tolerance: Duration::from_secs(60 * 60),
        };
        assert_eq!(report(&fresh, "ci-assurance.yml"), 0);
    }

    /// Stale is a finding, not an error: the gate looked and did not like what
    /// it saw. Exit 1 is what reds the check.
    #[test]
    fn a_stale_schedule_exits_one() {
        let stale = Liveness::Stale {
            age: Duration::from_secs(4 * 60 * 60),
            tolerance: Duration::from_secs(60 * 60),
        };
        assert_eq!(report(&stale, "ci-assurance.yml"), 1);
    }

    /// Never-ran is also a finding, and deliberately a DIFFERENT variant from
    /// stale — "it never started" and "it stopped" want different fixes, and
    /// collapsing them is the case ADR 0007 A-1 is about. The exit code is the
    /// same; the message is not, which is why both arms exist.
    #[test]
    fn a_schedule_that_never_ran_exits_one_and_is_not_stale() {
        let never = Liveness::NeverRan {
            tolerance: Duration::from_secs(60 * 60),
        };
        assert_eq!(report(&never, "ci-assurance.yml"), 1);
        assert_ne!(
            never,
            Liveness::Stale {
                age: Duration::from_secs(4 * 60 * 60),
                tolerance: Duration::from_secs(60 * 60),
            },
            "never-ran and stale must stay distinguishable"
        );
    }

    /// `report` never returns 2. Exit 2 means "could not look", which only the
    /// I/O boundary in `run` can decide — a pure function that has been handed
    /// a verdict has, by construction, already looked. Asserting it here keeps
    /// the meaning of 2 from leaking into the pure half.
    #[test]
    fn report_never_claims_it_could_not_look() {
        let tolerance = Duration::from_secs(60 * 60);
        for liveness in [
            Liveness::Fresh {
                age: Duration::from_secs(1),
                tolerance,
            },
            Liveness::Stale {
                age: Duration::from_secs(9_999),
                tolerance,
            },
            Liveness::NeverRan { tolerance },
        ] {
            assert_ne!(
                report(&liveness, "w.yml"),
                2,
                "exit 2 belongs to the I/O boundary, not to a decided verdict"
            );
        }
    }
}
