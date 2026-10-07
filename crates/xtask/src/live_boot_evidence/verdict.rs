//! One verdict per check, and the fold that decides the run.
//!
//! Three cases, because "could not look" is not "looked and it was fine"
//! (ADR 0007 A-1): a check that could not run is red unless the invocation
//! names it as allowed, and an allowance must name a check that exists.

use std::collections::BTreeSet;

use serde::Serialize;

/// What one check concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", content = "detail", rename_all = "snake_case")]
pub enum Verdict {
    /// The check ran and the property holds.
    Pass(String),
    /// The check ran and the property does not hold.
    Fail(String),
    /// The check could not run, and why.
    CouldNotRun(String),
}

/// A named verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    #[serde(flatten)]
    pub verdict: Verdict,
}

impl Check {
    pub fn new(name: impl Into<String>, verdict: Verdict) -> Self {
        Self {
            name: name.into(),
            verdict,
        }
    }
}

/// The run's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// Every check passed, or could not run under an allowance.
    Green {
        /// Allowances whose check ran and passed: no longer needed.
        stale_allowances: Vec<String>,
    },
    /// At least one reason the run is red, each named.
    Red { reasons: Vec<String> },
}

/// Decide the run. Exhaustive on purpose: there is no arm that turns an
/// unknown into a pass.
pub fn fold(checks: &[Check], allowed: &BTreeSet<String>) -> Outcome {
    let mut reasons = Vec::new();
    let mut stale = Vec::new();
    if checks.is_empty() {
        reasons.push("no checks ran".to_string());
    }
    for name in allowed {
        match checks.iter().find(|c| &c.name == name) {
            None => reasons.push(format!(
                "--allow-could-not-run {name} names no check this run has"
            )),
            Some(Check {
                verdict: Verdict::Pass(_),
                ..
            }) => stale.push(name.clone()),
            Some(_) => {}
        }
    }
    let mut seen = BTreeSet::new();
    for check in checks {
        if !seen.insert(&check.name) {
            reasons.push(format!("check {} was decided twice", check.name));
        }
        match &check.verdict {
            Verdict::Pass(_) => {}
            Verdict::Fail(why) => reasons.push(format!("{}: FAIL: {why}", check.name)),
            Verdict::CouldNotRun(_) if allowed.contains(&check.name) => {}
            Verdict::CouldNotRun(why) => {
                reasons.push(format!("{}: COULD NOT RUN: {why}", check.name));
            }
        }
    }
    if reasons.is_empty() {
        Outcome::Green {
            stale_allowances: stale,
        }
    } else {
        Outcome::Red { reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_fail_or_an_unallowed_could_not_run_is_red() {
        let pass = Check::new("a", Verdict::Pass("ok".into()));
        assert!(matches!(
            fold(std::slice::from_ref(&pass), &allow(&[])),
            Outcome::Green { .. }
        ));
        let fail = Check::new("b", Verdict::Fail("no".into()));
        assert!(matches!(
            fold(&[pass.clone(), fail], &allow(&[])),
            Outcome::Red { .. }
        ));
        let cnr = Check::new("c", Verdict::CouldNotRun("tool missing".into()));
        assert!(matches!(
            fold(&[pass.clone(), cnr.clone()], &allow(&[])),
            Outcome::Red { .. }
        ));
        assert_eq!(
            fold(&[pass, cnr], &allow(&["c"])),
            Outcome::Green {
                stale_allowances: vec![]
            }
        );
    }

    #[test]
    fn an_allowance_never_covers_a_fail_and_must_name_a_real_check() {
        let fail = Check::new("c", Verdict::Fail("no".into()));
        assert!(matches!(
            fold(std::slice::from_ref(&fail), &allow(&["c"])),
            Outcome::Red { .. }
        ));
        let pass = Check::new("c", Verdict::Pass("ok".into()));
        assert!(matches!(
            fold(std::slice::from_ref(&pass), &allow(&["typo"])),
            Outcome::Red { .. }
        ));
        assert_eq!(
            fold(&[pass], &allow(&["c"])),
            Outcome::Green {
                stale_allowances: vec!["c".into()]
            }
        );
    }

    #[test]
    fn nothing_checked_and_a_check_decided_twice_are_red() {
        assert!(matches!(fold(&[], &allow(&[])), Outcome::Red { .. }));
        let a = Check::new("a", Verdict::Pass("ok".into()));
        assert!(matches!(
            fold(&[a.clone(), a], &allow(&[])),
            Outcome::Red { .. }
        ));
    }
}
