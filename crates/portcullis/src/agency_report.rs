//! One measurement of the frontier: how much useful work got done, and what
//! the authority to do it cost (ADR 0005).
//!
//! The objective is a ratio,
//!
//! ```text
//!              useful autonomous work completed
//!     I  =  ───────────────────────────────────────────────────────
//!           authority risk + human friction + integration cost
//! ```
//!
//! and until this module there was no object that held both halves. The
//! denominator was already instrumented — [`crate::authority_metrics`] gives
//! ρ and C(T) over a kernel trace, [`crate::grant_usage`] gives ρ over effects
//! and the denials — while the numerator was measured nowhere at all. Every
//! number nucleus published was a proof count, a denial count, or a latency:
//! all of them about the constraint, none about what the constraint was for.
//!
//! An [`AgencyReport`] is therefore deliberately **not** derivable from a
//! trace alone. It needs a suite of tasks with oracles, and somebody has to
//! run them. That asymmetry is the point: you cannot infer that useful work
//! happened from the fact that nothing was refused.
//!
//! # What a report is not
//!
//! It is not a benchmark of a model. Nucleus does not own cognition (ADR 0005,
//! decision 3), and a task fails here when the *authority* would not admit the
//! work, not when a model was not clever enough. [`Enforcement`] records which
//! boundary the run actually crossed, because "8 of 8 under a microVM with a
//! sealed grant" and "8 of 8 with the gate switched off" are the same fraction
//! and not the same fact.

use serde::{Deserialize, Serialize};

use crate::capability::StateRisk;
use crate::grant_usage::UsageReport;

/// Which boundary the measured work actually crossed.
///
/// Stated by whoever ran the suite, never inferred: the completion rate is
/// meaningless without it, and the failure mode this prevents is a number
/// measured with enforcement off being quoted as a number measured with it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// No nucleus mediation at all — the control arm. The completion rate here
    /// is the ceiling the enforced arms are measured against.
    None,
    /// Mediated in-process: the kernel decides, but the workload shares the
    /// host. Tier 1.
    Local,
    /// Mediated inside a microVM with default-deny egress. Tier 2.
    MicroVm,
}

impl Enforcement {
    /// Whether nucleus was in the path at all.
    #[must_use]
    pub fn is_enforced(self) -> bool {
        !matches!(self, Enforcement::None)
    }

    /// The word used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Enforcement::None => "none",
            Enforcement::Local => "local",
            Enforcement::MicroVm => "microvm",
        }
    }
}

/// One task's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskOutcome {
    /// Stable id, so a row can be followed across runs.
    pub id: String,
    /// What the task was trying to achieve, in a person's words.
    pub goal: String,
    /// Whether its oracle passed. Oracles are deterministic checks only — a
    /// judged outcome is not a completion.
    pub completed: bool,
    /// When it did not complete, what stopped it, in the runtime's own words
    /// (`EFFECT_NOT_GRANTED`, `approval_required`, an assertion). Kept so a
    /// failure is attributable to a layer rather than to the suite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_by: Option<String>,
}

/// The denominator terms, as measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorityCost {
    /// ρ over the 13 core dimensions: granted ÷ used. `None` when nothing was
    /// used — undefined, not infinite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overhead_dimensions: Option<f64>,
    /// ρ over semantic effects: granted ÷ exercised. The one that matters, and
    /// the one a better effect catalog moves; the dimension figure is coarse
    /// by construction (13 buckets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overhead_effects: Option<f64>,
    /// C(T): authorization decisions a person made for this suite.
    pub clicks: u64,
    /// Denials on dimensions the grant holds — friction, and an upper bound on
    /// wrongly-refused work rather than a bug count. See
    /// [`UsageReport::denials_within_grant`].
    pub denials_within_grant: usize,
    /// Every denial, including those on dimensions nobody granted. The
    /// difference between the two is the boundary working as intended.
    pub denials_total: usize,
    /// Of the denials, how many were **deferrals to a person** rather than
    /// refusals — a `403 approval_required` that a grant then satisfied.
    ///
    /// Reported separately because a deferral is the system working exactly as
    /// designed, and folding it into friction makes human-in-the-loop look like
    /// a defect. `denials_within_grant - deferrals` is the number worth
    /// driving down; the deferral count is worth driving down too, but by
    /// lowering C(T), which is a different lever.
    #[serde(default)]
    pub deferrals: usize,
    /// The uninhabitable-state grade of the authority that was held.
    pub residual_risk: StateRisk,
}

/// One measurement of the safely-delegatable-agency frontier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgencyReport {
    /// Schema version.
    pub schema_version: u8,
    /// What was measured, in a sentence.
    pub label: String,
    /// The commit it was measured at. A report that cannot be traced to a tree
    /// is an anecdote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Which boundary the work crossed.
    pub enforcement: Enforcement,
    /// Per-task outcomes for **work**. The numerator is these, counted.
    pub tasks: Vec<TaskOutcome>,
    /// Checks that the boundary REFUSED what it should refuse.
    ///
    /// Deliberately not in `tasks`, and deliberately not in the numerator. A
    /// refusal is not work, and a suite that counted its own refusals as
    /// completions would make ℐ rise as the runtime got more restrictive —
    /// the exact inversion ADR 0005 exists to prevent. What these are for is
    /// [`Self::is_valid`]: they decide whether the completion rate means
    /// anything at all.
    #[serde(default)]
    pub containment: Vec<TaskOutcome>,
    /// What the authority cost.
    pub cost: AuthorityCost,
}

impl AgencyReport {
    /// Current schema version.
    pub const SCHEMA_VERSION: u8 = 1;

    /// Tasks whose oracle passed.
    #[must_use]
    pub fn completed(&self) -> usize {
        self.tasks.iter().filter(|t| t.completed).count()
    }

    /// Tasks attempted.
    #[must_use]
    pub fn total(&self) -> usize {
        self.tasks.len()
    }

    /// The numerator as a fraction. `None` for an empty suite — a report with
    /// no tasks measures nothing, and 0/0 dressed as 1.0 is the worst way to
    /// say so.
    #[must_use]
    pub fn completion_rate(&self) -> Option<f64> {
        (!self.tasks.is_empty()).then(|| {
            f64::from(u32::try_from(self.completed()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total()).unwrap_or(u32::MAX))
        })
    }

    /// Whether this report may be quoted as a point on the frontier.
    ///
    /// A completion rate measured while the boundary was leaking is not a
    /// measurement of *safely* delegatable agency; it is a measurement of
    /// delegatable agency, which is a different and much easier quantity. So
    /// a single failed containment check invalidates the whole report rather
    /// than subtracting from it — there is no exchange rate between "did more
    /// work" and "the boundary held", and pretending there is one is how a
    /// safety number gets traded away a percent at a time.
    ///
    /// An empty containment set is NOT valid. A suite that checked nothing has
    /// not established that the boundary held; it has only failed to look.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.containment.is_empty() && self.containment.iter().all(|c| c.completed)
    }

    /// The containment checks that did not hold.
    #[must_use]
    pub fn breaches(&self) -> Vec<&TaskOutcome> {
        self.containment.iter().filter(|c| !c.completed).collect()
    }

    /// Build the cost half from a run's [`UsageReport`], so the two halves of
    /// a report cannot be assembled from different runs by accident.
    #[must_use]
    pub fn cost_from_usage(
        usage: &UsageReport,
        clicks: u64,
        deferrals: usize,
        residual_risk: StateRisk,
    ) -> AuthorityCost {
        AuthorityCost {
            overhead_dimensions: usage.authority_overhead(),
            overhead_effects: usage.effect_overhead(),
            clicks,
            denials_within_grant: usage.denials_within_grant(),
            denials_total: usage.denied,
            deferrals,
            residual_risk,
        }
    }

    /// The report as the lines a person reads.
    #[must_use]
    pub fn render(&self) -> String {
        let rate = match self.completion_rate() {
            Some(r) => format!("{:.0}%", r * 100.0),
            None => "no tasks".to_string(),
        };
        let rho = match self.cost.overhead_effects {
            Some(r) => format!("{r:.2}"),
            None => "undefined".to_string(),
        };
        let rho_dim = match self.cost.overhead_dimensions {
            Some(r) => format!("{r:.2}"),
            None => "undefined".to_string(),
        };
        let mut out = format!(
            "agency: {}/{} tasks completed ({rate}) under {} enforcement\n\
             cost:   ρ_effect = {rho} · ρ_dimension = {rho_dim} · C(T) = {} · \
             {} denial(s) inside the grant of {} total, {} of them deferrals to a person \
             · risk {:?}\n",
            self.completed(),
            self.total(),
            self.enforcement.as_str(),
            self.cost.clicks,
            self.cost.denials_within_grant,
            self.cost.denials_total,
            self.cost.deferrals,
            self.cost.residual_risk,
        );
        for t in self.tasks.iter().filter(|t| !t.completed) {
            let why = t.refused_by.as_deref().unwrap_or("no reason recorded");
            out.push_str(&format!("  not completed: {} — {why}\n", t.id));
        }
        if self.is_valid() {
            out.push_str(&format!(
                "valid:  {} containment check(s) held\n",
                self.containment.len()
            ));
        } else if self.containment.is_empty() {
            out.push_str(
                "INVALID: no containment checks ran, so this is not a point on the frontier\n",
            );
        } else {
            out.push_str("INVALID: the boundary did not hold — do not quote the rate above\n");
            for c in self.breaches() {
                out.push_str(&format!("  breach: {} — {}\n", c.id, c.goal));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, completed: bool) -> TaskOutcome {
        TaskOutcome {
            id: id.to_string(),
            goal: format!("goal for {id}"),
            completed,
            refused_by: (!completed).then(|| "EFFECT_NOT_GRANTED".to_string()),
        }
    }

    fn report(tasks: Vec<TaskOutcome>) -> AgencyReport {
        AgencyReport {
            schema_version: AgencyReport::SCHEMA_VERSION,
            label: "test".to_string(),
            commit: None,
            enforcement: Enforcement::MicroVm,
            tasks,
            containment: vec![task("refuses-secret-read", true)],
            cost: AuthorityCost {
                overhead_dimensions: Some(2.0),
                overhead_effects: Some(1.5),
                clicks: 1,
                denials_within_grant: 0,
                denials_total: 2,
                deferrals: 0,
                residual_risk: StateRisk::Low,
            },
        }
    }

    #[test]
    fn the_numerator_is_counted_not_asserted() {
        let r = report(vec![task("a", true), task("b", false), task("c", true)]);
        assert_eq!(r.completed(), 2);
        assert_eq!(r.total(), 3);
        assert!((r.completion_rate().unwrap() - 2.0 / 3.0).abs() < 1e-9);
    }

    /// An empty suite measures nothing, and must not report that as success.
    /// 0/0 rendered as 100% is the single most dangerous number this type
    /// could produce: it would let a harness that ran no tasks at all pass a
    /// ratchet forever.
    #[test]
    fn an_empty_suite_has_no_completion_rate() {
        let r = report(vec![]);
        assert_eq!(r.completion_rate(), None);
        assert!(r.render().contains("no tasks"));
    }

    /// A failure has to say what stopped it, or the report cannot tell a
    /// missing capability from a broken task.
    #[test]
    fn a_failure_names_the_layer_that_refused_it() {
        let r = report(vec![task("a", false)]);
        let rendered = r.render();
        assert!(rendered.contains("not completed: a"), "{rendered}");
        assert!(rendered.contains("EFFECT_NOT_GRANTED"), "{rendered}");
    }

    /// Enforcement is part of the measurement, not metadata about it: the same
    /// fraction means different things on either side of the boundary.
    #[test]
    fn enforcement_is_recorded_and_distinguishes_the_control_arm() {
        assert!(!Enforcement::None.is_enforced());
        assert!(Enforcement::Local.is_enforced());
        assert!(Enforcement::MicroVm.is_enforced());
        let r = report(vec![task("a", true)]);
        assert!(r.render().contains("microvm"));
    }

    /// The property that keeps the numerator honest. A refusal is not work:
    /// if containment counted as a completion, ℐ would RISE as the runtime got
    /// more restrictive, which inverts the whole objective.
    #[test]
    fn containment_checks_are_not_counted_as_work() {
        let mut r = report(vec![task("a", true)]);
        r.containment = vec![
            task("refuses-secret-read", true),
            task("refuses-uncredentialed-egress", true),
        ];
        assert_eq!(r.total(), 1, "three passing checks, but only one is work");
        assert_eq!(r.completed(), 1);
        assert!((r.completion_rate().unwrap() - 1.0).abs() < 1e-9);
    }

    /// A leak invalidates the rate rather than reducing it. There is no
    /// exchange rate between work done and the boundary holding.
    #[test]
    fn a_failed_containment_check_invalidates_the_report() {
        let mut r = report(vec![task("a", true), task("b", true)]);
        r.containment = vec![task("refuses-secret-read", false)];
        assert!(!r.is_valid());
        assert_eq!(r.breaches().len(), 1);
        assert!((r.completion_rate().unwrap() - 1.0).abs() < 1e-9);
        let rendered = r.render();
        assert!(rendered.contains("INVALID"), "{rendered}");
        assert!(rendered.contains("do not quote"), "{rendered}");
    }

    /// Checking nothing is not the same as checking and finding nothing wrong.
    #[test]
    fn a_suite_with_no_containment_checks_is_invalid() {
        let mut r = report(vec![task("a", true)]);
        r.containment = vec![];
        assert!(
            !r.is_valid(),
            "a suite that did not look has not established anything"
        );
        assert!(r.render().contains("no containment checks ran"));
    }

    #[test]
    fn a_report_round_trips_through_json() {
        let r = report(vec![task("a", true), task("b", false)]);
        let json = serde_json::to_string_pretty(&r).expect("serialise");
        let back: AgencyReport = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(r, back);
    }
}
