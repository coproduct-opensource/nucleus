//! "One re-run per workflow per PR", as a type instead of a rule to remember.
//!
//! # The prose it replaces
//!
//! Re-running a workflow run makes it *new*, so GitHub's `cancel-in-progress`
//! concurrency cancels its sibling in the same group. Re-running two runs OF THE
//! SAME WORKFLOW on one PR therefore makes each cancel the other, and the count
//! of cancelled checks goes UP. Observed on 2026-09-02: a PR went from 4 to 6
//! cancelled runs across two rounds of batch re-running, and one of the
//! "cancelled" runs turned out to be `attempt=2` — a previous re-run of my own.
//!
//! Written down, that is a rule someone has to recall at the moment they are
//! firing a batch of commands. Written as a type, it is not a batch anyone can
//! express.
//!
//! # The encoding
//!
//! A plan is keyed by `(pull request, workflow)`. Two runs of one workflow on
//! one PR collapse to one entry on insertion, so the illegal batch has no
//! representation:
//!
//! ```text
//!   Vec<RunId>                     -- two runs of one workflow: representable
//!   BTreeMap<(Pr, Workflow), Run>  -- two runs of one workflow: not a value
//! ```
//!
//! The dependent-type statement this approximates is
//!
//! ```text
//!   ∀ (p : Plan) (a b : Entry), a ∈ p → b ∈ p → key a = key b → a = b
//! ```
//!
//! and a map is the proof-carrying representation of exactly that Σ-type: a list
//! together with a proof its keys are unique IS a map. The invariant is not
//! asserted and then checked — it is discharged by construction, which is the
//! same move as `IpCmd` making "forgot the `ip`" unwritable rather than linted.
//!
//! # What is still only pinned, not proved
//!
//! Rust's type system does not carry that ∀. What it carries is the
//! representation choice that makes the ∀ trivially true. The tests below pin
//! the shape — including that collapsing duplicates never DROPS a workflow,
//! which is the failure mode a naive "dedupe" would introduce. That split,
//! between what is enforced by construction and what is pinned by a checker, is
//! borrowed from olog's `MetaOlog.agda`: statements whose names and arities a
//! schema check enforces across provers, honest that the proofs are postulated.
//!
//! # Deliberately no I/O
//!
//! Observing which runs were cancelled is I/O and lives with the caller. This
//! module is the decision, so it is total, testable with no network, and the
//! part worth reasoning about is the part that can be reasoned about.

use std::collections::BTreeMap;

/// A cancelled run as observed. The raw, unconstrained shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelledRun {
    pub pr: u64,
    pub workflow: String,
    pub run_id: u64,
}

/// The key the constraint lives in. Making this a named type rather than an
/// inline tuple is what stops a later refactor from keying on `run_id` — which
/// would compile, and would silently restore the bug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkflowKey {
    pub pr: u64,
    pub workflow: String,
}

/// A set of re-runs that cannot contain two runs of one workflow on one PR.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RerunPlan {
    entries: BTreeMap<WorkflowKey, u64>,
}

impl RerunPlan {
    /// Build a plan from anything observed, however duplicated.
    ///
    /// Later duplicates lose to the first seen. Which one survives does not
    /// matter — both are runs of the same workflow on the same PR, and
    /// re-running either produces the same check-runs. What matters is that
    /// exactly one does.
    pub fn from_observed(runs: impl IntoIterator<Item = CancelledRun>) -> Self {
        let mut entries: BTreeMap<WorkflowKey, u64> = BTreeMap::new();
        for r in runs {
            entries
                .entry(WorkflowKey {
                    pr: r.pr,
                    workflow: r.workflow,
                })
                .or_insert(r.run_id);
        }
        Self { entries }
    }

    /// The run ids to re-run, safe to fire together.
    pub fn run_ids(&self) -> Vec<u64> {
        self.entries.values().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every (pr, workflow) the plan covers.
    pub fn keys(&self) -> impl Iterator<Item = &WorkflowKey> {
        self.entries.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(pr: u64, wf: &str, id: u64) -> CancelledRun {
        CancelledRun {
            pr,
            workflow: wf.to_string(),
            run_id: id,
        }
    }

    /// The bug, as data: two runs of ONE workflow on ONE PR. Firing both makes
    /// each cancel the other.
    #[test]
    fn two_runs_of_one_workflow_on_one_pr_collapse_to_one() {
        let plan = RerunPlan::from_observed([
            run(2360, "quickstart-boot", 111),
            run(2360, "quickstart-boot", 222),
        ]);
        assert_eq!(plan.len(), 1, "the illegal batch has no representation");
    }

    /// The other half, and the one a naive dedupe breaks: collapsing must not
    /// DROP a workflow. Different workflows do not share a concurrency group,
    /// so firing them together is safe and necessary.
    #[test]
    fn different_workflows_on_one_pr_all_survive() {
        let plan = RerunPlan::from_observed([
            run(2360, "quickstart-boot", 1),
            run(2360, "CK Policy Lean Proofs", 2),
            run(2360, "Dependency Hygiene Gates", 3),
        ]);
        assert_eq!(plan.len(), 3);
    }

    /// The same workflow on DIFFERENT PRs is a different concurrency group
    /// (the group includes the head ref), so both must survive.
    #[test]
    fn the_same_workflow_on_different_prs_is_not_a_duplicate() {
        let plan = RerunPlan::from_observed([
            run(2386, "quickstart-boot", 1),
            run(2387, "quickstart-boot", 2),
        ]);
        assert_eq!(plan.len(), 2);
    }

    /// The invariant itself, over adversarial input: whatever goes in, no two
    /// entries share a key. This is the ∀ the module doc states, checked over a
    /// case built to violate it.
    #[test]
    fn no_two_entries_ever_share_a_key() {
        let mut observed = Vec::new();
        for pr in [2360u64, 2386, 2387] {
            for wf in ["quickstart-boot", "Clippy", "Tests"] {
                for id in 0..4u64 {
                    observed.push(run(pr, wf, pr * 100 + id));
                }
            }
        }
        assert_eq!(
            observed.len(),
            36,
            "the input must actually contain duplicates"
        );

        let plan = RerunPlan::from_observed(observed);
        let keys: Vec<&WorkflowKey> = plan.keys().collect();
        let mut deduped = keys.clone();
        deduped.dedup();
        assert_eq!(keys.len(), deduped.len(), "keys must be unique");
        assert_eq!(plan.len(), 9, "3 PRs x 3 workflows, one run each");
    }

    /// Non-vacuity: every workflow that appeared in the input appears in the
    /// plan. Without this, a plan that returned nothing would satisfy every
    /// uniqueness assertion above.
    #[test]
    fn collapsing_never_loses_a_workflow() {
        let observed = vec![
            run(2360, "a", 1),
            run(2360, "a", 2),
            run(2360, "b", 3),
            run(2387, "a", 4),
        ];
        let plan = RerunPlan::from_observed(observed.clone());
        for o in &observed {
            assert!(
                plan.keys()
                    .any(|k| k.pr == o.pr && k.workflow == o.workflow),
                "workflow {} on #{} was dropped entirely",
                o.workflow,
                o.pr
            );
        }
    }

    #[test]
    fn an_empty_observation_is_an_empty_plan() {
        let plan = RerunPlan::from_observed([]);
        assert!(plan.is_empty());
        assert!(plan.run_ids().is_empty());
    }
}
