//! Trace validation: real merge-queue history replayed through the model.
//!
//! "Boot it, then measure" (the repo's rule for anything that claims to be
//! about the live path). GitHub records, per pull request, the timeline
//! events `AddedToMergeQueueEvent`, `RemovedFromMergeQueueEvent { reason }`
//! and `MergedEvent`. Ordered by time across PRs, those are a trace of the
//! queue. This module turns them into model events and replays them through
//! [`crate::queue::try_step`]; a transition the model rejects is either a
//! model bug or a GitHub behaviour the model does not capture — both are
//! worth a red — and a window with no enqueue or no merge is reported as
//! *undecided*, never as clean.
//!
//! Observation (`gh api graphql`) is the caller's (`cargo xtask ci-spec
//! trace-check`); this is the decision.
//!
//! # Mapping
//!
//! | timeline                      | model                       |
//! |-------------------------------|-----------------------------|
//! | `AddedToMergeQueueEvent`      | `enqueue p`                 |
//! | `MergedEvent`                 | `pass p` then `merge`       |
//! | `Removed…{reason: "merged"}`  | (already handled by merge)  |
//! | `Removed…{any other reason}`  | `fail p` (ejection)         |
//!
//! `pass` is synthesised before `merge` because GitHub only merges a green
//! head; the replay therefore checks ORDER and ACCOUNTING (T3/T4), not the
//! checks themselves. A `Removed` whose reason names a push (`dequeued`,
//! `new commits`) is still an ejection here: the model's `push` returns the
//! PR to waiting, the same accounting as `fail` for what the replay asserts.

use serde::{Deserialize, Serialize};

use crate::queue::{Ev, Illegal, Loc, State, try_step};

/// One timeline event, as fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    /// RFC 3339, from GitHub.
    pub at: String,
    pub pr: u32,
    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Added,
    Removed { reason: String },
    Merged,
}

/// What the replay established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Replay {
    pub events: usize,
    pub enqueues: usize,
    pub merges: usize,
    pub ejections: usize,
    /// Transitions the model rejected, with the event and the reason.
    pub violations: Vec<String>,
    /// Transitions GitHub performed that the model has no rule for, as opposed to transitions it
    /// forbids. Counted and reported, never silently dropped: a harness that cannot tell the two
    /// apart trains its readers to ignore it, which is exactly what happened for 23 hours.
    pub unmodelled: Vec<String>,
    /// The window contained too little to check anything.
    pub vacuous: Option<String>,
}

impl Replay {
    /// `0` clean, `1` violation, `2` vacuous.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if !self.violations.is_empty() {
            1
        } else if self.vacuous.is_some() {
            2
        } else {
            0
        }
    }
}

/// Turn timeline events into model events, in time order (stable on ties,
/// which keeps a PR's `Merged` before its `Removed(merged)` as GitHub emits
/// them). PR numbers are mapped to dense ids so the model's `Vec` storage
/// stays small.
#[must_use]
pub fn to_model_events(events: &[TraceEvent]) -> Vec<(TraceEvent, Ev)> {
    let mut sorted: Vec<&TraceEvent> = events.iter().collect();
    sorted.sort_by(|a, b| a.at.cmp(&b.at));
    let mut ids: Vec<u32> = Vec::new();
    let mut id_of = |pr: u32| -> u32 {
        match ids.iter().position(|x| *x == pr) {
            Some(i) => u32::try_from(i).expect("pr count fits u32"),
            None => {
                ids.push(pr);
                u32::try_from(ids.len() - 1).expect("pr count fits u32")
            }
        }
    };
    let mut out = Vec::new();
    for e in sorted {
        let p = id_of(e.pr);
        match &e.kind {
            Kind::Added => out.push((e.clone(), Ev::Enqueue(p))),
            Kind::Merged => {
                out.push((e.clone(), Ev::Pass(p)));
                out.push((e.clone(), Ev::Merge));
            }
            Kind::Removed { reason } => {
                if reason.eq_ignore_ascii_case("merged") {
                    continue;
                }
                out.push((e.clone(), Ev::Fail(p)));
            }
        }
    }
    out
}

/// Replay a window of history.
#[must_use]
pub fn replay(events: &[TraceEvent]) -> Replay {
    let model = to_model_events(events);
    let mut s = State::init();
    let mut r = Replay {
        unmodelled: Vec::new(),
        events: events.len(),
        enqueues: 0,
        merges: 0,
        ejections: 0,
        violations: Vec::new(),
        vacuous: None,
    };
    for (src, ev) in &model {
        match ev {
            Ev::Enqueue(_) => r.enqueues += 1,
            Ev::Merge => r.merges += 1,
            Ev::Fail(_) => r.ejections += 1,
            _ => {}
        }
        match try_step(s.clone(), *ev) {
            Ok(next) => s = next,
            Err(boxed) => {
                let (same, why) = *boxed;
                // A window that starts mid-flight sees `Merged`/`Removed` for
                // PRs whose `Added` is before the window: not a violation of
                // the model, a truncation of the trace. Report it as such.
                let truncated = matches!(
                    why,
                    Illegal::NotQueued(p) | Illegal::HeadNotGreen(p) if s.loc(p) == Loc::Waiting && !s.enq_log.contains(&p)
                ) || matches!(why, Illegal::EmptyQueue) && s.enq_log.is_empty();
                if truncated {
                    s = same;
                    continue;
                }
                // Re-enqueue after ejection: the model has no rule for it, GitHub does it
                // routinely. Record it as unmodelled, apply it anyway, and keep checking the rest
                // of the trace — otherwise one missing rule cascades into every later event for
                // that PR and fifteen reports share one cause. See gatehouse FINDINGS F-47.
                if let (Ev::Enqueue(p), Illegal::NotWaiting(q)) = (*ev, &why)
                    && *q == p
                    && same.loc(p) == Loc::Ejected
                {
                    let mut fixed = same.clone();
                    fixed.unmodelled_requeue(p);
                    r.unmodelled.push(format!(
                        "{} PR #{} re-enqueued after ejection — the model has no rule for this",
                        src.at, src.pr
                    ));
                    s = try_step(fixed, *ev).unwrap_or_else(|b| b.0);
                    continue;
                }
                r.violations.push(format!(
                    "{} PR #{} {:?} → {:?}: {:?} (queue was {:?})",
                    src.at, src.pr, src.kind, ev, why, same.queue
                ));
                s = same;
            }
        }
    }
    if r.enqueues == 0 || r.merges == 0 {
        r.vacuous = Some(format!(
            "window has {} enqueue(s) and {} merge(s) — nothing to replay against the model",
            r.enqueues, r.merges
        ));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(at: &str, pr: u32, kind: Kind) -> TraceEvent {
        TraceEvent {
            at: at.into(),
            pr,
            kind,
        }
    }

    /// The shape of 2026-09-05 from the PR timelines: #2628 enqueued and
    /// ejected by the timeout, #2636 enqueued and merged, #2642 waiting.
    #[test]
    fn a_real_day_replays_clean() {
        let t = vec![
            ev("2026-09-05T19:00:00Z", 2628, Kind::Added),
            ev(
                "2026-09-05T20:10:00Z",
                2628,
                Kind::Removed {
                    reason: "CI failed".into(),
                },
            ),
            ev("2026-09-05T21:37:57Z", 2636, Kind::Added),
            ev("2026-09-05T21:54:58Z", 2636, Kind::Merged),
            ev(
                "2026-09-05T21:54:58Z",
                2636,
                Kind::Removed {
                    reason: "merged".into(),
                },
            ),
        ];
        let r = replay(&t);
        assert_eq!(r.violations, Vec::<String>::new());
        assert_eq!((r.enqueues, r.merges, r.ejections), (2, 1, 1));
        assert_eq!(r.exit_code(), 0);
    }

    /// A merge the queue could not have performed (the PR was never added)
    /// after the window's own enqueues is a violation, not a truncation.
    #[test]
    fn a_merge_of_an_unqueued_pr_is_a_violation() {
        let t = vec![
            ev("2026-09-05T19:00:00Z", 1, Kind::Added),
            ev("2026-09-05T19:05:00Z", 2, Kind::Merged),
        ];
        let r = replay(&t);
        assert_eq!(r.violations.len(), 1, "{:?}", r.violations);
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn a_window_with_no_merges_is_vacuous_not_clean() {
        let t = vec![ev("2026-09-05T19:00:00Z", 1, Kind::Added)];
        let r = replay(&t);
        assert!(r.vacuous.is_some());
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn a_window_starting_mid_flight_is_truncation_not_violation() {
        // #2628's Removed arrives with no Added in the window.
        let t = vec![
            ev(
                "2026-09-05T20:10:00Z",
                2628,
                Kind::Removed {
                    reason: "CI failed".into(),
                },
            ),
            ev("2026-09-05T21:37:57Z", 2636, Kind::Added),
            ev("2026-09-05T21:54:58Z", 2636, Kind::Merged),
        ];
        let r = replay(&t);
        assert!(r.violations.is_empty(), "{:?}", r.violations);
        assert_eq!(r.exit_code(), 0);
    }

    /// GitHub ejects a PR and adds it back. `CiSpec.Queue.step` has no rule for that, so the
    /// harness must say "no rule" rather than "invariant broken" — and must keep going, or one
    /// missing rule cascades into every later event for that PR.
    #[test]
    fn re_enqueue_after_ejection_is_unmodelled_not_a_violation() {
        let t = vec![
            ev("2026-09-10T01:00:00Z", 1, Kind::Added),
            ev(
                "2026-09-10T02:00:00Z",
                1,
                Kind::Removed {
                    reason: "merge_conflict".into(),
                },
            ),
            ev("2026-09-10T03:00:00Z", 1, Kind::Added),
            ev("2026-09-10T04:00:00Z", 1, Kind::Merged),
        ];
        let r = replay(&t);
        assert_eq!(r.unmodelled.len(), 1, "{:?}", r.unmodelled);
        assert!(
            r.violations.is_empty(),
            "a missing rule was reported as a violation: {:?}",
            r.violations
        );
        assert_eq!(r.exit_code(), 0);
    }

    /// The risk this classification carries, tested rather than asserted: a genuine out-of-order
    /// merge must STILL fail. If compensating for the missing rule also swallowed real violations,
    /// the check would be worse than the red it replaced.
    #[test]
    fn a_real_out_of_order_merge_still_fails_after_the_compensation() {
        let t = vec![
            ev("2026-09-10T01:00:00Z", 1, Kind::Added),
            ev("2026-09-10T01:30:00Z", 2, Kind::Added),
            // #2 merges while #1 is the head: the queue merging out of enqueue order.
            ev("2026-09-10T02:00:00Z", 2, Kind::Merged),
        ];
        let r = replay(&t);
        assert!(
            !r.violations.is_empty(),
            "an out-of-order merge was not reported"
        );
        assert_ne!(r.exit_code(), 0);
    }

    /// And the two must not be confusable: an out-of-order merge is never filed as unmodelled.
    #[test]
    fn a_real_violation_is_not_filed_as_unmodelled() {
        let t = vec![
            ev("2026-09-10T01:00:00Z", 1, Kind::Added),
            ev("2026-09-10T01:30:00Z", 2, Kind::Added),
            ev("2026-09-10T02:00:00Z", 2, Kind::Merged),
        ];
        let r = replay(&t);
        assert!(r.unmodelled.is_empty(), "{:?}", r.unmodelled);
    }
}
