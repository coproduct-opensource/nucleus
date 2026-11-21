//! Evaluation results: computed from per-item outcomes by one function, and
//! compared with a policy's thresholds in integers.
//!
//! The evaluator runs base and candidate on the same items with the same
//! seeds and records one [`ItemOutcome`] per (task, item, seed). The results
//! in an evaluation receipt are [`EvalResults::from_outcomes`] of that list,
//! and the receipt binds the list's digest. Anyone holding the list can
//! recompute the results; only someone holding the suite can recompute the
//! grading that produced the list. The first is checked by this crate. The
//! second is the evaluator's signature.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::ContentDigest;

const TRANSCRIPT_DOMAIN: &[u8] = b"nucleus/weight-patch/transcript/v1\0";

/// One model's answer to one item, as graded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// Whether the answer was graded correct.
    pub correct: bool,
    /// Whether the answer ran out of tokens.
    pub token_limit: bool,
    /// The digest of the answer's text.
    pub output: ContentDigest,
}

/// Base and candidate on the same item with the same seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemOutcome {
    /// The task the item belongs to.
    pub task: String,
    /// The item, by the suite's own identifier.
    pub item: String,
    /// The sampling seed both models used.
    pub seed: u64,
    /// The base checkpoint's answer.
    pub base: Outcome,
    /// The candidate checkpoint's answer.
    pub candidate: Outcome,
}

/// One task's counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResult {
    /// The task.
    pub task: String,
    /// Paired answers counted.
    pub items: u64,
    /// Answers the base got right.
    pub base_correct: u64,
    /// Answers the candidate got right.
    pub candidate_correct: u64,
    /// Pairs the base got wrong and the candidate got right.
    pub improved: u64,
    /// Pairs the base got right and the candidate got wrong.
    pub regressed: u64,
    /// Base answers that ran out of tokens.
    pub base_token_limit: u64,
    /// Candidate answers that ran out of tokens.
    pub candidate_token_limit: u64,
}

/// Why a list of outcomes has no results.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OutcomeError {
    /// The list is empty.
    #[error("there are no outcomes")]
    Empty,
    /// One (task, item, seed) appears twice.
    #[error("task {task:?} item {item:?} seed {seed} appears twice")]
    Duplicate {
        /// The task.
        task: String,
        /// The item.
        item: String,
        /// The seed.
        seed: u64,
    },
    /// The list could not be put in canonical form.
    #[error("canonical form: {detail}")]
    Canonical {
        /// The serializer's message.
        detail: String,
    },
}

/// Every task's counts, in task order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalResults {
    tasks: Vec<TaskResult>,
}

impl EvalResults {
    /// The results of `outcomes`. The only way to compute them.
    ///
    /// # Errors
    ///
    /// [`OutcomeError`] for an empty list or a repeated (task, item, seed).
    pub fn from_outcomes(outcomes: &[ItemOutcome]) -> Result<Self, OutcomeError> {
        if outcomes.is_empty() {
            return Err(OutcomeError::Empty);
        }
        let mut seen = BTreeSet::new();
        let mut tasks: BTreeMap<&str, TaskResult> = BTreeMap::new();
        for outcome in outcomes {
            let ItemOutcome {
                task,
                item,
                seed,
                base,
                candidate,
            } = outcome;
            if !seen.insert((task.as_str(), item.as_str(), *seed)) {
                return Err(OutcomeError::Duplicate {
                    task: task.clone(),
                    item: item.clone(),
                    seed: *seed,
                });
            }
            let entry = tasks.entry(task.as_str()).or_insert_with(|| TaskResult {
                task: task.clone(),
                items: 0,
                base_correct: 0,
                candidate_correct: 0,
                improved: 0,
                regressed: 0,
                base_token_limit: 0,
                candidate_token_limit: 0,
            });
            // Each counter is bounded by the list's length, which fits.
            entry.items = entry.items.saturating_add(1);
            entry.base_correct = entry.base_correct.saturating_add(u64::from(base.correct));
            entry.candidate_correct = entry
                .candidate_correct
                .saturating_add(u64::from(candidate.correct));
            entry.improved = entry
                .improved
                .saturating_add(u64::from(!base.correct && candidate.correct));
            entry.regressed = entry
                .regressed
                .saturating_add(u64::from(base.correct && !candidate.correct));
            entry.base_token_limit = entry
                .base_token_limit
                .saturating_add(u64::from(base.token_limit));
            entry.candidate_token_limit = entry
                .candidate_token_limit
                .saturating_add(u64::from(candidate.token_limit));
        }
        Ok(Self {
            tasks: tasks.into_values().collect(),
        })
    }

    /// The named task's counts, if the evaluation covered it.
    #[must_use]
    pub fn task(&self, name: &str) -> Option<&TaskResult> {
        self.tasks.iter().find(|t| t.task == name)
    }

    /// Every task's counts, in task order.
    #[must_use]
    pub fn tasks(&self) -> &[TaskResult] {
        &self.tasks
    }
}

/// The digest an evaluation receipt binds for `outcomes`: one JSON line per
/// outcome, in the order given.
///
/// # Errors
///
/// [`OutcomeError::Canonical`] if an outcome does not serialize.
pub fn transcript_digest(outcomes: &[ItemOutcome]) -> Result<ContentDigest, OutcomeError> {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_DOMAIN);
    for outcome in outcomes {
        // The struct holds no map, so its JSON has one byte sequence.
        let line = serde_json::to_vec(outcome).map_err(|e| OutcomeError::Canonical {
            detail: e.to_string(),
        })?;
        h.update(&line);
        h.update(b"\n");
    }
    Ok(ContentDigest::from_bytes(h.finalize().into()))
}

/// The limit on one unrelated task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnrelatedLimit {
    /// The task.
    pub task: String,
    /// The fewest paired answers that count as having looked.
    pub min_items: u64,
    /// The largest net loss allowed, in hundredths of a percent of the items.
    pub max_net_loss_bp: u32,
}

/// What an evaluation must show before a candidate may be promoted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    /// The task the patch is meant to improve.
    pub target_task: String,
    /// The fewest paired answers on it that count as having looked.
    pub min_items: u64,
    /// The smallest net gain required on it, in hundredths of a percent of
    /// the items.
    pub min_net_gain_bp: u32,
    /// The largest share of candidate answers on it that may run out of
    /// tokens, in hundredths of a percent.
    pub max_token_limit_bp: u32,
    /// The tasks the patch is not meant to change, each with its limit.
    pub unrelated: Vec<UnrelatedLimit>,
}

/// The first threshold an evaluation does not meet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "threshold", rename_all = "snake_case", deny_unknown_fields)]
pub enum ThresholdFailure {
    /// The evaluation did not cover a task the policy names.
    #[error("the evaluation does not cover task {task:?}")]
    TaskMissing {
        /// The task.
        task: String,
    },
    /// The evaluation covered a task with too few answers to count.
    #[error("task {task:?} has {items} paired answers; the policy requires {required}")]
    TooFewItems {
        /// The task.
        task: String,
        /// How many it has.
        items: u64,
        /// How many the policy requires.
        required: u64,
    },
    /// The candidate's net gain on the target task is below the minimum.
    #[error("the candidate's net gain on {task:?} is below the minimum")]
    GainBelowMinimum {
        /// The task.
        task: String,
    },
    /// Too many candidate answers ran out of tokens.
    #[error("too many candidate answers on {task:?} ran out of tokens")]
    TokenLimitAboveMaximum {
        /// The task.
        task: String,
    },
    /// The candidate lost more than allowed on an unrelated task.
    #[error("the candidate regressed on unrelated task {task:?} by more than the limit")]
    UnrelatedRegression {
        /// The task.
        task: String,
    },
}

/// `count / items` compared with `bp / 10_000`, exactly. `None` on overflow,
/// which a `u64` count times ten thousand cannot produce in 128 bits.
fn share_cmp(count: i128, items: u64, bp: u32) -> Option<std::cmp::Ordering> {
    let left = count.checked_mul(10_000)?;
    let right = i128::from(bp).checked_mul(i128::from(items))?;
    Some(left.cmp(&right))
}

fn covered<'r>(
    results: &'r EvalResults,
    task: &str,
    min_items: u64,
) -> Result<&'r TaskResult, ThresholdFailure> {
    let Some(result) = results.task(task) else {
        return Err(ThresholdFailure::TaskMissing {
            task: task.to_owned(),
        });
    };
    // Zero items would satisfy any share; a policy that asks for zero still
    // gets at least one.
    let required = min_items.max(1);
    if result.items < required {
        return Err(ThresholdFailure::TooFewItems {
            task: task.to_owned(),
            items: result.items,
            required,
        });
    }
    Ok(result)
}

/// Checks `results` against `thresholds`.
///
/// # Errors
///
/// The first [`ThresholdFailure`], target task first, then the unrelated
/// tasks in the policy's order.
pub fn check_thresholds(
    results: &EvalResults,
    thresholds: &Thresholds,
) -> Result<(), ThresholdFailure> {
    use std::cmp::Ordering::{Equal, Greater, Less};

    let Thresholds {
        target_task,
        min_items,
        min_net_gain_bp,
        max_token_limit_bp,
        unrelated,
    } = thresholds;

    let target = covered(results, target_task, *min_items)?;
    let gain = i128::from(target.candidate_correct).saturating_sub(i128::from(target.base_correct));
    match share_cmp(gain, target.items, *min_net_gain_bp) {
        Some(Greater | Equal) => {}
        Some(Less) | None => {
            return Err(ThresholdFailure::GainBelowMinimum {
                task: target_task.clone(),
            });
        }
    }
    match share_cmp(
        i128::from(target.candidate_token_limit),
        target.items,
        *max_token_limit_bp,
    ) {
        Some(Less | Equal) => {}
        Some(Greater) | None => {
            return Err(ThresholdFailure::TokenLimitAboveMaximum {
                task: target_task.clone(),
            });
        }
    }

    for limit in unrelated {
        let UnrelatedLimit {
            task,
            min_items,
            max_net_loss_bp,
        } = limit;
        let result = covered(results, task, *min_items)?;
        let loss =
            i128::from(result.base_correct).saturating_sub(i128::from(result.candidate_correct));
        match share_cmp(loss, result.items, *max_net_loss_bp) {
            Some(Less | Equal) => {}
            Some(Greater) | None => {
                return Err(ThresholdFailure::UnrelatedRegression { task: task.clone() });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(correct: bool, token_limit: bool) -> Outcome {
        Outcome {
            correct,
            token_limit,
            output: ContentDigest::from_bytes([u8::from(correct); 32]),
        }
    }

    /// `n` items of `task`; base right on the first `base`, candidate right on
    /// the first `candidate`, candidate out of tokens on the last `limit`.
    fn items(task: &str, n: u64, base: u64, candidate: u64, limit: u64) -> Vec<ItemOutcome> {
        (0..n)
            .map(|i| ItemOutcome {
                task: task.to_owned(),
                item: format!("item-{i}"),
                seed: 7,
                base: outcome(i < base, false),
                candidate: outcome(i < candidate, i >= n - limit),
            })
            .collect()
    }

    fn thresholds() -> Thresholds {
        Thresholds {
            target_task: "math".to_owned(),
            min_items: 100,
            min_net_gain_bp: 300,
            max_token_limit_bp: 1000,
            unrelated: vec![UnrelatedLimit {
                task: "reading".to_owned(),
                min_items: 50,
                max_net_loss_bp: 100,
            }],
        }
    }

    fn results(math: (u64, u64, u64, u64), reading: (u64, u64, u64)) -> EvalResults {
        let mut all = items("math", math.0, math.1, math.2, math.3);
        all.extend(items("reading", reading.0, reading.1, reading.2, 0));
        EvalResults::from_outcomes(&all).unwrap()
    }

    #[test]
    fn counts_are_computed_from_the_outcomes() {
        let r = results((100, 50, 60, 5), (50, 40, 40));
        let math = r.task("math").unwrap();
        assert_eq!(
            (math.items, math.base_correct, math.candidate_correct),
            (100, 50, 60)
        );
        assert_eq!((math.improved, math.regressed), (10, 0));
        assert_eq!((math.base_token_limit, math.candidate_token_limit), (0, 5));
        assert_eq!(
            r.tasks()
                .iter()
                .map(|t| t.task.as_str())
                .collect::<Vec<_>>(),
            ["math", "reading"]
        );
    }

    #[test]
    fn an_empty_or_repeated_list_has_no_results() {
        assert_eq!(EvalResults::from_outcomes(&[]), Err(OutcomeError::Empty));
        let mut twice = items("math", 2, 1, 1, 0);
        twice.push(twice[0].clone());
        assert!(matches!(
            EvalResults::from_outcomes(&twice),
            Err(OutcomeError::Duplicate { .. })
        ));
    }

    #[test]
    fn the_transcript_digest_binds_every_outcome_and_their_order() {
        let a = items("math", 3, 1, 2, 0);
        let mut flipped = a.clone();
        flipped[1].candidate.correct = !flipped[1].candidate.correct;
        let mut reordered = a.clone();
        reordered.swap(0, 2);
        let d = transcript_digest(&a).unwrap();
        assert_eq!(d, transcript_digest(&a).unwrap());
        assert_ne!(d, transcript_digest(&flipped).unwrap());
        assert_ne!(d, transcript_digest(&reordered).unwrap());
    }

    #[test]
    fn a_gain_at_the_minimum_passes_and_one_below_it_does_not() {
        // 3% of 100 is exactly three answers.
        assert_eq!(
            check_thresholds(&results((100, 50, 53, 0), (50, 40, 40)), &thresholds()),
            Ok(())
        );
        assert!(matches!(
            check_thresholds(&results((100, 50, 52, 0), (50, 40, 40)), &thresholds()),
            Err(ThresholdFailure::GainBelowMinimum { .. })
        ));
    }

    #[test]
    fn running_out_of_tokens_too_often_fails() {
        assert_eq!(
            check_thresholds(&results((100, 50, 60, 10), (50, 40, 40)), &thresholds()),
            Ok(())
        );
        assert!(matches!(
            check_thresholds(&results((100, 50, 60, 11), (50, 40, 40)), &thresholds()),
            Err(ThresholdFailure::TokenLimitAboveMaximum { .. })
        ));
    }

    #[test]
    fn a_loss_on_an_unrelated_task_fails_even_with_a_large_gain() {
        // 1% of 50 is half an answer: losing one is over the limit.
        assert!(matches!(
            check_thresholds(&results((100, 50, 90, 0), (50, 40, 39)), &thresholds()),
            Err(ThresholdFailure::UnrelatedRegression { .. })
        ));
    }

    #[test]
    fn a_task_the_policy_names_must_be_covered_with_enough_items() {
        let only_math = EvalResults::from_outcomes(&items("math", 100, 50, 60, 0)).unwrap();
        assert_eq!(
            check_thresholds(&only_math, &thresholds()),
            Err(ThresholdFailure::TaskMissing {
                task: "reading".to_owned()
            })
        );
        assert!(matches!(
            check_thresholds(&results((99, 50, 60, 0), (50, 40, 40)), &thresholds()),
            Err(ThresholdFailure::TooFewItems {
                items: 99,
                required: 100,
                ..
            })
        ));
        assert!(matches!(
            check_thresholds(&results((100, 50, 60, 0), (49, 40, 40)), &thresholds()),
            Err(ThresholdFailure::TooFewItems { .. })
        ));
    }
}
