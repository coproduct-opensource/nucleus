//! The merge-queue state machine and the capacity scheduler, transcribed
//! declaration-for-declaration from `ci/lean/CiSpec/Queue.lean` and
//! `ci/lean/CiSpec/Capacity.lean` (the K4 `model_parity.rs` convention).
//!
//! The Lean files carry the theorems (T3–T7); this file carries the same
//! transition function in Rust so that (a) real merge-queue history can be
//! replayed through it (`crate::trace`), (b) golden traces pin the two
//! implementations to each other (`tests/golden`, regenerated into
//! `ci/lean/CiSpec/Golden.lean` and checked by `decide`), and (c) proptest
//! exercises T3–T6 on random sequences. A bounded Kani harness over this
//! mirror was attempted (3 PRs, 4 then 3 then 2 events): CBMC exceeded an
//! hour at four events and was killed under host memory pressure at two, so
//! it is NOT part of this crate yet — recorded as NOT-YET in
//! docs/assurance/ci-assurance.md, not claimed.
//!
//! | Lean (`CiSpec.Queue`)   | here                              |
//! |-------------------------|-----------------------------------|
//! | `Loc`                   | [`Loc`]                           |
//! | `State`, `State.init`   | [`State`], [`State::init`]        |
//! | `Ev`                    | [`Ev`]                            |
//! | `upd` / `setB`          | [`State::set_loc`] / [`State::set_check`] |
//! | `without`               | [`without`]                       |
//! | `eject`                 | [`State::eject`]                  |
//! | `step`                  | [`step`]                          |
//! | `run`                   | [`run`]                           |
//! | `mergeEnabled`          | [`merge_enabled`]                 |
//! | `Consistent`            | [`State::consistent`]             |
//! | `Ordered`               | [`State::ordered`]                |
//! | `CiSpec.Capacity.minOf` | [`min_of`]                        |
//! | `addToFirst`            | [`add_to_first`]                  |
//! | `assignMin`             | [`assign_min`]                    |
//! | `greedyFrom` / `greedy` | [`greedy_from`] / [`greedy`]      |
//! | `makespan`              | [`makespan`]                      |
//!
//! Representation: the Lean `loc : Nat → Loc` and `checks : Nat → Bool` are
//! total functions; here they are `Vec`s indexed by PR id, read as `Waiting`
//! / `false` past the end — the same function, finitely stored, and Kani-
//! tractable (no `BTreeMap`, per the kani-divergence discipline).
//!
//! # What this is NOT
//!
//! A formal extraction. The bridge to the Lean is golden vectors and proptest;
//! the parity is probabilistic and finite, as the K4 file says of itself.

use serde::{Deserialize, Serialize};

/// Where a PR is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Loc {
    Waiting,
    Queued,
    Merged,
    Ejected,
}

/// The queue state. Mirrors `CiSpec.State`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct State {
    loc: Vec<Loc>,
    checks: Vec<bool>,
    pub queue: Vec<u32>,
    pub enq_log: Vec<u32>,
    pub merged_log: Vec<u32>,
}

/// An event. Mirrors `CiSpec.Ev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ev {
    Enqueue(u32),
    Pass(u32),
    Fail(u32),
    Push(u32),
    Cancel(u32),
    Merge,
}

impl Ev {
    /// The Lean spelling, for `Golden.lean`.
    #[must_use]
    pub fn lean(&self) -> String {
        match self {
            Ev::Enqueue(p) => format!(".enqueue {p}"),
            Ev::Pass(p) => format!(".pass {p}"),
            Ev::Fail(p) => format!(".fail {p}"),
            Ev::Push(p) => format!(".push {p}"),
            Ev::Cancel(p) => format!(".cancel {p}"),
            Ev::Merge => ".merge".into(),
        }
    }

    /// Parse the golden-file spelling: `enqueue 1`, `merge`.
    pub fn parse(s: &str) -> Option<Ev> {
        let mut it = s.split_whitespace();
        let k = it.next()?;
        let arg = it.next().map(|a| a.parse::<u32>());
        match (k, arg) {
            ("merge", None) => Some(Ev::Merge),
            ("enqueue", Some(Ok(p))) => Some(Ev::Enqueue(p)),
            ("pass", Some(Ok(p))) => Some(Ev::Pass(p)),
            ("fail", Some(Ok(p))) => Some(Ev::Fail(p)),
            ("push", Some(Ok(p))) => Some(Ev::Push(p)),
            ("cancel", Some(Ok(p))) => Some(Ev::Cancel(p)),
            _ => None,
        }
    }
}

/// `without q p` — every occurrence of `p` removed.
#[must_use]
pub fn without(q: &[u32], p: u32) -> Vec<u32> {
    q.iter().copied().filter(|x| *x != p).collect()
}

impl State {
    /// `State.init`.
    #[must_use]
    pub fn init() -> State {
        State::default()
    }

    /// `loc p` (total: `Waiting` past the end).
    #[must_use]
    pub fn loc(&self, p: u32) -> Loc {
        self.loc.get(p as usize).copied().unwrap_or(Loc::Waiting)
    }

    /// `checks p` (total: `false` past the end).
    #[must_use]
    pub fn check(&self, p: u32) -> bool {
        self.checks.get(p as usize).copied().unwrap_or(false)
    }

    /// `upd loc p l`.
    fn set_loc(&mut self, p: u32, l: Loc) {
        let i = p as usize;
        if self.loc.len() <= i {
            self.loc.resize(i + 1, Loc::Waiting);
        }
        self.loc[i] = l;
    }

    /// `setB checks p b`.
    fn set_check(&mut self, p: u32, b: bool) {
        let i = p as usize;
        if self.checks.len() <= i {
            self.checks.resize(i + 1, false);
        }
        self.checks[i] = b;
    }

    /// `eject s p`.
    fn eject(&mut self, p: u32) {
        self.set_loc(p, Loc::Ejected);
        self.queue = without(&self.queue, p);
        self.set_check(p, false);
    }

    /// `Consistent`: a PR is in the queue exactly when its location says so,
    /// and the queue has no duplicates.
    #[must_use]
    pub fn consistent(&self) -> bool {
        let n = self.loc.len().max(self.queue.iter().map(|p| *p as usize + 1).max().unwrap_or(0));
        for p in 0..n as u32 {
            let in_q = self.queue.contains(&p);
            if in_q != (self.loc(p) == Loc::Queued) {
                return false;
            }
        }
        for (i, a) in self.queue.iter().enumerate() {
            if self.queue[i + 1..].contains(a) {
                return false;
            }
        }
        true
    }

    /// `Ordered`: `merged_log ++ queue` is a subsequence of `enq_log`.
    #[must_use]
    pub fn ordered(&self) -> bool {
        let mut want: Vec<u32> = self.merged_log.clone();
        want.extend_from_slice(&self.queue);
        let mut i = 0;
        for e in &self.enq_log {
            if i < want.len() && want[i] == *e {
                i += 1;
            }
        }
        i == want.len()
    }
}

/// `step s e`. Every precondition failure is a no-op, exactly as in Lean;
/// [`try_step`] reports it instead.
#[must_use]
pub fn step(mut s: State, e: Ev) -> State {
    match e {
        Ev::Enqueue(p) => {
            if s.loc(p) == Loc::Waiting {
                s.set_loc(p, Loc::Queued);
                s.queue.push(p);
                s.enq_log.push(p);
            }
        }
        Ev::Pass(p) => {
            if s.loc(p) == Loc::Queued {
                s.set_check(p, true);
            }
        }
        Ev::Fail(p) => {
            if s.loc(p) == Loc::Queued {
                s.eject(p);
            }
        }
        Ev::Push(p) => {
            if s.loc(p) == Loc::Queued {
                s.set_loc(p, Loc::Waiting);
                s.queue = without(&s.queue, p);
                s.set_check(p, false);
            }
        }
        Ev::Cancel(p) => {
            if s.loc(p) == Loc::Queued {
                s.eject(p);
            } else {
                s.set_check(p, false);
            }
        }
        Ev::Merge => {
            if let Some(&h) = s.queue.first() {
                if s.check(h) {
                    s.set_loc(h, Loc::Merged);
                    s.queue.remove(0);
                    s.merged_log.push(h);
                }
            }
        }
    }
    s
}

/// Why a step was a no-op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Illegal {
    /// `enqueue p` with `p` not waiting.
    NotWaiting(u32),
    /// `pass`/`fail`/`push` with `p` not queued.
    NotQueued(u32),
    /// `merge` with an empty queue.
    EmptyQueue,
    /// `merge` with the head's checks not green.
    HeadNotGreen(u32),
}

/// [`step`], but a precondition failure is reported rather than absorbed.
/// The trace replayer uses this: real history that the model cannot accept
/// is a model bug or a GitHub behaviour change, and both are worth a red.
pub fn try_step(s: State, e: Ev) -> Result<State, Box<(State, Illegal)>> {
    let illegal = match e {
        Ev::Enqueue(p) if s.loc(p) != Loc::Waiting => Some(Illegal::NotWaiting(p)),
        Ev::Pass(p) | Ev::Fail(p) | Ev::Push(p) if s.loc(p) != Loc::Queued => {
            Some(Illegal::NotQueued(p))
        }
        Ev::Merge => match s.queue.first() {
            None => Some(Illegal::EmptyQueue),
            Some(&h) if !s.check(h) => Some(Illegal::HeadNotGreen(h)),
            _ => None,
        },
        _ => None,
    };
    match illegal {
        Some(i) => Err(Box::new((s, i))),
        None => Ok(step(s, e)),
    }
}

/// `run s evs`.
#[must_use]
pub fn run(s: State, evs: &[Ev]) -> State {
    evs.iter().fold(s, |acc, e| step(acc, *e))
}

/// `mergeEnabled`.
#[must_use]
pub fn merge_enabled(s: &State) -> bool {
    match s.queue.first() {
        Some(&h) => s.check(h),
        None => false,
    }
}

// ── Capacity (CiSpec.Capacity) ────────────────────────────────────────────

/// `minOf`.
#[must_use]
pub fn min_of(l: &[u64]) -> u64 {
    match l.split_first() {
        None => 0,
        Some((x, rest)) => rest.iter().fold(*x, |a, b| a.min(*b)),
    }
}

/// `addToFirst m d l`.
#[must_use]
pub fn add_to_first(m: u64, d: u64, l: &[u64]) -> Vec<u64> {
    let mut out = l.to_vec();
    if let Some(i) = out.iter().position(|x| *x == m) {
        out[i] += d;
    }
    out
}

/// `assignMin`.
#[must_use]
pub fn assign_min(l: &[u64], d: u64) -> Vec<u64> {
    add_to_first(min_of(l), d, l)
}

/// `greedyFrom`.
#[must_use]
pub fn greedy_from(l0: &[u64], ds: &[u64]) -> Vec<u64> {
    ds.iter().fold(l0.to_vec(), |l, d| assign_min(&l, *d))
}

/// `greedy p ds`.
#[must_use]
pub fn greedy(p: usize, ds: &[u64]) -> Vec<u64> {
    greedy_from(&vec![0; p], ds)
}

/// `makespan`.
#[must_use]
pub fn makespan(l: &[u64]) -> u64 {
    l.iter().fold(0, |a, b| a.max(*b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CiSpecBite.cancelling_the_head_ejects_it`, replayed here.
    #[test]
    fn cancelling_the_head_ejects_it() {
        let s = run(State::init(), &[Ev::Enqueue(1), Ev::Pass(1)]);
        let s = step(s, Ev::Cancel(1));
        assert!(s.queue.is_empty());
        assert_eq!(s.loc(1), Loc::Ejected);
    }

    /// T5's guarded case: cancelling a DEQUEUED PR's run is a no-op on the queue.
    #[test]
    fn cancelling_a_dequeued_pr_is_safe() {
        let s = run(State::init(), &[Ev::Enqueue(1), Ev::Enqueue(2), Ev::Pass(1), Ev::Push(2)]);
        let before = merge_enabled(&s);
        let s2 = step(s.clone(), Ev::Cancel(2));
        assert_eq!(s2.queue, s.queue);
        assert_eq!(merge_enabled(&s2), before);
    }

    /// `CiSpecBite.budget_60_did_not_fit` / `budget_360_fits`, numerically.
    #[test]
    fn the_2026_09_04_group() {
        let jobs = [45, 30, 28, 25, 23, 20, 15, 15, 10, 10, 5, 5];
        assert_eq!(jobs.iter().sum::<u64>(), 231);
        assert!(makespan(&greedy(4, &jobs)) >= 60);
        assert!(makespan(&greedy(4, &jobs)) <= 360);
        assert!(makespan(&greedy_from(&[50, 50, 50, 50], &jobs)) > 60);
    }

    #[test]
    fn try_step_reports_out_of_order_merge() {
        let s = run(State::init(), &[Ev::Enqueue(1), Ev::Enqueue(2), Ev::Pass(2)]);
        // Head is 1 and its checks are not green: merging is illegal.
        let err = try_step(s, Ev::Merge).expect_err("merge must be illegal");
        assert!(matches!(err.1, Illegal::HeadNotGreen(1)));
    }
}
