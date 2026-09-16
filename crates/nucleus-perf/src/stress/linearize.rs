//! Is a concurrent history explainable by some sequential order?
//!
//! Linearizability (Herlihy & Wing): each call takes effect at one instant
//! between its invocation and its return, and the results agree with a sequential
//! model run in that order. The checker is Wing & Gong's search — repeatedly pick a
//! *minimal* call (one no pending call returned before it was invoked), apply it to
//! the model, recurse — with the memoisation Lowe and Porcupine add: a (done-set,
//! state) pair already explored is not explored again.
//!
//! Three things keep it tractable on real histories:
//!
//! - **Partitions** (Porcupine's P-compositionality). Calls on independent parts of
//!   the state — one file and another — cannot constrain each other's order, so
//!   [`SeqModel::partition`] splits the history and each part is checked alone.
//!   Measured on the first run: four clients hammering one proxy leave no quiescent
//!   point at all, so without this the whole run is one window.
//! - **Quiescent windows.** A history is cut wherever no call spans the cut. The
//!   windows are checked in order, carrying the *set* of states the previous window
//!   could end in (the model may be nondeterministic: a rate-limited call is
//!   consistent with any state and changes none).
//! - **A budget.** A search that visits more than [`MAX_STATES`] (done-set, state)
//!   pairs stops and reports [`Verdict::BudgetExceeded`] — "could not look", never
//!   a pass.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

/// (done-set, state) pairs one window's search may visit before giving up.
pub const MAX_STATES: usize = 2_000_000;

/// A sequential specification.
pub trait SeqModel: Clone + Eq + Hash {
    type Op: Clone + Debug;
    type Out: Clone + Debug;

    /// The state after `op`, if `observed` is a result the model allows for `op`
    /// in this state; `None` if it is not.
    fn step(&self, op: &Self::Op, observed: &Self::Out) -> Option<Self>;

    /// Which independent part of the state `op` touches. Calls in different
    /// partitions are checked separately; `None` touches nothing, so each such call
    /// is checked alone against the initial state.
    fn partition(&self, op: &Self::Op) -> Option<u64>;
}

/// One completed call. Times are any monotonic unit; only their order matters.
#[derive(Debug, Clone)]
pub struct Call<Op, Out> {
    pub invoke: u64,
    pub ret: u64,
    pub op: Op,
    pub out: Out,
}

#[derive(Debug)]
pub enum Verdict<Op, Out> {
    /// Some sequential order explains every call.
    Linearizable,
    /// No order does. `window` is the first window that could not be explained,
    /// and `explained` the most calls of it any order got through before sticking.
    NotLinearizable {
        window: Vec<Call<Op, Out>>,
        explained: usize,
    },
    /// The search ran out of budget: could not look.
    BudgetExceeded { window_len: usize },
}

/// Split into windows no call spans, in invocation order.
pub fn quiescent_windows<Op: Clone, Out: Clone>(
    calls: &[Call<Op, Out>],
) -> Vec<Vec<Call<Op, Out>>> {
    let mut sorted = calls.to_vec();
    sorted.sort_by_key(|c| (c.invoke, c.ret));
    let mut out: Vec<Vec<Call<Op, Out>>> = Vec::new();
    let mut open_until: Option<u64> = None;
    for c in sorted {
        match (open_until, out.last_mut()) {
            (Some(t), Some(w)) if c.invoke <= t => {
                open_until = Some(t.max(c.ret));
                w.push(c);
            }
            _ => {
                open_until = Some(c.ret);
                out.push(vec![c]);
            }
        }
    }
    out
}

/// Check `calls` against `init`, partition by partition.
pub fn check<M: SeqModel>(init: &M, calls: &[Call<M::Op, M::Out>]) -> Verdict<M::Op, M::Out> {
    let mut parts: BTreeMap<Option<u64>, Vec<Call<M::Op, M::Out>>> = BTreeMap::new();
    for c in calls {
        parts
            .entry(init.partition(&c.op))
            .or_default()
            .push(c.clone());
    }
    for (key, part) in parts {
        // A stateless call explains itself or not; nothing else orders it.
        let chunks: Vec<Vec<Call<M::Op, M::Out>>> = match key {
            None => part.into_iter().map(|c| vec![c]).collect(),
            Some(_) => vec![part],
        };
        for chunk in chunks {
            match check_part(init, &chunk) {
                Verdict::Linearizable => {}
                other => return other,
            }
        }
    }
    Verdict::Linearizable
}

fn check_part<M: SeqModel>(init: &M, calls: &[Call<M::Op, M::Out>]) -> Verdict<M::Op, M::Out> {
    let mut states = vec![init.clone()];
    for window in quiescent_windows(calls) {
        let Some((finals, explained)) = search(&states, &window) else {
            return Verdict::BudgetExceeded {
                window_len: window.len(),
            };
        };
        if finals.is_empty() {
            return Verdict::NotLinearizable { window, explained };
        }
        states = finals;
    }
    Verdict::Linearizable
}

/// Every state the window can end in, over every start state and order, and the
/// deepest point any order reached; `None` if the budget ran out first.
fn search<M: SeqModel>(starts: &[M], window: &[Call<M::Op, M::Out>]) -> Option<(Vec<M>, usize)> {
    let n = window.len();
    let words = n.div_ceil(64);
    let is_done = |done: &[u64], i: usize| done[i / 64] & (1u64 << (i % 64)) != 0;
    let mut seen: HashSet<(Vec<u64>, M)> = HashSet::new();
    let mut finals: HashSet<M> = HashSet::new();
    let mut deepest = 0usize;
    let mut stack: Vec<(Vec<u64>, usize, M)> = starts
        .iter()
        .map(|s| (vec![0u64; words], 0, s.clone()))
        .collect();
    while let Some((done, depth, state)) = stack.pop() {
        if !seen.insert((done.clone(), state.clone())) {
            continue;
        }
        if seen.len() > MAX_STATES {
            return None;
        }
        deepest = deepest.max(depth);
        if depth == n {
            finals.insert(state);
            continue;
        }
        // The earliest return among calls not yet placed: a call invoked after it
        // cannot come first, because that pending call had already finished.
        let min_ret = (0..n)
            .filter(|i| !is_done(&done, *i))
            .map(|i| window[i].ret)
            .min()
            .unwrap_or(u64::MAX);
        for (i, c) in window.iter().enumerate() {
            if is_done(&done, i) || c.invoke > min_ret {
                continue;
            }
            if let Some(next) = state.step(&c.op, &c.out) {
                let mut d = done.clone();
                d[i / 64] |= 1u64 << (i % 64);
                stack.push((d, depth + 1, next));
            }
        }
    }
    Some((finals.into_iter().collect(), deepest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-shot approval: granted once, spendable once.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct Approval {
        available: bool,
    }

    #[derive(Debug, Clone)]
    enum Op {
        Grant,
        Spend,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum Out {
        Ok,
        Refused,
        RateLimited,
    }

    impl SeqModel for Approval {
        type Op = Op;
        type Out = Out;
        fn step(&self, op: &Op, observed: &Out) -> Option<Self> {
            match (op, observed) {
                // Rate limiting is allowed anywhere and changes nothing.
                (_, Out::RateLimited) => Some(self.clone()),
                (Op::Grant, Out::Ok) => Some(Approval { available: true }),
                (Op::Spend, Out::Ok) if self.available => Some(Approval { available: false }),
                (Op::Spend, Out::Refused) if !self.available => Some(self.clone()),
                (Op::Grant, Out::Refused) | (Op::Spend, Out::Ok) | (Op::Spend, Out::Refused) => {
                    None
                }
            }
        }
        fn partition(&self, _: &Op) -> Option<u64> {
            Some(0)
        }
    }

    fn call(invoke: u64, ret: u64, op: Op, out: Out) -> Call<Op, Out> {
        Call {
            invoke,
            ret,
            op,
            out,
        }
    }

    fn fresh() -> Approval {
        Approval { available: false }
    }

    #[test]
    fn two_concurrent_spends_of_one_approval_both_succeeding_is_not_linearizable() {
        let h = vec![
            call(0, 1, Op::Grant, Out::Ok),
            call(2, 10, Op::Spend, Out::Ok),
            call(3, 9, Op::Spend, Out::Ok),
        ];
        assert!(matches!(
            check(&fresh(), &h),
            Verdict::NotLinearizable { .. }
        ));
    }

    #[test]
    fn two_concurrent_spends_one_refused_is_linearizable_in_either_order() {
        let h = vec![
            call(0, 1, Op::Grant, Out::Ok),
            // The refused spend RETURNED first, but overlapped the successful one,
            // so the order successful-then-refused is allowed.
            call(2, 10, Op::Spend, Out::Ok),
            call(3, 5, Op::Spend, Out::Refused),
        ];
        assert!(matches!(check(&fresh(), &h), Verdict::Linearizable));
    }

    #[test]
    fn order_is_forced_when_calls_do_not_overlap() {
        // The refused spend finished before the grant began, so it comes first — and
        // a refused spend before any grant is correct.
        let h = vec![
            call(0, 1, Op::Spend, Out::Refused),
            call(2, 3, Op::Grant, Out::Ok),
            call(4, 5, Op::Spend, Out::Ok),
        ];
        assert!(matches!(check(&fresh(), &h), Verdict::Linearizable));
        // A successful spend strictly before the grant is not.
        let h = vec![
            call(0, 1, Op::Spend, Out::Ok),
            call(2, 3, Op::Grant, Out::Ok),
        ];
        assert!(matches!(
            check(&fresh(), &h),
            Verdict::NotLinearizable { explained: 0, .. }
        ));
    }

    #[test]
    fn a_nondeterministic_result_carries_every_state_across_windows() {
        let h = vec![
            call(0, 1, Op::Grant, Out::RateLimited), // no effect
            call(2, 3, Op::Spend, Out::Refused),     // so nothing to spend
        ];
        assert!(matches!(check(&fresh(), &h), Verdict::Linearizable));
    }

    #[test]
    fn windows_cut_only_where_nothing_spans() {
        let h = vec![
            call(0, 5, Op::Grant, Out::Ok),
            call(4, 6, Op::Spend, Out::Ok),
            call(7, 8, Op::Spend, Out::Refused),
        ];
        let w = quiescent_windows(&h);
        assert_eq!(w.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 1]);
    }

    #[test]
    fn a_long_window_with_no_quiescent_point_is_still_searched() {
        // 300 calls, never quiescent (each overlaps the next three), far past a u128
        // done-set. Overlap is bounded, as it is on a real history: never more calls
        // in flight than there are clients. Fully overlapping calls are exponential
        // for any Wing-Gong checker and are not what a history looks like.
        let h: Vec<_> = (0..300u64)
            .map(|i| call(i, i + 3, Op::Spend, Out::RateLimited))
            .collect();
        assert_eq!(quiescent_windows(&h).len(), 1);
        assert!(matches!(check(&fresh(), &h), Verdict::Linearizable));
    }
}
