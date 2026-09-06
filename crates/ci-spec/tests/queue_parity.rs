//! T3–T6 over random event sequences, on the Rust mirror of
//! `ci/lean/CiSpec/Queue.lean`. The Lean proves these for every sequence;
//! this narrows the model↔mirror gap probabilistically (the K4 convention),
//! beside the golden vectors and the bounded Kani proof.

use ci_spec::queue::{Ev, Loc, State, merge_enabled, run, step};
use proptest::prelude::*;

fn arb_ev() -> impl Strategy<Value = Ev> {
    prop_oneof![
        (0u32..4).prop_map(Ev::Enqueue),
        (0u32..4).prop_map(Ev::Pass),
        (0u32..4).prop_map(Ev::Fail),
        (0u32..4).prop_map(Ev::Push),
        (0u32..4).prop_map(Ev::Cancel),
        Just(Ev::Merge),
    ]
}

proptest! {
    /// T3 + T4: every reachable state is consistent and ordered.
    #[test]
    fn t3_t4_hold_on_every_reachable_state(evs in prop::collection::vec(arb_ev(), 0..24)) {
        let mut s = State::init();
        prop_assert!(s.consistent());
        prop_assert!(s.ordered());
        for e in evs {
            s = step(s, e);
            prop_assert!(s.consistent(), "T3 broken after {e:?}: {s:?}");
            prop_assert!(s.ordered(), "T4 broken after {e:?}: {s:?}");
        }
    }

    /// T5: cancelling a run of a PR not in the queue changes neither the
    /// queue nor whether the head can merge.
    #[test]
    fn t5_cancel_of_a_dequeued_pr_is_safe(evs in prop::collection::vec(arb_ev(), 0..24), p in 0u32..4) {
        let s = run(State::init(), &evs);
        prop_assume!(!s.queue.contains(&p));
        let s2 = step(s.clone(), Ev::Cancel(p));
        prop_assert_eq!(&s2.queue, &s.queue);
        prop_assert_eq!(merge_enabled(&s2), merge_enabled(&s));
    }

    /// T6: a push to a queued PR returns it to waiting and dequeues it.
    #[test]
    fn t6_push_dequeues(evs in prop::collection::vec(arb_ev(), 0..24), idx in 0usize..4) {
        let s = run(State::init(), &evs);
        prop_assume!(!s.queue.is_empty());
        let p = s.queue[idx % s.queue.len()];
        prop_assert_eq!(s.loc(p), Loc::Queued);
        let s2 = step(s, Ev::Push(p));
        prop_assert_eq!(s2.loc(p), Loc::Waiting);
        prop_assert!(!s2.queue.contains(&p));
    }

    /// Merges only ever take the head: merged_log is a prefix-respecting
    /// subsequence of enq_log even under interleaved pushes and re-enqueues.
    #[test]
    fn merges_take_the_head(evs in prop::collection::vec(arb_ev(), 0..24)) {
        let mut s = State::init();
        for e in evs {
            let head = s.queue.first().copied();
            let before = s.merged_log.len();
            s = step(s, e);
            if s.merged_log.len() > before {
                prop_assert_eq!(e, Ev::Merge);
                prop_assert_eq!(s.merged_log.last().copied(), head);
            }
        }
    }
}
