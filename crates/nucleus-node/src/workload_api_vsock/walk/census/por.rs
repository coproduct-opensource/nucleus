//! The guest walk, exhaustive to a bound, explored one ordering per equivalence
//! class — the payoff of the commutation census.
//!
//! # Why this is sound
//!
//! The census measures, from EVERY reachable host state, which pairs of letters
//! commute; it asserts the result equals [`declared_hollow`]. A pair outside that
//! set is therefore independent in the trace-theory sense: swapping two adjacent
//! independent letters changes no reply either one gets and no part of the host
//! record, so it changes nothing the rest of the sequence can observe. Two words
//! that differ only by such swaps are one Mazurkiewicz trace, and checking one of
//! them checks all.
//!
//! The independence relation is read from the census's declaration, not restated:
//! if the census's assertion fails, this has no ground to stand on, and they fail
//! together.
//!
//! # How
//!
//! Depth-first over all words to [`DEPTH`], with sleep sets (Godefroid): after
//! exploring letter `a` from a node, `a` sleeps in the node's later subtrees for as
//! long as the letters chosen there are independent of it. Every word the walk
//! visits is model-checked against the walk's [`Model`], step by step, snapshot
//! decision included.
//!
//! # Two checks that the reduction itself is right
//!
//! - **Count.** The words sleep sets visit must be exactly the lexicographic normal
//!   forms, computed independently by rewriting `ba → ab` for independent `a < b`.
//!   Fewer is a class never checked; more is no reduction.
//! - **Observation.** To [`VALIDATE_DEPTH`], EVERY word is run, and what the host
//!   observed — each letter's replies in order, and the record — must equal what
//!   it observed for the word's normal form. That tests the independence relation
//!   against the code, not against the declaration.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Exhaustive depth for the model-checked, reduced walk.
const DEPTH: usize = 4;
/// Depth to which every unreduced word is run to validate the reduction.
const VALIDATE_DEPTH: usize = 3;

fn letter_index(letters: &[Letter], l: Letter) -> usize {
    letters.iter().position(|x| *x == l).unwrap_or(usize::MAX)
}

/// Independence from the census's declaration: distinct, and not a hollow face.
fn independence(letters: &[Letter]) -> Vec<Vec<bool>> {
    let hollow = declared_hollow();
    letters
        .iter()
        .map(|a| {
            letters
                .iter()
                .map(|b| {
                    a != b
                        && !hollow.contains(&(a.name(), b.name()))
                        && !hollow.contains(&(b.name(), a.name()))
                })
                .collect()
        })
        .collect()
}

/// The lexicographic normal form of a word under independence `ind`: the least
/// word of its trace.
///
/// Built front to back: at each step, the letters that could come first are those
/// independent of everything before them in what remains; take the least. A local
/// rule — swap adjacent out-of-order independent letters — is NOT this: from
/// `[15, 0, 1]` with 1 independent of both, it never moves 1 past 0 (already in
/// order) and so never finds `[1, 15, 0]`. That first version split classes, and
/// the count check below caught it.
fn normal_form(word: &[usize], ind: &[Vec<bool>]) -> Vec<usize> {
    let mut rest = word.to_vec();
    let mut out = Vec::with_capacity(rest.len());
    while !rest.is_empty() {
        let movable = (0..rest.len())
            .filter(|&i| rest[..i].iter().all(|&before| ind[before][rest[i]]))
            .min_by_key(|&i| rest[i]);
        let Some(i) = movable else {
            // Position 0 is always movable, so this cannot happen.
            return word.to_vec();
        };
        out.push(rest.remove(i));
    }
    out
}

/// Every word to `depth`, as index sequences.
fn all_words(n: usize, depth: usize) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for w in &frontier {
            for l in 0..n {
                let mut x: Vec<usize> = w.clone();
                x.push(l);
                next.push(x);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

/// The words sleep-set DFS visits to `depth`.
fn sleep_set_words(n: usize, depth: usize, ind: &[Vec<bool>]) -> Vec<Vec<usize>> {
    fn dfs(
        word: &mut Vec<usize>,
        sleep: &BTreeSet<usize>,
        depth: usize,
        n: usize,
        ind: &[Vec<bool>],
        out: &mut Vec<Vec<usize>>,
    ) {
        out.push(word.clone());
        if word.len() == depth {
            return;
        }
        let mut done: BTreeSet<usize> = BTreeSet::new();
        for l in 0..n {
            if sleep.contains(&l) {
                continue;
            }
            let child_sleep: BTreeSet<usize> = sleep
                .iter()
                .chain(done.iter())
                .copied()
                .filter(|s| ind[*s][l])
                .collect();
            word.push(l);
            dfs(word, &child_sleep, depth, n, ind, out);
            word.pop();
            done.insert(l);
        }
    }
    let mut out = Vec::new();
    dfs(&mut Vec::new(), &BTreeSet::new(), depth, n, ind, &mut out);
    out
}

/// What the host observed: each letter's replies in order, and the record.
type Observation = (BTreeMap<usize, Vec<Seen>>, Record);

/// Run `word` from the initial state; model-check every step; return what the
/// host observed.
async fn check_word(
    manager: &IdentityManager,
    provision: Provision,
    letters: &[Letter],
    word: &[usize],
) -> Result<Observation, String> {
    let seq: Vec<Letter> = word.iter().map(|i| letters[*i]).collect();
    let (seen, record) = run(manager, provision, &Record::initial(), &seq).await;

    let mut model = Model::new(provision);
    for (step, (letter, got)) in seq.iter().zip(&seen).enumerate() {
        let at = || {
            format!(
                "{:?} step {step}",
                seq.iter().map(|l| l.name()).collect::<Vec<_>>()
            )
        };
        match letter {
            Letter::HostSnapshotQuery => {
                let want = Seen::Verdict(model.snapshot_verdict());
                if *got != want {
                    return Err(format!("{}: host decided {got:?}, model {want:?}", at()));
                }
            }
            Letter::Guest(_) | Letter::Unknown => {
                let op = match letter {
                    Letter::Guest(i) => Op::Command(COMMANDS[*i]),
                    Letter::Unknown | Letter::HostSnapshotQuery => Op::Unknown,
                };
                let expect = model.pre(&op);
                let agrees = match (&expect, got) {
                    (Expect::Served, Seen::Served(_)) => true,
                    (Expect::Refused(want), Seen::Refused(got)) => want == got,
                    (Expect::Served | Expect::Refused(_), _) => false,
                };
                if !agrees {
                    return Err(format!("{}: host {got:?}, model {expect:?}", at()));
                }
                model.eff(&op, &expect);
            }
        }
    }
    let model_record = (
        model.personalized,
        model.at_barrier,
        model.broker_served,
        model.mediation_key_served,
        model.audit_served,
    );
    let host_record = (
        record.personalized,
        record.at_barrier,
        record.broker_served,
        record.mediation_key_served,
        record.audit_served,
    );
    if model_record != host_record {
        return Err(format!(
            "record {host_record:?}, model {model_record:?} after {word:?}"
        ));
    }

    let mut per_letter: BTreeMap<usize, Vec<Seen>> = BTreeMap::new();
    for (i, s) in word.iter().zip(seen) {
        per_letter.entry(*i).or_default().push(s);
    }
    Ok((per_letter, record))
}

#[test]
fn the_reduced_walk_checks_every_class_and_the_reduction_is_exact() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let manager = IdentityManager::new("por.local", std::time::Duration::from_secs(3600))
            .expect("identity manager");
        let letters = Letter::all();
        let n = letters.len();
        let ind = independence(&letters);
        let host = letter_index(&letters, Letter::HostSnapshotQuery);
        assert!(host < n, "the host letter is in the alphabet");

        // 1. Count: sleep sets visit exactly one word per class. Not necessarily the
        //    lexicographically least word of the class — so the check is that the
        //    visited words' normal forms are all distinct and cover every class.
        for depth in 1..=DEPTH {
            let visited = sleep_set_words(n, depth, &ind);
            let visited_classes: BTreeSet<Vec<usize>> =
                visited.iter().map(|w| normal_form(w, &ind)).collect();
            assert_eq!(
                visited.len(),
                visited_classes.len(),
                "two visited words share a class at depth {depth}: the reduction is not a reduction"
            );
            let classes: BTreeSet<Vec<usize>> = all_words(n, depth)
                .iter()
                .map(|w| normal_form(w, &ind))
                .collect();
            let missed: Vec<&Vec<usize>> = classes.difference(&visited_classes).take(5).collect();
            assert!(
                missed.is_empty() && visited_classes.len() == classes.len(),
                "at depth {depth} sleep sets visited {} classes of {}; first missed: {missed:?}",
                visited_classes.len(),
                classes.len()
            );
        }

        // 2. Observation: every word to VALIDATE_DEPTH looks, to the host, like its
        //    normal form. This is the reduction checked against the code.
        let mut by_class: BTreeMap<Vec<usize>, Observation> = BTreeMap::new();
        let mut words_run = 0usize;
        for &p in &[FULL, EMPTY] {
            by_class.clear();
            for word in all_words(n, VALIDATE_DEPTH) {
                let nf = normal_form(&word, &ind);
                let observed = match check_word(&manager, p, &letters, &word).await {
                    Ok(o) => o,
                    Err(e) => panic!("model disagreement: {e}"),
                };
                words_run += 1;
                match by_class.get(&nf) {
                    Some(rep) => assert!(
                        *rep == observed,
                        "{word:?} and its normal form {nf:?} look different to the host: \
                         the independence relation is wrong"
                    ),
                    None => {
                        by_class.insert(nf, observed);
                    }
                }
            }
        }

        // 3. The reduced walk proper: every class to DEPTH, model-checked.
        let mut classes_checked = 0usize;
        for &p in &[FULL, EMPTY] {
            for word in sleep_set_words(n, DEPTH, &ind) {
                if let Err(e) = check_word(&manager, p, &letters, &word).await {
                    panic!("model disagreement: {e}");
                }
                classes_checked += 1;
            }
        }

        let naive: usize = (0..=DEPTH)
            .map(|d| n.pow(u32::try_from(d).expect("a walk depth fits in u32")))
            .sum();
        let reduced = sleep_set_words(n, DEPTH, &ind).len();
        eprintln!(
            "por: {n} letters; depth {DEPTH}: {naive} words, {reduced} classes \
             ({}.{}x); {classes_checked} class checks; {words_run} words run to validate at depth \
             {VALIDATE_DEPTH}",
            naive / reduced,
            naive * 10 / reduced % 10
        );

        // Non-vacuity: a reduction that reduces nothing is not the claim.
        assert!(reduced < naive, "no reduction");
        // And one that swallowed A5 would reduce to nothing useful: svid;query and
        // query;svid must be two classes.
        let svid = letter_index(&letters, Letter::Guest(0));
        assert_ne!(
            normal_form(&[svid, host], &ind),
            normal_form(&[host, svid], &ind),
            "A5's two orders collapsed into one class"
        );
    });
}
