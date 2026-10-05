//! A translation may not inflate the reward (#2515).
//!
//! `faithful_total = Σ_RV weight × grade`, so a rubric translation that changes
//! `weight` or widens `max_grade` lets the same artifact score higher under the
//! translated rubric than under the source rubric. That is a reward-hacking
//! route: grade under the vocabulary that pays more. These tests pin the
//! invariant `check_translation` must enforce — for every mapped criterion
//! `weight × max_grade` (its *stakes*) is preserved, and a target criterion
//! outside the image carries no stakes — so `Σ weight × max_grade` and in
//! particular the maximum attainable faithful total is preserved.
//!
//! A-19: these tests were run red against `main` (where `check_translation`
//! accepted the crate's own 2.5x-distorting fixture) before the fix landed.

use nucleus_rubric::{Criterion, Provenance, Rubric, Scorecard, faithful_total};
use nucleus_rubric_olog::{RubricMapping, check_translation};
use proptest::prelude::*;

fn crit(id: &str, p: Provenance, w: u32, max: u32) -> Criterion {
    Criterion {
        id: id.into(),
        provenance: p,
        weight: w,
        max_grade: max,
    }
}

/// The scorecard that grades every criterion of `r` at its ceiling.
fn ceiling_card(r: &Rubric) -> Scorecard {
    Scorecard {
        artifact_id: "ceiling".into(),
        grades: r.criteria.iter().map(|c| c.max_grade).collect(),
    }
}

/// The maximum attainable faithful (ranking) total under `r`.
fn max_attainable(r: &Rubric) -> u128 {
    faithful_total(r, &ceiling_card(r))
}

/// The source rubric of the crate's own unit fixture.
fn rubric_a() -> Rubric {
    Rubric::new(vec![
        crit("correctness", Provenance::RecomputeVerified, 5, 10),
        crit("coverage", Provenance::RecomputeVerified, 3, 10),
        crit("cost", Provenance::Attested, 7, 10),
    ])
    .unwrap()
}

fn map_a_to_b() -> RubricMapping {
    RubricMapping::new([
        ("correctness", "accuracy"),
        ("coverage", "tests"),
        ("cost", "spend"),
    ])
}

// ── The adversarial corpus: every translation here inflates the reward ──────

/// One named translation `rubric_a() → b` that must be refused.
struct Inflating {
    name: &'static str,
    b: Rubric,
}

fn corpus() -> Vec<Inflating> {
    vec![
        Inflating {
            // The fixture `check_translation` used to accept: RV weights
            // 5,3 → 4,6. An artifact graded coverage=10, correctness=0 scores
            // 30 under A and 60 under B.
            name: "reweight_rv_5_3_to_4_6",
            b: Rubric::new(vec![
                crit("accuracy", Provenance::RecomputeVerified, 4, 10),
                crit("tests", Provenance::RecomputeVerified, 6, 10),
                crit("spend", Provenance::Attested, 7, 10),
            ])
            .unwrap(),
        },
        Inflating {
            // The issue's 7→2 fixture: an Attested weight silently rescaled.
            name: "attested_weight_7_to_2",
            b: Rubric::new(vec![
                crit("accuracy", Provenance::RecomputeVerified, 5, 10),
                crit("tests", Provenance::RecomputeVerified, 3, 10),
                crit("spend", Provenance::Attested, 2, 10),
            ])
            .unwrap(),
        },
        Inflating {
            // max_grade doubled at fixed weight: the widening that the old
            // rule (`b.max_grade >= a.max_grade`) explicitly allowed. The
            // ceiling total goes 80 → 100.
            name: "max_grade_doubled",
            b: Rubric::new(vec![
                crit("accuracy", Provenance::RecomputeVerified, 5, 20),
                crit("tests", Provenance::RecomputeVerified, 3, 10),
                crit("spend", Provenance::Attested, 7, 10),
            ])
            .unwrap(),
        },
        Inflating {
            // Every mapped stake preserved, but B carries an extra RV
            // criterion outside the image: B pays 40 more at the ceiling.
            name: "extra_unmapped_rv_target",
            b: Rubric::new(vec![
                crit("accuracy", Provenance::RecomputeVerified, 5, 10),
                crit("tests", Provenance::RecomputeVerified, 3, 10),
                crit("spend", Provenance::Attested, 7, 10),
                crit("bonus", Provenance::RecomputeVerified, 4, 10),
            ])
            .unwrap(),
        },
    ]
}

#[test]
fn every_inflating_translation_is_refused() {
    let a = rubric_a();
    let accepted: Vec<&str> = corpus()
        .iter()
        .filter(|case| check_translation(&a, &case.b, &map_a_to_b()).is_ok())
        .map(|case| case.name)
        .collect();
    assert!(
        accepted.is_empty(),
        "check_translation accepted reward-inflating translations: {accepted:?}"
    );
}

/// The concrete inflation the crate's old fixture carried: the SAME grades
/// score twice as high under the translated rubric.
#[test]
fn reweighting_fixture_doubles_the_same_artifacts_score() {
    let a = rubric_a();
    let b = &corpus()[0].b;
    let card = Scorecard {
        artifact_id: "same-output".into(),
        grades: vec![0, 10, 0],
    };
    assert_eq!(faithful_total(&a, &card), 30);
    assert_eq!(faithful_total(b, &card), 60);
    assert!(check_translation(&a, b, &map_a_to_b()).is_err());
}

// ── Property: an accepted translation never raises the attainable reward ────

/// How one target criterion is derived from its source criterion.
#[derive(Debug, Clone, Copy)]
enum Derive {
    /// Same weight and ceiling (stakes trivially preserved).
    Copy,
    /// `max × k`, `weight ÷ k` — stakes-preserving when `k` divides `weight`,
    /// a straight inflation otherwise (the weight is then left unchanged).
    Rescale(u32),
    /// Arbitrary weight and ceiling.
    Arbitrary(u32, u32),
}

fn provenance() -> impl Strategy<Value = Provenance> {
    prop_oneof![
        Just(Provenance::RecomputeVerified),
        Just(Provenance::Attested),
        Just(Provenance::AttestationOnly),
    ]
}

fn derive() -> impl Strategy<Value = Derive> {
    prop_oneof![
        3 => Just(Derive::Copy),
        3 => (1u32..=4).prop_map(Derive::Rescale),
        2 => (0u32..=12, 0u32..=24).prop_map(|(w, m)| Derive::Arbitrary(w, m)),
    ]
}

/// `(a, b, mapping, all_stakes_preserving)` — `b` is a reversed, renamed copy
/// of `a` with per-criterion [`Derive`] edits and up to two extra targets.
fn translation() -> impl Strategy<Value = (Rubric, Rubric, RubricMapping, bool)> {
    let column = (provenance(), 0u32..=12, 0u32..=12, derive());
    let extra = (provenance(), 0u32..=6, 0u32..=6);
    (
        prop::collection::vec(column, 1..6),
        prop::collection::vec(extra, 0..3),
    )
        .prop_map(|(cols, extras)| {
            let mut a_crits = Vec::new();
            let mut b_crits = Vec::new();
            let mut pairs = Vec::new();
            let mut preserving = true;
            for (i, (p, w, m, d)) in cols.iter().enumerate() {
                // The first column is RV so `Rubric::new` accepts both sides.
                let p = if i == 0 {
                    Provenance::RecomputeVerified
                } else {
                    *p
                };
                let (bw, bm) = match *d {
                    Derive::Copy => (*w, *m),
                    Derive::Rescale(k) if w % k == 0 => (w / k, m * k),
                    Derive::Rescale(k) => (*w, m * k),
                    Derive::Arbitrary(bw, bm) => (bw, bm),
                };
                // Stakes equal, and the ceiling not narrowed (narrowing is
                // refused separately: a migrated grade could leave B's range).
                preserving &=
                    u64::from(*w) * u64::from(*m) == u64::from(bw) * u64::from(bm) && bm >= *m;
                a_crits.push(crit(&format!("a{i}"), p, *w, *m));
                b_crits.push(crit(&format!("b{i}"), p, bw, bm));
                pairs.push((format!("a{i}"), format!("b{i}")));
            }
            for (j, (p, w, m)) in extras.iter().enumerate() {
                preserving &= u64::from(*w) * u64::from(*m) == 0;
                b_crits.push(crit(&format!("extra{j}"), *p, *w, *m));
            }
            b_crits.reverse();
            (
                Rubric::new(a_crits).unwrap(),
                Rubric::new(b_crits).unwrap(),
                RubricMapping::new(pairs),
                preserving,
            )
        })
}

proptest! {
    /// Soundness: no translation that passes `check_translation` raises the
    /// maximum attainable faithful total.
    #[test]
    fn accepted_translation_never_raises_max_attainable((a, b, m, _) in translation()) {
        if check_translation(&a, &b, &m).is_ok() {
            prop_assert!(
                max_attainable(&b) <= max_attainable(&a),
                "accepted translation inflates the ceiling: {} -> {}",
                max_attainable(&a),
                max_attainable(&b),
            );
        }
    }

    /// Non-vacuity of the property above: a translation that preserves every
    /// stake IS accepted, so the soundness property is exercised on a family
    /// that passes the gate rather than holding only because nothing passes.
    #[test]
    fn stakes_preserving_translation_is_accepted((a, b, m, preserving) in translation()) {
        if preserving {
            prop_assert_eq!(check_translation(&a, &b, &m), Ok(()));
            prop_assert_eq!(max_attainable(&b), max_attainable(&a));
        }
    }
}
