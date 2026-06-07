// Model ↔ production parity for the cardinal-scoring kernel. Bridges the
// PRODUCTION `nucleus_rubric` scoring functions to the Mathlib-free Lean model
// they are pinned to, by transcribing the Lean defs into a Rust mirror and
// asserting BYTE-EQUALITY over random scorecards.
//
// ── Proof ↔ production pin (grep me) ─────────────────────────────────────────
//
// Lean source: `crates/nucleus-rubric/lean/Nucleus/Rubric.lean`
// (namespace `Nucleus.Rubric`, Lean 4 v4.30.0-rc2, Mathlib-free, 0 `sorry`,
//  no `native_decide`; built + sorry-banned by `.github/workflows/rubric-lean.yml`).
//
//   MODEL DEFS (the Rust mirror below transcribes these EXACTLY):
//     • `faithfulTotal : Scorecard → Nat`            (lines 85-89)
//         fold of `if p.isLoadBearing then w*g else 0` over the columns.
//     • `Provenance.isLoadBearing`                    (lines 69-72)
//         `true` iff `RecomputeVerified` — the single gate.
//     • `rvVec : Scorecard → List Nat`                (lines 95-99)
//     • `allGe` / `anyGt` / `dominatesVec`            (lines 109-127)
//         `dominatesVec a b = allGe a b && anyGt a b` (every coord ≥ AND one >).
//
//   THEOREMS (each has a binding Rust witness — proptests below + in src/lib.rs):
//     • `faithfulTotal_inert_under_non_rv`            (lines 154-171)
//         witness: `faithful_total_invariant_under_non_rv_perturbation` (lib.rs).
//     • `ranksAtLeast_refl` / `_trans` / `_total`     (lines 183-193)
//         witness: `ranks_at_least_is_total_order` (lib.rs).
//     • `faithfulTotal_mono_in_rv_grade`              (lines 212-232)
//         witness: `raising_rv_grade_weakly_increases_total` (THIS file).
//     • `scalarized_winner_undominated`               (lines 352-379)
//       + its core `dominates_strengthens_total`      (lines 306-339)
//         witness: `scalarized_winner_is_in_pareto_front` (lib.rs).
//
// **The parity claim** asserted below: the Rust mirror is a TRANSCRIPTION of the
// Lean MODEL (`faithfulTotal` / `dominatesVec`), asserted EQUAL to the PRODUCTION
// `faithful_total` / `dominates` over random scorecards. The mirror is NOT the
// production function — it is a hand-written copy of the Lean defs. The proptest
// (~256 cases over a single fixed rubric shape) NARROWS the model↔Rust gap
// PROBABILISTICALLY; it does NOT close it and is NOT a formal extraction. A
// counterexample outside the sampled distribution could still diverge.
//
// ── EXTRACTION-GAP CAVEAT (grep me) ──────────────────────────────────────────
// The four theorems are proved about the Lean MODEL. These parity proptests bind
// them to the SHIPPED Rust only PROBABILISTICALLY (random sampling, finite cases).
// A formal Aeneas-style extraction of `faithful_total` (as in nucleus-econ-kernels)
// would be required to close the model↔Rust gap DEDUCTIVELY. Until then, treat the
// theorems as statements about the model, parity-checked — not extracted — into Rust.
//
// Self-contained: imports only the crate's own public surface plus proptest.

#![deny(clippy::float_arithmetic)]

use nucleus_rubric::{
    dominates, faithful_total, pareto_front, winner, Criterion, Provenance, Rubric, Scorecard,
};
use proptest::prelude::*;

// ── The Lean model, transcribed to Rust (the spec-pinned mirror) ─────────────

/// The Lean `Column` = `(Provenance, weight, grade)`. We build the Lean
/// `Scorecard` (list of columns) from a production `(Rubric, Scorecard)` pair by
/// zipping criteria with grades positionally — the Lean image of the Rust pair.
fn lean_columns(rubric: &Rubric, sc: &Scorecard) -> Vec<(Provenance, u128, u128)> {
    rubric
        .criteria
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let g = sc.grades.get(i).copied().unwrap_or(0) as u128;
            (c.provenance, c.weight as u128, g)
        })
        .collect()
}

/// Mirror of Lean `Provenance.isLoadBearing`: `true` iff `RecomputeVerified`.
fn lean_is_load_bearing(p: Provenance) -> bool {
    matches!(p, Provenance::RecomputeVerified)
}

/// Mirror of Lean `faithfulTotal`: fold `if p.isLoadBearing then w*g else 0`.
fn lean_faithful_total(cols: &[(Provenance, u128, u128)]) -> u128 {
    cols.iter()
        .map(|&(p, w, g)| if lean_is_load_bearing(p) { w * g } else { 0 })
        .sum()
}

/// Mirror of Lean `rvVec`: the grades of the RV columns, in order.
fn lean_rv_vec(cols: &[(Provenance, u128, u128)]) -> Vec<u128> {
    cols.iter()
        .filter(|&&(p, _, _)| lean_is_load_bearing(p))
        .map(|&(_, _, g)| g)
        .collect()
}

/// Mirror of Lean `allGe`: every parallel coordinate `≥` (false on len mismatch).
fn lean_all_ge(a: &[u128], b: &[u128]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x >= y)
}

/// Mirror of Lean `anyGt`: some parallel coordinate `>` (false on len mismatch).
fn lean_any_gt(a: &[u128], b: &[u128]) -> bool {
    a.len() == b.len() && a.iter().zip(b).any(|(x, y)| x > y)
}

/// Mirror of Lean `dominatesVec`: `allGe && anyGt`. (Empty vectors → false, since
/// `anyGt [] [] = false`.)
fn lean_dominates_vec(a: &[u128], b: &[u128]) -> bool {
    lean_all_ge(a, b) && lean_any_gt(a, b)
}

/// Mirror of Lean `dominates`: compare RV grade projections.
fn lean_dominates(rubric: &Rubric, a: &Scorecard, b: &Scorecard) -> bool {
    let av = lean_rv_vec(&lean_columns(rubric, a));
    let bv = lean_rv_vec(&lean_columns(rubric, b));
    lean_dominates_vec(&av, &bv)
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// The same fixed 5-criterion rubric as the inline tests: 3 RV (weights 5,3,2 —
/// all `> 0`, satisfying `AllPos` for the scalarized-winner theorem), 1 Attested,
/// 1 AttestationOnly. One `Rubric` scores all cards ⇒ the Lean `CommonRvWeights`
/// hypothesis holds by construction.
fn fixed_rubric() -> Rubric {
    Rubric::new(vec![
        Criterion {
            id: "correctness".into(),
            provenance: Provenance::RecomputeVerified,
            weight: 5,
            max_grade: 10,
        },
        Criterion {
            id: "coverage".into(),
            provenance: Provenance::RecomputeVerified,
            weight: 3,
            max_grade: 10,
        },
        Criterion {
            id: "determinism".into(),
            provenance: Provenance::RecomputeVerified,
            weight: 2,
            max_grade: 10,
        },
        Criterion {
            id: "cost".into(),
            provenance: Provenance::Attested,
            weight: 7,
            max_grade: 10,
        },
        Criterion {
            id: "llm_judge".into(),
            provenance: Provenance::AttestationOnly,
            weight: 9,
            max_grade: 100,
        },
    ])
    .unwrap()
}

fn arb_scorecard(r: Rubric) -> impl Strategy<Value = Scorecard> {
    let n = r.len();
    ("[a-z]{1,6}", proptest::collection::vec(any::<u32>(), n)).prop_map(move |(id, raw)| {
        let grades = raw
            .iter()
            .enumerate()
            .map(|(i, &g)| g % (r.max_grade_at(i) + 1))
            .collect();
        Scorecard {
            artifact_id: id,
            grades,
        }
    })
}

proptest! {
    /// PARITY: the Lean-mirror `faithful_total` equals the PRODUCTION
    /// `nucleus_rubric::faithful_total` over random scorecards. This is the
    /// model↔production bridge for `faithfulTotal` (Rubric.lean:85).
    #[test]
    fn lean_mirror_faithful_total_matches_production(
        sc in arb_scorecard(fixed_rubric()),
    ) {
        let r = fixed_rubric();
        let production = faithful_total(&r, &sc);
        let model = lean_faithful_total(&lean_columns(&r, &sc));
        prop_assert_eq!(production, model);
    }

    /// PARITY: the Lean-mirror `dominates` equals the PRODUCTION
    /// `nucleus_rubric::dominates` over random scorecard pairs. The bridge for
    /// `dominatesVec` (Rubric.lean:126) — note both agree the empty/equal RV case
    /// is NOT a dominance.
    #[test]
    fn lean_mirror_dominates_matches_production(
        a in arb_scorecard(fixed_rubric()),
        b in arb_scorecard(fixed_rubric()),
    ) {
        let r = fixed_rubric();
        prop_assert_eq!(dominates(&r, &a, &b), lean_dominates(&r, &a, &b));
    }

    /// WITNESS for `Nucleus.Rubric.faithfulTotal_mono_in_rv_grade` (Rubric.lean:212):
    /// raising any single RV grade weakly (weights held fixed) weakly raises the
    /// PRODUCTION `faithful_total`. Bumps `grades[i]` for a random RV index
    /// `i ∈ {0,1,2}` by a delta clamped to that criterion's `max_grade`.
    #[test]
    fn raising_rv_grade_weakly_increases_total(
        base in arb_scorecard(fixed_rubric()),
        rv_idx in 0usize..3,   // the three RV columns are indices 0,1,2
        delta in 0u32..=10,
    ) {
        let r = fixed_rubric();
        let before = faithful_total(&r, &base);
        let mut bumped = base.clone();
        let max = r.max_grade_at(rv_idx);
        // Raise weakly, clamped to the criterion ceiling (so the scorecard stays
        // valid and the grade only ever increases).
        bumped.grades[rv_idx] = bumped.grades[rv_idx].saturating_add(delta).min(max);
        prop_assert!(bumped.grades[rv_idx] >= base.grades[rv_idx]);
        prop_assert!(
            faithful_total(&r, &bumped) >= before,
            "raising RV grade lowered the faithful total"
        );
    }

    /// WITNESS for `Nucleus.Rubric.scalarized_winner_undominated` +
    /// `dominates_strengthens_total` (Rubric.lean:352, 306): with the all-positive
    /// RV weights of `fixed_rubric` (5,3,2), the PRODUCTION `winner` (argmax
    /// `faithful_total`) is undominated, i.e. a member of the PRODUCTION
    /// `pareto_front`. Re-asserted here against the Lean-mirror `dominates` so the
    /// witness and the model agree on the dominance relation.
    #[test]
    fn scalarized_winner_is_undominated(
        cards in proptest::collection::vec(arb_scorecard(fixed_rubric()), 1..6),
    ) {
        let r = fixed_rubric();
        let w = winner(&r, &cards).unwrap();
        let front = pareto_front(&r, &cards);
        prop_assert!(front.contains(&w), "winner not in Pareto front");
        // Stronger: NO card dominates the winner (per the Lean theorem), checked
        // against the Lean-mirror dominance relation.
        for (i, sc) in cards.iter().enumerate() {
            if i != w {
                prop_assert!(
                    !lean_dominates(&r, sc, &cards[w]),
                    "a card dominates the scalarized winner"
                );
            }
        }
    }
}
