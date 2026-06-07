//! `nucleus-rubric` — a CT-disciplined **cardinal scoring kernel** that applies
//! the same honesty boundary `nucleus-eval` already encodes to a fixed, weighted,
//! multi-criterion rubric.
//!
//! # The honesty boundary (the load-bearing idea)
//!
//! Exactly as in [`nucleus_eval`], a score has a *provenance* that decides whether
//! it is allowed to move the number that matters:
//!
//! * [`Provenance::RecomputeVerified`] — the strong tier. A grade on an RV
//!   criterion is independently re-derivable; **only RV criteria set the ranking
//!   total.** (The analogue of `nucleus-eval`'s `DeterministicCheck`.)
//! * [`Provenance::Attested`] — environmental, carried for provenance, **never**
//!   load-bearing on the rank. (The analogue of `cost_micro_usd` / `tokens` /
//!   `latency_ms`.)
//! * [`Provenance::AttestationOnly`] — a soft signal (e.g. an LLM-judge score).
//!   Carried, never load-bearing. (The analogue of `llm_judge_score`.)
//!
//! [`Provenance::is_load_bearing`] is the single gate, mirroring
//! `nucleus_creditworthiness::CreditDimension::is_active`.
//!
//! # The faithful sub-functor (why a lie can't climb the ranking)
//!
//! Let `π_RV` be the forgetful projection that drops every non-RV column of a
//! [`Scorecard`]. The ranking total
//!
//! ```text
//! faithful_total(rubric, sc) = Σ_{i : provenance_at(i) == RecomputeVerified}
//!                                  weight_at(i) * grades[i]      (u128, exact)
//! ```
//!
//! factors as `(weighted-sum ∘ π_RV)`. Because [`rank`] is a function of
//! `faithful_total` **alone**, `rank` factors through `π_RV`: any two score-vectors
//! with the same RV projection are rank-indistinguishable. That factorization *is*
//! the faithfulness / inertness guarantee — the exact structure of
//! `nucleus-eval`'s `mint_event` (the verdict depends only on the deterministic
//! check; cost / tokens / latency / judge cannot move it) and of
//! `CreditFile::reputation_micro` (only `is_active()` dimensions sum).
//!
//! # Ranking is a total order, transitive by construction
//!
//! [`rank`] sorts by `>=` on a single `u128` ([`faithful_total`]), tie-breaking on
//! `artifact_id`. There is no pairwise / Condorcet path that could cycle:
//! [`ranks_at_least`] is reflexive, transitive **and total** — strictly stronger
//! than `ck-policy`'s amendment *preorder*, and proven against the real [`rank`]
//! function, not a model.
//!
//! # Pareto front + scalarization, then a recomputable VCG-marginal
//!
//! [`pareto_front`] is the maximal antichain over the RV product-poset
//! ([`dominates`] is strict/weak Pareto dominance, higher-is-better). With every
//! RV weight `> 0`, the weighted-sum maximizer is always Pareto-optimal, so
//! [`winner`] (argmax `faithful_total`) is always a [`pareto_front`] member.
//!
//! [`marginal`] is the single-winner VCG-marginal `winner_total - runner_up_total`,
//! derived purely from recorded integer scores. A [`CounterfactualReceipt`]
//! carries the **full** inputs so a third party re-derives both totals and the
//! marginal byte-identically (the `RECEIPT_DOMAIN` / `canonical_bytes` /
//! `receipt_hash` discipline, re-applied from `nucleus-eval`). The marginal mints
//! a **real** [`nucleus_creditworthiness::CreditEvent`].
//!
//! The multi-contributor case (splitting the marginal) is the Shapley extension —
//! explicitly **not** built here; it routes through the sibling `axelrod`
//! (Folk + Shapley) crate. This crate stays single-winner and dependency-light.
//!
//! # WASM safety
//!
//! Integer-only (`u32` grades / weights, `u128` totals), `serde` + `serde_json` +
//! `sha2` + path deps only — no `ring` / `tokio` / `redb`. Builds for `wasm32`.

#![forbid(unsafe_code)]

use nucleus_creditworthiness::CreditEvent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Versioned, domain-separated tag prefixed to the canonical receipt bytes before
/// hashing — the `RECEIPT_DOMAIN` discipline re-applied from `nucleus-eval`.
/// Bumping the `vN` suffix versions the receipt wire format.
pub const RUBRIC_RECEIPT_DOMAIN: &[u8] = b"nucleus-rubric/rubric-receipt/v1\0";

/// How much a score is allowed to be trusted — the three-tier honesty boundary,
/// mirrored from `nucleus-eval`. Only [`Provenance::RecomputeVerified`] is
/// load-bearing on the rank; the other two are carried for provenance but
/// provably inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// The strong tier: independently re-derivable. **Sets the ranking total.**
    RecomputeVerified,
    /// Environmental measurement, carried for provenance, never load-bearing.
    Attested,
    /// A soft, non-deterministic signal (e.g. LLM judge). Carried, never
    /// load-bearing.
    AttestationOnly,
}

impl Provenance {
    /// The single gate: `true` iff [`Provenance::RecomputeVerified`]. The analogue
    /// of `CreditDimension::is_active`.
    pub fn is_load_bearing(self) -> bool {
        matches!(self, Provenance::RecomputeVerified)
    }
}

/// One weighted dimension over a graded axis. A criterion *score* is an integer
/// grade in `0..=max_grade` (no float).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Criterion {
    /// Stable identifier (must be unique within a [`Rubric`]).
    pub id: String,
    /// Whether grades on this criterion are load-bearing on the rank.
    pub provenance: Provenance,
    /// Integer cardinal weight. RV criteria should have `weight > 0` (a zero
    /// weight makes an RV column silently inert).
    pub weight: u32,
    /// Grade ceiling for this criterion — used by Pareto bounds + validation.
    pub max_grade: u32,
}

/// The fixed set of criteria. Canonical order = declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rubric {
    /// The criteria, in canonical (declaration) order.
    pub criteria: Vec<Criterion>,
}

/// One artifact's grades, aligned positionally to [`Rubric::criteria`]. Carries
/// grades for **all** provenances (signal preserved), exactly as `EvalRun` carries
/// cost / tokens / latency / judge alongside the deterministic check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scorecard {
    /// Identity of the artifact being scored.
    pub artifact_id: String,
    /// Grades aligned positionally to the rubric's criteria.
    pub grades: Vec<u32>,
}

/// One artifact's place in the faithful ranking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ranked {
    /// Identity of the ranked artifact.
    pub artifact_id: String,
    /// Its integer weighted cardinal total over the RV columns only.
    pub faithful_total: u128,
    /// Zero-based rank position (`0` = best). Positions are unique across the
    /// output (a total order, deterministic tie-break).
    pub position: usize,
}

/// Construction / validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RubricError {
    /// A rubric must have at least one criterion.
    Empty,
    /// Two criteria share an id.
    DuplicateId(String),
    /// A rubric must have at least one RecomputeVerified criterion, else the rank
    /// is vacuous.
    NoRecomputeVerified,
    /// A scorecard's grade count does not match the rubric's criterion count.
    GradeCountMismatch {
        /// The offending artifact.
        artifact_id: String,
        /// Expected grade count (== number of criteria).
        expected: usize,
        /// Actual grade count.
        got: usize,
    },
    /// A grade exceeds its criterion's `max_grade`.
    GradeExceedsMax {
        /// The offending artifact.
        artifact_id: String,
        /// The offending criterion.
        criterion_id: String,
        /// The offending grade.
        grade: u32,
        /// The criterion's ceiling.
        max_grade: u32,
    },
    /// An operation needs more artifacts than were supplied (e.g. a marginal needs
    /// a runner-up).
    NotEnoughArtifacts {
        /// How many artifacts the operation requires.
        needed: usize,
        /// How many were supplied.
        got: usize,
    },
}

impl std::fmt::Display for RubricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RubricError::Empty => write!(f, "rubric must have at least one criterion"),
            RubricError::DuplicateId(id) => write!(f, "duplicate criterion id: {id}"),
            RubricError::NoRecomputeVerified => write!(
                f,
                "rubric must have at least one RecomputeVerified criterion (else rank is vacuous)"
            ),
            RubricError::GradeCountMismatch {
                artifact_id,
                expected,
                got,
            } => write!(
                f,
                "scorecard {artifact_id}: expected {expected} grades, got {got}"
            ),
            RubricError::GradeExceedsMax {
                artifact_id,
                criterion_id,
                grade,
                max_grade,
            } => write!(
                f,
                "scorecard {artifact_id}: grade {grade} exceeds max_grade {max_grade} on criterion {criterion_id}"
            ),
            RubricError::NotEnoughArtifacts { needed, got } => {
                write!(f, "operation needs {needed} artifacts, got {got}")
            }
        }
    }
}

impl std::error::Error for RubricError {}

impl Rubric {
    /// Build a validated rubric: non-empty, unique ids, at least one
    /// RecomputeVerified criterion.
    pub fn new(criteria: Vec<Criterion>) -> Result<Self, RubricError> {
        if criteria.is_empty() {
            return Err(RubricError::Empty);
        }
        let mut seen = BTreeSet::new();
        for c in &criteria {
            if !seen.insert(c.id.as_str()) {
                return Err(RubricError::DuplicateId(c.id.clone()));
            }
        }
        if !criteria.iter().any(|c| c.provenance.is_load_bearing()) {
            return Err(RubricError::NoRecomputeVerified);
        }
        Ok(Self { criteria })
    }

    /// Number of criteria.
    pub fn len(&self) -> usize {
        self.criteria.len()
    }

    /// Whether the rubric has no criteria (cannot occur for a [`Rubric::new`]-built
    /// value; meaningful only for a hand-constructed one).
    pub fn is_empty(&self) -> bool {
        self.criteria.is_empty()
    }

    /// The RecomputeVerified column indices, in canonical order.
    pub fn rv_indices(&self) -> Vec<usize> {
        self.criteria
            .iter()
            .enumerate()
            .filter(|(_, c)| c.provenance.is_load_bearing())
            .map(|(i, _)| i)
            .collect()
    }

    /// Weight of criterion `i`.
    pub fn weight_at(&self, i: usize) -> u32 {
        self.criteria[i].weight
    }

    /// Provenance of criterion `i`.
    pub fn provenance_at(&self, i: usize) -> Provenance {
        self.criteria[i].provenance
    }

    /// `max_grade` of criterion `i`.
    pub fn max_grade_at(&self, i: usize) -> u32 {
        self.criteria[i].max_grade
    }

    /// Validate a scorecard against this rubric: matching grade count, every grade
    /// within its criterion's `max_grade`.
    pub fn validate_scorecard(&self, sc: &Scorecard) -> Result<(), RubricError> {
        if sc.grades.len() != self.criteria.len() {
            return Err(RubricError::GradeCountMismatch {
                artifact_id: sc.artifact_id.clone(),
                expected: self.criteria.len(),
                got: sc.grades.len(),
            });
        }
        for (c, &g) in self.criteria.iter().zip(&sc.grades) {
            if g > c.max_grade {
                return Err(RubricError::GradeExceedsMax {
                    artifact_id: sc.artifact_id.clone(),
                    criterion_id: c.id.clone(),
                    grade: g,
                    max_grade: c.max_grade,
                });
            }
        }
        Ok(())
    }

    /// Validate every scorecard against this rubric.
    pub fn validate_all(&self, scorecards: &[Scorecard]) -> Result<(), RubricError> {
        for sc in scorecards {
            self.validate_scorecard(sc)?;
        }
        Ok(())
    }
}

/// The faithful weighted cardinal total: `Σ` over RV columns of
/// `weight_at(i) * grades[i]`, as an exact `u128`. This is `(weighted-sum ∘
/// π_RV)` — non-RV grades are never read. Grades missing past the rubric length
/// (a malformed scorecard) are treated as `0` so this never panics; validate with
/// [`Rubric::validate_scorecard`] first for correctness.
pub fn faithful_total(rubric: &Rubric, sc: &Scorecard) -> u128 {
    rubric
        .rv_indices()
        .into_iter()
        .map(|i| {
            let g = sc.grades.get(i).copied().unwrap_or(0) as u128;
            rubric.weight_at(i) as u128 * g
        })
        .sum()
}

/// Internal: indices of `scorecards` in faithful-rank order (best first), with the
/// deterministic total-order tie-break on `artifact_id` ascending.
fn ranked_order(rubric: &Rubric, scorecards: &[Scorecard]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..scorecards.len()).collect();
    idx.sort_by(|&a, &b| {
        let ta = faithful_total(rubric, &scorecards[a]);
        let tb = faithful_total(rubric, &scorecards[b]);
        // Descending on total, then ascending on id for a TOTAL order.
        tb.cmp(&ta)
            .then_with(|| scorecards[a].artifact_id.cmp(&scorecards[b].artifact_id))
    });
    idx
}

/// Rank artifacts by [`faithful_total`] descending, tie-broken by `artifact_id`
/// ascending. Reads grades **only** at RV indices — Attested / AttestationOnly
/// grades are never touched in the ranking path (no pairwise / LLM duel).
pub fn rank(rubric: &Rubric, scorecards: &[Scorecard]) -> Vec<Ranked> {
    ranked_order(rubric, scorecards)
        .into_iter()
        .enumerate()
        .map(|(position, i)| Ranked {
            artifact_id: scorecards[i].artifact_id.clone(),
            faithful_total: faithful_total(rubric, &scorecards[i]),
            position,
        })
        .collect()
}

/// The ranking relation, exposed for testing: `faithful_total(a) >=
/// faithful_total(b)`. A total preorder — reflexive, transitive **and** total —
/// by construction (it is `>=` on a single `u128`).
pub fn ranks_at_least(rubric: &Rubric, a: &Scorecard, b: &Scorecard) -> bool {
    faithful_total(rubric, a) >= faithful_total(rubric, b)
}

/// Extract the RV grade vector (the RV columns in canonical order). This is the
/// concrete `π_RV` projection.
pub fn rv_vec(rubric: &Rubric, sc: &Scorecard) -> Vec<u32> {
    rubric
        .rv_indices()
        .into_iter()
        .map(|i| sc.grades.get(i).copied().unwrap_or(0))
        .collect()
}

/// Strict/weak Pareto dominance over RV grade vectors (higher-is-better): `a`
/// dominates `b` iff `a[i] >= b[i]` for **all** RV `i` and `a[j] > b[j]` for at
/// least one `j`. A tiny local integer product-poset — the pointwise-`<=` pattern
/// of `portcullis-core`'s `CapabilityLattice`, but generic over a rubric's dynamic
/// RV dimension set (so it is *not* a dependency).
pub fn dominates(rubric: &Rubric, a: &Scorecard, b: &Scorecard) -> bool {
    let av = rv_vec(rubric, a);
    let bv = rv_vec(rubric, b);
    dominates_vec(&av, &bv)
}

/// Slice-level Pareto dominance — see [`dominates`].
fn dominates_vec(a: &[u32], b: &[u32]) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut strict = false;
    for (x, y) in a.iter().zip(b) {
        if x < y {
            return false;
        }
        if x > y {
            strict = true;
        }
    }
    strict
}

/// The Pareto front (maximal antichain) over the RV product-poset: the indices of
/// artifacts **not** strictly dominated by any other artifact. Output indices are
/// in ascending order.
pub fn pareto_front(rubric: &Rubric, scorecards: &[Scorecard]) -> Vec<usize> {
    let vecs: Vec<Vec<u32>> = scorecards.iter().map(|s| rv_vec(rubric, s)).collect();
    (0..scorecards.len())
        .filter(|&i| !(0..scorecards.len()).any(|j| j != i && dominates_vec(&vecs[j], &vecs[i])))
        .collect()
}

/// The single winner: argmax [`faithful_total`], tie-broken by `artifact_id`
/// ascending (i.e. `rank[0]`). Returns the index into `scorecards`, or `None` for
/// an empty slice. By the positive-weight scalarization theorem, the winner is
/// always a [`pareto_front`] member.
pub fn winner(rubric: &Rubric, scorecards: &[Scorecard]) -> Option<usize> {
    ranked_order(rubric, scorecards).into_iter().next()
}

/// The single-winner VCG-marginal: `winner_total - runner_up_total`, derived
/// purely from the recorded integer RV scores. Requires `>= 2` artifacts (a
/// marginal is a contribution *over the next-best*; with no runner-up it is
/// undefined — see [`RubricError::NotEnoughArtifacts`]).
pub fn marginal(rubric: &Rubric, scorecards: &[Scorecard]) -> Result<u128, RubricError> {
    if scorecards.len() < 2 {
        return Err(RubricError::NotEnoughArtifacts {
            needed: 2,
            got: scorecards.len(),
        });
    }
    let order = ranked_order(rubric, scorecards);
    let winner_total = faithful_total(rubric, &scorecards[order[0]]);
    let runner_up_total = faithful_total(rubric, &scorecards[order[1]]);
    // winner_total >= runner_up_total by the sort, so this never underflows.
    Ok(winner_total - runner_up_total)
}

/// A fully self-contained record of a single-winner counterfactual: the rubric,
/// every artifact's grades (for every provenance), and the derived winner /
/// runner-up totals + marginal. Carries the **full** inputs so a third party
/// re-derives both totals and the marginal byte-identically via
/// [`CounterfactualReceipt::recompute_marginal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualReceipt {
    /// The rubric (weights + provenances), embedded so totals are re-derivable.
    pub rubric: Rubric,
    /// Every artifact's full grades, embedded so totals are re-derivable.
    pub scorecards: Vec<Scorecard>,
    /// The winning artifact's id.
    pub winner_id: String,
    /// The winning artifact's faithful total.
    pub winner_total: u128,
    /// The runner-up's id.
    pub runner_up_id: String,
    /// The runner-up's faithful total.
    pub runner_up_total: u128,
    /// `winner_total - runner_up_total`.
    pub marginal: u128,
}

/// Build a [`CounterfactualReceipt`] for the single winner. Validates every
/// scorecard, requires `>= 2` artifacts.
pub fn counterfactual(
    rubric: &Rubric,
    scorecards: &[Scorecard],
) -> Result<CounterfactualReceipt, RubricError> {
    rubric.validate_all(scorecards)?;
    if scorecards.len() < 2 {
        return Err(RubricError::NotEnoughArtifacts {
            needed: 2,
            got: scorecards.len(),
        });
    }
    let order = ranked_order(rubric, scorecards);
    let w = &scorecards[order[0]];
    let r = &scorecards[order[1]];
    let winner_total = faithful_total(rubric, w);
    let runner_up_total = faithful_total(rubric, r);
    Ok(CounterfactualReceipt {
        rubric: rubric.clone(),
        scorecards: scorecards.to_vec(),
        winner_id: w.artifact_id.clone(),
        winner_total,
        runner_up_id: r.artifact_id.clone(),
        runner_up_total,
        marginal: winner_total - runner_up_total,
    })
}

impl CounterfactualReceipt {
    /// Independently re-derive `(winner_total, runner_up_total, marginal)` from the
    /// embedded inputs — ignoring the recorded summary fields. This is the
    /// recompute: a third party calls it and compares to the recorded
    /// [`CounterfactualReceipt::marginal`].
    pub fn recompute_marginal(&self) -> (u128, u128, u128) {
        let order = ranked_order(&self.rubric, &self.scorecards);
        let winner_total = faithful_total(&self.rubric, &self.scorecards[order[0]]);
        let runner_up_total = faithful_total(&self.rubric, &self.scorecards[order[1]]);
        (
            winner_total,
            runner_up_total,
            winner_total - runner_up_total,
        )
    }

    /// Canonical, domain-separated bytes: [`RUBRIC_RECEIPT_DOMAIN`] followed by the
    /// receipt's canonical JSON. Deterministic for a given receipt (struct field
    /// order is stable; no maps), hence stable across recomputation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RUBRIC_RECEIPT_DOMAIN.len() + 256);
        out.extend_from_slice(RUBRIC_RECEIPT_DOMAIN);
        serde_json::to_writer(&mut out, self).expect("rubric receipt serialization is infallible");
        out
    }

    /// `sha256` over [`CounterfactualReceipt::canonical_bytes`] — the receipt's
    /// content hash, bound into the minted [`CreditEvent`] as its `receipt_hash`.
    pub fn receipt_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.canonical_bytes());
        h.finalize().into()
    }

    /// Hex-encoded [`CounterfactualReceipt::receipt_hash`].
    pub fn receipt_hash_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.receipt_hash() {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Mint the reward: a **real** [`nucleus_creditworthiness::CreditEvent`] via
    /// `honest_settlement(marginal, receipt_hash)`. The marginal is clamped to
    /// `u64::MAX` (the `CreditEvent` weight domain); `u128` totals make that
    /// effectively unreachable for realistic grades/weights.
    pub fn mint_reward(&self) -> CreditEvent {
        let weight = self.marginal.min(u64::MAX as u128) as u64;
        CreditEvent::honest_settlement(weight, self.receipt_hash())
    }
}

/// Bridge: turn a recompute-verified `nucleus_eval::EvalRun` into a grade for a
/// RecomputeVerified criterion — the recomputed passing-case count. This is how a
/// rubric's RV column can be *populated* by a recompute-verified eval, tying the
/// two crates together (the rubric grade inherits the eval's recompute guarantee).
/// Saturates at `u32::MAX`.
pub fn grade_from_eval(run: &nucleus_eval::EvalRun) -> u32 {
    let (passed, _total) = run.deterministic.recompute();
    passed.min(u32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_creditworthiness::{CreditFile, Polarity};
    use proptest::prelude::*;

    /// A fixed 5-criterion rubric: 3 RV (correctness, coverage, determinism), 1
    /// Attested (cost), 1 AttestationOnly (judge). Mirrors the example.
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

    fn sc(id: &str, grades: [u32; 5]) -> Scorecard {
        Scorecard {
            artifact_id: id.into(),
            grades: grades.to_vec(),
        }
    }

    // ── Validation ──────────────────────────────────────────────────────────

    #[test]
    fn rubric_new_rejects_empty_dup_and_no_rv() {
        assert_eq!(Rubric::new(vec![]).unwrap_err(), RubricError::Empty);

        let dup = vec![
            Criterion {
                id: "a".into(),
                provenance: Provenance::RecomputeVerified,
                weight: 1,
                max_grade: 1,
            },
            Criterion {
                id: "a".into(),
                provenance: Provenance::Attested,
                weight: 1,
                max_grade: 1,
            },
        ];
        assert_eq!(
            Rubric::new(dup).unwrap_err(),
            RubricError::DuplicateId("a".into())
        );

        let no_rv = vec![Criterion {
            id: "a".into(),
            provenance: Provenance::Attested,
            weight: 1,
            max_grade: 1,
        }];
        assert_eq!(
            Rubric::new(no_rv).unwrap_err(),
            RubricError::NoRecomputeVerified
        );
    }

    #[test]
    fn scorecard_length_and_bounds_enforced() {
        let r = fixed_rubric();
        let bad_len = Scorecard {
            artifact_id: "x".into(),
            grades: vec![1, 2, 3],
        };
        assert!(matches!(
            r.validate_scorecard(&bad_len),
            Err(RubricError::GradeCountMismatch { .. })
        ));
        let over_max = sc("x", [11, 0, 0, 0, 0]); // correctness max is 10
        assert!(matches!(
            r.validate_scorecard(&over_max),
            Err(RubricError::GradeExceedsMax { .. })
        ));
        assert!(r
            .validate_scorecard(&sc("x", [10, 10, 10, 10, 100]))
            .is_ok());
    }

    // ── Transitivity / totality (mirrors ck-policy reflexive+transitive) ──────

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
        /// ranks_at_least is reflexive, transitive AND total over arbitrary
        /// scorecards on a fixed rubric — stronger than ck-policy's preorder
        /// (the integer scalar yields a TOTAL order).
        #[test]
        fn ranks_at_least_is_total_order(
            a in arb_scorecard(fixed_rubric()),
            b in arb_scorecard(fixed_rubric()),
            c in arb_scorecard(fixed_rubric()),
        ) {
            let r = fixed_rubric();
            // reflexive
            prop_assert!(ranks_at_least(&r, &a, &a), "reflexivity failed");
            // total
            prop_assert!(
                ranks_at_least(&r, &a, &b) || ranks_at_least(&r, &b, &a),
                "totality failed"
            );
            // transitive
            if ranks_at_least(&r, &a, &b) && ranks_at_least(&r, &b, &c) {
                prop_assert!(
                    ranks_at_least(&r, &a, &c),
                    "TRANSITIVITY: a>=b and b>=c but not a>=c"
                );
            }
        }

        /// Perturbations confined to NON-RV columns never change faithful_total —
        /// proves rank factors through π_RV.
        #[test]
        fn faithful_total_invariant_under_non_rv_perturbation(
            base in arb_scorecard(fixed_rubric()),
            cost in 0u32..=10,
            judge in 0u32..=100,
        ) {
            let r = fixed_rubric();
            let before = faithful_total(&r, &base);
            let mut twiddled = base.clone();
            twiddled.grades[3] = cost;  // Attested
            twiddled.grades[4] = judge; // AttestationOnly
            prop_assert_eq!(before, faithful_total(&r, &twiddled));
        }

        /// With strictly positive RV weights, the weighted-sum winner is always a
        /// member of the Pareto front.
        #[test]
        fn scalarized_winner_is_in_pareto_front(
            cards in proptest::collection::vec(arb_scorecard(fixed_rubric()), 1..6),
        ) {
            let r = fixed_rubric();
            let w = winner(&r, &cards).unwrap();
            let front = pareto_front(&r, &cards);
            prop_assert!(front.contains(&w), "winner not in Pareto front");
        }
    }

    #[test]
    fn rank_positions_are_unique_and_non_increasing() {
        let r = fixed_rubric();
        let cards = vec![
            sc("b", [3, 3, 3, 0, 0]),
            sc("a", [3, 3, 3, 0, 0]), // tie with b on total → id breaks it
            sc("c", [10, 10, 10, 0, 0]),
        ];
        let ranked = rank(&r, &cards);
        // positions are exactly 0..n, unique
        let positions: BTreeSet<usize> = ranked.iter().map(|x| x.position).collect();
        assert_eq!(positions, (0..cards.len()).collect());
        // non-increasing totals
        for w in ranked.windows(2) {
            assert!(w[0].faithful_total >= w[1].faithful_total);
        }
        // c wins; tie a<b breaks by id
        assert_eq!(ranked[0].artifact_id, "c");
        assert_eq!(ranked[1].artifact_id, "a");
        assert_eq!(ranked[2].artifact_id, "b");
    }

    // ── Faithful inertness: attested/judge cannot move ANY output ─────────────

    #[test]
    fn attested_and_judge_dims_cannot_change_any_outcome() {
        let r = fixed_rubric();
        let base = vec![
            sc("A", [9, 2, 5, 5, 50]),  // high correctness, low coverage
            sc("B", [6, 8, 7, 5, 50]),  // balanced strong RV
            sc("C", [3, 1, 2, 0, 100]), // dominated on RV, maxed judge + best cost
        ];
        // Twiddle EVERY Attested + AttestationOnly grade to extremes.
        let twiddled: Vec<Scorecard> = base
            .iter()
            .map(|s| {
                let mut t = s.clone();
                t.grades[3] = 10; // Attested cost → max
                t.grades[4] = 0; // AttestationOnly judge → min
                t
            })
            .collect();

        // rank order + per-artifact totals
        assert_eq!(rank(&r, &base), rank(&r, &twiddled));
        for (a, b) in base.iter().zip(&twiddled) {
            assert_eq!(faithful_total(&r, a), faithful_total(&r, b));
        }
        // Pareto front
        assert_eq!(pareto_front(&r, &base), pareto_front(&r, &twiddled));
        // winner
        assert_eq!(winner(&r, &base), winner(&r, &twiddled));
        // marginal
        assert_eq!(
            marginal(&r, &base).unwrap(),
            marginal(&r, &twiddled).unwrap()
        );
        // receipts mint the same weight (hash differs because it commits to the
        // whole receipt incl. carried signal — independent guarantee)
        let rc_base = counterfactual(&r, &base).unwrap();
        let rc_tw = counterfactual(&r, &twiddled).unwrap();
        assert_eq!(rc_base.marginal, rc_tw.marginal);
        assert_eq!(
            rc_base.mint_reward().weight_micro,
            rc_tw.mint_reward().weight_micro
        );
        assert_ne!(rc_base.receipt_hash(), rc_tw.receipt_hash());
    }

    // ── Pareto correctness ────────────────────────────────────────────────────

    #[test]
    fn pareto_front_correctness_fixture() {
        let r = fixed_rubric();
        let cards = vec![
            sc("A", [9, 2, 5, 0, 0]), // incomparable with B
            sc("B", [6, 8, 7, 0, 0]), // incomparable with A
            sc("C", [3, 1, 2, 0, 0]), // strictly dominated by both A and B
        ];
        let front = pareto_front(&r, &cards);
        // C (idx 2) excluded; A and B retained
        assert_eq!(front, vec![0, 1]);
        // front is an antichain
        for &i in &front {
            for &j in &front {
                if i != j {
                    assert!(!dominates(&r, &cards[i], &cards[j]));
                }
            }
        }
        // every non-front artifact is dominated by some front member
        for i in 0..cards.len() {
            if !front.contains(&i) {
                assert!(front.iter().any(|&j| dominates(&r, &cards[j], &cards[i])));
            }
        }
        // A and B genuinely incomparable
        assert!(!dominates(&r, &cards[0], &cards[1]));
        assert!(!dominates(&r, &cards[1], &cards[0]));
    }

    // ── Counterfactual recompute: byte-identical ──────────────────────────────

    #[test]
    fn counterfactual_recomputes_byte_identical() {
        let r = fixed_rubric();
        let cards = vec![
            sc("A", [9, 2, 5, 5, 50]),
            sc("B", [6, 8, 7, 5, 50]),
            sc("C", [3, 1, 2, 0, 100]),
        ];
        let receipt = counterfactual(&r, &cards).unwrap();

        // Re-derive both totals + marginal from the recorded inputs.
        let (wt, rt, m) = receipt.recompute_marginal();
        assert_eq!(wt, receipt.winner_total);
        assert_eq!(rt, receipt.runner_up_total);
        assert_eq!(m, receipt.marginal);

        // Reconstruct a receipt from the embedded inputs and re-serialize.
        let rebuilt = counterfactual(&receipt.rubric, &receipt.scorecards).unwrap();
        assert_eq!(receipt.canonical_bytes(), rebuilt.canonical_bytes());
        assert_eq!(receipt.receipt_hash(), rebuilt.receipt_hash());

        // Domain separation + determinism.
        assert!(receipt.canonical_bytes().starts_with(RUBRIC_RECEIPT_DOMAIN));
        assert_eq!(receipt.receipt_hash(), receipt.receipt_hash());
        assert_eq!(receipt.receipt_hash_hex().len(), 64);
    }

    // ── Reward composition: real CreditEvent / CreditFile ─────────────────────

    #[test]
    fn marginal_mints_real_credit_event_and_reputation() {
        let r = fixed_rubric();
        let cards = vec![
            sc("A", [10, 10, 10, 0, 0]), // winner, total = 50+30+20 = 100
            sc("B", [9, 10, 10, 0, 0]),  // runner-up, total = 45+30+20 = 95
            sc("C", [1, 1, 1, 0, 0]),
        ];
        let receipt = counterfactual(&r, &cards).unwrap();
        assert_eq!(receipt.winner_id, "A");
        assert_eq!(receipt.winner_total, 100);
        assert_eq!(receipt.runner_up_total, 95);
        assert_eq!(receipt.marginal, 5);

        let ev = receipt.mint_reward();
        assert_eq!(ev.polarity, Polarity::Credit);
        assert_eq!(ev.weight_micro as u128, receipt.marginal);
        assert_eq!(ev.receipt_hash, receipt.receipt_hash());

        let file = CreditFile::from_events(&[ev]);
        assert_eq!(file.reputation_micro() as u128, receipt.marginal);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn single_artifact_marginal_is_an_error() {
        let r = fixed_rubric();
        let cards = vec![sc("A", [10, 10, 10, 0, 0])];
        assert_eq!(
            marginal(&r, &cards).unwrap_err(),
            RubricError::NotEnoughArtifacts { needed: 2, got: 1 }
        );
        assert!(counterfactual(&r, &cards).is_err());
    }

    #[test]
    fn all_equal_scores_tie_resolved_by_id_and_zero_marginal() {
        let r = fixed_rubric();
        let cards = vec![
            sc("c", [5, 5, 5, 0, 0]),
            sc("a", [5, 5, 5, 0, 0]),
            sc("b", [5, 5, 5, 0, 0]),
        ];
        let ranked = rank(&r, &cards);
        assert_eq!(ranked[0].artifact_id, "a");
        assert_eq!(ranked[1].artifact_id, "b");
        assert_eq!(ranked[2].artifact_id, "c");
        // tie ⇒ zero marginal
        assert_eq!(marginal(&r, &cards).unwrap(), 0);
        // winner is the id-min
        assert_eq!(winner(&r, &cards), Some(1)); // "a" at index 1
    }

    // ── Serde round-trips ─────────────────────────────────────────────────────

    #[test]
    fn serde_round_trips() {
        let r = fixed_rubric();
        let r2: Rubric = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(r, r2);

        let s = sc("A", [9, 2, 5, 5, 50]);
        let s2: Scorecard = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s, s2);

        let cards = vec![sc("A", [9, 2, 5, 5, 50]), sc("B", [6, 8, 7, 5, 50])];
        let receipt = counterfactual(&r, &cards).unwrap();
        let receipt2: CounterfactualReceipt =
            serde_json::from_str(&serde_json::to_string(&receipt).unwrap()).unwrap();
        assert_eq!(receipt, receipt2);
    }

    // ── Bridge: RV grade populated from a recompute-verified eval ──────────────

    #[test]
    fn grade_from_eval_uses_recomputed_pass_count() {
        use nucleus_eval::{Attested as EvalAttested, DeterministicCheck, EvalCase, EvalRun};
        let run = EvalRun {
            agent_id: "a".into(),
            task_id: "t".into(),
            cost_micro_usd: 0,
            tokens: 0,
            latency_ms: 0,
            deterministic: DeterministicCheck {
                cases: vec![
                    EvalCase {
                        case_id: "1".into(),
                        produced: "ok".into(),
                        expected: "ok".into(),
                    },
                    EvalCase {
                        case_id: "2".into(),
                        produced: "no".into(),
                        expected: "ok".into(),
                    },
                    EvalCase {
                        case_id: "3".into(),
                        produced: "ok".into(),
                        expected: "ok".into(),
                    },
                ],
                // A lie in the claim does NOT change the recomputed grade.
                claimed_passed: 99,
                claimed_total: 3,
            },
            attested: EvalAttested {
                llm_judge_score: Some(100),
            },
            declared_magnitude_micro: 0,
        };
        // 2 of 3 cases actually pass on recompute — that's the grade.
        assert_eq!(grade_from_eval(&run), 2);
    }
}
