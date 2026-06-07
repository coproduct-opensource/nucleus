/-
  Nucleus / Rubric  (CT-disciplined cardinal scoring kernel — soundness proofs)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Nat` + `omega` + structural
  recursion / list induction + `decide`. No native-decide. Lean 4 v4.30.0-rc2,
  `autoImplicit = false`. Same discipline as `Nucleus.Commons` and
  `Nucleus.Auctions.IntegerVcgTruthful` in `nucleus-econ-kernels/lean`.

  This file is the Lean *statement and proof* of the four soundness properties the
  Rust crate `nucleus-rubric` (`crates/nucleus-rubric/src/lib.rs`) is parity-pinned
  to. Each theorem has a binding Rust witness (a proptest), and the Rust mirror of
  `faithfulTotal` / `dominatesVec` is asserted byte-equal to the production
  `faithful_total` / `dominates` over random scorecards in
  `crates/nucleus-rubric/tests/rubric_lean_parity.rs`.

  # EXTRACTION-GAP CAVEAT

  These theorems are proved about the Lean MODEL. The parity proptests bind them to
  the SHIPPED Rust only probabilistically; a formal Aeneas-style extraction of
  `faithful_total` (as in `nucleus-econ-kernels`) would be required to close the
  model↔Rust gap deductively.

  # The model

  A `Scorecard` is a `List (Provenance × Nat × Nat)` = a list of
  `(provenance, weight, grade)` columns, positionally aligned (the Lean image of
  the Rust `(Rubric, Scorecard)` pair zipped column-wise). `Provenance` mirrors the
  three-tier honesty boundary; `Provenance.isLoadBearing` is `true` iff
  `RecomputeVerified` — the single gate, exactly as `Provenance::is_load_bearing`.

  `faithfulTotal` folds `if p.isLoadBearing then w * g else 0` — the Lean image of
  `faithful_total = (weighted-sum ∘ π_RV)`: non-RV grades are never read (they
  contribute `0` regardless of their value). `ranksAtLeast a b := faithfulTotal a ≥
  faithfulTotal b`. `rvVec` is the RV grade projection; `dominatesVec` / `dominates`
  is pointwise weak Pareto dominance (all `≥`, at least one `>`) over RV vectors.

  # The four theorems (all PROVED, 0 sorry)

  1. `faithfulTotal_inert_under_non_rv` — replacing every NON-RV grade by any other
     grade leaves `faithfulTotal` unchanged. Corollary: `ranksAtLeast` and any
     rank/winner/marginal derived from `faithfulTotal` are inert under non-RV
     perturbation (they factor through `faithfulTotal`).
  2. `ranksAtLeast_refl` / `_trans` / `_total` — `ranksAtLeast` is a TOTAL preorder
     (reflexive + transitive + total). Strictly stronger than `ck-policy`'s
     preorder: it is total, being `≥` on a single `Nat`.
  3. `faithfulTotal_mono_in_rv_grade` — raising any RV grade weakly (weights fixed)
     weakly raises `faithfulTotal`. Monotone in the GRADE; says nothing about
     weight changes.
  4. `scalarized_winner_undominated` — with strictly positive RV weights, the
     `faithfulTotal` maximizer is Pareto-undominated (hence a Pareto-front member).
     Its inductive core is `dominates_strengthens_total`: a weak-Pareto dominator
     with positive shared weights has a STRICTLY greater weighted sum.

  # Verifier wire contract (future work)

  When `nucleus-rubric/build.rs` embeds this file's SHA-256 into
  `CounterfactualReceipt::canonical_bytes`, every minted `CreditEvent` will advertise
  which proof version it claims — the mechanism documented as future work in
  `IntegerVcgTruthful.lean`. Until then the grep-pin header in
  `rubric_lean_parity.rs` IS the spec pin, matching current econ-kernels practice.
-/

namespace Nucleus.Rubric

/-- How much a score is allowed to be trusted — the three-tier honesty boundary,
    mirrored from the Rust `Provenance`. Only `RecomputeVerified` is load-bearing
    on the rank. -/
inductive Provenance
  | RecomputeVerified
  | Attested
  | AttestationOnly
deriving DecidableEq, Repr

/-- The single gate: `true` iff `RecomputeVerified`. Mirrors
    `Provenance::is_load_bearing`. -/
def Provenance.isLoadBearing : Provenance → Bool
  | RecomputeVerified => true
  | Attested => false
  | AttestationOnly => false

/-- One scored column: `(provenance, weight, grade)`. The Lean image of one
    `(Criterion, grade)` pair from the zipped Rust `(Rubric, Scorecard)`. -/
abbrev Column := Provenance × Nat × Nat

/-- A scorecard: the positionally-aligned columns. The Lean image of a Rust
    `(Rubric, Scorecard)` pair zipped column-wise. -/
abbrev Scorecard := List Column

/-- The faithful weighted cardinal total: `Σ` over RV columns of `weight * grade`.
    The Lean image of `faithful_total = (weighted-sum ∘ π_RV)` — non-RV grades
    contribute `0` regardless of value. -/
def faithfulTotal : Scorecard → Nat
  | [] => 0
  | (p, w, g) :: rest =>
      (if p.isLoadBearing then w * g else 0) + faithfulTotal rest

/-- The ranking relation: `faithfulTotal a ≥ faithfulTotal b`. -/
def ranksAtLeast (a b : Scorecard) : Prop :=
  faithfulTotal a ≥ faithfulTotal b

/-- The RV grade projection `π_RV`: the grades of the RV columns, in order. -/
def rvVec : Scorecard → List Nat
  | [] => []
  | (p, _, g) :: rest =>
      if p.isLoadBearing then g :: rvVec rest else rvVec rest

/-- The RV weight projection: the weights of the RV columns, in order. Paired
    positionally with `rvVec`. -/
def rvWeights : Scorecard → List Nat
  | [] => []
  | (p, w, _) :: rest =>
      if p.isLoadBearing then w :: rvWeights rest else rvWeights rest

/-- Every parallel coordinate of the first vector is `≥` the second. `false` on
    length mismatch. (The Rust `dominates_vec`'s "`x < y` ⇒ return false" guard.) -/
def allGe : List Nat → List Nat → Bool
  | [], [] => true
  | (x :: xs), (y :: ys) => decide (y ≤ x) && allGe xs ys
  | _, _ => false

/-- At least one parallel coordinate of the first vector is strictly `>` the
    second. (The Rust `dominates_vec`'s `strict` flag.) -/
def anyGt : List Nat → List Nat → Bool
  | [], [] => false
  | (x :: xs), (y :: ys) => decide (x > y) || anyGt xs ys
  | _, _ => false

/-- Pointwise weak Pareto dominance over equal-length Nat vectors (higher better):
    every coordinate `≥` AND at least one `>`. The boolean RESULT is identical to
    the Rust `dominates_vec` (and is parity-asserted): production `dominates_vec`
    DOES short-circuit — it returns `false` on the first `x < y` — whereas this Lean
    def computes `allGe && anyGt` without short-circuiting; the two agree on the
    final boolean. `false` on length mismatch or empty. -/
def dominatesVec (a b : List Nat) : Bool :=
  allGe a b && anyGt a b

/-- Pareto dominance over scorecards: compare their RV grade projections. -/
def dominates (a b : Scorecard) : Bool :=
  dominatesVec (rvVec a) (rvVec b)

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM 1 — faithful inertness under non-RV perturbation
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Replace the grades on the NON-RV columns by `gs` (consumed in order), leaving
    RV columns and all `(provenance, weight)` pairs fixed. The cleanest statement
    of "non-RV grades may differ arbitrarily". -/
def setNonRvGrades : Scorecard → List Nat → Scorecard
  | [], _ => []
  | (p, w, g) :: rest, gs =>
      if p.isLoadBearing then
        -- RV column: grade fixed, non-RV replacement list flows past unchanged.
        (p, w, g) :: setNonRvGrades rest gs
      else
        match gs with
        | [] => (p, w, g) :: setNonRvGrades rest []   -- ran out: keep original
        | g' :: gs' => (p, w, g') :: setNonRvGrades rest gs'

/-- **THEOREM 1 (PROVED).** Faithful inertness: replacing the NON-RV grades by any
    list `gs` leaves `faithfulTotal` unchanged. Non-RV columns contribute `0`
    regardless of grade, so the fold is identical. -/
theorem faithfulTotal_inert_under_non_rv (sc : Scorecard) (gs : List Nat) :
    faithfulTotal (setNonRvGrades sc gs) = faithfulTotal sc := by
  induction sc generalizing gs with
  | nil => rfl
  | cons c rest ih =>
      obtain ⟨p, w, g⟩ := c
      cases hp : p.isLoadBearing with
      | true =>
          simp [setNonRvGrades, faithfulTotal, hp, ih]
      | false =>
          cases gs with
          | nil =>
              simp [setNonRvGrades, faithfulTotal, hp, ih]
          | cons g' gs' =>
              simp [setNonRvGrades, faithfulTotal, hp, ih]

/-- **COROLLARY.** `ranksAtLeast` is inert under non-RV perturbation on either
    side: it factors through `faithfulTotal`. Any rank/winner/marginal derived
    from `faithfulTotal` inherits this. -/
theorem ranksAtLeast_inert_under_non_rv (a b : Scorecard) (gsa gsb : List Nat) :
    ranksAtLeast (setNonRvGrades a gsa) (setNonRvGrades b gsb) ↔ ranksAtLeast a b := by
  unfold ranksAtLeast
  rw [faithfulTotal_inert_under_non_rv, faithfulTotal_inert_under_non_rv]

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM 2 — ranksAtLeast is a TOTAL preorder
   ─────────────────────────────────────────────────────────────────────────── -/

/-- **THEOREM 2a (PROVED).** Reflexive. -/
theorem ranksAtLeast_refl (a : Scorecard) : ranksAtLeast a a := Nat.le_refl _

/-- **THEOREM 2b (PROVED).** Transitive. -/
theorem ranksAtLeast_trans (a b c : Scorecard)
    (hab : ranksAtLeast a b) (hbc : ranksAtLeast b c) : ranksAtLeast a c :=
  Nat.le_trans hbc hab

/-- **THEOREM 2c (PROVED).** Total — strictly stronger than a bare preorder. -/
theorem ranksAtLeast_total (a b : Scorecard) :
    ranksAtLeast a b ∨ ranksAtLeast b a :=
  Nat.le_total (faithfulTotal b) (faithfulTotal a)

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM 3 — monotone in the RV grade (weights fixed)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- `RvGradeDominates b a`: `b` is `a` with every `(provenance, weight)` fixed and
    each grade weakly raised (`gᵢ' ≥ gᵢ`). Inductive, structural — the cleanest
    premise for grade monotonicity. -/
def RvGradeDominates : Scorecard → Scorecard → Prop
  | [], [] => True
  | (pb, wb, gb) :: bs, (pa, wa, ga) :: as_ =>
      pb = pa ∧ wb = wa ∧ ga ≤ gb ∧ RvGradeDominates bs as_
  | _, _ => False

/-- **THEOREM 3 (PROVED).** Monotone in the RV grade with weights held fixed:
    if `b` raises any RV grades of `a` (weakly), `faithfulTotal a ≤ faithfulTotal b`.
    Non-RV columns contribute `0` on both sides; on an RV column
    `wᵢ * gᵢ ≤ wᵢ * gᵢ'` by `Nat.mul_le_mul_left`, then add the IH. -/
theorem faithfulTotal_mono_in_rv_grade (b a : Scorecard)
    (h : RvGradeDominates b a) : faithfulTotal a ≤ faithfulTotal b := by
  induction b generalizing a with
  | nil =>
      cases a with
      | nil => exact Nat.le_refl _
      | cons ca asx => exact absurd h (by simp [RvGradeDominates])
  | cons cb bs ih =>
      obtain ⟨pb, wb, gb⟩ := cb
      cases a with
      | nil => exact absurd h (by simp [RvGradeDominates])
      | cons ca asx =>
          obtain ⟨pa, wa, ga⟩ := ca
          obtain ⟨hp, hw, hg, hrest⟩ := h
          subst hp; subst hw
          have hih := ih asx hrest
          have hmul : wb * ga ≤ wb * gb := Nat.mul_le_mul_left wb hg
          simp only [faithfulTotal]
          split <;> omega

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM 4 — scalarized winner is Pareto-undominated
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Weighted sum of a grade vector against a parallel weight vector:
    `Σ wᵢ * gᵢ`. The RV-projected form of `faithfulTotal`. -/
def weightedSum : List Nat → List Nat → Nat
  | [], _ => 0
  | _, [] => 0
  | (w :: ws), (g :: gs) => w * g + weightedSum ws gs

/-- `faithfulTotal` equals the weighted sum of its RV weight/grade projections.
    This rewrites `faithfulTotal` into the RV-vector form the Pareto core needs. -/
theorem faithfulTotal_eq_weightedSum (sc : Scorecard) :
    faithfulTotal sc = weightedSum (rvWeights sc) (rvVec sc) := by
  induction sc with
  | nil => rfl
  | cons c rest ih =>
      obtain ⟨p, w, g⟩ := c
      cases hp : p.isLoadBearing with
      | true =>
          simp [faithfulTotal, rvWeights, rvVec, weightedSum, hp, ih]
      | false =>
          simp [faithfulTotal, rvWeights, rvVec, hp, ih]

/-- All weights in a list are strictly positive. -/
def AllPos : List Nat → Prop
  | [] => True
  | w :: ws => 0 < w ∧ AllPos ws

/-- `allGe`-as-`Prop`: pointwise `≥` over two parallel vectors. -/
def PointwiseGe : List Nat → List Nat → Prop
  | [], [] => True
  | (x :: xs), (y :: ys) => y ≤ x ∧ PointwiseGe xs ys
  | _, _ => False

/-- `allGe a b = true` ⇒ `PointwiseGe a b` (decode the boolean scan into a Prop). -/
theorem allGe_pointwiseGe :
    ∀ (xs ys : List Nat), allGe xs ys = true → PointwiseGe xs ys
  | [], [], _ => trivial
  | (x :: xs), (y :: ys), h => by
      simp only [allGe, Bool.and_eq_true, decide_eq_true_eq] at h
      exact ⟨h.1, allGe_pointwiseGe xs ys h.2⟩
  | (_ :: _), [], h => by simp [allGe] at h
  | [], (_ :: _), h => by simp [allGe] at h

/-- Pointwise `≥` lifts to weighted sums: if `xᵢ ≥ yᵢ` at every parallel
    coordinate, then `weightedSum ws y ≤ weightedSum ws x`. (Weak monotonicity in
    the grade vector; no positivity needed.) -/
theorem weightedSum_mono :
    ∀ (ws xs ys : List Nat),
      ws.length = xs.length → xs.length = ys.length →
      PointwiseGe xs ys →
      weightedSum ws ys ≤ weightedSum ws xs
  | [], _, _, _, _, _ => by simp [weightedSum]
  | (_ :: _), [], _, hlx, _, _ => by simp at hlx
  | (_ :: _), (_ :: _), [], _, hxy, _ => by simp at hxy
  | (w :: ws), (x :: xs), (y :: ys), hlx, hxy, hge => by
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hlx hxy
      obtain ⟨hxy_ge, hge_rest⟩ := hge
      have hwle : w * y ≤ w * x := Nat.mul_le_mul_left w hxy_ge
      have htail := weightedSum_mono ws xs ys hlx hxy hge_rest
      simp only [weightedSum]
      omega

/-- **THE INDUCTIVE CORE (PROVED).** `dominates_strengthens_total`: if `x`
    weak-Pareto-dominates `y` over RV grade vectors and the SHARED RV weights `ws`
    are all strictly positive (and parallel in length), then the weighted sum of
    `x` is STRICTLY greater than that of `y`.

    `allGe` gives termwise `wᵢ * yᵢ ≤ wᵢ * xᵢ` (so `weightedSum_mono` bounds the
    whole sum weakly); `anyGt` gives at least one `xⱼ > yⱼ`, which with `wⱼ > 0`
    yields `wⱼ * yⱼ < wⱼ * xⱼ` (`Nat.mul_lt_mul_left`); combining the strict
    coordinate with the weak remainder gives the strict total inequality. -/
theorem dominates_strengthens_total :
    ∀ (ws xs ys : List Nat),
      ws.length = xs.length → xs.length = ys.length →
      AllPos ws → dominatesVec xs ys = true →
      weightedSum ws ys < weightedSum ws xs
  | [], [], [], _, _, _, hdom => by simp [dominatesVec, allGe, anyGt] at hdom
  | (_ :: _), [], _, hlx, _, _, _ => by simp at hlx
  | (w :: ws), (x :: xs), [], _, hxy, _, _ => by simp at hxy
  | (w :: ws), (x :: xs), (y :: ys), hlx, hxy, hpos, hdom => by
      obtain ⟨hw, hposrest⟩ := hpos
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hlx hxy
      -- Split dominance into allGe (head ≥, tail allGe) and anyGt (head > or tail anyGt).
      simp only [dominatesVec, Bool.and_eq_true] at hdom
      obtain ⟨hallge, hanygt⟩ := hdom
      have hallge' := hallge
      simp only [allGe, Bool.and_eq_true, decide_eq_true_eq] at hallge'
      obtain ⟨hxy_ge, halltail⟩ := hallge'
      have hwle : w * y ≤ w * x := Nat.mul_le_mul_left w hxy_ge
      -- The whole tail is weakly monotone (from allGe on the tail).
      have htailmono : weightedSum ws ys ≤ weightedSum ws xs :=
        weightedSum_mono ws xs ys hlx hxy (allGe_pointwiseGe xs ys halltail)
      simp only [anyGt, Bool.or_eq_true, decide_eq_true_eq] at hanygt
      simp only [weightedSum]
      cases hanygt with
      | inl hstrict =>
          have hwlt : w * y < w * x := (Nat.mul_lt_mul_left hw).mpr hstrict
          omega
      | inr htaildom =>
          -- strict somewhere in the tail: recurse for a strict tail inequality.
          have htailstrict : weightedSum ws ys < weightedSum ws xs :=
            dominates_strengthens_total ws xs ys hlx hxy hposrest
              (by simp only [dominatesVec, Bool.and_eq_true]; exact ⟨halltail, htaildom⟩)
          omega

/-- Predicate form: scorecard `x` Pareto-dominates `y` (over RV vectors). -/
def Dominates (x y : Scorecard) : Prop := dominates x y = true

/-- **THEOREM 4 (PROVED).** Scalarized winner is Pareto-undominated. With strictly
    positive shared RV weights, the `faithfulTotal` maximizer of a card list is
    dominated by NO card in the list — hence it lies in the Pareto front.

    Hypotheses encode the Rust API invariant (one `Rubric` scores all cards, so the
    RV `(weight)` column structure is common): every card shares the SAME RV weight
    vector `ws`, all positive; lengths align. The proof is the contrapositive of
    `dominates_strengthens_total`: if some `sc` dominated `w`, then
    `faithfulTotal sc > faithfulTotal w`, contradicting maximality. -/
theorem scalarized_winner_undominated
    (cards : List Scorecard) (ws : List Nat)
    (hposw : AllPos ws)
    (hcommon : ∀ sc ∈ cards, rvWeights sc = ws)
    (hlen : ∀ sc ∈ cards, ws.length = (rvVec sc).length)
    (w : Scorecard) (hw : w ∈ cards)
    (hmax : ∀ sc ∈ cards, faithfulTotal sc ≤ faithfulTotal w) :
    ∀ sc ∈ cards, dominates sc w = false := by
  intro sc hsc
  -- Case on whether sc dominates w; the `true` case is impossible by maximality.
  cases hdom : dominates sc w with
  | false => rfl
  | true =>
      exfalso
      -- Rewrite faithfulTotal of both into the shared-weight weighted sum.
      have hfs : faithfulTotal sc = weightedSum ws (rvVec sc) := by
        rw [faithfulTotal_eq_weightedSum, hcommon sc hsc]
      have hfw : faithfulTotal w = weightedSum ws (rvVec w) := by
        rw [faithfulTotal_eq_weightedSum, hcommon w hw]
      -- Strict gap from the inductive core: dom ⇒ strictly greater weighted sum.
      have hstrict : weightedSum ws (rvVec w) < weightedSum ws (rvVec sc) :=
        dominates_strengthens_total ws (rvVec sc) (rvVec w)
          (hlen sc hsc) (by rw [← hlen sc hsc, hlen w hw]) hposw hdom
      -- Contradicts maximality of w.
      have hle : faithfulTotal sc ≤ faithfulTotal w := hmax sc hsc
      rw [hfs, hfw] at hle
      omega

end Nucleus.Rubric
