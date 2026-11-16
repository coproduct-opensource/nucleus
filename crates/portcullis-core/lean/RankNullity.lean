/-
████████████████████████████████████████████████████████████████████████████
  RESEARCH-TIER CLOSURE — no open proof holes in this file (0 `sorry`), but it
  imports `SemanticIFCDecidable`, which has declarations on `sorryAx`, so it is
  not part of the proven build. Do NOT cite a result here as "verified" on the
  strength of this file alone. This file is part of the alignment-tax /
  Cech-cohomology / braid research cluster.

  Status + full manifest: crates/portcullis-core/lean/CONJECTURES.md (Tier 2c).
  The PROVEN, CI-gated enforcement core is a SEPARATE set of libraries.
████████████████████████████████████████████████████████████████████████████
-/
import SemanticIFCDecidable

/-! # GF(2) rank-nullity scaffold for List-based boolean matrices

This file collects structural lemmas about `gaussRankBool` and `gf2Rank`
(defined in `SemanticIFCDecidable` and `ComparisonTheorem` respectively)
that support the Honest Fundamental Theorem of Cohomological Security.

The two load-bearing downstream facts (in `ComparisonTheorem.lean`) are:

* `uniform_implies_h1_zero` — a constant presheaf on a covering has `Ȟ¹ = 0`.
* `exclusive_implies_h1_pos` — an exclusive forcing obstruction gives `Ȟ¹ > 0`.

Both reduce to linear-algebra facts about the Boolean boundary matrices
`reducedDelta0` and `reducedDelta1`. This module factors out those facts as
first-class lemmas so the cohomology proofs can cite them cleanly.

The `gaussRankBool` function is a fuel-bounded Gaussian elimination on
`List (List Bool)`; its recursion makes direct structural induction painful.
Lemmas here are stated as stand-alone facts and proved one-by-one in
subsequent steps.
-/

open SemanticIFCDecidable.BoundaryMaps

namespace PortcullisCore.RankNullity

/-- Rank of the empty matrix is zero. -/
theorem gaussRankBool_nil : gaussRankBool [] = 0 := by
  rfl

/-- Filter with `· ≠ x` strictly shrinks a list that contains `x`. -/
private theorem length_filter_ne_lt {α : Type*} [DecidableEq α]
    (l : List α) {x : α} (hx : x ∈ l) :
    (l.filter (· ≠ x)).length < l.length := by
  induction l with
  | nil => exact (List.not_mem_nil hx).elim
  | cons hd tl ih =>
    by_cases heq : hd = x
    · subst heq
      simp [List.filter_cons]
      -- filter keeps others with length ≤ tl.length, + 0 for hd
      exact Nat.lt_succ_of_le (List.length_filter_le _ _)
    · rcases List.mem_cons.mp hx with rfl | htl
      · exact absurd rfl heq
      · have hlt := ih htl
        simp [List.filter_cons, heq]
        omega

/-- Gaussian elimination invariant: rank ≤ starting rank + row count. -/
private theorem go_le_rows (M : List (List Bool)) (col r fuel : Nat) :
    gaussRankBool.go M col r fuel ≤ r + M.length := by
  induction fuel generalizing M col r with
  | zero =>
    unfold gaussRankBool.go
    omega
  | succ k ih =>
    unfold gaussRankBool.go
    cases hfind : M.find? (fun row => row.getD col false) with
    | none =>
      simp only
      by_cases hlt : col + 1 < (M.head?.map List.length |>.getD 0)
      · simp [hlt]
        exact ih M (col + 1) r
      · simp [hlt]
    | some pivot =>
      simp only
      have hmem : pivot ∈ M := List.mem_of_find?_eq_some hfind
      have hshrink : (M.filter (· ≠ pivot)).length < M.length :=
        length_filter_ne_lt M hmem
      have h_map_len : ((M.filter (· ≠ pivot)).map
          (fun row => if row.getD col false then xorRows row pivot else row)).length
          = (M.filter (· ≠ pivot)).length := List.length_map _
      have h_ih := ih
          ((M.filter (· ≠ pivot)).map
            (fun row => if row.getD col false then xorRows row pivot else row))
          (col + 1) (r + 1)
      rw [h_map_len] at h_ih
      omega

/-- Rank is at most the number of rows. -/
theorem gaussRankBool_le_rows (M : List (List Bool)) :
    gaussRankBool M ≤ M.length := by
  unfold gaussRankBool
  have := go_le_rows M 0 0 (M.length + (M.head?.map List.length |>.getD 0))
  omega

/-- Auxiliary: Gaussian elimination on a matrix of all-empty rows preserves rank. -/
private theorem go_empty_rows (M : List (List Bool))
    (h : ∀ row ∈ M, row = []) (col r fuel : Nat) :
    gaussRankBool.go M col r fuel = r := by
  induction fuel generalizing M col r with
  | zero => rfl
  | succ k ih =>
    unfold gaussRankBool.go
    -- All rows are [], so row.getD col false = false for every row.
    have hfind : M.find? (fun row => row.getD col false) = none := by
      apply List.find?_eq_none.mpr
      intro row hrow
      simp [h row hrow]
    rw [hfind]
    -- M.head?.map List.length |>.getD 0 = 0 since head, if any, is [].
    have hlen : (M.head?.map List.length |>.getD 0) = 0 := by
      cases M with
      | nil => rfl
      | cons hd tl =>
        have : hd = [] := h hd List.mem_cons_self
        simp [this]
    rw [hlen]
    simp

/-- A matrix whose rows are all empty has rank zero. -/
theorem gaussRankBool_empty_rows (M : List (List Bool))
    (h : ∀ row ∈ M, row = []) : gaussRankBool M = 0 := by
  unfold gaussRankBool
  exact go_empty_rows M h 0 0 _

/-- A row of all-false entries returns `false` at any index via `getD`. -/
private theorem getD_false_of_all_false (row : List Bool)
    (h : ∀ b ∈ row, b = false) (col : Nat) :
    row.getD col false = false := by
  induction row generalizing col with
  | nil => rfl
  | cons hd tl ih =>
    cases col with
    | zero => exact h hd List.mem_cons_self
    | succ n =>
      have h' : ∀ b ∈ tl, b = false :=
        fun b hb => h b (List.mem_cons_of_mem _ hb)
      exact ih h' n

/-- Gaussian elimination on an all-false matrix keeps rank at its input. -/
private theorem go_zero_matrix (M : List (List Bool))
    (h : ∀ row ∈ M, ∀ b ∈ row, b = false) (col r fuel : Nat) :
    gaussRankBool.go M col r fuel = r := by
  induction fuel generalizing M col r with
  | zero => rfl
  | succ k ih =>
    unfold gaussRankBool.go
    have hfind : M.find? (fun row => row.getD col false) = none := by
      apply List.find?_eq_none.mpr
      intro row hrow hcontra
      have hrf : row.getD col false = false :=
        getD_false_of_all_false row (h row hrow) col
      rw [hrf] at hcontra
      exact Bool.false_ne_true hcontra
    rw [hfind]
    by_cases hlt : col + 1 < (M.head?.map List.length |>.getD 0)
    · simp [hlt]
      exact ih M h (col + 1) r
    · simp [hlt]

/-- A matrix whose entries are all `false` has rank zero. -/
theorem gaussRankBool_zero_matrix (M : List (List Bool))
    (h : ∀ row ∈ M, ∀ b ∈ row, b = false) : gaussRankBool M = 0 := by
  unfold gaussRankBool
  exact go_zero_matrix M h 0 0 _

/-! ## Rank subadditivity under row concatenation

### The general form is false (2026-11-14)

Until 2026-11-14 this file stated, with a `sorry`,

    gaussRankBool_append_le (M N : List (List Bool)) :
      gaussRankBool (M ++ N) ≤ gaussRankBool M + N.length

and called it "the single load-bearing structural sorry" of the
alignment-tax chain. **It is false for ragged matrices**, and its
negation is decided below (`gaussRankBool_append_le_counterexample`):

    M = [[], [false, true]],  N = [[true]]
    gaussRankBool M = 0,  gaussRankBool (M ++ N) = 2,  2 ≤ 0 + 1 fails.

The reason is in `gaussRankBool` itself: the no-pivot branch stops at
the width of the *head* row, while the pivot branch advances the column
without consulting any width. With `M`'s head row `[]`, elimination on
`M` stops at column 0 and never sees the `true` at column 1. In `M ++ N`
the head row is still `[]`, but `[true]` supplies a pivot at column 0,
so the pivot branch walks on to column 1 and finds `[false, true]`. On a
ragged matrix `gaussRankBool` is therefore not a rank, and no
subadditivity law holds for it.

With the `sorry` in scope `False` was derivable — the two-line proof
`gaussRankBool_append_le_counterexample (gaussRankBool_append_le _ _)`
type-checked, with axioms `[propext, sorryAx]`.

**The true statement** carries a uniform-row-width hypothesis
(`∀ row ∈ M ++ N, row.length = m`) and is proved, sorry-free, as
`PortcullisCore.MatrixBridge.gaussRankBool_append_le_via_bridge`
through the bridge `gaussRankBool = Matrix.rank`. It lives there rather
than here because `MatrixBridge` imports this file. Every former use
of the general form now goes through it; see `AlignmentTaxBridge.lean`
for the one downstream theorem whose matrix is *not* rectangular in
general and which now takes that as an explicit hypothesis.

**Weak version** (`gaussRankBool_append_le_length`, proved below):
the trivial consequence of `gaussRankBool_le_rows`, true for every
matrix, ragged or not.
-/

/-- **Weak rank subadditivity** (provable, trivial): the rank of any
    matrix is bounded by its row count. Not strong enough for the
    alignment tax theorem but records the honest guaranteed bound. -/
theorem gaussRankBool_append_le_length (M N : List (List Bool)) :
    gaussRankBool (M ++ N) ≤ M.length + N.length := by
  have h := gaussRankBool_le_rows (M ++ N)
  simpa [List.length_append] using h

/-- **The former `gaussRankBool_append_le` fails at one instance**, decided
    by the kernel. `M = [[], [false, true]]` has `gaussRankBool` 0 (elimination
    stops at the head row's width, 0); `M ++ [[true]]` has `gaussRankBool` 2.
    `N` is a single row, so this also refutes the removed corollary
    `gaussRankBool_append_rows_le_succ` (`gaussRankBool (M ++ [r]) ≤
    gaussRankBool M + 1`). What stops either from coming back as a `sorry`
    is not this theorem but the proven-tier gate: `RankNullity` is no
    longer on the `CONJECTURES.md` allowlist, so any hole here fails
    `portcullis-core-proven-lean.yml`. -/
theorem gaussRankBool_append_le_counterexample :
    ¬ (gaussRankBool ([[], [false, true]] ++ [[true]]) ≤
        gaussRankBool [[], [false, true]] + [[true]].length) := by
  decide

/-- **The general (hypothesis-free) subadditivity law is false.** Any proof of
    it yields `False`; the true form needs uniform row width and is
    `PortcullisCore.MatrixBridge.gaussRankBool_append_le_via_bridge`. -/
theorem not_gaussRankBool_append_le_general :
    ¬ ∀ M N : List (List Bool),
        gaussRankBool (M ++ N) ≤ gaussRankBool M + N.length :=
  fun h => gaussRankBool_append_le_counterexample (h _ _)

end PortcullisCore.RankNullity
