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

/-- Rank is at most the number of rows. -/
theorem gaussRankBool_le_rows (M : List (List Bool)) :
    gaussRankBool M ≤ M.length := by
  sorry

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

/-- A matrix whose entries are all `false` has rank zero. -/
theorem gaussRankBool_zero_matrix (M : List (List Bool))
    (h : ∀ row ∈ M, ∀ b ∈ row, b = false) : gaussRankBool M = 0 := by
  sorry

end PortcullisCore.RankNullity
