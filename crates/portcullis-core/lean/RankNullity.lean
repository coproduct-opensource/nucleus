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

The following lemma is the structural input to the *main theorem* Alignment
Tax Theorem: appending `k` rows to a matrix increases its GF(2) rank by
at most `k`.

Classical linear algebra: `rank(A ++ B) ≤ rank(A) + rank(B) ≤ rank(A) +
(#rows of B)`. For `gaussRankBool` on `List (List Bool)` the identity is
intuitively "each appended row adds at most one new pivot".

Proof strategy (follow-up PR): induction on `N`, using the "add-one-row
increases rank by at most 1" lemma as the inductive step. The add-one
step unfolds `gaussRankBool.go` on the augmented matrix and tracks the
rank through the elimination phase. -/

/-- **Rank subadditivity**: appending `k` rows to a matrix increases its
    GF(2) rank by at most `k`. Stated as a sorry here; the proof is the
    structural content of the next PR in the main theorem sprint. -/
theorem gaussRankBool_append_le (M N : List (List Bool)) :
    gaussRankBool (M ++ N) ≤ gaussRankBool M + N.length := by
  sorry

/-- **Corollary**: appending a fixed list of rows is rank-subadditive. -/
theorem gaussRankBool_append_rows_le_succ (M : List (List Bool)) (r : List Bool) :
    gaussRankBool (M ++ [r]) ≤ gaussRankBool M + 1 := by
  have h := gaussRankBool_append_le M [r]
  simpa using h

end PortcullisCore.RankNullity
