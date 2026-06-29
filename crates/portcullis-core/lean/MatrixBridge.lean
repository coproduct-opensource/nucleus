/-
████████████████████████████████████████████████████████████████████████████
  SORRY-FREE as of 2026-06-27 (`lake build MatrixBridge` clean; every theorem
  below `#print axioms`-checks to [propext, Classical.choice, Quot.sound] only).

  The bridge `gaussRankBool = Matrix.rank` and all three downstream derivations
  (`gaussRankBool_append_le_via_bridge`, `fullDeclassList_realises_via_bridge`,
  `h1_basis_realiser_exists_via_bridge`) are kernel-checked. HONEST SCOPE CAVEAT:
  the three derivations carry an explicit uniform-row-width hypothesis
  (`∀ row ∈ …, row.length = m`) required to invoke the bridge; the corresponding
  axioms still stated in `RankNullity.lean` / `AlignmentTaxBridge.lean` are
  hypothesis-free and are NOT yet rewired to consume these lemmas, so those
  downstream files remain Tier-2 until that wiring lands. This file is part of
  the alignment-tax / Cech-cohomology / braid research cluster.

  Status + full manifest: crates/portcullis-core/lean/CONJECTURES.md (Tier 2).
  The PROVEN, CI-gated enforcement core is a SEPARATE set of libraries.
████████████████████████████████████████████████████████████████████████████
-/
import Mathlib.Data.Matrix.Basic
import Mathlib.LinearAlgebra.Matrix.Rank
import Mathlib.LinearAlgebra.Dimension.Finrank
import Mathlib.Data.ZMod.Basic
import Mathlib.Algebra.Field.ZMod
import RankNullity

/-! # Bridge: `gaussRankBool` ↔ `Matrix.rank`

The `gaussRankBool` function in `SemanticIFCDecidable` computes the GF(2)
rank of a `List (List Bool)` matrix via fuel-bounded Gaussian elimination.
This file establishes the bridge to Mathlib's `Matrix.rank`, unlocking
the full row-space algebra needed to close the alignment-tax theorem
unconditionally.

## Strategy

1. Convert `List (List Bool)` to `Matrix (Fin n) (Fin m) (ZMod 2)`.
2. State the **bridge theorem**: `gaussRankBool M = (toMatrix M).rank`.
3. Derive the three structural axioms used downstream:
   * `gaussRankBool_append_le` (rank subadditivity under row append)
   * `fullDeclassList_realises` (standard basis spans full)
   * `h1_basis_realiser_exists` (quotient-basis transversal)

This collapses the holy-grail's three open axioms to *one* (the bridge
theorem itself), which is the standard correctness statement for
Gaussian elimination over GF(2).

## Status

The bridge theorem is PROVEN (sorry-free), and all three downstream
derivations are discharged through it — each modulo an explicit
uniform-row-width hypothesis needed to apply the bridge. See the banner
at the top of this file for the precise scope caveat. -/

open Matrix

namespace PortcullisCore.MatrixBridge

/-- Boolean to GF(2) coercion. -/
@[simp] def boolToZMod : Bool → ZMod 2
  | false => 0
  | true => 1

/-- Convert a `List (List Bool)` matrix (assumed uniform) to a Mathlib
    `Matrix` over `ZMod 2`. The dimensions are taken explicitly. -/
def toMatrix (M : List (List Bool)) (n m : Nat) :
    Matrix (Fin n) (Fin m) (ZMod 2) :=
  fun i j =>
    boolToZMod ((M[i.val]?.bind (fun row => row[j.val]?)).getD false)

/-- Width of a uniform-row matrix. -/
def matWidth (M : List (List Bool)) : Nat :=
  (M.head?.map List.length).getD 0

/-! ### Pivot independence — the linear-algebra core of the rank drop

The single hard fact behind Gaussian-elimination correctness: when a pivot row
has a `1` in the pivot column and every *eliminated* row has a `0` there, the
pivot is linearly independent of the eliminated rows. Concretely: a vector that
is nonzero in a coordinate where a whole set is zero cannot lie in that set's
span (the coordinate projection is a linear functional vanishing on the span but
not on the vector). This is the `+1` in `rowSpanRank rows = rowSpanRank eliminated + 1`. -/
theorem not_mem_span_of_pivot_coord {m : Nat}
    (s : Set (Fin m → ZMod 2)) (v : Fin m → ZMod 2) (c : Fin m)
    (hv : v c = 1) (hs : ∀ w ∈ s, w c = 0) :
    v ∉ Submodule.span (ZMod 2) s := by
  intro hmem
  -- The coordinate-`c` projection is a linear functional that vanishes on `s`,
  -- hence on `span s`; but it sends `v` to `1 ≠ 0`.
  have hsub : s ⊆ (LinearMap.ker (LinearMap.proj c : (Fin m → ZMod 2) →ₗ[ZMod 2] ZMod 2)) := by
    intro w hw
    simp only [SetLike.mem_coe, LinearMap.mem_ker, LinearMap.proj_apply]
    exact hs w hw
  have hvk : v ∈ LinearMap.ker (LinearMap.proj c : (Fin m → ZMod 2) →ₗ[ZMod 2] ZMod 2) :=
    (Submodule.span_le.mpr hsub) hmem
  rw [LinearMap.mem_ker, LinearMap.proj_apply, hv] at hvk
  exact one_ne_zero hvk

/-- The other half of the rank drop: adjoining a vector outside the span lifts the
    span's dimension by exactly one. Combined with `not_mem_span_of_pivot_coord`,
    this gives `rowSpanRank rows = rowSpanRank eliminated + 1` at the abstract
    (Submodule) level — the whole *mathematical* content of one Gaussian-elimination
    step (the remaining work is List↔Matrix bookkeeping). -/
theorem finrank_span_insert_of_not_mem {K V : Type*}
    [Field K] [AddCommGroup V] [Module K V] [FiniteDimensional K V]
    (s : Set V) (v : V) (hv : v ∉ Submodule.span K s) :
    Module.finrank K (Submodule.span K (insert v s)) =
      Module.finrank K (Submodule.span K s) + 1 := by
  -- `v ≠ 0` since `0` is always in the span.
  have hv0 : v ≠ 0 := fun h => hv (h ▸ Submodule.zero_mem _)
  -- `span {v}` and `span s` are disjoint (`v ∉ span s`), so their inf is `⊥`.
  have hdisj : Disjoint (Submodule.span K {v}) (Submodule.span K s) := by
    rw [disjoint_comm]
    exact Submodule.disjoint_span_singleton.mpr (fun hvs => absurd hvs hv)
  have hsum := Submodule.finrank_sup_add_finrank_inf_eq
    (Submodule.span K {v}) (Submodule.span K s)
  rw [hdisj.eq_bot, finrank_bot, add_zero, finrank_span_singleton hv0] at hsum
  rw [Submodule.span_insert]
  omega

/-! ### Bridge theorem proof skeleton

The bridge `gaussRankBool M = (toMatrix M).rank` is decomposed into
explicit sub-lemmas, each one a tractable focused-session target. -/

/-- Row-span dimension of a List-encoded matrix. The semantic invariant
    `gaussRankBool.go` is supposed to track. -/
noncomputable def rowSpanRank (M : List (List Bool)) (n m : Nat) : Nat :=
  (toMatrix M n m).rank

/-- Sub-lemma A: the row-span dimension equals Mathlib's `Matrix.rank`.
    True by definition above; included for symmetry. -/
theorem rowSpanRank_eq_matrix_rank (M : List (List Bool)) (n m : Nat) :
    rowSpanRank M n m = (toMatrix M n m).rank := rfl

/-- Generalized connector over an arbitrary field `R`. With `R` a free type
    variable, `A.rank` and the field lemma share the *same* `Field.toCommRing`
    instance, so this elaborates with no instance diamond and no `ZMod`
    reduction — it is a verbatim restatement of `Matrix.rank_eq_finrank_span_row`. -/
private theorem rank_eq_finrank_span_row' {R : Type*} [Field R] {n m : Nat}
    (A : Matrix (Fin n) (Fin m) R) :
    A.rank =
      Module.finrank R (Submodule.span R (Set.range A.row)) :=
  Matrix.rank_eq_finrank_span_row A

/-- Sub-lemma A′: the row-span dimension equals the `finrank` of the row span.

    The trivial term `rank_eq_finrank_span_row' (toMatrix M n m)` hits a `whnf`
    heartbeat explosion: `rowSpanRank` bakes in the canonical `ZMod.commRing 2`,
    while `Matrix.rank_eq_finrank_span_row` forces `Field.toCommRing`, and
    reconciling those two `CommRing (ZMod 2)` instances makes `isDefEq` reduce
    `ZMod`/`Fin`/`Nat` arithmetic in the `npow`/`nsmul`/`natCast` data fields
    (≈70k `Nat.casesOn` — times out even at `maxHeartbeats 1000000`).

    Fix: pin a local `Field (ZMod 2)` whose `toCommRing` projection *is* the
    canonical `ZMod.commRing 2`. The lemma's `.rank` then uses the very instance
    `rowSpanRank` already uses, so the defeq check is syntactic — no diamond,
    no reduction. (The data fields are unchanged, so the field remains lawful.) -/
theorem rowSpanRank_eq_finrank_span_row (M : List (List Bool)) (n m : Nat) :
    rowSpanRank M n m =
      Module.finrank (ZMod 2) (Submodule.span (ZMod 2) (Set.range (toMatrix M n m).row)) := by
  letI fld : Field (ZMod 2) :=
    { (inferInstance : Field (ZMod 2)) with toCommRing := ZMod.commRing 2 }
  exact rank_eq_finrank_span_row' (toMatrix M n m)

/-- **Row-count upper bound** (Mathlib application): rank ≤ n (row count). -/
theorem rowSpanRank_le_rows (M : List (List Bool)) (n m : Nat) :
    rowSpanRank M n m ≤ n := by
  unfold rowSpanRank
  have h := Matrix.rank_le_card_height (toMatrix M n m)
  simp [Fintype.card_fin] at h
  exact h

/-- **Column-count upper bound** (Mathlib application): rank ≤ m (column count). -/
theorem rowSpanRank_le_cols (M : List (List Bool)) (n m : Nat) :
    rowSpanRank M n m ≤ m := by
  unfold rowSpanRank
  have h := Matrix.rank_le_card_width (toMatrix M n m)
  simp [Fintype.card_fin] at h
  exact h

/-! ### List ↔ row-vector bridging

The `gaussRankBool.go` recursion manipulates `List (List Bool)`; the rank lives in
the Mathlib `Matrix`/`finrank` world. These lemmas package the positional
correspondence between a `List Bool` row and its GF(2) coordinate vector, so the
hard linear-algebra step (`finrank_drop_abstract`) can be stated purely over
`Fin m → ZMod 2` and the bookkeeping kept separate. -/

/-- A `List Bool` row as a GF(2) coordinate vector (positional `getD`, then coerce). -/
def listVec (row : List Bool) (m : Nat) : Fin m → ZMod 2 :=
  fun j => boolToZMod (row.getD j.val false)

/-- The set of row-vectors of a list-encoded matrix (over its actual rows). -/
def rowVecSet (M : List (List Bool)) (m : Nat) : Set (Fin m → ZMod 2) :=
  (fun row => listVec row m) '' {row | row ∈ M}

theorem mem_rowVecSet {m : Nat} (M : List (List Bool)) (v : Fin m → ZMod 2) :
    v ∈ rowVecSet M m ↔ ∃ row, row ∈ M ∧ listVec row m = v := by
  simp only [rowVecSet, Set.mem_image, Set.mem_setOf_eq]

/-- Convert a GF(2) coordinate vector back to a `List Bool` row of width `m`. The
    inverse (on the nose) of `listVec`: `listVec (vecToRow v) m = v`. -/
def vecToRow (m : Nat) (v : Fin m → ZMod 2) : List Bool :=
  List.ofFn (fun j => decide (v j = 1))

/-- On `ZMod 2`, recovering a coordinate through `decide (· = 1)` is the identity. -/
theorem boolToZMod_decide_eq (a : ZMod 2) : boolToZMod (decide (a = 1)) = a := by
  revert a; decide

/-- `vecToRow` is a section of `listVec`: re-encoding a coordinate vector and
    reading it back yields the original vector. -/
theorem listVec_vecToRow (m : Nat) (v : Fin m → ZMod 2) :
    listVec (vecToRow m v) m = v := by
  funext j
  show boolToZMod ((vecToRow m v).getD j.val false) = v j
  rw [vecToRow, List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_pos j.isLt,
      Option.getD_some]
  simp only [Fin.eta]
  exact boolToZMod_decide_eq (v j)

/-- Boolean XOR corresponds to addition in `ZMod 2`. -/
@[simp] theorem boolToZMod_xor (x y : Bool) :
    boolToZMod (x != y) = boolToZMod x + boolToZMod y := by
  cases x <;> cases y <;> decide

/-- Positional value of `xorRows` is the boolean XOR of the positional values,
    within the common length range. -/
theorem xorRows_getD (a b : List Bool) (k : Nat)
    (ha : k < a.length) (hb : k < b.length) :
    (SemanticIFCDecidable.BoundaryMaps.xorRows a b).getD k false
      = (a.getD k false != b.getD k false) := by
  unfold SemanticIFCDecidable.BoundaryMaps.xorRows
  simp only [List.getD_eq_getElem?_getD, List.getElem?_zipWith,
    List.getElem?_eq_getElem ha, List.getElem?_eq_getElem hb, Option.getD_some]

/-- `listVec` is additive on `xorRows` (over equal-length rows). -/
theorem listVec_xorRows (a b : List Bool) (m : Nat)
    (ha : a.length = m) (hb : b.length = m) :
    listVec (SemanticIFCDecidable.BoundaryMaps.xorRows a b) m
      = listVec a m + listVec b m := by
  funext j
  show boolToZMod ((SemanticIFCDecidable.BoundaryMaps.xorRows a b).getD j.val false)
     = boolToZMod (a.getD j.val false) + boolToZMod (b.getD j.val false)
  rw [xorRows_getD a b j.val (by rw [ha]; exact j.isLt) (by rw [hb]; exact j.isLt),
      boolToZMod_xor]

/-- The `i`-th matrix row of `toMatrix M M.length m` is `listVec` of the `i`-th list row. -/
theorem toMatrix_row_eq_listVec (M : List (List Bool)) (m : Nat)
    (i : Fin M.length) :
    (toMatrix M M.length m).row i = listVec M[i] m := by
  funext j
  simp only [Matrix.row_apply, toMatrix, listVec, Fin.getElem_fin,
    List.getElem?_eq_getElem i.isLt, Option.bind_some, List.getD_eq_getElem?_getD]

/-- The row-vector range of `toMatrix` equals the membership-indexed `rowVecSet`. -/
theorem range_eq_rowVecSet (M : List (List Bool)) (m : Nat) :
    Set.range (toMatrix M M.length m).row = rowVecSet M m := by
  ext v
  rw [mem_rowVecSet]
  constructor
  · rintro ⟨i, rfl⟩
    exact ⟨M[i], List.getElem_mem i.isLt, (toMatrix_row_eq_listVec M m i).symm⟩
  · rintro ⟨row, hrow, hv⟩
    obtain ⟨i, hi, hrow_eq⟩ := List.getElem_of_mem hrow
    refine ⟨⟨i, hi⟩, ?_⟩
    rw [toMatrix_row_eq_listVec M m ⟨i, hi⟩]
    show listVec M[i] m = v
    rw [hrow_eq, hv]

/-- The row-span rank of a list matrix equals the `finrank` of the span of its
    membership-indexed row-vector set (the clean handle for the rank-drop step). -/
theorem rowSpanRank_eq_finrank_rowVecSet (M : List (List Bool)) (m : Nat) :
    rowSpanRank M M.length m
      = Module.finrank (ZMod 2) (Submodule.span (ZMod 2) (rowVecSet M m)) := by
  rw [rowSpanRank_eq_finrank_span_row, range_eq_rowVecSet]

/-! ### The abstract rank-drop (pure linear algebra, no lists)

This is the whole mathematical content of one Gaussian-elimination step: if a
pivot vector is nonzero in a coordinate where the eliminated set vanishes, lies
in the original span, and the eliminated set is contained in the original span,
then the eliminated span has rank exactly one less than the original. -/
theorem finrank_drop_abstract {m : Nat} (c : Fin m)
    (Selim Srows : Set (Fin m → ZMod 2)) (pv : Fin m → ZMod 2)
    (hpv_col : pv c = 1)
    (helim_col : ∀ w ∈ Selim, w c = 0)
    (hpv_mem : pv ∈ Submodule.span (ZMod 2) Srows)
    (helim_sub : Selim ⊆ ↑(Submodule.span (ZMod 2) Srows)) :
    Module.finrank (ZMod 2) (Submodule.span (ZMod 2) Selim) + 1
      ≤ Module.finrank (ZMod 2) (Submodule.span (ZMod 2) Srows) := by
  have hnotmem : pv ∉ Submodule.span (ZMod 2) Selim :=
    not_mem_span_of_pivot_coord Selim pv c hpv_col helim_col
  have hins : Module.finrank (ZMod 2) (Submodule.span (ZMod 2) (insert pv Selim))
      = Module.finrank (ZMod 2) (Submodule.span (ZMod 2) Selim) + 1 :=
    finrank_span_insert_of_not_mem Selim pv hnotmem
  have hsub : Submodule.span (ZMod 2) (insert pv Selim)
      ≤ Submodule.span (ZMod 2) Srows := by
    rw [Submodule.span_le, Set.insert_subset_iff]
    exact ⟨hpv_mem, helim_sub⟩
  have hmono := Submodule.finrank_mono hsub
  omega

/-! ### Per-row bookkeeping for the eliminated matrix -/

/-- Each eliminated row-vector is `0` in the pivot column. -/
theorem elim_row_col_zero
    (col m : Nat) (pivot orig : List Bool) (hcol : col < m)
    (hpl : pivot.length = m) (hol : orig.length = m)
    (hpiv_col : pivot.getD col false = true) :
    listVec (if orig.getD col false
        then SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot else orig) m
      ⟨col, hcol⟩ = 0 := by
  split
  · rename_i h
    show boolToZMod ((SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot).getD col false) = 0
    rw [xorRows_getD orig pivot col (by omega) (by omega), h, hpiv_col]
    decide
  · rename_i h
    rw [Bool.not_eq_true] at h
    show boolToZMod (orig.getD col false) = 0
    rw [h]
    decide

/-- Each eliminated row-vector lies in the span of the original row-vectors. -/
theorem elim_row_mem_span
    (rows : List (List Bool)) (col m : Nat) (pivot orig : List Bool)
    (hpl : pivot.length = m) (hol : orig.length = m)
    (horig_mem : orig ∈ rows) (hpiv_mem : pivot ∈ rows) :
    listVec (if orig.getD col false
        then SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot else orig) m
      ∈ Submodule.span (ZMod 2) (rowVecSet rows m) := by
  have horig_span : listVec orig m ∈ Submodule.span (ZMod 2) (rowVecSet rows m) :=
    Submodule.subset_span ((mem_rowVecSet _ _).mpr ⟨orig, horig_mem, rfl⟩)
  have hpiv_span : listVec pivot m ∈ Submodule.span (ZMod 2) (rowVecSet rows m) :=
    Submodule.subset_span ((mem_rowVecSet _ _).mpr ⟨pivot, hpiv_mem, rfl⟩)
  split
  · rw [listVec_xorRows orig pivot m hol hpl]
    exact Submodule.add_mem _ horig_span hpiv_span
  · exact horig_span

/-! ### The crux rank-drop lemma (one elimination step lowers rank by ≥ 1) -/

/-- One Gaussian-elimination step: after pivoting on `pivot` in column `col`, the
    row-span rank of the eliminated matrix is at least one less than the original. -/
theorem crux_rank_drop
    (rows eliminated : List (List Bool)) (col m : Nat) (pivot : List Bool)
    (h_m : ∀ row ∈ rows, row.length = m)
    (hpiv_mem : pivot ∈ rows)
    (hpiv_col : pivot.getD col false = true)
    (hdef : eliminated = (rows.filter (· ≠ pivot)).map
      (fun row => if row.getD col false
        then SemanticIFCDecidable.BoundaryMaps.xorRows row pivot else row)) :
    rowSpanRank eliminated eliminated.length m + 1 ≤ rowSpanRank rows rows.length m := by
  have hpl : pivot.length = m := h_m pivot hpiv_mem
  have hcol : col < m := by
    by_contra h
    push_neg at h
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none (by omega)] at hpiv_col
    simp at hpiv_col
  rw [rowSpanRank_eq_finrank_rowVecSet eliminated m, rowSpanRank_eq_finrank_rowVecSet rows m]
  apply finrank_drop_abstract ⟨col, hcol⟩ (rowVecSet eliminated m) (rowVecSet rows m)
      (listVec pivot m)
  · show boolToZMod (pivot.getD col false) = 1
    rw [hpiv_col]; decide
  · intro w hw
    obtain ⟨er, her_mem, rfl⟩ := (mem_rowVecSet _ _).mp hw
    rw [hdef] at her_mem
    obtain ⟨orig, horig_filter, rfl⟩ := List.mem_map.mp her_mem
    have horig_mem : orig ∈ rows := (List.mem_filter.mp horig_filter).1
    exact elim_row_col_zero col m pivot orig hcol hpl (h_m orig horig_mem) hpiv_col
  · exact Submodule.subset_span ((mem_rowVecSet _ _).mpr ⟨pivot, hpiv_mem, rfl⟩)
  · intro w hw
    obtain ⟨er, her_mem, rfl⟩ := (mem_rowVecSet _ _).mp hw
    rw [hdef] at her_mem
    obtain ⟨orig, horig_filter, rfl⟩ := List.mem_map.mp her_mem
    have horig_mem : orig ∈ rows := (List.mem_filter.mp horig_filter).1
    exact elim_row_mem_span rows col m pivot orig hpl (h_m orig horig_mem) horig_mem hpiv_mem

/-- Loop invariant with the row-count fixed to the actual list length (the form
    that lets the induction hypothesis fire on the shrunk `eliminated` matrix). -/
private theorem go_invariant_aux
    (rows : List (List Bool)) (col r fuel m : Nat)
    (h_m : ∀ row ∈ rows, row.length = m) :
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows col r fuel ≤
      r + rowSpanRank rows rows.length m := by
  induction fuel generalizing rows col r with
  | zero =>
    have : SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows col r 0 = r := rfl
    rw [this]
    exact Nat.le_add_right _ _
  | succ k ih =>
    unfold SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go
    cases hfind : rows.find? (fun row => row.getD col false) with
    | none =>
      simp only
      by_cases hlt : col + 1 < (rows.head?.map List.length |>.getD 0)
      · rw [if_pos hlt]
        exact ih rows (col + 1) r h_m
      · rw [if_neg hlt]
        exact Nat.le_add_right _ _
    | some pivot =>
      simp only
      have hpiv_mem : pivot ∈ rows := List.mem_of_find?_eq_some hfind
      have hpiv_col : pivot.getD col false = true := by
        have h := List.find?_some hfind
        simpa using h
      set eliminated := (rows.filter (· ≠ pivot)).map
        (fun row => if row.getD col false
          then SemanticIFCDecidable.BoundaryMaps.xorRows row pivot else row) with helim
      have h_m_elim : ∀ row ∈ eliminated, row.length = m := by
        intro row hrow
        rw [helim] at hrow
        obtain ⟨orig, horig_filter, rfl⟩ := List.mem_map.mp hrow
        have horig_mem : orig ∈ rows := (List.mem_filter.mp horig_filter).1
        have hol : orig.length = m := h_m orig horig_mem
        have hpl : pivot.length = m := h_m pivot hpiv_mem
        split
        · unfold SemanticIFCDecidable.BoundaryMaps.xorRows
          rw [List.length_zipWith]; omega
        · exact hol
      have hih := ih eliminated (col + 1) (r + 1) h_m_elim
      have hcrux : rowSpanRank eliminated eliminated.length m + 1 ≤
          rowSpanRank rows rows.length m :=
        crux_rank_drop rows eliminated col m pivot h_m hpiv_mem hpiv_col helim
      omega

/-- Sub-lemma B (the loop invariant): at every recursive step of
    `gaussRankBool.go`, the rank counter is bounded by start rank plus
    row-span dimension. -/
theorem gaussRankBool_go_invariant
    (rows : List (List Bool)) (col r fuel : Nat)
    (n m : Nat) (h_n : rows.length = n) (h_m : ∀ row ∈ rows, row.length = m) :
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows col r fuel ≤
      r + (rowSpanRank rows n m) := by
  subst h_n
  exact go_invariant_aux rows col r fuel m h_m

/-! ### Completeness direction: the pivot counter *reaches* the full rank

The invariant (`≤`) shows the counter never overcounts. The converse — the
counter is *tight* given enough fuel — needs three ingredients beyond the
`≤` direction:

* `rowSpanRank_eq_zero_of_zero_below`: once every row is zero in all columns
  `< col` and `m ≤ col`, every row-vector is the zero vector, so the rank is 0
  (the terminating / out-of-fuel branches).
* `crux_rank_drop_ge`: one elimination step drops the rank by *at most* one
  (the matching half of `crux_rank_drop`'s `+1 ≤`); together they pin the drop
  to exactly one.
* `go_tight_lb_aux`: the lower-bound loop invariant, threading the
  "zero below `col`" predicate so the IH fires on the eliminated matrix. -/

/-- Empty matrix has row-span rank `0`. -/
theorem rowSpanRank_nil (m : Nat) : rowSpanRank [] 0 m = 0 := by
  unfold rowSpanRank
  have h := Matrix.rank_le_card_height (toMatrix ([] : List (List Bool)) 0 m)
  rw [Fintype.card_fin] at h
  omega

/-- If every row is zero in all columns `< col` and the matrix has at most `col`
    columns, every row-vector is the zero vector, so the row-span rank is `0`. -/
theorem rowSpanRank_eq_zero_of_zero_below
    (rows : List (List Bool)) (col m : Nat)
    (h_m : ∀ row ∈ rows, row.length = m)
    (h_zero : ∀ row ∈ rows, ∀ k, k < col → row.getD k false = false)
    (hmcol : m ≤ col) :
    rowSpanRank rows rows.length m = 0 := by
  rw [rowSpanRank_eq_finrank_rowVecSet]
  have hsub : rowVecSet rows m ⊆ {0} := by
    intro v hv
    obtain ⟨row, hrow, rfl⟩ := (mem_rowVecSet _ _).mp hv
    simp only [Set.mem_singleton_iff]
    funext j
    have hz : row.getD j.val false = false := h_zero row hrow j.val (by omega)
    show boolToZMod (row.getD j.val false) = (0 : Fin m → ZMod 2) j
    rw [hz]; rfl
  rw [show Submodule.span (ZMod 2) (rowVecSet rows m) = ⊥ from by
        rw [Submodule.span_eq_bot]
        intro x hx
        simpa using hsub hx,
      finrank_bot]

/-- The eliminated row-vector is still zero in every column `k < col` (the
    already-cleared pivot columns), because both `orig` and `pivot` are. -/
theorem elim_row_zero_below (col m k : Nat) (pivot orig : List Bool)
    (hk : k < col) (hcol : col ≤ m)
    (hpl : pivot.length = m) (hol : orig.length = m)
    (hpiv0 : pivot.getD k false = false) (horig0 : orig.getD k false = false) :
    (if orig.getD col false
        then SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot else orig).getD k false
      = false := by
  split
  · rw [xorRows_getD orig pivot k (by omega) (by omega), horig0, hpiv0]; decide
  · exact horig0

/-- Bool-level version of `elim_row_col_zero`: the eliminated row is `false` in
    the pivot column itself. -/
theorem elim_row_col_zero_bool (col m : Nat) (pivot orig : List Bool) (hcol : col < m)
    (hpl : pivot.length = m) (hol : orig.length = m)
    (hpiv_col : pivot.getD col false = true) :
    (if orig.getD col false
        then SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot else orig).getD col false
      = false := by
  split
  · rename_i h
    rw [xorRows_getD orig pivot col (by omega) (by omega), h, hpiv_col]; decide
  · rename_i h
    rw [Bool.not_eq_true] at h
    exact h

/-- The abstract `≥`-side of the rank drop: if `pv` is nonzero in a coordinate
    where `Selim` vanishes, and every vector of `Srows` lies in the span of
    `insert pv Selim`, then `Srows`'s span has rank at most `finrank (span Selim) + 1`.
    Combined with `finrank_drop_abstract` this gives exact equality. -/
theorem finrank_drop_abstract_ge {m : Nat} (c : Fin m)
    (Selim Srows : Set (Fin m → ZMod 2)) (pv : Fin m → ZMod 2)
    (hpv_col : pv c = 1)
    (helim_col : ∀ w ∈ Selim, w c = 0)
    (hrows_sub : Srows ⊆ ↑(Submodule.span (ZMod 2) (insert pv Selim))) :
    Module.finrank (ZMod 2) (Submodule.span (ZMod 2) Srows)
      ≤ Module.finrank (ZMod 2) (Submodule.span (ZMod 2) Selim) + 1 := by
  have hnotmem : pv ∉ Submodule.span (ZMod 2) Selim :=
    not_mem_span_of_pivot_coord Selim pv c hpv_col helim_col
  have hins : Module.finrank (ZMod 2) (Submodule.span (ZMod 2) (insert pv Selim))
      = Module.finrank (ZMod 2) (Submodule.span (ZMod 2) Selim) + 1 :=
    finrank_span_insert_of_not_mem Selim pv hnotmem
  have hsub : Submodule.span (ZMod 2) Srows
      ≤ Submodule.span (ZMod 2) (insert pv Selim) :=
    Submodule.span_le.mpr hrows_sub
  have hmono := Submodule.finrank_mono hsub
  omega

/-- One Gaussian-elimination step lowers the rank by *at most* one. The matching
    bound to `crux_rank_drop`'s `eliminated + 1 ≤ rows`; together they force the
    drop to be exactly one. The key fact is that every original row-vector lies in
    the span of `{pivot} ∪ eliminated`: untouched rows are eliminated as-is, and a
    cleared row `orig` is recovered as `(orig ⊕ pivot) ⊕ pivot`. -/
theorem crux_rank_drop_ge
    (rows eliminated : List (List Bool)) (col m : Nat) (pivot : List Bool)
    (h_m : ∀ row ∈ rows, row.length = m)
    (hpiv_mem : pivot ∈ rows)
    (hpiv_col : pivot.getD col false = true)
    (hdef : eliminated = (rows.filter (· ≠ pivot)).map
      (fun row => if row.getD col false
        then SemanticIFCDecidable.BoundaryMaps.xorRows row pivot else row)) :
    rowSpanRank rows rows.length m ≤ rowSpanRank eliminated eliminated.length m + 1 := by
  have hpl : pivot.length = m := h_m pivot hpiv_mem
  have hcol : col < m := by
    by_contra h
    push_neg at h
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none (by omega)] at hpiv_col
    simp at hpiv_col
  rw [rowSpanRank_eq_finrank_rowVecSet eliminated m, rowSpanRank_eq_finrank_rowVecSet rows m]
  apply finrank_drop_abstract_ge ⟨col, hcol⟩ (rowVecSet eliminated m) (rowVecSet rows m)
      (listVec pivot m)
  · show boolToZMod (pivot.getD col false) = 1
    rw [hpiv_col]; decide
  · intro w hw
    obtain ⟨er, her_mem, rfl⟩ := (mem_rowVecSet _ _).mp hw
    rw [hdef] at her_mem
    obtain ⟨orig, horig_filter, rfl⟩ := List.mem_map.mp her_mem
    have horig_mem : orig ∈ rows := (List.mem_filter.mp horig_filter).1
    exact elim_row_col_zero col m pivot orig hcol hpl (h_m orig horig_mem) hpiv_col
  · intro v hv
    obtain ⟨orig, horig_mem, rfl⟩ := (mem_rowVecSet _ _).mp hv
    rw [SetLike.mem_coe]
    by_cases hop : orig = pivot
    · subst hop
      exact Submodule.subset_span (Set.mem_insert _ _)
    · have horig_filter : orig ∈ rows.filter (· ≠ pivot) := by
        rw [List.mem_filter]
        exact ⟨horig_mem, by simpa using hop⟩
      have hol : orig.length = m := h_m orig horig_mem
      by_cases hbit : orig.getD col false = true
      · have helim_mem : SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot ∈ eliminated := by
          rw [hdef, List.mem_map]
          refine ⟨orig, horig_filter, ?_⟩
          show (if orig.getD col false
              then SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot else orig)
            = SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot
          rw [if_pos hbit]
        have hxor_span : listVec (SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot) m
            ∈ Submodule.span (ZMod 2) (insert (listVec pivot m) (rowVecSet eliminated m)) :=
          Submodule.subset_span
            (Set.mem_insert_of_mem _ ((mem_rowVecSet _ _).mpr ⟨_, helim_mem, rfl⟩))
        have hpiv_span : listVec pivot m
            ∈ Submodule.span (ZMod 2) (insert (listVec pivot m) (rowVecSet eliminated m)) :=
          Submodule.subset_span (Set.mem_insert _ _)
        have hsum := Submodule.add_mem _ hxor_span hpiv_span
        rw [listVec_xorRows orig pivot m hol hpl] at hsum
        have hpp : listVec pivot m + listVec pivot m = 0 := by
          funext j
          simp only [Pi.add_apply, Pi.zero_apply]
          have hz : ∀ a : ZMod 2, a + a = 0 := by decide
          exact hz _
        have hcancel : listVec orig m + listVec pivot m + listVec pivot m = listVec orig m := by
          rw [add_assoc, hpp, add_zero]
        rwa [hcancel] at hsum
      · rw [Bool.not_eq_true] at hbit
        have helim_mem : orig ∈ eliminated := by
          rw [hdef, List.mem_map]
          refine ⟨orig, horig_filter, ?_⟩
          show (if orig.getD col false
              then SemanticIFCDecidable.BoundaryMaps.xorRows orig pivot else orig)
            = orig
          rw [if_neg (by rw [hbit]; exact Bool.false_ne_true)]
        exact Submodule.subset_span
          (Set.mem_insert_of_mem _ ((mem_rowVecSet _ _).mpr ⟨orig, helim_mem, rfl⟩))

/-- Lower-bound loop invariant: with enough fuel (`m ≤ col + fuel`) and every row
    already zero in columns `< col`, the rank counter reaches *at least* the
    row-span rank. The dual of `go_invariant_aux`. -/
private theorem go_tight_lb_aux
    (rows : List (List Bool)) (col r fuel m : Nat)
    (h_m : ∀ row ∈ rows, row.length = m)
    (h_zero : ∀ row ∈ rows, ∀ k, k < col → row.getD k false = false)
    (h_fuel : m ≤ col + fuel) :
    r + rowSpanRank rows rows.length m ≤
      SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows col r fuel := by
  induction fuel generalizing rows col r with
  | zero =>
    have hgo : SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows col r 0 = r := rfl
    rw [hgo]
    have hz0 : rowSpanRank rows rows.length m = 0 :=
      rowSpanRank_eq_zero_of_zero_below rows col m h_m h_zero (by omega)
    omega
  | succ k ih =>
    unfold SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go
    cases hfind : rows.find? (fun row => row.getD col false) with
    | none =>
      simp only
      have hcol_zero : ∀ row ∈ rows, row.getD col false = false := by
        intro row hrow
        by_contra hne
        rw [Bool.not_eq_false] at hne
        rw [List.find?_eq_none] at hfind
        exact hfind row hrow hne
      have h_zero_succ : ∀ row ∈ rows, ∀ kk, kk < col + 1 → row.getD kk false = false := by
        intro row hrow kk hkk
        rcases Nat.lt_or_ge kk col with h | h
        · exact h_zero row hrow kk h
        · have : kk = col := by omega
          subst this
          exact hcol_zero row hrow
      by_cases hlt : col + 1 < (rows.head?.map List.length |>.getD 0)
      · rw [if_pos hlt]
        exact ih rows (col + 1) r h_m h_zero_succ (by omega)
      · rw [if_neg hlt]
        by_cases hnil : rows = []
        · subst hnil
          simp only [List.length_nil]
          have hz0 : rowSpanRank ([] : List (List Bool)) 0 m = 0 := rowSpanRank_nil m
          omega
        · have hwidth : (rows.head?.map List.length |>.getD 0) = m := by
            obtain ⟨hd, tl, rfl⟩ := List.exists_cons_of_ne_nil hnil
            have hh : ((hd :: tl).head?.map List.length |>.getD 0) = hd.length := by simp
            rw [hh]
            exact h_m hd (by simp)
          rw [hwidth] at hlt
          have hz0 : rowSpanRank rows rows.length m = 0 :=
            rowSpanRank_eq_zero_of_zero_below rows (col + 1) m h_m h_zero_succ (by omega)
          omega
    | some pivot =>
      simp only
      have hpiv_mem : pivot ∈ rows := List.mem_of_find?_eq_some hfind
      have hpiv_col : pivot.getD col false = true := by
        have h := List.find?_some hfind
        simpa using h
      set eliminated := (rows.filter (· ≠ pivot)).map
        (fun row => if row.getD col false
          then SemanticIFCDecidable.BoundaryMaps.xorRows row pivot else row) with helim
      have hpl : pivot.length = m := h_m pivot hpiv_mem
      have hcol : col < m := by
        by_contra h
        push_neg at h
        rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none (by omega)] at hpiv_col
        simp at hpiv_col
      have h_m_elim : ∀ row ∈ eliminated, row.length = m := by
        intro row hrow
        rw [helim] at hrow
        obtain ⟨orig, horig_filter, rfl⟩ := List.mem_map.mp hrow
        have horig_mem : orig ∈ rows := (List.mem_filter.mp horig_filter).1
        have hol : orig.length = m := h_m orig horig_mem
        split
        · unfold SemanticIFCDecidable.BoundaryMaps.xorRows
          rw [List.length_zipWith]; omega
        · exact hol
      have h_zero_elim : ∀ row ∈ eliminated, ∀ kk, kk < col + 1 → row.getD kk false = false := by
        intro row hrow kk hkk
        rw [helim] at hrow
        obtain ⟨orig, horig_filter, rfl⟩ := List.mem_map.mp hrow
        have horig_mem : orig ∈ rows := (List.mem_filter.mp horig_filter).1
        have hol : orig.length = m := h_m orig horig_mem
        rcases Nat.lt_or_ge kk col with h | h
        · exact elim_row_zero_below col m kk pivot orig h (le_of_lt hcol) hpl hol
            (h_zero pivot hpiv_mem kk (by omega)) (h_zero orig horig_mem kk (by omega))
        · have hkc : kk = col := by omega
          rw [hkc]
          exact elim_row_col_zero_bool col m pivot orig hcol hpl hol hpiv_col
      have hih := ih eliminated (col + 1) (r + 1) h_m_elim h_zero_elim (by omega)
      have hge : rowSpanRank rows rows.length m ≤ rowSpanRank eliminated eliminated.length m + 1 :=
        crux_rank_drop_ge rows eliminated col m pivot h_m hpiv_mem hpiv_col helim
      omega

/-- Sub-lemma C: the converse — the loop invariant is tight at termination.
    When fuel runs out (or all columns processed), the rank counter
    *equals* the row-span dimension. -/
theorem gaussRankBool_go_tight
    (rows : List (List Bool)) (n m : Nat)
    (h_n : rows.length = n) (h_m : ∀ row ∈ rows, row.length = m)
    (h_fuel : n + m ≤ n + m) :  -- placeholder for sufficient fuel
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows 0 0 (n + m) =
      rowSpanRank rows n m := by
  subst h_n
  have hle : SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows 0 0 (rows.length + m)
      ≤ rowSpanRank rows rows.length m := by
    have h := gaussRankBool_go_invariant rows 0 0 (rows.length + m) rows.length m rfl h_m
    simpa using h
  have hge : rowSpanRank rows rows.length m
      ≤ SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go rows 0 0 (rows.length + m) := by
    have h := go_tight_lb_aux rows 0 0 (rows.length + m) m h_m
      (fun row _ k hk => absurd hk (Nat.not_lt_zero k)) (by omega)
    simpa using h
  omega

/-- **Bridge for the empty matrix**: trivially zero on both sides. -/
theorem gaussRankBool_eq_matrix_rank_nil :
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool ([] : List (List Bool)) =
      (toMatrix [] 0 0).rank := by
  rw [show SemanticIFCDecidable.BoundaryMaps.gaussRankBool [] = 0 from rfl]
  -- The matrix (Fin 0 → Fin 0 → ZMod 2) has empty row index type;
  -- its rank is 0 by the rank-≤-row-count bound applied to a 0-row matrix.
  have h_le : (toMatrix [] 0 0).rank ≤ Fintype.card (Fin 0) :=
    Matrix.rank_le_card_height _
  rw [Fintype.card_fin] at h_le
  omega

/-- **Bridge theorem**: `gaussRankBool` agrees with `Matrix.rank`.

    Direct corollary of `gaussRankBool_go_tight` once the bridge fuel
    suffices. The proof unfolds `gaussRankBool` to `gaussRankBool.go`
    and applies the tight invariant. -/
theorem gaussRankBool_eq_matrix_rank
    (M : List (List Bool)) (n m : Nat)
    (h_n : M.length = n) (h_m : ∀ row ∈ M, row.length = m) :
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool M =
      (toMatrix M n m).rank := by
  by_cases hM : M = []
  · subst hM
    simp only [List.length_nil] at h_n
    subst h_n
    rw [show SemanticIFCDecidable.BoundaryMaps.gaussRankBool ([] : List (List Bool)) = 0 from rfl]
    have hz : rowSpanRank ([] : List (List Bool)) 0 m = 0 := rowSpanRank_nil m
    unfold rowSpanRank at hz
    omega
  · have hwidth : (M.head?.map List.length |>.getD 0) = m := by
      obtain ⟨hd, tl, rfl⟩ := List.exists_cons_of_ne_nil hM
      have hh : ((hd :: tl).head?.map List.length |>.getD 0) = hd.length := by simp
      rw [hh]
      exact h_m hd (by simp)
    have hgo : SemanticIFCDecidable.BoundaryMaps.gaussRankBool M
        = SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go M 0 0 (M.length + m) := by
      conv_lhs => rw [show SemanticIFCDecidable.BoundaryMaps.gaussRankBool M
        = SemanticIFCDecidable.BoundaryMaps.gaussRankBool.go M 0 0
          (M.length + (M.head?.map List.length |>.getD 0)) from rfl]
      rw [hwidth]
    rw [hgo, gaussRankBool_go_tight M M.length m rfl h_m (by omega),
        rowSpanRank_eq_matrix_rank, h_n]

/-- Bridge specialised to the `finrank` of the row-span set: for a uniform-width
    list matrix the Gaussian-elimination rank equals the dimension of the span of
    its row-vectors. The clean handle used by all three derivations below. -/
theorem gaussRankBool_eq_finrank_rowVecSet
    (L : List (List Bool)) (m : Nat) (h : ∀ row ∈ L, row.length = m) :
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool L
      = Module.finrank (ZMod 2) (Submodule.span (ZMod 2) (rowVecSet L m)) := by
  rw [gaussRankBool_eq_matrix_rank L L.length m rfl h]
  show rowSpanRank L L.length m = _
  rw [rowSpanRank_eq_finrank_rowVecSet]

/-- The row-vector set of an appended matrix is the union of the row-vector sets.
    (Rows of `M ++ N` are exactly the rows of `M` together with the rows of `N`.) -/
theorem rowVecSet_append (M N : List (List Bool)) (m : Nat) :
    rowVecSet (M ++ N) m = rowVecSet M m ∪ rowVecSet N m := by
  unfold rowVecSet
  rw [← Set.image_union]
  congr 1
  ext row
  simp only [Set.mem_setOf_eq, Set.mem_union, List.mem_append]

/-! ## Derivations of the three structural axioms

These are the unconditional closures of the axioms introduced in
`RankNullity.lean` and `AlignmentTaxBridge.lean`, conditional only on
`gaussRankBool_eq_matrix_rank`. -/

/-- **Axiom 1 closed (modulo bridge)**: `gaussRankBool_append_le`.

    Standard `Matrix.rank` subadditivity: `rank (A ++ B) ≤ rank A + (rows of B)`. -/
theorem gaussRankBool_append_le_via_bridge
    (M N : List (List Bool)) (m : Nat)
    (h_m : ∀ row ∈ M ++ N, row.length = m) :
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool (M ++ N) ≤
    SemanticIFCDecidable.BoundaryMaps.gaussRankBool M + N.length := by
  -- Convert both sides via the bridge; then use Mathlib's row-append rank lemma.
  -- Mathlib path: rank(stack A B) = finrank (span M ⊔ span N) ≤ finrank (span M) + finrank (span N)
  --             ≤ rank M + (#rows of N).
  have h_mM : ∀ row ∈ M, row.length = m :=
    fun r hr => h_m r (List.mem_append.mpr (Or.inl hr))
  rw [gaussRankBool_eq_matrix_rank (M ++ N) (M ++ N).length m rfl h_m,
      gaussRankBool_eq_matrix_rank M M.length m rfl h_mM]
  show rowSpanRank (M ++ N) (M ++ N).length m ≤ rowSpanRank M M.length m + N.length
  rw [rowSpanRank_eq_finrank_rowVecSet, rowSpanRank_eq_finrank_rowVecSet,
      rowVecSet_append, Submodule.span_union]
  have hsup := Submodule.finrank_sup_add_finrank_inf_eq
    (Submodule.span (ZMod 2) (rowVecSet M m)) (Submodule.span (ZMod 2) (rowVecSet N m))
  have hN : Module.finrank (ZMod 2) (Submodule.span (ZMod 2) (rowVecSet N m)) ≤ N.length := by
    have h := rowSpanRank_le_rows N N.length m
    rwa [rowSpanRank_eq_finrank_rowVecSet] at h
  omega

/-- **Axiom 2 closed (modulo bridge)**: `fullDeclassList realises`.

    The standard basis e_1, ..., e_n spans the full ambient (Fin n → ZMod 2)
    space; appending all e_i to any matrix gives rank ≥ n. -/
theorem fullDeclassList_realises_via_bridge
    (M : List (List Bool)) (n : Nat)
    (allRows : List (List Bool))
    (h_m : ∀ row ∈ M ++ allRows, row.length = n)
    (h_basis : ∀ i : Fin n, ∃ row ∈ allRows, ∀ j : Fin n,
      (toMatrix [row] 1 n) ⟨0, Nat.one_pos⟩ j = if j = i then 1 else 0) :
    n ≤ SemanticIFCDecidable.BoundaryMaps.gaussRankBool (M ++ allRows) := by
  -- Bridge converts to Matrix.rank, then standard-basis spans give rank = n.
  rw [gaussRankBool_eq_matrix_rank (M ++ allRows) (M ++ allRows).length n rfl h_m]
  show n ≤ rowSpanRank (M ++ allRows) (M ++ allRows).length n
  rw [rowSpanRank_eq_finrank_rowVecSet]
  -- Each standard basis vector `e i` is a row-vector of `allRows ⊆ M ++ allRows`.
  have hbasis_mem : ∀ i : Fin n,
      (Pi.basisFun (ZMod 2) (Fin n)) i ∈ rowVecSet (M ++ allRows) n := by
    intro i
    obtain ⟨row, hrow, hrow_eq⟩ := h_basis i
    rw [mem_rowVecSet]
    refine ⟨row, List.mem_append.mpr (Or.inr hrow), ?_⟩
    funext j
    have htm : (toMatrix [row] 1 n) ⟨0, Nat.one_pos⟩ j = listVec row n j := rfl
    have hval : listVec row n j = if j = i then (1 : ZMod 2) else 0 := by
      rw [← htm]; exact hrow_eq j
    rw [hval, Pi.basisFun_apply, Pi.single_apply]
  -- The standard basis spans the whole ambient space, so the row span is `⊤`.
  have htop : Submodule.span (ZMod 2) (rowVecSet (M ++ allRows) n) = ⊤ := by
    rw [eq_top_iff, ← (Pi.basisFun (ZMod 2) (Fin n)).span_eq, Submodule.span_le]
    rintro v ⟨i, rfl⟩
    exact Submodule.subset_span (hbasis_mem i)
  rw [htop, finrank_top, Module.finrank_fin_fun]

/-- **Axiom 3 closed (modulo bridge)**: `h1_basis_realiser_exists`.

    Any finite-dimensional GF(2) quotient space has a basis of dimension
    equal to its rank. Each basis element gives one declassification edge. -/
theorem h1_basis_realiser_exists_via_bridge
    (M N : List (List Bool)) (k : Nat) (m : Nat)
    (h_mMN : ∀ row ∈ M ++ N, row.length = m)
    (h_dim : SemanticIFCDecidable.BoundaryMaps.gaussRankBool (M ++ N) =
             SemanticIFCDecidable.BoundaryMaps.gaussRankBool M + k) :
    ∃ (basis : List (List Bool)), basis.length = k ∧
      SemanticIFCDecidable.BoundaryMaps.gaussRankBool (M ++ basis) =
        SemanticIFCDecidable.BoundaryMaps.gaussRankBool M + k := by
  -- Bridge converts to finrank; extract a complement basis of `span M` inside
  -- `span (M ++ N)` and realise its `k` vectors as concrete Bool rows.
  have h_mM : ∀ row ∈ M, row.length = m :=
    fun r hr => h_mMN r (List.mem_append.mpr (Or.inl hr))
  have hbM := gaussRankBool_eq_finrank_rowVecSet M m h_mM
  have hbMN := gaussRankBool_eq_finrank_rowVecSet (M ++ N) m h_mMN
  rw [rowVecSet_append, Submodule.span_union] at hbMN
  -- `finrank (span M ⊔ span N) = finrank (span M) + k`
  have hdimfr : Module.finrank (ZMod 2)
        ↥(Submodule.span (ZMod 2) (rowVecSet M m) ⊔ Submodule.span (ZMod 2) (rowVecSet N m))
      = Module.finrank (ZMod 2) (Submodule.span (ZMod 2) (rowVecSet M m)) + k := by
    rw [← hbMN, ← hbM]; exact h_dim
  -- A complement `q` of `span M` cuts out a `k`-dimensional `C := (span M ⊔ span N) ⊓ q`.
  obtain ⟨q, hq⟩ := Submodule.exists_isCompl (Submodule.span (ZMod 2) (rowVecSet M m))
  have hAC : Submodule.span (ZMod 2) (rowVecSet M m)
        ⊔ ((Submodule.span (ZMod 2) (rowVecSet M m)
            ⊔ Submodule.span (ZMod 2) (rowVecSet N m)) ⊓ q)
      = Submodule.span (ZMod 2) (rowVecSet M m) ⊔ Submodule.span (ZMod 2) (rowVecSet N m) := by
    rw [inf_comm, ← sup_inf_assoc_of_le _ le_sup_left, hq.sup_eq_top, top_inf_eq]
  have hAcap : Submodule.span (ZMod 2) (rowVecSet M m)
        ⊓ ((Submodule.span (ZMod 2) (rowVecSet M m)
            ⊔ Submodule.span (ZMod 2) (rowVecSet N m)) ⊓ q)
      = ⊥ := by
    refine le_bot_iff.mp (le_trans (inf_le_inf_left _ inf_le_right) (le_of_eq hq.inf_eq_bot))
  have hfrC : Module.finrank (ZMod 2)
        ↥((Submodule.span (ZMod 2) (rowVecSet M m)
          ⊔ Submodule.span (ZMod 2) (rowVecSet N m)) ⊓ q) = k := by
    have hsum := Submodule.finrank_sup_add_finrank_inf_eq
      (Submodule.span (ZMod 2) (rowVecSet M m))
      ((Submodule.span (ZMod 2) (rowVecSet M m)
        ⊔ Submodule.span (ZMod 2) (rowVecSet N m)) ⊓ q)
    rw [hAC, hAcap, finrank_bot, add_zero, hdimfr] at hsum
    omega
  -- A basis of `C` indexed by `Fin k`; realise each basis vector as a Bool row.
  let bC := Module.finBasisOfFinrankEq (ZMod 2)
    ↥((Submodule.span (ZMod 2) (rowVecSet M m)
      ⊔ Submodule.span (ZMod 2) (rowVecSet N m)) ⊓ q) hfrC
  refine ⟨List.ofFn (fun i : Fin k => vecToRow m ((bC i : Fin m → ZMod 2))), ?_, ?_⟩
  · rw [List.length_ofFn]
  set basis := List.ofFn (fun i : Fin k => vecToRow m ((bC i : Fin m → ZMod 2))) with hbasis
  have h_mbasis : ∀ row ∈ basis, row.length = m := by
    intro row hrow
    rw [hbasis, List.mem_ofFn] at hrow
    obtain ⟨i, rfl⟩ := hrow
    unfold vecToRow; rw [List.length_ofFn]
  have h_mMbasis : ∀ row ∈ M ++ basis, row.length = m := by
    intro row hrow
    rcases List.mem_append.mp hrow with h | h
    · exact h_mM row h
    · exact h_mbasis row h
  -- `rowVecSet basis = C.subtype '' range bC`, so its span is `C`.
  have hspanC : Submodule.span (ZMod 2) (rowVecSet basis m)
      = (Submodule.span (ZMod 2) (rowVecSet M m)
          ⊔ Submodule.span (ZMod 2) (rowVecSet N m)) ⊓ q := by
    have himg : rowVecSet basis m
        = ⇑(((Submodule.span (ZMod 2) (rowVecSet M m)
            ⊔ Submodule.span (ZMod 2) (rowVecSet N m)) ⊓ q).subtype) '' Set.range ⇑bC := by
      ext v
      rw [mem_rowVecSet]
      constructor
      · rintro ⟨row, hrow, rfl⟩
        rw [hbasis, List.mem_ofFn] at hrow
        obtain ⟨i, rfl⟩ := hrow
        exact ⟨bC i, Set.mem_range_self i, by rw [listVec_vecToRow, Submodule.subtype_apply]⟩
      · rintro ⟨c, ⟨i, rfl⟩, rfl⟩
        exact ⟨vecToRow m ↑(bC i), by rw [hbasis, List.mem_ofFn]; exact ⟨i, rfl⟩,
          listVec_vecToRow m _⟩
    rw [himg, Submodule.span_image, bC.span_eq, Submodule.map_subtype_top]
  -- Conclude: `gaussRankBool (M ++ basis) = finrank (span M ⊔ C) = finrank (span M) + k`.
  have hbasiseq := gaussRankBool_eq_finrank_rowVecSet (M ++ basis) m h_mMbasis
  rw [rowVecSet_append, Submodule.span_union, hspanC, hAC] at hbasiseq
  rw [hbasiseq, hdimfr, ← hbM]

end PortcullisCore.MatrixBridge
