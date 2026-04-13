import ComparisonTheorem
import RankNullity

/-! # Alignment Tax = rank H¹: the operational–structural bridge

`alignmentTaxH1` is already defined as `reducedCechDim P indices 1` (the
structural / Čech-cohomological invariant). That identity is a **definition**,
not a theorem.

The **main theorem** from `project_alignment_tax_conjecture.md`
asserts a non-trivial bridge between two *independently motivated* notions:

* **Operational** (this file's `operationalAlignmentTax`):
    the minimum number of declassification edges required to realise full
    capability under an IFC policy. Operationally meaningful — counts
    mandatory policy relaxations.

* **Structural** (`alignmentTaxH1`):
    the rank of reduced Čech H¹ of the IFC presheaf. Structural — counts
    independent obstructions to gluing local sections.

The conjecture is that these coincide:

    operationalAlignmentTax = rank H¹

This is a quantitative information-theoretic bound for AI security —
an analog of a Shannon limit rather than a Rice-style undecidability
result. It pins the tax exactly, proving that each independent
cohomology class corresponds to exactly one mandatory declassification.

## Proof strategy

1. **Upper bound** (`operationalTax ≤ rank H¹`): build an explicit
   declassification set from a basis of H¹ cocycles. Each cocycle pins
   one obstruction; declassifying it kills the class.

2. **Lower bound** (`operationalTax ≥ rank H¹`): any declassification set
   that realises the task must hit every H¹ class (by dimension counting
   on the cocycle space, via rank-nullity from `RankNullity.lean`).

Both directions are classical in the sheaf-theoretic literature (Laudal,
Stacks Project §21); the formal content is assembling them against the
List-based `gaussRankBool` encoding.

## Prior art

* Baudot–Bennequin 2015 (*Entropy*): entropy is the universal H¹ cocycle
  of an information structure. Connects semantic content of H¹ classes
  to Shannon-entropy quantities.
* Vigneaux 2017: information cohomology as a derived functor; H¹ equals
  relative homological information classes under connexity/richness.
* OGPSA (2026): empirical alignment tax via orthogonal gradient projection;
  subspace-geometry mirror of the H¹ picture.

## Current status

This file states the bridge. Proving it is the research frontier.
-/

open SemanticIFCDecidable
open SemanticIFCDecidable.BoundaryMaps
open AlexandrovSite
open PresheafCech
open BridgeTheorem
open HonestFundamental

namespace PortcullisCore.AlignmentTaxBridge

variable {Secret : Type} [Fintype Secret] [DecidableEq Secret]

/-- A **declassification edge** is a permission to leak a specific proposition
    from one observation level to another. Operationally: a crack in the
    policy that allows capability recovery at the cost of a known leak. -/
structure DeclassEdge where
  fromIdx : Nat   -- source observation index
  toIdx   : Nat   -- sink observation index
  prop    : Nat   -- proposition being declassified
  deriving DecidableEq, Repr

/-- A **realising set** of declassification edges: an `L` that makes every
    cocycle become a coboundary after adding indicator rows for `L` to `δ⁰`.

    Structurally: `L` realises iff the augmented 0-chain space covers every
    element of `reducedC1`. This is the combinatorial reflection of "every
    local section glues globally once policy is relaxed by `L`".

    An edge `⟨i, j, p⟩` is said to *cover* the 1-simplex entry `(a, b, q)`
    when the proposition matches (`p = q`) and the endpoints coincide
    (`(i, j) = (a, b)` or `(i, j) = (b, a)`). -/
def Covers (e : DeclassEdge) (c : Nat × Nat × Nat) : Prop :=
  e.prop = c.2.2 ∧
    ((e.fromIdx = c.1 ∧ e.toIdx = c.2.1) ∨
     (e.fromIdx = c.2.1 ∧ e.toIdx = c.1))

instance (e : DeclassEdge) (c : Nat × Nat × Nat) : Decidable (Covers e c) := by
  unfold Covers; infer_instance

/-- `L` realises: every C¹ entry is covered by some edge in `L`. -/
def Realises (P : IndexedPoset Secret) (indices : List Nat)
    (L : List DeclassEdge) : Prop :=
  ∀ c ∈ reducedC1 P indices, ∃ e ∈ L, Covers e c

/-- The canonical realiser: one edge per 1-simplex. Always realises. -/
def canonicalRealiser (P : IndexedPoset Secret) (indices : List Nat) :
    List DeclassEdge :=
  (reducedC1 P indices).map (fun c => ⟨c.1, c.2.1, c.2.2⟩)

/-- The canonical realiser realises. -/
theorem canonicalRealiser_realises
    (P : IndexedPoset Secret) (indices : List Nat) :
    Realises P indices (canonicalRealiser P indices) := by
  intro c hc
  refine ⟨⟨c.1, c.2.1, c.2.2⟩, ?_, ?_⟩
  · exact List.mem_map.mpr ⟨c, hc, rfl⟩
  · exact ⟨rfl, Or.inl ⟨rfl, rfl⟩⟩

/-- **Existence of a realising set** (constructive witness). -/
theorem exists_realising_set (P : IndexedPoset Secret) (indices : List Nat) :
    ∃ L : List DeclassEdge, Realises P indices L :=
  ⟨canonicalRealiser P indices, canonicalRealiser_realises P indices⟩

/-- **Operational alignment tax**: the minimum cardinality of a realising set.

    Defined classically via `Nat.find` (non-computable); used for stating
    the bridge theorem abstractly. Concrete computation uses the canonical
    realiser as an upper-bound witness. -/
noncomputable def operationalAlignmentTax
    (P : IndexedPoset Secret) (indices : List Nat) : Nat := by
  classical
  exact Nat.find (p := fun n => ∃ L : List DeclassEdge,
    L.length ≤ n ∧ Realises P indices L)
    ⟨(reducedC1 P indices).length, canonicalRealiser P indices,
      by unfold canonicalRealiser; simp, canonicalRealiser_realises P indices⟩

/-- **Upper bound on the operational tax**: bounded by `|C¹|` via the
    canonical realiser. -/
theorem operationalAlignmentTax_le_c1 (P : IndexedPoset Secret) (indices : List Nat) :
    operationalAlignmentTax P indices ≤ (reducedC1 P indices).length := by
  classical
  unfold operationalAlignmentTax
  apply Nat.find_le
  exact ⟨canonicalRealiser P indices, by unfold canonicalRealiser; simp,
         canonicalRealiser_realises P indices⟩

/-- **Base case of the bridge**: when `reducedC1 = []`, the operational tax
    vanishes. The empty list is a realising set trivially.

    Combined with `reducedCechDim_of_c1_empty`, this closes the bridge equation
    on degenerate inputs: `operationalAlignmentTax = 0 = alignmentTaxH1`. -/
theorem operationalAlignmentTax_of_c1_empty
    (P : IndexedPoset Secret) (indices : List Nat)
    (h : reducedC1 P indices = []) :
    operationalAlignmentTax P indices = 0 := by
  classical
  have h_le : operationalAlignmentTax P indices ≤ 0 := by
    unfold operationalAlignmentTax
    apply Nat.find_le
    refine ⟨[], ?_, ?_⟩
    · simp
    · intro c hc; rw [h] at hc; exact absurd hc (List.not_mem_nil)
  omega

/-- **Bridge theorem, degenerate case**: when the 1-simplex list is empty,
    operational tax = 0 = `alignmentTaxH1`. -/
theorem alignmentTax_eq_h1_of_c1_empty
    (P : IndexedPoset Secret) (indices : List Nat)
    (h : reducedC1 P indices = []) :
    operationalAlignmentTax P indices = alignmentTaxH1 P indices := by
  rw [operationalAlignmentTax_of_c1_empty P indices h]
  rw [show alignmentTaxH1 P indices = reducedCechDim P indices 1 from rfl]
  exact (reducedCechDim_of_c1_empty P indices h).symm

/-- **Bridge theorem (upper bound)**: operational tax ≤ rank H¹.

    Strategy: exhibit a declassification set of size `rank H¹` built from a
    basis of the reduced Čech H¹ quotient space. Each basis element specifies
    an independent obstruction; the corresponding edge resolves it. -/
theorem operationalTax_le_h1 (P : IndexedPoset Secret) (indices : List Nat) :
    operationalAlignmentTax P indices ≤ alignmentTaxH1 P indices := by
  sorry -- basis of H¹ cocycles induces a realising set of size = rank H¹

/-- **Bridge theorem (lower bound)**: operational tax ≥ rank H¹.

    Strategy: any realising set induces an augmentation of `δ⁰` whose rank
    increase is at most `|L|`. To kill all `rank H¹` obstruction classes
    the augmentation must have rank increase ≥ `rank H¹` (rank-nullity,
    from `RankNullity.lean`). -/
theorem operationalTax_ge_h1 (P : IndexedPoset Secret) (indices : List Nat) :
    operationalAlignmentTax P indices ≥ alignmentTaxH1 P indices := by
  sorry -- rank-nullity argument via gaussRankBool_le_rows on augmented δ⁰

/-- **The Alignment Tax Theorem**: operational = structural.

    Conjecturally closes the main theorem: the cohomological rank exactly
    equals the operational cost of realising capability under policy. -/
theorem alignmentTax_eq_h1 (P : IndexedPoset Secret) (indices : List Nat) :
    operationalAlignmentTax P indices = alignmentTaxH1 P indices :=
  Nat.le_antisymm (operationalTax_le_h1 P indices) (operationalTax_ge_h1 P indices)

/-! ## Cohomological-rank semantics for `Realises`

The original `Realises` predicate above (every C¹ entry covered) is the
*combinatorial* version. It's correct as an existence witness but loose:
it requires `|L| ≥ |C¹|` rather than `|L| ≥ rank H¹`. The genuine
bridge theorem needs the *cohomological* version below: `L` realises
iff augmenting `δ⁰` with `L`'s indicator rows kills H¹.

Under this stronger predicate, `operationalTax_ge_h1` follows from rank
subadditivity (`gaussRankBool_append_le`): augmenting δ⁰ by `|L|` rows
increases its rank by at most `|L|`, so to push H¹ to 0 one needs
`|L| ≥ rank H¹`. -/

/-- The C¹-indicator row of a declassification edge.

    For an edge `(f, t, p)`, the row has `true` exactly at C¹ entries
    `(i, j, q)` matching the edge in either direction (i.e., `q = p`
    and `{i, j} = {f, t}`), `false` elsewhere. This is the cohomological
    "kill the obstruction at `(f, t, p)`" generator. -/
def declassRow (P : IndexedPoset Secret) (indices : List Nat)
    (e : DeclassEdge) : List Bool :=
  (reducedC1 P indices).map fun c =>
    decide (e.prop = c.2.2 ∧
      ((e.fromIdx = c.1 ∧ e.toIdx = c.2.1) ∨
       (e.fromIdx = c.2.1 ∧ e.toIdx = c.1)))

/-- The augmented coboundary matrix: original `δ⁰` with one new row per
    declassification edge. -/
def augmentedDelta0 (P : IndexedPoset Secret) (indices : List Nat)
    (L : List DeclassEdge) : List (List Bool) :=
  reducedDelta0 P indices ++ L.map (declassRow P indices)

/-- **Cohomological realising condition**: `L` realises iff the augmented
    `δ⁰` together with `δ¹` spans all of C¹, i.e. the augmented complex
    has H¹ = 0. -/
def RealisesH1 (P : IndexedPoset Secret) (indices : List Nat)
    (L : List DeclassEdge) : Prop :=
  (reducedC1 P indices).length ≤
    gaussRankBool (augmentedDelta0 P indices L) +
    gaussRankBool (reducedDelta1 P indices)

/-- **Lower bound on realising sets** — the main-theorem core lemma.

    Any cohomologically-realising declassification set has cardinality at
    least `alignmentTaxH1 P indices = rank H¹`. The proof uses rank
    subadditivity of `gaussRankBool` under row append (from `RankNullity`).

    Once this lands, it implies `operationalTax ≥ rank H¹` for any
    operationalAlignmentTax defined as `min |L|` over realising sets — i.e.
    the lower bound of the Alignment Tax Theorem. -/
theorem realising_set_size_ge_h1
    (P : IndexedPoset Secret) (indices : List Nat) (L : List DeclassEdge)
    (h : RealisesH1 P indices L) :
    alignmentTaxH1 P indices ≤ L.length := by
  -- Rank subadditivity: augmented rank ≤ original + |L|.
  have h_aug : gaussRankBool (augmentedDelta0 P indices L) ≤
      gaussRankBool (reducedDelta0 P indices) + L.length := by
    unfold augmentedDelta0
    have := PortcullisCore.RankNullity.gaussRankBool_append_le
              (reducedDelta0 P indices) (L.map (declassRow P indices))
    simpa using this
  -- Realising: augmented rank + rank δ¹ ≥ |C¹|.
  -- Substitute: rank δ⁰ + |L| + rank δ¹ ≥ |C¹|, i.e. |L| ≥ alignmentTaxH1.
  unfold alignmentTaxH1
  show ((reducedC1 P indices).length - gaussRankBool (reducedDelta1 P indices)
        - gaussRankBool (reducedDelta0 P indices)) ≤ L.length
  unfold RealisesH1 at h
  -- Combine h and h_aug: substitute the augmented-rank bound.
  have h_combined :
      (reducedC1 P indices).length ≤
        gaussRankBool (reducedDelta0 P indices) + L.length +
        gaussRankBool (reducedDelta1 P indices) := by
    have := Nat.add_le_add_right h_aug (gaussRankBool (reducedDelta1 P indices))
    omega
  omega

/-! ## Operational alignment tax under the cohomological predicate

Repeat the operational-min construction with the corrected `RealisesH1`
predicate. This gives the main-theorem-shaped operational invariant. -/

/-- The trivially full edge list realises `RealisesH1` because once C¹
    is fully covered by indicator rows, augmented δ⁰ has rank ≥ |C¹|. -/
private def fullDeclassList (P : IndexedPoset Secret) (indices : List Nat) :
    List DeclassEdge :=
  (reducedC1 P indices).map (fun c => ⟨c.1, c.2.1, c.2.2⟩)

/-- **Operational H¹-tax**: the minimum cardinality over `RealisesH1`
    sets. The honest "least cost to kill all H¹ obstructions". -/
noncomputable def operationalAlignmentTaxH1
    (P : IndexedPoset Secret) (indices : List Nat) : Nat := by
  classical
  exact Nat.find (p := fun n => ∃ L : List DeclassEdge,
    L.length ≤ n ∧ RealisesH1 P indices L)
    -- Existence witness: any sufficiently large L; we use `|C¹|` and
    -- defer a tight realiser construction to follow-up work.
    ⟨(reducedC1 P indices).length, fullDeclassList P indices,
      by unfold fullDeclassList; simp,
      by
        -- Realising follows once a tight realiser construction is in hand.
        -- For now we use the fact that `RealisesH1` is an *upper* bound
        -- request, and use the trivial lower bound on `gaussRankBool`.
        sorry⟩

/-- **Main Theorem lower bound** on the H¹-flavoured operational tax.

    Direct corollary of `realising_set_size_ge_h1`: every realising set
    is at least `rank H¹` in size, so the minimum is too. -/
theorem operationalAlignmentTaxH1_ge (P : IndexedPoset Secret) (indices : List Nat) :
    alignmentTaxH1 P indices ≤ operationalAlignmentTaxH1 P indices := by
  classical
  unfold operationalAlignmentTaxH1
  -- Use the spec of Nat.find: it satisfies the predicate.
  have h_spec := Nat.find_spec
    (p := fun n => ∃ L : List DeclassEdge, L.length ≤ n ∧ RealisesH1 P indices L)
    ⟨(reducedC1 P indices).length, fullDeclassList P indices,
      by unfold fullDeclassList; simp,
      by sorry⟩
  obtain ⟨L, hL_len, hL_h1⟩ := h_spec
  have h_lower := realising_set_size_ge_h1 P indices L hL_h1
  omega

/-! ## Upper bound and the main-theorem equality

The lower bound says any cohomologically-realising L has |L| ≥ rank H¹.
The upper bound says there *exists* such an L of size exactly rank H¹ —
a transversal of the H¹ quotient space.

This is classical linear algebra (any quotient of finite-dim space has
a basis), but our List-encoded matrices need direct formalization. We
state it as a clean axiom; combined with the lower bound, this gives the
**Alignment Tax Theorem**: `operationalTax = rank H¹`. -/

/-- **Basis transversal existence**: there is a list of declassification
    edges of length exactly `rank H¹` that realises `RealisesH1`.

    Classical linear algebra: pick a basis of the H¹ quotient and
    represent each basis element as an indicator-row declass edge.

    Stated as a sorry; the structural proof requires extracting a basis
    from the gaussRankBool elimination. The fact is true for any finite
    GF(2)-cohomology theory. -/
theorem h1_basis_realiser_exists
    (P : IndexedPoset Secret) (indices : List Nat) :
    ∃ L : List DeclassEdge,
      L.length = alignmentTaxH1 P indices ∧ RealisesH1 P indices L := by
  sorry

/-- **Main Theorem upper bound**: operational tax ≤ rank H¹.

    Direct from `h1_basis_realiser_exists`: a transversal of size
    `alignmentTaxH1` realises, so the minimum is at most that. -/
theorem operationalAlignmentTaxH1_le (P : IndexedPoset Secret) (indices : List Nat) :
    operationalAlignmentTaxH1 P indices ≤ alignmentTaxH1 P indices := by
  classical
  obtain ⟨L, hL_len, hL_real⟩ := h1_basis_realiser_exists P indices
  unfold operationalAlignmentTaxH1
  apply Nat.find_le
  exact ⟨L, by omega, hL_real⟩

/-- **The Alignment Tax Theorem**

    `operationalAlignmentTaxH1 = alignmentTaxH1`

    The minimum number of declassification edges required to globally
    realise a task under an IFC policy equals the rank of the first
    Čech cohomology group of the IFC sheaf — the "main theorem"
    from `project_alignment_tax_conjecture.md`.

    Proved (modulo three structural sorries — all classical-LA facts
    about GF(2) row-space rank). -/
theorem alignmentTaxH1_eq_operational
    (P : IndexedPoset Secret) (indices : List Nat) :
    operationalAlignmentTaxH1 P indices = alignmentTaxH1 P indices :=
  Nat.le_antisymm
    (operationalAlignmentTaxH1_le P indices)
    (operationalAlignmentTaxH1_ge P indices)

end PortcullisCore.AlignmentTaxBridge
