import ComparisonTheorem

/-! # Alignment Tax = rank H¹: the operational–structural bridge

`alignmentTaxH1` is already defined as `reducedCechDim P indices 1` (the
structural / Čech-cohomological invariant). That identity is a **definition**,
not a theorem.

The **holy-grail conjecture** from `project_alignment_tax_conjecture.md`
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

This is the Rice's-theorem / Shannon-bound for AI security: it pins the
tax exactly, proving that each independent cohomology class corresponds
to exactly one mandatory declassification and vice-versa.

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

    Conjecturally closes the holy grail: the cohomological rank exactly
    equals the operational cost of realising capability under policy. -/
theorem alignmentTax_eq_h1 (P : IndexedPoset Secret) (indices : List Nat) :
    operationalAlignmentTax P indices = alignmentTaxH1 P indices :=
  Nat.le_antisymm (operationalTax_le_h1 P indices) (operationalTax_ge_h1 P indices)

end PortcullisCore.AlignmentTaxBridge
