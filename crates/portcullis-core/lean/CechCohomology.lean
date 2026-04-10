import Mathlib.Data.Fintype.Basic
import Mathlib.Data.Finset.Basic
import Mathlib.Order.Basic
import SemanticIFCDecidable

/-!
# Čech cohomology of finite posets (scaffold — Phase 8 Y6.0, issue #1493)

This module lays the foundation for formally connecting the ad-hoc
`h1_witnesses` / `h2_compute` functions in `SemanticIFCDecidable.lean`
to **actual Čech cohomology** of the Alexandrov site on a finite poset.

## Status

This is the **scaffold** (PR 1 of ~4). It defines the type signatures and
the headline comparison theorem, with placeholder proofs that document
the shape of the work required. Subsequent PRs will:

- **PR 2 — Čech complex:** replace `cechCochain`, `cechBoundary`, and
  `cechH` with honest alternating-sum computations over the nerve of
  the principal filter cover.
- **PR 3 — Topos side:** define `toposH` via `Mathlib.CategoryTheory.Sites`
  and the sheafification functor on `(P, Alexandrov)`.
- **PR 4 — Comparison iso:** prove `cech_iso_topos` under the
  Dedekind-MacNeille acyclicity condition from
  [arxiv 2310.05577](https://arxiv.org/html/2310.05577) (Čech cohomology
  of partially ordered sets, updated Feb 2026).
- **PR 5 — Bridge lemmas:** prove `h1_witnesses diamondPoset = cechH _ 1`
  and `h2_compute borromeanPoset = cechH _ 2`, upgrading the existing
  `StrictHierarchy` work from "worked examples" to "theorems about
  actual cohomology".

## The load-bearing point

Nothing downstream of this file — `alignment_tax`, the strict hierarchy
theorem, the attention-topos functor, the commercial attestation pitch —
is formally legitimate until the comparison theorem lands. The scaffold
stubs mark exactly where the work lives.

## References

- [arxiv 2310.05577](https://arxiv.org/html/2310.05577) — Čech cohomology
  of partially ordered sets (Kuzminov 90th anniversary, Feb 2026).
  Gives the exact Dedekind-MacNeille acyclicity criterion for when the
  Čech-to-topos comparison is an isomorphism.
- [Stacks Project Tag 03AJ](https://stacks.math.columbia.edu/tag/03AJ) —
  general Čech-to-topos comparison.
- Weibel, *An Introduction to Homological Algebra*, §5.8 (Čech cohomology).
- [Mathlib.CategoryTheory.Sites.Grothendieck](https://leanprover-community.github.io/mathlib4_docs/Mathlib/CategoryTheory/Sites/Grothendieck.html)
- [Mathlib.Topology.Order.UpperLowerSetTopology](https://leanprover-community.github.io/mathlib4_docs/Mathlib/Topology/Order/UpperLowerSetTopology.html)
-/

namespace CechCohomology

/-! ## Presheaves of propositions on a finite poset

A `BoolPresheaf P` is the data that every `DObsLevel`-flavoured theorem
in `SemanticIFCDecidable.lean` is secretly about: at each observation
level (= point of the poset), which Bool-valued propositions are
"allowed" (forced). We represent this as a function `P → Bool` for the
scaffold; Phase 2 will upgrade it to a proper contravariant functor
`Pᵒᵖ ⥤ Type` that respects the restriction maps. -/

/-- A Bool-valued "presheaf" on a finite poset.

    **Scaffold simplification.** In the real Phase 2 definition this will
    be a monotone contravariant functor `P → Finset (Secret → Bool)`
    assigning to each observation level the set of propositions forced
    there. For the scaffold we collapse this to `P → Bool` — a single bit
    per level — and defer the restriction-map structure. -/
def BoolPresheaf (P : Type) [PartialOrder P] : Type :=
  P → Bool

/-- A trivial presheaf that's `true` everywhere. Useful for smoke tests. -/
def trivialPresheaf (P : Type) [PartialOrder P] : BoolPresheaf P :=
  fun _ => true

/-! ## The Čech complex

The Čech complex of a presheaf `𝓕` on a cover `𝓤 = {U_i}` is

    C⁰ → C¹ → C² → ...

where `Cⁿ := ∏_{(i₀,…,iₙ)} 𝓕(U_{i₀} ∩ ⋯ ∩ U_{iₙ})` and the boundary
maps δⁿ are the alternating sum of the obvious restriction maps.

For the Alexandrov site on a finite poset `P`, the canonical cover is
the collection of principal filters `{P^≥x}_{x ∈ P}`. For the scaffold
we just return `0` at every degree, documenting the types.

Phase 2 will replace these stubs with honest alternating-sum
computations on the nerve of the principal-filter cover. -/

/-- The `n`-th Čech cochain group, as a Nat. Scaffold stub.

    Real definition (Phase 2): the number of `n+1`-tuples of poset
    points whose principal filters have a non-empty intersection, with
    the presheaf assigning a Bool section to each. -/
def cechCochain {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P]
    (_𝓕 : BoolPresheaf P) (_n : ℕ) : Nat := 0

/-- The Čech coboundary operator `δⁿ` at degree `n`. Scaffold stub.

    Real definition (Phase 2): alternating sum of face maps on the
    nerve of the principal-filter cover. -/
def cechBoundary {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P]
    (_𝓕 : BoolPresheaf P) (_n : ℕ) : Nat := 0

/-- Čech cohomology at degree `n`: `ker(δⁿ) / im(δⁿ⁻¹)`. Scaffold stub.

    Real definition (Phase 2): the standard quotient computation on
    the cochain complex. For now this returns `0` unconditionally,
    matching the stub cochain groups. -/
def cechH {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P]
    (_𝓕 : BoolPresheaf P) (_n : ℕ) : Nat := 0

/-! ## Topos cohomology

The **topos cohomology** of a presheaf `𝓕` on a Grothendieck site is
the derived functor of global sections applied to the sheafification
of `𝓕`. For the Alexandrov site on a finite poset, this coincides
with the Čech cohomology under the Dedekind-MacNeille acyclicity
condition.

For the scaffold this is also a stub. Phase 3 will wire in Mathlib's
`CategoryTheory.Sites.Grothendieck` and `CategoryTheory.Sheaf` to give
an honest definition via derived functors of the forgetful sheaf-to-Bool
map. -/

/-- Topos cohomology at degree `n` for the Alexandrov site. Scaffold stub.

    Real definition (Phase 3): the derived functor of `Γ` applied to
    the sheafification of `𝓕` via `Mathlib.CategoryTheory.Sheafification`. -/
def toposH {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P]
    (_𝓕 : BoolPresheaf P) (_n : ℕ) : Nat := 0

/-! ## Dedekind-MacNeille acyclicity

A finite poset is **DM-acyclic** when the principal-filter cover of its
Dedekind-MacNeille completion is acyclic in the sense that every upper
section has trivial higher cohomology. [arxiv 2310.05577] proves this
is the exact condition under which the Čech-to-topos comparison map
is an isomorphism in every degree.

For the scaffold we use `True` as a placeholder. Phase 2 will give the
honest definition in terms of Mathlib's `Order.DedekindMacNeille` (or
via an order-theoretic acyclicity predicate if the completion is not
directly available). -/

/-- The Dedekind-MacNeille acyclicity condition on a finite poset.
    Scaffold stub — always `True`. Phase 2 will replace this with
    the real definition from [arxiv 2310.05577]. -/
def isDMAcyclic (P : Type) [PartialOrder P] [Fintype P] : Prop := True

/-- Every finite poset trivially satisfies the stub condition.
    (Phase 2 will refine this to a predicate that's `False` for some
    pathological posets.) -/
theorem isDMAcyclic_trivial (P : Type) [PartialOrder P] [Fintype P] :
    isDMAcyclic P := trivial

/-! ## The main comparison theorem

This is the load-bearing theorem the whole Phase 8 math depends on. -/

/-- **Čech-to-topos comparison theorem** (scaffold).

    For finite posets satisfying the Dedekind-MacNeille acyclicity
    condition, Čech cohomology of a Bool-valued presheaf agrees with
    topos cohomology in every degree.

    **Current proof:** trivially `rfl` because both sides are scaffold
    stubs returning `0`. Phase 4 will replace this with the real
    structural proof via the Čech-to-derived-functor spectral sequence,
    under the DM acyclicity hypothesis. -/
theorem cech_iso_topos {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P]
    (_h : isDMAcyclic P) (𝓕 : BoolPresheaf P) (n : ℕ) :
    cechH 𝓕 n = toposH 𝓕 n := by
  -- Stub proof: both sides are 0 in the scaffold.
  -- Phase 4: prove via Čech-to-derived-functor comparison + DM acyclicity.
  rfl

/-! ## Bridge lemmas to `SemanticIFCDecidable.lean`

These are the theorems that make the existing work legitimate. They
state: the ad-hoc counting functions `h1_witnesses` and `h2_compute`,
applied to our worked examples (diamond, Borromean), equal the Čech
cohomology of the corresponding presheaf at the corresponding degree.

**Scaffold status:** not yet stated here, because `h1_witnesses` and
`h2_compute` live in `SemanticIFCDecidable` and importing it would
create a dependency loop with the bridge targets. Phase 5 handles the
bridge in a dedicated PR that either imports this module from
`SemanticIFCDecidable` or moves the bridge into a third module that
imports both.

Phase 5 target (planned shape):
```
theorem h1_witnesses_eq_cechH_diamond :
    SemanticIFCDecidable.h1_witnesses
      SemanticIFCDecidable.ThreeSecretCohomology.diamondPoset
      SemanticIFCDecidable.ThreeSecretCohomology.allProps =
    cechH (diamondAsBoolPresheaf) 1 := ...

theorem h2_compute_eq_cechH_borromean :
    SemanticIFCDecidable.h2_compute
      SemanticIFCDecidable.Borromean.borromeanPoset
      SemanticIFCDecidable.BorromeanCohomology.allFiveSecretProps =
    cechH (borromeanAsBoolPresheaf) 2 := ...
```
-/

/-! ## Smoke tests

Trivial lemmas that exercise the scaffold signatures. These confirm the
file builds and the definitions have the intended shapes. -/

/-- Sanity: the stub `cechH` returns 0 on the trivial presheaf. -/
example {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P] (n : ℕ) :
    cechH (trivialPresheaf P) n = 0 := rfl

/-- Sanity: the stub `toposH` also returns 0. -/
example {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P] (n : ℕ) :
    toposH (trivialPresheaf P) n = 0 := rfl

/-- Sanity: the comparison theorem holds trivially in the scaffold. -/
example {P : Type} [PartialOrder P] [Fintype P] [DecidableEq P] (n : ℕ) :
    cechH (trivialPresheaf P) n = toposH (trivialPresheaf P) n :=
  cech_iso_topos (isDMAcyclic_trivial P) _ n

end CechCohomology

/-! ## Order complex of a finite poset (Phase 2 content for #1493)

The **order complex** Δ(P) of a finite poset P is the abstract
simplicial complex whose n-simplices are the strictly increasing
chains p₀ < p₁ < ... < pₙ in P. Its simplicial cohomology is the
Čech cohomology of the Alexandrov site.

For List-encoded posets (as used in `SemanticIFCDecidable.lean`), we
define the order complex concretely via index chains and compute
the face numbers (number of n-simplices). Future work connects these
to the Čech boundary operators.

This is the first non-stub content toward the honest Čech complex.
-/

namespace OrderComplex

/-- Check refinement via index-based comparison on a list-encoded poset.
    `refinesAtB poset allProps i j` returns `true` iff `poset[j]` refines
    `poset[i]` — i.e. everything forced at `poset[i]` is also forced at
    `poset[j]` (the finer level forces more). This means `poset[i] ≤ poset[j]`
    in the coarseness preorder.

    Uses the forcing-based proxy for ≤ since `DObsLevel` lacks a computable
    `DecidableLE` in general. -/
def refinesAtB {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (poset : List (SemanticIFCDecidable.DObsLevel Secret))
    (allProps : List (SemanticIFCDecidable.DProp Secret))
    (i j : Nat) : Bool :=
  match poset[i]?, poset[j]? with
  | some Ei, some Ej =>
    -- "j refines i" = everything forced at Ei is also forced at Ej
    allProps.all fun φ =>
      !SemanticIFCDecidable.DObsLevel.dForces Ei φ ||
       SemanticIFCDecidable.DObsLevel.dForces Ej φ
  | _, _ => false

/-- **Edges** of the order complex: pairs `(i, j)` with `i < j` where
    `poset[j]` refines `poset[i]` (i.e. `j` is finer than `i`). These
    are the 1-simplices of Δ(P).

    For the diamond `[bot, obsAC, obsBC, top]`, the edges are:
    `(0,1), (0,2), (0,3), (1,3), (2,3)` — bot < obsAC, bot < obsBC,
    bot < top, obsAC < top, obsBC < top. -/
def edges {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (poset : List (SemanticIFCDecidable.DObsLevel Secret))
    (allProps : List (SemanticIFCDecidable.DProp Secret)) :
    List (Nat × Nat) :=
  (List.range poset.length).flatMap fun i =>
  (List.range poset.length).filterMap fun j =>
    if i < j && refinesAtB poset allProps i j then some (i, j) else none

/-- **Triangles** of the order complex: triples `(i, j, k)` with
    `i < j < k` where each consecutive pair refines. These are the
    2-simplices of Δ(P).

    For the diamond: `(0,1,3), (0,2,3)` — the two maximal chains
    through the diamond. -/
def triangles {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (poset : List (SemanticIFCDecidable.DObsLevel Secret))
    (allProps : List (SemanticIFCDecidable.DProp Secret)) :
    List (Nat × Nat × Nat) :=
  (List.range poset.length).flatMap fun i =>
  (List.range poset.length).flatMap fun j =>
  (List.range poset.length).filterMap fun k =>
    if i < j && j < k &&
       refinesAtB poset allProps i j &&
       refinesAtB poset allProps j k
    then some (i, j, k) else none

/-- The **face numbers** of the order complex: `faceNumber P n` is the
    number of `n`-simplices. `f₀ = vertices, f₁ = edges, f₂ = triangles`.
    These are the dimensions of the Čech cochain groups `Cⁿ`. -/
def faceNumber {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (poset : List (SemanticIFCDecidable.DObsLevel Secret))
    (allProps : List (SemanticIFCDecidable.DProp Secret))
    (n : Nat) : Nat :=
  match n with
  | 0 => poset.length
  | 1 => (edges poset allProps).length
  | 2 => (triangles poset allProps).length
  | _ => 0  -- higher simplices: future work

/-- The **Euler characteristic** of the order complex: `Σ (-1)ⁿ fₙ`.
    For a connected poset this equals 1 + (f₁ - f₂ + ...) adjustments.
    The key relation to cohomology: `χ = Σ (-1)ⁿ hⁿ` (when defined
    over the right coefficient field). -/
def eulerChar {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (poset : List (SemanticIFCDecidable.DObsLevel Secret))
    (allProps : List (SemanticIFCDecidable.DProp Secret)) : Int :=
  (faceNumber poset allProps 0 : Int) -
  (faceNumber poset allProps 1 : Int) +
  (faceNumber poset allProps 2 : Int)

end OrderComplex

/-! ## Order complex smoke tests on concrete posets -/

namespace OrderComplexExamples
open OrderComplex SemanticIFCDecidable

/-! ### Diamond (ThreeSecret) -/

/-- Diamond has 4 vertices. -/
example : faceNumber ThreeSecretCohomology.diamondPoset
    ThreeSecretCohomology.allProps 0 = 4 := by decide

/-- Diamond edge count (f₁). -/
example : faceNumber ThreeSecretCohomology.diamondPoset
    ThreeSecretCohomology.allProps 1 = 5 := by decide

/-- Diamond triangle count (f₂). -/
example : faceNumber ThreeSecretCohomology.diamondPoset
    ThreeSecretCohomology.allProps 2 = 2 := by decide

/-- Diamond Euler characteristic: f₀ − f₁ + f₂ = 4 − 5 + 2 = 1. -/
example : eulerChar ThreeSecretCohomology.diamondPoset
    ThreeSecretCohomology.allProps = 1 := by decide

/-! ### Borromean (FiveSecret) -/

/-- Borromean has 5 vertices. -/
example : faceNumber Borromean.borromeanPoset
    BorromeanCohomology.allFiveSecretProps 0 = 5 := by decide

/-- Borromean edge count (f₁). -/
example : faceNumber Borromean.borromeanPoset
    BorromeanCohomology.allFiveSecretProps 1 = 7 := by decide

/-- Borromean triangle count (f₂). -/
example : faceNumber Borromean.borromeanPoset
    BorromeanCohomology.allFiveSecretProps 2 = 3 := by decide

/-- Borromean Euler characteristic. -/
example : eulerChar Borromean.borromeanPoset
    BorromeanCohomology.allFiveSecretProps = 1 := by decide

end OrderComplexExamples
