import ComparisonTheorem

/-! # Acyclicity of the full simplex over GF(2)

This file develops the classical cone/contracting-homotopy proof that a
full simplex has trivial reduced cohomology, specialised to the Čech
presheaf of a *constant* (uniform) restriction.

## Strategy

For a finite set of indices and a presheaf `F` that restricts trivially
(every level forces the same props), the reduced Čech complex decomposes
per-proposition into copies of the simplicial cochain complex of the full
simplex on `indices`.

Over GF(2), the full n-simplex has trivial reduced cohomology. The
classical proof uses a *cone construction*: fix a cone vertex `v₀` and
define `s : Cᵏ → Cᵏ⁻¹` by "delete `v₀` from simplices containing it".
One verifies

    δ ∘ s + s ∘ δ = id − ε∘η

where `ε` is the augmentation and `η : M → C⁰` the constant embedding.
This identity gives `ker δ ⊆ im δ`, hence H¹ = 0.

## Connection to the List-based Čech complex

The concrete matrices in `ComparisonTheorem` (`reducedDelta0`, `reducedDelta1`)
are Boolean matrices indexed by `(C⁰, C¹)` and `(C¹, C²)` respectively.
The cone operator is an explicit Boolean matrix `S : C¹ → C⁰` that picks a
cone vertex and "prepends" it to each 1-simplex containing it.

## Current status

This file states the definitions and the target theorem. Proving the
contracting-homotopy identity and bridging to `gaussRankBool` closes
`ComparisonTheorem.uniform_implies_h1_zero` for the nonempty C¹ case.

The proof strategy is classical (Hatcher §2.1, Mumford–Oda Ch. VII §1,
Weibel §8). Over GF(2) the sign arithmetic collapses, giving the cleanest
formalisation.
-/

open SemanticIFCDecidable
open SemanticIFCDecidable.BoundaryMaps
open AlexandrovSite
open PresheafCech

namespace PortcullisCore.SimplexAcyclic

/-- Cone operator at vertex `i₀`: sends a 1-simplex `(i, j, p)` to the
    0-simplex `(i₀, p)` if `i₀` is incident to the 1-simplex's carrier,
    else 0. This is the "delete `i₀` from the 1-simplex" homotopy,
    rephrased as a C¹ → C⁰ map via adjacency.

    The precise rule: `s₁(i₀)(i, j, p) = 1_{(i₀, p)}` exactly when
    `i₀ ∈ {i, j}` and `p` is forced at `i₀`. Else `0`.

    Over GF(2), this collapses `±` signs into simple `xor`. -/
def coneMap1 (i₀ : Nat) (c1entry : Nat × Nat × Nat) : Option (Nat × Nat) :=
  let (i, j, p) := c1entry
  if i = i₀ ∨ j = i₀ then some (i₀, p) else none

/-- Cone operator at vertex `i₀` for 2-simplices: sends `(i, j, k, p)` to
    the 1-simplex obtained by deleting `i₀` if `i₀ ∈ {i, j, k}`. -/
def coneMap2 (i₀ : Nat) (c2entry : Nat × Nat × Nat × Nat) :
    Option (Nat × Nat × Nat) :=
  let (i, j, k, p) := c2entry
  if i = i₀ then some (j, k, p)
  else if j = i₀ then some (i, k, p)
  else if k = i₀ then some (i, j, p)
  else none

/-- **Characterization**: `coneMap1` returns `some` iff the cone vertex is
    incident to the 1-simplex. Foundational small lemma for the cone
    construction — every downstream homotopy identity case-splits on this. -/
theorem coneMap1_isSome (i₀ : Nat) (c1entry : Nat × Nat × Nat) :
    (coneMap1 i₀ c1entry).isSome ↔ c1entry.1 = i₀ ∨ c1entry.2.1 = i₀ := by
  obtain ⟨i, j, p⟩ := c1entry
  unfold coneMap1
  by_cases h : i = i₀ ∨ j = i₀
  · simp [h]
  · simp [h]

/-- **Characterization**: `coneMap2` returns `some` iff the cone vertex is
    incident to the 2-simplex. -/
theorem coneMap2_isSome (i₀ : Nat) (c2entry : Nat × Nat × Nat × Nat) :
    (coneMap2 i₀ c2entry).isSome ↔
      c2entry.1 = i₀ ∨ c2entry.2.1 = i₀ ∨ c2entry.2.2.1 = i₀ := by
  obtain ⟨i, j, k, p⟩ := c2entry
  unfold coneMap2
  by_cases hi : i = i₀
  · simp [hi]
  by_cases hj : j = i₀
  · simp [hi, hj]
  by_cases hk : k = i₀
  · simp [hi, hj, hk]
  simp [hi, hj, hk]

/-- **Target theorem** (nonempty C¹ case of `uniform_implies_h1_zero`).

    Under the uniform hypothesis and for a nonempty `indices`, the
    contracting-homotopy identity via `coneMap1`/`coneMap2` shows every
    cocycle is a coboundary, hence H¹ = 0.

    Proof outline:
      1. Extract a cone vertex `i₀` from the nonempty `indices`.
      2. Build explicit preimages for each (i, j, p) ∈ C¹ via `coneMap1`.
      3. Verify δ⁰ ∘ s₁ + s₂ ∘ δ¹ = id by case analysis on whether `i₀`
         is incident to the simplex.
      4. Conclude `rank(δ⁰) ≥ |C¹| − rank(δ¹)`, which combined with the
         chain-complex property δ¹ ∘ δ⁰ = 0 yields equality. -/
theorem simplex_acyclic_h1 {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (P : IndexedPoset Secret) (indices : List Nat)
    (hne : indices ≠ [])
    (hC1 : reducedC1 P indices ≠ [])
    (h_uniform : ∀ i ∈ indices, ∀ j ∈ indices, ∀ p : Nat,
      p < P.allProps.length →
      (match P.levels[i]? with
       | some E => DObsLevel.dForces E (P.allProps[p]!)
       | none => false) = true →
      (match P.levels[j]? with
       | some E => DObsLevel.dForces E (P.allProps[p]!)
       | none => false) = true) :
    reducedCechDim P indices 1 = 0 := by
  sorry -- cone construction: δ⁰ ∘ s₁ + s₂ ∘ δ¹ = id ⇒ H¹ = 0

end PortcullisCore.SimplexAcyclic
