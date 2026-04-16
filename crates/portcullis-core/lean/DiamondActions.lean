import ComparisonTheorem

/-! # DiamondActions — Z/2 action test on diamondSite's H¹ = 2

The diamond IFC poset has two non-trivial observation levels:
  obsAC — confuses A↔C
  obsBC — confuses B↔C

Swapping obsAC ↔ obsBC (indices 1 ↔ 2 in covering [1,2,3]) is
a natural Z/2 symmetry. Binary test:

  dim H¹^σ₁₂ = 2  → Z/2 acts trivially on H¹ (both generators are
                     "structurally equivalent" — symmetric diamond)
  dim H¹^σ₁₂ = 1  → Z/2 acts non-trivially (P(1)-type non-split
                     extension, like the Borromean case)

Over GF(2), the 2×2 σ with σ² = I is either I (trivial, fixed = 2)
or [[1,1],[0,1]] (unipotent, fixed = 1). No other options.

This is the simplest test of whether the action-theoretic framework
developed for Borromean/augmented generalizes to a second IFC poset.
-/

open SemanticIFCDecidable DObsLevel
open AlexandrovSite PresheafCech

namespace PortcullisCore.DiamondActions

abbrev Cell := Nat × Nat × Nat

def cellEq (x y : Cell) : Bool :=
  x.1 == y.1 && x.2.1 == y.2.1 && x.2.2 == y.2.2

def applySwap (f : Nat → Nat) : Cell → Cell
  | (i, j, p) =>
    let i' := f i
    let j' := f j
    if i' < j' then (i', j', p)
    else if j' < i' then (j', i', p)
    else (i', j', p)

def swap12 : Nat → Nat
  | 1 => 2
  | 2 => 1
  | n => n

def c1Basis : List Cell :=
  reducedC1 diamondSite [1, 2, 3]

def sigmaMinusIdMatrix (basis : List Cell) (σ : Cell → Cell) :
    List (List Bool) :=
  basis.map fun b =>
    let σb := σ b
    basis.map fun x => cellEq x b != cellEq x σb

def h1DescentMatrix (σ : Cell → Cell) : List (List Bool) :=
  let b0 := reducedC0 diamondSite [1, 2, 3]
  let b1 := c1Basis
  let n0 := b0.length
  let n1 := b1.length
  let d1 := reducedDelta1 diamondSite [1, 2, 3]
  let d0 := reducedDelta0 diamondSite [1, 2, 3]
  let σMinusId := sigmaMinusIdMatrix b1 σ
  let topBlock := d1.map fun row => row ++ List.replicate n0 false
  let bottomBlock := (List.range n1).map fun idx =>
    let σRow := σMinusId[idx]!
    let d0Row := d0[idx]!
    σRow ++ d0Row
  topBlock ++ bottomBlock

/-! ## Results -/

#eval s!"|C⁰| diamond [1,2,3]               = {(reducedC0 diamondSite [1,2,3]).length}"
#eval s!"|C¹| diamond [1,2,3]               = {c1Basis.length}"
#eval s!"|C²| diamond [1,2,3]               = {(reducedC2 diamondSite [1,2,3]).length}"
#eval s!"H¹ diamond [1,2,3]                 = {reducedCechDim diamondSite [1,2,3] 1}"

#eval s!"rank(σ₁₂ - id) on C¹              = {gf2Rank (sigmaMinusIdMatrix c1Basis (applySwap swap12))}"
#eval s!"dim H¹^σ₁₂ = |C¹| - rank(M)       = {c1Basis.length - gf2Rank (h1DescentMatrix (applySwap swap12))}"

/-! ## Interpretation

  dim H¹^σ₁₂ = 2 → trivial Z/2 action; diamond is "too symmetric"
                     for the action framework to detect structure.
                     (Both obs levels are interchangeable.)

  dim H¹^σ₁₂ = 1 → non-trivial Z/2 action on H¹ = 2.
                     Diamond carries a P(1)-type non-split extension
                     under its natural Z/2. The action framework
                     generalizes beyond Borromean.

  dim H¹^σ₁₂ = 0 → σ₁₂ acts freely on H¹ (no fixed vectors).
                     Over GF(2) with σ² = 1, this can't happen on a
                     2-dim space (σ is unipotent, always has 1 fixed).
-/

end PortcullisCore.DiamondActions
