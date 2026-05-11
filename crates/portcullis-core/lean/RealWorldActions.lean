import ComparisonTheorem

/-! # RealWorldActions — Z/2 action tests on real-world IFC posets

Tests whether observation-level swaps produce non-trivial actions on
H¹ for four real-world security models:

  1. **BLP** (Bell-LaPadula): military confidentiality, obsSecretRead ↔ obsSecretWrite
  2. **Biba**: integrity model (dual of BLP), obsVerifiedRead ↔ obsVerifiedWrite
  3. **PrivEsc**: privilege escalation, obsUser ↔ obsAdmin
  4. **Indirect**: RAG injection / confused-deputy, obsQuery ↔ obsProvenance

All are 4-level diamond-shaped posets with 2³ = 8 propositions.

## Hypothesis

Diamond (obsAC ↔ obsBC) had TRIVIAL Z/2 action because both
observations are structurally similar (same-type letter confusion).

Real-world models have structurally DIFFERENT observation types:
  BLP:     read-up vs write-down
  Biba:    read-down vs write-up
  PrivEsc: user-level vs admin-level
  Indirect: query-trust vs provenance-trust

If the Z/2 action is NON-TRIVIAL on any of these, it means the
alignment cost has hidden directional structure that the scalar
H¹ value (= 2 for all diamond posets) doesn't capture. This would
be a real-world application of the representation-theoretic framework.
-/

open SemanticIFCDecidable
open AlexandrovSite PresheafCech

namespace PortcullisCore.RealWorldActions

/-! ## IndexedPoset wrappers -/

def indirectSite : IndexedPoset IndirectSecret where
  levels := IndirectInjection.indirectPoset
  allProps := IndirectInjection.allIndirectProps


def blpSite : IndexedPoset BLPLevel where
  levels := BellLaPadula.blpPoset
  allProps := BellLaPadula.allBLPProps

def bibaSite : IndexedPoset BibaLevel where
  levels := Biba.bibaPoset
  allProps := Biba.allBibaProps

/-! ## H¹ values (confirm all have obstruction) -/

#eval! s!"H¹ indirect  [1,2,3] = {reducedCechDim indirectSite [1,2,3] 1}"
#eval! s!"H¹ BLP       [1,2,3] = {reducedCechDim blpSite      [1,2,3] 1}"
#eval! s!"H¹ Biba      [1,2,3] = {reducedCechDim bibaSite     [1,2,3] 1}"

/-! ## Z/2 action: swap the two observation-level indices (1 ↔ 2)

For each poset, compute:
  rank(σ₁₂ - id) on C¹  — chain-level non-triviality
  dim H¹^σ₁₂             — cohomology-level action
-/

abbrev Cell := Nat × Nat × Nat

def cellEq (x y : Cell) : Bool :=
  x.1 == y.1 && x.2.1 == y.2.1 && x.2.2 == y.2.2

def applySwap12 : Cell → Cell
  | (i, j, p) =>
    let i' := if i == 1 then 2 else if i == 2 then 1 else i
    let j' := if j == 1 then 2 else if j == 2 then 1 else j
    if i' < j' then (i', j', p)
    else if j' < i' then (j', i', p)
    else (i', j', p)

def sigmaMinusIdMatrix {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (P : IndexedPoset Secret) : List (List Bool) :=
  let basis := reducedC1 P [1, 2, 3]
  basis.map fun b =>
    let σb := applySwap12 b
    basis.map fun x => cellEq x b != cellEq x σb

def h1DescentMatrix {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (P : IndexedPoset Secret) : List (List Bool) :=
  let b0 := reducedC0 P [1, 2, 3]
  let b1 := reducedC1 P [1, 2, 3]
  let n0 := b0.length
  let n1 := b1.length
  let d1 := reducedDelta1 P [1, 2, 3]
  let d0 := reducedDelta0 P [1, 2, 3]
  let σMinusId := sigmaMinusIdMatrix P
  let topBlock := d1.map fun row => row ++ List.replicate n0 false
  let bottomBlock := (List.range n1).map fun idx =>
    let σRow := σMinusId[idx]!
    let d0Row := d0[idx]!
    σRow ++ d0Row
  topBlock ++ bottomBlock

/-! ## Results: chain-level action -/

#eval! s!"rank(σ - id) C¹ indirect  = {gf2Rank (sigmaMinusIdMatrix indirectSite)}"
#eval! s!"rank(σ - id) C¹ BLP       = {gf2Rank (sigmaMinusIdMatrix blpSite)}"
#eval! s!"rank(σ - id) C¹ Biba      = {gf2Rank (sigmaMinusIdMatrix bibaSite)}"

/-! ## Results: H¹-level action (the real test) -/

#eval! s!"dim H¹^σ₁₂ indirect  = {(reducedC1 indirectSite [1,2,3]).length - gf2Rank (h1DescentMatrix indirectSite)}"
#eval! s!"dim H¹^σ₁₂ BLP       = {(reducedC1 blpSite [1,2,3]).length - gf2Rank (h1DescentMatrix blpSite)}"
#eval! s!"dim H¹^σ₁₂ Biba      = {(reducedC1 bibaSite [1,2,3]).length - gf2Rank (h1DescentMatrix bibaSite)}"

/-! ## Interpretation

For each poset with H¹ = k:
  dim H¹^σ = k  → Z/2 acts trivially. Observation levels are
                   interchangeable. No hidden directional structure.
  dim H¹^σ < k  → Z/2 acts non-trivially! The alignment cost has
                   hidden structure tied to WHICH observation direction
                   (read vs write, user vs admin). Real-world application
                   of the representation-theoretic framework.

The prediction: BLP and Biba should have non-trivial actions because
their observation levels encode read/write ASYMMETRY. Diamond was
trivial because its two observations were same-type (letter confusion).
-/

end PortcullisCore.RealWorldActions
