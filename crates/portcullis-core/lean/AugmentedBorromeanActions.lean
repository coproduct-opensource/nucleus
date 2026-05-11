import AugmentedBorromean

/-! # AugmentedBorromeanActions — explicit S₃ permutation matrices on C¹/C²

The refined braid-framework memory (`project_braid_rmatrix_test.md`)
names this as the prerequisite test for any R-matrix work: before
constructing a non-involutive R, first confirm that the S₃ action
induced by permuting covering indices is a *genuine* action on the
chain complex, not a trivial one.

## What this file computes

For each S₃ transposition σ ∈ {(1 2), (1 3), (2 3)} on the three
letter-confuser indices {1, 2, 3} of `augmentedBorromeanSite`:

1. Build the matrix of `σ - id` on `reducedC1 [1,2,3,4,5]` as a
   GF(2) matrix.
2. Compute `rank(σ - id)` via `gaussRankBool`.
3. Derive `dim (C¹)^σ = |C¹| - rank(σ - id)` — the fixed subspace.

Concrete discriminator:
- `rank(σ - id) = 0` on C¹ → σ acts as identity on C¹, symmetry
  is trivial, H^n invariance is vacuous.
- `rank(σ - id) > 0` → σ is a genuine non-trivial action on C¹.
  Next step: descend to H¹ and compute rank of induced map.

Over GF(2) with σ² = 1: `(σ - id)² = 0`, so `σ - id` is nilpotent
and `rank = |C¹| - dim(fixed subspace) = (# non-trivial orbits)`.

## Status

Prerequisite gate for the R-matrix future test. If even the chain-
level permutation action is trivial (rank = 0), all higher braid
structure is impossible and the R-matrix target is moot.
-/

open SemanticIFCDecidable DObsLevel FiveSecret
open AlexandrovSite PresheafCech
open PortcullisCore.AugmentedBorromean

namespace PortcullisCore.AugmentedBorromeanActions

/-- A 1-cochain basis cell: triple `(i, j, p)` with `i < j`. -/
abbrev Cell := Nat × Nat × Nat

/-- Boolean equality on `Cell`. -/
def cellEq (x y : Cell) : Bool :=
  x.1 == y.1 && x.2.1 == y.2.1 && x.2.2 == y.2.2

/-- Apply a swap `f` to the first two indices of a cell and re-sort
    so the smaller index comes first (Čech cells use `i < j`). -/
def applySwap (f : Nat → Nat) : Cell → Cell
  | (i, j, p) =>
    let i' := f i
    let j' := f j
    if i' < j' then (i', j', p)
    else if j' < i' then (j', i', p)
    else (i', j', p)  -- degenerate; shouldn't occur on our basis

/-- Transposition `(1 2)` on letter-confuser indices. -/
def swap12 : Nat → Nat
  | 1 => 2
  | 2 => 1
  | n => n

/-- Transposition `(1 3)` on letter-confuser indices. -/
def swap13 : Nat → Nat
  | 1 => 3
  | 3 => 1
  | n => n

/-- Transposition `(2 3)` on letter-confuser indices. -/
def swap23 : Nat → Nat
  | 2 => 3
  | 3 => 2
  | n => n

/-- Build the `(σ - id)` matrix on C¹: row `b` has 1s at basis
    positions `b` and `σ(b)` (XOR), zero if `σ(b) = b`. -/
def sigmaMinusIdMatrix (basis : List Cell) (σ : Cell → Cell) :
    List (List Bool) :=
  basis.map fun b =>
    let σb := σ b
    basis.map fun x => cellEq x b != cellEq x σb

/-- The augmented C¹ basis on the full covering `[1,2,3,4,5]`. -/
def c1Basis : List Cell :=
  reducedC1 augmentedBorromeanSite [1, 2, 3, 4, 5]

/-! ## Rank computations

These are `#eval`-emitted at build time via `native_decide`-style
reduction in the elaborator.
-/

#eval s!"|C¹| augmented [1,2,3,4,5]      = {c1Basis.length}"

#eval s!"rank(σ₁₂ - id) on C¹            = {gf2Rank (sigmaMinusIdMatrix c1Basis (applySwap swap12))}"
#eval s!"rank(σ₁₃ - id) on C¹            = {gf2Rank (sigmaMinusIdMatrix c1Basis (applySwap swap13))}"
#eval s!"rank(σ₂₃ - id) on C¹            = {gf2Rank (sigmaMinusIdMatrix c1Basis (applySwap swap23))}"

/-! ## H¹-descent: rank of induced σ_* on H¹

Given chain involution σ on C¹ commuting with δ⁰, δ¹, the induced
map σ_* on H¹ = ker δ¹ / im δ⁰ has fixed subspace

    dim H¹^σ = |C¹| - rank(M)

where `M` is the block matrix

      ⎡ D₁      0  ⎤  — (|C²| rows)
      ⎣ σ̃      D₀ ⎦  — (|C¹| rows)

acting on `C¹ ⊕ C⁰` with `σ̃ = σ - id`. (Derivation: the kernel of
`M` is `{(c, v) : D₁ c = 0 ∧ σ̃ c = D₀ v}`; projecting to the
c-coordinate gives `{c ∈ Z¹ : σ̃ c ∈ B¹}`, whose quotient by `B¹`
is `H¹^σ`. Counting dimensions gives the formula.)

From this: `rank σ_* = dim H¹ - dim H¹^σ = 138 - (640 - rank M)`.
-/

/-- Build the block matrix described above. -/
def h1DescentMatrix (σ : Cell → Cell) : List (List Bool) :=
  let b0 := reducedC0 augmentedBorromeanSite [1, 2, 3, 4, 5]
  let b1 := c1Basis
  let n0 := b0.length
  let n1 := b1.length
  let d1 := reducedDelta1 augmentedBorromeanSite [1, 2, 3, 4, 5]
  let d0 := reducedDelta0 augmentedBorromeanSite [1, 2, 3, 4, 5]
  let σMinusId := sigmaMinusIdMatrix b1 σ
  -- Top block: d1 rows padded with n0 zeros on the right
  let topBlock := d1.map fun row => row ++ List.replicate n0 false
  -- Bottom block: [σ̃ | d0], where d0 row b has n0 entries
  let bottomBlock := (List.range n1).map fun idx =>
    let σRow := σMinusId[idx]!
    let d0Row := d0[idx]!
    σRow ++ d0Row
  topBlock ++ bottomBlock

#eval s!"|C⁰| augmented [1,2,3,4,5]      = {(reducedC0 augmentedBorromeanSite [1,2,3,4,5]).length}"
#eval s!"|C²| augmented [1,2,3,4,5]      = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length}"

#eval s!"dim H¹^σ₁₂ = 640 - rank(M) = {640 - gf2Rank (h1DescentMatrix (applySwap swap12))}"
#eval s!"dim H¹^σ₁₃ = 640 - rank(M) = {640 - gf2Rank (h1DescentMatrix (applySwap swap13))}"
#eval s!"dim H¹^σ₂₃ = 640 - rank(M) = {640 - gf2Rank (h1DescentMatrix (applySwap swap23))}"

/-! ## H²-descent: rank of induced σ_* on H² for all 6 S₄ transpositions

With δ² absent in the current framework (`reducedCechDim` treats
C³ = 0), we have `H² = C² / B²` where `B² = im δ¹`. The fixed
subspace under σ acting on C² is

    dim H²^σ = |C²| - rank(M'')

with `M'' = [σ̃_{C²} | D₁]` acting on `C² ⊕ C¹ → C²`. Derivation
mirrors H¹: kernel `{(w, c) : σ̃(w) = D₁ c}` projects to `{w ∈ C² :
σ̃(w) ∈ B²}`; quotient by `B²` is `H²^σ`.

Testing all 6 S₄ transpositions discriminates the symmetry type:
- All 6 equal → full S₄ acts on H²
- Split 3 letter-letter vs 3 letter-sign → only S₃ × Z/2
-/

/-- C² basis cell: `(i, j, k, p)` with `i < j < k`. -/
abbrev Cell2 := Nat × Nat × Nat × Nat

/-- Boolean equality on `Cell2`. -/
def cellEq2 (x y : Cell2) : Bool :=
  x.1 == y.1 && x.2.1 == y.2.1 && x.2.2.1 == y.2.2.1 && x.2.2.2 == y.2.2.2

/-- Sort three Nats ascending. -/
def sort3 (a b c : Nat) : Nat × Nat × Nat :=
  let (a', b') := if a ≤ b then (a, b) else (b, a)
  if c ≤ a' then (c, a', b')
  else if c ≤ b' then (a', c, b')
  else (a', b', c)

/-- Apply a swap to a C² cell, re-sorting the index triple. -/
def applySwap2 (f : Nat → Nat) : Cell2 → Cell2
  | (i, j, k, p) =>
    let (a, b, c) := sort3 (f i) (f j) (f k)
    (a, b, c, p)

def c2Basis : List Cell2 :=
  reducedC2 augmentedBorromeanSite [1, 2, 3, 4, 5]

/-- `(σ - id)` matrix on C². Symmetric (σ² = id). -/
def sigmaMinusIdMatrix2 (σ : Cell2 → Cell2) : List (List Bool) :=
  c2Basis.map fun b =>
    let σb := σ b
    c2Basis.map fun x => cellEq2 x b != cellEq2 x σb

/-- Additional S₄ transpositions involving index 4 (sign-confuser). -/
def swap14 : Nat → Nat
  | 1 => 4
  | 4 => 1
  | n => n

def swap24 : Nat → Nat
  | 2 => 4
  | 4 => 2
  | n => n

def swap34 : Nat → Nat
  | 3 => 4
  | 4 => 3
  | n => n

/-- Build the H²-descent block matrix `[σ̃ | D₁]`. -/
def h2DescentMatrix (σ : Cell2 → Cell2) : List (List Bool) :=
  let n2 := c2Basis.length
  let d1 := reducedDelta1 augmentedBorromeanSite [1, 2, 3, 4, 5]
  let σMinusId := sigmaMinusIdMatrix2 σ
  (List.range n2).map fun idx =>
    let σRow := σMinusId[idx]!
    let d1Row := d1[idx]!
    σRow ++ d1Row

#eval s!"dim H²^σ₁₂ (letter-letter) = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 swap12))}"
#eval s!"dim H²^σ₁₃ (letter-letter) = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 swap13))}"
#eval s!"dim H²^σ₂₃ (letter-letter) = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 swap23))}"
#eval s!"dim H²^σ₁₄ (letter-sign)   = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 swap14))}"
#eval s!"dim H²^σ₂₄ (letter-sign)   = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 swap24))}"
#eval s!"dim H²^σ₃₄ (letter-sign)   = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 swap34))}"

/-! ## Falsification tests: non-transposition fixed subspaces

The decompositions
- H¹ ≅ 22·trivial ⊕ 58·standard  (S₃ over GF(2))
- H² ≅ 128·trivial ⊕ 64·D^(3,1)  (S₄ over GF(2))
predict specific fixed-dim values for other conjugacy classes.

**3-cycle (1 2 3)**: the standard 2-dim irrep has no 1-eigenvalue
(char poly x²+x+1 irreducible over GF(2)), so 3-cycles fix only
the trivial summand.
- dim H¹^{(123)} predicted = 22
- dim H²^{(123)} predicted = 128

**Double transposition (1 2)(3 4)** in S₄: lies in the Klein-4
normal subgroup V ⊲ S₄, which is the kernel of S₄ → S₃. Since
D^(3,1) factors through this quotient, V acts trivially on it.
- dim H²^{(12)(34)} predicted = 256 (all of H²)

Any miss falsifies the corresponding decomposition.
-/

def cycle123 : Nat → Nat
  | 1 => 2
  | 2 => 3
  | 3 => 1
  | n => n

def dtrans1234 : Nat → Nat
  | 1 => 2
  | 2 => 1
  | 3 => 4
  | 4 => 3
  | n => n

#eval s!"dim H¹^(123) predicted 22       = {640 - gf2Rank (h1DescentMatrix (applySwap cycle123))}"
#eval s!"dim H²^(123) predicted 128      = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 cycle123))}"
#eval s!"dim H²^(12)(34) predicted 256   = {(reducedC2 augmentedBorromeanSite [1,2,3,4,5]).length - gf2Rank (h2DescentMatrix (applySwap2 dtrans1234))}"

/-! ## Interpretation

For each σ = (i j):
- `rank(σ - id) = 2k` where `k` is the number of non-trivial swap pairs
  in the basis.
- `dim (C¹)^σ = |C¹| - k` (wait — over GF(2) with row having two 1s,
  rank = k, so dim fixed = |C¹| - k = f + k where f = fixed points,
  k = swap-pair count). Actually for a permutation with `f` fixed
  basis elements and `k` swap pairs: `|C¹| = f + 2k`,
  `rank(σ - id) = k`, `dim fixed subspace = f + k = |C¹| - k`.

Three numerical sanity checks the S₃ structure must satisfy:
1. All three ranks equal (by S₃ symmetry of the augmented poset).
2. Non-zero (otherwise trivial action).
3. Equal to the number of (i,j,p) triples involving exactly one of
   the swapped indices (hand-checkable).

If (1) passes at rank > 0, the permutation action is a genuine
S₃ action on C¹ and the next test (H¹-descent) becomes meaningful.
-/

end PortcullisCore.AugmentedBorromeanActions
