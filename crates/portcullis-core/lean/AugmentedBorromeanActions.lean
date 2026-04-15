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

#eval s!"rank(σ₁₂ - id) on C¹            = {gaussRankBool (sigmaMinusIdMatrix c1Basis (applySwap swap12))}"
#eval s!"rank(σ₁₃ - id) on C¹            = {gaussRankBool (sigmaMinusIdMatrix c1Basis (applySwap swap13))}"
#eval s!"rank(σ₂₃ - id) on C¹            = {gaussRankBool (sigmaMinusIdMatrix c1Basis (applySwap swap23))}"

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
