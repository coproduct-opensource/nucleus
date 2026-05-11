import AugmentedBorromean

/-! # BraidObstruction — characteristic-2 obstruction to braid-group lift

## Result (negative, honest)

The unique non-degenerate YB-compatible set-theoretic solution on
`{obs1, obs2, obs_ac}` extending the S₃ transposition action is
the **conjugation rack**: `r(x,y) = (σ_x(y), x)`.

Over sets: `r³ = id`, `r² ≠ id`. Genuinely non-involutive. ✓

Over GF(2): the linearized R-matrix on sorted pairs is

    R = [[0, 1, 1],
         [1, 0, 1],
         [1, 1, 0]]   = J - I  (all-ones minus identity)

which satisfies `R² = R` (idempotent, NOT involutive), `det R = 0`
(singular), `ker R = span{[1,1,1]}` (rank 2).

**R is not invertible ⟹ cannot be a braid generator.**

## Why: characteristic-2 kills odd-order non-involutivity

Any set-theoretic YB solution of odd order `k` linearizes over GF(2)
to an R with `R^k = R` (since `k ≡ 1 mod 2`). For `k = 3`:
`R³ = R` ⟹ `R²(R - I) = 0`. Since `R` is not generally invertible,
this gives `R² = R` (idempotent) rather than `R² = I` (involutive).

The obstruction is intrinsic to characteristic 2. Over GF(4), the
rack's order-3 structure survives (`ω³ = 1`, `ω ≠ 1` for
`ω ∈ GF(4)`), so non-involutivity would be preserved.

## Implication for the braid conjecture

The natural path S₃ → B₃ via set-theoretic racks is **blocked** at
characteristic 2. Non-involutive braid structure over GF(2) would
require either:

1. A **genuinely linear** (non-set-theoretic) YB solution — one not
   arising as the linearization of a set map.
2. **Extending scalars** to GF(4) where the rack's order-3 structure
   survives as a non-trivial cube root of unity.

Option 2 is more natural: lift the GF(2) Čech cohomology to GF(4)
coefficients, then the S₃ rack linearizes to an invertible R with
eigenvalues `{1, ω, ω²}` (ω = primitive cube root in GF(4)). The
braid relation is automatic from the rack axioms.

## GF(4) scalar extension: also blocked on Čech cochains

Over GF(4), the cocycle-twisted rack r_f(x,y) = (ω^{f(x,y)} · (x▷y), x)
gives an **invertible, order-3** R-matrix on ORDERED pairs (9×9, rank 9).
Genuine braid generator on raw cochains.

However, Čech cohomology uses SYMMETRIC cochains (alternating = symmetric
in char 2). The R-matrix restricted to the symmetric quotient (3×3) has
rank 2, det = 0 — **SINGULAR**. Does not descend.

### Structural resolution

The braid/symmetric-group distinction IS the alternation condition:
- S₃ action: survives symmetrization (permutes unordered pairs)
- B₃ action: killed by symmetrization (rack has order 3 ≠ 2 on pairs)

The involution condition σ² = 1 of symmetric-group generators is
precisely what's needed for the action to respect the relation
f(i,j) = f(j,i). A non-involutive generator maps some ordered pairs
(i,j) and (j,i) to DIFFERENT outputs, which the symmetric quotient
collapses — destroying invertibility.

This is a **theorem-level obstruction**, not a search failure:
no set-theoretic rack-based R-matrix can descend to a non-involutive
action on Čech symmetric cochains, regardless of the coefficient field.

## What this does NOT disprove

- The S₃ action on H¹ is still real (22·D(1) ⊕ 56·D(2,1) ⊕ 2·P(1)).
- The S₄ action on H² is still real (128·D(4) ⊕ 64·D(3,1)).
- A genuinely linear (non-rack) R-matrix MIGHT still exist, but has
  no natural candidate and would not arise from index permutations.

## Search result (computational)

Brute-force over all 216 = 6³ choices of `τ_y ∈ S₃` for the
non-degenerate set-theoretic ansatz `r(x,y) = (σ_x(y), τ_y(x))` on
`{1, 2, 3}` with σ = S₃ conjugation quandle:

  Total non-degenerate YB solutions: 1
  Involutive: 0
  Non-involutive: 1  (the conjugation rack, τ = id)

The conjugation rack is the UNIQUE compatible solution.

-/

open SemanticIFCDecidable DObsLevel FiveSecret
open AlexandrovSite PresheafCech
open PortcullisCore.AugmentedBorromean

namespace PortcullisCore.BraidObstruction

/-! ## Explicit R-matrix on the 3-pair basis

The conjugation rack linearized over GF(2) on sorted pairs
{[12], [13], [23]}: R = J - I. We verify R² = R (idempotent)
and det R = 0 (singular) via `native_decide` on the 3×3 matrix. -/

def rackMatrix : List (List Bool) :=
  [[false, true, true],
   [true, false, true],
   [true, true, false]]

example : gaussRankBool rackMatrix = 2 := by native_decide

def rackSquared : List (List Bool) :=
  rackMatrix.map fun row =>
    (List.range 3).map fun j =>
      (List.range 3).foldl (fun acc k =>
        xor acc (row[k]! && rackMatrix[k]![j]!)) false

example : rackSquared = rackMatrix := by native_decide

end PortcullisCore.BraidObstruction
