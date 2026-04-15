import BraidCohomology

/-! # Braid conjecture — empirical tests (falsified as originally stated)

Concrete tests via `native_decide` that **falsified** the naive braid
conjecture on `borromeanSite`. Honest record of the result.

## Measured values

    reducedCechDim borromeanSite [1,2,3]   1 = 90
    reducedCechDim borromeanSite [1,2,3,4] 1 = 90
    reducedCechDim borromeanSite [1,2,4]   1 = 36
    reducedCechDim borromeanSite [1,3,4]   1 = 44
    reducedCechDim borromeanSite [2,3,4]   1 = 44

## Two findings

**Finding 1: Index 4 is cohomologically silent.** `[1,2,3]` and
`[1,2,3,4]` both give 90. So the "full" covering is really 3-ring,
and index 4 sits orthogonally (maybe an apex / bottom of a sub-lattice
with no independent H¹ contribution).

**Finding 2: S₃ symmetry on {1,2,3,4} is FALSIFIED.** `[1,2,4] = 36`
but `[1,3,4] = [2,3,4] = 44`. Indices 1 and 2 are swappable; index
3 is distinguished. No 3-fold permutation symmetry.

## What this says about the braid conjecture

- **Naive "S₃ acts freely on {1,2,3,4}"**: falsified.
- **Residual ℤ/2 symmetry on {1,2}**: survives. That's a *strand-
  transposition* symmetry — consistent with B₃'s σ₁ generator acting
  at rank 2.
- **Distinguished role of index 3**: suggests 3 is the "basepoint"
  or "target" of the cochain structure, not symmetric with 1,2.

The residual ℤ/2 symmetry is weaker than full braid but not nothing.
A more careful braid framing would need to:
1. Identify which index pair *actually* has swap symmetry (done: {1,2})
2. Check whether that transposition generates a ℤ/2 action on the
   cochain complex (not tested here)
3. Test the higher-rank symmetries (σ₁σ₂σ₁ = σ₂σ₁σ₂) only if (2)
   passes

## This file records the falsification

Rather than hide the negative result, we state it: the naive braid
framing doesn't hold. The residual structure below is concrete and
testable.
-/

open PortcullisCore.BraidCohomology
open SemanticIFCDecidable
open AlexandrovSite
open PresheafCech
open BridgeTheorem

namespace PortcullisCore.BraidEmpirical

/-- Empirical: `reducedCechDim borromeanSite [1,2,3] 1 = 90` — the
    full three-ring subset already carries all the H¹ structure. -/
theorem h1_three_rings : reducedCechDim borromeanSite [1, 2, 3] 1 = 90 := by
  native_decide

/-- Empirical: `reducedCechDim borromeanSite [1,2,3,4] 1 = 90` — same
    as the three-ring subset. Index 4 contributes nothing to H¹. -/
theorem h1_full_equals_three_rings :
    reducedCechDim borromeanSite [1, 2, 3, 4] 1 =
      reducedCechDim borromeanSite [1, 2, 3] 1 := by
  native_decide

/-- Empirical: `reducedCechDim borromeanSite [1,2,4] 1 = 36`. Drop ring 3. -/
theorem h1_drop_3 : reducedCechDim borromeanSite [1, 2, 4] 1 = 36 := by
  native_decide

/-- Empirical: `reducedCechDim borromeanSite [1,3,4] 1 = 44`. Drop ring 2. -/
theorem h1_drop_2 : reducedCechDim borromeanSite [1, 3, 4] 1 = 44 := by
  native_decide

/-- Empirical: `reducedCechDim borromeanSite [2,3,4] 1 = 44`. Drop ring 1. -/
theorem h1_drop_1 : reducedCechDim borromeanSite [2, 3, 4] 1 = 44 := by
  native_decide

/-- **Residual ℤ/2 symmetry** (the ONE thing that survives): indices
    1 and 2 are swappable in the 3-element drop-one coverings. -/
theorem z2_swap_1_and_2 :
    reducedCechDim borromeanSite [1, 3, 4] 1 =
    reducedCechDim borromeanSite [2, 3, 4] 1 := by
  rw [h1_drop_2, h1_drop_1]

/-- **S₃ symmetry FALSIFIED**: `[1,2,4] ≠ [1,3,4]`. The 36 vs 44 gap
    rules out any 3-fold permutation symmetry of the ring indices. -/
theorem s3_symmetry_falsified :
    reducedCechDim borromeanSite [1, 2, 4] 1 ≠
    reducedCechDim borromeanSite [1, 3, 4] 1 := by
  rw [h1_drop_3, h1_drop_2]
  decide

/-- **Brunnian-drop gap**: dropping any one ring reduces H¹ from 90
    to {36, 44, 44}. This IS a dramatic reduction (~50-60%),
    consistent with a Brunnian-style decoupling. The *different* drop
    values show the rings aren't fully symmetric, but dropping does
    strongly reduce the obstruction count. -/
theorem brunnian_drop_reduces_h1 :
    reducedCechDim borromeanSite [1, 2, 4] 1 < 90 ∧
    reducedCechDim borromeanSite [1, 3, 4] 1 < 90 ∧
    reducedCechDim borromeanSite [2, 3, 4] 1 < 90 := by
  refine ⟨?_, ?_, ?_⟩
  · rw [h1_drop_3]; decide
  · rw [h1_drop_2]; decide
  · rw [h1_drop_1]; decide

/-- **Index 4 cohomological silence**: as a standalone theorem. -/
theorem index_4_adds_nothing :
    reducedCechDim borromeanSite [1, 2, 3, 4] 1 =
    reducedCechDim borromeanSite [1, 2, 3] 1 :=
  h1_full_equals_three_rings

/- **Honest summary**

This file's role: record that the most natural braid-group
conjecture (naive S₃ on {1,2,3,4}) is EMPIRICALLY FALSIFIED, and
that the residual structure is narrower: a single ℤ/2 swap
between indices 1 and 2.

That narrower finding is still interesting but it's not a braid
group action. A more refined hypothesis — the 1-2 swap generates
a genuine cochain-complex automorphism, lifting to a ℤ/2 action
on H¹ — would need further testing. Not done here.

**The correct next move is not more Lean scaffolding. It's one of:**
1. Investigate what specifically distinguishes index 3 from indices
   1 and 2 in `borromeanSite`'s level structure.
2. Abandon the braid framing and look for a different symmetry group
   that the residual ℤ/2 is a subgroup of.
3. Accept that the 90 and 64 values are combinatorial artifacts of
   the IFC poset construction, with no deep symmetry behind them.
-/

#eval s!"h1_full       = {reducedCechDim borromeanSite [1, 2, 3, 4] 1}"
#eval s!"h1_three_rings= {reducedCechDim borromeanSite [1, 2, 3] 1}"
#eval s!"h1_drop_3     = {reducedCechDim borromeanSite [1, 2, 4] 1}"
#eval s!"h1_drop_2     = {reducedCechDim borromeanSite [1, 3, 4] 1}"
#eval s!"h1_drop_1     = {reducedCechDim borromeanSite [2, 3, 4] 1}"

end PortcullisCore.BraidEmpirical
