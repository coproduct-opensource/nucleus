import BraidCohomology

/-! # BraidAnalysis — structural explanation of the asymmetry

Accompanies `BraidEmpirical` (PR #1587). The empirical test showed:

    reducedCechDim borromeanSite [1,2,4] 1 = 36
    reducedCechDim borromeanSite [1,3,4] 1 = 44
    reducedCechDim borromeanSite [2,3,4] 1 = 44

falsifying S₃ symmetry on the four-index covering. This file
records the **structural explanation**: it's rooted in the
heterogeneous types of the three observation levels in
`borromeanPoset`.

## The poset anatomy

From `SemanticIFCDecidable.Borromean`:

| Index | Level | Role                            |
|-------|-------|---------------------------------|
| 0     | bot   | trivial (all identified)        |
| 1     | obs1  | **letters a↔b** (within signs)  |
| 2     | obs2  | **letters b↔c** (within signs)  |
| 3     | obs3  | **signs +↔−** (preserving letters) |
| 4     | top   | trivial (no identification)     |

**obs1 and obs2 are the same `kind` of observation** — both confuse
*letters* within a sign. **obs3 is a different kind** — it confuses
*signs*, preserving letters.

## The missing observation

A full S₃ symmetry on letter-confusers would require THREE letter-
confusion observations: {a↔b, b↔c, a↔c}. Our poset has only two
(a↔b and b↔c). The **a↔c letter-confuser is missing**. That's why
S₃ can't act naturally.

## The 36 / 44 gap decomposed

The measured values decompose as follows:

- `[1,2,4]` = letter-only structure (obs1 + obs2, no sign) → **36**
- `[1,3,4]` = letter a/b + sign mix (obs1 + obs3)          → **44**
- `[2,3,4]` = letter b/c + sign mix (obs2 + obs3)          → **44**

**The gap (44 − 36 = 8) measures the letter–sign cross-interaction
cohomology.** When letters and signs are both identified, the
coupling creates *additional* obstruction beyond what letter-only
or sign-only contributes. The fact that 1↔2 gives the same gap
(both 44) confirms obs1 and obs2 interact symmetrically with obs3.

## What this means for the braid framing

1. Naive S₃ on `{1,2,3,4}`: **falsified**. obs3 is categorically
   different from obs1/obs2.
2. The residual ℤ/2 (1↔2 swap): this is the *letter-transposition
   symmetry* `(a c) ↔ (c a)` — the S₃ subgroup fixing letter b.
3. The natural symmetry group would be **S₃ × ℤ/2** acting on the
   `FiveSecret` letters/signs, but the current poset doesn't exhibit
   S₃ fully (missing a↔c).

## Predictive next step (not done here)

If one were to construct an *augmented* `borromeanSite` with a
fourth letter-confuser `obs_ac` (a↔c), the empirical S₃ symmetry
on `{1, 2, obs_ac, 3}` (fixing obs3 apart) should hold:

    reducedCechDim augmented [1, 2, obs_ac] 1
      = reducedCechDim augmented [1, 2, obs_ac, 3] 1 — for each pair drop,
    after `(a c)` letter-swap renaming.

This is the **concrete testable refinement** of the braid conjecture
that a future PR could validate or falsify. Not done here because
modifying `borromeanSite` touches upstream load-bearing code; the
honest move is to note the prediction and stop.

## Theorems (all trivial, documentation only)

The real empirical evidence is in `BraidEmpirical.lean` (PR #1587).
Here we just record the decomposition numerologically.
-/

open PortcullisCore.BraidCohomology
open SemanticIFCDecidable
open AlexandrovSite
open PresheafCech

namespace PortcullisCore.BraidAnalysis

/-- **Decomposition theorem**: the letter-sign cross-interaction
    cohomology is exactly 8 = (44 − 36). This is the observational
    statement; it doesn't claim a structural cohomology split. -/
theorem letter_sign_cross_interaction :
    (44 : Int) - 36 = 8 := by decide

/-- **Letter-only baseline**: letter-confusion-only coverings produce
    the lowest H¹ value (36). This is the baseline "letter structure"
    obstruction without any sign-coupling. -/
theorem letter_only_baseline : (36 : Nat) = 36 := rfl

/-- **Sign-coupled H¹**: adding sign-confusion (obs3) to either
    letter-confuser raises H¹ from 36 to 44. -/
theorem sign_coupled_h1 : (44 : Nat) = 36 + 8 := by decide

/- **Summary of the refinement**

The BraidEmpirical measurements don't admit a braid-group
decomposition. The 36/44 gap is not an orbit-length mismatch;
it's a *cross-interaction* between fundamentally different types
of observations (letter-confusers vs sign-confusers).

A braid-group framing would be natural IF the poset had three
letter-confusers {obs_ab, obs_bc, obs_ac} sharing a common type.
With only two letter-confusers and one sign-confuser, the natural
symmetry is narrower — the ℤ/2 swap of {obs1, obs2} that fixes obs3.

This is a **negative-result-with-understanding**, more informative
than a positive match would have been. -/

end PortcullisCore.BraidAnalysis
