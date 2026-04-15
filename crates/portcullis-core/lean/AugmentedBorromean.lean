import SemanticIFCDecidable
import ComparisonTheorem

/-! # AugmentedBorromean — add the missing `obs_ac` letter-confuser

The `borromeanPoset` in `SemanticIFCDecidable.Borromean` has three
non-trivial observation levels:

  obs1 — letters a↔b (keep signs)
  obs2 — letters b↔c (keep signs)
  obs3 — signs  +↔− (keep letters)

The empirical test in `BraidEmpirical` (PR #1587) showed that this
set does NOT exhibit S₃ symmetry: `[1,2,4]=36 ≠ [1,3,4]=[2,3,4]=44`.

`BraidAnalysis` (PR #1588) traced the root cause: obs1 and obs2
share type (letter-confusers) but obs3 is a DIFFERENT type
(sign-confuser), AND the third letter-confuser (obs_ac = a↔c)
is **missing**.

This file constructs the missing `obs_ac` and an augmented poset
that includes all three letter-confusers plus the sign-confuser.
**Empirically tests whether adding obs_ac restores S₃ symmetry
on the three letter-confusers.**

## FiveSecret reminder

    A  = +a    AB = −a
    B  = +b    BC = −b
    C  = +c    CA = −c

Six elements forming a Cartesian product {letter} × {sign}.

## `obs_ac` definition

Identifies letters a↔c within each sign, following the obs1/obs2 pattern:

    Classes: {A, C}, {B}, {AB, CA}, {BC}

This is the direct analog of obs1 (a↔b) and obs2 (b↔c). With all
three, S₃ acts transitively on {obs1, obs2, obs_ac} via letter
permutation.

## Predictive test

If the structural hypothesis from `BraidAnalysis` is correct:

1. On the augmented poset, **dropping any one letter-confuser
   should give equal H¹** (full S₃ symmetry restored).
2. If the three H¹ values are equal → S₃ empirically restored,
   structural hypothesis confirmed.
3. If still unequal → structural hypothesis refined/refuted.

The test is run at build time via `native_decide` + `#eval`.
-/

open SemanticIFCDecidable SemanticIFCDecidable.Borromean DObsLevel FiveSecret
open AlexandrovSite PresheafCech

namespace PortcullisCore.AugmentedBorromean

/-- `obs_ac` confuses letters a↔c within each sign.
    Classes: {A, C}, {B}, {AB, CA}, {BC}. -/
def obs_ac : DObsLevel FiveSecret where
  rel s₁ s₂ := match s₁, s₂ with
    | A, A => true | A, C => true | C, A => true | C, C => true
    | B, B => true
    | AB, AB => true | AB, CA => true | CA, AB => true | CA, CA => true
    | BC, BC => true
    | _, _ => false
  refl s := by cases s <;> rfl
  symm s₁ s₂ h := by cases s₁ <;> cases s₂ <;> first | rfl | exact h
  trans s₁ s₂ s₃ h₁ h₂ := by
    cases s₁ <;> cases s₂ <;> cases s₃ <;>
      first | rfl | (exfalso; exact Bool.false_ne_true h₁)
            | (exfalso; exact Bool.false_ne_true h₂)

/-- Augmented poset: inserts `obs_ac` as the fourth letter-confuser
    level, between obs2 and obs3 in the index ordering.

    Indexing (6 non-bottom levels, 7 total including top):
      0: bot
      1: obs1    — letters a↔b
      2: obs2    — letters b↔c
      3: obs_ac  — letters a↔c (NEW)
      4: obs3    — signs +↔−
      5: top
-/
def augmentedBorromeanPoset : List (DObsLevel FiveSecret) :=
  [(bot : DObsLevel FiveSecret), obs1, obs2, obs_ac, obs3,
   (top : DObsLevel FiveSecret)]

/-- The augmented `IndexedPoset`. Matching `FiveSecret` typeclass
    assumptions from `borromeanSite`. -/
def augmentedBorromeanSite : IndexedPoset FiveSecret where
  levels := augmentedBorromeanPoset
  allProps := BorromeanCohomology.allFiveSecretProps

example : augmentedBorromeanPoset.length = 6 := by decide

/-! ## Sanity: obs_ac identifies the right pairs -/

example : obs_ac.rel A C = true := by decide
example : obs_ac.rel AB CA = true := by decide
example : obs_ac.rel A B = false := by decide
example : obs_ac.rel B C = false := by decide

/-! ## Empirical test: does S₃ symmetry hold on letter-confusers?

The three drop-one-letter-confuser coverings are:
* `[2, 3, 4, 5]` — drop obs1 (keep obs2, obs_ac, obs3, top)
* `[1, 3, 4, 5]` — drop obs2 (keep obs1, obs_ac, obs3, top)
* `[1, 2, 4, 5]` — drop obs_ac (keep obs1, obs2, obs3, top)

If S₃ on letter-confusers is a genuine symmetry of the cohomology,
all three H¹ values should be equal.

Each value is computed by `native_decide` at build time. Slow
(~30 min per value on pure-Python-equivalent elimination).
-/

#eval s!"H¹ [1,2,3,4,5] full           = {reducedCechDim augmentedBorromeanSite [1,2,3,4,5] 1}"
#eval s!"H¹ [2,3,4,5]   drop obs1      = {reducedCechDim augmentedBorromeanSite [2,3,4,5]   1}"
#eval s!"H¹ [1,3,4,5]   drop obs2      = {reducedCechDim augmentedBorromeanSite [1,3,4,5]   1}"
#eval s!"H¹ [1,2,4,5]   drop obs_ac    = {reducedCechDim augmentedBorromeanSite [1,2,4,5]   1}"
#eval s!"H¹ [1,2,3,5]   drop obs3      = {reducedCechDim augmentedBorromeanSite [1,2,3,5]   1}"

/-! ## Expected outcomes

1. **All three "drop letter-confuser" give equal H¹** → S₃ symmetry
   on letter-confusers is a genuine cohomology symmetry. Strong
   positive result — refined braid framing vindicated.
2. **Three drops still unequal** → even with obs_ac added, letter
   symmetry isn't cohomologically realized. Negative result —
   letter permutation isn't the right group, deeper issue.
3. **"Drop obs3" (sign-confuser) gives different H¹ than any
   letter-confuser drop** → expected; letter vs sign are still
   heterogeneous.

## What this file does NOT prove

- Does NOT modify `borromeanSite` (that's upstream load-bearing).
- Does NOT establish any categorical braid action — just the
  S₃ permutation symmetry as a necessary condition.
- Even if the equality holds, it's necessary-not-sufficient for a
  full braid-group action.
-/

end PortcullisCore.AugmentedBorromean
