import GkatPeriodProofs

/-!
# The exit law: a `while` has one exit condition

The period law (`GkatPeriod`) is the group-theoretic half of what a cover preserves, and it
has a ceiling: it bounds how *big* a cover must be and can never forbid one, because
`cyclicCover` multiplies the period by any `k`.  Any genuine impossibility must live where
`π₁` cannot see — in the **halt labelling**.

This file proves the labelling law, and it is derived from GKAT's own loop construction
rather than imported.  `loopInitialized g B` sets

    core.hlt s = B.core.hlt s ∧ ¬g          initHlt = ¬g

so every state inside the loop halts only where the *entry* halts.  A `while` has exactly one
exit condition, tested at the entry — which is precisely what GKAT lacks a `break` for, and
the reason GKAT-expressible is strictly narrower than the classical "reducible flow graph"
notion, which permits multi-exit loops.

Since a cover preserves halting pointwise, the law transfers: anything covered by a loop
inherits it, and a single state that halts where the entry does not refutes every loop cover
outright — no map need be exhibited or refuted.

## Where this meets the measurements

The separator the search found, against the proper control group, was halting *inside cycles*
(`haltcyc`: 0.53 covered, 1.00 rescued, 1.33 uncovered).  That is this law seen from outside:
a halt inside a cyclic region has to sit below the region's entry halt, or the region cannot
be a single `while` and the automaton must pay for extra structure around it.

## What the law does not settle

It refutes a *loop* cover.  It says nothing about covers by `seq` or `ite` composites, and
the property is genuinely loop-specific — `seq_halt_not_below_entry` exhibits a Thompson
automaton whose core state halts where its entry does not.  So this is an obstruction for one
constructor, not yet a characterisation.
-/

namespace GkatLoopExit

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatQuotient GkatPeriod

variable {A T : Type}
variable {S R Q : Type} {src : InitializedGAut S A T} {tgt : InitializedGAut Q A T}

/-! ## Covers preserve halting -/

/-- A cover preserves halting at every state, pseudostate included — `initHlt_eq` and
    `coreHlt_eq` read one level up, where the state type is `Option S`. -/
theorem cover_halt (φ : InitCover src tgt) (u : Option S) {X : Type}
    (W : T → X → Bool) (x : X) :
    bval W (src.toGAut.hlt u) x = bval W (tgt.toGAut.hlt (u.map φ.map)) x := by
  cases u with
  | none => exact φ.initHlt_eq X W x
  | some s => exact φ.coreHlt_eq s X W x

/-! ## The exit law -/

/-- **A `while` has one exit condition.**  Every state inside `loopInitialized g B` halts
    only where the entry halts, because the construction conjoins `¬g` onto every body
    state's halt guard and takes `¬g` itself as the entry's. -/
theorem loop_halt_below_entry (g : BExp T) (B : InitializedGAut R A T) (s : R)
    {X : Type} (W : T → X → Bool) (x : X)
    (h : bval W ((loopInitialized g B).core.hlt s) x = true) :
    bval W (loopInitialized g B).initHlt x = true := by
  have hand : (bval W (B.core.hlt s) x && bval W (BExp.not g) x) = true := h
  exact (Bool.and_eq_true _ _).mp hand |>.2

/-- **The law transfers along covers.**  Anything covered by a `while` inherits the single
    exit condition: a core state may halt only where the pseudostate does. -/
theorem halt_below_entry_of_cover {g : BExp T} {B : InitializedGAut R A T}
    (φ : InitCover src (loopInitialized g B)) (s : S)
    {X : Type} (W : T → X → Bool) (x : X)
    (h : bval W (src.core.hlt s) x = true) :
    bval W src.initHlt x = true := by
  rw [φ.initHlt_eq X W x]
  refine loop_halt_below_entry g B (φ.map s) W x ?_
  rw [← φ.coreHlt_eq s X W x]
  exact h

/-- **The obstruction.**  One state halting where the entry does not refutes every loop
    cover — established without exhibiting or refuting any map, exactly as
    `no_cover_of_period` does on the group side. -/
theorem no_loop_cover {g : BExp T} {B : InitializedGAut R A T} (s : S)
    {X : Type} (W : T → X → Bool) (x : X)
    (hs : bval W (src.core.hlt s) x = true)
    (hi : bval W src.initHlt x = false) :
    ¬ Nonempty (InitCover src (loopInitialized g B)) := by
  rintro ⟨φ⟩
  rw [halt_below_entry_of_cover φ s W x hs] at hi
  exact absurd hi (by simp)

/-! ## The law is loop-specific

    Worth pinning down, because it would be easy to mistake for a property of Thompson
    automata in general.  It is not: sequential composition breaks it. -/

/-- `a ; 1` — its core state halts everywhere, its pseudostate nowhere. -/
private abbrev seqWitness : Exp Unit Unit := .seq (.act ()) (.test .one)

/-- **Sequential composition does not satisfy the exit law.**  So `no_loop_cover` really is
    an obstruction for the `wh` constructor alone, not a characterisation of coverability. -/
theorem seq_halt_not_below_entry :
    bval (fun _ (_ : Unit) => true)
        ((certifiedThompson Unit Unit seqWitness).aut.core.hlt (Sum.inl ())) () = true ∧
    bval (fun _ (_ : Unit) => true)
        ((certifiedThompson Unit Unit seqWitness).aut.initHlt) () = false :=
  ⟨rfl, rfl⟩

#print axioms cover_halt
#print axioms loop_halt_below_entry
#print axioms halt_below_entry_of_cover
#print axioms no_loop_cover
#print axioms seq_halt_not_below_entry

end GkatLoopExit
