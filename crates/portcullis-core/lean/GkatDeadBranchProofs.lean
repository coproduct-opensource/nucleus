import GkatDecidedPullbackProofs

/-!
# Dead-branch elimination in the completeness endgame, unconditionally

This is the composition check for `GkatNullLanguage.nullLanguage_complete`: the theorem
is only worth having if it removes the circular step it was built for.

The endgame (`certifiedThompson_uniform_solved_quotient`) compares the Thompson automata
of two uniformly language-equivalent programs cell by cell.  `uniform_cell_classification`
splits each satisfiable cell three ways; the awkward case is a cell where one automaton
steps and the other does not.  `unmatched_step_target_uniformly_dead` already showed that
the step's target is *uniformly dead* — but turning that into a rewrite needed
`dead_thompson_label_eq_zero_of_complete`, which assumes `FiniteAxiomsCompleteBA`, i.e.
the theorem under construction.

`unmatched_branch_label_eq_zero` below closes that loop with no hypothesis at all.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatDeadBranch

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson
open GkatNullLanguage

variable {S A T : Type}

/-! ## Materialized Thompson automata are target-closed -/

theorem toGAut_targetsListed (aut : InitializedGAut S A T)
    (hcore : CoreTargetsListed aut) (hinit : InitTargetsListed aut) :
    GAutTargetsListed aut.toGAut := by
  intro state hstate transition htransition
  cases state with
  | none =>
      simp only [InitializedGAut.toGAut, List.mem_map] at htransition
      obtain ⟨original, horiginal, rfl⟩ := htransition
      exact List.Mem.tail _ (List.mem_map_of_mem (hinit original horiginal))
  | some inner =>
      have hinner : inner ∈ aut.core.states := by
        simp only [InitializedGAut.toGAut, List.mem_cons, List.mem_map] at hstate
        rcases hstate with hcontra | ⟨found, hfound, heq⟩
        · exact absurd hcontra (by simp)
        · cases heq
          exact hfound
      simp only [InitializedGAut.toGAut, List.mem_map] at htransition
      obtain ⟨original, horiginal, rfl⟩ := htransition
      exact List.Mem.tail _
        (List.mem_map_of_mem (hcore inner hinner original horiginal))

theorem certifiedThompson_targetsListed (program : Exp A T) :
    GAutTargetsListed (certifiedThompson A T program).aut.toGAut :=
  toGAut_targetsListed (certifiedThompson A T program).aut
    (certifiedThompson A T program).structural.targets
    (certifiedThompson A T program).certificate.initTargets

/-- Every step lands in a listed state. -/
theorem autStep_target_listed {aut : GAut S A T}
    (htargets : GAutTargetsListed aut) {X : Type} (W : T → X → Bool) (x : X)
    {state : S} (hstate : state ∈ aut.states) {action : A} {target : S}
    (hstep : autStep W aut state x = some (action, target)) :
    target ∈ aut.states :=
  firstMatch_target_listed W x (aut.trans state) aut.states
    (fun transition htransition => htargets state hstate transition htransition)
    hstep

/-! ## The elimination -/

/-- **Dead-branch elimination, with no completeness hypothesis.**  When the two Thompson
    automata of uniformly language-equivalent states disagree at a cell — the left steps,
    the right cannot match — the left step's target carries the canonical label `0`,
    provably, in the finite theory.

    Compare `dead_thompson_label_eq_zero_of_complete`, whose `hcomplete` premise made the
    same rewrite circular. -/
theorem unmatched_branch_label_eq_zero
    {leftProgram rightProgram : Exp A T}
    {s₁ : Option (certifiedThompson A T leftProgram).State}
    {s₂ : Option (certifiedThompson A T rightProgram).State}
    (hrel : UniformAutLangEq
      (certifiedThompson A T leftProgram).aut.toGAut
      (certifiedThompson A T rightProgram).aut.toGAut s₁ s₂)
    (hs₁ : s₁ ∈ (certifiedThompson A T leftProgram).aut.toGAut.states)
    {X : Type} (W : T → X → Bool) (x : X)
    {action : A} {target : Option (certifiedThompson A T leftProgram).State}
    (hstep : autStep W (certifiedThompson A T leftProgram).aut.toGAut s₁ x
      = some (action, target))
    (hnomatch : ¬ ∃ target₂,
      autStep W (certifiedThompson A T rightProgram).aut.toGAut s₂ x
        = some (action, target₂)) :
    EquivBA (initializedStandard leftProgram
      (certifiedThompson A T leftProgram).standard target) (.test .zero) :=
  dead_thompson_label_eq_zero leftProgram target
    (autStep_target_listed (certifiedThompson_targetsListed leftProgram) W x hs₁ hstep)
    (unmatched_step_target_uniformly_dead
      (certifiedThompson A T leftProgram).aut.toGAut
      (certifiedThompson A T rightProgram).aut.toGAut hrel W x hstep hnomatch)

/-- The start-state instance, driven directly by uniform language equivalence of the two
    source programs.  This is the shape the quotient construction consumes. -/
theorem unmatched_start_branch_label_eq_zero
    {leftProgram rightProgram : Exp A T}
    (heq : UniformLanguageEquivalent leftProgram rightProgram)
    {X : Type} (W : T → X → Bool) (x : X)
    {action : A} {target : Option (certifiedThompson A T leftProgram).State}
    (hstep : autStep W (certifiedThompson A T leftProgram).aut.toGAut none x
      = some (action, target))
    (hnomatch : ¬ ∃ target₂,
      autStep W (certifiedThompson A T rightProgram).aut.toGAut none x
        = some (action, target₂)) :
    EquivBA (initializedStandard leftProgram
      (certifiedThompson A T leftProgram).standard target) (.test .zero) :=
  unmatched_branch_label_eq_zero
    (certifiedThompson_starts_uniform_langEq heq) (List.Mem.head _) W x hstep hnomatch

/-- Symmetric form: the same holds with the roles of the two programs exchanged. -/
theorem unmatched_start_branch_label_eq_zero_symm
    {leftProgram rightProgram : Exp A T}
    (heq : UniformLanguageEquivalent leftProgram rightProgram)
    {X : Type} (W : T → X → Bool) (x : X)
    {action : A} {target : Option (certifiedThompson A T rightProgram).State}
    (hstep : autStep W (certifiedThompson A T rightProgram).aut.toGAut none x
      = some (action, target))
    (hnomatch : ¬ ∃ target₁,
      autStep W (certifiedThompson A T leftProgram).aut.toGAut none x
        = some (action, target₁)) :
    EquivBA (initializedStandard rightProgram
      (certifiedThompson A T rightProgram).standard target) (.test .zero) := by
  refine unmatched_branch_label_eq_zero
    (certifiedThompson_starts_uniform_langEq (leftProgram := rightProgram)
      (rightProgram := leftProgram) ?_) (List.Mem.head _) W x hstep hnomatch
  intro Y W' gs
  exact (heq Y W' gs).symm

/-- The dead-branch obligation of the whole endgame, stated once: *every* uniformly dead
    listed state of a certified Thompson automaton is `0`-labelled.  No premise. -/
theorem every_dead_state_eq_zero (program : Exp A T)
    (state : Option (certifiedThompson A T program).State)
    (hstate : state ∈ (certifiedThompson A T program).aut.toGAut.states)
    (hdead : UniformAutLempty (certifiedThompson A T program).aut.toGAut state) :
    EquivBA (initializedStandard program
      (certifiedThompson A T program).standard state) (.test .zero) :=
  dead_thompson_label_eq_zero program state hstate hdead

#print axioms certifiedThompson_targetsListed
#print axioms unmatched_branch_label_eq_zero
#print axioms unmatched_start_branch_label_eq_zero
#print axioms unmatched_start_branch_label_eq_zero_symm
#print axioms every_dead_state_eq_zero

end GkatDeadBranch
