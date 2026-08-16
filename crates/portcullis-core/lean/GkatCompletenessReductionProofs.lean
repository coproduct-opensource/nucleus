import GkatDecidedUAProofs

/-!
# What full completeness is exactly equivalent to

The remaining gap in GKAT completeness is usually described as "UA is needed": uniqueness
of solutions for equation systems of *arbitrary* finite automata.  That description is
too generous to UA.  This file proves that completeness is equivalent to a strictly
smaller statement — one that never mentions an arbitrary system at all:

    ThompsonInternalCompleteBA
      : two listed states of the Thompson automaton **of a single program**, if they have
        the same guarded language, have provably equal canonical labels.

`completeness_iff_thompson_internal` shows this is not merely sufficient but *equivalent*
to `FiniteAxiomsCompleteBA`.  So the entire content of the open problem is a statement
about syntax-generated automata.  Uniqueness for automata that are not syntax-generated —
behavioural quotients, products, minimizations — is never actually required; it appears
only as an artefact of how the standard completeness proofs are organised.

That is the precise form of the structural criterion: **global uniqueness was never
fundamental.  What is left is control-flow provenance — telling apart two positions
*inside one program's own automaton* that happen to behave alike.**

The reverse direction needs one action symbol to exist, which is what lets two programs be
placed as *internal states* of a single third program: `1 ? (a·e) : (a·f)`.  Without any
action, GKAT expressions denote tests and completeness is Boolean-algebra completeness.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatCompletenessReduction

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson
open GkatGuardedAlgebra GkatAtomTransfer GkatNullLanguage

variable {A T : Type}

/-- Language-equivalent listed states of one certified Thompson automaton have provably
    equal canonical labels. -/
def ThompsonInternalCompleteBA (A T : Type) : Prop :=
  ∀ (program : Exp A T)
    (s t : Option (certifiedThompson A T program).State),
    s ∈ (certifiedThompson A T program).aut.toGAut.states →
    t ∈ (certifiedThompson A T program).aut.toGAut.states →
    UniformAutLangEq (certifiedThompson A T program).aut.toGAut
      (certifiedThompson A T program).aut.toGAut s t →
    EquivBA (initializedStandard program
        (certifiedThompson A T program).standard s)
      (initializedStandard program
        (certifiedThompson A T program).standard t)

/-! ## Completeness implies the internal form -/

theorem thompson_internal_of_complete
    (hcomplete : FiniteAxiomsCompleteBA A T) :
    ThompsonInternalCompleteBA A T := by
  intro program s t hs ht hlang
  refine hcomplete _ _ ?_
  intro X W gs
  rw [← certifiedThompson_state_language program s hs X W,
    ← certifiedThompson_state_language program t ht X W]
  exact hlang X W gs

/-! ## The internal form implies completeness

    The construction: given `e` and `f`, place both inside one program as the states
    reached after a common leading action.  Their canonical labels there are `1·e` and
    `1·f`, so internal completeness returns exactly the equation wanted. -/

/-- The witness program: both `e` and `f` occur as internal states of this one program. -/
private def probe (a : A) (e f : Exp A T) : Exp A T :=
  .ite .one (.seq (.act a) e) (.seq (.act a) f)

private theorem probe_left_listed (a : A) (e f : Exp A T) :
    (some (Sum.inl (Sum.inl ())) :
      Option (certifiedThompson A T (probe a e f)).State) ∈
      (certifiedThompson A T (probe a e f)).aut.toGAut.states :=
  List.Mem.tail _ (List.mem_map_of_mem
    (List.mem_append_left _ (List.mem_map_of_mem (List.Mem.head _))))

private theorem probe_right_listed (a : A) (e f : Exp A T) :
    (some (Sum.inr (Sum.inl ())) :
      Option (certifiedThompson A T (probe a e f)).State) ∈
      (certifiedThompson A T (probe a e f)).aut.toGAut.states :=
  List.Mem.tail _ (List.mem_map_of_mem
    (List.mem_append_right _ (List.mem_map_of_mem (List.Mem.head _))))

private theorem probe_left_label (a : A) (e f : Exp A T) :
    initializedStandard (probe a e f)
        (certifiedThompson A T (probe a e f)).standard
        (some (Sum.inl (Sum.inl ()))) = .seq (.test .one) e := rfl

private theorem probe_right_label (a : A) (e f : Exp A T) :
    initializedStandard (probe a e f)
        (certifiedThompson A T (probe a e f)).standard
        (some (Sum.inr (Sum.inl ()))) = .seq (.test .one) f := rfl

/-- One action symbol is enough to reduce full completeness to the internal form. -/
theorem complete_of_thompson_internal (a : A)
    (hinternal : ThompsonInternalCompleteBA A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  have hlang : UniformAutLangEq
      (certifiedThompson A T (probe a e f)).aut.toGAut
      (certifiedThompson A T (probe a e f)).aut.toGAut
      (some (Sum.inl (Sum.inl ()))) (some (Sum.inr (Sum.inl ()))) := by
    intro X W gs
    rw [certifiedThompson_state_language (probe a e f) _
        (probe_left_listed a e f) X W,
      certifiedThompson_state_language (probe a e f) _
        (probe_right_listed a e f) X W,
      probe_left_label a e f, probe_right_label a e f]
    obtain ⟨x, l⟩ := gs
    rw [den_test_seq_iff W .one e x l, den_test_seq_iff W .one f x l]
    exact and_congr_right (fun _ => heq X W (x, l))
  have hstates := hinternal (probe a e f)
    (some (Sum.inl (Sum.inl ()))) (some (Sum.inr (Sum.inl ())))
    (probe_left_listed a e f) (probe_right_listed a e f) hlang
  rw [probe_left_label a e f, probe_right_label a e f] at hstates
  exact EquivBA.trans (EquivBA.symm (one_seq e))
    (EquivBA.trans hstates (one_seq f))

/-- **The reduction.**  With one action symbol available, full finite-axiom completeness
    for GKAT is *equivalent* to the statement that behaviourally identical positions
    inside a single program's own Thompson automaton carry provably equal labels.

    Nothing about arbitrary equation systems survives on the right-hand side.  Whatever
    `UA` is still supplying, it is supplying it about syntax-generated control flow. -/
theorem completeness_iff_thompson_internal (a : A) :
    FiniteAxiomsCompleteBA A T ↔ ThompsonInternalCompleteBA A T :=
  ⟨thompson_internal_of_complete, complete_of_thompson_internal a⟩

/-! ## What is already discharged on the right-hand side

    Two of the three ways two listed states can be behaviourally identical are settled
    unconditionally by this development. -/

/-- If both states are uniformly dead, their labels are provably equal — both are `0`.
    This is the case that used to be circular. -/
theorem thompson_internal_dead_case (program : Exp A T)
    (s t : Option (certifiedThompson A T program).State)
    (hs : s ∈ (certifiedThompson A T program).aut.toGAut.states)
    (ht : t ∈ (certifiedThompson A T program).aut.toGAut.states)
    (hsdead : UniformAutLempty (certifiedThompson A T program).aut.toGAut s)
    (htdead : UniformAutLempty (certifiedThompson A T program).aut.toGAut t) :
    EquivBA (initializedStandard program
        (certifiedThompson A T program).standard s)
      (initializedStandard program
        (certifiedThompson A T program).standard t) :=
  EquivBA.trans (dead_thompson_label_eq_zero program s hs hsdead)
    (EquivBA.symm (dead_thompson_label_eq_zero program t ht htdead))

/-- If one of two language-equivalent states is dead then so is the other, so the dead
    case is closed under the equivalence rather than being a side condition. -/
theorem thompson_internal_dead_transfers (program : Exp A T)
    (s t : Option (certifiedThompson A T program).State)
    (hlang : UniformAutLangEq (certifiedThompson A T program).aut.toGAut
      (certifiedThompson A T program).aut.toGAut s t)
    (hsdead : UniformAutLempty (certifiedThompson A T program).aut.toGAut s) :
    UniformAutLempty (certifiedThompson A T program).aut.toGAut t :=
  fun X W gs hrun => hsdead X W gs ((hlang X W gs).mpr hrun)

/-- Consequently the whole dead half of the internal statement is unconditional. -/
theorem thompson_internal_on_dead_states (program : Exp A T)
    (s t : Option (certifiedThompson A T program).State)
    (hs : s ∈ (certifiedThompson A T program).aut.toGAut.states)
    (ht : t ∈ (certifiedThompson A T program).aut.toGAut.states)
    (hlang : UniformAutLangEq (certifiedThompson A T program).aut.toGAut
      (certifiedThompson A T program).aut.toGAut s t)
    (hsdead : UniformAutLempty (certifiedThompson A T program).aut.toGAut s) :
    EquivBA (initializedStandard program
        (certifiedThompson A T program).standard s)
      (initializedStandard program
        (certifiedThompson A T program).standard t) :=
  thompson_internal_dead_case program s t hs ht hsdead
    (thompson_internal_dead_transfers program s t hlang hsdead)

#print axioms thompson_internal_of_complete
#print axioms complete_of_thompson_internal
#print axioms completeness_iff_thompson_internal
#print axioms thompson_internal_on_dead_states

end GkatCompletenessReduction
