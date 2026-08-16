import GkatPullbackProofs

/-!
# `CommonTarget` is false, and what replaces it

`GkatPullback.spanExists_of_commonTarget` reduces the constructive half of the programme to
`CommonTarget`: uniformly equivalent programs admit a system both their Thompson automata
cover.  It is a natural-looking statement — it is just "they have a common behavioural
quotient" — and it is **false**.

The witness is the smallest one there is:

    e = 0                    f = a ; 0

Both denote the empty language, so they are uniformly equivalent.  But `f`'s automaton steps
from its pseudostate and `e`'s does not, and `star_bijection_init` says a cover preserves
exactly that: a covering map is bijective on stars, so it cannot turn a state that steps into
one that does not.  A common target would have to step and not step at the same atom.

This is not an artefact of the empty language.  The same argument kills

    if b then (a ; 0) else c      vs      if b then 0 else c

whose common language is perfectly nonempty; what matters is a *dead region*, not a dead
program.  So the precondition is productivity — every state can still reach a halt — which is
exactly the filter the search always had to apply, and exactly what `nullLanguage_complete`
and the dead-branch results are there to discharge.
-/

namespace GkatCommonTarget

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCofinality GkatPullback

variable {A T : Type}

/-! ## The refuting pair -/

/-- One action, one test. -/
abbrev Act := Unit
abbrev Tst := Unit

/-- `0` — no steps from the pseudostate, and no halting. -/
abbrev deadTest : Exp Act Tst := .test .zero

/-- `a ; 0` — one step from the pseudostate into a state that never halts. -/
abbrev deadAction : Exp Act Tst := .seq (.act ()) (.test .zero)

/-- Both denote nothing at all, so they are uniformly equivalent. -/
theorem refuting_pair_equivalent : UniformLanguageEquivalent deadTest deadAction := by
  intro X W gs
  constructor
  · intro h
    exact absurd h.1 (by simp [bval])
  · intro h
    obtain ⟨l1, l2, _, _, hzero⟩ := h
    exact absurd hzero.1 (by simp [bval])

/-- `0`'s pseudostate never steps. -/
theorem deadTest_no_step {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (certifiedThompson Act Tst deadTest).aut.initTrans = none := rfl

/-- `a ; 0`'s pseudostate always steps — the action's guard is `1`. -/
theorem deadAction_steps {X : Type} (W : Tst → X → Bool) (x : X) :
    (firstMatch W x (certifiedThompson Act Tst deadAction).aut.initTrans).isSome = true := rfl

/-! ## The refutation -/

/-- **No common target.**  A cover is bijective on stars (`star_bijection_init`), so any
    system covered by both automata would have to step and not step at the same atom. -/
theorem no_common_target
    {Q : Type} (m : InitializedGAut Q Act Tst)
    (φ : InitCover (certifiedThompson Act Tst deadTest).aut m)
    (ψ : InitCover (certifiedThompson Act Tst deadAction).aut m) : False := by
  have h₁ := star_bijection_init φ Unit (fun _ _ => true) ()
  have h₂ := star_bijection_init ψ Unit (fun _ _ => true) ()
  rw [deadTest_no_step] at h₁
  rw [deadAction_steps] at h₂
  rw [← h₁] at h₂
  exact absurd h₂ (by simp)

/-- **`CommonTarget` is false.**  The constructive half of the programme cannot be stated
    without a productivity precondition. -/
theorem not_commonTarget : ¬ CommonTarget Act Tst := by
  intro h
  obtain ⟨Q, m, φ, ψ, _⟩ := h deadTest deadAction refuting_pair_equivalent
  exact no_common_target m φ ψ

/-! ## The repair

    Productivity is the precondition, and it is not a tidy-up: it is what the whole
    development has needed all along.  The search's own pair filter applies `all_productive`
    before asking any of these questions, and `nullLanguage_complete` together with the
    dead-branch results is what discharges the excluded region. -/

/-- A system is **productive** when every reachable configuration can still halt.  Stated
    semantically so it does not depend on how the automaton was built: from every state, at
    every atom, some guarded string is accepted. -/
def Productive {S : Type} (aut : InitializedGAut S A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X) (s : S),
    ∃ w : List (A × X), autRun W aut.toGAut (some s) x w

/-- The pseudostate too. -/
def ProductiveInit {S : Type} (aut : InitializedGAut S A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X),
    ∃ w : List (A × X), autRun W aut.toGAut none x w

/-- **The repaired constructive half.**  Restricted to programs whose automata are
    productive, which is precisely the class the counterexamples leave. -/
def ProductiveCommonTarget (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    Productive (certifiedThompson A T e).aut → ProductiveInit (certifiedThompson A T e).aut →
    Productive (certifiedThompson A T f).aut → ProductiveInit (certifiedThompson A T f).aut →
    ∃ (Q : Type) (m : InitializedGAut Q A T)
      (φ : InitCover (certifiedThompson A T e).aut m)
      (ψ : InitCover (certifiedThompson A T f).aut m),
      Nonempty (Base φ ψ)

/-- **Phase A, named.**  Every program is provably equal to one whose automaton is
    productive — dead regions are `0` and can be pruned.  This is the bridge that makes the
    productive restriction lossless, and it is a statement about the finite axioms rather
    than about covers. -/
def DeadBranchPruning (A T : Type) : Prop :=
  ∀ e : Exp A T, ∃ e' : Exp A T, EquivBA e e' ∧
    Productive (certifiedThompson A T e').aut ∧ ProductiveInit (certifiedThompson A T e').aut

/-- **Completeness, from the repaired statements.**  Pruning moves an arbitrary pair into the
    productive fragment, the repaired target spans it, the fibre product covers both sides,
    and cofinality supplies the Thompson cover.

    Note what pruning has to preserve: `EquivBA` on both sides, so the conclusion transports
    back.  Nothing here assumes a uniqueness axiom. -/
theorem completeness_of_repaired
    (hprune : DeadBranchPruning A T)
    (hct : ProductiveCommonTarget A T)
    (hcof : ThompsonCofinal A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨e', hee', hpe, hpie⟩ := hprune e
  obtain ⟨f', hff', hpf, hpif⟩ := hprune f
  have heq' : UniformLanguageEquivalent e' f' := by
    intro X W gs
    exact ((sound_BA (V := W) hee' gs).symm.trans (heq X W gs)).trans (sound_BA (V := W) hff' gs)
  obtain ⟨Q, m, φ, ψ, ⟨base⟩⟩ := hct e' f' heq' hpe hpie hpf hpif
  have hspan : ∃ (S : Type) (mid : InitializedGAut S A T),
      Nonempty (InitCover mid (certifiedThompson A T e').aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T f').aut) :=
    ⟨Fib φ ψ, pullback φ ψ base, ⟨pullbackFst φ ψ base⟩, ⟨pullbackSnd φ ψ base⟩⟩
  obtain ⟨S, mid, ⟨π₁⟩, ⟨π₂⟩⟩ := hspan
  obtain ⟨h, ⟨χ⟩⟩ := hcof mid e' ⟨π₁⟩
  exact EquivBA.trans hee'
    (EquivBA.trans (equivBA_of_common_refinement χ π₁ π₂) (EquivBA.symm hff'))

#print axioms not_commonTarget
#print axioms no_common_target
#print axioms completeness_of_repaired

end GkatCommonTarget
