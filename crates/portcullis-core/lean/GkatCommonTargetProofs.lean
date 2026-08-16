import GkatPullbackProofs
import GkatAtomTransferProofs

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
open GkatSynthesis GkatCofinality GkatPullback GkatAtomTransfer

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

/-- A system is **productive** when no configuration is dead: from every state — the
    pseudostate included — and every atom, some guarded string is accepted.  Stated
    semantically, so it does not depend on how the automaton was built. -/
def Productive {S : Type} (aut : InitializedGAut S A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X) (s : Option S),
    ∃ w : List (A × X), autRun W aut.toGAut s x w

/-- Two states with the same language, uniformly in the test interpretation. -/
def LangEquiv {S : Type} (aut : InitializedGAut S A T) (s t : Option S) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (gs : GS A X),
    autLang W aut.toGAut s gs ↔ autLang W aut.toGAut t gs

/-! ### Atom transfer for runs

    Comparing two states' languages at *different* interpretations needs both replayed in
    one carrier.  `bval_relabel` moves a guard; these move a whole run. -/

private theorem firstMatch_transfer {S X Z : Type} {W : T → X → Bool} {W' : T → Z → Bool}
    {f : X → Z} (hf : ∀ t x, W' t (f x) = W t x) (L : List (BExp T × A × S)) (x : X) :
    firstMatch W' (f x) L = firstMatch W x L := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, q, s⟩ := hd
      simp only [firstMatch]
      rw [bval_relabel g (fun t _ y => hf t y) x, ih]

private theorem autRun_transfer {S X Z : Type} {W : T → X → Bool} {W' : T → Z → Bool}
    {f : X → Z} (hf : ∀ t x, W' t (f x) = W t x) (aut : GAut S A T) (s : S) (x : X)
    (w : List (A × X)) :
    autRun W' aut s (f x) (mapAtoms f w) ↔ autRun W aut s x w := by
  induction w generalizing s x with
  | nil =>
      change (bval W' (aut.hlt s) (f x) = true) ↔ (bval W (aut.hlt s) x = true)
      rw [bval_relabel (aut.hlt s) (fun t _ y => hf t y) x]
  | cons hd tl ih =>
      obtain ⟨q, x'⟩ := hd
      change (∃ s', autStep W' aut s (f x) = some (q, s') ∧
          autRun W' aut s' (f x') (mapAtoms f tl)) ↔
        (∃ s', autStep W aut s x = some (q, s') ∧ autRun W aut s' x' tl)
      constructor
      · rintro ⟨s', hstep, hrun⟩
        rw [show autStep W' aut s (f x) = autStep W aut s x from
          firstMatch_transfer hf (aut.trans s) x] at hstep
        exact ⟨s', hstep, (ih (s := s') (x := x')).mp hrun⟩
      · rintro ⟨s', hstep, hrun⟩
        refine ⟨s', ?_, (ih (s := s') (x := x')).mpr hrun⟩
        rw [show autStep W' aut s (f x) = autStep W aut s x from
          firstMatch_transfer hf (aut.trans s) x]
        exact hstep

/-! ### Language equivalence is a bisimulation — but only when productive

    This is exactly what the counterexample above denies in general.  `0` and `a ; 0` have
    the same language and do not step alike; what rescues the implication is that a step
    must lead somewhere that accepts *something*, so it cannot be invisible. -/

/-- Halting agrees, read off the empty word.  No productivity needed. -/
theorem langEquiv_hlt {S : Type} {aut : InitializedGAut S A T} {s t : Option S}
    (h : LangEquiv aut s t) (X : Type) (W : T → X → Bool) (x : X) :
    bval W (aut.toGAut.hlt s) x = bval W (aut.toGAut.hlt t) x := by
  have hiff := h X W (x, [])
  change (bval W (aut.toGAut.hlt s) x = true) ↔ (bval W (aut.toGAut.hlt t) x = true) at hiff
  cases hs : bval W (aut.toGAut.hlt s) x <;> cases ht : bval W (aut.toGAut.hlt t) x
  · rfl
  · rw [hs, ht] at hiff; exact absurd (hiff.mpr rfl) (by simp)
  · rw [hs, ht] at hiff; exact absurd (hiff.mp rfl) (by simp)
  · rfl

/-- **Steps agree, given productivity.**  If one side steps, productivity supplies a tail
    making that step part of an accepted word, so the other side must step too and with the
    same action — and the two targets are again language-equivalent.

    The targets are compared in a *combined* carrier `X ⊕ Y`: the step was witnessed under
    one interpretation and the languages must agree under every other, so both are replayed
    side by side with `autRun_transfer`. -/
theorem langEquiv_step {S : Type} {aut : InitializedGAut S A T}
    (hprod : Productive aut) {s t : Option S} (h : LangEquiv aut s t)
    {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S}
    (hs : autStep W aut.toGAut s x = some (q, s')) :
    ∃ t', autStep W aut.toGAut t x = some (q, t') ∧ LangEquiv aut s' t' := by
  obtain ⟨w, hw⟩ := hprod X W x s'
  obtain ⟨t', ht, _⟩ := (h X W (x, (q, x) :: w)).mp ⟨s', hs, hw⟩
  refine ⟨t', ht, ?_⟩
  intro Y V gs
  obtain ⟨y, v⟩ := gs
  -- replay both sides in `X ⊕ Y`
  let W'' : T → Sum X Y → Bool := fun c => Sum.elim (W c) (V c)
  have hl : ∀ (c : T) (z : X), W'' c (Sum.inl z) = W c z := fun _ _ => rfl
  have hr : ∀ (c : T) (z : Y), W'' c (Sum.inr z) = V c z := fun _ _ => rfl
  have push : ∀ u : Option S,
      autRun W'' aut.toGAut u (Sum.inr y) (mapAtoms Sum.inr v) ↔ autRun V aut.toGAut u y v :=
    fun u => autRun_transfer hr aut.toGAut u y v
  have step_l : autStep W'' aut.toGAut s (Sum.inl x) = some (q, s') := by
    rw [show autStep W'' aut.toGAut s (Sum.inl x) = autStep W aut.toGAut s x from
      firstMatch_transfer hl (aut.toGAut.trans s) x]
    exact hs
  have step_r : autStep W'' aut.toGAut t (Sum.inl x) = some (q, t') := by
    rw [show autStep W'' aut.toGAut t (Sum.inl x) = autStep W aut.toGAut t x from
      firstMatch_transfer hl (aut.toGAut.trans t) x]
    exact ht
  have bridge := h (Sum X Y) W'' (Sum.inl x, (q, Sum.inr y) :: mapAtoms Sum.inr v)
  change (∃ u, autStep W'' aut.toGAut s (Sum.inl x) = some (q, u) ∧
      autRun W'' aut.toGAut u (Sum.inr y) (mapAtoms Sum.inr v)) ↔
    (∃ u, autStep W'' aut.toGAut t (Sum.inl x) = some (q, u) ∧
      autRun W'' aut.toGAut u (Sum.inr y) (mapAtoms Sum.inr v)) at bridge
  constructor
  · intro hrun
    obtain ⟨u, hu, hru⟩ := bridge.mp ⟨s', step_l, (push s').mpr hrun⟩
    rw [step_r] at hu
    have : u = t' := congrArg Prod.snd (Option.some.inj hu.symm)
    exact (push t').mp (this ▸ hru)
  · intro hrun
    obtain ⟨u, hu, hru⟩ := bridge.mpr ⟨t', step_r, (push t').mpr hrun⟩
    rw [step_l] at hu
    have : u = s' := congrArg Prod.snd (Option.some.inj hu.symm)
    exact (push s').mp (this ▸ hru)

#print axioms langEquiv_hlt
#print axioms langEquiv_step

/-- **The repaired constructive half.**  Restricted to programs whose automata are
    productive, which is precisely the class the counterexamples leave. -/
def ProductiveCommonTarget (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    Productive (certifiedThompson A T e).aut → Productive (certifiedThompson A T f).aut →
    ∃ (Q : Type) (m : InitializedGAut Q A T)
      (φ : InitCover (certifiedThompson A T e).aut m)
      (ψ : InitCover (certifiedThompson A T f).aut m),
      Nonempty (Base φ ψ)

/-- **Phase A, named.**  Every program is provably equal to one whose automaton is
    productive — dead regions are `0` and can be pruned.  This is the bridge that makes the
    productive restriction lossless, and it is a statement about the finite axioms rather
    than about covers. -/
def DeadBranchPruning (A T : Type) : Prop :=
  ∀ e : Exp A T, ∃ e' : Exp A T, EquivBA e e' ∧ Productive (certifiedThompson A T e').aut

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
  obtain ⟨e', hee', hpe⟩ := hprune e
  obtain ⟨f', hff', hpf⟩ := hprune f
  have heq' : UniformLanguageEquivalent e' f' := by
    intro X W gs
    exact ((sound_BA (V := W) hee' gs).symm.trans (heq X W gs)).trans (sound_BA (V := W) hff' gs)
  obtain ⟨Q, m, φ, ψ, ⟨base⟩⟩ := hct e' f' heq' hpe hpf
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
