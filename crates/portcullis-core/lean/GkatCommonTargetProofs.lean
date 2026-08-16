import GkatPullbackProofs
import GkatAtomTransferProofs
import GkatNullLanguageProofs

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
open GkatSynthesis GkatCofinality GkatPullback GkatAtomTransfer GkatNullLanguage

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

/-- A system is **productive** when no state is dead: from every state — the pseudostate
    included — *some* guarded string is accepted, at *some* atom.

    The atom is existential, and that is not a detail.  Demanding acceptance at *every* atom
    would be satisfied by almost nothing: `a ; b?` has a core state that cannot halt at a
    `¬b` atom and has no transition there, so it would fail, and with it every program
    carrying a nontrivial guard.  `crossEquiv_step` only ever needs a word starting at the
    atom *after* the step, and it is free to choose that atom — so the weaker form is both
    what the proof uses and what matches the search's `all_productive` ("can still reach a
    halt").  The `X` argument is kept only to witness that the atom type is inhabited. -/
def Productive {S : Type} (aut : InitializedGAut S A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (_ : X) (s : Option S),
    ∃ (x' : X) (w : List (A × X)), autRun W aut.toGAut s x' w

/-- Two states of two (possibly different) systems with the same language, uniformly in the
    test interpretation.  Stated across a pair because that is what the matching argument
    needs; taking `b := a` recovers the single-system notion. -/
def CrossEquiv {S₁ S₂ : Type} (a : InitializedGAut S₁ A T) (b : InitializedGAut S₂ A T)
    (s : Option S₁) (t : Option S₂) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (gs : GS A X),
    autLang W a.toGAut s gs ↔ autLang W b.toGAut t gs

/-- Language equivalence inside one system. -/
abbrev LangEquiv {S : Type} (aut : InitializedGAut S A T) (s t : Option S) : Prop :=
  CrossEquiv aut aut s t

theorem CrossEquiv.symm {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} {s : Option S₁} {t : Option S₂}
    (h : CrossEquiv a b s t) : CrossEquiv b a t s :=
  fun X W gs => (h X W gs).symm

theorem CrossEquiv.trans {S₁ S₂ S₃ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} {c : InitializedGAut S₃ A T}
    {s : Option S₁} {t : Option S₂} {u : Option S₃}
    (h₁ : CrossEquiv a b s t) (h₂ : CrossEquiv b c t u) : CrossEquiv a c s u :=
  fun X W gs => (h₁ X W gs).trans (h₂ X W gs)

/-! ### Atom transfer for runs

    Comparing two states' languages at *different* interpretations needs both replayed in
    one carrier.  `bval_relabel` moves a guard; these move a whole run. -/

theorem firstMatch_transfer {S X Z : Type} {W : T → X → Bool} {W' : T → Z → Bool}
    {f : X → Z} (hf : ∀ t x, W' t (f x) = W t x) (L : List (BExp T × A × S)) (x : X) :
    firstMatch W' (f x) L = firstMatch W x L := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, q, s⟩ := hd
      simp only [firstMatch]
      rw [bval_relabel g (fun t _ y => hf t y) x, ih]

theorem autRun_transfer {S X Z : Type} {W : T → X → Bool} {W' : T → Z → Bool}
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
theorem crossEquiv_hlt {S₁ S₂ : Type} {a : InitializedGAut S₁ A T} {b : InitializedGAut S₂ A T}
    {s : Option S₁} {t : Option S₂} (h : CrossEquiv a b s t)
    (X : Type) (W : T → X → Bool) (x : X) :
    bval W (a.toGAut.hlt s) x = bval W (b.toGAut.hlt t) x := by
  have hiff := h X W (x, [])
  change (bval W (a.toGAut.hlt s) x = true) ↔ (bval W (b.toGAut.hlt t) x = true) at hiff
  cases hs : bval W (a.toGAut.hlt s) x <;> cases ht : bval W (b.toGAut.hlt t) x
  · rfl
  · rw [hs, ht] at hiff; exact absurd (hiff.mpr rfl) (by simp)
  · rw [hs, ht] at hiff; exact absurd (hiff.mp rfl) (by simp)
  · rfl

/-- **Steps agree, given productivity.**  If one side steps, productivity supplies a tail
    making that step part of an accepted word, so the other side must step too and with the
    same action — and the two targets are again language-equivalent.

    The targets are compared in a *combined* carrier `X ⊕ Y`: the step was witnessed under
    one interpretation and the languages must agree under every other, so both are replayed
    side by side with `autRun_transfer`.

    Productivity of the *stepping* side is what is used, and it is exactly what the
    counterexample denies: `0` and `a ; 0` have the same language and do not step alike. -/
theorem crossEquiv_step {S₁ S₂ : Type} {a : InitializedGAut S₁ A T} {b : InitializedGAut S₂ A T}
    (hprod : Productive a) {s : Option S₁} {t : Option S₂} (h : CrossEquiv a b s t)
    {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S₁}
    (hs : autStep W a.toGAut s x = some (q, s')) :
    ∃ t', autStep W b.toGAut t x = some (q, t') ∧ CrossEquiv a b s' t' := by
  obtain ⟨x', w, hw⟩ := hprod X W x s'
  obtain ⟨t', ht, _⟩ := (h X W (x, (q, x') :: w)).mp ⟨s', hs, hw⟩
  refine ⟨t', ht, ?_⟩
  intro Y V gs
  obtain ⟨y, v⟩ := gs
  let W'' : T → Sum X Y → Bool := fun c => Sum.elim (W c) (V c)
  have hl : ∀ (c : T) (z : X), W'' c (Sum.inl z) = W c z := fun _ _ => rfl
  have hr : ∀ (c : T) (z : Y), W'' c (Sum.inr z) = V c z := fun _ _ => rfl
  have pushA : ∀ u : Option S₁,
      autRun W'' a.toGAut u (Sum.inr y) (mapAtoms Sum.inr v) ↔ autRun V a.toGAut u y v :=
    fun u => autRun_transfer hr a.toGAut u y v
  have pushB : ∀ u : Option S₂,
      autRun W'' b.toGAut u (Sum.inr y) (mapAtoms Sum.inr v) ↔ autRun V b.toGAut u y v :=
    fun u => autRun_transfer hr b.toGAut u y v
  have step_l : autStep W'' a.toGAut s (Sum.inl x) = some (q, s') := by
    rw [show autStep W'' a.toGAut s (Sum.inl x) = autStep W a.toGAut s x from
      firstMatch_transfer hl (a.toGAut.trans s) x]
    exact hs
  have step_r : autStep W'' b.toGAut t (Sum.inl x) = some (q, t') := by
    rw [show autStep W'' b.toGAut t (Sum.inl x) = autStep W b.toGAut t x from
      firstMatch_transfer hl (b.toGAut.trans t) x]
    exact ht
  have bridge := h (Sum X Y) W'' (Sum.inl x, (q, Sum.inr y) :: mapAtoms Sum.inr v)
  change (∃ u, autStep W'' a.toGAut s (Sum.inl x) = some (q, u) ∧
      autRun W'' a.toGAut u (Sum.inr y) (mapAtoms Sum.inr v)) ↔
    (∃ u, autStep W'' b.toGAut t (Sum.inl x) = some (q, u) ∧
      autRun W'' b.toGAut u (Sum.inr y) (mapAtoms Sum.inr v)) at bridge
  constructor
  · intro hrun
    obtain ⟨u, hu, hru⟩ := bridge.mp ⟨s', step_l, (pushA s').mpr hrun⟩
    rw [step_r] at hu
    have : u = t' := congrArg Prod.snd (Option.some.inj hu.symm)
    exact (pushB t').mp (this ▸ hru)
  · intro hrun
    obtain ⟨u, hu, hru⟩ := bridge.mpr ⟨t', step_r, (pushB t').mpr hrun⟩
    rw [step_l] at hu
    have : u = s' := congrArg Prod.snd (Option.some.inj hu.symm)
    exact (pushA s').mp (this ▸ hru)

/-- **The only thing the span construction ever needed.**  Language-equivalent states step
    along the same action into language-equivalent states.  Isolated as a property in its own
    right because there is more than one way to establish it: `Productive` supplies it, and so
    does `Total` together with a canonical dead part — and the second is achievable where the
    first is not. -/
def StepAgree {S₁ S₂ : Type} (a : InitializedGAut S₁ A T) (b : InitializedGAut S₂ A T) : Prop :=
  ∀ {s : Option S₁} {t : Option S₂}, CrossEquiv a b s t →
    ∀ {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S₁},
      autStep W a.toGAut s x = some (q, s') →
      ∃ t', autStep W b.toGAut t x = some (q, t') ∧ CrossEquiv a b s' t'

/-- Productivity supplies it. -/
theorem stepAgree_of_productive {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} (hprod : Productive a) : StepAgree a b := by
  intro s t h X W x q s' hs
  exact crossEquiv_step hprod h W x hs

#print axioms crossEquiv_hlt
#print axioms crossEquiv_step
#print axioms stepAgree_of_productive

/-- Reachability of a state from the pseudostate, along any interpretation.  Unreachable
    states are the *other* thing a Thompson automaton can carry that no behavioural target
    can account for: `if 1 then a else (b ; b)` is productive, but its else-branch realises
    languages the equivalent program `a` never does, so no common target can be onto both. -/
inductive Reaches {S : Type} (aut : InitializedGAut S A T) : Option S → Prop where
  | start : Reaches aut none
  | step {u v : Option S} {X : Type} {W : T → X → Bool} {x : X} {q : A} :
      Reaches aut u → autStep W aut.toGAut u x = some (q, v) → Reaches aut v

/-- Every state is reachable. -/
def Reachable {S : Type} (aut : InitializedGAut S A T) : Prop :=
  ∀ s : S, Reaches aut (some s)

/-- **Normal form.**  Productive *and* fully reachable — the two conditions the search has
    always imposed on the automata it considers, and the two a behavioural target needs. -/
def Normal {S : Type} (aut : InitializedGAut S A T) : Prop :=
  Productive aut ∧ Reachable aut

/-- **Phase A, named — for non-null programs only.**  Every program with a nonempty language
    is provably equal to one in normal form.

    The restriction is forced, not cosmetic.  `0` is not productive: its pseudostate accepts
    nothing at any atom, so no null program is normal, and `Normalizable` without the
    hypothesis would be false.  Nothing is lost — the null case is discharged outright by
    `nullLanguage_complete`, which needs none of this machinery.

    Dead regions inside a non-null program are `0` (`every_dead_state_eq_zero`) and
    unreachable branches sit under unsatisfiable guards (`ite_of_taut`, `ite_of_unsat`);
    since GKAT actions are uninterpreted, every atom is possible after a step, so
    unreachability can only come from guard structure at a branch. -/
def Normalizable (A T : Type) : Prop :=
  ∀ e : Exp A T, ¬ UniformExpLempty e →
    ∃ e' : Exp A T, EquivBA e e' ∧ Normal (certifiedThompson A T e').aut

/-- **The repaired constructive half.**  Restricted to normal automata, which is precisely
    the class the counterexamples leave. -/
def NormalCommonTarget (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    Normal (certifiedThompson A T e).aut → Normal (certifiedThompson A T f).aut →
    ∃ (Q : Type) (m : InitializedGAut Q A T)
      (φ : InitCover (certifiedThompson A T e).aut m)
      (ψ : InitCover (certifiedThompson A T f).aut m),
      Nonempty (Base φ ψ)

/-- **The residual target, stated about pullbacks and nothing else.**

    Two earlier attempts to state this more generally are refuted.  `Nested ⟹
    HasThompsonCover` fails on six automata at three states; `ThompsonCofinal` — anything
    covering a Thompson automaton is covered by one — fails on eighty-four at four states.
    In both searches *not one* counterexample was a pullback, while every crux pullback was
    covered.  So the hypothesis has to be the one a pullback actually satisfies: it is the
    fibre product of two **syntax-generated** automata, not merely something that covers
    one. -/
def PullbackCovered (A T : Type) : Prop :=
  ∀ (e f : Exp A T) (Q : Type) (m : InitializedGAut Q A T)
    (φ : InitCover (certifiedThompson A T e).aut m)
    (ψ : InitCover (certifiedThompson A T f).aut m)
    (base : Base φ ψ),
    HasThompsonCover (pullback φ ψ base)

/-- **Completeness, from the three remaining statements.**  Normalization moves an arbitrary
    pair into the fragment where a behavioural target exists, that target spans them, the
    fibre product covers both sides, and `PullbackCovered` supplies the Thompson cover.

    Two of the three are constructions; only `PullbackCovered` is open.  No uniqueness
    axiom appears anywhere in the chain. -/
theorem completeness_of_normalized
    (hnorm : Normalizable A T)
    (hct : NormalCommonTarget A T)
    (hpc : PullbackCovered A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  by_cases hnull : UniformExpLempty e
  · -- both are null, and `nullLanguage_complete` settles it with nothing else
    have hf : UniformExpLempty f := by
      refine (uniformExpLempty_iff_zero f).mpr ?_
      intro X W gs
      exact ((heq X W gs).symm.trans ((uniformExpLempty_iff_zero e).mp hnull X W gs))
    exact EquivBA.trans (nullLanguage_complete e hnull)
      (EquivBA.symm (nullLanguage_complete f hf))
  · have hfn : ¬ UniformExpLempty f := by
      intro hf
      refine hnull ?_
      refine (uniformExpLempty_iff_zero e).mpr ?_
      intro X W gs
      exact (heq X W gs).trans ((uniformExpLempty_iff_zero f).mp hf X W gs)
    obtain ⟨e', hee', hne⟩ := hnorm e hnull
    obtain ⟨f', hff', hnf⟩ := hnorm f hfn
    have heq' : UniformLanguageEquivalent e' f' := by
      intro X W gs
      exact ((sound_BA (V := W) hee' gs).symm.trans (heq X W gs)).trans
        (sound_BA (V := W) hff' gs)
    obtain ⟨Q, m, φ, ψ, ⟨base⟩⟩ := hct e' f' heq' hne hnf
    obtain ⟨h, ⟨χ⟩⟩ := hpc e' f' Q m φ ψ base
    exact EquivBA.trans hee'
      (EquivBA.trans
        (equivBA_of_common_refinement χ (pullbackFst φ ψ base) (pullbackSnd φ ψ base))
        (EquivBA.symm hff'))

#print axioms not_commonTarget
#print axioms no_common_target
#print axioms completeness_of_normalized

end GkatCommonTarget
