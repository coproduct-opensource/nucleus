import GkatChainFragmentProofs
import GkatGuardDecideProofs

/-! # The certified decision procedure

    Program equivalence reduces to bisimilarity of the two start states
    in the trimmed Thompson sum — and bisimilarity DECIDES.  Combined
    with completeness (`chainloops_complete_free`) and soundness
    (`sound_BA`), provable equivalence itself becomes decidable on the
    chain-loop fragment: a certified, computable, choice-free decision
    procedure for the finite GKAT axioms without UA. -/

namespace GkatDecide

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop GkatChainLoop GkatOrbit
open GkatChainFragment GkatGuardDecide

variable {A T : Type}

/-- Thompson state types have decidable equality, structurally. -/
def thompsonDecEq : (p : Exp A T) →
    DecidableEq (certifiedThompson A T p).State
  | .test _ => fun x => nomatch x
  | .act _ => fun _ _ => isTrue rfl
  | .ite _ e f =>
      letI := thompsonDecEq e
      letI := thompsonDecEq f
      inferInstanceAs (DecidableEq (Sum _ _))
  | .seq e f =>
      letI := thompsonDecEq e
      letI := thompsonDecEq f
      inferInstanceAs (DecidableEq (Sum _ _))
  | .wh _ e => thompsonDecEq e

/-- Every Thompson state is listed. -/
theorem thompson_exhaustive : (p : Exp A T) →
    ∀ x : (certifiedThompson A T p).State,
      x ∈ (certifiedThompson A T p).aut.core.states
  | .test _ => fun x => nomatch x
  | .act _ => fun x => by
      cases x
      exact List.mem_cons_self ..
  | .ite _ e f => fun x => by
      show x ∈ (certifiedThompson A T e).aut.core.states.map Sum.inl
        ++ (certifiedThompson A T f).aut.core.states.map Sum.inr
      cases x with
      | inl a =>
          exact List.mem_append.mpr (Or.inl (List.mem_map.mpr
            ⟨a, thompson_exhaustive e a, rfl⟩))
      | inr a =>
          exact List.mem_append.mpr (Or.inr (List.mem_map.mpr
            ⟨a, thompson_exhaustive f a, rfl⟩))
  | .seq e f => fun x => by
      show x ∈ (certifiedThompson A T e).aut.core.states.map Sum.inl
        ++ (certifiedThompson A T f).aut.core.states.map Sum.inr
      cases x with
      | inl a =>
          exact List.mem_append.mpr (Or.inl (List.mem_map.mpr
            ⟨a, thompson_exhaustive e a, rfl⟩))
      | inr a =>
          exact List.mem_append.mpr (Or.inr (List.mem_map.mpr
            ⟨a, thompson_exhaustive f a, rfl⟩))
  | .wh _ e => fun x => by
      show x ∈ (certifiedThompson A T e).aut.core.states
      exact thompson_exhaustive e x

/-- Every state of the Thompson sum is listed. -/
theorem sumof_exhaustive (e f : Exp A T) :
    ∀ x : Sum (Option (certifiedThompson A T e).State)
        (Option (certifiedThompson A T f).State),
      x ∈ (SUMof A T e f).states := by
  intro x
  cases x with
  | inl o =>
      refine List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨o, ?_, rfl⟩))
      cases o with
      | none => exact List.mem_cons_self ..
      | some s =>
          exact List.mem_cons_of_mem _ (List.mem_map.mpr
            ⟨s, thompson_exhaustive e s, rfl⟩)
  | inr o =>
      refine List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨o, ?_, rfl⟩))
      cases o with
      | none => exact List.mem_cons_self ..
      | some s =>
          exact List.mem_cons_of_mem _ (List.mem_map.mpr
            ⟨s, thompson_exhaustive f s, rfl⟩)

/-- Language through the left sum embedding. -/
theorem autLang_sum_inl {S₁ S₂ Atom : Type} (V : T → Atom → Bool)
    (a₁ : GAut S₁ A T) (a₂ : GAut S₂ A T) (s : S₁) :
    autLang V (sumGAut a₁ a₂) (Sum.inl s) = autLang V a₁ s := by
  funext gs
  obtain ⟨x, w⟩ := gs
  exact propext (autRun_sumGAut_inl V a₁ a₂ w s x)

/-- Language through the right sum embedding. -/
theorem autLang_sum_inr {S₁ S₂ Atom : Type} (V : T → Atom → Bool)
    (a₁ : GAut S₁ A T) (a₂ : GAut S₂ A T) (s : S₂) :
    autLang V (sumGAut a₁ a₂) (Sum.inr s) = autLang V a₂ s := by
  funext gs
  obtain ⟨x, w⟩ := gs
  exact propext (autRun_sumGAut_inr V a₁ a₂ w s x)

/-- **EQUIVALENCE IS START-STATE BISIMILARITY** in the trimmed sum. -/
theorem ule_iff_start_bisim (e f : Exp A T) :
    UniformLanguageEquivalent e f
      ↔ GenBisimilar (trimAut (SUMof A T e f))
          (Sum.inl none) (Sum.inr none) := by
  constructor
  · intro h
    refine genBisimilar_of_uniformStateEquiv
      (liveSteps_trimAut (SUMof A T e f))
      (uniformStateEquiv_of_gen ?_)
    rw [autLang_trimAut, autLang_trimAut]
    show autLang (genW T) (sumGAut
        (certifiedThompson A T e).aut.toGAut
        (certifiedThompson A T f).aut.toGAut) (Sum.inl none)
      = autLang (genW T) (sumGAut
        (certifiedThompson A T e).aut.toGAut
        (certifiedThompson A T f).aut.toGAut) (Sum.inr none)
    rw [autLang_sum_inl, autLang_sum_inr,
      certifiedThompson_start_language e,
      certifiedThompson_start_language f]
    funext gs
    exact propext (h (T → Bool) (genW T) gs)
  · intro h X W gs
    have hL : autLang (genW T) (trimAut (SUMof A T e f))
        (Sum.inl none)
        = autLang (genW T) (trimAut (SUMof A T e f)) (Sum.inr none) :=
      autLang_eq_of_gautBisim
        (genBisimilar_bisim (trimAut (SUMof A T e f))) h
    rw [autLang_trimAut, autLang_trimAut] at hL
    have hU := uniformStateEquiv_of_gen hL X W
    show den W e gs ↔ den W f gs
    have h1 : autLang W (SUMof A T e f) (Sum.inl none) = den W e := by
      show autLang W (sumGAut
          (certifiedThompson A T e).aut.toGAut
          (certifiedThompson A T f).aut.toGAut) (Sum.inl none) = _
      rw [autLang_sum_inl, certifiedThompson_start_language e]
    have h2 : autLang W (SUMof A T e f) (Sum.inr none) = den W f := by
      show autLang W (sumGAut
          (certifiedThompson A T e).aut.toGAut
          (certifiedThompson A T f).aut.toGAut) (Sum.inr none) = _
      rw [autLang_sum_inr, certifiedThompson_start_language f]
    rw [← h1, ← h2, hU]

/-- **THE EQUIVALENCE DECIDER**: uniform language equivalence of GKAT
    programs is decidable, and the decision procedure is COMPUTABLE —
    Lean accepts this `def` without `noncomputable`, so the `Decidable`
    DATA is choice-free and runs.

    Its CORRECTNESS ARGUMENT is not: `#print axioms uleDec` reports
    `[propext, Classical.choice, Quot.sound]`, because the proof that
    the computable `trimAutD`/`genBisimilarDec` pipeline agrees with the
    `Classical.choose`-based `trimAut` goes through choice.  Algorithm
    choice-free, proof classical — the two claims are separate and only
    the first is about running the decider. -/
def uleDec [DecidableEq T] [DecidableEq A] (e f : Exp A T) :
    Decidable (UniformLanguageEquivalent e f) :=
  letI := thompsonDecEq e
  letI := thompsonDecEq f
  @decidable_of_iff _ _ (ule_iff_start_bisim e f).symm
    (@decidable_of_iff _ _
      (iff_of_eq (congrArg
        (fun a => GenBisimilar a
          (Sum.inl (none : Option (certifiedThompson A T e).State))
          (Sum.inr (none : Option (certifiedThompson A T f).State)))
        (trimAutD_eq_trimAut (SUMof A T e f)
          ((SUMof A T e f).states)
          (fun _ _ e' _ => sumof_exhaustive _ _ e'.2.2)
          (fun _ e' _ => sumof_exhaustive _ _ e'.2.2))))
      (genBisimilarDec
        (trimAutD (SUMof A T e f) ((SUMof A T e f).states).length)
        ((SUMof A T e f).states)
        (fun _ _ e' _ => sumof_exhaustive _ _ e'.2.2)
        (sumof_exhaustive _ _ _) (sumof_exhaustive _ _ _)))

/-- **THE CERTIFIED DECISION PROCEDURE**: provable equivalence of
    chain-loop programs is decidable from the finite axioms — no
    uniqueness axiom, no choice in the decision. -/
def chainloops_equivBA_dec [DecidableEq T] [DecidableEq A]
    (b₁ b₂ : BExp T) {body₁ body₂ : Exp A T}
    (hc₁ : Chain2 body₁) (hc₂ : Chain2 body₂) :
    Decidable (EquivBA (.wh b₁ body₁ : Exp A T) (.wh b₂ body₂)) :=
  @decidable_of_iff _ _
    ⟨chainloops_complete_free b₁ b₂ hc₁ hc₂,
      fun h X W gs => sound_BA (V := W) h gs⟩
    (uleDec _ _)

#print axioms ule_iff_start_bisim
#print axioms uleDec
#print axioms chainloops_equivBA_dec

/-! ## The whole ladder decides

    Every stratum with a completeness theorem inherits a certified
    decision procedure for provable equivalence — the same three-line
    pattern: completeness one way, soundness the other, `uleDec` in the
    middle. -/

/-- Loop-free provable equivalence is decidable. -/
def loopfree_equivBA_dec [DecidableEq T] [DecidableEq A]
    {e f : Exp A T} (he : LoopFree e) (hf : LoopFree f) :
    Decidable (EquivBA e f) :=
  @decidable_of_iff _ _
    ⟨loopfree_complete e f he hf, fun h X W gs => sound_BA (V := W) h gs⟩
    (uleDec e f)

/-- Atomic-loop provable equivalence is decidable. -/
def atomicloops_equivBA_dec [DecidableEq T] [DecidableEq A]
    {e f : Exp A T} (he : AtomicLoops e) (hf : AtomicLoops f) :
    Decidable (EquivBA e f) :=
  @decidable_of_iff _ _
    ⟨atomicloops_complete e f he hf,
      fun h X W gs => sound_BA (V := W) h gs⟩
    (uleDec e f)

/-- Guarded-one-action-loop provable equivalence is decidable. -/
def gloops_equivBA_dec [DecidableEq T] [DecidableEq A]
    {e f : Exp A T} (he : GLoops e) (hf : GLoops f) :
    Decidable (EquivBA e f) :=
  @decidable_of_iff _ _
    ⟨gloops_complete e f he hf, fun h X W gs => sound_BA (V := W) h gs⟩
    (uleDec e f)

#print axioms loopfree_equivBA_dec
#print axioms atomicloops_equivBA_dec
#print axioms gloops_equivBA_dec

end GkatDecide
