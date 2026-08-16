import GkatDupCoverProofs

/-!
# Refinement, as one relation

The search explores a refinement closure: start from a candidate program and apply three
moves — W1-unrolling, guard-split duplication, degree-`k` cyclic covering — anywhere inside
the term, repeatedly, until something covers the target.  Each move is now a cover in Lean.
This file makes the *closure* one object.

`Refines h e` says `h` is reachable from `e` by those moves under congruence and transitivity.
`cover_of_refines` proves that every such `h` covers `e`'s automaton, and `equivBA_of_refines`
that `e` and `h` are provably equal from the finite axioms.

Why bother, given the three moves individually.  The search's results are statements about
*this* relation: "W1+dup+cyc2 ×1 closes K=4 and K=5" is a claim that certain pairs are
related by `Refines`.  Naming it in Lean is what lets those results be quoted as facts about
a defined object rather than as properties of a Rust program.  It also makes the remaining
obligation sharp: `PullbackCovered` asks whether, for equivalent `e` and `f`, some `h` with
`Refines h e` covers the pullback — an existence statement over a relation that is now
defined, rather than over an informal notion of "refinement".

Nothing here needs a uniqueness axiom: each move carries its own cover, and covers compose.
-/

namespace GkatRefines

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatUnrollCover GkatCyclicCover GkatCyclicK GkatDupCover

variable {A T : Type}

/-- Reachability under the three refinement moves, closed under congruence and composition.

    The three generators are exactly the ones the search uses, and exactly one per case of
    the synthesis induction: `dup` for `ite`, `unroll` for `seq`, `cyc` for `wh`. -/
inductive Refines : Exp A T → Exp A T → Prop where
  | refl (e : Exp A T) : Refines e e
  | unroll (g : BExp T) (e : Exp A T) :
      Refines (.ite g (.seq e (.wh g e)) (.test BExp.one)) (.wh g e)
  | dup (g : BExp T) (e : Exp A T) : Refines (.ite g e e) e
  | cyc (g : BExp T) (e : Exp A T) (n : Nat) : Refines (.wh g (expK g e n)) (.wh g e)
  | seqL {e e' : Exp A T} (f : Exp A T) : Refines e' e → Refines (.seq e' f) (.seq e f)
  | seqR (e : Exp A T) {f f' : Exp A T} : Refines f' f → Refines (.seq e f') (.seq e f)
  | iteL (g : BExp T) {e e' : Exp A T} (f : Exp A T) :
      Refines e' e → Refines (.ite g e' f) (.ite g e f)
  | iteR (g : BExp T) (e : Exp A T) {f f' : Exp A T} :
      Refines f' f → Refines (.ite g e f') (.ite g e f)
  | whB (g : BExp T) {e e' : Exp A T} : Refines e' e → Refines (.wh g e') (.wh g e)
  | trans {a b c : Exp A T} : Refines a b → Refines b c → Refines a c

/-- **Every refinement is a cover.**  The three generators are `unrollCover`, `dupCover` and
    `cyclicCoverExp`; congruence is `InitCover.seq` / `.ite` / `.loop`; transitivity is
    `InitCover.comp`.  So the relation the search explores is exactly a relation of covers. -/
theorem cover_of_refines {h e : Exp A T} (r : Refines h e) :
    Nonempty (InitCover (certifiedThompson A T h).aut (certifiedThompson A T e).aut) := by
  induction r with
  | refl e => exact ⟨InitCover.id _⟩
  | unroll g e => exact ⟨unrollCover g (certifiedThompson A T e).aut⟩
  | dup g e => exact ⟨dupCover g (certifiedThompson A T e).aut⟩
  | cyc g e n => exact ⟨cyclicCoverExp g e n⟩
  | seqL f _ ih => obtain ⟨φ⟩ := ih; exact ⟨InitCover.seq φ (InitCover.id _)⟩
  | seqR e _ ih => obtain ⟨ψ⟩ := ih; exact ⟨InitCover.seq (InitCover.id _) ψ⟩
  | iteL g f _ ih => obtain ⟨φ⟩ := ih; exact ⟨InitCover.ite g φ (InitCover.id _)⟩
  | iteR g e _ ih => obtain ⟨ψ⟩ := ih; exact ⟨InitCover.ite g (InitCover.id _) ψ⟩
  | whB g _ ih => obtain ⟨φ⟩ := ih; exact ⟨InitCover.loop g φ⟩
  | trans _ _ ih₁ ih₂ =>
      obtain ⟨φ⟩ := ih₁
      obtain ⟨ψ⟩ := ih₂
      exact ⟨φ.comp ψ⟩

/-- **Refinement preserves provable equality.**  Recovered through the cover, so the moves
    need no separate axiomatic justification — and none of them is a uniqueness axiom. -/
theorem equivBA_of_refines {h e : Exp A T} (r : Refines h e) : EquivBA e h := by
  obtain ⟨φ⟩ := cover_of_refines r
  exact equivBA_of_common_refinement (InitCover.id (certifiedThompson A T h).aut) φ
    (InitCover.id _)

/-- **REFUTED BY SEARCH — recorded, not to be built on.**  For uniformly equivalent `e` and
    `f`, some refinement of `e` covers a system covering both.

    This was the shape of the synthesis plan: recurse on `e`, emitting refinements of `e`.
    It is too strong.  Restricting the search to start from `e` and `f` themselves — rather
    than from any program in the behaviour class, which is what every earlier measurement
    allowed — covers only **227 of 273** crux pullbacks, stable at 3, 4 and 5 rounds with a
    200000-term frontier.  Depth-saturated, so it is not a search artefact.

    Note that any `mid` covering both `e` and `f` factors through the pullback, so `h` covering
    `mid` forces `h` to cover the pullback; the measurement therefore tests exactly this
    statement and not something weaker.

    What survives is `GkatCommonTarget.PullbackCovered`: *some* Thompson automaton covers the
    pullback — 267 of 273 directly at K=6, the rest after one unrolling.  The covering program
    is simply not always reachable from either input by refinement, which is why the search
    always drew its candidates from the whole behaviour class.

    Kept because the negative result is the content: the induction cannot be "recurse on `e`
    emitting refinements of `e`". -/
def RefinementSuffices (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (S : Type) (mid : InitializedGAut S A T) (h : Exp A T),
      Refines h e ∧
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T f).aut) ∧
      Nonempty (InitCover (certifiedThompson A T h).aut mid)

/-- The implication is still true — it is the hypothesis that fails. -/
theorem completeness_of_refinementSuffices (hr : RefinementSuffices A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨S, mid, h, _, ⟨π₁⟩, ⟨π₂⟩, ⟨χ⟩⟩ := hr e f heq
  exact equivBA_of_common_refinement χ π₁ π₂

/-- Non-vacuity: a program refines itself, so the relation is inhabited on the diagonal. -/
theorem refinementSuffices_refl (e : Exp A T) :
    ∃ (S : Type) (mid : InitializedGAut S A T) (h : Exp A T),
      Refines h e ∧
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover (certifiedThompson A T h).aut mid) :=
  ⟨(certifiedThompson A T e).State, (certifiedThompson A T e).aut, e,
    Refines.refl e, ⟨InitCover.id _⟩, ⟨InitCover.id _⟩, ⟨InitCover.id _⟩⟩

#print axioms cover_of_refines
#print axioms equivBA_of_refines
#print axioms completeness_of_refinementSuffices

end GkatRefines
