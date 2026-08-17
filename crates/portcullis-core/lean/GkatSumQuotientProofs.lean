import GkatTotalizationProofs

/-!
# The open conjunct, restated on the weaker hypothesis

This development has carried `ReachListCovered` as its single open conjunct: the pullback,
listed on its reachable states, is Thompson-**covered**.  Measurement no longer supports that
as the right target.  At `K = 5` it holds for 4288/4679 = 91.6%; at `K = 6`, on a much larger
instance space, the union of both routes reaches only 68244/113795 = **60.0%**.  A rate that
falls that far as the space grows is what a real gap looks like, not only a search-budget one.

The hypothesis actually consumed by the completeness reduction is weaker.  It asks not for a
cover but for a **solution**: an assignment of expressions to the states of a behavioural
quotient of `Me + Mf` satisfying that quotient's equations.  No surjection from a Thompson
automaton is required.  Measured with a procedure that is sound — it rejects 5000/5000
non-nested automata, which provably have no solution since the nesting coequation is an iff,
and it rejects the Figure 3 automaton — sum-quotient solvability holds on 9221/9245 = 99.7%
of instances, against 45.4% for arbitrary (non-equivalent) pairs of Thompson automata drawn
from the same population.

So this file swaps the open conjunct.  `SumQuotientSolvable` is the hypothesis, and
`completeness_of_sumQuotientSolvable` is the reduction, proved.

What makes the swap non-trivial is the pseudostate.  A Thompson automaton's start is *not* a
core state: `InitializedGAut.toGAut` adjoins it as `none`, with `hlt none = initHlt` and
`trans none = initTrans`.  The uniqueness theorem available here,
`certifiedThompson_solution_unique`, speaks about core states, while the reduction needs the
value at `none`.  The bridge is `certifiedThompson_initial_canonical`, and connecting them
needs the observation that `eqRHS` and `eqRHSParam` are the same fold over the same branches,
differing only in the fallback — `test h` versus `seq (test h) (test 1)` — which S5 identifies.
-/

namespace GkatSumQuotient

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSynthesis

variable {A T S : Type}

/-! ## The two folds agree -/

/-- `guardedFold` over `transitionBranches` is the same right fold `eqRHS` performs.  Both are
    `foldr` over the transition list; this fuses the intervening `map`. -/
theorem guardedFold_transitionBranches (l : List (BExp T × A × S))
    (sol : S → Exp A T) (fallback : Exp A T) :
    guardedFold (transitionBranches l sol) fallback =
      l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) fallback := by
  induction l with
  | nil => rfl
  | cons head tail ih =>
      exact congrArg (fun r => Exp.ite head.1 (.seq (.act head.2.1) (sol head.2.2)) r) ih

/-- `eqRHS` unfolded to its fold. -/
theorem eqRHS_fold (aut : GAut S A T) (sol : S → Exp A T) (s : S) :
    eqRHS aut sol s =
      (aut.trans s).foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc)
        (.test (aut.hlt s)) := rfl

/-- `eqRHSParam` unfolded to the same fold, with the parameterised fallback. -/
theorem eqRHSParam_fold (aut : GSystem S A T) (sol : S → Exp A T)
    (finish : Exp A T) (s : S) :
    eqRHSParam aut sol finish s =
      (aut.trans s).foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc)
        (paramFallback (aut.hlt s) finish) :=
  guardedFold_transitionBranches _ _ _

/-- Retagging the targets with `some` before folding is folding through `some`. -/
theorem foldr_map_some (l : List (BExp T × A × S)) (sol : Option S → Exp A T)
    (fb : Exp A T) :
    (l.map (fun t => (t.1, t.2.1, some t.2.2))).foldr
        (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) fb =
      l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol (some t.2.2))) acc) fb := by
  induction l with
  | nil => rfl
  | cons head tail ih =>
      exact congrArg
        (fun r => Exp.ite head.1 (.seq (.act head.2.1) (sol (some head.2.2))) r) ih

/-- Changing the fallback under a provable equality changes the fold under one. -/
theorem foldr_fallback_congr (l : List (BExp T × A × S)) (sol : S → Exp A T)
    {b₁ b₂ : Exp A T} (h : EquivBA b₁ b₂) :
    EquivBA (l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) b₁)
      (l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) b₂) := by
  induction l with
  | nil => exact h
  | cons _ _ ih => exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih

/-- The fallback of `eqRHS` and the fallback of `eqRHSParam` at ending `1` agree, by S5. -/
theorem fallback_equiv (halt : BExp T) :
    EquivBA (.test halt : Exp A T) (paramFallback halt (.test .one)) :=
  EquivBA.symm (EquivBA.base (Equiv.s5 (.test halt)))

/-! ## A solution of `toGAut` is a Thompson solution, plus a value at the pseudostate -/

/-- On core states, `eqRHS` of the pseudostate-extended automaton is `eqRHSParam` of the core
    at ending `1`. -/
theorem eqRHS_some (aut : InitializedGAut S A T)
    (sol : Option S → Exp A T) (state : S) :
    EquivBA (eqRHS aut.toGAut sol (some state))
      (eqRHSParam aut.core (fun s => sol (some s)) (.test .one) state) := by
  rw [eqRHS_fold, eqRHSParam_fold]
  simp only [InitializedGAut.toGAut]
  rw [foldr_map_some]
  exact foldr_fallback_congr _ (fun s => sol (some s)) (fallback_equiv _)

/-- At the pseudostate, `eqRHS` is `initRHSParam` at ending `1`. -/
theorem eqRHS_none (aut : InitializedGAut S A T) (sol : Option S → Exp A T) :
    EquivBA (eqRHS aut.toGAut sol none)
      (initRHSParam aut (fun s => sol (some s)) (.test .one)) := by
  rw [eqRHS_fold, initRHSParam, guardedFold_transitionBranches]
  simp only [InitializedGAut.toGAut]
  rw [foldr_map_some]
  exact foldr_fallback_congr _ (fun s => sol (some s)) (fallback_equiv _)

/-- **The restriction is a Thompson solution.**  Solving the pseudostate-extended system
    entails solving the core system at ending `1`. -/
theorem thompsonSolves_of_solvesBA (aut : InitializedGAut S A T)
    (sol : Option S → Exp A T) (hsol : SolvesBA aut.toGAut sol) :
    ThompsonSolvesBA aut.core (fun s => sol (some s)) := by
  intro state hstate
  have hmem : (some state) ∈ aut.toGAut.states :=
    List.mem_cons_of_mem _ (List.mem_map_of_mem hstate)
  exact EquivBA.trans (hsol (some state) hmem) (eqRHS_some aut sol state)

/-- **The pseudostate carries the program.**  Any solution of the extended system assigns to
    `none` an expression provably equal to the program itself — which is what the completeness
    reduction needs and what the core uniqueness theorem does not directly give. -/
theorem sol_none_equiv (program : Exp A T)
    (sol : Option (certifiedThompson A T program).State → Exp A T)
    (hsol : SolvesBA (certifiedThompson A T program).aut.toGAut sol) :
    EquivBA (sol none) program := by
  have hcore : ThompsonSolvesBA (certifiedThompson A T program).aut.core
      (fun s => sol (some s)) :=
    thompsonSolves_of_solvesBA _ sol hsol
  have hnone : none ∈ (certifiedThompson A T program).aut.toGAut.states := List.mem_cons_self
  have h₁ : EquivBA (sol none)
      (initRHSParam (certifiedThompson A T program).aut
        (fun s => sol (some s)) (.test .one)) :=
    EquivBA.trans (hsol none hnone) (eqRHS_none _ sol)
  have h₂ := certifiedThompson_initial_canonical program (.test .one)
    (fun s => sol (some s)) hcore
  exact EquivBA.trans (EquivBA.trans h₁ h₂) (EquivBA.base (Equiv.s5 program))

/-! ## The swap -/

/-- **The open conjunct, weakened.**  For uniformly equivalent `e` and `f`, some behavioural
    quotient of `Me + Mf` identifying the two starts has a solution.

    Weaker than `ReachListCovered` in two independent ways: it asks for a solution rather than
    a cover, and it says nothing about the covering automaton being Thompson.  Measured at
    9221/9245 = 99.7% by a sound procedure, against 45.4% for non-equivalent pairs from the
    same population, and against `ReachListCovered`'s 60.0% at `K = 6`. -/
def SumQuotientSolvable (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (Q : Type) (quot : GAut Q A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T f).aut.toGAut) quot)
      (qsol : Q → Exp A T),
      SolvesBA quot qsol ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none)

/-- **The reduction, proved.**  Solvability of the sum-quotient gives completeness of the
    finite axioms.  No uniqueness axiom appears: uniqueness is used only where it is already a
    theorem here, at Thompson-generated automata, and enters through
    `certifiedThompson_initial_canonical` via `sol_none_equiv`. -/
theorem completeness_of_sumQuotientSolvable (h : SumQuotientSolvable A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨Q, quot, π, qsol, hqsol, hstart⟩ := h e f heq
  have hsum : SolvesBA
      (sumGAut (certifiedThompson A T e).aut.toGAut (certifiedThompson A T f).aut.toGAut)
      (fun s => qsol (π.mapState s)) := π.lift_solvesBA hqsol
  have hleft : SolvesBA (certifiedThompson A T e).aut.toGAut
      (fun s => qsol (π.mapState (Sum.inl s))) :=
    (GAutHom.inl _ _).lift_solvesBA hsum
  have hright : SolvesBA (certifiedThompson A T f).aut.toGAut
      (fun s => qsol (π.mapState (Sum.inr s))) :=
    (GAutHom.inr _ _).lift_solvesBA hsum
  have he : EquivBA (qsol (π.mapState (Sum.inl none))) e := sol_none_equiv e _ hleft
  have hf : EquivBA (qsol (π.mapState (Sum.inr none))) f := sol_none_equiv f _ hright
  rw [hstart] at he
  exact EquivBA.trans (EquivBA.symm he) hf

#print axioms guardedFold_transitionBranches
#print axioms thompsonSolves_of_solvesBA
#print axioms sol_none_equiv
#print axioms completeness_of_sumQuotientSolvable

end GkatSumQuotient
