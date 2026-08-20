import GkatRingDecompProofs

/-! # The decomposition theorem

    The composition pilot showed each state of a mixed quotient closes by exactly one
    library lemma once its solution and equation carry the API shapes.  This file
    packages that as the general theorem: a `StateRole` witness per state — fold,
    ring member (`extSol`-shaped, which subsumes inner nodes and levels), or ring
    header — implies `SolvesBA`.

    All structure lives in the witness fields (equalities between the automaton's
    equations and the API forms, plus the `bval`-level side conditions); the theorem
    itself is the case dispatch.  Emitted instances discharge the equalities by `rfl`
    against assembled automata; the plan-existence programme will construct witnesses
    for canonical quotients. -/

namespace GkatDecomp

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatRingSupport GkatGuardedAlgebra
open GkatResidue GkatRingPlan GkatRingPlan2 GkatRingDecomp GkatThompson

variable {S A T : Type}

/-- The role a state plays in a decomposition of `aut` solved by `sol`. -/
inductive StateRole (aut : GAut S A T) (sol : S → Exp A T) (s : S) : Prop where
  /-- A fold state: its solution is literally its equation. -/
  | fold (h : sol s = eqRHS aut sol s)
  /-- The fully general escape hatch: the solution provably satisfies its
      equation.  Witnesses are whole `EquivBA` derivations (e.g. the cycle
      strata's chain collapses). -/
  | equivFold (h : EquivBA (sol s) (eqRHS aut sol s))
  /-- A ring member (also covers inner nodes and level states): `extSol`-shaped
      solution, equation in the corresponding dispatch form. -/
  | member (n : ExtNode A T) (next : Exp A T)
      (hsol : sol s = extSol n next)
      (hrhs : eqRHS aut sol s
        = .ite n.loopG (.seq (.act n.loopA) (innerSuffix n.loopW (extSol n next)))
            (exitFold n.exits
              (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG))))
      (hdead : ∀ g ∈ n.loopW, GuardEmpty g.hltG)
  /-- A Salomaa self-loop state: a single self-arm at the head of its dispatch.
      Closes by `salomaa_solution_exists` alone — no side conditions. -/
  | selfLoop (g : BExp T) (p : A) (rest : Exp A T)
      (hsol : sol s = .seq (.wh g (.act p)) rest)
      (hrhs : eqRHS aut sol s = .ite g (.seq (.act p) (sol s)) rest)
  /-- A Salomaa state up to provable equation massage: the dispatch is
      EquivBA-equal to a single guarded self-call.  Subsumes `selfLoop`; the
      gathering algebra (arm commutation) produces these for self-arms in any
      position. -/
  | salomaaE (G : BExp T) (BODY rest : Exp A T)
      (hsol : sol s = .seq (.wh G BODY) rest)
      (hrhs : EquivBA (eqRHS aut sol s)
        (.ite G (.seq BODY (sol s)) rest))
  /-- A ring header: `extHeaderSol`-shaped solution, with the ring's side
      conditions — guard disjointness, member-halt subset parking, and exit
      absorption. -/
  | header (R : ExtRing A T) (n0 : ExtNode A T) (r : List (ExtNode A T))
      (hns : R.nodes = n0 :: r)
      (hsol : sol s = extHeaderSol R)
      (hrhs : eqRHS aut sol s
        = .ite R.hStepG
            (.seq (.act R.hStepA) (extWalkSuffix R.nodes (extHeaderSol R)))
            (.ite R.hLoopG
              (.seq (.act R.hLoopA) (innerSuffix R.hLoopW (extHeaderSol R)))
              (.test R.exitG)))
      (hdisj : GuardDisjoint R.hStepG R.hLoopG)
      (habs : ∀ n ∈ R.nodes,
        EquivBA (.seq (.test n.hltG) (extHeaderSol R)) (.test n.hltG))
      (habsx : ∀ n ∈ R.nodes, ∀ x ∈ n.exits,
        EquivBA (.seq x.2.2 (extHeaderSol R)) x.2.2)
      (hdeadH : ∀ g ∈ R.hLoopW, GuardEmpty g.hltG)

/-- **THE DECOMPOSITION THEOREM**: role witnesses for every state give a solution of
    the whole automaton in the finite axioms. -/
theorem decomp_solves (aut : GAut S A T) (sol : S → Exp A T)
    (h : ∀ s ∈ aut.states, StateRole aut sol s) : SolvesBA aut sol := by
  intro s hs
  cases h s hs with
  | fold hf =>
      rw [hf]
      exact EquivBA.base (Equiv.refl _)
  | equivFold hf => exact hf
  | member n next hsol hrhs hdead =>
      rw [hsol, hrhs]
      exact extSol_solves n next hdead
  | selfLoop g p rest hsol hrhs =>
      rw [hrhs, hsol]
      exact EquivBA.base (salomaa_solution_exists g (.act p) rest)
  | salomaaE G BODY rest hsol hrhs =>
      refine EquivBA.trans ?_ (EquivBA.symm hrhs)
      rw [hsol]
      exact EquivBA.base (salomaa_solution_exists G BODY rest)
  | header R n0 r hns hsol hrhs hdisj habs habsx hdeadH =>
      rw [hsol, hrhs]
      exact extHeaderSol_solves R hdisj n0 r hns habs habsx hdeadH

#print axioms decomp_solves

/-! ## The summit, conditionally: the open problem reduced to plan existence -/

open GkatSumQuotient in
/-- **The plan-existence hypothesis — REFUTED as stated.**
    `GkatPlanExistence.decompCovered_false` proves `¬ DecompCovered Unit Unit`:
    merged starts force the starts bisimilar, and `a·0` vs `0` are language-equal
    with non-bisimilar starts (a silent transition).  The live formulation is
    `GkatPlanExistence.DecompCoveredTrim` (trim as a hypothesis) together with
    `NormalizationBridge`; see `completeness_of_decompCoveredTrim`.  Kept for the
    record and because `completeness_of_decompCovered` below is still a true
    (now vacuous-hypothesis) conditional. -/
def DecompCovered (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (Q : Type) (quot : GAut Q A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T f).aut.toGAut) quot)
      (qsol : Q → Exp A T),
      (∀ s ∈ quot.states, StateRole quot qsol s) ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none)

open GkatSumQuotient in
theorem sumQuotientSolvable_of_decompCovered {A T : Type}
    (h : DecompCovered A T) : SumQuotientSolvable A T := by
  intro e f heq
  obtain ⟨Q, quot, π, qsol, hroles, hstart⟩ := h e f heq
  exact ⟨Q, quot, π, qsol, decomp_solves quot qsol hroles, hstart⟩

open GkatSumQuotient in
/-- **The conditional summit**: plan existence implies UA-free completeness of GKAT
    over the free Boolean algebra, for every action and test alphabet. -/
theorem completeness_of_decompCovered {A T : Type}
    (h : DecompCovered A T) : FiniteAxiomsCompleteBA A T :=
  completeness_of_sumQuotientSolvable (sumQuotientSolvable_of_decompCovered h)

#print axioms completeness_of_decompCovered

end GkatDecomp
