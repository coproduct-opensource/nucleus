import GkatRingPlan2Proofs

/-! # Compositional rings: exit arms to external continuations

    `GkatRingPlan2` proves closed rings.  Real quotients are DAGs of components: rings
    whose members may also EXIT to states of later components (the k=6 census's
    `Inline`), plus straight-line and level states.  This file supplies the ring layer
    of that composition: node equations RELATIVE to arbitrary continuation
    expressions.

    The continuation style keeps exits free: an exit arm `(exitA ; K)` in the solution
    matches the equation's transition arm by refl.  The single obligation exits add is
    at the header's spine — pushing `solH` through the raw walk meets `(exitA ; K) ;
    solH`, which must collapse to `exitA ; K`; the hypothesis `K ; solH ≡ K` is the
    classifier's exit-closure condition ("every halt reachable through the exit lies
    below the ring's exit guard"), in equational form. -/

namespace GkatRingDecomp

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatRingSupport GkatGuardedAlgebra
open GkatResidue GkatRingPlan GkatRingPlan2

variable {A T : Type}

/-- A walk node with external exits: like `GkatRingPlan2.Node` plus a list of exit
    arms, each carrying its guard, action, and the CONTINUATION EXPRESSION it hands
    control to (an already-solved state's solution). -/
structure ExtNode (A T : Type) where
  loopG : BExp T
  loopA : A
  loopW : List (FlatNode A T)
  exits : List (BExp T × A × Exp A T)
  stepG : BExp T
  stepA : A
  hltG : BExp T

/-- The exit-dispatch chain around a tail expression. -/
def exitFold (xs : List (BExp T × A × Exp A T)) (tail : Exp A T) : Exp A T :=
  xs.foldr (fun x acc => .ite x.1 (.seq (.act x.2.1) x.2.2) acc) tail

/-- An ext node's solution, given the next state's. -/
def extSol (n : ExtNode A T) (next : Exp A T) : Exp A T :=
  .seq (.wh n.loopG (loopRaw n.loopA n.loopW))
    (exitFold n.exits (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG)))

/-- **The ext-node equation** — still just one salomaa unroll (exit arms and the halt
    arm are refl against the equation's own arms), with the sub-loop spine when the
    local loop is compound. -/
theorem extSol_solves (n : ExtNode A T) (next : Exp A T)
    (hdead : ∀ g ∈ n.loopW, GuardEmpty g.hltG) :
    EquivBA (extSol n next)
      (.ite n.loopG
        (.seq (.act n.loopA) (innerSuffix n.loopW (extSol n next)))
        (exitFold n.exits
          (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG)))) :=
  EquivBA.trans
    (EquivBA.base (salomaa_solution_exists n.loopG (loopRaw n.loopA n.loopW)
      (exitFold n.exits (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG)))))
    (EquivBA.ite_c (loopRaw_spine n.loopA n.loopW (extSol n next) hdead)
      (EquivBA.base (Equiv.refl _)))

/-- The raw walk with exits, continuation-nested; the terminal step returns to the
    header. -/
def extWalkRaw : List (ExtNode A T) → Exp A T
  | [] => .test .one
  | [n] =>
      .seq (.wh n.loopG (loopRaw n.loopA n.loopW))
        (exitFold n.exits (.ite n.stepG (.act n.stepA) (.test n.hltG)))
  | n :: r =>
      .seq (.wh n.loopG (loopRaw n.loopA n.loopW))
        (exitFold n.exits
          (.ite n.stepG (.seq (.act n.stepA) (extWalkRaw r)) (.test n.hltG)))

/-- Walk suffix solutions down to the header's. -/
def extWalkSuffix (ns : List (ExtNode A T)) (solH : Exp A T) : Exp A T :=
  match ns with
  | [] => solH
  | n :: r => extSol n (extWalkSuffix r solH)

/-- Pushing a continuation through an exit fold: `u5` per arm, with each exit's
    absorption hypothesis at its arm and the given lemma at the tail. -/
theorem exitFold_push (xs : List (BExp T × A × Exp A T)) (tail solH : Exp A T)
    (tail' : Exp A T)
    (habsx : ∀ x ∈ xs, EquivBA (.seq x.2.2 solH) x.2.2)
    (htail : EquivBA (.seq tail solH) tail') :
    EquivBA (.seq (exitFold xs tail) solH) (exitFold xs tail') := by
  induction xs with
  | nil => exact htail
  | cons x r ih =>
      refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 x.1
        (.seq (.act x.2.1) x.2.2) (exitFold r tail) solH))) ?_
      refine EquivBA.ite_c ?_ (ih (fun y hy => habsx y (List.mem_cons_of_mem x hy)))
      refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act x.2.1) x.2.2 solH)) ?_
      exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (habsx x List.mem_cons_self)

/-- **The ext tree-spine**: as in `GkatRingPlan2.walkRaw_spine`, with the exit arms
    absorbed through their continuation hypotheses. -/
theorem extWalkRaw_spine (solH : Exp A T) (ns : List (ExtNode A T))
    (habs : ∀ n ∈ ns, EquivBA (.seq (.test n.hltG) solH) (.test n.hltG))
    (habsx : ∀ n ∈ ns, ∀ x ∈ n.exits, EquivBA (.seq x.2.2 solH) x.2.2) :
    ns ≠ [] →
    EquivBA (.seq (extWalkRaw ns) solH) (extWalkSuffix ns solH) := by
  induction ns with
  | nil => intro h; exact absurd rfl h
  | cons n r ih =>
      intro _
      have hn := habs n List.mem_cons_self
      have hnx := habsx n List.mem_cons_self
      cases r with
      | nil =>
          refine EquivBA.trans (EquivBA.base (Equiv.s1
            (.wh n.loopG (loopRaw n.loopA n.loopW))
            (exitFold n.exits (.ite n.stepG (.act n.stepA) (.test n.hltG)))
            solH)) ?_
          refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
          refine exitFold_push n.exits _ solH _ hnx ?_
          refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 n.stepG
            (.act n.stepA) (.test n.hltG) solH))) ?_
          exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) hn
      | cons m s =>
          refine EquivBA.trans (EquivBA.base (Equiv.s1
            (.wh n.loopG (loopRaw n.loopA n.loopW))
            (exitFold n.exits
              (.ite n.stepG (.seq (.act n.stepA) (extWalkRaw (m :: s))) (.test n.hltG)))
            solH)) ?_
          refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
          refine exitFold_push n.exits _ solH _ hnx ?_
          refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 n.stepG
            (.seq (.act n.stepA) (extWalkRaw (m :: s))) (.test n.hltG) solH))) ?_
          refine EquivBA.ite_c ?_ hn
          refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act n.stepA)
            (extWalkRaw (m :: s)) solH)) ?_
          exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (ih (fun q hq => habs q (List.mem_cons_of_mem n hq))
                (fun q hq => habsx q (List.mem_cons_of_mem n hq)) (by simp))

/-- A compositional ring: header data plus the ext walk. -/
structure ExtRing (A T : Type) where
  hLoopG : BExp T
  hLoopA : A
  hLoopW : List (FlatNode A T)
  hStepG : BExp T
  hStepA : A
  exitG : BExp T
  nodes : List (ExtNode A T)

def extBody (R : ExtRing A T) : Exp A T :=
  .ite R.hLoopG (loopRaw R.hLoopA R.hLoopW)
    (match R.nodes with
     | [] => .act R.hStepA
     | n :: r => .seq (.act R.hStepA) (extWalkRaw (n :: r)))

def extHeaderSol (R : ExtRing A T) : Exp A T :=
  .seq (.wh (.or R.hStepG R.hLoopG) (extBody R)) (.test R.exitG)

/-- **The compositional header obligation.**  Identical in shape to the closed case;
    exits contribute only their absorption hypotheses. -/
theorem extHeaderSol_solves (R : ExtRing A T)
    (hdisj : GuardDisjoint R.hStepG R.hLoopG)
    (n0 : ExtNode A T) (r : List (ExtNode A T)) (hns : R.nodes = n0 :: r)
    (habs : ∀ n ∈ R.nodes,
      EquivBA (.seq (.test n.hltG) (extHeaderSol R)) (.test n.hltG))
    (habsx : ∀ n ∈ R.nodes, ∀ x ∈ n.exits,
      EquivBA (.seq x.2.2 (extHeaderSol R)) x.2.2)
    (hdead : ∀ g ∈ R.hLoopW, GuardEmpty g.hltG) :
    EquivBA (extHeaderSol R)
      (.ite R.hStepG (.seq (.act R.hStepA) (extWalkSuffix R.nodes (extHeaderSol R)))
        (.ite R.hLoopG
          (.seq (.act R.hLoopA) (innerSuffix R.hLoopW (extHeaderSol R)))
          (.test R.exitG))) := by
  have hbody : extBody R
      = .ite R.hLoopG (loopRaw R.hLoopA R.hLoopW)
          (.seq (.act R.hStepA) (extWalkRaw (n0 :: r))) := by
    unfold extBody
    rw [hns]
  refine EquivBA.trans (EquivBA.base (salomaa_solution_exists
    (.or R.hStepG R.hLoopG) (extBody R) (.test R.exitG))) ?_
  refine EquivBA.trans (ite_or_split R.hStepG R.hLoopG
    (.seq (extBody R) (extHeaderSol R)) (.test R.exitG)) ?_
  have h_step : EquivBA (.seq (.test R.hStepG) (.seq (extBody R) (extHeaderSol R)))
      (.seq (.test R.hStepG)
        (.seq (.act R.hStepA) (extWalkSuffix R.nodes (extHeaderSol R)))) := by
    have hsel : EquivBA (.seq (.test R.hStepG) (extBody R))
        (.seq (.test R.hStepG) (.seq (.act R.hStepA) (extWalkRaw (n0 :: r)))) := by
      rw [hbody]
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.base (Equiv.u2 R.hLoopG (loopRaw R.hLoopA R.hLoopW)
          (.seq (.act R.hStepA) (extWalkRaw (n0 :: r)))))) ?_
      exact test_seq_ite_of_implies _ _ hdisj.implies_not
    refine EquivBA.trans (seq_under_guard (extHeaderSol R) hsel) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act R.hStepA)
      (extWalkRaw (n0 :: r)) (extHeaderSol R))) ?_
    rw [hns]
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
    exact extWalkRaw_spine (extHeaderSol R) (n0 :: r)
      (by rw [← hns]; exact habs) (by rw [← hns]; exact habsx) (by simp)
  have h_loop : EquivBA (.seq (.test R.hLoopG) (.seq (extBody R) (extHeaderSol R)))
      (.seq (.test R.hLoopG)
        (.seq (.act R.hLoopA) (innerSuffix R.hLoopW (extHeaderSol R)))) := by
    have hsel : EquivBA (.seq (.test R.hLoopG) (extBody R))
        (.seq (.test R.hLoopG) (loopRaw R.hLoopA R.hLoopW)) := by
      rw [hbody]
      exact test_seq_ite_of_implies _ _ (himp_self R.hLoopG)
    refine EquivBA.trans (seq_under_guard (extHeaderSol R) hsel) ?_
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (loopRaw_spine R.hLoopA R.hLoopW (extHeaderSol R) hdead)
  exact EquivBA.trans (ite_congr_under_guard h_step)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ite_congr_under_guard h_loop))

#print axioms extHeaderSol_solves
#print axioms extSol_solves
#print axioms extWalkRaw_spine

end GkatRingDecomp
