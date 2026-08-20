import GkatTwoLoopProofs

/-! # The chord frontier: a mid-chain skippable inner loop

    `wh b (p; (wh c q); r)` is the minimal program BEYOND the walked
    discipline: the `p`-state branches per atom to TWO forward cycle
    positions — enter the inner loop (`c`) or skip it (`¬c`).  Its cycle
    `p → q → r → p` carries the chord `p → r`.  This file grounds the
    branching frontier: the concrete automaton, its halt structure, and
    its per-region steps — the test bed for the branching-successor
    discipline and the chord-cycle role. -/

namespace GkatThreeLoop

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop GkatChainLoop GkatOrbit
open GkatChainFragment GkatWalkedOrbit GkatTwoLoop

variable {A T : Type}

/-- The chord body: an action, a skippable atomic loop, an action. -/
def threeLoopBody (c : BExp T) (p q r : A) : Exp A T :=
  .seq (.act p) (.seq (.wh c (.act q)) (.act r))

/-- The chord program. -/
def threeLoop (b c : BExp T) (p q r : A) : Exp A T :=
  .wh b (threeLoopBody c p q r)

/-- Its loop automaton.  States: `inl () = pState` (post-`p`),
    `inr (inl ()) = qState` (the inner loop), `inr (inr ()) = rState`
    (the port). -/
def threeLoopAut (b c : BExp T) (p q r : A) :
    InitializedGAut (Sum Unit (Sum Unit Unit)) A T :=
  loopInitialized b (certifiedThompson A T (threeLoopBody c p q r)).aut

/-- **THE BRANCH**: at a `c`-atom, `pState` enters the inner loop. -/
theorem threeLoop_step_p_enter (b c : BExp T) (p q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α
        ((threeLoopAut b c p q r).core.trans (Sum.inl ()))
      = some (q, Sum.inr (Sum.inl ())) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inr (Sum.inl ()))
    else _) = some (q, Sum.inr (Sum.inl ()))
  rw [hc]
  rfl

/-- **THE CHORD**: at a `¬c`-atom, `pState` skips to the port. -/
theorem threeLoop_step_p_skip (b c : BExp T) (p q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α
        ((threeLoopAut b c p q r).core.trans (Sum.inl ()))
      = some (r, Sum.inr (Sum.inr ())) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inr (Sum.inl ()))
    else if ((true && !(bval (genW T) c α)) && true) = true
      then some (r, Sum.inr (Sum.inr ()))
      else _) = some (r, Sum.inr (Sum.inr ()))
  rw [hc]
  rfl

/-- Inner self-step at a `c`-atom. -/
theorem threeLoop_step_q_self (b c : BExp T) (p q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α
        ((threeLoopAut b c p q r).core.trans (Sum.inr (Sum.inl ())))
      = some (q, Sum.inr (Sum.inl ())) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inr (Sum.inl ()))
    else _) = some (q, Sum.inr (Sum.inl ()))
  rw [hc]
  rfl

/-- Inner advance to the port at a `¬c`-atom. -/
theorem threeLoop_step_q_adv (b c : BExp T) (p q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α
        ((threeLoopAut b c p q r).core.trans (Sum.inr (Sum.inl ())))
      = some (r, Sum.inr (Sum.inr ())) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inr (Sum.inl ()))
    else if ((true && !(bval (genW T) c α)) && true) = true
      then some (r, Sum.inr (Sum.inr ()))
      else _) = some (r, Sum.inr (Sum.inr ()))
  rw [hc]
  rfl

/-- Port feedback to `pState` at a `b`-atom — deterministic, no
    branching at the port. -/
theorem threeLoop_step_r_feed (b c : BExp T) (p q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    firstMatch (genW T) α
        ((threeLoopAut b c p q r).core.trans (Sum.inr (Sum.inr ())))
      = some (p, Sum.inl ()) := by
  show (if (true && (bval (genW T) b α && true)) = true
    then some (p, Sum.inl ())
    else _) = some (p, Sum.inl ())
  rw [hb]
  rfl

/-- Port rest at a `¬b`-atom. -/
theorem threeLoop_step_r_none (b c : BExp T) (p q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α
        ((threeLoopAut b c p q r).core.trans (Sum.inr (Sum.inr ())))
      = none := by
  show (if (true && (bval (genW T) b α && true)) = true
    then some (p, Sum.inl ())
    else if (true && (bval (genW T) b α
        && (false && (bval (genW T) c α && true)))) = true
      then some (q, Sum.inr (Sum.inl ()))
      else if (true && (bval (genW T) b α
          && (false && (!(bval (genW T) c α) && true)))) = true
        then some (r, Sum.inr (Sum.inr ()))
        else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

/-- `pState` never halts. -/
theorem threeLoop_hlt_p (b c : BExp T) (p q r : A) :
    ∀ α : T → Bool,
      bval (genW T)
        ((threeLoopAut b c p q r).core.hlt (Sum.inl ())) α = false := by
  intro α
  show ((true && ((true && !(bval (genW T) c α)) && false))
    && !(bval (genW T) b α)) = false
  cases bval (genW T) c α <;> cases bval (genW T) b α <;> rfl

/-- `qState` never halts. -/
theorem threeLoop_hlt_q (b c : BExp T) (p q r : A) :
    ∀ α : T → Bool,
      bval (genW T)
        ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inl ()))) α
        = false := by
  intro α
  show (((true && !(bval (genW T) c α)) && false)
    && !(bval (genW T) b α)) = false
  cases bval (genW T) c α <;> cases bval (genW T) b α <;> rfl

/-- The port halts exactly at `¬b`. -/
theorem threeLoop_hlt_r (b c : BExp T) (p q r : A) :
    ∀ α : T → Bool,
      bval (genW T)
        ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) α
        = !(bval (genW T) b α) := by
  intro α
  show (true && !(bval (genW T) b α)) = !(bval (genW T) b α)
  cases bval (genW T) b α <;> rfl

#print axioms threeLoop_step_p_enter
#print axioms threeLoop_step_p_skip
#print axioms threeLoop_hlt_p

/-! ## THE CHORD-CYCLE ROLE

    The elimination order dissolves the chord: the inner self-loop `Q`
    solves locally (Salomaa), the branch state `P` is then a loop-free
    dispatch into solved parts (fold), and the port `R` — whose closed
    solution is ONE while-loop over the full lap body — satisfies its
    equation by `w1`-unrolling plus distribution.  No axiom beyond the
    finite system; `w3`'s one-unknown power carried by `salomaaE`. -/

open Classical in
/-- The lap prefix: everything from `P` back to the port. -/
def chordPre (cG : BExp T) (qB rB : Exp A T) : Exp A T :=
  .ite cG (.seq qB (.seq (.wh cG qB) rB)) rB

open Classical in
/-- **THE CHORD-CYCLE ROLES**: closed solutions built by reverse
    elimination satisfy all three equations. -/
theorem chord3_roles {S : Type} (aut : GAut S A T) (sol : S → Exp A T)
    (P Q R : S) (bG cG : BExp T) (pB qB rB : Exp A T)
    (hsolQ : sol Q = .seq (.wh cG qB) (.seq rB (sol R)))
    (hsolP : sol P = .ite cG (.seq qB (sol Q)) (.seq rB (sol R)))
    (hsolR : sol R
      = .wh bG (.seq pB (chordPre cG qB rB)))
    (hrhsQ : EquivBA (eqRHS aut sol Q)
      (.ite cG (.seq qB (sol Q)) (.seq rB (sol R))))
    (hrhsP : EquivBA (eqRHS aut sol P)
      (.ite cG (.seq qB (sol Q)) (.seq rB (sol R))))
    (hrhsR : EquivBA (eqRHS aut sol R)
      (.ite bG (.seq pB (sol P)) (.test .one))) :
    StateRole aut sol P ∧ StateRole aut sol Q
      ∧ StateRole aut sol R := by
  have hsolR' : EquivBA (sol R)
      (.ite bG (.seq (.seq pB (chordPre cG qB rB)) (sol R))
        (.test .one)) := by
    rw [hsolR]
    exact EquivBA.base (Equiv.w1 bG (.seq pB (chordPre cG qB rB)))
  have hPfactor : EquivBA
      (.seq (chordPre cG qB rB) (sol R)) (sol P) := by
    show EquivBA
      (.seq (.ite cG (.seq qB (.seq (.wh cG qB) rB)) rB) (sol R)) _
    refine EquivBA.trans (EquivBA.symm
      (EquivBA.base (Equiv.u5 cG (.seq qB (.seq (.wh cG qB) rB)) rB
        (sol R)))) ?_
    rw [hsolP]
    refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
    refine EquivBA.trans
      (EquivBA.base (Equiv.s1 qB (.seq (.wh cG qB) rB) (sol R))) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl qB)) ?_
    rw [hsolQ]
    exact EquivBA.base (Equiv.s1 (.wh cG qB) rB (sol R))
  refine ⟨?_, ?_, ?_⟩
  · -- P: its solution IS its dispatch
    refine StateRole.equivFold ?_
    refine EquivBA.trans ?_ hrhsP.symm
    rw [hsolP]
    exact EquivBA.base (Equiv.refl _)
  · -- Q: Salomaa
    exact StateRole.salomaaE cG qB (.seq rB (sol R)) hsolQ hrhsQ
  · -- R: unroll the lap
    refine StateRole.equivFold ?_
    refine EquivBA.trans ?_ hrhsR.symm
    refine EquivBA.trans hsolR' ?_
    refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
    refine EquivBA.trans
      (EquivBA.base (Equiv.s1 pB (chordPre cG qB rB) (sol R))) ?_
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl pB)) hPfactor

#print axioms chord3_roles

open Classical in
/-- **THE TAILED CHORD-CYCLE ROLES**: the assembly-ready form — the port
    carries a continuation `tail` (its gathered descent arms and halt), so
    the theorem applies to quotient ports with exits below the cycle rank.
    The derivation is the same lap-unrolling; the tail rides along by
    right-distribution (`u5`) and skip-left (`s4`). -/
theorem chord3_roles_tail {S : Type} (aut : GAut S A T) (sol : S → Exp A T)
    (P Q R : S) (bG cG : BExp T) (pB qB rB tail : Exp A T)
    (hsolQ : sol Q = .seq (.wh cG qB) (.seq rB (sol R)))
    (hsolP : sol P = .ite cG (.seq qB (sol Q)) (.seq rB (sol R)))
    (hsolR : sol R
      = .seq (.wh bG (.seq pB (chordPre cG qB rB))) tail)
    (hrhsQ : EquivBA (eqRHS aut sol Q)
      (.ite cG (.seq qB (sol Q)) (.seq rB (sol R))))
    (hrhsP : EquivBA (eqRHS aut sol P)
      (.ite cG (.seq qB (sol Q)) (.seq rB (sol R))))
    (hrhsR : EquivBA (eqRHS aut sol R)
      (.ite bG (.seq pB (sol P)) tail)) :
    StateRole aut sol P ∧ StateRole aut sol Q
      ∧ StateRole aut sol R := by
  have hPfactor : EquivBA
      (.seq (chordPre cG qB rB) (sol R)) (sol P) := by
    show EquivBA
      (.seq (.ite cG (.seq qB (.seq (.wh cG qB) rB)) rB) (sol R)) _
    refine EquivBA.trans (EquivBA.symm
      (EquivBA.base (Equiv.u5 cG (.seq qB (.seq (.wh cG qB) rB)) rB
        (sol R)))) ?_
    rw [hsolP]
    refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
    refine EquivBA.trans
      (EquivBA.base (Equiv.s1 qB (.seq (.wh cG qB) rB) (sol R))) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl qB)) ?_
    rw [hsolQ]
    exact EquivBA.base (Equiv.s1 (.wh cG qB) rB (sol R))
  have hunroll : EquivBA (sol R)
      (.ite bG (.seq pB (sol P)) tail) := by
    conv => lhs; rw [hsolR]
    refine EquivBA.trans (EquivBA.seq_c
      (EquivBA.base (Equiv.w1 bG (.seq pB (chordPre cG qB rB))))
      (EquivBA.base (Equiv.refl tail))) ?_
    refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 bG
      (.seq (.seq pB (chordPre cG qB rB))
        (.wh bG (.seq pB (chordPre cG qB rB))))
      (.test .one) tail))) ?_
    refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.s4 tail))
    refine EquivBA.trans (EquivBA.base (Equiv.s1
      (.seq pB (chordPre cG qB rB))
      (.wh bG (.seq pB (chordPre cG qB rB))) tail)) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.s1 pB (chordPre cG qB rB)
      (.seq (.wh bG (.seq pB (chordPre cG qB rB))) tail))) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl pB)) ?_
    rw [← hsolR]
    exact hPfactor
  refine ⟨?_, ?_, ?_⟩
  · refine StateRole.equivFold ?_
    refine EquivBA.trans ?_ hrhsP.symm
    rw [hsolP]
    exact EquivBA.base (Equiv.refl _)
  · exact StateRole.salomaaE cG qB (.seq rB (sol R)) hsolQ hrhsQ
  · refine StateRole.equivFold ?_
    exact EquivBA.trans hunroll hrhsR.symm

#print axioms chord3_roles_tail

end GkatThreeLoop
