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

end GkatThreeLoop
