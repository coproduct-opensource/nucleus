import GkatWalkedOrbitProofs
import GkatChainFragmentProofs

/-! # The two-loop fragment: genuinely nested cycles

    `wh b ((wh c q); r)` is the minimal genuinely nested program: its
    Thompson automaton has TWO interlocking cycles sharing states — the
    inner self-loop at the `wh c q` state and the outer 2-cycle through
    the `r` port.  The skip of the inner loop on re-entry lands on the
    port ITSELF, so the walked discipline holds; and with two core
    states every arm targets self-or-swap, trivializing the rank layer. -/

namespace GkatTwoLoop

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop GkatChainLoop GkatOrbit
open GkatChainFragment GkatWalkedOrbit

variable {A T : Type}

/-- The two-loop body: an atomic inner loop, then one action. -/
def twoLoopBody (c : BExp T) (q r : A) : Exp A T :=
  .seq (.wh c (.act q)) (.act r)

/-- The two-loop program. -/
def twoLoop (b c : BExp T) (q r : A) : Exp A T :=
  .wh b (twoLoopBody c q r)

/-- Its loop automaton: `inl ()` is the inner state, `inr ()` the port. -/
def twoLoopAut (b c : BExp T) (q r : A) :
    InitializedGAut (Sum Unit Unit) A T :=
  loopInitialized b (certifiedThompson A T (twoLoopBody c q r)).aut

/-- The swap successor. -/
def twoNxt : Sum Unit Unit → Sum Unit Unit
  | .inl _ => .inr ()
  | .inr _ => .inl ()

/-- In a two-state space, every target is self or the swap. -/
theorem two_state_dec (s t : Sum Unit Unit) : t = s ∨ t = twoNxt s := by
  cases s with
  | inl u =>
      cases u
      cases t with
      | inl v => cases v; exact Or.inl rfl
      | inr v => cases v; exact Or.inr rfl
  | inr u =>
      cases u
      cases t with
      | inl v => cases v; exact Or.inr rfl
      | inr v => cases v; exact Or.inl rfl

/-- The swap has period two. -/
theorem twoNxt_period (s : Sum Unit Unit) :
    twoNxt (twoNxt s) = s := by
  cases s with
  | inl u => cases u; rfl
  | inr u => cases u; rfl

/-- The swap never fixes. -/
theorem twoNxt_nofix (s : Sum Unit Unit) : twoNxt s ≠ s := by
  cases s with
  | inl u => cases u; intro h; exact nomatch h
  | inr u => cases u; intro h; exact nomatch h

/-- **INTERIOR SILENCE**: the inner state never halts. -/
theorem twoLoop_hlt_inl (b c : BExp T) (q r : A) :
    ∀ α : T → Bool,
      bval (genW T) ((twoLoopAut b c q r).core.hlt (Sum.inl ())) α
        = false := by
  intro α
  show (((true && !(bval (genW T) c α)) && false)
    && !(bval (genW T) b α)) = false
  cases bval (genW T) c α <;> cases bval (genW T) b α <;> rfl

/-- **PORT EXIT**: the port halts exactly at `¬b`. -/
theorem twoLoop_hlt_inr (b c : BExp T) (q r : A) :
    ∀ α : T → Bool,
      bval (genW T) ((twoLoopAut b c q r).core.hlt (Sum.inr ())) α
        = !(bval (genW T) b α) := by
  intro α
  show (true && !(bval (genW T) b α)) = !(bval (genW T) b α)
  cases bval (genW T) b α <;> rfl

/-- **INNER SELF-STEP**: at a `c`-atom, the inner state loops. -/
theorem twoLoop_step_inl_self (b c : BExp T) (q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inl ()))
      = some (q, Sum.inl ()) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inl ())
    else _) = some (q, Sum.inl ())
  rw [hc]
  rfl

/-- **INNER ADVANCE**: at a `¬c`-atom, the inner state advances to the
    port. -/
theorem twoLoop_step_inl_adv (b c : BExp T) (q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inl ()))
      = some (r, Sum.inr ()) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inl ())
    else if ((true && !(bval (genW T) c α)) && true) = true
      then some (r, Sum.inr ())
      else _) = some (r, Sum.inr ())
  rw [hc]
  rfl

/-- **PORT FEEDBACK INTO THE INNER LOOP**: at a `b ∧ c`-atom. -/
theorem twoLoop_step_inr_feed (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inr ()))
      = some (q, Sum.inl ()) := by
  show (if (true && (bval (genW T) b α
      && (bval (genW T) c α && true))) = true
    then some (q, Sum.inl ())
    else _) = some (q, Sum.inl ())
  rw [hb, hc]
  rfl

/-- **PORT SELF-STEP** (skipping the inner loop on re-entry): at a
    `b ∧ ¬c`-atom. -/
theorem twoLoop_step_inr_self (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inr ()))
      = some (r, Sum.inr ()) := by
  show (if (true && (bval (genW T) b α
      && (bval (genW T) c α && true))) = true
    then some (q, Sum.inl ())
    else if (true && (bval (genW T) b α
        && (!(bval (genW T) c α) && true))) = true
      then some (r, Sum.inr ())
      else _) = some (r, Sum.inr ())
  rw [hb, hc]
  rfl

/-- **PORT REST**: at a `¬b`-atom the port takes no step. -/
theorem twoLoop_step_inr_none (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inr ()))
      = none := by
  show (if (true && (bval (genW T) b α
      && (bval (genW T) c α && true))) = true
    then some (q, Sum.inl ())
    else if (true && (bval (genW T) b α
        && (!(bval (genW T) c α) && true))) = true
      then some (r, Sum.inr ())
      else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

#print axioms two_state_dec
#print axioms twoLoop_hlt_inl
#print axioms twoLoop_step_inl_adv
#print axioms twoLoop_step_inr_self

end GkatTwoLoop
