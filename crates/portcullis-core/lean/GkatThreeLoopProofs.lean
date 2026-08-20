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

/-! ## The assembly-facing forms

    Gathered quotient arms produce (i) a second `ite` layer ending in the
    state's halt test — collapsed by `chord_else_collapse` when the two
    dispatch guards cover and the halt is empty — and (ii) SEPARATE guard
    and body data at the branch state and the inner state (each gathers its
    own arm list), handled by the split-parameter roles theorem. -/

open Classical in
/-- **ELSE-COLLAPSE**: a two-way dispatch whose guards cover (`¬g₁ → g₂`)
    and whose halt is empty is a plain `ite`. -/
theorem chord_else_collapse {g₁ g₂ h : BExp T}
    (himp : GuardImplies (.not g₁) g₂) (hemp : GuardEmpty h)
    (X Y : Exp A T) :
    EquivBA (.ite g₁ X (.ite g₂ Y (.test h))) (.ite g₁ X Y) := by
  refine EquivBA.trans (ite_else_restrict g₁ g₂ X Y (.test h)) ?_
  refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl X))
    (EquivBA.ite_guard (e := Y) (f := .test h) (fun Z W x => by
      show (bval W (.not g₁) x && bval W g₂ x) = bval W (.not g₁) x
      cases hb : bval W (.not g₁) x
      · rfl
      · rw [himp Z W x hb]
        rfl))) ?_
  refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl X))
    (EquivBA.ite_c (EquivBA.base (Equiv.refl Y))
      (EquivBA.baTest (b := h) (c := .zero)
        (fun Z W x => hemp Z W x)))) ?_
  refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl X))
    (ite_zero_else (.not g₁) Y)) ?_
  exact EquivBA.symm (ite_restrict_else g₁ X Y)

#print axioms chord_else_collapse

open Classical in
/-- The lap prefix, split-parameter form: the branch state's own gathered
    data (`cG`, `qB`, `rB`) with the inner state's own solved loop
    (`cQ`, `qBQ`, `rBQ`) spliced into the enter arm. -/
def chordPreS (cG cQ : BExp T) (qB qBQ rBQ rB : Exp A T) : Exp A T :=
  .ite cG (.seq qB (.seq (.wh cQ qBQ) rBQ)) rB

open Classical in
/-- **THE SPLIT CHORD-CYCLE ROLES**: as `chord3_roles_tail`, but the
    branch state and the inner state each carry their own gathered guards
    and bodies — the exact shape `double_gather` + `chord_else_collapse`
    produce on a canonical quotient. -/
theorem chord3_roles_split {S : Type} (aut : GAut S A T) (sol : S → Exp A T)
    (P Q R : S) (bG cG cQ : BExp T) (pB qB qBQ rBQ rB tail : Exp A T)
    (hsolQ : sol Q = .seq (.wh cQ qBQ) (.seq rBQ (sol R)))
    (hsolP : sol P = .ite cG (.seq qB (sol Q)) (.seq rB (sol R)))
    (hsolR : sol R
      = .seq (.wh bG (.seq pB (chordPreS cG cQ qB qBQ rBQ rB))) tail)
    (hrhsQ : EquivBA (eqRHS aut sol Q)
      (.ite cQ (.seq qBQ (sol Q)) (.seq rBQ (sol R))))
    (hrhsP : EquivBA (eqRHS aut sol P)
      (.ite cG (.seq qB (sol Q)) (.seq rB (sol R))))
    (hrhsR : EquivBA (eqRHS aut sol R)
      (.ite bG (.seq pB (sol P)) tail)) :
    StateRole aut sol P ∧ StateRole aut sol Q
      ∧ StateRole aut sol R := by
  have hQwh : EquivBA (.seq qBQ (sol Q))
      (.seq qBQ (.seq (.wh cQ qBQ) (.seq rBQ (sol R)))) := by
    rw [hsolQ]
    exact EquivBA.base (Equiv.refl _)
  have hPfactor : EquivBA
      (.seq (chordPreS cG cQ qB qBQ rBQ rB) (sol R)) (sol P) := by
    show EquivBA
      (.seq (.ite cG (.seq qB (.seq (.wh cQ qBQ) rBQ)) rB) (sol R)) _
    refine EquivBA.trans (EquivBA.symm
      (EquivBA.base (Equiv.u5 cG (.seq qB (.seq (.wh cQ qBQ) rBQ)) rB
        (sol R)))) ?_
    rw [hsolP]
    refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
    refine EquivBA.trans
      (EquivBA.base (Equiv.s1 qB (.seq (.wh cQ qBQ) rBQ) (sol R))) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl qB)) ?_
    rw [hsolQ]
    exact EquivBA.base (Equiv.s1 (.wh cQ qBQ) rBQ (sol R))
  have hunroll : EquivBA (sol R)
      (.ite bG (.seq pB (sol P)) tail) := by
    conv => lhs; rw [hsolR]
    refine EquivBA.trans (EquivBA.seq_c
      (EquivBA.base (Equiv.w1 bG
        (.seq pB (chordPreS cG cQ qB qBQ rBQ rB))))
      (EquivBA.base (Equiv.refl tail))) ?_
    refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 bG
      (.seq (.seq pB (chordPreS cG cQ qB qBQ rBQ rB))
        (.wh bG (.seq pB (chordPreS cG cQ qB qBQ rBQ rB))))
      (.test .one) tail))) ?_
    refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.s4 tail))
    refine EquivBA.trans (EquivBA.base (Equiv.s1
      (.seq pB (chordPreS cG cQ qB qBQ rBQ rB))
      (.wh bG (.seq pB (chordPreS cG cQ qB qBQ rBQ rB))) tail)) ?_
    refine EquivBA.trans (EquivBA.base
      (Equiv.s1 pB (chordPreS cG cQ qB qBQ rBQ rB)
        (.seq (.wh bG (.seq pB (chordPreS cG cQ qB qBQ rBQ rB))) tail))) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl pB)) ?_
    rw [← hsolR]
    exact hPfactor
  refine ⟨?_, ?_, ?_⟩
  · refine StateRole.equivFold ?_
    refine EquivBA.trans ?_ hrhsP.symm
    rw [hsolP]
    exact EquivBA.base (Equiv.refl _)
  · exact StateRole.salomaaE cQ qBQ (.seq rBQ (sol R)) hsolQ hrhsQ
  · refine StateRole.equivFold ?_
    exact EquivBA.trans hunroll hrhsR.symm

#print axioms chord3_roles_split

end GkatThreeLoop
