import GkatTwoLoopProofs
import GkatDecideProofs

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
open GkatChainFragment GkatWalkedOrbit GkatTwoLoop GkatDecide

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

/-! ## The chord assembly

    The engine-facing assembly: a classifier `cy` designates chord-3
    clusters `(port, branch, inner)`; every other state is base (arms self
    or strictly descending).  Closed forms are built from gathered arm
    data, with descent references rank-guarded — the chord analogue of
    `asmSolW`/`walked_assembly_roles`. -/

open Classical in
private theorem foldTL_congrC {S : Type} {sol₁ sol₂ : S → Exp A T}
    (h : BExp T) :
    ∀ L : List (BExp T × A × S), (∀ e ∈ L, sol₁ e.2.2 = sol₂ e.2.2) →
    foldTL sol₁ h L = foldTL sol₂ h L := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons a L ih =>
      intro hL
      show Exp.ite a.1 (.seq (.act a.2.1) (sol₁ a.2.2)) (foldTL sol₁ h L)
        = Exp.ite a.1 (.seq (.act a.2.1) (sol₂ a.2.2)) (foldTL sol₂ h L)
      rw [hL a (by exact List.mem_cons_self ..),
        ih (fun e he => hL e (List.mem_cons_of_mem a he))]

open Classical in
/-- The port's closed form: the tailed lap while-loop over gathered data. -/
noncomputable def chordPortE {S : Type} (aut : GAut S A T)
    (dsol : S → Exp A T) (Rs Ps Qs : S) : Exp A T :=
  .seq (.wh (gGuard Ps (aut.trans Rs))
      (.seq (gBody Ps (aut.trans Rs))
        (chordPreS (gGuard Qs (aut.trans Ps)) (gGuard Qs (aut.trans Qs))
          (gBody Qs (aut.trans Ps)) (gBody Qs (aut.trans Qs))
          (gBody Rs (gOthers Qs (aut.trans Qs)))
          (gBody Rs (gOthers Qs (aut.trans Ps))))))
    (foldTL dsol (aut.hlt Rs) (gOthers Ps (aut.trans Rs)))

open Classical in
/-- The inner state's closed form: its own loop, then exit to the port. -/
noncomputable def chordInnerE {S : Type} (aut : GAut S A T)
    (dsol : S → Exp A T) (Rs Ps Qs : S) : Exp A T :=
  .seq (.wh (gGuard Qs (aut.trans Qs)) (gBody Qs (aut.trans Qs)))
    (.seq (gBody Rs (gOthers Qs (aut.trans Qs)))
      (chordPortE aut dsol Rs Ps Qs))

open Classical in
/-- The branch state's closed form: the two-way dispatch. -/
noncomputable def chordBranchE {S : Type} (aut : GAut S A T)
    (dsol : S → Exp A T) (Rs Ps Qs : S) : Exp A T :=
  .ite (gGuard Qs (aut.trans Ps))
    (.seq (gBody Qs (aut.trans Ps)) (chordInnerE aut dsol Rs Ps Qs))
    (.seq (gBody Rs (gOthers Qs (aut.trans Ps)))
      (chordPortE aut dsol Rs Ps Qs))

open Classical in
private theorem chordPortE_congr {S : Type} (aut : GAut S A T)
    (Rs Ps Qs : S) {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthers Ps (aut.trans Rs), sol₁ e.2.2 = sol₂ e.2.2) :
    chordPortE aut sol₁ Rs Ps Qs = chordPortE aut sol₂ Rs Ps Qs := by
  unfold chordPortE
  rw [foldTL_congrC (aut.hlt Rs) (gOthers Ps (aut.trans Rs)) h]

open Classical in
private theorem chordInnerE_congr {S : Type} (aut : GAut S A T)
    (Rs Ps Qs : S) {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthers Ps (aut.trans Rs), sol₁ e.2.2 = sol₂ e.2.2) :
    chordInnerE aut sol₁ Rs Ps Qs = chordInnerE aut sol₂ Rs Ps Qs := by
  unfold chordInnerE
  rw [chordPortE_congr aut Rs Ps Qs h]

open Classical in
private theorem chordBranchE_congr {S : Type} (aut : GAut S A T)
    (Rs Ps Qs : S) {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthers Ps (aut.trans Rs), sol₁ e.2.2 = sol₂ e.2.2) :
    chordBranchE aut sol₁ Rs Ps Qs = chordBranchE aut sol₂ Rs Ps Qs := by
  unfold chordBranchE
  rw [chordInnerE_congr aut Rs Ps Qs h, chordPortE_congr aut Rs Ps Qs h]

open Classical in
/-- The chord assembly solution. -/
noncomputable def asmSolC {S : Type} (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option ((S × S × S) × Nat)) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    match cy s with
    | none =>
        .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
            (aut.hlt s) (gOthers s (aut.trans s)))
    | some ((Rs, Ps, Qs), i) =>
        if i = 0 then
          chordPortE aut
            (fun t => if h : rank t < rank s then rec t h else .test .zero)
            Rs Ps Qs
        else if i = 1 then
          chordBranchE aut
            (fun t => if h : rank t < rank s then rec t h else .test .zero)
            Rs Ps Qs
        else
          chordInnerE aut
            (fun t => if h : rank t < rank s then rec t h else .test .zero)
            Rs Ps Qs)

open Classical in
theorem asmSolC_eq {S : Type} (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option ((S × S × S) × Nat)) (s : S) :
    asmSolC aut rank cy s
      = (match cy s with
        | none =>
            .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (fun t =>
                  if _ : rank t < rank s then asmSolC aut rank cy t
                  else .test .zero)
                (aut.hlt s) (gOthers s (aut.trans s)))
        | some ((Rs, Ps, Qs), i) =>
            if i = 0 then
              chordPortE aut
                (fun t => if _ : rank t < rank s then asmSolC aut rank cy t
                  else .test .zero) Rs Ps Qs
            else if i = 1 then
              chordBranchE aut
                (fun t => if _ : rank t < rank s then asmSolC aut rank cy t
                  else .test .zero) Rs Ps Qs
            else
              chordInnerE aut
                (fun t => if _ : rank t < rank s then asmSolC aut rank cy t
                  else .test .zero) Rs Ps Qs) := by
  unfold asmSolC
  rw [WellFounded.fix_eq]

open Classical in
/-- **THE CHORD ASSEMBLY THEOREM**: an automaton whose every state is base
    (arms self or strictly descending) or a member of a designated chord-3
    cluster — port with descent exits, covering branch dispatch, covering
    inner loop, empty interior halts — is fully role-covered. -/
theorem chord_assembly_roles {S : Type} (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option ((S × S × S) × Nat))
    (hcy : ∀ s Rs Ps Qs i, cy s = some ((Rs, Ps, Qs), i) →
      ((i = 0 ∧ s = Rs) ∨ (i = 1 ∧ s = Ps) ∨ (i = 2 ∧ s = Qs))
      ∧ cy Rs = some ((Rs, Ps, Qs), 0)
      ∧ cy Ps = some ((Rs, Ps, Qs), 1)
      ∧ cy Qs = some ((Rs, Ps, Qs), 2)
      ∧ rank Ps = rank Rs ∧ rank Qs = rank Rs
      ∧ (∀ e ∈ gOthers Ps (aut.trans Rs), rank e.2.2 < rank Rs)
      ∧ gOthers Rs (gOthers Qs (aut.trans Ps)) = []
      ∧ gOthers Rs (gOthers Qs (aut.trans Qs)) = []
      ∧ GuardImplies (.not (gGuard Qs (aut.trans Ps)))
          (gGuard Rs (gOthers Qs (aut.trans Ps)))
      ∧ GuardImplies (.not (gGuard Qs (aut.trans Qs)))
          (gGuard Rs (gOthers Qs (aut.trans Qs)))
      ∧ GuardEmpty (aut.hlt Ps) ∧ GuardEmpty (aut.hlt Qs))
    (hbase : ∀ s ∈ aut.states, cy s = none →
      ∀ e ∈ aut.trans s, e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨asmSolC aut rank cy, fun s hs => ?_⟩
  cases hcys : cy s with
  | none =>
      have hlow : ∀ e ∈ gOthers s (aut.trans s), rank e.2.2 < rank s := by
        intro e he
        obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
        rcases hbase s hs hcys e heL with h1 | h2
        · exact absurd h1 hne
        · exact h2
      have hsol : asmSolC aut rank cy s
          = .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (asmSolC aut rank cy) (aut.hlt s)
                (gOthers s (aut.trans s))) := by
        rw [asmSolC_eq, hcys]
        exact congrArg _ (foldTL_congrC (aut.hlt s) (gOthers s (aut.trans s))
          (fun e he => dif_pos (hlow e he)))
      refine StateRole.salomaaE (gGuard s (aut.trans s))
        (gBody s (aut.trans s))
        (foldTL (asmSolC aut rank cy) (aut.hlt s) (gOthers s (aut.trans s)))
        hsol ?_
      rw [eqRHS_foldTL]
      exact multi_gather (asmSolC aut rank cy) (aut.hlt s) s (aut.trans s)
  | some q =>
      obtain ⟨⟨Rs, Ps, Qs⟩, i⟩ := q
      obtain ⟨hpos, hcyR, hcyP, hcyQ, hrkP, hrkQ, hport_lo, hnilP, hnilQ,
        himpP, himpQ, hempP, hempQ⟩ := hcy s Rs Ps Qs i hcys
      have hlowR : ∀ e ∈ gOthers Ps (aut.trans Rs),
          (if _ : rank e.2.2 < rank Rs then asmSolC aut rank cy e.2.2
            else Exp.test BExp.zero) = asmSolC aut rank cy e.2.2 :=
        fun e he => dif_pos (hport_lo e he)
      have hlowP : ∀ e ∈ gOthers Ps (aut.trans Rs),
          (if _ : rank e.2.2 < rank Ps then asmSolC aut rank cy e.2.2
            else Exp.test BExp.zero) = asmSolC aut rank cy e.2.2 :=
        fun e he => dif_pos (by rw [hrkP]; exact hport_lo e he)
      have hlowQ : ∀ e ∈ gOthers Ps (aut.trans Rs),
          (if _ : rank e.2.2 < rank Qs then asmSolC aut rank cy e.2.2
            else Exp.test BExp.zero) = asmSolC aut rank cy e.2.2 :=
        fun e he => dif_pos (by rw [hrkQ]; exact hport_lo e he)
      have hsolR_eq : asmSolC aut rank cy Rs
          = chordPortE aut (asmSolC aut rank cy) Rs Ps Qs := by
        rw [asmSolC_eq, hcyR]
        show (if (0 : Nat) = 0 then _ else _) = _
        rw [if_pos rfl]
        exact chordPortE_congr aut Rs Ps Qs hlowR
      have hsolP_eq : asmSolC aut rank cy Ps
          = chordBranchE aut (asmSolC aut rank cy) Rs Ps Qs := by
        rw [asmSolC_eq, hcyP]
        show (if (1 : Nat) = 0 then _ else if (1 : Nat) = 1 then _ else _) = _
        rw [if_neg (by omega : ¬ (1 : Nat) = 0), if_pos rfl]
        exact chordBranchE_congr aut Rs Ps Qs hlowP
      have hsolQ_eq : asmSolC aut rank cy Qs
          = chordInnerE aut (asmSolC aut rank cy) Rs Ps Qs := by
        rw [asmSolC_eq, hcyQ]
        show (if (2 : Nat) = 0 then _ else if (2 : Nat) = 1 then _ else _) = _
        rw [if_neg (by omega : ¬ (2 : Nat) = 0),
          if_neg (by omega : ¬ (2 : Nat) = 1)]
        exact chordInnerE_congr aut Rs Ps Qs hlowQ
      have hsolQ' : asmSolC aut rank cy Qs
          = .seq (.wh (gGuard Qs (aut.trans Qs)) (gBody Qs (aut.trans Qs)))
              (.seq (gBody Rs (gOthers Qs (aut.trans Qs)))
                (asmSolC aut rank cy Rs)) := by
        rw [hsolQ_eq]
        show chordInnerE aut (asmSolC aut rank cy) Rs Ps Qs
          = .seq (.wh (gGuard Qs (aut.trans Qs)) (gBody Qs (aut.trans Qs)))
              (.seq (gBody Rs (gOthers Qs (aut.trans Qs)))
                (asmSolC aut rank cy Rs))
        rw [hsolR_eq]
        rfl
      have hsolP' : asmSolC aut rank cy Ps
          = .ite (gGuard Qs (aut.trans Ps))
              (.seq (gBody Qs (aut.trans Ps)) (asmSolC aut rank cy Qs))
              (.seq (gBody Rs (gOthers Qs (aut.trans Ps)))
                (asmSolC aut rank cy Rs)) := by
        rw [hsolP_eq]
        show chordBranchE aut (asmSolC aut rank cy) Rs Ps Qs = _
        rw [hsolR_eq, hsolQ_eq]
        rfl
      have hsolR' : asmSolC aut rank cy Rs
          = .seq (.wh (gGuard Ps (aut.trans Rs))
              (.seq (gBody Ps (aut.trans Rs))
                (chordPreS (gGuard Qs (aut.trans Ps))
                  (gGuard Qs (aut.trans Qs)) (gBody Qs (aut.trans Ps))
                  (gBody Qs (aut.trans Qs))
                  (gBody Rs (gOthers Qs (aut.trans Qs)))
                  (gBody Rs (gOthers Qs (aut.trans Ps))))))
              (foldTL (asmSolC aut rank cy) (aut.hlt Rs)
                (gOthers Ps (aut.trans Rs))) := by
        rw [hsolR_eq]
        rfl
      have hroles := chord3_roles_split aut (asmSolC aut rank cy) Ps Qs Rs
        (gGuard Ps (aut.trans Rs)) (gGuard Qs (aut.trans Ps))
        (gGuard Qs (aut.trans Qs)) (gBody Ps (aut.trans Rs))
        (gBody Qs (aut.trans Ps)) (gBody Qs (aut.trans Qs))
        (gBody Rs (gOthers Qs (aut.trans Qs)))
        (gBody Rs (gOthers Qs (aut.trans Ps)))
        (foldTL (asmSolC aut rank cy) (aut.hlt Rs)
          (gOthers Ps (aut.trans Rs)))
        hsolQ' hsolP' hsolR'
        (by
          rw [eqRHS_foldTL]
          refine EquivBA.trans (double_gather (asmSolC aut rank cy)
            (aut.hlt Qs) Qs Rs (aut.trans Qs)) ?_
          rw [hnilQ]
          exact chord_else_collapse himpQ hempQ _ _)
        (by
          rw [eqRHS_foldTL]
          refine EquivBA.trans (double_gather (asmSolC aut rank cy)
            (aut.hlt Ps) Qs Rs (aut.trans Ps)) ?_
          rw [hnilP]
          exact chord_else_collapse himpP hempP _ _)
        (by
          rw [eqRHS_foldTL]
          exact multi_gather (asmSolC aut rank cy) (aut.hlt Rs) Ps
            (aut.trans Rs))
      obtain ⟨hroleP, hroleQ, hroleR⟩ := hroles
      rcases hpos with ⟨-, hsR⟩ | ⟨-, hsP⟩ | ⟨-, hsQ⟩
      · rw [hsR]; exact hroleR
      · rw [hsP]; exact hroleP
      · rw [hsQ]; exact hroleQ

#print axioms chord_assembly_roles

/-! ## The de-choiced chord assembly

    `Classical.choice` enters `chord_assembly_roles` solely through the
    classical `if u = t` state-equality decisions in `gGuard`/`gBody`/
    `gOthers`.  With `[DecidableEq S]` — structural on every concrete
    quotient state type — the same gathering, the same gather lemmas
    (their EquivBA cores `arms_merge`/`arm_commute`/`ite_zero_guard` are
    axiom-free), and the same assembly re-elaborate choice-free. -/

/-- Decidable gathered guard. -/
def gGuardD {S : Type} [DecidableEq S] (t : S) :
    List (BExp T × A × S) → BExp T
  | [] => .zero
  | (g, _, u) :: rest =>
      if u = t then .or g (gGuardD t rest)
      else .and (gGuardD t rest) (.not g)

/-- Decidable gathered body. -/
def gBodyD {S : Type} [DecidableEq S] (t : S) :
    List (BExp T × A × S) → Exp A T
  | [] => .test .zero
  | (g, a, u) :: rest =>
      if u = t then .ite g (.act a) (gBodyD t rest)
      else gBodyD t rest

/-- Decidable non-self remainder. -/
def gOthersD {S : Type} [DecidableEq S] (t : S) :
    List (BExp T × A × S) → List (BExp T × A × S)
  | [] => []
  | (g, a, u) :: rest =>
      if u = t then gOthersD t rest
      else (g, a, u) :: gOthersD t rest

private theorem gGuardD_cons {S : Type} [DecidableEq S] (t : S) (g : BExp T)
    (a : A) (u : S) (rest : List (BExp T × A × S)) :
    gGuardD t ((g, a, u) :: rest)
      = if u = t then .or g (gGuardD t rest)
        else .and (gGuardD t rest) (.not g) := rfl

private theorem gBodyD_cons {S : Type} [DecidableEq S] (t : S) (g : BExp T)
    (a : A) (u : S) (rest : List (BExp T × A × S)) :
    gBodyD t ((g, a, u) :: rest)
      = if u = t then .ite g (.act a) (gBodyD t rest)
        else gBodyD t rest := rfl

private theorem gOthersD_cons {S : Type} [DecidableEq S] (t : S) (g : BExp T)
    (a : A) (u : S) (rest : List (BExp T × A × S)) :
    gOthersD t ((g, a, u) :: rest)
      = if u = t then gOthersD t rest
        else (g, a, u) :: gOthersD t rest := rfl

theorem gOthersD_sub {S : Type} [DecidableEq S] (t : S) :
    ∀ L : List (BExp T × A × S), ∀ e ∈ gOthersD t L,
      e ∈ L ∧ e.2.2 ≠ t := by
  intro L
  induction L with
  | nil => intro e he; exact nomatch he
  | cons hd rest ih =>
      obtain ⟨g, a, u⟩ := hd
      intro e he
      rw [gOthersD_cons] at he
      by_cases hu : u = t
      · rw [if_pos hu] at he
        obtain ⟨h1, h2⟩ := ih e he
        exact ⟨List.mem_cons_of_mem _ h1, h2⟩
      · rw [if_neg hu] at he
        rcases List.mem_cons.mp he with heq | hmem
        · subst heq
          exact ⟨by exact List.mem_cons_self .., hu⟩
        · obtain ⟨h1, h2⟩ := ih e hmem
          exact ⟨List.mem_cons_of_mem _ h1, h2⟩

/-- Bridges to the classical gathering (for interop with existing
    lemmas; not used by the choice-free assembly). -/
theorem gGuardD_eq_gGuard {S : Type} [DecidableEq S] (t : S) :
    ∀ L : List (BExp T × A × S), gGuardD t L = gGuard t L := by
  intro L
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, u⟩ := hd
      simp only [gGuardD, gGuard]
      by_cases hu : u = t
      · rw [if_pos hu, if_pos hu, ih]
      · rw [if_neg hu, if_neg hu, ih]

theorem gBodyD_eq_gBody {S : Type} [DecidableEq S] (t : S) :
    ∀ L : List (BExp T × A × S), gBodyD t L = gBody t L := by
  intro L
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, u⟩ := hd
      simp only [gBodyD, gBody]
      by_cases hu : u = t
      · rw [if_pos hu, if_pos hu, ih]
      · rw [if_neg hu, if_neg hu, ih]

theorem gOthersD_eq_gOthers {S : Type} [DecidableEq S] (t : S) :
    ∀ L : List (BExp T × A × S), gOthersD t L = gOthers t L := by
  intro L
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, u⟩ := hd
      simp only [gOthersD, gOthers]
      by_cases hu : u = t
      · rw [if_pos hu, if_pos hu, ih]
      · rw [if_neg hu, if_neg hu, ih]

/-- Choice-free `multi_gather`. -/
theorem multi_gatherD {S : Type} [DecidableEq S] (sol : S → Exp A T)
    (h : BExp T) (t : S) :
    ∀ L : List (BExp T × A × S),
    EquivBA (foldTL sol h L)
      (.ite (gGuardD t L) (.seq (gBodyD t L) (sol t))
        (foldTL sol h (gOthersD t L))) := by
  intro L
  induction L with
  | nil =>
      exact EquivBA.symm (GkatDeadExitElim.ite_zero_guard _ _
        (fun X W x => rfl))
  | cons hd rest ih =>
      obtain ⟨g, a, u⟩ := hd
      rw [gGuardD_cons, gBodyD_cons, gOthersD_cons]
      by_cases hu : u = t
      · subst hu
        rw [if_pos rfl, if_pos rfl, if_pos rfl]
        show EquivBA (.ite g (.seq (.act a) (sol u)) (foldTL sol h rest)) _
        refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih) ?_
        exact arms_merge g (gGuardD u rest) (.act a) (gBodyD u rest) (sol u)
          (foldTL sol h (gOthersD u rest))
      · rw [if_neg hu, if_neg hu, if_neg hu]
        show EquivBA (.ite g (.seq (.act a) (sol u)) (foldTL sol h rest)) _
        refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih) ?_
        exact arm_commute g (gGuardD t rest) (.seq (.act a) (sol u))
          (.seq (gBodyD t rest) (sol t)) (foldTL sol h (gOthersD t rest))

/-- Choice-free `double_gather`. -/
theorem double_gatherD {S : Type} [DecidableEq S] (sol : S → Exp A T)
    (h : BExp T) (u v : S) (L : List (BExp T × A × S)) :
    EquivBA (foldTL sol h L)
      (.ite (gGuardD u L) (.seq (gBodyD u L) (sol u))
        (.ite (gGuardD v (gOthersD u L))
          (.seq (gBodyD v (gOthersD u L)) (sol v))
          (foldTL sol h (gOthersD v (gOthersD u L))))) :=
  EquivBA.trans (multi_gatherD sol h u L)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
      (multi_gatherD sol h v (gOthersD u L)))

#print axioms multi_gatherD
#print axioms double_gatherD

/-- Choice-free port closed form. -/
def chordPortED {S : Type} [DecidableEq S] (aut : GAut S A T)
    (dsol : S → Exp A T) (Rs Ps Qs : S) : Exp A T :=
  .seq (.wh (gGuardD Ps (aut.trans Rs))
      (.seq (gBodyD Ps (aut.trans Rs))
        (chordPreS (gGuardD Qs (aut.trans Ps)) (gGuardD Qs (aut.trans Qs))
          (gBodyD Qs (aut.trans Ps)) (gBodyD Qs (aut.trans Qs))
          (gBodyD Rs (gOthersD Qs (aut.trans Qs)))
          (gBodyD Rs (gOthersD Qs (aut.trans Ps))))))
    (foldTL dsol (aut.hlt Rs) (gOthersD Ps (aut.trans Rs)))

/-- Choice-free inner closed form. -/
def chordInnerED {S : Type} [DecidableEq S] (aut : GAut S A T)
    (dsol : S → Exp A T) (Rs Ps Qs : S) : Exp A T :=
  .seq (.wh (gGuardD Qs (aut.trans Qs)) (gBodyD Qs (aut.trans Qs)))
    (.seq (gBodyD Rs (gOthersD Qs (aut.trans Qs)))
      (chordPortED aut dsol Rs Ps Qs))

/-- Choice-free branch closed form. -/
def chordBranchED {S : Type} [DecidableEq S] (aut : GAut S A T)
    (dsol : S → Exp A T) (Rs Ps Qs : S) : Exp A T :=
  .ite (gGuardD Qs (aut.trans Ps))
    (.seq (gBodyD Qs (aut.trans Ps)) (chordInnerED aut dsol Rs Ps Qs))
    (.seq (gBodyD Rs (gOthersD Qs (aut.trans Ps)))
      (chordPortED aut dsol Rs Ps Qs))

private theorem chordPortED_congr {S : Type} [DecidableEq S]
    (aut : GAut S A T) (Rs Ps Qs : S) {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthersD Ps (aut.trans Rs), sol₁ e.2.2 = sol₂ e.2.2) :
    chordPortED aut sol₁ Rs Ps Qs = chordPortED aut sol₂ Rs Ps Qs := by
  unfold chordPortED
  rw [foldTL_congrC (aut.hlt Rs) (gOthersD Ps (aut.trans Rs)) h]

private theorem chordInnerED_congr {S : Type} [DecidableEq S]
    (aut : GAut S A T) (Rs Ps Qs : S) {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthersD Ps (aut.trans Rs), sol₁ e.2.2 = sol₂ e.2.2) :
    chordInnerED aut sol₁ Rs Ps Qs = chordInnerED aut sol₂ Rs Ps Qs := by
  unfold chordInnerED
  rw [chordPortED_congr aut Rs Ps Qs h]

private theorem chordBranchED_congr {S : Type} [DecidableEq S]
    (aut : GAut S A T) (Rs Ps Qs : S) {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthersD Ps (aut.trans Rs), sol₁ e.2.2 = sol₂ e.2.2) :
    chordBranchED aut sol₁ Rs Ps Qs = chordBranchED aut sol₂ Rs Ps Qs := by
  unfold chordBranchED
  rw [chordInnerED_congr aut Rs Ps Qs h, chordPortED_congr aut Rs Ps Qs h]

/-- The choice-free chord assembly solution. -/
def asmSolCD {S : Type} [DecidableEq S] (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option ((S × S × S) × Nat)) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    match cy s with
    | none =>
        .seq (.wh (gGuardD s (aut.trans s)) (gBodyD s (aut.trans s)))
          (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
            (aut.hlt s) (gOthersD s (aut.trans s)))
    | some ((Rs, Ps, Qs), i) =>
        if i = 0 then
          chordPortED aut
            (fun t => if h : rank t < rank s then rec t h else .test .zero)
            Rs Ps Qs
        else if i = 1 then
          chordBranchED aut
            (fun t => if h : rank t < rank s then rec t h else .test .zero)
            Rs Ps Qs
        else
          chordInnerED aut
            (fun t => if h : rank t < rank s then rec t h else .test .zero)
            Rs Ps Qs)

theorem asmSolCD_eq {S : Type} [DecidableEq S] (aut : GAut S A T)
    (rank : S → Nat) (cy : S → Option ((S × S × S) × Nat)) (s : S) :
    asmSolCD aut rank cy s
      = (match cy s with
        | none =>
            .seq (.wh (gGuardD s (aut.trans s)) (gBodyD s (aut.trans s)))
              (foldTL (fun t =>
                  if _ : rank t < rank s then asmSolCD aut rank cy t
                  else .test .zero)
                (aut.hlt s) (gOthersD s (aut.trans s)))
        | some ((Rs, Ps, Qs), i) =>
            if i = 0 then
              chordPortED aut
                (fun t => if _ : rank t < rank s then asmSolCD aut rank cy t
                  else .test .zero) Rs Ps Qs
            else if i = 1 then
              chordBranchED aut
                (fun t => if _ : rank t < rank s then asmSolCD aut rank cy t
                  else .test .zero) Rs Ps Qs
            else
              chordInnerED aut
                (fun t => if _ : rank t < rank s then asmSolCD aut rank cy t
                  else .test .zero) Rs Ps Qs) := by
  unfold asmSolCD
  rw [WellFounded.fix_eq]

/-- **THE CHOICE-FREE CHORD ASSEMBLY THEOREM**: `chord_assembly_roles`
    with decidable state equality — no `Classical.choice`. -/
theorem chord_assembly_rolesD {S : Type} [DecidableEq S] (aut : GAut S A T)
    (rank : S → Nat) (cy : S → Option ((S × S × S) × Nat))
    (hcy : ∀ s Rs Ps Qs i, cy s = some ((Rs, Ps, Qs), i) →
      ((i = 0 ∧ s = Rs) ∨ (i = 1 ∧ s = Ps) ∨ (i = 2 ∧ s = Qs))
      ∧ cy Rs = some ((Rs, Ps, Qs), 0)
      ∧ cy Ps = some ((Rs, Ps, Qs), 1)
      ∧ cy Qs = some ((Rs, Ps, Qs), 2)
      ∧ rank Ps = rank Rs ∧ rank Qs = rank Rs
      ∧ (∀ e ∈ gOthersD Ps (aut.trans Rs), rank e.2.2 < rank Rs)
      ∧ gOthersD Rs (gOthersD Qs (aut.trans Ps)) = []
      ∧ gOthersD Rs (gOthersD Qs (aut.trans Qs)) = []
      ∧ GuardImplies (.not (gGuardD Qs (aut.trans Ps)))
          (gGuardD Rs (gOthersD Qs (aut.trans Ps)))
      ∧ GuardImplies (.not (gGuardD Qs (aut.trans Qs)))
          (gGuardD Rs (gOthersD Qs (aut.trans Qs)))
      ∧ GuardEmpty (aut.hlt Ps) ∧ GuardEmpty (aut.hlt Qs))
    (hbase : ∀ s ∈ aut.states, cy s = none →
      ∀ e ∈ aut.trans s, e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨asmSolCD aut rank cy, fun s hs => ?_⟩
  cases hcys : cy s with
  | none =>
      have hlow : ∀ e ∈ gOthersD s (aut.trans s), rank e.2.2 < rank s := by
        intro e he
        obtain ⟨heL, hne⟩ := gOthersD_sub s (aut.trans s) e he
        rcases hbase s hs hcys e heL with h1 | h2
        · exact absurd h1 hne
        · exact h2
      have hsol : asmSolCD aut rank cy s
          = .seq (.wh (gGuardD s (aut.trans s)) (gBodyD s (aut.trans s)))
              (foldTL (asmSolCD aut rank cy) (aut.hlt s)
                (gOthersD s (aut.trans s))) := by
        rw [asmSolCD_eq, hcys]
        exact congrArg _ (foldTL_congrC (aut.hlt s) (gOthersD s (aut.trans s))
          (fun e he => dif_pos (hlow e he)))
      refine StateRole.salomaaE (gGuardD s (aut.trans s))
        (gBodyD s (aut.trans s))
        (foldTL (asmSolCD aut rank cy) (aut.hlt s) (gOthersD s (aut.trans s)))
        hsol ?_
      rw [eqRHS_foldTL]
      exact multi_gatherD (asmSolCD aut rank cy) (aut.hlt s) s (aut.trans s)
  | some q =>
      obtain ⟨⟨Rs, Ps, Qs⟩, i⟩ := q
      obtain ⟨hpos, hcyR, hcyP, hcyQ, hrkP, hrkQ, hport_lo, hnilP, hnilQ,
        himpP, himpQ, hempP, hempQ⟩ := hcy s Rs Ps Qs i hcys
      have hlowR : ∀ e ∈ gOthersD Ps (aut.trans Rs),
          (if _ : rank e.2.2 < rank Rs then asmSolCD aut rank cy e.2.2
            else Exp.test BExp.zero) = asmSolCD aut rank cy e.2.2 :=
        fun e he => dif_pos (hport_lo e he)
      have hlowP : ∀ e ∈ gOthersD Ps (aut.trans Rs),
          (if _ : rank e.2.2 < rank Ps then asmSolCD aut rank cy e.2.2
            else Exp.test BExp.zero) = asmSolCD aut rank cy e.2.2 :=
        fun e he => dif_pos (by rw [hrkP]; exact hport_lo e he)
      have hlowQ : ∀ e ∈ gOthersD Ps (aut.trans Rs),
          (if _ : rank e.2.2 < rank Qs then asmSolCD aut rank cy e.2.2
            else Exp.test BExp.zero) = asmSolCD aut rank cy e.2.2 :=
        fun e he => dif_pos (by rw [hrkQ]; exact hport_lo e he)
      have hsolR_eq : asmSolCD aut rank cy Rs
          = chordPortED aut (asmSolCD aut rank cy) Rs Ps Qs := by
        rw [asmSolCD_eq, hcyR]
        show (if (0 : Nat) = 0 then _ else _) = _
        rw [if_pos rfl]
        exact chordPortED_congr aut Rs Ps Qs hlowR
      have hsolP_eq : asmSolCD aut rank cy Ps
          = chordBranchED aut (asmSolCD aut rank cy) Rs Ps Qs := by
        rw [asmSolCD_eq, hcyP]
        show (if (1 : Nat) = 0 then _ else if (1 : Nat) = 1 then _ else _) = _
        rw [if_neg (by omega : ¬ (1 : Nat) = 0), if_pos rfl]
        exact chordBranchED_congr aut Rs Ps Qs hlowP
      have hsolQ_eq : asmSolCD aut rank cy Qs
          = chordInnerED aut (asmSolCD aut rank cy) Rs Ps Qs := by
        rw [asmSolCD_eq, hcyQ]
        show (if (2 : Nat) = 0 then _ else if (2 : Nat) = 1 then _ else _) = _
        rw [if_neg (by omega : ¬ (2 : Nat) = 0),
          if_neg (by omega : ¬ (2 : Nat) = 1)]
        exact chordInnerED_congr aut Rs Ps Qs hlowQ
      have hsolQ' : asmSolCD aut rank cy Qs
          = .seq (.wh (gGuardD Qs (aut.trans Qs)) (gBodyD Qs (aut.trans Qs)))
              (.seq (gBodyD Rs (gOthersD Qs (aut.trans Qs)))
                (asmSolCD aut rank cy Rs)) := by
        rw [hsolQ_eq]
        show chordInnerED aut (asmSolCD aut rank cy) Rs Ps Qs
          = .seq (.wh (gGuardD Qs (aut.trans Qs)) (gBodyD Qs (aut.trans Qs)))
              (.seq (gBodyD Rs (gOthersD Qs (aut.trans Qs)))
                (asmSolCD aut rank cy Rs))
        rw [hsolR_eq]
        rfl
      have hsolP' : asmSolCD aut rank cy Ps
          = .ite (gGuardD Qs (aut.trans Ps))
              (.seq (gBodyD Qs (aut.trans Ps)) (asmSolCD aut rank cy Qs))
              (.seq (gBodyD Rs (gOthersD Qs (aut.trans Ps)))
                (asmSolCD aut rank cy Rs)) := by
        rw [hsolP_eq]
        show chordBranchED aut (asmSolCD aut rank cy) Rs Ps Qs = _
        rw [hsolR_eq, hsolQ_eq]
        rfl
      have hsolR' : asmSolCD aut rank cy Rs
          = .seq (.wh (gGuardD Ps (aut.trans Rs))
              (.seq (gBodyD Ps (aut.trans Rs))
                (chordPreS (gGuardD Qs (aut.trans Ps))
                  (gGuardD Qs (aut.trans Qs)) (gBodyD Qs (aut.trans Ps))
                  (gBodyD Qs (aut.trans Qs))
                  (gBodyD Rs (gOthersD Qs (aut.trans Qs)))
                  (gBodyD Rs (gOthersD Qs (aut.trans Ps))))))
              (foldTL (asmSolCD aut rank cy) (aut.hlt Rs)
                (gOthersD Ps (aut.trans Rs))) := by
        rw [hsolR_eq]
        rfl
      have hroles := chord3_roles_split aut (asmSolCD aut rank cy) Ps Qs Rs
        (gGuardD Ps (aut.trans Rs)) (gGuardD Qs (aut.trans Ps))
        (gGuardD Qs (aut.trans Qs)) (gBodyD Ps (aut.trans Rs))
        (gBodyD Qs (aut.trans Ps)) (gBodyD Qs (aut.trans Qs))
        (gBodyD Rs (gOthersD Qs (aut.trans Qs)))
        (gBodyD Rs (gOthersD Qs (aut.trans Ps)))
        (foldTL (asmSolCD aut rank cy) (aut.hlt Rs)
          (gOthersD Ps (aut.trans Rs)))
        hsolQ' hsolP' hsolR'
        (by
          rw [eqRHS_foldTL]
          refine EquivBA.trans (double_gatherD (asmSolCD aut rank cy)
            (aut.hlt Qs) Qs Rs (aut.trans Qs)) ?_
          rw [hnilQ]
          exact chord_else_collapse himpQ hempQ _ _)
        (by
          rw [eqRHS_foldTL]
          refine EquivBA.trans (double_gatherD (asmSolCD aut rank cy)
            (aut.hlt Ps) Qs Rs (aut.trans Ps)) ?_
          rw [hnilP]
          exact chord_else_collapse himpP hempP _ _)
        (by
          rw [eqRHS_foldTL]
          exact multi_gatherD (asmSolCD aut rank cy) (aut.hlt Rs) Ps
            (aut.trans Rs))
      obtain ⟨hroleP, hroleQ, hroleR⟩ := hroles
      rcases hpos with ⟨-, hsR⟩ | ⟨-, hsP⟩ | ⟨-, hsQ⟩
      · rw [hsR]; exact hroleR
      · rw [hsP]; exact hroleP
      · rw [hsQ]; exact hroleQ

#print axioms chord_assembly_rolesD

/-! ## The fragment facts, left side: liveness and trim transparency

    With the exits satisfiable (`sat ¬c`, `sat ¬b`), every core state
    reaches a halt, so the trim is invisible and the trimmed sum steps
    are the concrete step lemmas verbatim. -/

open Classical in
/-- The port is live: exit at `¬b`. -/
theorem threeLoop_live_r (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (threeLoopAut b c p q r).toGAut aut₂)
      (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αb, [], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inr (Sum.inr ()))]
  show bval (genW T)
    ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) αb = true
  rw [threeLoop_hlt_r, hαb]
  rfl

open Classical in
/-- The inner state is live: advance at `¬c`, exit at `¬b`. -/
theorem threeLoop_live_q (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (threeLoopAut b c p q r).toGAut aut₂)
      (Sum.inl (some (Sum.inr (Sum.inl ())))) := by
  obtain ⟨αc, hαc⟩ := hexitC
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αc, [(r, αb)], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inr (Sum.inl ()))]
  refine ⟨Sum.inr (Sum.inr ()), ?_, ?_⟩
  · show firstMatch (genW T) αc
      ((threeLoopAut b c p q r).core.trans (Sum.inr (Sum.inl ())))
      = some (r, Sum.inr (Sum.inr ()))
    exact threeLoop_step_q_adv b c p q r αc hαc
  · show bval (genW T)
      ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) αb = true
    rw [threeLoop_hlt_r, hαb]
    rfl

open Classical in
/-- The branch state is live: skip at `¬c`, exit at `¬b`. -/
theorem threeLoop_live_p (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (threeLoopAut b c p q r).toGAut aut₂)
      (Sum.inl (some (Sum.inl ()))) := by
  obtain ⟨αc, hαc⟩ := hexitC
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αc, [(r, αb)], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inl ())]
  refine ⟨Sum.inr (Sum.inr ()), ?_, ?_⟩
  · show firstMatch (genW T) αc
      ((threeLoopAut b c p q r).core.trans (Sum.inl ()))
      = some (r, Sum.inr (Sum.inr ()))
    exact threeLoop_step_p_skip b c p q r αc hαc
  · show bval (genW T)
      ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) αb = true
    rw [threeLoop_hlt_r, hαb]
    rfl

open Classical in
/-- Every core state of the chord automaton is live. -/
theorem threeLoop_live_all (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum Unit Unit)) :
    Live (sumGAut (threeLoopAut b c p q r).toGAut aut₂)
      (Sum.inl (some s)) := by
  cases s with
  | inl u =>
      cases u
      exact threeLoop_live_p b c p q r aut₂ hexitC hexitB
  | inr v =>
      cases v with
      | inl u =>
          cases u
          exact threeLoop_live_q b c p q r aut₂ hexitC hexitB
      | inr u =>
          cases u
          exact threeLoop_live_r b c p q r aut₂ hexitB

open Classical in
/-- All composite arms at a chord core state have live targets. -/
theorem threeLoop_targets_live (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum Unit Unit)) :
    ∀ e ∈ (sumGAut (threeLoopAut b c p q r).toGAut aut₂).trans
        (Sum.inl (some s)),
      Live (sumGAut (threeLoopAut b c p q r).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inl (some t₀.2.2))
  exact threeLoop_live_all b c p q r aut₂ hexitC hexitB t₀.2.2

open Classical in
/-- Trimmed sum step, branch state, `c`-atom: enter the inner loop. -/
theorem threeLoop_trim_step_p_enter (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
        (Sum.inl (some (Sum.inl ()))) α
      = some (q, Sum.inl (some (Sum.inr (Sum.inl ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live b c p q r aut₂ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [threeLoop_step_p_enter b c p q r α hc]
  rfl

open Classical in
/-- Trimmed sum step, branch state, `¬c`-atom: the chord to the port. -/
theorem threeLoop_trim_step_p_skip (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
        (Sum.inl (some (Sum.inl ()))) α
      = some (r, Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live b c p q r aut₂ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [threeLoop_step_p_skip b c p q r α hc]
  rfl

open Classical in
/-- Trimmed sum step, inner state, `c`-atom: self. -/
theorem threeLoop_trim_step_q_self (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inl ())))) α
      = some (q, Sum.inl (some (Sum.inr (Sum.inl ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live b c p q r aut₂ hexitC hexitB
      (Sum.inr (Sum.inl ()))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [threeLoop_step_q_self b c p q r α hc]
  rfl

open Classical in
/-- Trimmed sum step, inner state, `¬c`-atom: advance to the port. -/
theorem threeLoop_trim_step_q_adv (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inl ())))) α
      = some (r, Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live b c p q r aut₂ hexitC hexitB
      (Sum.inr (Sum.inl ()))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [threeLoop_step_q_adv b c p q r α hc]
  rfl

open Classical in
/-- Trimmed sum step, port, `b`-atom: feed back to the branch state. -/
theorem threeLoop_trim_step_r_feed (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    autStep (genW T)
        (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inr ())))) α
      = some (p, Sum.inl (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live b c p q r aut₂ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [threeLoop_step_r_feed b c p q r α hb]
  rfl

open Classical in
/-- Trimmed sum step, port, `¬b`-atom: no step. -/
theorem threeLoop_trim_step_r_none (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    autStep (genW T)
        (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inr ())))) α
      = none := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live b c p q r aut₂ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [threeLoop_step_r_none b c p q r α hb]
  rfl

#print axioms threeLoop_live_all
#print axioms threeLoop_targets_live
#print axioms threeLoop_trim_step_p_skip
#print axioms threeLoop_trim_step_r_none

/-! ## Init-state target liveness and the right-summand mirrors -/

open Classical in
/-- All composite arms at the LEFT INIT state have live targets. -/
theorem threeLoop_targets_live_none (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut (threeLoopAut b c p q r).toGAut aut₂).trans
        (Sum.inl (none : Option (Sum Unit (Sum Unit Unit)))),
      Live (sumGAut (threeLoopAut b c p q r).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inl (some t₀.2.2))
  exact threeLoop_live_all b c p q r aut₂ hexitC hexitB t₀.2.2

open Classical in
/-- Every core state is live, right summand. -/
theorem threeLoop_live_all_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum Unit Unit)) :
    Live (sumGAut aut₁ (threeLoopAut b c p q r).toGAut)
      (Sum.inr (some s)) := by
  obtain ⟨αc, hαc⟩ := hexitC
  obtain ⟨αb, hαb⟩ := hexitB
  cases s with
  | inl u =>
      cases u
      refine ⟨αc, [(r, αb)], ?_⟩
      rw [autRun_sumGAut_inr,
        autRun_toGAut_some (start := Sum.inl ())]
      refine ⟨Sum.inr (Sum.inr ()), ?_, ?_⟩
      · exact threeLoop_step_p_skip b c p q r αc hαc
      · show bval (genW T)
          ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) αb
            = true
        rw [threeLoop_hlt_r, hαb]
        rfl
  | inr v =>
      cases v with
      | inl u =>
          cases u
          refine ⟨αc, [(r, αb)], ?_⟩
          rw [autRun_sumGAut_inr,
            autRun_toGAut_some (start := Sum.inr (Sum.inl ()))]
          refine ⟨Sum.inr (Sum.inr ()), ?_, ?_⟩
          · exact threeLoop_step_q_adv b c p q r αc hαc
          · show bval (genW T)
              ((threeLoopAut b c p q r).core.hlt
                (Sum.inr (Sum.inr ()))) αb = true
            rw [threeLoop_hlt_r, hαb]
            rfl
      | inr u =>
          cases u
          refine ⟨αb, [], ?_⟩
          rw [autRun_sumGAut_inr,
            autRun_toGAut_some (start := Sum.inr (Sum.inr ()))]
          show bval (genW T)
            ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) αb
              = true
          rw [threeLoop_hlt_r, hαb]
          rfl

open Classical in
/-- All composite arms at a right core state have live targets. -/
theorem threeLoop_targets_live_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum Unit Unit)) :
    ∀ e ∈ (sumGAut aut₁ (threeLoopAut b c p q r).toGAut).trans
        (Sum.inr (some s)),
      Live (sumGAut aut₁ (threeLoopAut b c p q r).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inr (some t₀.2.2))
  exact threeLoop_live_all_r b c p q r aut₁ hexitC hexitB t₀.2.2

open Classical in
/-- All composite arms at the RIGHT INIT state have live targets. -/
theorem threeLoop_targets_live_none_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut aut₁ (threeLoopAut b c p q r).toGAut).trans
        (Sum.inr (none : Option (Sum Unit (Sum Unit Unit)))),
      Live (sumGAut aut₁ (threeLoopAut b c p q r).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inr (some t₀.2.2))
  exact threeLoop_live_all_r b c p q r aut₁ hexitC hexitB t₀.2.2

open Classical in
theorem threeLoop_trim_step_p_enter_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
        (Sum.inr (some (Sum.inl ()))) α
      = some (q, Sum.inr (some (Sum.inr (Sum.inl ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live_r b c p q r aut₁ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [threeLoop_step_p_enter b c p q r α hc]
  rfl

open Classical in
theorem threeLoop_trim_step_p_skip_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
        (Sum.inr (some (Sum.inl ()))) α
      = some (r, Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live_r b c p q r aut₁ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [threeLoop_step_p_skip b c p q r α hc]
  rfl

open Classical in
theorem threeLoop_trim_step_q_self_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inl ())))) α
      = some (q, Sum.inr (some (Sum.inr (Sum.inl ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live_r b c p q r aut₁ hexitC hexitB
      (Sum.inr (Sum.inl ()))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [threeLoop_step_q_self b c p q r α hc]
  rfl

open Classical in
theorem threeLoop_trim_step_q_adv_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inl ())))) α
      = some (r, Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live_r b c p q r aut₁ hexitC hexitB
      (Sum.inr (Sum.inl ()))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [threeLoop_step_q_adv b c p q r α hc]
  rfl

open Classical in
theorem threeLoop_trim_step_r_feed_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inr ())))) α
      = some (p, Sum.inr (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live_r b c p q r aut₁ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [threeLoop_step_r_feed b c p q r α hb]
  rfl

open Classical in
theorem threeLoop_trim_step_r_none_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inr ())))) α
      = none := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (threeLoop_targets_live_r b c p q r aut₁ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [threeLoop_step_r_none b c p q r α hb]
  rfl

#print axioms threeLoop_live_all_r
#print axioms threeLoop_targets_live_none
#print axioms threeLoop_trim_step_p_skip_r
#print axioms threeLoop_trim_step_r_none_r

/-! ## Init steps and the init–port identification

    The init pseudostate steps exactly as the port (enter the lap doing
    `p` at `b`-atoms, rest at `¬b`), so their trimmed languages coincide
    — no induction, just `lang_eq_of_step_hlt`. -/

open Classical in
/-- Init step at a `b`-atom: enter the lap. -/
theorem threeLoop_step_init_enter (b c : BExp T) (p q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    firstMatch (genW T) α ((threeLoopAut b c p q r).initTrans)
      = some (p, Sum.inl ()) := by
  show (if (bval (genW T) b α && true) = true
    then some (p, Sum.inl ())
    else _) = some (p, Sum.inl ())
  rw [hb]
  rfl

open Classical in
/-- Init rest at a `¬b`-atom. -/
theorem threeLoop_step_init_none (b c : BExp T) (p q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α ((threeLoopAut b c p q r).initTrans)
      = none := by
  show (if (bval (genW T) b α && true) = true
    then some (p, Sum.inl ())
    else if (bval (genW T) b α
        && (false && (bval (genW T) c α && true))) = true
      then some (q, Sum.inr (Sum.inl ()))
      else if (bval (genW T) b α
          && (false && (!(bval (genW T) c α) && true))) = true
        then some (r, Sum.inr (Sum.inr ()))
        else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

open Classical in
/-- **INIT ~ PORT** (left): the start class is the port class. -/
theorem threeLoop_none_lang (b c : BExp T) (p q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
        (Sum.inl (none : Option (Sum Unit (Sum Unit Unit))))
      = autLang (genW T)
          (trimAut (sumGAut (threeLoopAut b c p q r).toGAut aut₂))
          (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (threeLoop_targets_live_none b c p q r aut₂ hexitC hexitB) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (threeLoop_targets_live b c p q r aut₂ hexitC hexitB
        (Sum.inr (Sum.inr ()))) α]
    rw [autStep_sumGAut_inl, autStep_sumGAut_inl]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    cases hb : bval (genW T) b α with
    | false =>
        rw [threeLoop_step_init_none b c p q r α hb,
          threeLoop_step_r_none b c p q r α hb]
    | true =>
        rw [threeLoop_step_init_enter b c p q r α hb,
          threeLoop_step_r_feed b c p q r α hb]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) α
    rw [threeLoop_hlt_r]

open Classical in
/-- **INIT ~ PORT** (right). -/
theorem threeLoop_none_lang_r (b c : BExp T) (p q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
        (Sum.inr (none : Option (Sum Unit (Sum Unit Unit))))
      = autLang (genW T)
          (trimAut (sumGAut aut₁ (threeLoopAut b c p q r).toGAut))
          (Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (threeLoop_targets_live_none_r b c p q r aut₁ hexitC hexitB) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (threeLoop_targets_live_r b c p q r aut₁ hexitC hexitB
        (Sum.inr (Sum.inr ()))) α]
    rw [autStep_sumGAut_inr, autStep_sumGAut_inr]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    cases hb : bval (genW T) b α with
    | false =>
        rw [threeLoop_step_init_none b c p q r α hb,
          threeLoop_step_r_none b c p q r α hb]
    | true =>
        rw [threeLoop_step_init_enter b c p q r α hb,
          threeLoop_step_r_feed b c p q r α hb]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((threeLoopAut b c p q r).core.hlt (Sum.inr (Sum.inr ()))) α
    rw [threeLoop_hlt_r]

#print axioms threeLoop_step_init_enter
#print axioms threeLoop_none_lang
#print axioms threeLoop_none_lang_r

/-! ## THE TRUE CHORD WITNESS

    Course correction: in `wh b (p; (wh c q); r)` the branch state and
    the inner-loop head have IDENTICAL residuals (`(wh c q); r; loop`),
    so they are bisimilar and the canonical quotient collapses to the
    walked 2-cycle shape — that program is NOT beyond the walked
    discipline.  The genuine frontier witness makes the entered branch
    rejoin LATER than the skip:

        `chordLoop b c p x y  :=  wh b (p; ite c (x; y) y)`

    Quotient classes: port (= both post-`y` states and init), the branch
    `P` (post-`p`), and the mid state `X` (post-`x`).  Cycle
    port → P → X → port with the CHORD P → port — the branch state maps
    per-atom onto TWO forward positions, beyond `WalkedDec`, and exactly
    the `chord_assembly_roles` cluster with the inner state's self-guard
    semantically zero. -/

/-- The chord witness body: a two-action detour or a straight skip. -/
def chordBody (c : BExp T) (p x y : A) : Exp A T :=
  .seq (.act p) (.ite c (.seq (.act x) (.act y)) (.act y))

/-- The chord witness program. -/
def chordLoop (b c : BExp T) (p x y : A) : Exp A T :=
  .wh b (chordBody c p x y)

/-- Its loop automaton.  States: `inl () = P` (post-`p`, the branch),
    `inr (inl (inl ())) = X` (post-`x`), `inr (inl (inr ())) = Yl`
    (post-`y`, detour), `inr (inr ()) = Yr` (post-`y`, skip). -/
def chordLoopAut (b c : BExp T) (p x y : A) :
    InitializedGAut (Sum Unit (Sum (Sum Unit Unit) Unit)) A T :=
  loopInitialized b (certifiedThompson A T (chordBody c p x y)).aut

/-- **THE BRANCH, ENTER**: at a `c`-atom, `P` takes the detour. -/
theorem chord_step_p_enter (b c : BExp T) (p x y : A)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α
        ((chordLoopAut b c p x y).core.trans (Sum.inl ()))
      = some (x, Sum.inr (Sum.inl (Sum.inl ()))) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (x, Sum.inr (Sum.inl (Sum.inl ())))
    else _) = some (x, Sum.inr (Sum.inl (Sum.inl ())))
  rw [hc]
  rfl

/-- **THE CHORD**: at a `¬c`-atom, `P` skips straight to a port state. -/
theorem chord_step_p_skip (b c : BExp T) (p x y : A)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α
        ((chordLoopAut b c p x y).core.trans (Sum.inl ()))
      = some (y, Sum.inr (Sum.inr ())) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (x, Sum.inr (Sum.inl (Sum.inl ())))
    else if (true && (bval (genW T) c α && (false && true))) = true
      then some (y, Sum.inr (Sum.inl (Sum.inr ())))
      else if (true && (!(bval (genW T) c α) && true)) = true
        then some (y, Sum.inr (Sum.inr ()))
        else _) = some (y, Sum.inr (Sum.inr ()))
  rw [hc]
  rfl

/-- The mid state fires `y` to the detour port at EVERY atom. -/
theorem chord_step_x (b c : BExp T) (p x y : A) (α : T → Bool) :
    firstMatch (genW T) α
        ((chordLoopAut b c p x y).core.trans
          (Sum.inr (Sum.inl (Sum.inl ()))))
      = some (y, Sum.inr (Sum.inl (Sum.inr ()))) := by
  show (if (true && true) = true
    then some (y, Sum.inr (Sum.inl (Sum.inr ())))
    else _) = some (y, Sum.inr (Sum.inl (Sum.inr ())))
  rfl

/-- Detour-port feedback at a `b`-atom. -/
theorem chord_step_yl_feed (b c : BExp T) (p x y : A)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    firstMatch (genW T) α
        ((chordLoopAut b c p x y).core.trans
          (Sum.inr (Sum.inl (Sum.inr ()))))
      = some (p, Sum.inl ()) := by
  show (if (true && (bval (genW T) b α && true)) = true
    then some (p, Sum.inl ())
    else _) = some (p, Sum.inl ())
  rw [hb]
  rfl

/-- Detour-port rest at a `¬b`-atom. -/
theorem chord_step_yl_none (b c : BExp T) (p x y : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α
        ((chordLoopAut b c p x y).core.trans
          (Sum.inr (Sum.inl (Sum.inr ()))))
      = none := by
  show (if (true && (bval (genW T) b α && true)) = true
    then some (p, Sum.inl ())
    else if (true && (bval (genW T) b α
        && (false && (bval (genW T) c α && true)))) = true
      then some (x, Sum.inr (Sum.inl (Sum.inl ())))
      else if (true && (bval (genW T) b α
          && (false && (bval (genW T) c α && (false && true))))) = true
        then some (y, Sum.inr (Sum.inl (Sum.inr ())))
        else if (true && (bval (genW T) b α
            && (false && (!(bval (genW T) c α) && true)))) = true
          then some (y, Sum.inr (Sum.inr ()))
          else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

/-- Skip-port feedback at a `b`-atom. -/
theorem chord_step_yr_feed (b c : BExp T) (p x y : A)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    firstMatch (genW T) α
        ((chordLoopAut b c p x y).core.trans (Sum.inr (Sum.inr ())))
      = some (p, Sum.inl ()) := by
  show (if (true && (bval (genW T) b α && true)) = true
    then some (p, Sum.inl ())
    else _) = some (p, Sum.inl ())
  rw [hb]
  rfl

/-- Skip-port rest at a `¬b`-atom. -/
theorem chord_step_yr_none (b c : BExp T) (p x y : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α
        ((chordLoopAut b c p x y).core.trans (Sum.inr (Sum.inr ())))
      = none := by
  show (if (true && (bval (genW T) b α && true)) = true
    then some (p, Sum.inl ())
    else if (true && (bval (genW T) b α
        && (false && (bval (genW T) c α && true)))) = true
      then some (x, Sum.inr (Sum.inl (Sum.inl ())))
      else if (true && (bval (genW T) b α
          && (false && (bval (genW T) c α && (false && true))))) = true
        then some (y, Sum.inr (Sum.inl (Sum.inr ())))
        else if (true && (bval (genW T) b α
            && (false && (!(bval (genW T) c α) && true)))) = true
          then some (y, Sum.inr (Sum.inr ()))
          else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

/-- The branch state never halts. -/
theorem chord_hlt_p (b c : BExp T) (p x y : A) :
    ∀ α : T → Bool,
      bval (genW T)
        ((chordLoopAut b c p x y).core.hlt (Sum.inl ())) α = false := by
  intro α
  show ((true && ((bval (genW T) c α && (false && false))
      || (!(bval (genW T) c α) && false)))
    && !(bval (genW T) b α)) = false
  cases bval (genW T) c α <;> cases bval (genW T) b α <;> rfl

/-- The mid state never halts. -/
theorem chord_hlt_x (b c : BExp T) (p x y : A) :
    ∀ α : T → Bool,
      bval (genW T)
        ((chordLoopAut b c p x y).core.hlt
          (Sum.inr (Sum.inl (Sum.inl ())))) α = false := by
  intro α
  show ((true && false) && !(bval (genW T) b α)) = false
  cases bval (genW T) b α <;> rfl

/-- The detour port halts exactly at `¬b`. -/
theorem chord_hlt_yl (b c : BExp T) (p x y : A) :
    ∀ α : T → Bool,
      bval (genW T)
        ((chordLoopAut b c p x y).core.hlt
          (Sum.inr (Sum.inl (Sum.inr ())))) α
        = !(bval (genW T) b α) := by
  intro α
  show (true && !(bval (genW T) b α)) = !(bval (genW T) b α)
  cases bval (genW T) b α <;> rfl

/-- The skip port halts exactly at `¬b`. -/
theorem chord_hlt_yr (b c : BExp T) (p x y : A) :
    ∀ α : T → Bool,
      bval (genW T)
        ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) α
        = !(bval (genW T) b α) := by
  intro α
  show (true && !(bval (genW T) b α)) = !(bval (genW T) b α)
  cases bval (genW T) b α <;> rfl

/-- Init enter at a `b`-atom. -/
theorem chord_step_init_enter (b c : BExp T) (p x y : A)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    firstMatch (genW T) α ((chordLoopAut b c p x y).initTrans)
      = some (p, Sum.inl ()) := by
  show (if (bval (genW T) b α && true) = true
    then some (p, Sum.inl ())
    else _) = some (p, Sum.inl ())
  rw [hb]
  rfl

/-- Init rest at a `¬b`-atom. -/
theorem chord_step_init_none (b c : BExp T) (p x y : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α ((chordLoopAut b c p x y).initTrans)
      = none := by
  show (if (bval (genW T) b α && true) = true
    then some (p, Sum.inl ())
    else if (bval (genW T) b α
        && (false && (bval (genW T) c α && true))) = true
      then some (x, Sum.inr (Sum.inl (Sum.inl ())))
      else if (bval (genW T) b α
          && (false && (bval (genW T) c α && (false && true)))) = true
        then some (y, Sum.inr (Sum.inl (Sum.inr ())))
        else if (bval (genW T) b α
            && (false && (!(bval (genW T) c α) && true))) = true
          then some (y, Sum.inr (Sum.inr ()))
          else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

#print axioms chord_step_p_enter
#print axioms chord_step_p_skip
#print axioms chord_step_x
#print axioms chord_step_yl_none
#print axioms chord_hlt_p
#print axioms chord_step_init_none

/-! ## chordLoop fragment: liveness, trim transparency, and the port
    identifications (left summand) -/

open Classical in
/-- The skip port is live: exit at `¬b`. -/
theorem chord_live_yr (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (chordLoopAut b c p x y).toGAut aut₂)
      (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αb, [], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inr (Sum.inr ()))]
  show bval (genW T)
    ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb = true
  rw [chord_hlt_yr, hαb]
  rfl

open Classical in
/-- The detour port is live: exit at `¬b`. -/
theorem chord_live_yl (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (chordLoopAut b c p x y).toGAut aut₂)
      (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αb, [], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inr (Sum.inl (Sum.inr ())))]
  show bval (genW T)
    ((chordLoopAut b c p x y).core.hlt
      (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
  rw [chord_hlt_yl, hαb]
  rfl

open Classical in
/-- The mid state is live: fire `y`, exit at `¬b`. -/
theorem chord_live_x (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (chordLoopAut b c p x y).toGAut aut₂)
      (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αb, [(y, αb)], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inr (Sum.inl (Sum.inl ())))]
  refine ⟨Sum.inr (Sum.inl (Sum.inr ())), ?_, ?_⟩
  · exact chord_step_x b c p x y αb
  · show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt
        (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
    rw [chord_hlt_yl, hαb]
    rfl

open Classical in
/-- The branch state is live: skip at `¬c`, exit at `¬b`. -/
theorem chord_live_p (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (chordLoopAut b c p x y).toGAut aut₂)
      (Sum.inl (some (Sum.inl ()))) := by
  obtain ⟨αc, hαc⟩ := hexitC
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αc, [(y, αb)], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inl ())]
  refine ⟨Sum.inr (Sum.inr ()), ?_, ?_⟩
  · exact chord_step_p_skip b c p x y αc hαc
  · show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb
        = true
    rw [chord_hlt_yr, hαb]
    rfl

open Classical in
/-- Every chordLoop core state is live. -/
theorem chord_live_all (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum (Sum Unit Unit) Unit)) :
    Live (sumGAut (chordLoopAut b c p x y).toGAut aut₂)
      (Sum.inl (some s)) := by
  cases s with
  | inl u =>
      cases u
      exact chord_live_p b c p x y aut₂ hexitC hexitB
  | inr v =>
      cases v with
      | inl w =>
          cases w with
          | inl u =>
              cases u
              exact chord_live_x b c p x y aut₂ hexitB
          | inr u =>
              cases u
              exact chord_live_yl b c p x y aut₂ hexitB
      | inr u =>
          cases u
          exact chord_live_yr b c p x y aut₂ hexitB

open Classical in
/-- All composite arms at a chordLoop core state have live targets. -/
theorem chord_targets_live (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum (Sum Unit Unit) Unit)) :
    ∀ e ∈ (sumGAut (chordLoopAut b c p x y).toGAut aut₂).trans
        (Sum.inl (some s)),
      Live (sumGAut (chordLoopAut b c p x y).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inl (some t₀.2.2))
  exact chord_live_all b c p x y aut₂ hexitC hexitB t₀.2.2

open Classical in
/-- All composite arms at the init pseudostate have live targets. -/
theorem chord_targets_live_none (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut (chordLoopAut b c p x y).toGAut aut₂).trans
        (Sum.inl (none : Option (Sum Unit (Sum (Sum Unit Unit) Unit)))),
      Live (sumGAut (chordLoopAut b c p x y).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inl (some t₀.2.2))
  exact chord_live_all b c p x y aut₂ hexitC hexitB t₀.2.2

open Classical in
theorem chord_trim_step_p_enter (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inl ()))) α
      = some (x, Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live b c p x y aut₂ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [chord_step_p_enter b c p x y α hc]
  rfl

open Classical in
theorem chord_trim_step_p_skip (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inl ()))) α
      = some (y, Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live b c p x y aut₂ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [chord_step_p_skip b c p x y α hc]
  rfl

open Classical in
theorem chord_trim_step_x (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) :
    autStep (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) α
      = some (y, Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live b c p x y aut₂ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inl ())))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [chord_step_x b c p x y α]
  rfl

open Classical in
theorem chord_trim_step_yl_feed (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    autStep (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) α
      = some (p, Sum.inl (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live b c p x y aut₂ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inr ())))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [chord_step_yl_feed b c p x y α hb]
  rfl

open Classical in
theorem chord_trim_step_yl_none (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    autStep (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) α
      = none := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live b c p x y aut₂ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inr ())))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [chord_step_yl_none b c p x y α hb]
  rfl

open Classical in
theorem chord_trim_step_yr_feed (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    autStep (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inr ())))) α
      = some (p, Sum.inl (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live b c p x y aut₂ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [chord_step_yr_feed b c p x y α hb]
  rfl

open Classical in
theorem chord_trim_step_yr_none (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    autStep (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inr ())))) α
      = none := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live b c p x y aut₂ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [chord_step_yr_none b c p x y α hb]
  rfl

open Classical in
/-- **DETOUR PORT ~ SKIP PORT**: the two post-`y` states have the same
    trimmed language. -/
theorem chord_yl_yr_lang (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
          (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  apply lang_eq_of_step_hlt
  · intro α
    cases hb : bval (genW T) b α with
    | true =>
        rw [chord_trim_step_yl_feed b c p x y aut₂ hexitC hexitB α hb,
          chord_trim_step_yr_feed b c p x y aut₂ hexitC hexitB α hb]
    | false =>
        rw [chord_trim_step_yl_none b c p x y aut₂ hexitC hexitB α hb,
          chord_trim_step_yr_none b c p x y aut₂ hexitC hexitB α hb]
  · intro α
    show bval (genW T)
        ((chordLoopAut b c p x y).core.hlt
          (Sum.inr (Sum.inl (Sum.inr ())))) α
      = bval (genW T)
          ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) α
    rw [chord_hlt_yl, chord_hlt_yr]

open Classical in
/-- **INIT ~ SKIP PORT**: the start class is the port class. -/
theorem chord_none_lang (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (none : Option (Sum Unit (Sum (Sum Unit Unit) Unit))))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
          (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (chord_targets_live_none b c p x y aut₂ hexitC hexitB) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (chord_targets_live b c p x y aut₂ hexitC hexitB
        (Sum.inr (Sum.inr ()))) α]
    rw [autStep_sumGAut_inl, autStep_sumGAut_inl]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    cases hb : bval (genW T) b α with
    | false =>
        rw [chord_step_init_none b c p x y α hb,
          chord_step_yr_none b c p x y α hb]
    | true =>
        rw [chord_step_init_enter b c p x y α hb,
          chord_step_yr_feed b c p x y α hb]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) α
    rw [chord_hlt_yr]

#print axioms chord_live_all
#print axioms chord_targets_live
#print axioms chord_trim_step_p_skip
#print axioms chord_yl_yr_lang
#print axioms chord_none_lang

/-! ## chordLoop fragment: right-summand mirrors -/

open Classical in
/-- Every chordLoop core state is live, right summand. -/
theorem chord_live_all_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum (Sum Unit Unit) Unit)) :
    Live (sumGAut aut₁ (chordLoopAut b c p x y).toGAut)
      (Sum.inr (some s)) := by
  obtain ⟨αc, hαc⟩ := hexitC
  obtain ⟨αb, hαb⟩ := hexitB
  cases s with
  | inl u =>
      cases u
      refine ⟨αc, [(y, αb)], ?_⟩
      rw [autRun_sumGAut_inr,
        autRun_toGAut_some (start := Sum.inl ())]
      refine ⟨Sum.inr (Sum.inr ()), ?_, ?_⟩
      · exact chord_step_p_skip b c p x y αc hαc
      · show bval (genW T)
          ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb
            = true
        rw [chord_hlt_yr, hαb]
        rfl
  | inr v =>
      cases v with
      | inl w =>
          cases w with
          | inl u =>
              cases u
              refine ⟨αb, [(y, αb)], ?_⟩
              rw [autRun_sumGAut_inr,
                autRun_toGAut_some (start := Sum.inr (Sum.inl (Sum.inl ())))]
              refine ⟨Sum.inr (Sum.inl (Sum.inr ())), ?_, ?_⟩
              · exact chord_step_x b c p x y αb
              · show bval (genW T)
                  ((chordLoopAut b c p x y).core.hlt
                    (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
                rw [chord_hlt_yl, hαb]
                rfl
          | inr u =>
              cases u
              refine ⟨αb, [], ?_⟩
              rw [autRun_sumGAut_inr,
                autRun_toGAut_some (start := Sum.inr (Sum.inl (Sum.inr ())))]
              show bval (genW T)
                ((chordLoopAut b c p x y).core.hlt
                  (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
              rw [chord_hlt_yl, hαb]
              rfl
      | inr u =>
          cases u
          refine ⟨αb, [], ?_⟩
          rw [autRun_sumGAut_inr,
            autRun_toGAut_some (start := Sum.inr (Sum.inr ()))]
          show bval (genW T)
            ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb
              = true
          rw [chord_hlt_yr, hαb]
          rfl

open Classical in
theorem chord_targets_live_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit (Sum (Sum Unit Unit) Unit)) :
    ∀ e ∈ (sumGAut aut₁ (chordLoopAut b c p x y).toGAut).trans
        (Sum.inr (some s)),
      Live (sumGAut aut₁ (chordLoopAut b c p x y).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inr (some t₀.2.2))
  exact chord_live_all_r b c p x y aut₁ hexitC hexitB t₀.2.2

open Classical in
theorem chord_targets_live_none_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut aut₁ (chordLoopAut b c p x y).toGAut).trans
        (Sum.inr (none : Option (Sum Unit (Sum (Sum Unit Unit) Unit)))),
      Live (sumGAut aut₁ (chordLoopAut b c p x y).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inr (some t₀.2.2))
  exact chord_live_all_r b c p x y aut₁ hexitC hexitB t₀.2.2

open Classical in
theorem chord_trim_step_p_enter_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inl ()))) α
      = some (x, Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live_r b c p x y aut₁ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [chord_step_p_enter b c p x y α hc]
  rfl

open Classical in
theorem chord_trim_step_p_skip_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inl ()))) α
      = some (y, Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live_r b c p x y aut₁ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [chord_step_p_skip b c p x y α hc]
  rfl

open Classical in
theorem chord_trim_step_x_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) α
      = some (y, Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live_r b c p x y aut₁ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inl ())))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [chord_step_x b c p x y α]
  rfl

open Classical in
theorem chord_trim_step_yl_feed_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) α
      = some (p, Sum.inr (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live_r b c p x y aut₁ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inr ())))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [chord_step_yl_feed b c p x y α hb]
  rfl

open Classical in
theorem chord_trim_step_yl_none_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) α
      = none := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live_r b c p x y aut₁ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inr ())))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [chord_step_yl_none b c p x y α hb]
  rfl

open Classical in
theorem chord_trim_step_yr_feed_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inr ())))) α
      = some (p, Sum.inr (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live_r b c p x y aut₁ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [chord_step_yr_feed b c p x y α hb]
  rfl

open Classical in
theorem chord_trim_step_yr_none_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inr ())))) α
      = none := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (chord_targets_live_r b c p x y aut₁ hexitC hexitB
      (Sum.inr (Sum.inr ()))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [chord_step_yr_none b c p x y α hb]
  rfl

open Classical in
/-- Detour port ~ skip port, right summand. -/
theorem chord_yl_yr_lang_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ())))))
      = autLang (genW T)
          (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
          (Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  apply lang_eq_of_step_hlt
  · intro α
    cases hb : bval (genW T) b α with
    | true =>
        rw [chord_trim_step_yl_feed_r b c p x y aut₁ hexitC hexitB α hb,
          chord_trim_step_yr_feed_r b c p x y aut₁ hexitC hexitB α hb]
    | false =>
        rw [chord_trim_step_yl_none_r b c p x y aut₁ hexitC hexitB α hb,
          chord_trim_step_yr_none_r b c p x y aut₁ hexitC hexitB α hb]
  · intro α
    show bval (genW T)
        ((chordLoopAut b c p x y).core.hlt
          (Sum.inr (Sum.inl (Sum.inr ())))) α
      = bval (genW T)
          ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) α
    rw [chord_hlt_yl, chord_hlt_yr]

open Classical in
/-- Init ~ skip port, right summand. -/
theorem chord_none_lang_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (none : Option (Sum Unit (Sum (Sum Unit Unit) Unit))))
      = autLang (genW T)
          (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
          (Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (chord_targets_live_none_r b c p x y aut₁ hexitC hexitB) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (chord_targets_live_r b c p x y aut₁ hexitC hexitB
        (Sum.inr (Sum.inr ()))) α]
    rw [autStep_sumGAut_inr, autStep_sumGAut_inr]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    cases hb : bval (genW T) b α with
    | false =>
        rw [chord_step_init_none b c p x y α hb,
          chord_step_yr_none b c p x y α hb]
    | true =>
        rw [chord_step_init_enter b c p x y α hb,
          chord_step_yr_feed b c p x y α hb]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) α
    rw [chord_hlt_yr]

#print axioms chord_live_all_r
#print axioms chord_yl_yr_lang_r
#print axioms chord_none_lang_r

/-! ## The separations: port ≠ branch ≠ mid

    The port is separated from both interior states by the empty word at
    a `¬b`-atom.  The branch and the mid state are separated by the
    one-step probe `⟨α_c, [(y, α_¬b)]⟩`: the mid state fires `y` into
    the detour port and halts; the branch state's step at a `c`-atom is
    pinned to `(x, X)`, so accepting the probe would force the mid state
    to halt — it is silent.  `sat c` is NECESSARY: with `c` empty both
    arms of the `ite` collapse and `P ~ X`. -/

open Classical in
/-- Interior silence: the branch state accepts no empty word. -/
theorem chord_noeps_p (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
          (Sum.inl (some (Sum.inl ()))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inl ())) α = true := h
  rw [chord_hlt_p] at h'
  exact nomatch h'

open Classical in
/-- Interior silence: the mid state accepts no empty word. -/
theorem chord_noeps_x (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
          (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((chordLoopAut b c p x y).core.hlt
        (Sum.inr (Sum.inl (Sum.inl ())))) α = true := h
  rw [chord_hlt_x] at h'
  exact nomatch h'

open Classical in
/-- Branch ≠ port. -/
theorem chord_lang_ne_p_yr (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inl ())))
      ≠ autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
          (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αb, []))
  have hport : autRun (genW T)
      (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
      (Sum.inl (some (Sum.inr (Sum.inr ())))) αb [] := by
    show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb = true
    rw [chord_hlt_yr, hαb]
    rfl
  exact chord_noeps_p b c p x y aut₂ αb (hiff.mpr hport)

open Classical in
/-- Mid ≠ port. -/
theorem chord_lang_ne_x_yr (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ())))))
      ≠ autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
          (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αb, []))
  have hport : autRun (genW T)
      (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
      (Sum.inl (some (Sum.inr (Sum.inr ())))) αb [] := by
    show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb = true
    rw [chord_hlt_yr, hαb]
    rfl
  exact chord_noeps_x b c p x y aut₂ αb (hiff.mpr hport)

open Classical in
/-- **BRANCH ≠ MID**: the one-step probe. -/
theorem chord_lang_ne_p_x (b c : BExp T) (p x y : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
        (Sum.inl (some (Sum.inl ())))
      ≠ autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
          (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) := by
  obtain ⟨αc, hαc⟩ := hentC
  obtain ⟨αb, hαb⟩ := id hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αc, [(y, αb)]))
  have hX : autRun (genW T)
      (trimAut (sumGAut (chordLoopAut b c p x y).toGAut aut₂))
      (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) αc [(y, αb)] := by
    refine ⟨Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))), ?_, ?_⟩
    · exact chord_trim_step_x b c p x y aut₂ hexitC hexitB αc
    · show bval (genW T)
        ((chordLoopAut b c p x y).core.hlt
          (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
      rw [chord_hlt_yl, hαb]
      rfl
  obtain ⟨s', hstep, hrest⟩ := hiff.mpr hX
  rw [chord_trim_step_p_enter b c p x y aut₂ hexitC hexitB αc hαc]
    at hstep
  have hpair := Option.some.inj hstep
  have hs' : Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))
      = s' := congrArg Prod.snd hpair
  rw [← hs'] at hrest
  exact chord_noeps_x b c p x y aut₂ αb hrest

open Classical in
/-- Interior silence, right summand: the branch state. -/
theorem chord_noeps_p_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
          (Sum.inr (some (Sum.inl ()))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inl ())) α = true := h
  rw [chord_hlt_p] at h'
  exact nomatch h'

open Classical in
/-- Interior silence, right summand: the mid state. -/
theorem chord_noeps_x_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
          (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((chordLoopAut b c p x y).core.hlt
        (Sum.inr (Sum.inl (Sum.inl ())))) α = true := h
  rw [chord_hlt_x] at h'
  exact nomatch h'

open Classical in
/-- Branch ≠ port, right summand. -/
theorem chord_lang_ne_p_yr_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inl ())))
      ≠ autLang (genW T)
          (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
          (Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αb, []))
  have hport : autRun (genW T)
      (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
      (Sum.inr (some (Sum.inr (Sum.inr ())))) αb [] := by
    show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb = true
    rw [chord_hlt_yr, hαb]
    rfl
  exact chord_noeps_p_r b c p x y aut₁ αb (hiff.mpr hport)

open Classical in
/-- Mid ≠ port, right summand. -/
theorem chord_lang_ne_x_yr_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ())))))
      ≠ autLang (genW T)
          (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
          (Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αb, []))
  have hport : autRun (genW T)
      (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
      (Sum.inr (some (Sum.inr (Sum.inr ())))) αb [] := by
    show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb = true
    rw [chord_hlt_yr, hαb]
    rfl
  exact chord_noeps_x_r b c p x y aut₁ αb (hiff.mpr hport)

open Classical in
/-- Branch ≠ mid, right summand. -/
theorem chord_lang_ne_p_x_r (b c : BExp T) (p x y : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
        (Sum.inr (some (Sum.inl ())))
      ≠ autLang (genW T)
          (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
          (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) := by
  obtain ⟨αc, hαc⟩ := hentC
  obtain ⟨αb, hαb⟩ := id hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αc, [(y, αb)]))
  have hX : autRun (genW T)
      (trimAut (sumGAut aut₁ (chordLoopAut b c p x y).toGAut))
      (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) αc [(y, αb)] := by
    refine ⟨Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ())))), ?_, ?_⟩
    · exact chord_trim_step_x_r b c p x y aut₁ hexitC hexitB αc
    · show bval (genW T)
        ((chordLoopAut b c p x y).core.hlt
          (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
      rw [chord_hlt_yl, hαb]
      rfl
  obtain ⟨s', hstep, hrest⟩ := hiff.mpr hX
  rw [chord_trim_step_p_enter_r b c p x y aut₁ hexitC hexitB αc hαc]
    at hstep
  have hpair := Option.some.inj hstep
  have hs' : Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))
      = s' := congrArg Prod.snd hpair
  rw [← hs'] at hrest
  exact chord_noeps_x_r b c p x y aut₁ αb hrest

#print axioms chord_lang_ne_p_yr
#print axioms chord_lang_ne_x_yr
#print axioms chord_lang_ne_p_x
#print axioms chord_lang_ne_p_x_r

/-! ## Cross-side pairings

    Language equality of the two start classes propagates around the
    cycle by DERIVATIVE TRANSFER: if two states have equal languages and
    both step at some atom, determinism forces the fired actions equal
    and the successor languages equal (given the first successor is
    nonempty).  Around the cycle this pairs the two summands' classes
    AND extracts the action equalities `p = p'`, `x = x'`, `y = y'`
    from the semantic hypothesis. -/

open Classical in
/-- **DERIVATIVE TRANSFER**: equal languages step to equal-action,
    equal-language successors. -/
theorem chord_lang_deriv {S' : Type} (aut : GAut S' A T)
    {s₁ s₂ t₁ t₂ : S'} {a₁ a₂ : A} {α : T → Bool}
    (hL : autLang (genW T) aut s₁ = autLang (genW T) aut s₂)
    (h₁ : autStep (genW T) aut s₁ α = some (a₁, t₁))
    (h₂ : autStep (genW T) aut s₂ α = some (a₂, t₂))
    (hne : ∃ gs : GS A (T → Bool), autLang (genW T) aut t₁ gs) :
    a₁ = a₂ ∧ autLang (genW T) aut t₁ = autLang (genW T) aut t₂ := by
  obtain ⟨⟨β, w⟩, hw⟩ := hne
  have hrun₁ : autRun (genW T) aut s₁ α ((a₁, β) :: w) := ⟨t₁, h₁, hw⟩
  have hrun₂ := (iff_of_eq (congrFun hL (α, (a₁, β) :: w))).mp hrun₁
  obtain ⟨s', hs', -⟩ := hrun₂
  rw [h₂] at hs'
  have hpair := Option.some.inj hs'
  have ha : a₂ = a₁ := congrArg Prod.fst hpair
  rw [ha] at h₂
  refine ⟨ha.symm, ?_⟩
  funext gs
  apply propext
  constructor
  · intro hg
    have h1 : autRun (genW T) aut s₁ α ((a₁, gs.1) :: gs.2) :=
      ⟨t₁, h₁, hg⟩
    have h2 := (iff_of_eq (congrFun hL (α, (a₁, gs.1) :: gs.2))).mp h1
    obtain ⟨u, hu, hrun⟩ := h2
    rw [h₂] at hu
    have hupair := Option.some.inj hu
    have hu' : t₂ = u := congrArg Prod.snd hupair
    rw [← hu'] at hrun
    exact hrun
  · intro hg
    have h1 : autRun (genW T) aut s₂ α ((a₁, gs.1) :: gs.2) :=
      ⟨t₂, h₂, hg⟩
    have h2 := (iff_of_eq (congrFun hL (α, (a₁, gs.1) :: gs.2))).mpr h1
    obtain ⟨u, hu, hrun⟩ := h2
    rw [h₁] at hu
    have hupair := Option.some.inj hu
    have hu' : t₁ = u := congrArg Prod.snd hupair
    rw [← hu'] at hrun
    exact hrun

open Classical in
/-- **PORT PAIRING**: the two summands' port classes coincide. -/
theorem chord_pair_port (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl none)
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr none)) :
    autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl (some (Sum.inr (Sum.inr ()))))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr (some (Sum.inr (Sum.inr ())))) := by
  refine ((chord_none_lang b c p x y _ hexitC hexitB).symm.trans
    heq).trans ?_
  exact chord_none_lang_r b' c' p' x' y' _ hexitC' hexitB'

open Classical in
/-- **BRANCH PAIRING** (+ `p = p'`): given `sat b`, the port pairing
    transfers along the feedback arms. -/
theorem chord_pair_p (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (hport : autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl (some (Sum.inr (Sum.inr ()))))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr (some (Sum.inr (Sum.inr ()))))) :
    p = p' ∧ autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl (some (Sum.inl ())))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr (some (Sum.inl ()))) := by
  obtain ⟨αB, hαB, hαB'⟩ := hentB
  obtain ⟨αc, hαc⟩ := id hexitC
  obtain ⟨αb, hαb⟩ := id hexitB
  refine chord_lang_deriv _ hport
    (chord_trim_step_yr_feed b c p x y _ hexitC hexitB αB hαB)
    (chord_trim_step_yr_feed_r b' c' p' x' y' _ hexitC' hexitB' αB hαB')
    ⟨(αc, [(y, αb)]), ?_⟩
  refine ⟨Sum.inl (some (Sum.inr (Sum.inr ()))), ?_, ?_⟩
  · exact chord_trim_step_p_skip b c p x y _ hexitC hexitB αc hαc
  · show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt (Sum.inr (Sum.inr ()))) αb
        = true
    rw [chord_hlt_yr, hαb]
    rfl

open Classical in
/-- **MID PAIRING** (+ `x = x'`): the branch pairing transfers along the
    enter arms. -/
theorem chord_pair_x (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (hP : autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl (some (Sum.inl ())))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr (some (Sum.inl ())))) :
    x = x' ∧ autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ())))))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) := by
  obtain ⟨αC, hαC, hαC'⟩ := hentC
  obtain ⟨αb, hαb⟩ := id hexitB
  refine chord_lang_deriv _ hP
    (chord_trim_step_p_enter b c p x y _ hexitC hexitB αC hαC)
    (chord_trim_step_p_enter_r b' c' p' x' y' _ hexitC' hexitB' αC hαC')
    ⟨(αb, [(y, αb)]), ?_⟩
  refine ⟨Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))), ?_, ?_⟩
  · exact chord_trim_step_x b c p x y _ hexitC hexitB αb
  · show bval (genW T)
      ((chordLoopAut b c p x y).core.hlt
        (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
    rw [chord_hlt_yl, hαb]
    rfl

open Classical in
/-- **DETOUR-PORT PAIRING** (+ `y = y'`): the mid pairing transfers
    along the unconditional arms. -/
theorem chord_pair_y (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (hX : autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ())))))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ())))))) :
    y = y' ∧ autLang (genW T)
        (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
          (chordLoopAut b' c' p' x' y').toGAut))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))))
      = autLang (genW T)
          (trimAut (sumGAut (chordLoopAut b c p x y).toGAut
            (chordLoopAut b' c' p' x' y').toGAut))
          (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) := by
  obtain ⟨αb, hαb⟩ := id hexitB
  refine chord_lang_deriv _ hX
    (chord_trim_step_x b c p x y _ hexitC hexitB αb)
    (chord_trim_step_x_r b' c' p' x' y' _ hexitC' hexitB' αb)
    ⟨(αb, []), ?_⟩
  show bval (genW T)
    ((chordLoopAut b c p x y).core.hlt
      (Sum.inr (Sum.inl (Sum.inr ())))) αb = true
  rw [chord_hlt_yl, hαb]
  rfl

#print axioms chord_lang_deriv
#print axioms chord_pair_port
#print axioms chord_pair_p
#print axioms chord_pair_x
#print axioms chord_pair_y

/-! ## The class census

    Every carrier value of the chord sum represents one of THREE
    classes: the port `R̂`, the branch `P̂`, or the mid `X̂`.  The
    quotient is therefore exactly the chord cluster; the classifier and
    bundle discharge build on these reps. -/

/-- The chord sum automaton for a completeness pair. -/
noncomputable def chordSum (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A) :
    GAut (Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))) A T :=
  sumGAut (chordLoopAut b c p x y).toGAut (chordLoopAut b' c' p' x' y').toGAut

/-- The port representative. -/
noncomputable def chordRepR (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A) :
    Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      (Option (Sum Unit (Sum (Sum Unit Unit) Unit))) :=
  bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
    (Sum.inl (some (Sum.inr (Sum.inr ()))))

/-- The branch representative. -/
noncomputable def chordRepP (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A) :
    Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      (Option (Sum Unit (Sum (Sum Unit Unit) Unit))) :=
  bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
    (Sum.inl (some (Sum.inl ())))

/-- The mid representative. -/
noncomputable def chordRepX (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A) :
    Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      (Option (Sum Unit (Sum (Sum Unit Unit) Unit))) :=
  bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
    (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ())))))

open Classical in
/-- **THE CENSUS**: every carrier value represents the port, the
    branch, or the mid class. -/
theorem chord_census (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none))
    (s : Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))) :
    bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) s
        = chordRepR b c p x y b' c' p' x' y'
      ∨ bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) s
          = chordRepP b c p x y b' c' p' x' y'
      ∨ bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) s
          = chordRepX b c p x y b' c' p' x' y' := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hpairy := chord_pair_y b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' hpairx.2
  cases s with
  | inl o =>
      cases o with
      | none =>
          exact Or.inl (rep_lang_congr _
            (chord_none_lang b c p x y _ hexitC hexitB))
      | some u =>
          cases u with
          | inl v =>
              cases v
              exact Or.inr (Or.inl rfl)
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v =>
                      cases v
                      exact Or.inr (Or.inr rfl)
                  | inr v =>
                      cases v
                      exact Or.inl (rep_lang_congr _
                        (chord_yl_yr_lang b c p x y _ hexitC hexitB))
              | inr v =>
                  cases v
                  exact Or.inl rfl
  | inr o =>
      cases o with
      | none =>
          refine Or.inl (rep_lang_congr _ ?_)
          exact (chord_none_lang_r b' c' p' x' y' _ hexitC' hexitB').trans
            hport.symm
      | some u =>
          cases u with
          | inl v =>
              cases v
              exact Or.inr (Or.inl (rep_lang_congr _ hpair.2.symm))
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v =>
                      cases v
                      exact Or.inr (Or.inr
                        (rep_lang_congr _ hpairx.2.symm))
                  | inr v =>
                      cases v
                      refine Or.inl (rep_lang_congr _ ?_)
                      exact ((chord_yl_yr_lang_r b' c' p' x' y' _
                        hexitC' hexitB').trans hport.symm)
              | inr v =>
                  cases v
                  exact Or.inl (rep_lang_congr _ hport.symm)

open Classical in
/-- The three representatives are pairwise distinct. -/
theorem chord_reps_distinct (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    chordRepR b c p x y b' c' p' x' y'
        ≠ chordRepP b c p x y b' c' p' x' y'
      ∧ chordRepR b c p x y b' c' p' x' y'
          ≠ chordRepX b c p x y b' c' p' x' y'
      ∧ chordRepP b c p x y b' c' p' x' y'
          ≠ chordRepX b c p x y b' c' p' x' y' := by
  refine ⟨?_, ?_, ?_⟩
  · intro h
    have h' : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inr (Sum.inr ()))))
      = bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inl ()))) := h
    have hL : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inl ())))
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y'))
          (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
      rw [← rep_lang (chordSum b c p x y b' c' p' x' y')
          (Sum.inl (some (Sum.inl ()))),
        ← rep_lang (chordSum b c p x y b' c' p' x' y')
          (Sum.inl (some (Sum.inr (Sum.inr ())))),
        h']
    exact chord_lang_ne_p_yr b c p x y
      ((chordLoopAut b' c' p' x' y').toGAut) hexitB hL
  · intro h
    have h' : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inr (Sum.inr ()))))
      = bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) := h
    have hL : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ())))))
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y'))
          (Sum.inl (some (Sum.inr (Sum.inr ())))) := by
      rw [← rep_lang (chordSum b c p x y b' c' p' x' y')
          (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))),
        ← rep_lang (chordSum b c p x y b' c' p' x' y')
          (Sum.inl (some (Sum.inr (Sum.inr ())))),
        h']
    exact chord_lang_ne_x_yr b c p x y
      ((chordLoopAut b' c' p' x' y').toGAut) hexitB hL
  · intro h
    have h' : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inl ())))
      = bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) := h
    have hL : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inl ())))
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y'))
          (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) := by
      rw [← rep_lang (chordSum b c p x y b' c' p' x' y')
          (Sum.inl (some (Sum.inl ()))),
        ← rep_lang (chordSum b c p x y b' c' p' x' y')
          (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))),
        h']
    exact chord_lang_ne_p_x b c p x y
      ((chordLoopAut b' c' p' x' y').toGAut) hentC hexitC hexitB hL

#print axioms chord_census
#print axioms chord_reps_distinct

/-! ## Representative membership

    Each representative is pinned to its class's concrete members: the
    rep is a carrier value with the class language, and the separations
    kill every value outside the class. -/

open Classical in
/-- The branch representative is one of the two branch states. -/
theorem chord_repP_cases (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    chordRepP b c p x y b' c' p' x' y' = Sum.inl (some (Sum.inl ()))
      ∨ chordRepP b c p x y b' c' p' x' y'
          = Sum.inr (some (Sum.inl ())) := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hlangP : autLang (genW T)
      (trimAut (chordSum b c p x y b' c' p' x' y'))
      (chordRepP b c p x y b' c' p' x' y')
    = autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inl ()))) :=
    rep_lang (chordSum b c p x y b' c' p' x' y') _
  have hCne : ∃ α : T → Bool, bval (genW T) c α = true :=
    ⟨Classical.choose hentC, (Classical.choose_spec hentC).1⟩
  cases hval : chordRepP b c p x y b' c' p' x' y' with
  | inl o =>
      rw [hval] at hlangP
      cases o with
      | none =>
          exfalso
          exact chord_lang_ne_p_yr b c p x y _ hexitB
            (((chord_none_lang b c p x y _ hexitC hexitB).symm.trans
              hlangP).symm)
      | some u =>
          cases u with
          | inl v => cases v; exact Or.inl rfl
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v =>
                      cases v
                      exfalso
                      exact chord_lang_ne_p_x b c p x y _ hCne hexitC
                        hexitB hlangP.symm
                  | inr v =>
                      cases v
                      exfalso
                      exact chord_lang_ne_p_yr b c p x y _ hexitB
                        (((chord_yl_yr_lang b c p x y _ hexitC
                          hexitB).symm.trans hlangP).symm)
              | inr v =>
                  cases v
                  exfalso
                  exact chord_lang_ne_p_yr b c p x y _ hexitB hlangP.symm
  | inr o =>
      rw [hval] at hlangP
      cases o with
      | none =>
          exfalso
          refine chord_lang_ne_p_yr b c p x y
            ((chordLoopAut b' c' p' x' y').toGAut) hexitB ?_
          have h1 : autLang (genW T)
              (trimAut (chordSum b c p x y b' c' p' x' y'))
              (Sum.inr none)
            = autLang (genW T)
                (trimAut (chordSum b c p x y b' c' p' x' y'))
                (Sum.inl (some (Sum.inr (Sum.inr ())))) :=
            (chord_none_lang_r b' c' p' x' y' _ hexitC' hexitB').trans
              hport.symm
          exact (h1.symm.trans hlangP).symm
      | some u =>
          cases u with
          | inl v =>
              cases v
              refine Or.inr ?_
              rfl
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v =>
                      cases v
                      exfalso
                      exact chord_lang_ne_p_x b c p x y _ hCne hexitC
                        hexitB (hlangP.symm.trans hpairx.2.symm)
                  | inr v =>
                      cases v
                      exfalso
                      refine chord_lang_ne_p_yr b c p x y
                        ((chordLoopAut b' c' p' x' y').toGAut) hexitB ?_
                      have h1 : autLang (genW T)
                          (trimAut (chordSum b c p x y b' c' p' x' y'))
                          (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ())))))
                        = autLang (genW T)
                            (trimAut (chordSum b c p x y b' c' p' x' y'))
                            (Sum.inl (some (Sum.inr (Sum.inr ())))) :=
                        (chord_yl_yr_lang_r b' c' p' x' y' _ hexitC'
                          hexitB').trans hport.symm
                      exact (h1.symm.trans hlangP).symm
              | inr v =>
                  cases v
                  exfalso
                  exact chord_lang_ne_p_yr b c p x y _ hexitB
                    (hport.trans hlangP).symm

open Classical in
/-- The mid representative is one of the two mid states. -/
theorem chord_repX_cases (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    chordRepX b c p x y b' c' p' x' y'
        = Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))
      ∨ chordRepX b c p x y b' c' p' x' y'
          = Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ())))) := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hlangX : autLang (genW T)
      (trimAut (chordSum b c p x y b' c' p' x' y'))
      (chordRepX b c p x y b' c' p' x' y')
    = autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))) :=
    rep_lang (chordSum b c p x y b' c' p' x' y') _
  have hCne : ∃ α : T → Bool, bval (genW T) c α = true :=
    ⟨Classical.choose hentC, (Classical.choose_spec hentC).1⟩
  cases hval : chordRepX b c p x y b' c' p' x' y' with
  | inl o =>
      rw [hval] at hlangX
      cases o with
      | none =>
          exfalso
          exact chord_lang_ne_x_yr b c p x y _ hexitB
            (((chord_none_lang b c p x y _ hexitC hexitB).symm.trans
              hlangX).symm)
      | some u =>
          cases u with
          | inl v =>
              cases v
              exfalso
              exact chord_lang_ne_p_x b c p x y _ hCne hexitC hexitB
                hlangX
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v => cases v; exact Or.inl rfl
                  | inr v =>
                      cases v
                      exfalso
                      exact chord_lang_ne_x_yr b c p x y _ hexitB
                        (((chord_yl_yr_lang b c p x y _ hexitC
                          hexitB).symm.trans hlangX).symm)
              | inr v =>
                  cases v
                  exfalso
                  exact chord_lang_ne_x_yr b c p x y _ hexitB hlangX.symm
  | inr o =>
      rw [hval] at hlangX
      cases o with
      | none =>
          exfalso
          refine chord_lang_ne_x_yr b c p x y
            ((chordLoopAut b' c' p' x' y').toGAut) hexitB ?_
          have h1 : autLang (genW T)
              (trimAut (chordSum b c p x y b' c' p' x' y'))
              (Sum.inr none)
            = autLang (genW T)
                (trimAut (chordSum b c p x y b' c' p' x' y'))
                (Sum.inl (some (Sum.inr (Sum.inr ())))) :=
            (chord_none_lang_r b' c' p' x' y' _ hexitC' hexitB').trans
              hport.symm
          exact (h1.symm.trans hlangX).symm
      | some u =>
          cases u with
          | inl v =>
              cases v
              exfalso
              exact chord_lang_ne_p_x b c p x y _ hCne hexitC hexitB
                (hpair.2.trans hlangX)
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v => cases v; exact Or.inr rfl
                  | inr v =>
                      cases v
                      exfalso
                      refine chord_lang_ne_x_yr b c p x y
                        ((chordLoopAut b' c' p' x' y').toGAut) hexitB ?_
                      have h1 : autLang (genW T)
                          (trimAut (chordSum b c p x y b' c' p' x' y'))
                          (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ())))))
                        = autLang (genW T)
                            (trimAut (chordSum b c p x y b' c' p' x' y'))
                            (Sum.inl (some (Sum.inr (Sum.inr ())))) :=
                        (chord_yl_yr_lang_r b' c' p' x' y' _ hexitC'
                          hexitB').trans hport.symm
                      exact (h1.symm.trans hlangX).symm
              | inr v =>
                  cases v
                  exfalso
                  exact chord_lang_ne_x_yr b c p x y _ hexitB
                    (hport.trans hlangX).symm

#print axioms chord_repP_cases
#print axioms chord_repX_cases

open Classical in
/-- The port representative is one of the six port-class states. -/
theorem chord_repR_cases (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    chordRepR b c p x y b' c' p' x' y' = Sum.inl none
      ∨ chordRepR b c p x y b' c' p' x' y'
          = Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))
      ∨ chordRepR b c p x y b' c' p' x' y'
          = Sum.inl (some (Sum.inr (Sum.inr ())))
      ∨ chordRepR b c p x y b' c' p' x' y' = Sum.inr none
      ∨ chordRepR b c p x y b' c' p' x' y'
          = Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))
      ∨ chordRepR b c p x y b' c' p' x' y'
          = Sum.inr (some (Sum.inr (Sum.inr ()))) := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hlangR : autLang (genW T)
      (trimAut (chordSum b c p x y b' c' p' x' y'))
      (chordRepR b c p x y b' c' p' x' y')
    = autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y'))
        (Sum.inl (some (Sum.inr (Sum.inr ())))) :=
    rep_lang (chordSum b c p x y b' c' p' x' y') _
  cases hval : chordRepR b c p x y b' c' p' x' y' with
  | inl o =>
      rw [hval] at hlangR
      cases o with
      | none => exact Or.inl rfl
      | some u =>
          cases u with
          | inl v =>
              cases v
              exfalso
              exact chord_lang_ne_p_yr b c p x y _ hexitB hlangR
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v =>
                      cases v
                      exfalso
                      exact chord_lang_ne_x_yr b c p x y _ hexitB hlangR
                  | inr v =>
                      cases v
                      exact Or.inr (Or.inl rfl)
              | inr v =>
                  cases v
                  exact Or.inr (Or.inr (Or.inl rfl))
  | inr o =>
      rw [hval] at hlangR
      cases o with
      | none => exact Or.inr (Or.inr (Or.inr (Or.inl rfl)))
      | some u =>
          cases u with
          | inl v =>
              cases v
              exfalso
              exact chord_lang_ne_p_yr b c p x y _ hexitB
                (hpair.2.trans hlangR)
          | inr w =>
              cases w with
              | inl z =>
                  cases z with
                  | inl v =>
                      cases v
                      exfalso
                      exact chord_lang_ne_x_yr b c p x y _ hexitB
                        (hpairx.2.trans hlangR)
                  | inr v =>
                      cases v
                      exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl rfl))))
              | inr v =>
                  cases v
                  exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr rfl))))

#print axioms chord_repR_cases

/-! ## Quotient arm computation

    For each carrier state, the cleaned quotient arm list is computed
    concretely: `trimList` decorates (all targets live), the quotient
    retargets onto the three representatives, and `cleanList` drops the
    phantom arms (their guards carry `∧0` conjuncts).  The mid state
    first — one real unconditional arm to the port. -/

open Classical in
private theorem cleanList_consC {S : Type} (g : BExp T) (a : A) (t : S)
    (rest : List (BExp T × A × S)) (D : BExp T) :
    cleanList ((g, a, t) :: rest) D
      = if GuardEmpty (.and g (.not D)) then cleanList rest (.or D g)
        else (g, a, t) :: cleanList rest (.or D g) := rfl

open Classical in
/-- The mid state's cleaned quotient arms: one unconditional `y` to the
    port. -/
theorem chord_qarms_x (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ())))))
      = [(.and (.and .one .one) (.not .zero), y,
          chordRepR b c p x y b' c' p' x' y')] := by
  have hrepYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
      (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))))
    = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ (chord_yl_yr_lang b c p x y _ hexitC hexitB)
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ())))))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inl (some (Sum.inr (Sum.inl (Sum.inl ()))))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live b c p x y _ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inl ())))
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [(.and (.and .one .one) (.not .zero), y,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))))),
        (.and (.and (.and .one .zero) (.and b .one)) (.not .zero), p,
          chordRepP b c p x y b' c' p' x' y'),
        (.and (.and (.and .one .zero)
            (.and b (.and .zero (.and c .one)))) (.not .zero), x,
          chordRepX b c p x y b' c' p' x' y'),
        (.and (.and (.and .one .zero)
            (.and b (.and .zero (.and c (.and .zero .one))))) (.not .zero),
          y, bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))))),
        (.and (.and (.and .one .zero)
            (.and b (.and .zero (.and (.not c) .one)))) (.not .zero), y,
          chordRepR b c p x y b' c' p' x' y')]
      .zero = _
  rw [hrepYl]
  have h1 : ¬ GuardEmpty (T := T) (BExp.and
      (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero))
      (BExp.not BExp.zero)) :=
    fun hE => nomatch (hE Unit (fun _ _ => false) ())
  have h2 : GuardEmpty (BExp.and
      (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
        (BExp.and b BExp.one)) (BExp.not BExp.zero))
      (BExp.not (BExp.or BExp.zero
        (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero))))) :=
    fun X W v => rfl
  have h3 : GuardEmpty (BExp.and
      (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
        (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one))))
        (BExp.not BExp.zero))
      (BExp.not (BExp.or (BExp.or BExp.zero
        (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero)))
        (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
          (BExp.and b BExp.one)) (BExp.not BExp.zero))))) :=
    fun X W v => rfl
  have h4 : GuardEmpty (BExp.and
      (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
        (BExp.and b (BExp.and BExp.zero
          (BExp.and c (BExp.and BExp.zero BExp.one)))))
        (BExp.not BExp.zero))
      (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero
        (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero)))
        (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
          (BExp.and b BExp.one)) (BExp.not BExp.zero)))
        (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
          (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one))))
          (BExp.not BExp.zero))))) :=
    fun X W v => rfl
  have h5 : GuardEmpty (BExp.and
      (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
        (BExp.and b (BExp.and BExp.zero
          (BExp.and (BExp.not c) BExp.one))))
        (BExp.not BExp.zero))
      (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero
        (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero)))
        (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
          (BExp.and b BExp.one)) (BExp.not BExp.zero)))
        (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
          (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one))))
          (BExp.not BExp.zero)))
        (BExp.and (BExp.and (BExp.and BExp.one BExp.zero)
          (BExp.and b (BExp.and BExp.zero
            (BExp.and c (BExp.and BExp.zero BExp.one)))))
          (BExp.not BExp.zero))))) :=
    fun X W v => rfl
  rw [cleanList_consC, if_neg h1, cleanList_consC, if_pos h2,
    cleanList_consC, if_pos h3, cleanList_consC, if_pos h4,
    cleanList_consC, if_pos h5]
  rfl

#print axioms chord_qarms_x

open Classical in
theorem chord_qarms_x_r (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ())))))
      = [((BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero)), y',
          chordRepR b c p x y b' c' p' x' y')] := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hrP : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inl ()))) = chordRepP b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpair.2.symm
  have hrX : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) = chordRepX b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpairx.2.symm
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ ((chord_yl_yr_lang_r b' c' p' x' y' _
      hexitC' hexitB').trans hport.symm)
  have hrYr : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inr ())))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hport.symm
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ())))))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live_r b' c' p' x' y' _ hexitC' hexitB'
      (Sum.inr (Sum.inl (Sum.inl ())))
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' BExp.one)) (BExp.not BExp.zero)),
          p', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inl ()))))),
        ((BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)),
          x', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))))),
        ((BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inr ()))))))]
      .zero = _
  rw [hrP, hrX, hrYl, hrYr]
  have h1 : ¬ GuardEmpty (T := T) (BExp.and (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero)) (BExp.not BExp.zero)) :=
    fun hE => nomatch (hE Unit (fun _ _ => false) ())
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' BExp.one)) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && false) && ((bval W b' u) && true)) && (!false)) && (!(false || ((true && true) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h3 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && false) && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false)) && (!((false || ((true && true) && (!false))) || (((true && false) && ((bval W b' u) && true)) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && false) && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false)) && (!(((false || ((true && true) && (!false))) || (((true && false) && ((bval W b' u) && true)) && (!false))) || (((true && false) && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h5 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one BExp.one) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one BExp.zero) (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && false) && ((bval W b' u) && (false && ((!(bval W c' u)) && true)))) && (!false)) && (!((((false || ((true && true) && (!false))) || (((true && false) && ((bval W b' u) && true)) && (!false))) || (((true && false) && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))) || (((true && false) && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_pos h3,
    cleanList_consC,
    if_pos h4,
    cleanList_consC,
    if_pos h5]
  rfl

open Classical in
theorem chord_qarms_p (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inl (some (Sum.inl ())))
      = [((BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero)), x,
          chordRepX b c p x y b' c' p' x' y'),
        ((BExp.and (BExp.and BExp.one (BExp.and (BExp.not c) BExp.one)) (BExp.not BExp.zero)), y,
          chordRepR b c p x y b' c' p' x' y')] := by
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ (chord_yl_yr_lang b c p x y _ hexitC hexitB)
  obtain ⟨αC, hαC1, hαC2⟩ := id hentC
  obtain ⟨αc, hαc⟩ := id hexitC
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inl (some (Sum.inl ())))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inl (some (Sum.inl ()))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live b c p x y _ hexitC hexitB (Sum.inl ())
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero)),
          x, (chordRepX b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and BExp.one (BExp.and c (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero)),
          y, (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and (BExp.not c) BExp.one)) (BExp.not BExp.zero)),
          y, (chordRepR b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b BExp.one)) (BExp.not BExp.zero)),
          p, (chordRepP b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero)),
          x, (chordRepX b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)),
          y, (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one)))) (BExp.not BExp.zero)),
          y, (chordRepR b c p x y b' c' p' x' y'))]
      .zero = _
  rw [hrYl]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : (((true && ((bval (genW T) c αC) && true)) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αC
    rw [hαC1] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and c (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W c u) && (false && true))) && (!false)) && (!(false || ((true && ((bval W c u) && true)) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h3 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c) BExp.one)) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))))) := by
    intro hE
    have hx : (((true && ((!(bval (genW T) c αc)) && true)) && (!false)) && (!((false || ((true && ((bval (genW T) c αc) && true)) && (!false))) || ((true && ((bval (genW T) c αc) && (false && true))) && (!false))))) = false :=
      hE (T → Bool) (genW T) αc
    rw [hαc] at hx
    exact nomatch hx
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b BExp.one)) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c) BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && true)) && (!false)) && (!(((false || ((true && ((bval W c u) && true)) && (!false))) || ((true && ((bval W c u) && (false && true))) && (!false))) || ((true && ((!(bval W c u)) && true)) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h5 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c) BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false)) && (!((((false || ((true && ((bval W c u) && true)) && (!false))) || ((true && ((bval W c u) && (false && true))) && (!false))) || ((true && ((!(bval W c u)) && true)) && (!false))) || (((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && true)) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h6 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c) BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && (false && ((bval W c u) && (false && true))))) && (!false)) && (!(((((false || ((true && ((bval W c u) && true)) && (!false))) || ((true && ((bval W c u) && (false && true))) && (!false))) || ((true && ((!(bval W c u)) && true)) && (!false))) || (((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && true)) && (!false))) || (((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h7 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c) BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c) BExp.zero))) (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && (false && ((!(bval W c u)) && true)))) && (!false)) && (!((((((false || ((true && ((bval W c u) && true)) && (!false))) || ((true && ((bval W c u) && (false && true))) && (!false))) || ((true && ((!(bval W c u)) && true)) && (!false))) || (((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && true)) && (!false))) || (((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false))) || (((true && (((bval W c u) && (false && false)) || ((!(bval W c u)) && false))) && ((bval W b u) && (false && ((bval W c u) && (false && true))))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_neg h3,
    cleanList_consC,
    if_pos h4,
    cleanList_consC,
    if_pos h5,
    cleanList_consC,
    if_pos h6,
    cleanList_consC,
    if_pos h7]
  rfl

open Classical in
theorem chord_qarms_p_r (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inr (some (Sum.inl ())))
      = [((BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero)), x',
          chordRepX b c p x y b' c' p' x' y'),
        ((BExp.and (BExp.and BExp.one (BExp.and (BExp.not c') BExp.one)) (BExp.not BExp.zero)), y',
          chordRepR b c p x y b' c' p' x' y')] := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hrP : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inl ()))) = chordRepP b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpair.2.symm
  have hrX : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) = chordRepX b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpairx.2.symm
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ ((chord_yl_yr_lang_r b' c' p' x' y' _
      hexitC' hexitB').trans hport.symm)
  have hrYr : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inr ())))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hport.symm
  obtain ⟨αC, hαC1, hαC2⟩ := id hentC
  obtain ⟨αd, hαd⟩ := id hexitC'
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inr (some (Sum.inl ())))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inr (some (Sum.inl ()))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live_r b' c' p' x' y' _ hexitC' hexitB' (Sum.inl ())
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero)),
          x', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and c' (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and (BExp.not c') BExp.one)) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inr ())))))),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' BExp.one)) (BExp.not BExp.zero)),
          p', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inl ()))))),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)),
          x', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))))),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inr ()))))))]
      .zero = _
  rw [hrP, hrX, hrYl, hrYr]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : (((true && ((bval (genW T) c' αC) && true)) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αC
    rw [hαC2] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and c' (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W c' u) && (false && true))) && (!false)) && (!(false || ((true && ((bval W c' u) && true)) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h3 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c') BExp.one)) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c' (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))))) := by
    intro hE
    have hx : (((true && ((!(bval (genW T) c' αd)) && true)) && (!false)) && (!((false || ((true && ((bval (genW T) c' αd) && true)) && (!false))) || ((true && ((bval (genW T) c' αd) && (false && true))) && (!false))))) = false :=
      hE (T → Bool) (genW T) αd
    rw [hαd] at hx
    exact nomatch hx
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' BExp.one)) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c' (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c') BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && true)) && (!false)) && (!(((false || ((true && ((bval W c' u) && true)) && (!false))) || ((true && ((bval W c' u) && (false && true))) && (!false))) || ((true && ((!(bval W c' u)) && true)) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h5 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c' (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c') BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false)) && (!((((false || ((true && ((bval W c' u) && true)) && (!false))) || ((true && ((bval W c' u) && (false && true))) && (!false))) || ((true && ((!(bval W c' u)) && true)) && (!false))) || (((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && true)) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h6 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c' (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c') BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false)) && (!(((((false || ((true && ((bval W c' u) && true)) && (!false))) || ((true && ((bval W c' u) && (false && true))) && (!false))) || ((true && ((!(bval W c' u)) && true)) && (!false))) || (((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && true)) && (!false))) || (((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h7 : GuardEmpty (BExp.and (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and c' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and c' (BExp.and BExp.zero BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and (BExp.not c') BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))) (BExp.and (BExp.and (BExp.and BExp.one (BExp.or (BExp.and c' (BExp.and BExp.zero BExp.zero)) (BExp.and (BExp.not c') BExp.zero))) (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && (false && ((!(bval W c' u)) && true)))) && (!false)) && (!((((((false || ((true && ((bval W c' u) && true)) && (!false))) || ((true && ((bval W c' u) && (false && true))) && (!false))) || ((true && ((!(bval W c' u)) && true)) && (!false))) || (((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && true)) && (!false))) || (((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))) || (((true && (((bval W c' u) && (false && false)) || ((!(bval W c' u)) && false))) && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_neg h3,
    cleanList_consC,
    if_pos h4,
    cleanList_consC,
    if_pos h5,
    cleanList_consC,
    if_pos h6,
    cleanList_consC,
    if_pos h7]
  rfl

open Classical in
theorem chord_qarms_yl (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))))
      = [((BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero)), p,
          chordRepP b c p x y b' c' p' x' y')] := by
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ (chord_yl_yr_lang b c p x y _ hexitC hexitB)
  obtain ⟨αB, hαB1, hαB2⟩ := id hentB
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ())))))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live b c p x y _ hexitC hexitB
      (Sum.inr (Sum.inl (Sum.inr ())))
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero)),
          p, (chordRepP b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero)),
          x, (chordRepX b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)),
          y, (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one)))) (BExp.not BExp.zero)),
          y, (chordRepR b c p x y b' c' p' x' y'))]
      .zero = _
  rw [hrYl]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : (((true && ((bval (genW T) b αB) && true)) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αB
    rw [hαB1] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false)) && (!(false || ((true && ((bval W b u) && true)) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h3 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b u) && (false && ((bval W c u) && (false && true))))) && (!false)) && (!((false || ((true && ((bval W b u) && true)) && (!false))) || ((true && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b u) && (false && ((!(bval W c u)) && true)))) && (!false)) && (!(((false || ((true && ((bval W b u) && true)) && (!false))) || ((true && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false))) || ((true && ((bval W b u) && (false && ((bval W c u) && (false && true))))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_pos h3,
    cleanList_consC,
    if_pos h4]
  rfl

open Classical in
theorem chord_qarms_yr (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inl (some (Sum.inr (Sum.inr ()))))
      = [((BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero)), p,
          chordRepP b c p x y b' c' p' x' y')] := by
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ (chord_yl_yr_lang b c p x y _ hexitC hexitB)
  obtain ⟨αB, hαB1, hαB2⟩ := id hentB
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inl (some (Sum.inr (Sum.inr ()))))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inl (some (Sum.inr (Sum.inr ())))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live b c p x y _ hexitC hexitB (Sum.inr (Sum.inr ()))
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero)),
          p, (chordRepP b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero)),
          x, (chordRepX b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)),
          y, (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one)))) (BExp.not BExp.zero)),
          y, (chordRepR b c p x y b' c' p' x' y'))]
      .zero = _
  rw [hrYl]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : (((true && ((bval (genW T) b αB) && true)) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αB
    rw [hαB1] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false)) && (!(false || ((true && ((bval W b u) && true)) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h3 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b u) && (false && ((bval W c u) && (false && true))))) && (!false)) && (!((false || ((true && ((bval W b u) && true)) && (!false))) || ((true && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one)))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b u) && (false && ((!(bval W c u)) && true)))) && (!false)) && (!(((false || ((true && ((bval W b u) && true)) && (!false))) || ((true && ((bval W b u) && (false && ((bval W c u) && true)))) && (!false))) || ((true && ((bval W b u) && (false && ((bval W c u) && (false && true))))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_pos h3,
    cleanList_consC,
    if_pos h4]
  rfl

open Classical in
theorem chord_qarms_yl_r (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ())))))
      = [((BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero)), p',
          chordRepP b c p x y b' c' p' x' y')] := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hrP : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inl ()))) = chordRepP b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpair.2.symm
  have hrX : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) = chordRepX b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpairx.2.symm
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ ((chord_yl_yr_lang_r b' c' p' x' y' _
      hexitC' hexitB').trans hport.symm)
  have hrYr : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inr ())))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hport.symm
  obtain ⟨αB, hαB1, hαB2⟩ := id hentB
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ())))))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live_r b' c' p' x' y' _ hexitC' hexitB'
      (Sum.inr (Sum.inl (Sum.inr ())))
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero)),
          p', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inl ()))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)),
          x', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inr ()))))))]
      .zero = _
  rw [hrP, hrX, hrYl, hrYr]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : (((true && ((bval (genW T) b' αB) && true)) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αB
    rw [hαB2] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false)) && (!(false || ((true && ((bval W b' u) && true)) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h3 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false)) && (!((false || ((true && ((bval W b' u) && true)) && (!false))) || ((true && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b' u) && (false && ((!(bval W c' u)) && true)))) && (!false)) && (!(((false || ((true && ((bval W b' u) && true)) && (!false))) || ((true && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))) || ((true && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_pos h3,
    cleanList_consC,
    if_pos h4]
  rfl

open Classical in
theorem chord_qarms_yr_r (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inr (some (Sum.inr (Sum.inr ()))))
      = [((BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero)), p',
          chordRepP b c p x y b' c' p' x' y')] := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hrP : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inl ()))) = chordRepP b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpair.2.symm
  have hrX : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) = chordRepX b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpairx.2.symm
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ ((chord_yl_yr_lang_r b' c' p' x' y' _
      hexitC' hexitB').trans hport.symm)
  have hrYr : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inr ())))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hport.symm
  obtain ⟨αB, hαB1, hαB2⟩ := id hentB
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inr (some (Sum.inr (Sum.inr ()))))) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inr (some (Sum.inr (Sum.inr ())))),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live_r b' c' p' x' y' _ hexitC' hexitB' (Sum.inr (Sum.inr ()))
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero)),
          p', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inl ()))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)),
          x', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inr ()))))))]
      .zero = _
  rw [hrP, hrX, hrYl, hrYr]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : (((true && ((bval (genW T) b' αB) && true)) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αB
    rw [hαB2] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false)) && (!(false || ((true && ((bval W b' u) && true)) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h3 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false)) && (!((false || ((true && ((bval W b' u) && true)) && (!false))) || ((true && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and BExp.one (BExp.and b' BExp.one)) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one)))) (BExp.not BExp.zero))) (BExp.and (BExp.and BExp.one (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one))))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show (((true && ((bval W b' u) && (false && ((!(bval W c' u)) && true)))) && (!false)) && (!(((false || ((true && ((bval W b' u) && true)) && (!false))) || ((true && ((bval W b' u) && (false && ((bval W c' u) && true)))) && (!false))) || ((true && ((bval W b' u) && (false && ((bval W c' u) && (false && true))))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_pos h3,
    cleanList_consC,
    if_pos h4]
  rfl

open Classical in
theorem chord_qarms_none (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inl none)
      = [((BExp.and (BExp.and b BExp.one) (BExp.not BExp.zero)), p,
          chordRepP b c p x y b' c' p' x' y')] := by
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ (chord_yl_yr_lang b c p x y _ hexitC hexitB)
  obtain ⟨αB, hαB1, hαB2⟩ := id hentB
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inl none)) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inl none),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live_none b c p x y _ hexitC hexitB
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and b BExp.one) (BExp.not BExp.zero)),
          p, (chordRepP b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one))) (BExp.not BExp.zero)),
          x, (chordRepX b c p x y b' c' p' x' y')),
        ((BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one)))) (BExp.not BExp.zero)),
          y, (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inl (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one))) (BExp.not BExp.zero)),
          y, (chordRepR b c p x y b' c' p' x' y'))]
      .zero = _
  rw [hrYl]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and b BExp.one) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : ((((bval (genW T) b αB) && true) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αB
    rw [hαB1] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and b BExp.one) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((bval W b u) && (false && ((bval W c u) && true))) && (!false)) && (!(false || (((bval W b u) && true) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h3 : GuardEmpty (BExp.and (BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and b BExp.one) (BExp.not BExp.zero))) (BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((bval W b u) && (false && ((bval W c u) && (false && true)))) && (!false)) && (!((false || (((bval W b u) && true) && (!false))) || (((bval W b u) && (false && ((bval W c u) && true))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and (BExp.not c) BExp.one))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and b BExp.one) (BExp.not BExp.zero))) (BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and c BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and b (BExp.and BExp.zero (BExp.and c (BExp.and BExp.zero BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((bval W b u) && (false && ((!(bval W c u)) && true))) && (!false)) && (!(((false || (((bval W b u) && true) && (!false))) || (((bval W b u) && (false && ((bval W c u) && true))) && (!false))) || (((bval W b u) && (false && ((bval W c u) && (false && true)))) && (!false))))) = false
    cases bval W c u <;> cases bval W b u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_pos h3,
    cleanList_consC,
    if_pos h4]
  rfl

open Classical in
theorem chord_qarms_none_r (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    (cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (Sum.inr none)
      = [((BExp.and (BExp.and b' BExp.one) (BExp.not BExp.zero)), p',
          chordRepP b c p x y b' c' p' x' y')] := by
  have hport := chord_pair_port b c p x y b' c' p' x' y'
    hexitC hexitB hexitC' hexitB' heq
  have hpair := chord_pair_p b c p x y b' c' p' x' y' hentB
    hexitC hexitB hexitC' hexitB' hport
  have hpairx := chord_pair_x b c p x y b' c' p' x' y' hentC
    hexitC hexitB hexitC' hexitB' hpair.2
  have hrP : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inl ()))) = chordRepP b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpair.2.symm
  have hrX : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))) = chordRepX b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hpairx.2.symm
  have hrYl : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ ((chord_yl_yr_lang_r b' c' p' x' y' _
      hexitC' hexitB').trans hport.symm)
  have hrYr : bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr (some (Sum.inr (Sum.inr ())))) = chordRepR b c p x y b' c' p' x' y' :=
    rep_lang_congr _ hport.symm
  obtain ⟨αB, hαB1, hαB2⟩ := id hentB
  show cleanList
      (((trimList (chordSum b c p x y b' c' p' x' y')
          ((chordSum b c p x y b' c' p' x' y').trans
            (Sum.inr none)) .zero)).map
        (fun e => (e.1, e.2.1,
          bisimRep (trimAut (chordSum b c p x y b' c' p' x' y')) e.2.2)))
      .zero = _
  have htl : ∀ e ∈ (chordSum b c p x y b' c' p' x' y').trans
      (Sum.inr none),
      Live (chordSum b c p x y b' c' p' x' y') e.2.2 :=
    chord_targets_live_none_r b' c' p' x' y' _ hexitC' hexitB'
  rw [trimList_all_live (chordSum b c p x y b' c' p' x' y') _ .zero htl]
  show cleanList
      [((BExp.and (BExp.and b' BExp.one) (BExp.not BExp.zero)),
          p', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inl ()))))),
        ((BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one))) (BExp.not BExp.zero)),
          x', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inl ()))))))),
        ((BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one)))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inl (Sum.inr ()))))))),
        ((BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one))) (BExp.not BExp.zero)),
          y', (bisimRep (trimAut (chordSum b c p x y b' c' p' x' y'))
            (Sum.inr (some (Sum.inr (Sum.inr ()))))))]
      .zero = _
  rw [hrP, hrX, hrYl, hrYr]
  have h1 : ¬ GuardEmpty (BExp.and (BExp.and (BExp.and b' BExp.one) (BExp.not BExp.zero)) (BExp.not BExp.zero)) := by
    intro hE
    have hx : ((((bval (genW T) b' αB) && true) && (!false)) && (!false)) = false :=
      hE (T → Bool) (genW T) αB
    rw [hαB2] at hx
    exact nomatch hx
  have h2 : GuardEmpty (BExp.and (BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one))) (BExp.not BExp.zero)) (BExp.not (BExp.or BExp.zero (BExp.and (BExp.and b' BExp.one) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((bval W b' u) && (false && ((bval W c' u) && true))) && (!false)) && (!(false || (((bval W b' u) && true) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h3 : GuardEmpty (BExp.and (BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one)))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and b' BExp.one) (BExp.not BExp.zero))) (BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((bval W b' u) && (false && ((bval W c' u) && (false && true)))) && (!false)) && (!((false || (((bval W b' u) && true) && (!false))) || (((bval W b' u) && (false && ((bval W c' u) && true))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  have h4 : GuardEmpty (BExp.and (BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and (BExp.not c') BExp.one))) (BExp.not BExp.zero)) (BExp.not (BExp.or (BExp.or (BExp.or BExp.zero (BExp.and (BExp.and b' BExp.one) (BExp.not BExp.zero))) (BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and c' BExp.one))) (BExp.not BExp.zero))) (BExp.and (BExp.and b' (BExp.and BExp.zero (BExp.and c' (BExp.and BExp.zero BExp.one)))) (BExp.not BExp.zero))))) := by
    intro Z W u
    show ((((bval W b' u) && (false && ((!(bval W c' u)) && true))) && (!false)) && (!(((false || (((bval W b' u) && true) && (!false))) || (((bval W b' u) && (false && ((bval W c' u) && true))) && (!false))) || (((bval W b' u) && (false && ((bval W c' u) && (false && true)))) && (!false))))) = false
    cases bval W c' u <;> cases bval W b' u <;> rfl
  rw [cleanList_consC,
    if_neg h1,
    cleanList_consC,
    if_pos h2,
    cleanList_consC,
    if_pos h3,
    cleanList_consC,
    if_pos h4]
  rfl

#print axioms chord_qarms_x_r
#print axioms chord_qarms_p
#print axioms chord_qarms_p_r
#print axioms chord_qarms_yl
#print axioms chord_qarms_yr
#print axioms chord_qarms_yl_r
#print axioms chord_qarms_yr_r
#print axioms chord_qarms_none
#print axioms chord_qarms_none_r


/-! ## The packaged bundle facts

    Rep-independent statements of the cleaned cluster structure —
    existentially quantified over the guards/actions so that the
    representative identity never leaks into the bundle discharge. -/

open Classical in
private theorem gOthers_consK {S : Type} (t : S) (g : BExp T) (a : A)
    (u : S) (rest : List (BExp T × A × S)) :
    gOthers t ((g, a, u) :: rest)
      = if u = t then gOthers t rest
        else (g, a, u) :: gOthers t rest := rfl

open Classical in
private theorem gGuard_consK {S : Type} (t : S) (g : BExp T) (a : A)
    (u : S) (rest : List (BExp T × A × S)) :
    gGuard t ((g, a, u) :: rest)
      = if u = t then .or g (gGuard t rest)
        else .and (gGuard t rest) (.not g) := rfl

open Classical in
/-- The port's cleaned quotient arms: one arm to the branch. -/
theorem chord_portarms (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    ∃ (g : BExp T) (a₀ : A),
      (cleanAut (bisimQuotAut (trimAut
          (chordSum b c p x y b' c' p' x' y')))).trans
          (chordRepR b c p x y b' c' p' x' y')
        = [(g, a₀, chordRepP b c p x y b' c' p' x' y')] := by
  rcases chord_repR_cases b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq with h|h|h|h|h|h
  · rw [h]
    exact ⟨_, _, chord_qarms_none b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq⟩
  · rw [h]
    exact ⟨_, _, chord_qarms_yl b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq⟩
  · rw [h]
    exact ⟨_, _, chord_qarms_yr b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq⟩
  · rw [h]
    exact ⟨_, _, chord_qarms_none_r b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq⟩
  · rw [h]
    exact ⟨_, _, chord_qarms_yl_r b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq⟩
  · rw [h]
    exact ⟨_, _, chord_qarms_yr_r b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq⟩

open Classical in
/-- The branch's cleaned quotient arms: the covering two-way dispatch. -/
theorem chord_brancharms (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    ∃ (g₁ g₂ : BExp T) (a₁ a₂ : A),
      (cleanAut (bisimQuotAut (trimAut
          (chordSum b c p x y b' c' p' x' y')))).trans
          (chordRepP b c p x y b' c' p' x' y')
        = [(g₁, a₁, chordRepX b c p x y b' c' p' x' y'),
            (g₂, a₂, chordRepR b c p x y b' c' p' x' y')]
      ∧ GuardImplies (.not g₁) g₂ := by
  rcases chord_repP_cases b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq with h|h
  · rw [h]
    refine ⟨_, _, _, _, chord_qarms_p b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq, ?_⟩
    intro Z W v hv
    show ((true && ((!(bval W c v)) && true)) && !false) = true
    cases hc : bval W c v
    · rfl
    · exfalso
      rw [show bval W (BExp.not (BExp.and
          (BExp.and BExp.one (BExp.and c BExp.one))
          (BExp.not BExp.zero))) v
        = !((true && ((bval W c v) && true)) && !false) from rfl, hc]
        at hv
      exact nomatch hv
  · rw [h]
    refine ⟨_, _, _, _, chord_qarms_p_r b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq, ?_⟩
    intro Z W v hv
    show ((true && ((!(bval W c' v)) && true)) && !false) = true
    cases hc : bval W c' v
    · rfl
    · exfalso
      rw [show bval W (BExp.not (BExp.and
          (BExp.and BExp.one (BExp.and c' BExp.one))
          (BExp.not BExp.zero))) v
        = !((true && ((bval W c' v) && true)) && !false) from rfl, hc]
        at hv
      exact nomatch hv

open Classical in
/-- The mid's cleaned quotient arms: one full-guard arm to the port. -/
theorem chord_midarms (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    ∃ (g : BExp T) (a₀ : A),
      (cleanAut (bisimQuotAut (trimAut
          (chordSum b c p x y b' c' p' x' y')))).trans
          (chordRepX b c p x y b' c' p' x' y')
        = [(g, a₀, chordRepR b c p x y b' c' p' x' y')]
      ∧ ∀ (Z : Type) (W : T → Z → Bool) (v : Z), bval W g v = true := by
  rcases chord_repX_cases b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq with h|h
  · rw [h]
    exact ⟨_, _, chord_qarms_x b c p x y b' c' p' x' y' hexitC hexitB,
      fun Z W v => rfl⟩
  · rw [h]
    exact ⟨_, _, chord_qarms_x_r b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq, fun Z W v => rfl⟩

open Classical in
/-- The interior halts are empty. -/
theorem chord_hlts_empty (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    GuardEmpty ((cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).hlt
        (chordRepP b c p x y b' c' p' x' y'))
    ∧ GuardEmpty ((cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).hlt
        (chordRepX b c p x y b' c' p' x' y')) := by
  constructor
  · rcases chord_repP_cases b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq with h|h
    · rw [h]
      intro Z W v
      show ((true && (((bval W c v) && (false && false))
          || ((!(bval W c v)) && false))) && !(bval W b v)) = false
      cases bval W c v <;> rfl
    · rw [h]
      intro Z W v
      show ((true && (((bval W c' v) && (false && false))
          || ((!(bval W c' v)) && false))) && !(bval W b' v)) = false
      cases bval W c' v <;> rfl
  · rcases chord_repX_cases b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq with h|h
    · rw [h]
      intro Z W v
      show ((true && false) && !(bval W b v)) = false
      rfl
    · rw [h]
      intro Z W v
      show ((true && false) && !(bval W b' v)) = false
      rfl

#print axioms chord_portarms
#print axioms chord_brancharms
#print axioms chord_midarms
#print axioms chord_hlts_empty

/-! ## The classifier and quotient solvability -/

open Classical in
/-- The chord classifier: the three representatives form the cluster. -/
noncomputable def chordCy (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A) :
    Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
    → Option ((Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
        (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      × Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
        (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      × Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
        (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))) × Nat) :=
  fun s =>
    if s = chordRepR b c p x y b' c' p' x' y' then
      some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
        chordRepX b c p x y b' c' p' x' y'), 0)
    else if s = chordRepP b c p x y b' c' p' x' y' then
      some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
        chordRepX b c p x y b' c' p' x' y'), 1)
    else if s = chordRepX b c p x y b' c' p' x' y' then
      some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
        chordRepX b c p x y b' c' p' x' y'), 2)
    else none

open Classical in
private theorem chordCy_def (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A) (s : Sum (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))
      (Option (Sum Unit (Sum (Sum Unit Unit) Unit)))) :
    chordCy b c p x y b' c' p' x' y' s
      = if s = chordRepR b c p x y b' c' p' x' y' then
          some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
            chordRepX b c p x y b' c' p' x' y'), 0)
        else if s = chordRepP b c p x y b' c' p' x' y' then
          some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
            chordRepX b c p x y b' c' p' x' y'), 1)
        else if s = chordRepX b c p x y b' c' p' x' y' then
          some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
            chordRepX b c p x y b' c' p' x' y'), 2)
        else none := rfl

open Classical in
/-- **CHORD QUOTIENT SOLVABILITY**: the canonical quotient of the
    trimmed chord sum is solvable with the finite axioms. -/
theorem chordLoops_solvable (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
      = autLang (genW T)
          (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none)) :
    ∃ qsol, SolvesBA (bisimQuotAut (trimAut
      (chordSum b c p x y b' c' p' x' y'))) qsol := by
  have hdist := chord_reps_distinct b c p x y b' c' p' x' y'
    (⟨Classical.choose hentC, (Classical.choose_spec hentC).1⟩)
    hexitC hexitB
  obtain ⟨gR, aR, harmR⟩ := chord_portarms b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq
  obtain ⟨g₁, g₂, a₁, a₂, harmP, himpP⟩ := chord_brancharms b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq
  obtain ⟨gX, aX, harmX, htopX⟩ := chord_midarms b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq
  obtain ⟨hhP, hhX⟩ := chord_hlts_empty b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq
  have hcy0 : chordCy b c p x y b' c' p' x' y' (chordRepR b c p x y b' c' p' x' y')
      = some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
          chordRepX b c p x y b' c' p' x' y'), 0) := by
    rw [chordCy_def, if_pos rfl]
  have hcy1 : chordCy b c p x y b' c' p' x' y' (chordRepP b c p x y b' c' p' x' y')
      = some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
          chordRepX b c p x y b' c' p' x' y'), 1) := by
    rw [chordCy_def, if_neg (fun h => hdist.1 h.symm), if_pos rfl]
  have hcy2 : chordCy b c p x y b' c' p' x' y' (chordRepX b c p x y b' c' p' x' y')
      = some ((chordRepR b c p x y b' c' p' x' y', chordRepP b c p x y b' c' p' x' y',
          chordRepX b c p x y b' c' p' x' y'), 2) := by
    rw [chordCy_def, if_neg (fun h => hdist.2.1 h.symm),
      if_neg (fun h => hdist.2.2 h.symm), if_pos rfl]
  have hoX : gOthers (chordRepX b c p x y b' c' p' x' y')
      ((cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (chordRepP b c p x y b' c' p' x' y'))
      = [(g₂, a₂, chordRepR b c p x y b' c' p' x' y')] := by
    rw [harmP, gOthers_consK, if_pos rfl, gOthers_consK,
      if_neg hdist.2.1]
    rfl
  have hoXX : gOthers (chordRepX b c p x y b' c' p' x' y')
      ((cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (chordRepX b c p x y b' c' p' x' y'))
      = [(gX, aX, chordRepR b c p x y b' c' p' x' y')] := by
    rw [harmX, gOthers_consK, if_neg hdist.2.1]
    rfl
  have hF1 : ∀ e ∈ gOthers (chordRepP b c p x y b' c' p' x' y')
      ((cleanAut (bisimQuotAut (trimAut
        (chordSum b c p x y b' c' p' x' y')))).trans
        (chordRepR b c p x y b' c' p' x' y')),
      (0 : Nat) < 0 := by
    rw [harmR, gOthers_consK, if_pos rfl]
    intro e he
    exact nomatch he
  have hF2 : gOthers (chordRepR b c p x y b' c' p' x' y')
      (gOthers (chordRepX b c p x y b' c' p' x' y')
        ((cleanAut (bisimQuotAut (trimAut
          (chordSum b c p x y b' c' p' x' y')))).trans
          (chordRepP b c p x y b' c' p' x' y'))) = [] := by
    rw [hoX, gOthers_consK, if_pos rfl]
    rfl
  have hF3 : gOthers (chordRepR b c p x y b' c' p' x' y')
      (gOthers (chordRepX b c p x y b' c' p' x' y')
        ((cleanAut (bisimQuotAut (trimAut
          (chordSum b c p x y b' c' p' x' y')))).trans
          (chordRepX b c p x y b' c' p' x' y'))) = [] := by
    rw [hoXX, gOthers_consK, if_pos rfl]
    rfl
  have hF4 : GuardImplies
      (.not (gGuard (chordRepX b c p x y b' c' p' x' y')
        ((cleanAut (bisimQuotAut (trimAut
          (chordSum b c p x y b' c' p' x' y')))).trans
          (chordRepP b c p x y b' c' p' x' y'))))
      (gGuard (chordRepR b c p x y b' c' p' x' y')
        (gOthers (chordRepX b c p x y b' c' p' x' y')
          ((cleanAut (bisimQuotAut (trimAut
            (chordSum b c p x y b' c' p' x' y')))).trans
            (chordRepP b c p x y b' c' p' x' y')))) := by
    rw [hoX, harmP, gGuard_consK, if_pos rfl, gGuard_consK,
      if_neg hdist.2.1, gGuard_consK, if_pos rfl]
    intro Z W v h
    have h' : (!((bval W g₁ v)
        || ((bval W (gGuard (chordRepX b c p x y b' c' p' x' y')
            ([] : List (BExp T × A × _))) v) && (!(bval W g₂ v)))))
        = true := h
    cases hg1 : bval W g₁ v
    · have hg2 := himpP Z W v (by
        show (!(bval W g₁ v)) = true
        rw [hg1]
        rfl)
      show ((bval W g₂ v) || _) = true
      rw [hg2]
      rfl
    · rw [hg1] at h'
      exact nomatch h'
  have hF5 : GuardImplies
      (.not (gGuard (chordRepX b c p x y b' c' p' x' y')
        ((cleanAut (bisimQuotAut (trimAut
          (chordSum b c p x y b' c' p' x' y')))).trans
          (chordRepX b c p x y b' c' p' x' y'))))
      (gGuard (chordRepR b c p x y b' c' p' x' y')
        (gOthers (chordRepX b c p x y b' c' p' x' y')
          ((cleanAut (bisimQuotAut (trimAut
            (chordSum b c p x y b' c' p' x' y')))).trans
            (chordRepX b c p x y b' c' p' x' y')))) := by
    rw [hoXX, harmX, gGuard_consK, if_neg hdist.2.1, gGuard_consK,
      if_pos rfl]
    intro Z W v _
    show ((bval W gX v) || _) = true
    rw [htopX Z W v]
    rfl
  obtain ⟨qsol, hroles⟩ := chord_assembly_roles
    (cleanAut (bisimQuotAut (trimAut (chordSum b c p x y b' c' p' x' y'))))
    (fun _ => 0) (chordCy b c p x y b' c' p' x' y')
    (by
      intro s Rs Ps Qs i hcys
      rw [chordCy_def] at hcys
      by_cases hR : s = chordRepR b c p x y b' c' p' x' y'
      · rw [if_pos hR] at hcys
        have hinj := Option.some.inj hcys
        rw [Prod.mk.injEq, Prod.mk.injEq, Prod.mk.injEq] at hinj
        obtain ⟨⟨hRs, hPs, hQs⟩, hi⟩ := hinj
        subst hRs; subst hPs; subst hQs
        exact ⟨Or.inl ⟨hi.symm, hR⟩, hcy0, hcy1, hcy2, rfl, rfl,
          hF1, hF2, hF3, hF4, hF5, hhP, hhX⟩
      · rw [if_neg hR] at hcys
        by_cases hP : s = chordRepP b c p x y b' c' p' x' y'
        · rw [if_pos hP] at hcys
          have hinj := Option.some.inj hcys
          rw [Prod.mk.injEq, Prod.mk.injEq, Prod.mk.injEq] at hinj
          obtain ⟨⟨hRs, hPs, hQs⟩, hi⟩ := hinj
          subst hRs; subst hPs; subst hQs
          exact ⟨Or.inr (Or.inl ⟨hi.symm, hP⟩), hcy0, hcy1, hcy2,
            rfl, rfl, hF1, hF2, hF3, hF4, hF5, hhP, hhX⟩
        · rw [if_neg hP] at hcys
          by_cases hX : s = chordRepX b c p x y b' c' p' x' y'
          · rw [if_pos hX] at hcys
            have hinj := Option.some.inj hcys
            rw [Prod.mk.injEq, Prod.mk.injEq, Prod.mk.injEq] at hinj
            obtain ⟨⟨hRs, hPs, hQs⟩, hi⟩ := hinj
            subst hRs; subst hPs; subst hQs
            exact ⟨Or.inr (Or.inr ⟨hi.symm, hX⟩), hcy0, hcy1, hcy2,
              rfl, rfl, hF1, hF2, hF3, hF4, hF5, hhP, hhX⟩
          · rw [if_neg hX] at hcys
            exact nomatch hcys)
    (by
      intro s hs hnone e he
      exfalso
      obtain ⟨t, ht, hrep⟩ := List.mem_map.mp hs
      rcases chord_census b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' heq t with h|h|h
      · rw [← hrep, h, hcy0] at hnone
        exact nomatch hnone
      · rw [← hrep, h, hcy1] at hnone
        exact nomatch hnone
      · rw [← hrep, h, hcy2] at hnone
        exact nomatch hnone)
  exact ⟨qsol, solvesBA_unclean _ (decomp_solves _ _ hroles)⟩

#print axioms chordLoops_solvable

open Classical in
/-- **THE SIXTH THEOREM — CHORD COMPLETENESS**: uniformly equivalent
    chord programs `wh b (p; ite c (x; y) y)` — the minimal shape BEYOND
    the walked discipline, whose branch state maps per-atom onto two
    forward cycle positions — are provably equivalent with the FINITE
    axioms.  No n-ary uniqueness axiom; `w3` (one unknown) throughout. -/
theorem chordloops_complete (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : UniformLanguageEquivalent (chordLoop b c p x y)
      (chordLoop b' c' p' x' y')) :
    EquivBA (chordLoop b c p x y) (chordLoop b' c' p' x' y') := by
  have hstart : autLang (genW T)
      (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
    = autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none) := by
    rw [autLang_trimAut, autLang_trimAut]
    show autLang (genW T) (sumGAut
        (certifiedThompson A T (chordLoop b c p x y)).aut.toGAut
        (certifiedThompson A T (chordLoop b' c' p' x' y')).aut.toGAut)
        (Sum.inl none)
      = autLang (genW T) (sumGAut
        (certifiedThompson A T (chordLoop b c p x y)).aut.toGAut
        (certifiedThompson A T (chordLoop b' c' p' x' y')).aut.toGAut)
        (Sum.inr none)
    rw [autLang_sum_inl, autLang_sum_inr,
      certifiedThompson_start_language (chordLoop b c p x y),
      certifiedThompson_start_language (chordLoop b' c' p' x' y')]
    funext gs
    exact propext (heq (T → Bool) (genW T) gs)
  obtain ⟨qsol, hq⟩ := chordLoops_solvable b c p x y b' c' p' x' y'
    hentB hentC hexitC hexitB hexitC' hexitB' hstart
  exact equivBA_of_quot_solvesBA (chordLoop b c p x y)
    (chordLoop b' c' p' x' y') heq hq

#print axioms chordloops_complete

end GkatThreeLoop
