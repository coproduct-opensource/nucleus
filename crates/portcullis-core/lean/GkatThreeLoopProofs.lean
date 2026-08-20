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

end GkatThreeLoop
