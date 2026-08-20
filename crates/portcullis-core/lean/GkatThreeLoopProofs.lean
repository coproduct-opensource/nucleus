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

end GkatThreeLoop
