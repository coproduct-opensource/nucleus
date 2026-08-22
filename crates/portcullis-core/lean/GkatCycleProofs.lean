import GkatPlanExistenceProofs
import GkatNormalizationProofs

/-! # The single-port cycle stratum

    The SCC census (PAD_SCC_CENSUS) measured canonical quotients of trimmed
    Thompson sums: 97–99% of pairs are covered by the proved strata already, and
    of the remaining multi-state SCCs, ~82% are SIMPLE CYCLES WITH ONE HALTING
    MEMBER and no exits — with single-exit variants next.  For that dominant
    shape NO PARKING is needed:

    * interior members are halt-free with all arms to their single successor, so
      their equations collapse to straight lines (`ite G Z 0? ≡ G?·Z`);
    * the cycle composes into ONE Salomaa body at the port
      (`chain_expand` + `prod_assoc`);
    * `multi_gather` (arbitrary target) does the per-state gathering.

    This file proves the cycle-LOCAL theorem: given a solution assignment whose
    values on the cycle take the chain/port closed forms, every cycle member has
    a `StateRole` — the port by `salomaaE`, interiors by `equivFold`.  The
    ambient assembly (defining that solution by well-founded recursion alongside
    the other strata) composes on top. -/

namespace GkatCycle

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization

variable {S A T : Type}

/-- Right-nested product with a terminal continuation. -/
def prodR : List (Exp A T) → Exp A T → Exp A T
  | [], z => z
  | f :: r, z => .seq f (prodR r z)

/-- Left-seeded core product — no trailing unit. -/
def prodCore : Exp A T → List (Exp A T) → Exp A T
  | f, [] => f
  | f, g :: r => .seq f (prodCore g r)

/-- Re-bracketing: the core product against a continuation is the seed against
    the right-nested product. -/
theorem prod_assoc : ∀ (fs : List (Exp A T)) (f0 P : Exp A T),
    EquivBA (.seq (prodCore f0 fs) P) (.seq f0 (prodR fs P)) := by
  intro fs
  induction fs with
  | nil => intro f0 P; exact EquivBA.base (Equiv.refl _)
  | cons g r ih =>
      intro f0 P
      show EquivBA (.seq (.seq f0 (prodCore g r)) P)
        (.seq f0 (.seq g (prodR r P)))
      refine EquivBA.trans (EquivBA.base (Equiv.s1 f0 (prodCore g r) P)) ?_
      exact EquivBA.seq_c (EquivBA.base (Equiv.refl f0)) (ih g P)

open Classical in
private theorem gOthers_cons' (t : S) (g : BExp T) (a : A) (u : S)
    (rest : List (BExp T × A × S)) :
    gOthers t ((g, a, u) :: rest)
      = if u = t then gOthers t rest
        else (g, a, u) :: gOthers t rest := rfl

open Classical in
/-- A dispatch aimed entirely at one target has no remainder. -/
theorem gOthers_nil_of_all (t : S) :
    ∀ L : List (BExp T × A × S), (∀ e ∈ L, e.2.2 = t) → gOthers t L = [] := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons hd rest ih =>
      intro h
      obtain ⟨g, a, u⟩ := hd
      rw [gOthers_cons', if_pos (h (g, a, u) (by simp)),
          ih (fun e he => h e (by simp [he]))]

open Classical in
/-- **The straight-line collapse**: a halt-free state whose arms all target `v`
    has equation `(G?·B)·sol v`. -/
theorem straight_line (aut : GAut S A T) (sol : S → Exp A T) {u v : S}
    (harms : ∀ e ∈ aut.trans u, e.2.2 = v)
    (hhlt : GuardEmpty (aut.hlt u)) :
    EquivBA (eqRHS aut sol u)
      (.seq (.seq (.test (gGuard v (aut.trans u))) (gBody v (aut.trans u)))
        (sol v)) := by
  rw [eqRHS_foldTL]
  refine EquivBA.trans (multi_gather sol (aut.hlt u) v (aut.trans u)) ?_
  rw [gOthers_nil_of_all v (aut.trans u) harms]
  refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
    (guard_zero_test hhlt)) ?_
  refine EquivBA.trans (ite_zero_else _ _) ?_
  exact seq_assoc' _ _ (sol v)

open Classical in
/-- The straight-line factor at cycle position `j` (successor is position
    `j + 1`, wrapping to the port at `len`). -/
noncomputable def factorAt (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (j : Nat) : Exp A T :=
  .seq (.test (gGuard (if j + 1 = len then m 0 else m (j + 1))
      (aut.trans (m j))))
    (gBody (if j + 1 = len then m 0 else m (j + 1)) (aut.trans (m j)))

open Classical in
/-- The factors for positions `j, j+1, …, j+c-1`. -/
noncomputable def factsFrom (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    Nat → Nat → List (Exp A T)
  | _, 0 => []
  | j, c + 1 => factorAt aut m len j :: factsFrom aut m len (j + 1) c

open Classical in
/-- **Chain expansion**: an interior solution is the right-nested product of its
    onward factors into the port solution. -/
theorem chain_expand (aut : GAut S A T) (sol : S → Exp A T) (m : Nat → S)
    (len : Nat)
    (hsol_int : ∀ j, 1 ≤ j → j < len →
      sol (m j) = .seq (factorAt aut m len j)
        (sol (if j + 1 = len then m 0 else m (j + 1)))) :
    ∀ c j, 1 ≤ c → 1 ≤ j → j + c = len →
      sol (m j) = prodR (factsFrom aut m len j c) (sol (m 0)) := by
  intro c
  induction c with
  | zero => intro j hc _ _; exact absurd hc (by omega)
  | succ c ih =>
      intro j _ hj hlen
      cases c with
      | zero =>
          have hj1 : j + 1 = len := by omega
          have hjlt : j < len := by omega
          rw [hsol_int j hj hjlt, if_pos hj1]
          rfl
      | succ c' =>
          have hjlt : j < len := by omega
          have hne : ¬ (j + 1 = len) := by omega
          rw [hsol_int j hj hjlt, if_neg hne,
              ih (j + 1) (by omega) (by omega) (by omega)]
          rfl

open Classical in
/-- **THE SINGLE-PORT CYCLE THEOREM** (cycle-local): if the solution takes the
    chain closed forms on a simple cycle whose interiors are halt-free with all
    arms to their successor, then every cycle member has a `StateRole` — the
    port a `salomaaE` state whose body is the composed cycle, interiors
    `equivFold`s via the straight-line collapse.  No parking, no side
    conditions. -/
theorem single_port_cycle_roles (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) (hlen : 2 ≤ len)
    (hsol_int : ∀ j, 1 ≤ j → j < len →
      sol (m j) = .seq (factorAt aut m len j)
        (sol (if j + 1 = len then m 0 else m (j + 1))))
    (hsol_port : sol (m 0)
      = .seq (.wh (gGuard (m 1) (aut.trans (m 0)))
          (prodCore (gBody (m 1) (aut.trans (m 0)))
            (factsFrom aut m len 1 (len - 1))))
        (foldTL sol (aut.hlt (m 0)) (gOthers (m 1) (aut.trans (m 0)))))
    (hint_arms : ∀ j, 1 ≤ j → j < len → ∀ e ∈ aut.trans (m j),
      e.2.2 = (if j + 1 = len then m 0 else m (j + 1)))
    (hint_hlt : ∀ j, 1 ≤ j → j < len → GuardEmpty (aut.hlt (m j))) :
    ∀ j, j < len → StateRole aut sol (m j) := by
  intro j hj
  cases Nat.eq_zero_or_pos j with
  | inl hzero =>
      subst hzero
      refine StateRole.salomaaE
        (gGuard (m 1) (aut.trans (m 0)))
        (prodCore (gBody (m 1) (aut.trans (m 0)))
          (factsFrom aut m len 1 (len - 1)))
        (foldTL sol (aut.hlt (m 0)) (gOthers (m 1) (aut.trans (m 0))))
        hsol_port ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (multi_gather sol (aut.hlt (m 0)) (m 1)
        (aut.trans (m 0))) ?_
      refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
      rw [chain_expand aut sol m len hsol_int (len - 1) 1
        (by omega) (Nat.le_refl 1) (by omega)]
      exact EquivBA.symm (prod_assoc (factsFrom aut m len 1 (len - 1))
        (gBody (m 1) (aut.trans (m 0))) (sol (m 0)))
  | inr hpos =>
      refine StateRole.equivFold ?_
      refine EquivBA.trans ?_ (EquivBA.symm (straight_line aut sol
        (hint_arms j hpos hj) (hint_hlt j hpos hj)))
      rw [hsol_int j hpos hj]
      exact EquivBA.base (Equiv.refl _)

#print axioms single_port_cycle_roles

/-! ## The assembly: mixed strata under one well-founded recursion

    One solution for a whole automaton whose states are (i) base — arms to self
    or strictly lower rank (the singleton stratum), or (ii) members of
    designated single-port simple cycles.  The solution dispatches per state:
    gathered Salomaa closed forms at base states, chain/port closed forms on
    cycles; every equation the local theorems need holds by construction. -/

private theorem foldTL_congr' {sol₁ sol₂ : S → Exp A T} (h : BExp T) :
    ∀ L : List (BExp T × A × S), (∀ e ∈ L, sol₁ e.2.2 = sol₂ e.2.2) →
    foldTL sol₁ h L = foldTL sol₂ h L := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons hd tl ih =>
      intro hL
      show Exp.ite hd.1 (.seq (.act hd.2.1) (sol₁ hd.2.2)) (foldTL sol₁ h tl)
        = Exp.ite hd.1 (.seq (.act hd.2.1) (sol₂ hd.2.2)) (foldTL sol₂ h tl)
      rw [hL hd (by simp), ih (fun e he => hL e (by simp [he]))]

open Classical in
/-- The port's closed form, parametric in the ambient solution. -/
noncomputable def portExprOf (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (sol : S → Exp A T) : Exp A T :=
  .seq (.wh (gGuard (m 1) (aut.trans (m 0)))
      (prodCore (gBody (m 1) (aut.trans (m 0)))
        (factsFrom aut m len 1 (len - 1))))
    (foldTL sol (aut.hlt (m 0)) (gOthers (m 1) (aut.trans (m 0))))

open Classical in
/-- The closed form of cycle position `i`. -/
noncomputable def cycSolOf (aut : GAut S A T) (m : Nat → S) (len i : Nat)
    (sol : S → Exp A T) : Exp A T :=
  if i = 0 then portExprOf aut m len sol
  else prodR (factsFrom aut m len i (len - i)) (portExprOf aut m len sol)

open Classical in
private theorem cycSolOf_congr (aut : GAut S A T) (m : Nat → S) (len i : Nat)
    {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthers (m 1) (aut.trans (m 0)), sol₁ e.2.2 = sol₂ e.2.2) :
    cycSolOf aut m len i sol₁ = cycSolOf aut m len i sol₂ := by
  unfold cycSolOf portExprOf
  rw [foldTL_congr' (aut.hlt (m 0)) (gOthers (m 1) (aut.trans (m 0))) h]

open Classical in
/-- The assembled solution: base states take the gathered Salomaa closed form,
    cycle members their chain/port closed forms, by well-founded recursion. -/
noncomputable def asmSol (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    match cy s with
    | none =>
        .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
            (aut.hlt s) (gOthers s (aut.trans s)))
    | some (len, m, i) =>
        cycSolOf aut m len i
          (fun t => if h : rank t < rank s then rec t h else .test .zero))

open Classical in
theorem asmSol_eq (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) (s : S) :
    asmSol aut rank cy s
      = (match cy s with
        | none =>
            .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (fun t =>
                  if _ : rank t < rank s then asmSol aut rank cy t
                  else .test .zero)
                (aut.hlt s) (gOthers s (aut.trans s)))
        | some (len, m, i) =>
            cycSolOf aut m len i
              (fun t =>
                if _ : rank t < rank s then asmSol aut rank cy t
                else .test .zero)) := by
  unfold asmSol
  rw [WellFounded.fix_eq]

open Classical in
private theorem asm_none_sol (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) {s : S} (hcys : cy s = none)
    (hlow : ∀ e ∈ gOthers s (aut.trans s), rank e.2.2 < rank s) :
    asmSol aut rank cy s
      = .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (asmSol aut rank cy) (aut.hlt s)
            (gOthers s (aut.trans s))) := by
  rw [asmSol_eq, hcys]
  exact congrArg _ (foldTL_congr' (aut.hlt s) (gOthers s (aut.trans s))
    (fun e he => dif_pos (hlow e he)))

open Classical in
private theorem asm_cyc_sol (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) {s : S} {len i : Nat}
    {m : Nat → S} (hcys : cy s = some (len, m, i))
    (hlow : ∀ e ∈ gOthers (m 1) (aut.trans (m 0)), rank e.2.2 < rank s) :
    asmSol aut rank cy s = cycSolOf aut m len i (asmSol aut rank cy) := by
  rw [asmSol_eq, hcys]
  exact cycSolOf_congr aut m len i (fun e he => dif_pos (hlow e he))

open Classical in
/-- **THE ASSEMBLY THEOREM**: an automaton whose every state is base
    (self-or-descending) or a member of a designated single-port simple cycle
    is fully role-covered. -/
theorem assembly_roles (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat))
    (hcy : ∀ s len m i, cy s = some (len, m, i) →
      i < len ∧ 2 ≤ len ∧ m i = s ∧
      (∀ j, j < len → cy (m j) = some (len, m, j)) ∧
      (∀ j, j < len → rank (m j) = rank (m 0)) ∧
      (∀ j, 1 ≤ j → j < len →
        (∀ e ∈ aut.trans (m j),
          e.2.2 = (if j + 1 = len then m 0 else m (j + 1)))
        ∧ GuardEmpty (aut.hlt (m j))) ∧
      (∀ e ∈ aut.trans (m 0), e.2.2 = m 1 ∨ rank e.2.2 < rank (m 0)))
    (hbase : ∀ s ∈ aut.states, cy s = none →
      ∀ e ∈ aut.trans s, e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨asmSol aut rank cy, fun s hs => ?_⟩
  cases hcys : cy s with
  | none =>
      -- base: the singleton stratum, gathered Salomaa role
      have hlow : ∀ e ∈ gOthers s (aut.trans s), rank e.2.2 < rank s := by
        intro e he
        obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
        rcases hbase s hs hcys e heL with h1 | h2
        · exact absurd h1 hne
        · exact h2
      refine StateRole.salomaaE (gGuard s (aut.trans s))
        (gBody s (aut.trans s))
        (foldTL (asmSol aut rank cy) (aut.hlt s) (gOthers s (aut.trans s)))
        (asm_none_sol aut rank cy hcys hlow) ?_
      rw [eqRHS_foldTL]
      exact multi_gather (asmSol aut rank cy) (aut.hlt s) s (aut.trans s)
  | some q =>
      obtain ⟨len, m, i⟩ := q
      obtain ⟨hilt, hlen, hmi, hcoh, hrank, hint, hport⟩ :=
        hcy s len m i hcys
      -- port-REST targets are strictly below every cycle member
      have hlowAt : ∀ j, j < len →
          ∀ e ∈ gOthers (m 1) (aut.trans (m 0)), rank e.2.2 < rank (m j) := by
        intro j hj e he
        obtain ⟨heL, hne⟩ := gOthers_sub (m 1) (aut.trans (m 0)) e he
        rcases hport e heL with h1 | h2
        · exact absurd h1 hne
        · rw [hrank j hj]; exact h2
      -- the port equation
      have hsol_port : asmSol aut rank cy (m 0)
          = portExprOf aut m len (asmSol aut rank cy) := by
        rw [asm_cyc_sol aut rank cy (hcoh 0 (by omega))
          (hlowAt 0 (by omega))]
        unfold cycSolOf
        rw [if_pos rfl]
      -- the interior equations
      have hsol_int : ∀ j, 1 ≤ j → j < len →
          asmSol aut rank cy (m j)
            = .seq (factorAt aut m len j)
              (asmSol aut rank cy (if j + 1 = len then m 0 else m (j + 1))) := by
        intro j hj hjlt
        rw [asm_cyc_sol aut rank cy (hcoh j hjlt) (hlowAt j hjlt)]
        unfold cycSolOf
        rw [if_neg (by omega : ¬ (j = 0)),
            show len - j = (len - (j + 1)) + 1 from by omega]
        by_cases hj1 : j + 1 = len
        · rw [if_pos hj1, hsol_port,
              show len - (j + 1) = 0 from by omega]
          rfl
        · rw [if_neg hj1,
              asm_cyc_sol aut rank cy (hcoh (j + 1) (by omega))
                (hlowAt (j + 1) (by omega))]
          unfold cycSolOf
          rw [if_neg (by omega : ¬ (j + 1 = 0))]
          rfl
      have hroles := single_port_cycle_roles aut (asmSol aut rank cy) m len
        hlen hsol_int
        (by rw [hsol_port]; rfl)
        (fun j hj hjlt => (hint j hj hjlt).1)
        (fun j hj hjlt => (hint j hj hjlt).2)
      rw [← hmi]
      exact hroles i hilt

#print axioms assembly_roles

/-! ## The parked cycle: multi-halt simple cycles under subset parking

    The multi-port census dump shows the tail's structure: in EVERY observed
    halt-flavored multi-port cycle, the interior halt guards are SUBSETS of the
    port's halt guard — the subset-parking condition the k6/NA=4 certificates
    used.  Under it, no walk machinery is needed either: parked halts absorb
    the port solution (`park_absorb`, via `test_header_absorb`), `u5`
    right-distributes the port solution out of the whole chain
    (`pChain_split`), and the port closes as a `salomaaE` state whose body is
    the parked chain.  Interiors are `equivFold`s of literal chain forms. -/

open Classical in
/-- The cycle successor of position `j`. -/
noncomputable def nxtAt (m : Nat → S) (len j : Nat) : S :=
  if j + 1 = len then m 0 else m (j + 1)

open Classical in
/-- The parked chain from position `j`, `c` steps long, ending in `term`:
    step onward or halt in place. -/
noncomputable def pChain (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (term : Exp A T) : Nat → Nat → Exp A T
  | 0, _ => term
  | c + 1, j =>
      .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
        (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
          (pChain aut m len term c (j + 1)))
        (.test (aut.hlt (m j)))

open Classical in
/-- The parked port solution: loop the whole parked chain, exit on the port
    halt. -/
noncomputable def parkedPortE (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    Exp A T :=
  .seq (.wh (gGuard (m 1) (aut.trans (m 0)))
      (.seq (gBody (m 1) (aut.trans (m 0)))
        (pChain aut m len (.test .one) (len - 1) 1)))
    (.test (aut.hlt (m 0)))

/-- **Parking absorption**: a halt inside the port's halt guard absorbs the
    port solution. -/
theorem park_absorb {h c g : BExp T} (B : Exp A T)
    (himp : GuardImplies h c) (hexcl : GuardImplies c (.not g)) :
    EquivBA (.test h : Exp A T)
      (.seq (.test h) (.seq (.wh g B) (.test c))) := by
  refine EquivBA.trans (test_widen himp) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
    (EquivBA.symm (test_header_absorb c g B hexcl))) ?_
  refine EquivBA.trans (seq_assoc' (.test h) (.test c)
    (.seq (.wh g B) (.test c))) ?_
  exact EquivBA.seq_c (EquivBA.symm (test_widen himp))
    (EquivBA.base (Equiv.refl _))

open Classical in
/-- **THE PARKED SPLIT**: the port solution right-distributes out of the whole
    parked chain — `u5` on the step arm, `park_absorb` on every halt arm. -/
theorem pChain_split (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (himp : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hexcl : GuardImplies (aut.hlt (m 0))
      (.not (gGuard (m 1) (aut.trans (m 0))))) :
    ∀ c j, 1 ≤ j → j + c ≤ len →
      EquivBA (pChain aut m len (parkedPortE aut m len) c j)
        (.seq (pChain aut m len (.test .one) c j)
          (parkedPortE aut m len)) := by
  intro c
  induction c with
  | zero =>
      intro j _ _
      exact EquivBA.symm (EquivBA.base (Equiv.s4 (parkedPortE aut m len)))
  | succ c ih =>
      intro j hj hle
      show EquivBA
        (.ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (pChain aut m len (parkedPortE aut m len) c (j + 1)))
          (.test (aut.hlt (m j))))
        (.seq (.ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (pChain aut m len (.test .one) c (j + 1)))
          (.test (aut.hlt (m j)))) (parkedPortE aut m len))
      refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
        (EquivBA.base (Equiv.u5 _ _ _ (parkedPortE aut m len)))
      · refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (ih (j + 1) (by omega) (by omega))) ?_
        exact seq_assoc' _ _ (parkedPortE aut m len)
      · exact park_absorb _ (himp j hj (by omega)) hexcl

open Classical in
/-- **THE PARKED CYCLE THEOREM** (cycle-local): a simple cycle whose interior
    halts are SUBSETS of the port's halt guard, whose port arms all re-enter
    the cycle, and whose port halt excludes its step guard, is fully
    role-covered — the port a `salomaaE` state whose body is the parked chain,
    interiors `equivFold`s of literal chain forms. -/
theorem parked_cycle_roles (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) (hlen : 2 ≤ len)
    (hsol_int : ∀ j, 1 ≤ j → j < len →
      sol (m j) = pChain aut m len (parkedPortE aut m len) (len - j) j)
    (hsol_port : sol (m 0) = parkedPortE aut m len)
    (hint_arms : ∀ j, 1 ≤ j → j < len → ∀ e ∈ aut.trans (m j),
      e.2.2 = nxtAt m len j)
    (hport_arms : ∀ e ∈ aut.trans (m 0), e.2.2 = m 1)
    (himp : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hexcl : GuardImplies (aut.hlt (m 0))
      (.not (gGuard (m 1) (aut.trans (m 0))))) :
    ∀ j, j < len → StateRole aut sol (m j) := by
  intro j hj
  cases Nat.eq_zero_or_pos j with
  | inl hzero =>
      subst hzero
      refine StateRole.salomaaE (gGuard (m 1) (aut.trans (m 0)))
        (.seq (gBody (m 1) (aut.trans (m 0)))
          (pChain aut m len (.test .one) (len - 1) 1))
        (.test (aut.hlt (m 0))) hsol_port ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (multi_gather sol (aut.hlt (m 0)) (m 1)
        (aut.trans (m 0))) ?_
      rw [gOthers_nil_of_all (m 1) (aut.trans (m 0)) hport_arms,
          hsol_int 1 (Nat.le_refl 1) (by omega)]
      refine EquivBA.trans (EquivBA.ite_c
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (pChain_split aut m len himp hexcl (len - 1) 1
            (Nat.le_refl 1) (by omega)))
        (EquivBA.base (Equiv.refl _))) ?_
      refine EquivBA.trans (EquivBA.ite_c
        (seq_assoc' _ _ (parkedPortE aut m len))
        (EquivBA.base (Equiv.refl _))) ?_
      rw [← hsol_port]
      exact EquivBA.base (Equiv.refl _)
  | inr hpos =>
      refine StateRole.equivFold ?_
      have hstep : sol (m j)
          = .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
            (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
              (sol (nxtAt m len j)))
            (.test (aut.hlt (m j))) := by
        rw [hsol_int j hpos hj,
            show len - j = (len - (j + 1)) + 1 from by omega]
        by_cases hj1 : j + 1 = len
        · have : sol (nxtAt m len j) = parkedPortE aut m len := by
            unfold nxtAt
            rw [if_pos hj1]
            exact hsol_port
          rw [this, show len - (j + 1) = 0 from by omega]
          rfl
        · have : sol (nxtAt m len j)
              = pChain aut m len (parkedPortE aut m len) (len - (j + 1))
                (j + 1) := by
            unfold nxtAt
            rw [if_neg hj1]
            exact hsol_int (j + 1) (by omega) (by omega)
          rw [this]
          rfl
      rw [hstep, eqRHS_foldTL]
      refine EquivBA.trans ?_ (EquivBA.symm
        (multi_gather sol (aut.hlt (m j)) (nxtAt m len j) (aut.trans (m j))))
      rw [gOthers_nil_of_all (nxtAt m len j) (aut.trans (m j))
        (hint_arms j hpos hj)]
      exact EquivBA.base (Equiv.refl _)

#print axioms parked_cycle_roles

/-! ## The full assembly: all proved strata under one recursion

    Base states, single-port cycles, and parked cycles dispatched by one
    WF-recursive solution.  Parked closed forms reference no other solutions at
    all (their port REST is a bare halt test), so they impose no rank
    conditions. -/

open Classical in
/-- The three-way assembled solution.  Payload tag: `false` = single-port
    cycle (chain/port closed forms), `true` = parked cycle. -/
noncomputable def asmSol2 (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Bool × Nat × (Nat → S) × Nat)) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    match cy s with
    | none =>
        .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
            (aut.hlt s) (gOthers s (aut.trans s)))
    | some (false, len, m, i) =>
        cycSolOf aut m len i
          (fun t => if h : rank t < rank s then rec t h else .test .zero)
    | some (true, len, m, i) =>
        if i = 0 then parkedPortE aut m len
        else pChain aut m len (parkedPortE aut m len) (len - i) i)

open Classical in
theorem asmSol2_eq (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Bool × Nat × (Nat → S) × Nat)) (s : S) :
    asmSol2 aut rank cy s
      = (match cy s with
        | none =>
            .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (fun t =>
                  if _ : rank t < rank s then asmSol2 aut rank cy t
                  else .test .zero)
                (aut.hlt s) (gOthers s (aut.trans s)))
        | some (false, len, m, i) =>
            cycSolOf aut m len i
              (fun t =>
                if _ : rank t < rank s then asmSol2 aut rank cy t
                else .test .zero)
        | some (true, len, m, i) =>
            if i = 0 then parkedPortE aut m len
            else pChain aut m len (parkedPortE aut m len) (len - i) i) := by
  unfold asmSol2
  rw [WellFounded.fix_eq]

open Classical in
/-- **THE FULL ASSEMBLY THEOREM**: an automaton whose every state is base
    (self-or-descending), a member of a designated single-port simple cycle, or
    a member of a designated parked cycle, is fully role-covered. -/
theorem full_assembly_roles (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Bool × Nat × (Nat → S) × Nat))
    (hcyF : ∀ s len m i, cy s = some (false, len, m, i) →
      i < len ∧ 2 ≤ len ∧ m i = s ∧
      (∀ j, j < len → cy (m j) = some (false, len, m, j)) ∧
      (∀ j, j < len → rank (m j) = rank (m 0)) ∧
      (∀ j, 1 ≤ j → j < len →
        (∀ e ∈ aut.trans (m j),
          e.2.2 = (if j + 1 = len then m 0 else m (j + 1)))
        ∧ GuardEmpty (aut.hlt (m j))) ∧
      (∀ e ∈ aut.trans (m 0), e.2.2 = m 1 ∨ rank e.2.2 < rank (m 0)))
    (hcyT : ∀ s len m i, cy s = some (true, len, m, i) →
      i < len ∧ 2 ≤ len ∧ m i = s ∧
      (∀ j, j < len → cy (m j) = some (true, len, m, j)) ∧
      (∀ j, 1 ≤ j → j < len → ∀ e ∈ aut.trans (m j),
        e.2.2 = nxtAt m len j) ∧
      (∀ e ∈ aut.trans (m 0), e.2.2 = m 1) ∧
      (∀ j, 1 ≤ j → j < len →
        GuardImplies (aut.hlt (m j)) (aut.hlt (m 0))) ∧
      GuardImplies (aut.hlt (m 0))
        (.not (gGuard (m 1) (aut.trans (m 0)))))
    (hbase : ∀ s ∈ aut.states, cy s = none →
      ∀ e ∈ aut.trans s, e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨asmSol2 aut rank cy, fun s hs => ?_⟩
  cases hcys : cy s with
  | none =>
      have hlow : ∀ e ∈ gOthers s (aut.trans s), rank e.2.2 < rank s := by
        intro e he
        obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
        rcases hbase s hs hcys e heL with h1 | h2
        · exact absurd h1 hne
        · exact h2
      have hsol : asmSol2 aut rank cy s
          = .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (asmSol2 aut rank cy) (aut.hlt s)
                (gOthers s (aut.trans s))) := by
        rw [asmSol2_eq, hcys]
        exact congrArg _ (foldTL_congr' (aut.hlt s) (gOthers s (aut.trans s))
          (fun e he => dif_pos (hlow e he)))
      refine StateRole.salomaaE (gGuard s (aut.trans s))
        (gBody s (aut.trans s))
        (foldTL (asmSol2 aut rank cy) (aut.hlt s) (gOthers s (aut.trans s)))
        hsol ?_
      rw [eqRHS_foldTL]
      exact multi_gather (asmSol2 aut rank cy) (aut.hlt s) s (aut.trans s)
  | some q =>
      obtain ⟨tag, len, m, i⟩ := q
      cases tag with
      | false =>
          obtain ⟨hilt, hlen, hmi, hcoh, hrank, hint, hport⟩ :=
            hcyF s len m i hcys
          have hlowAt : ∀ j, j < len →
              ∀ e ∈ gOthers (m 1) (aut.trans (m 0)),
                rank e.2.2 < rank (m j) := by
            intro j hj e he
            obtain ⟨heL, hne⟩ := gOthers_sub (m 1) (aut.trans (m 0)) e he
            rcases hport e heL with h1 | h2
            · exact absurd h1 hne
            · rw [hrank j hj]; exact h2
          have hcycsol : ∀ j, j < len →
              asmSol2 aut rank cy (m j)
                = cycSolOf aut m len j (asmSol2 aut rank cy) := by
            intro j hj
            rw [asmSol2_eq, hcoh j hj]
            exact cycSolOf_congr aut m len j
              (fun e he => dif_pos (hlowAt j hj e he))
          have hsol_port : asmSol2 aut rank cy (m 0)
              = portExprOf aut m len (asmSol2 aut rank cy) := by
            rw [hcycsol 0 (by omega)]
            unfold cycSolOf
            rw [if_pos rfl]
          have hsol_int : ∀ j, 1 ≤ j → j < len →
              asmSol2 aut rank cy (m j)
                = .seq (factorAt aut m len j)
                  (asmSol2 aut rank cy
                    (if j + 1 = len then m 0 else m (j + 1))) := by
            intro j hj hjlt
            rw [hcycsol j hjlt]
            unfold cycSolOf
            rw [if_neg (by omega : ¬ (j = 0)),
                show len - j = (len - (j + 1)) + 1 from by omega]
            by_cases hj1 : j + 1 = len
            · rw [if_pos hj1, hsol_port,
                  show len - (j + 1) = 0 from by omega]
              rfl
            · rw [if_neg hj1, hcycsol (j + 1) (by omega)]
              unfold cycSolOf
              rw [if_neg (by omega : ¬ (j + 1 = 0))]
              rfl
          have hroles := single_port_cycle_roles aut (asmSol2 aut rank cy)
            m len hlen hsol_int
            (by rw [hsol_port]; rfl)
            (fun j hj hjlt => (hint j hj hjlt).1)
            (fun j hj hjlt => (hint j hj hjlt).2)
          rw [← hmi]
          exact hroles i hilt
      | true =>
          obtain ⟨hilt, hlen, hmi, hcoh, hint, hport, himp, hexcl⟩ :=
            hcyT s len m i hcys
          have hsol_port : asmSol2 aut rank cy (m 0)
              = parkedPortE aut m len := by
            rw [asmSol2_eq, hcoh 0 (by omega)]
            show (if (0 : Nat) = 0 then parkedPortE aut m len
              else pChain aut m len (parkedPortE aut m len) (len - 0) 0)
              = parkedPortE aut m len
            rw [if_pos rfl]
          have hsol_int : ∀ j, 1 ≤ j → j < len →
              asmSol2 aut rank cy (m j)
                = pChain aut m len (parkedPortE aut m len) (len - j) j := by
            intro j hj hjlt
            rw [asmSol2_eq, hcoh j hjlt]
            show (if j = 0 then parkedPortE aut m len
              else pChain aut m len (parkedPortE aut m len) (len - j) j) = _
            rw [if_neg (by omega : ¬ (j = 0))]
          have hroles := parked_cycle_roles aut (asmSol2 aut rank cy)
            m len hlen hsol_int hsol_port hint hport himp hexcl
          rw [← hmi]
          exact hroles i hilt

#print axioms full_assembly_roles

/-! ## The walked cycle: members may self-loop

    In a 2-state SCC, a brancher can only branch to itself and the other
    member — so every 2-state "branchy" census row is a cycle whose members
    carry self-loops.  Gathering self-arms per member and Salomaa-wrapping them
    locally turns each member into a `wh`-prefixed straight-line factor; the
    port's own self-loop folds into the cycle body by `arms_merge`.  Parked
    halts are carried through as before. -/

open Classical in
/-- Gather a dispatch twice: self-arms first, then next-arms among the rest. -/
theorem double_gather (sol : S → Exp A T) (h : BExp T) (u v : S)
    (L : List (BExp T × A × S)) :
    EquivBA (foldTL sol h L)
      (.ite (gGuard u L) (.seq (gBody u L) (sol u))
        (.ite (gGuard v (gOthers u L)) (.seq (gBody v (gOthers u L)) (sol v))
          (foldTL sol h (gOthers v (gOthers u L))))) :=
  EquivBA.trans (multi_gather sol h u L)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
      (multi_gather sol h v (gOthers u L)))

open Classical in
/-- The gathered self-loop guard of position `j`. -/
noncomputable def selfG (aut : GAut S A T) (m : Nat → S) (j : Nat) : BExp T :=
  gGuard (m j) (aut.trans (m j))

open Classical in
/-- The gathered self-loop body of position `j`. -/
noncomputable def selfB (aut : GAut S A T) (m : Nat → S) (j : Nat) : Exp A T :=
  gBody (m j) (aut.trans (m j))

open Classical in
/-- The non-self remainder of position `j`'s dispatch. -/
noncomputable def restL (aut : GAut S A T) (m : Nat → S) (j : Nat) :
    List (BExp T × A × S) :=
  gOthers (m j) (aut.trans (m j))

open Classical in
/-- The gathered next-step guard of position `j` (within the non-self rest). -/
noncomputable def nextG (aut : GAut S A T) (m : Nat → S) (len j : Nat) :
    BExp T :=
  gGuard (nxtAt m len j) (restL aut m j)

open Classical in
/-- The gathered next-step body of position `j`. -/
noncomputable def nextB (aut : GAut S A T) (m : Nat → S) (len j : Nat) :
    Exp A T :=
  gBody (nxtAt m len j) (restL aut m j)

open Classical in
/-- The walked chain from position `j`: locally loop the self-arms, then step
    onward or halt in place. -/
noncomputable def wChain (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (term : Exp A T) : Nat → Nat → Exp A T
  | 0, _ => term
  | c + 1, j =>
      .seq (.wh (selfG aut m j) (selfB aut m j))
        (.ite (nextG aut m len j)
          (.seq (nextB aut m len j) (wChain aut m len term c (j + 1)))
          (.test (aut.hlt (m j))))

open Classical in
/-- The walked port solution: the port's own self-loop is merged into the
    cycle body. -/
noncomputable def walkedPortE (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    Exp A T :=
  .seq (.wh (.or (selfG aut m 0) (nextG aut m len 0))
      (.ite (selfG aut m 0) (selfB aut m 0)
        (.seq (nextB aut m len 0) (wChain aut m len (.test .one) (len - 1) 1))))
    (.test (aut.hlt (m 0)))

open Classical in
/-- **THE WALKED SPLIT**: the port solution right-distributes out of the whole
    walked chain — associativity through the local `wh` prefixes, `u5` on the
    step arms, `park_absorb` on the halt arms. -/
theorem wChain_split (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (himp : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hexcl : GuardImplies (aut.hlt (m 0))
      (.not (.or (selfG aut m 0) (nextG aut m len 0)))) :
    ∀ c j, 1 ≤ j → j + c ≤ len →
      EquivBA (wChain aut m len (walkedPortE aut m len) c j)
        (.seq (wChain aut m len (.test .one) c j)
          (walkedPortE aut m len)) := by
  intro c
  induction c with
  | zero =>
      intro j _ _
      exact EquivBA.symm (EquivBA.base (Equiv.s4 (walkedPortE aut m len)))
  | succ c ih =>
      intro j hj hle
      show EquivBA
        (.seq (.wh (selfG aut m j) (selfB aut m j))
          (.ite (nextG aut m len j)
            (.seq (nextB aut m len j)
              (wChain aut m len (walkedPortE aut m len) c (j + 1)))
            (.test (aut.hlt (m j)))))
        (.seq (.seq (.wh (selfG aut m j) (selfB aut m j))
          (.ite (nextG aut m len j)
            (.seq (nextB aut m len j)
              (wChain aut m len (.test .one) c (j + 1)))
            (.test (aut.hlt (m j)))))
          (walkedPortE aut m len))
      refine EquivBA.trans ?_ (seq_assoc' _ _ (walkedPortE aut m len))
      refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
      refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
        (EquivBA.base (Equiv.u5 _ _ _ (walkedPortE aut m len)))
      · refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (ih (j + 1) (by omega) (by omega))) ?_
        exact seq_assoc' _ _ (walkedPortE aut m len)
      · exact park_absorb _ (himp j hj (by omega)) hexcl

open Classical in
/-- **THE WALKED CYCLE THEOREM** (cycle-local): a cycle whose members may each
    carry self-loops, with parked halts and single next-successors, is fully
    role-covered — every member (port included) is a `salomaaE` state. -/
theorem walked_cycle_roles (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) (hlen : 2 ≤ len)
    (hsol_int : ∀ j, 1 ≤ j → j < len →
      sol (m j) = wChain aut m len (walkedPortE aut m len) (len - j) j)
    (hsol_port : sol (m 0) = walkedPortE aut m len)
    (hint_nil : ∀ j, 1 ≤ j → j < len →
      gOthers (nxtAt m len j) (restL aut m j) = [])
    (hport_nil : gOthers (nxtAt m len 0) (restL aut m 0) = [])
    (himp : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hexcl : GuardImplies (aut.hlt (m 0))
      (.not (.or (selfG aut m 0) (nextG aut m len 0)))) :
    ∀ j, j < len → StateRole aut sol (m j) := by
  have hstep : ∀ j, 1 ≤ j → j < len →
      sol (m j) = .seq (.wh (selfG aut m j) (selfB aut m j))
        (.ite (nextG aut m len j)
          (.seq (nextB aut m len j) (sol (nxtAt m len j)))
          (.test (aut.hlt (m j)))) := by
    intro j hj hjlt
    rw [hsol_int j hj hjlt,
        show len - j = (len - (j + 1)) + 1 from by omega]
    by_cases hj1 : j + 1 = len
    · have hnx : sol (nxtAt m len j) = walkedPortE aut m len := by
        unfold nxtAt
        rw [if_pos hj1]
        exact hsol_port
      rw [hnx, show len - (j + 1) = 0 from by omega]
      rfl
    · have hnx : sol (nxtAt m len j)
          = wChain aut m len (walkedPortE aut m len) (len - (j + 1))
            (j + 1) := by
        unfold nxtAt
        rw [if_neg hj1]
        exact hsol_int (j + 1) (by omega) (by omega)
      rw [hnx]
      rfl
  intro j hj
  cases Nat.eq_zero_or_pos j with
  | inl hzero =>
      subst hzero
      refine StateRole.salomaaE
        (.or (selfG aut m 0) (nextG aut m len 0))
        (.ite (selfG aut m 0) (selfB aut m 0)
          (.seq (nextB aut m len 0)
            (wChain aut m len (.test .one) (len - 1) 1)))
        (.test (aut.hlt (m 0))) hsol_port ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (double_gather sol (aut.hlt (m 0)) (m 0)
        (nxtAt m len 0) (aut.trans (m 0))) ?_
      rw [show gOthers (nxtAt m len 0) (gOthers (m 0) (aut.trans (m 0))) = []
        from hport_nil]
      have hx1 : sol (nxtAt m len 0)
          = wChain aut m len (walkedPortE aut m len) (len - 1) 1 := by
        unfold nxtAt
        rw [if_neg (by omega : ¬ (0 + 1 = len))]
        exact hsol_int 1 (Nat.le_refl 1) (by omega)
      rw [hx1]
      refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
        (EquivBA.ite_c
          (EquivBA.trans
            (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
              (wChain_split aut m len himp hexcl (len - 1) 1
                (Nat.le_refl 1) (by omega)))
            (seq_assoc' _ _ (walkedPortE aut m len)))
          (EquivBA.base (Equiv.refl _)))) ?_
      rw [← hsol_port]
      exact arms_merge (selfG aut m 0) (nextG aut m len 0) (selfB aut m 0)
        (.seq (nextB aut m len 0) (wChain aut m len (.test .one) (len - 1) 1))
        (sol (m 0)) (.test (aut.hlt (m 0)))
  | inr hpos =>
      refine StateRole.salomaaE (selfG aut m j) (selfB aut m j)
        (.ite (nextG aut m len j)
          (.seq (nextB aut m len j) (sol (nxtAt m len j)))
          (.test (aut.hlt (m j))))
        (hstep j hpos hj) ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (double_gather sol (aut.hlt (m j)) (m j)
        (nxtAt m len j) (aut.trans (m j))) ?_
      rw [show gOthers (nxtAt m len j) (gOthers (m j) (aut.trans (m j))) = []
        from hint_nil j hpos hj]
      exact EquivBA.base (Equiv.refl _)

#print axioms walked_cycle_roles

/-! ## The exit port: the walked cycle with an arbitrary port residual

    The port may carry exit arms: its REST becomes the residual fold over its
    non-cycle dispatch.  Parked interior halts must then FALL THROUGH the
    port's exit fold to its final halt: three `bval`-level side conditions
    (halt inside the port halt, disjoint from every port exit guard, excluded
    from the port loop guard), each census-checkable. -/

open Classical in
/-- A guard disjoint from every arm falls through a Salomaa fold to its final
    test, and a sub-halt is absorbed there. -/
theorem fold_absorb {sol : S → Exp A T} {h c : BExp T}
    (himpc : GuardImplies h c) :
    ∀ E : List (BExp T × A × S), (∀ e ∈ E, GuardEmpty (.and h e.1)) →
    EquivBA (.seq (.test h) (foldTL sol c E)) (.test h) := by
  intro E
  induction E with
  | nil =>
      intro _
      refine EquivBA.trans (EquivBA.s6 h c) ?_
      refine EquivBA.baTest ?_
      intro X W x
      show (bval W h x && bval W c x) = bval W h x
      cases hh : bval W h x with
      | true => rw [himpc X W x hh]; rfl
      | false => rfl
  | cons hd rest ih =>
      intro hdisj
      obtain ⟨g, a, t⟩ := hd
      show EquivBA (.seq (.test h)
        (.ite g (.seq (.act a) (sol t)) (foldTL sol c rest))) (.test h)
      refine EquivBA.trans (test_seq_ite h g _ _) ?_
      refine EquivBA.trans (GkatDeadExitElim.ite_zero_guard _ _
        (fun X W x => hdisj (g, a, t) (by simp) X W x)) ?_
      exact ih (fun e he => hdisj e (by simp [he]))

open Classical in
/-- **Parking absorption through an exit fold**: a halt excluded from the loop
    guard and from every exit guard, and inside the final halt, absorbs the
    whole port solution. -/
theorem park_absorb_exits {sol : S → Exp A T} {h c G : BExp T} (B : Exp A T)
    {E : List (BExp T × A × S)}
    (himpG : GuardImplies h (.not G))
    (hdisj : ∀ e ∈ E, GuardEmpty (.and h e.1))
    (himpc : GuardImplies h c) :
    EquivBA (.test h : Exp A T)
      (.seq (.test h) (.seq (.wh G B) (foldTL sol c E))) := by
  refine EquivBA.symm ?_
  refine EquivBA.trans (seq_assoc' (.test h) (.wh G B) (foldTL sol c E)) ?_
  refine EquivBA.trans (EquivBA.seq_c (test_wh_absorb h G B himpG)
    (EquivBA.base (Equiv.refl _))) ?_
  exact fold_absorb himpc E hdisj

open Classical in
/-- The exit-port walked port solution: loop the walked chain, exit into the
    port's residual fold. -/
noncomputable def walkedExitPortE (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) : Exp A T :=
  .seq (.wh (.or (selfG aut m 0) (nextG aut m len 0))
      (.ite (selfG aut m 0) (selfB aut m 0)
        (.seq (nextB aut m len 0) (wChain aut m len (.test .one) (len - 1) 1))))
    (foldTL sol (aut.hlt (m 0)) (gOthers (nxtAt m len 0) (restL aut m 0)))

open Classical in
/-- The walked chain terminated at the exit-port solution. -/
noncomputable def wChainE (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) : Nat → Nat → Exp A T :=
  wChain aut m len (walkedExitPortE aut sol m len)

open Classical in
/-- The walked split, exit-port version. -/
theorem wChainE_split (aut : GAut S A T) (sol : S → Exp A T) (m : Nat → S)
    (len : Nat)
    (himpc : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hdisj : ∀ j, 1 ≤ j → j < len →
      ∀ e ∈ gOthers (nxtAt m len 0) (restL aut m 0),
        GuardEmpty (.and (aut.hlt (m j)) e.1))
    (hexcl : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j))
        (.not (.or (selfG aut m 0) (nextG aut m len 0)))) :
    ∀ c j, 1 ≤ j → j + c ≤ len →
      EquivBA (wChainE aut sol m len c j)
        (.seq (wChain aut m len (.test .one) c j)
          (walkedExitPortE aut sol m len)) := by
  intro c
  induction c with
  | zero =>
      intro j _ _
      exact EquivBA.symm
        (EquivBA.base (Equiv.s4 (walkedExitPortE aut sol m len)))
  | succ c ih =>
      intro j hj hle
      show EquivBA
        (.seq (.wh (selfG aut m j) (selfB aut m j))
          (.ite (nextG aut m len j)
            (.seq (nextB aut m len j) (wChainE aut sol m len c (j + 1)))
            (.test (aut.hlt (m j)))))
        (.seq (.seq (.wh (selfG aut m j) (selfB aut m j))
          (.ite (nextG aut m len j)
            (.seq (nextB aut m len j)
              (wChain aut m len (.test .one) c (j + 1)))
            (.test (aut.hlt (m j)))))
          (walkedExitPortE aut sol m len))
      refine EquivBA.trans ?_ (seq_assoc' _ _ (walkedExitPortE aut sol m len))
      refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
      refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
        (EquivBA.base (Equiv.u5 _ _ _ (walkedExitPortE aut sol m len)))
      · refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (ih (j + 1) (by omega) (by omega))) ?_
        exact seq_assoc' _ _ (walkedExitPortE aut sol m len)
      · exact park_absorb_exits _ (hexcl j hj (by omega))
          (hdisj j hj (by omega)) (himpc j hj (by omega))

open Classical in
/-- **THE EXIT-PORT WALKED CYCLE THEOREM** (cycle-local): the walked cycle
    with an arbitrary port residual — exits and halt — is fully role-covered,
    provided interior halts fall through the port's exit fold. -/
theorem walked_exit_cycle_roles (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) (hlen : 2 ≤ len)
    (hsol_int : ∀ j, 1 ≤ j → j < len →
      sol (m j) = wChainE aut sol m len (len - j) j)
    (hsol_port : sol (m 0) = walkedExitPortE aut sol m len)
    (hint_nil : ∀ j, 1 ≤ j → j < len →
      gOthers (nxtAt m len j) (restL aut m j) = [])
    (himpc : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hdisj : ∀ j, 1 ≤ j → j < len →
      ∀ e ∈ gOthers (nxtAt m len 0) (restL aut m 0),
        GuardEmpty (.and (aut.hlt (m j)) e.1))
    (hexcl : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j))
        (.not (.or (selfG aut m 0) (nextG aut m len 0)))) :
    ∀ j, j < len → StateRole aut sol (m j) := by
  have hstep : ∀ j, 1 ≤ j → j < len →
      sol (m j) = .seq (.wh (selfG aut m j) (selfB aut m j))
        (.ite (nextG aut m len j)
          (.seq (nextB aut m len j) (sol (nxtAt m len j)))
          (.test (aut.hlt (m j)))) := by
    intro j hj hjlt
    rw [hsol_int j hj hjlt]
    show wChain aut m len (walkedExitPortE aut sol m len) (len - j) j = _
    rw [show len - j = (len - (j + 1)) + 1 from by omega]
    by_cases hj1 : j + 1 = len
    · have hnx : sol (nxtAt m len j) = walkedExitPortE aut sol m len := by
        unfold nxtAt
        rw [if_pos hj1]
        exact hsol_port
      rw [hnx, show len - (j + 1) = 0 from by omega]
      rfl
    · have hnx : sol (nxtAt m len j)
          = wChain aut m len (walkedExitPortE aut sol m len)
            (len - (j + 1)) (j + 1) := by
        unfold nxtAt
        rw [if_neg hj1]
        exact hsol_int (j + 1) (by omega) (by omega)
      rw [hnx]
      rfl
  intro j hj
  cases Nat.eq_zero_or_pos j with
  | inl hzero =>
      subst hzero
      refine StateRole.salomaaE
        (.or (selfG aut m 0) (nextG aut m len 0))
        (.ite (selfG aut m 0) (selfB aut m 0)
          (.seq (nextB aut m len 0)
            (wChain aut m len (.test .one) (len - 1) 1)))
        (foldTL sol (aut.hlt (m 0)) (gOthers (nxtAt m len 0) (restL aut m 0)))
        hsol_port ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (double_gather sol (aut.hlt (m 0)) (m 0)
        (nxtAt m len 0) (aut.trans (m 0))) ?_
      have hx1 : sol (nxtAt m len 0) = wChainE aut sol m len (len - 1) 1 := by
        unfold nxtAt
        rw [if_neg (by omega : ¬ (0 + 1 = len))]
        exact hsol_int 1 (Nat.le_refl 1) (by omega)
      rw [hx1]
      refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
        (EquivBA.ite_c
          (EquivBA.trans
            (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
              (wChainE_split aut sol m len himpc hdisj hexcl (len - 1) 1
                (Nat.le_refl 1) (by omega)))
            (seq_assoc' _ _ (walkedExitPortE aut sol m len)))
          (EquivBA.base (Equiv.refl _)))) ?_
      rw [← hsol_port]
      exact arms_merge (selfG aut m 0) (nextG aut m len 0) (selfB aut m 0)
        (.seq (nextB aut m len 0) (wChain aut m len (.test .one) (len - 1) 1))
        (sol (m 0))
        (foldTL sol (aut.hlt (m 0)) (gOthers (nxtAt m len 0) (restL aut m 0)))
  | inr hpos =>
      refine StateRole.salomaaE (selfG aut m j) (selfB aut m j)
        (.ite (nextG aut m len j)
          (.seq (nextB aut m len j) (sol (nxtAt m len j)))
          (.test (aut.hlt (m j))))
        (hstep j hpos hj) ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (double_gather sol (aut.hlt (m j)) (m j)
        (nxtAt m len j) (aut.trans (m j))) ?_
      rw [show gOthers (nxtAt m len j) (gOthers (m j) (aut.trans (m j))) = []
        from hint_nil j hpos hj]
      exact EquivBA.base (Equiv.refl _)

#print axioms walked_exit_cycle_roles

/-! ## The walked-exit assembly

    The engine-facing assembly: states are BASE (all arms self or strictly
    descending — the gathered Salomaa closed form covers self-arms) or members
    of designated WALKED-EXIT cycles — exactly the two shapes the cycle
    dichotomy produces on cleaned canonical quotients. -/

open Classical in
private theorem walkedExitPortE_congr (aut : GAut S A T) (m : Nat → S)
    (len : Nat) {sol₁ sol₂ : S → Exp A T}
    (h : ∀ e ∈ gOthers (nxtAt m len 0) (restL aut m 0),
      sol₁ e.2.2 = sol₂ e.2.2) :
    walkedExitPortE aut sol₁ m len = walkedExitPortE aut sol₂ m len := by
  unfold walkedExitPortE
  rw [foldTL_congr' (aut.hlt (m 0))
    (gOthers (nxtAt m len 0) (restL aut m 0)) h]

open Classical in
private theorem wChain_term_congr (aut : GAut S A T) (m : Nat → S) (len : Nat)
    {t₁ t₂ : Exp A T} (h : t₁ = t₂) :
    ∀ c j, wChain aut m len t₁ c j = wChain aut m len t₂ c j := by
  intro c
  induction c with
  | zero => intro j; exact h
  | succ c ih =>
      intro j
      show Exp.seq _ (.ite _ (.seq _ (wChain aut m len t₁ c (j + 1))) _)
        = Exp.seq _ (.ite _ (.seq _ (wChain aut m len t₂ c (j + 1))) _)
      rw [ih (j + 1)]

open Classical in
/-- The walked assembly solution: gathered Salomaa closed forms at base
    states, walked-exit chain/port closed forms on designated cycles. -/
noncomputable def asmSolW (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    match cy s with
    | none =>
        .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
            (aut.hlt s) (gOthers s (aut.trans s)))
    | some (len, m, i) =>
        if i = 0 then
          walkedExitPortE aut
            (fun t => if h : rank t < rank s then rec t h else .test .zero)
            m len
        else
          wChain aut m len
            (walkedExitPortE aut
              (fun t => if h : rank t < rank s then rec t h else .test .zero)
              m len)
            (len - i) i)

open Classical in
theorem asmSolW_eq (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) (s : S) :
    asmSolW aut rank cy s
      = (match cy s with
        | none =>
            .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (fun t =>
                  if _ : rank t < rank s then asmSolW aut rank cy t
                  else .test .zero)
                (aut.hlt s) (gOthers s (aut.trans s)))
        | some (len, m, i) =>
            if i = 0 then
              walkedExitPortE aut
                (fun t =>
                  if _ : rank t < rank s then asmSolW aut rank cy t
                  else .test .zero) m len
            else
              wChain aut m len
                (walkedExitPortE aut
                  (fun t =>
                    if _ : rank t < rank s then asmSolW aut rank cy t
                    else .test .zero) m len)
                (len - i) i) := by
  unfold asmSolW
  rw [WellFounded.fix_eq]

open Classical in
/-- **THE WALKED-EXIT ASSEMBLY THEOREM**: an automaton whose every state is
    base (arms self or strictly descending) or a member of a designated
    walked-exit cycle is fully role-covered. -/
theorem walked_assembly_roles (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat))
    (hcy : ∀ s len m i, cy s = some (len, m, i) →
      i < len ∧ 2 ≤ len ∧ m i = s ∧
      (∀ j, j < len → cy (m j) = some (len, m, j)) ∧
      (∀ j, j < len → rank (m j) = rank (m 0)) ∧
      (∀ e ∈ gOthers (nxtAt m len 0) (restL aut m 0),
        rank e.2.2 < rank (m 0)) ∧
      (∀ j, 1 ≤ j → j < len →
        gOthers (nxtAt m len j) (restL aut m j) = []) ∧
      (∀ j, 1 ≤ j → j < len →
        GuardImplies (aut.hlt (m j)) (aut.hlt (m 0))) ∧
      (∀ j, 1 ≤ j → j < len →
        ∀ e ∈ gOthers (nxtAt m len 0) (restL aut m 0),
          GuardEmpty (.and (aut.hlt (m j)) e.1)) ∧
      (∀ j, 1 ≤ j → j < len →
        GuardImplies (aut.hlt (m j))
          (.not (.or (selfG aut m 0) (nextG aut m len 0)))))
    (hbase : ∀ s ∈ aut.states, cy s = none →
      ∀ e ∈ aut.trans s, e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨asmSolW aut rank cy, fun s hs => ?_⟩
  cases hcys : cy s with
  | none =>
      have hlow : ∀ e ∈ gOthers s (aut.trans s), rank e.2.2 < rank s := by
        intro e he
        obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
        rcases hbase s hs hcys e heL with h1 | h2
        · exact absurd h1 hne
        · exact h2
      have hsol : asmSolW aut rank cy s
          = .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (asmSolW aut rank cy) (aut.hlt s)
                (gOthers s (aut.trans s))) := by
        rw [asmSolW_eq, hcys]
        exact congrArg _ (foldTL_congr' (aut.hlt s) (gOthers s (aut.trans s))
          (fun e he => dif_pos (hlow e he)))
      refine StateRole.salomaaE (gGuard s (aut.trans s))
        (gBody s (aut.trans s))
        (foldTL (asmSolW aut rank cy) (aut.hlt s) (gOthers s (aut.trans s)))
        hsol ?_
      rw [eqRHS_foldTL]
      exact multi_gather (asmSolW aut rank cy) (aut.hlt s) s (aut.trans s)
  | some q =>
      obtain ⟨len, m, i⟩ := q
      obtain ⟨hilt, hlen, hmi, hcoh, hrank, hport_lo, hint_nil, himpc,
        hdisj, hexcl⟩ := hcy s len m i hcys
      have hlowAt : ∀ j, j < len →
          ∀ e ∈ gOthers (nxtAt m len 0) (restL aut m 0),
            rank e.2.2 < rank (m j) := by
        intro j hj e he
        rw [hrank j hj]
        exact hport_lo e he
      have hcycsol : ∀ j, j < len →
          asmSolW aut rank cy (m j)
            = (if j = 0 then
                walkedExitPortE aut (asmSolW aut rank cy) m len
              else
                wChain aut m len
                  (walkedExitPortE aut (asmSolW aut rank cy) m len)
                  (len - j) j) := by
        intro j hj
        rw [asmSolW_eq, hcoh j hj]
        show (if j = 0 then
            walkedExitPortE aut
              (fun t => if _ : rank t < rank (m j) then asmSolW aut rank cy t
                else Exp.test BExp.zero) m len
          else
            wChain aut m len
              (walkedExitPortE aut
                (fun t => if _ : rank t < rank (m j) then asmSolW aut rank cy t
                  else Exp.test BExp.zero) m len)
              (len - j) j) = _
        by_cases hj0 : j = 0
        · rw [if_pos hj0, if_pos hj0]
          exact walkedExitPortE_congr aut m len
            (fun e he => dif_pos (hlowAt j hj e he))
        · rw [if_neg hj0, if_neg hj0]
          exact wChain_term_congr aut m len
            (walkedExitPortE_congr aut m len
              (fun e he => dif_pos (hlowAt j hj e he))) (len - j) j
      have hsol_port : asmSolW aut rank cy (m 0)
          = walkedExitPortE aut (asmSolW aut rank cy) m len := by
        have h0 := hcycsol 0 (by omega)
        rw [if_pos rfl] at h0
        exact h0
      have hsol_int : ∀ j, 1 ≤ j → j < len →
          asmSolW aut rank cy (m j)
            = wChainE aut (asmSolW aut rank cy) m len (len - j) j := by
        intro j hj hjlt
        have h0 := hcycsol j hjlt
        rw [if_neg (by omega : ¬ (j = 0))] at h0
        exact h0
      have hroles := walked_exit_cycle_roles aut (asmSolW aut rank cy)
        m len hlen hsol_int hsol_port hint_nil himpc hdisj hexcl
      rw [← hmi]
      exact hroles i hilt

#print axioms walked_assembly_roles

/-! ## The parked cycle with a GATED port exit

    `parked_cycle_roles` requires every interior halt to be a SUBSET of the
    port's halt guard.  The SCC census names that condition as one of three
    shapes in the residue: 44 open instances in 59947 pairs, split between
    multi-member exit ports, NON-SUBSET HALTS, and genuine tree walks.

    NOTE, and read it before the theorem: this section was FIRST WRITTEN as
    though it admitted non-subset interior halts.  **That was wrong.**
    `gated_exit_forced` and `gated_himp_subset`, at the end of this file,
    prove it wrong: the exclusion and agreement hypotheses together PIN the
    "arbitrary" exit test to `¬G ∧ hlt (m 0)`, so the subset condition on
    interior halts survives unchanged.

    What this section actually buys is the removal of the ORIGINAL `hexcl`
    — the requirement that the PORT's own halt exclude the port's step
    guard.  Under the gated form the port halt may overlap its step guard
    freely; only its restriction to `¬G` is ever used.  Real, and much
    smaller than first advertised.

    The larger claim could not have been true, and the reason is a theorem
    rather than an accident.  Kosaraju: a flowchart is reducible to a
    structured program WITHOUT auxiliary variables iff it contains no loop
    with two distinct exits.  GKAT has no auxiliary variables, and a cycle
    with two incomparable halts IS a loop with two distinct exits.  No
    single `wh` expresses it, whatever the parking algebra does.  That
    shape needs unrolling or state duplication — a different automaton —
    not a better role theorem.

    `parked_cycle_roles` remains the special case `C := aut.hlt (m 0)`,
    where the agreement hypothesis is reflexivity. -/

/-- Congruence in the else arm, with the guard available (`ite_restrict_else`
    on both sides). -/
private theorem ite_else_congr_under {g : BExp T} {u v v' : Exp A T}
    (h : EquivBA (.seq (.test (.not g)) v) (.seq (.test (.not g)) v')) :
    EquivBA (.ite g u v) (.ite g u v') :=
  EquivBA.trans (ite_restrict_else g u v)
    (EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl u)) h)
      (EquivBA.symm (ite_restrict_else g u v')))

/-- Two else-arm TESTS that agree off the guard are interchangeable. -/
private theorem ite_else_test_gated {g h0 C : BExp T} (u : Exp A T)
    (hagree : ∀ (Y : Type) (W : T → Y → Bool) (y : Y),
      bval W (.and (.not g) h0) y = bval W (.and (.not g) C) y) :
    EquivBA (.ite g u (.test h0) : Exp A T) (.ite g u (.test C)) :=
  ite_else_congr_under
    (EquivBA.trans (EquivBA.s6 (.not g) h0)
      (EquivBA.trans (EquivBA.baTest hagree)
        (EquivBA.symm (EquivBA.s6 (.not g) C))))

open Classical in
/-- The parked port solution with an arbitrary exit test. -/
noncomputable def parkedPortG (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (C : BExp T) : Exp A T :=
  .seq (.wh (gGuard (m 1) (aut.trans (m 0)))
      (.seq (gBody (m 1) (aut.trans (m 0)))
        (pChain aut m len (.test .one) (len - 1) 1)))
    (.test C)

/-- `parkedPortE` is the special case where the exit test is the port halt. -/
theorem parkedPortG_hlt (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    parkedPortG aut m len (aut.hlt (m 0)) = parkedPortE aut m len := rfl

/-- **THE GATED PARKED SPLIT**: identical to `pChain_split`, with every
    interior halt parked under `C` instead of under the port's own halt. -/
theorem pChain_split_gated (aut : GAut S A T) (m : Nat → S) (len : Nat)
    (C : BExp T)
    (himp : ∀ j, 1 ≤ j → j < len → GuardImplies (aut.hlt (m j)) C)
    (hexcl : GuardImplies C (.not (gGuard (m 1) (aut.trans (m 0))))) :
    ∀ c j, 1 ≤ j → j + c ≤ len →
      EquivBA (pChain aut m len (parkedPortG aut m len C) c j)
        (.seq (pChain aut m len (.test .one) c j)
          (parkedPortG aut m len C)) := by
  intro c
  induction c with
  | zero =>
      intro j _ _
      exact EquivBA.symm (EquivBA.base (Equiv.s4 (parkedPortG aut m len C)))
  | succ c ih =>
      intro j hj hle
      show EquivBA
        (.ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (pChain aut m len (parkedPortG aut m len C) c (j + 1)))
          (.test (aut.hlt (m j))))
        (.seq (.ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (pChain aut m len (.test .one) c (j + 1)))
          (.test (aut.hlt (m j)))) (parkedPortG aut m len C))
      refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
        (EquivBA.base (Equiv.u5 _ _ _ (parkedPortG aut m len C)))
      · refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (ih (j + 1) (by omega) (by omega))) ?_
        exact seq_assoc' _ _ (parkedPortG aut m len C)
      · exact park_absorb _ (himp j hj (by omega)) hexcl

open Classical in
/-- **THE GATED PARKED CYCLE THEOREM.**  A simple cycle whose interior
    halts are subsets of an exit test `C` that excludes the port's step
    guard and agrees with the port halt off that guard is fully
    role-covered.

    `C` LOOKS free and is not: `gated_exit_forced` shows the last two
    hypotheses pin it to `¬G ∧ hlt (m 0)`, and `gated_himp_subset` shows
    the interior halts are therefore STILL below the port's halt.  The
    genuine content is that the PORT's halt no longer has to exclude its
    own step guard — only its restriction to `¬G` is used.  Taking
    `C := aut.hlt (m 0)` recovers `parked_cycle_roles`. -/
theorem parked_cycle_roles_gated (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) (hlen : 2 ≤ len) (C : BExp T)
    (hsol_int : ∀ j, 1 ≤ j → j < len →
      sol (m j) = pChain aut m len (parkedPortG aut m len C) (len - j) j)
    (hsol_port : sol (m 0) = parkedPortG aut m len C)
    (hint_arms : ∀ j, 1 ≤ j → j < len → ∀ e ∈ aut.trans (m j),
      e.2.2 = nxtAt m len j)
    (hport_arms : ∀ e ∈ aut.trans (m 0), e.2.2 = m 1)
    (himp : ∀ j, 1 ≤ j → j < len → GuardImplies (aut.hlt (m j)) C)
    (hexcl : GuardImplies C (.not (gGuard (m 1) (aut.trans (m 0)))))
    (hport : ∀ (Y : Type) (W : T → Y → Bool) (y : Y),
      bval W (.and (.not (gGuard (m 1) (aut.trans (m 0)))) (aut.hlt (m 0))) y
        = bval W (.and (.not (gGuard (m 1) (aut.trans (m 0)))) C) y) :
    ∀ j, j < len → StateRole aut sol (m j) := by
  intro j hj
  cases Nat.eq_zero_or_pos j with
  | inl hzero =>
      subst hzero
      refine StateRole.salomaaE (gGuard (m 1) (aut.trans (m 0)))
        (.seq (gBody (m 1) (aut.trans (m 0)))
          (pChain aut m len (.test .one) (len - 1) 1))
        (.test C) hsol_port ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (multi_gather sol (aut.hlt (m 0)) (m 1)
        (aut.trans (m 0))) ?_
      rw [gOthers_nil_of_all (m 1) (aut.trans (m 0)) hport_arms,
          hsol_int 1 (Nat.le_refl 1) (by omega)]
      refine EquivBA.trans (ite_else_test_gated _ hport) ?_
      refine EquivBA.trans (EquivBA.ite_c
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (pChain_split_gated aut m len C himp hexcl (len - 1) 1
            (Nat.le_refl 1) (by omega)))
        (EquivBA.base (Equiv.refl _))) ?_
      refine EquivBA.trans (EquivBA.ite_c
        (seq_assoc' _ _ (parkedPortG aut m len C))
        (EquivBA.base (Equiv.refl _))) ?_
      rw [← hsol_port]
      exact EquivBA.base (Equiv.refl _)
  | inr hpos =>
      refine StateRole.equivFold ?_
      have hstep : sol (m j)
          = .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
            (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
              (sol (nxtAt m len j)))
            (.test (aut.hlt (m j))) := by
        rw [hsol_int j hpos hj,
            show len - j = (len - (j + 1)) + 1 from by omega]
        by_cases hj1 : j + 1 = len
        · have : sol (nxtAt m len j) = parkedPortG aut m len C := by
            unfold nxtAt
            rw [if_pos hj1]
            exact hsol_port
          rw [this, show len - (j + 1) = 0 from by omega]
          rfl
        · have : sol (nxtAt m len j)
              = pChain aut m len (parkedPortG aut m len C) (len - (j + 1))
                (j + 1) := by
            unfold nxtAt
            rw [if_neg hj1]
            exact hsol_int (j + 1) (by omega) (by omega)
          rw [this]
          rfl
      rw [hstep, eqRHS_foldTL]
      refine EquivBA.trans ?_ (EquivBA.symm
        (multi_gather sol (aut.hlt (m j)) (nxtAt m len j) (aut.trans (m j))))
      rw [gOthers_nil_of_all (nxtAt m len j) (aut.trans (m j))
        (hint_arms j hpos hj)]
      exact EquivBA.base (Equiv.refl _)

#print axioms pChain_split_gated
#print axioms parked_cycle_roles_gated

/-! ## CORRECTION (iteration 174): the gated exit test is FORCED

    Iteration 173 shipped `parked_cycle_roles_gated` and described it as
    admitting NON-SUBSET interior halts.  That description is wrong, and
    the two theorems below are the proof rather than an argument.

    `hexcl` and `hport` together PIN `C` to `¬G ∧ hlt (m 0)`: there is no
    freedom in the "arbitrary" exit test at all.  Consequently `himp`
    still forces `hlt (m j) ⟹ hlt (m 0)`, exactly as the ungated theorem
    did.  Non-subset halts are NOT covered.

    What the gated theorem actually drops is the ORIGINAL `hexcl`, which
    required the PORT's own halt to exclude the port's step guard.  Under
    the gated form the port halt may overlap its step guard freely; only
    its restriction to `¬G` is used.  That is a real generalization, and a
    much smaller one than was claimed.

    Why the larger claim could not have been true, from the literature:
    Kosaraju's theorem says a flowchart is reducible to a structured
    program WITHOUT auxiliary variables iff it contains no loop with two
    distinct exits.  GKAT has no auxiliary variables.  A cycle with two
    incomparable halts is precisely a loop with two distinct exits, so no
    amount of massaging a SINGLE `wh` can express it — the ceiling is a
    theorem, not a shortfall in the parking algebra.  Coverage for that
    shape has to come from unrolling or state duplication, which changes
    the automaton, not from a better role theorem. -/

/-- **THE GATED EXIT TEST IS FORCED.**  `C` is not a free parameter: the
    exclusion and agreement hypotheses pin it to `¬G ∧ h₀`. -/
theorem gated_exit_forced {G C h0 : BExp T}
    (hexcl : GuardImplies C (.not G))
    (hport : ∀ (Y : Type) (W : T → Y → Bool) (y : Y),
      bval W (.and (.not G) h0) y = bval W (.and (.not G) C) y) :
    ∀ (Y : Type) (W : T → Y → Bool) (y : Y),
      bval W C y = bval W (.and (.not G) h0) y := by
  intro Y W y
  have hp : ((!bval W G y) && bval W h0 y)
      = ((!bval W G y) && bval W C y) := hport Y W y
  have hx : bval W C y = true → (!bval W G y) = true := hexcl Y W y
  show bval W C y = ((!bval W G y) && bval W h0 y)
  revert hp hx
  cases bval W G y <;> cases bval W h0 y <;> cases bval W C y <;>
    intro hp hx <;>
      first
        | rfl
        | exact Bool.noConfusion hp
        | exact Bool.noConfusion (hx rfl)

/-- **SO THE SUBSET CONDITION SURVIVES.**  Under the gated hypotheses the
    interior halts are still below the port's halt.  Iteration 173's claim
    that non-subset halts fall is retracted by this theorem. -/
theorem gated_himp_subset {G C h0 hj : BExp T}
    (hexcl : GuardImplies C (.not G))
    (hport : ∀ (Y : Type) (W : T → Y → Bool) (y : Y),
      bval W (.and (.not G) h0) y = bval W (.and (.not G) C) y)
    (himp : GuardImplies hj C) :
    GuardImplies hj h0 := by
  intro Y W y hy
  have h1 := himp Y W y hy
  have h2 := gated_exit_forced hexcl hport Y W y
  rw [h1] at h2
  have h2' : true = ((!bval W G y) && bval W h0 y) := h2
  revert h2'
  cases bval W G y <;> cases bval W h0 y <;> intro h2' <;>
    first | rfl | exact Bool.noConfusion h2'

#print axioms gated_exit_forced
#print axioms gated_himp_subset


/-! ## THE CHORDED CYCLE: a lap with one short-circuit back to the port

    Iteration 175 dumped the 15 open SCCs; 176 showed all 15 are
    T1/T2-reducible.  Reading their edge sets, THIRTEEN OF THE FIFTEEN are
    one shape, in six variants:

        a cycle through every member, plus ONE extra arm from one interior
        position straight back to the port.

    Concretely the modal instance (6 of 15) is `0→1, 1→0, 1→2, 2→0` with
    the port halting: a long lap `0→1→2→0` and a chord `1→0` short-circuiting
    it.  The others are the same with longer laps (`0→1→3→2→0`, `0→4→3→1→2→0`)
    or the brancher deeper along the lap.

    The algebra is the parked cycle's, with one extra alternative at the
    chord position.  The chord arm ends at the port, so it is already
    `something ; sol (m 0)`; `s2` turns the dead fallback into
    `0 ; sol (m 0)` and `u5` factors the port solution out of BOTH
    alternatives, exactly as it does out of a plain chain.  Everything
    downstream — `park_absorb` on the halt arms, the `salomaaE` close at
    the port — is unchanged.

    So the chorded stratum costs one constructor case in the chain, one
    case in the split, and `double_gather` in place of `multi_gather` at
    the chord position. -/

open Classical in
/-- The chorded chain: the parked chain, with position `c` carrying one
    extra arm straight back to the port. -/
noncomputable def cChain (aut : GAut S A T) (m : Nat → S) (len c : Nat)
    (term : Exp A T) : Nat → Nat → Exp A T
  | 0, _ => term
  | k + 1, j =>
      if j = c then
        .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (cChain aut m len c term k (j + 1)))
          (.ite (gGuard (m 0) (gOthers (nxtAt m len j) (aut.trans (m j))))
            (.seq (gBody (m 0) (gOthers (nxtAt m len j) (aut.trans (m j))))
              term)
            (.test (aut.hlt (m j))))
      else
        .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (cChain aut m len c term k (j + 1)))
          (.test (aut.hlt (m j)))

/-- The unfolding equation for `cChain`, with the position test intact.
    `cChain` does not reduce under `whnf` because `j = c` is undecided for
    variable `j`, so every proof rewrites with this rather than `show`. -/
theorem cChain_succ (aut : GAut S A T) (m : Nat → S) (len c : Nat)
    (term : Exp A T) (k j : Nat) :
    cChain aut m len c term (k + 1) j =
      (if j = c then
        .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (cChain aut m len c term k (j + 1)))
          (.ite (gGuard (m 0) (gOthers (nxtAt m len j) (aut.trans (m j))))
            (.seq (gBody (m 0) (gOthers (nxtAt m len j) (aut.trans (m j))))
              term)
            (.test (aut.hlt (m j))))
      else
        .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
          (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
            (cChain aut m len c term k (j + 1)))
          (.test (aut.hlt (m j)))) := rfl

open Classical in
/-- The chorded port solution: loop the whole chorded chain, exit on the
    port halt. -/
noncomputable def cPortE (aut : GAut S A T) (m : Nat → S) (len c : Nat) :
    Exp A T :=
  .seq (.wh (gGuard (m 1) (aut.trans (m 0)))
      (.seq (gBody (m 1) (aut.trans (m 0)))
        (cChain aut m len c (.test .one) (len - 1) 1)))
    (.test (aut.hlt (m 0)))

/-- **THE CHORDED SPLIT**: the port solution right-distributes out of the
    chorded chain.  `u5` on the step arm as before, `u5` again on the
    chord arm, `park_absorb` on every halt arm. -/
theorem cChain_split (aut : GAut S A T) (m : Nat → S) (len c : Nat)
    (himp : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hexcl : GuardImplies (aut.hlt (m 0))
      (.not (gGuard (m 1) (aut.trans (m 0))))) :
    ∀ k j, 1 ≤ j → j + k ≤ len →
      EquivBA (cChain aut m len c (cPortE aut m len c) k j)
        (.seq (cChain aut m len c (.test .one) k j)
          (cPortE aut m len c)) := by
  intro k
  induction k with
  | zero =>
      intro j _ _
      exact EquivBA.symm (EquivBA.base (Equiv.s4 (cPortE aut m len c)))
  | succ k ih =>
      intro j hj hle
      rw [cChain_succ, cChain_succ]
      by_cases hjc : j = c
      · rw [if_pos hjc, if_pos hjc]
        refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
          (EquivBA.base (Equiv.u5 _ _ _ (cPortE aut m len c)))
        · refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (ih (j + 1) (by omega) (by omega))) ?_
          exact seq_assoc' _ _ (cPortE aut m len c)
        · refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
            (EquivBA.base (Equiv.u5 _ _ _ (cPortE aut m len c)))
          · exact EquivBA.seq_c
              (EquivBA.symm (seq_one
                (gBody (m 0) (gOthers (nxtAt m len j) (aut.trans (m j))))))
              (EquivBA.base (Equiv.refl _))
          · exact park_absorb _ (himp j hj (by omega)) hexcl
      · rw [if_neg hjc, if_neg hjc]
        refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
          (EquivBA.base (Equiv.u5 _ _ _ (cPortE aut m len c)))
        · refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (ih (j + 1) (by omega) (by omega))) ?_
          exact seq_assoc' _ _ (cPortE aut m len c)
        · exact park_absorb _ (himp j hj (by omega)) hexcl

open Classical in
/-- **THE CHORDED CYCLE THEOREM.**  A simple cycle through every member,
    with ONE interior position carrying an extra arm straight back to the
    port, is fully role-covered — the port a `salomaaE` state whose body
    is the chorded chain, interiors `equivFold`s, the chord position an
    `equivFold` gathered by `double_gather`.

    This is the shape thirteen of the fifteen measured open SCCs have. -/
theorem chorded_cycle_roles (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len c : Nat) (hlen : 2 ≤ len)
    (hc1 : 1 ≤ c) (hc2 : c + 1 < len)
    (hsol_int : ∀ j, 1 ≤ j → j < len →
      sol (m j) = cChain aut m len c (cPortE aut m len c) (len - j) j)
    (hsol_port : sol (m 0) = cPortE aut m len c)
    (hint_arms : ∀ j, 1 ≤ j → j < len → j ≠ c → ∀ e ∈ aut.trans (m j),
      e.2.2 = nxtAt m len j)
    (hchord_arms : ∀ e ∈ gOthers (nxtAt m len c) (aut.trans (m c)),
      e.2.2 = m 0)
    (hport_arms : ∀ e ∈ aut.trans (m 0), e.2.2 = m 1)
    (himp : ∀ j, 1 ≤ j → j < len →
      GuardImplies (aut.hlt (m j)) (aut.hlt (m 0)))
    (hexcl : GuardImplies (aut.hlt (m 0))
      (.not (gGuard (m 1) (aut.trans (m 0))))) :
    ∀ j, j < len → StateRole aut sol (m j) := by
  intro j hj
  cases Nat.eq_zero_or_pos j with
  | inl hzero =>
      subst hzero
      refine StateRole.salomaaE (gGuard (m 1) (aut.trans (m 0)))
        (.seq (gBody (m 1) (aut.trans (m 0)))
          (cChain aut m len c (.test .one) (len - 1) 1))
        (.test (aut.hlt (m 0))) hsol_port ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (multi_gather sol (aut.hlt (m 0)) (m 1)
        (aut.trans (m 0))) ?_
      rw [gOthers_nil_of_all (m 1) (aut.trans (m 0)) hport_arms,
          hsol_int 1 (Nat.le_refl 1) (by omega)]
      refine EquivBA.trans (EquivBA.ite_c
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (cChain_split aut m len c himp hexcl (len - 1) 1
            (Nat.le_refl 1) (by omega)))
        (EquivBA.base (Equiv.refl _))) ?_
      refine EquivBA.trans (EquivBA.ite_c
        (seq_assoc' _ _ (cPortE aut m len c))
        (EquivBA.base (Equiv.refl _))) ?_
      rw [← hsol_port]
      exact EquivBA.base (Equiv.refl _)
  | inr hpos =>
      refine StateRole.equivFold ?_
      by_cases hjc : j = c
      · -- the chord position
        have hnx : nxtAt m len j = m (j + 1) := by
          unfold nxtAt
          rw [if_neg (show ¬ (j + 1 = len) by omega)]
        have hstep : sol (m j)
            = .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
              (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
                (sol (nxtAt m len j)))
              (.ite (gGuard (m 0) (gOthers (nxtAt m len j) (aut.trans (m j))))
                (.seq (gBody (m 0)
                  (gOthers (nxtAt m len j) (aut.trans (m j)))) (sol (m 0)))
                (.test (aut.hlt (m j)))) := by
          rw [hsol_int j hpos hj,
              show len - j = (len - (j + 1)) + 1 from by omega,
              cChain_succ, if_pos hjc, hnx, hsol_port,
              hsol_int (j + 1) (by omega) (by omega)]
        rw [hstep, eqRHS_foldTL]
        refine EquivBA.trans ?_ (EquivBA.symm
          (double_gather sol (aut.hlt (m j)) (nxtAt m len j) (m 0)
            (aut.trans (m j))))
        have hchord' : ∀ e ∈ gOthers (nxtAt m len j) (aut.trans (m j)),
            e.2.2 = m 0 := by rw [hjc]; exact hchord_arms
        rw [gOthers_nil_of_all (m 0)
          (gOthers (nxtAt m len j) (aut.trans (m j))) hchord']
        exact EquivBA.base (Equiv.refl _)
      · -- an ordinary chain position
        have hstep : sol (m j)
            = .ite (gGuard (nxtAt m len j) (aut.trans (m j)))
              (.seq (gBody (nxtAt m len j) (aut.trans (m j)))
                (sol (nxtAt m len j)))
              (.test (aut.hlt (m j))) := by
          rw [hsol_int j hpos hj,
              show len - j = (len - (j + 1)) + 1 from by omega,
              cChain_succ, if_neg hjc]
          by_cases hj1 : j + 1 = len
          · have hnx : sol (nxtAt m len j) = cPortE aut m len c := by
              unfold nxtAt
              rw [if_pos hj1]
              exact hsol_port
            rw [hnx, show len - (j + 1) = 0 from by omega]
            rfl
          · have hnx : sol (nxtAt m len j)
                = cChain aut m len c (cPortE aut m len c) (len - (j + 1))
                  (j + 1) := by
              unfold nxtAt
              rw [if_neg hj1]
              exact hsol_int (j + 1) (by omega) (by omega)
            rw [hnx]
        rw [hstep, eqRHS_foldTL]
        refine EquivBA.trans ?_ (EquivBA.symm
          (multi_gather sol (aut.hlt (m j)) (nxtAt m len j) (aut.trans (m j))))
        rw [gOthers_nil_of_all (nxtAt m len j) (aut.trans (m j))
          (hint_arms j hpos hj hjc)]
        exact EquivBA.base (Equiv.refl _)

#print axioms cChain_split
#print axioms chorded_cycle_roles

/-! ## The chorded assembly

    177 proved the chorded cycle theorem CYCLE-LOCALLY: closed forms
    supplied, roles derived.  This is the other half — the solution
    DEFINED by recursion, so the stratum is usable by the engine rather
    than only stated.

    One thing makes this assembly much lighter than the walked one.  A
    chorded cycle's port arms all re-enter the cycle and its interiors'
    arms all stay in it, so **`cPortE` and `cChain` mention no `sol` at
    all** — the whole SCC's solution is closed in `aut, m, len, c`.  The
    recursion is therefore needed only at BASE states, and the cycle
    branch of the fixpoint equation needs no congruence lemma: it is
    already syntactically what it should be.

    That is the pattern to expect whenever a stratum's cycles are
    self-contained.  The walked assembly needs `walkedExitPortE_congr` and
    `wChain_term_congr` precisely because its port folds `sol` over
    descending arms; a chorded cycle has none. -/

open Classical in
/-- The chorded assembly solution: gathered Salomaa closed forms at base
    states, chorded chain/port closed forms on designated cycles. -/
noncomputable def asmSolC (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat × Nat)) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    match cy s with
    | none =>
        .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
            (aut.hlt s) (gOthers s (aut.trans s)))
    | some (len, m, c, i) =>
        if i = 0 then cPortE aut m len c
        else cChain aut m len c (cPortE aut m len c) (len - i) i)

open Classical in
theorem asmSolC_eq (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat × Nat)) (s : S) :
    asmSolC aut rank cy s
      = (match cy s with
        | none =>
            .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (fun t =>
                  if _ : rank t < rank s then asmSolC aut rank cy t
                  else .test .zero)
                (aut.hlt s) (gOthers s (aut.trans s)))
        | some (len, m, c, i) =>
            if i = 0 then cPortE aut m len c
            else cChain aut m len c (cPortE aut m len c) (len - i) i) := by
  unfold asmSolC
  rw [WellFounded.fix_eq]

open Classical in
/-- **THE CHORDED ASSEMBLY THEOREM**: an automaton whose every state is
    BASE (arms self or strictly descending) or a member of a designated
    CHORDED cycle — a lap through every member plus one interior arm
    straight back to the port — is fully role-covered.

    This is the shape thirteen of the fifteen measured open SCCs have. -/
theorem chorded_assembly_roles (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat × Nat))
    (hcy : ∀ s len m c i, cy s = some (len, m, c, i) →
      i < len ∧ 2 ≤ len ∧ 1 ≤ c ∧ c + 1 < len ∧ m i = s ∧
      (∀ j, j < len → cy (m j) = some (len, m, c, j)) ∧
      (∀ j, 1 ≤ j → j < len → j ≠ c →
        ∀ e ∈ aut.trans (m j), e.2.2 = nxtAt m len j) ∧
      (∀ e ∈ gOthers (nxtAt m len c) (aut.trans (m c)), e.2.2 = m 0) ∧
      (∀ e ∈ aut.trans (m 0), e.2.2 = m 1) ∧
      (∀ j, 1 ≤ j → j < len →
        GuardImplies (aut.hlt (m j)) (aut.hlt (m 0))) ∧
      GuardImplies (aut.hlt (m 0))
        (.not (gGuard (m 1) (aut.trans (m 0)))))
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
      refine self_gather_role aut (asmSolC aut rank cy) s ?_
      rw [asmSolC_eq, hcys]
      exact congrArg _ (foldTL_congr' (aut.hlt s) (gOthers s (aut.trans s))
        (fun e he => dif_pos (hlow e he)))
  | some q =>
      obtain ⟨len, m, c, i⟩ := q
      obtain ⟨hilt, hlen, hc1, hc2, hmi, hcoh, hint_arms, hchord_arms,
        hport_arms, himp, hexcl⟩ := hcy s len m c i hcys
      have hcycsol : ∀ j, j < len →
          asmSolC aut rank cy (m j)
            = (if j = 0 then cPortE aut m len c
               else cChain aut m len c (cPortE aut m len c) (len - j) j) := by
        intro j hj
        rw [asmSolC_eq, hcoh j hj]
      have hsol_port : asmSolC aut rank cy (m 0) = cPortE aut m len c := by
        rw [hcycsol 0 (by omega), if_pos rfl]
      have hsol_int : ∀ j, 1 ≤ j → j < len →
          asmSolC aut rank cy (m j)
            = cChain aut m len c (cPortE aut m len c) (len - j) j := by
        intro j hj1 hj
        rw [hcycsol j hj, if_neg (by omega : ¬ j = 0)]
      have := chorded_cycle_roles aut (asmSolC aut rank cy) m len c hlen
        hc1 hc2 hsol_int hsol_port hint_arms hchord_arms hport_arms himp hexcl
        i hilt
      rw [hmi] at this
      exact this

#print axioms asmSolC_eq
#print axioms chorded_assembly_roles

/-! ## THE NESTED-CHORD STRATUM: two `w3` applications, inner then outer

    Built to the derivation in `span-search/NESTED-CHORD-PLAN.md`, which
    was written and checked before any Lean.  Shape, from iteration 181's
    classification of the measured residue:

        lap   m 0 → m 1 → … → m (len-1) → m 0
        port  m 0 is the UNIQUE exit state; interiors are silent
        chord one extra arm at position `len-1` back to position `1`

    Interiors being silent is what makes the chain factor: every interior
    fallback is `test 0`, which `s2` rewrites to `0 ; X`, so `u5` pulls the
    continuation out of the whole walk.  `nWalk_split` is therefore
    UNCONDITIONAL — no `park_absorb`, no halt hypotheses, no length bound.

    **The rotation is the trick.**  The inner loop heads at the BRANCHER,
    not at the chord's target.  A `wh` tests its guard at the top, and the
    chord guard is the test available at the brancher's atom; at the
    chord's target the continue condition is not a test at all, it is a
    test several actions later.  Rotating makes the inner equation a
    Salomaa equation and `w3` closes it. -/

open Classical in
/-- The straight walk from position `j` over `k` steps: step onward, or
    fail.  Interiors are silent, so the fallback is literally `0`. -/
noncomputable def nWalk (aut : GAut S A T) (m : Nat → S)
    (term : Exp A T) : Nat → Nat → Exp A T
  | 0, _ => term
  | k + 1, j =>
      .ite (gGuard (m (j + 1)) (aut.trans (m j)))
        (.seq (gBody (m (j + 1)) (aut.trans (m j)))
          (nWalk aut m term k (j + 1)))
        (.test .zero)

/-- **THE WALK SPLIT**, unconditional: a dead fallback is `0 ; X` by `s2`,
    so `u5` factors the continuation out of the entire walk. -/
theorem nWalk_split (aut : GAut S A T) (m : Nat → S) (X : Exp A T) :
    ∀ k j, EquivBA (nWalk aut m X k j)
      (.seq (nWalk aut m (.test .one) k j) X) := by
  intro k
  induction k with
  | zero => intro j; exact EquivBA.symm (EquivBA.base (Equiv.s4 X))
  | succ k ih =>
      intro j
      show EquivBA
        (.ite (gGuard (m (j + 1)) (aut.trans (m j)))
          (.seq (gBody (m (j + 1)) (aut.trans (m j)))
            (nWalk aut m X k (j + 1)))
          (.test .zero))
        (.seq (.ite (gGuard (m (j + 1)) (aut.trans (m j)))
          (.seq (gBody (m (j + 1)) (aut.trans (m j)))
            (nWalk aut m (.test .one) k (j + 1)))
          (.test .zero)) X)
      refine EquivBA.trans (EquivBA.ite_c ?_ ?_)
        (EquivBA.base (Equiv.u5 _ _ _ X))
      · exact EquivBA.trans
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (ih (j + 1)))
          (seq_assoc' _ _ X)
      · exact EquivBA.symm (EquivBA.base (Equiv.s2 X))

open Classical in
/-- The inner loop, headed AT THE BRANCHER: take the chord, walk back. -/
noncomputable def nInner (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    Exp A T :=
  .wh (gGuard (m 1) (aut.trans (m (len - 1))))
    (.seq (gBody (m 1) (aut.trans (m (len - 1))))
      (nWalk aut m (.test .one) (len - 2) 1))

open Classical in
/-- The brancher's exit dispatch, with the port solution already factored
    out: close the lap, or fail. -/
noncomputable def nTail (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    Exp A T :=
  .ite (gGuard (m 0) (gOthers (m 1) (aut.trans (m (len - 1)))))
    (gBody (m 0) (gOthers (m 1) (aut.trans (m (len - 1)))))
    (.test .zero)

open Classical in
/-- The outer loop: one lap is walk, inner loop, lap close. -/
noncomputable def nPortE (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    Exp A T :=
  .seq (.wh (gGuard (m 1) (aut.trans (m 0)))
      (.seq (gBody (m 1) (aut.trans (m 0)))
        (.seq (nWalk aut m (.test .one) (len - 2) 1)
          (.seq (nInner aut m len) (nTail aut m len)))))
    (.test (aut.hlt (m 0)))

open Classical in
/-- **THE NESTED-CHORD CYCLE THEOREM.**  A lap whose LAST position carries
    an extra arm back to position 1, with the port the unique exit state,
    is fully role-covered — the port and the brancher both `salomaaE`
    states, the interiors `equivFold`s of walk forms.

    Two `w3` applications, inner then outer.  No uniqueness axiom. -/
theorem nested_chord_roles (aut : GAut S A T) (sol : S → Exp A T)
    (m : Nat → S) (len : Nat) (hlen : 3 ≤ len)
    (hsol_port : sol (m 0) = nPortE aut m len)
    (hsol_last : sol (m (len - 1))
      = .seq (nInner aut m len) (.seq (nTail aut m len) (nPortE aut m len)))
    (hsol_int : ∀ j, 1 ≤ j → j + 1 < len →
      sol (m j) = nWalk aut m (sol (m (len - 1))) (len - 1 - j) j)
    (hport_arms : ∀ e ∈ aut.trans (m 0), e.2.2 = m 1)
    (hint_arms : ∀ j, 1 ≤ j → j + 1 < len →
      ∀ e ∈ aut.trans (m j), e.2.2 = m (j + 1))
    (hbr_arms : ∀ e ∈ gOthers (m 1) (aut.trans (m (len - 1))), e.2.2 = m 0)
    (hsilent : ∀ j, 1 ≤ j → j < len → GuardEmpty (aut.hlt (m j))) :
    ∀ j, j < len → StateRole aut sol (m j) := by
  -- the walk from position 1, with the brancher's solution as terminal
  have hwalk1 : EquivBA (sol (m 1))
      (.seq (nWalk aut m (.test .one) (len - 2) 1) (sol (m (len - 1)))) := by
    by_cases h2 : 1 + 1 < len
    · rw [hsol_int 1 (Nat.le_refl 1) h2,
        show len - 1 - 1 = len - 2 from by omega]
      exact nWalk_split aut m (sol (m (len - 1))) (len - 2) 1
    · have : len - 2 = 0 := by omega
      have h1 : m 1 = m (len - 1) := by
        rw [show len - 1 = 1 from by omega]
      rw [this, h1]
      exact EquivBA.symm (EquivBA.base (Equiv.s4 (sol (m (len - 1)))))
  intro j hj
  cases Nat.eq_zero_or_pos j with
  | inl hzero =>
      subst hzero
      refine StateRole.salomaaE (gGuard (m 1) (aut.trans (m 0)))
        (.seq (gBody (m 1) (aut.trans (m 0)))
          (.seq (nWalk aut m (.test .one) (len - 2) 1)
            (.seq (nInner aut m len) (nTail aut m len))))
        (.test (aut.hlt (m 0))) hsol_port ?_
      rw [eqRHS_foldTL]
      refine EquivBA.trans (multi_gather sol (aut.hlt (m 0)) (m 1)
        (aut.trans (m 0))) ?_
      rw [gOthers_nil_of_all (m 1) (aut.trans (m 0)) hport_arms]
      refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
      -- gBody ; sol (m 1)  ≡  (gBody ; (W ; (I ; Tl))) ; sol (m 0)
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        hwalk1) ?_
      rw [hsol_last, hsol_port]
      refine EquivBA.trans (seq_assoc' _ _ _) ?_
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (seq_assoc' _ _ _)) ?_
      refine EquivBA.trans (seq_assoc' _ _ _) ?_
      exact EquivBA.seq_c (EquivBA.symm (seq_assoc' _ _ _))
        (EquivBA.base (Equiv.refl _))
  | inr hpos =>
      by_cases hlast : j + 1 = len
      · -- the brancher
        have hjl : m j = m (len - 1) := by
          rw [show len - 1 = j from by omega]
        rw [hjl]
        refine StateRole.salomaaE (gGuard (m 1) (aut.trans (m (len - 1))))
          (.seq (gBody (m 1) (aut.trans (m (len - 1))))
            (nWalk aut m (.test .one) (len - 2) 1))
          (.seq (nTail aut m len) (nPortE aut m len)) hsol_last ?_
        rw [eqRHS_foldTL]
        refine EquivBA.trans (double_gather sol (aut.hlt (m (len - 1)))
          (m 1) (m 0) (aut.trans (m (len - 1)))) ?_
        rw [gOthers_nil_of_all (m 0)
          (gOthers (m 1) (aut.trans (m (len - 1)))) hbr_arms]
        refine EquivBA.ite_c ?_ ?_
        · -- gBody ; sol (m 1) ≡ (gBody ; W) ; sol (m (len-1))
          refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            hwalk1) ?_
          exact seq_assoc' _ _ (sol (m (len - 1)))
        · -- ite gn (bn ; sol (m 0)) (test hlt) ≡ nTail ; nPortE
          rw [hsol_port]
          refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
            (EquivBA.baTest (b := aut.hlt (m (len - 1))) (c := .zero)
              (fun X W x => hsilent (len - 1) (by omega) (by omega) X W x))) ?_
          refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
            (EquivBA.symm (EquivBA.base (Equiv.s2 (nPortE aut m len))))) ?_
          exact EquivBA.base (Equiv.u5 _ _ _ (nPortE aut m len))
      · -- an ordinary interior
        have hjl : j + 1 < len := by omega
        refine StateRole.equivFold ?_
        have hstep : sol (m j)
            = .ite (gGuard (m (j + 1)) (aut.trans (m j)))
              (.seq (gBody (m (j + 1)) (aut.trans (m j))) (sol (m (j + 1))))
              (.test .zero) := by
          rw [hsol_int j hpos hjl,
            show len - 1 - j = (len - 1 - (j + 1)) + 1 from by omega]
          by_cases hj1 : j + 1 + 1 = len
          · have hm : m (len - 1) = m (j + 1) := by
              rw [show len - 1 = j + 1 from by omega]
            rw [show len - 1 - (j + 1) = 0 from by omega, hm]
            rfl
          · rw [hsol_int (j + 1) (by omega) (by omega)]
            rfl
        rw [hstep, eqRHS_foldTL]
        refine EquivBA.trans ?_ (EquivBA.symm
          (multi_gather sol (aut.hlt (m j)) (m (j + 1)) (aut.trans (m j))))
        rw [gOthers_nil_of_all (m (j + 1)) (aut.trans (m j))
          (hint_arms j hpos hjl)]
        exact EquivBA.ite_c (EquivBA.base (Equiv.refl _))
          (EquivBA.symm (EquivBA.baTest (b := aut.hlt (m j)) (c := .zero)
            (fun X W x => hsilent j hpos hj X W x)))

#print axioms nWalk_split
#print axioms nested_chord_roles

open Classical in
/-- The brancher's closed solution, named so the assembly can use it. -/
noncomputable def nLastE (aut : GAut S A T) (m : Nat → S) (len : Nat) :
    Exp A T :=
  .seq (nInner aut m len) (.seq (nTail aut m len) (nPortE aut m len))

open Classical in
/-- The nested-chord assembly solution.  As with the chorded stratum the
    cycle's closed forms mention no `sol`, so the recursion is needed only
    at base states and the cycle branch needs no congruence lemma. -/
noncomputable def asmSolN (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    match cy s with
    | none =>
        .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
            (aut.hlt s) (gOthers s (aut.trans s)))
    | some (len, m, i) =>
        if i = 0 then nPortE aut m len
        else nWalk aut m (nLastE aut m len) (len - 1 - i) i)

open Classical in
theorem asmSolN_eq (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat)) (s : S) :
    asmSolN aut rank cy s
      = (match cy s with
        | none =>
            .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
              (foldTL (fun t =>
                  if _ : rank t < rank s then asmSolN aut rank cy t
                  else .test .zero)
                (aut.hlt s) (gOthers s (aut.trans s)))
        | some (len, m, i) =>
            if i = 0 then nPortE aut m len
            else nWalk aut m (nLastE aut m len) (len - 1 - i) i) := by
  unfold asmSolN
  rw [WellFounded.fix_eq]

open Classical in
/-- **THE NESTED-CHORD ASSEMBLY THEOREM**: an automaton whose every state
    is BASE (arms self or strictly descending) or a member of a designated
    nested-chord cycle is fully role-covered. -/
theorem nested_chord_assembly_roles (aut : GAut S A T) (rank : S → Nat)
    (cy : S → Option (Nat × (Nat → S) × Nat))
    (hcy : ∀ s len m i, cy s = some (len, m, i) →
      i < len ∧ 3 ≤ len ∧ m i = s ∧
      (∀ j, j < len → cy (m j) = some (len, m, j)) ∧
      (∀ e ∈ aut.trans (m 0), e.2.2 = m 1) ∧
      (∀ j, 1 ≤ j → j + 1 < len →
        ∀ e ∈ aut.trans (m j), e.2.2 = m (j + 1)) ∧
      (∀ e ∈ gOthers (m 1) (aut.trans (m (len - 1))), e.2.2 = m 0) ∧
      (∀ j, 1 ≤ j → j < len → GuardEmpty (aut.hlt (m j))))
    (hbase : ∀ s ∈ aut.states, cy s = none →
      ∀ e ∈ aut.trans s, e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨asmSolN aut rank cy, fun s hs => ?_⟩
  cases hcys : cy s with
  | none =>
      have hlow : ∀ e ∈ gOthers s (aut.trans s), rank e.2.2 < rank s := by
        intro e he
        obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
        rcases hbase s hs hcys e heL with h1 | h2
        · exact absurd h1 hne
        · exact h2
      refine self_gather_role aut (asmSolN aut rank cy) s ?_
      rw [asmSolN_eq, hcys]
      exact congrArg _ (foldTL_congr' (aut.hlt s) (gOthers s (aut.trans s))
        (fun e he => dif_pos (hlow e he)))
  | some q =>
      obtain ⟨len, m, i⟩ := q
      obtain ⟨hilt, hlen, hmi, hcoh, hport_arms, hint_arms, hbr_arms,
        hsilent⟩ := hcy s len m i hcys
      have hcycsol : ∀ j, j < len →
          asmSolN aut rank cy (m j)
            = (if j = 0 then nPortE aut m len
               else nWalk aut m (nLastE aut m len) (len - 1 - j) j) := by
        intro j hj
        rw [asmSolN_eq, hcoh j hj]
      have hsol_port : asmSolN aut rank cy (m 0) = nPortE aut m len := by
        rw [hcycsol 0 (by omega), if_pos rfl]
      have hsol_last : asmSolN aut rank cy (m (len - 1))
          = .seq (nInner aut m len)
              (.seq (nTail aut m len) (nPortE aut m len)) := by
        rw [hcycsol (len - 1) (by omega), if_neg (by omega : ¬ len - 1 = 0),
          show len - 1 - (len - 1) = 0 from by omega]
        rfl
      have hsol_int : ∀ j, 1 ≤ j → j + 1 < len →
          asmSolN aut rank cy (m j)
            = nWalk aut m (asmSolN aut rank cy (m (len - 1))) (len - 1 - j) j := by
        intro j hj1 hj
        rw [hcycsol j (by omega), if_neg (by omega : ¬ j = 0), hsol_last]
        rfl
      have := nested_chord_roles aut (asmSolN aut rank cy) m len hlen
        hsol_port hsol_last hsol_int hport_arms hint_arms hbr_arms hsilent
        i hilt
      rw [hmi] at this
      exact this

#print axioms asmSolN_eq
#print axioms nested_chord_assembly_roles

/-! ### EXIT ABSORPTION — the second move the resistant instances need

    Iteration 187 left five resistant instances that
    `gated_unknown_identification` cannot reach: a two-state SCC whose
    members differ at EVERY atom, giving a loop whose body has an EARLY
    EXIT into a continuation that does something else entirely.

    They are all solvable, and by one observation: **the escape branch is
    not a break.**  Its continuation terminates only at atoms where the
    loop guard ALREADY FAILS, so control returns to the loop head, the
    guard rejects, and the loop's own exit does the work — and the
    trailing test after the loop accepts exactly there.  So the branch can
    be INLINED IN THE BODY and no break is needed.

    Verified on the measured instance: with `X2 = wh (a0∨a1∨a2) p ; test a3`,

        X0 = wh (a0∨a1) (p ; ite a1 (p ; X2) p) ; test (a2∨a3)

    has exactly the automaton's language (8116 guarded strings up to eight
    actions, exact set equality), and all five resistant instances satisfy
    the two side conditions.

    Algebraically the move is `park_absorb` lifted from a test to an
    arbitrary continuation. -/

/-- **EXIT ABSORPTION.**  A continuation that terminates only inside a
    region `r` absorbs a following loop-and-test, provided `r` implies the
    trailing test and the trailing test excludes the loop guard.

    So a mid-body branch running `K` may be inlined into the body of
    `wh g B ; test c`: after `K` the loop is a no-op. -/
theorem exit_absorb {r c g : BExp T} {K B : Exp A T}
    (hK : EquivBA K (.seq K (.test r)))
    (himp : GuardImplies r c)
    (hexcl : GuardImplies c (.not g)) :
    EquivBA (.seq K (.seq (.wh g B) (.test c))) K := by
  refine EquivBA.trans (EquivBA.seq_c hK (EquivBA.base (Equiv.refl _))) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.s1 K (.test r) _)) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl K))
    (EquivBA.symm (park_absorb B himp hexcl))) ?_
  exact EquivBA.symm hK

#print axioms exit_absorb

end GkatCycle
