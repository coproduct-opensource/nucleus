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

end GkatCycle
