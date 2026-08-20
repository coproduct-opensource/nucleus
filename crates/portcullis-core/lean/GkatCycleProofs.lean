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

end GkatCycle
