import GkatRingSupportProofs

/-! # The Ring Theorem, reflected: walk plans as data

    Every ring certificate so far (GkatCertR1-R6, GkatK6R01-80, GkatMixPilot) is one
    instance of a single construction: a header whose loop guard is the union of its
    continue-guards, a walk of interior states whose factors dispatch between a
    self-loop, a step onward, and a (subset-)parked halt, and suffix-composed
    solutions.  This file states that construction ONCE, over plan data:

      ringPlan_solves : WellFormedRing P → SolvesBA (planAut P) (planSol P)

    An instance certificate then becomes a `RingPlan` literal plus a decidable
    well-formedness check — the reflection step.  This is Lemma 3 of the completeness
    chain at full (linear-walk) generality; the tree cases (Branch/Sub) and the
    plan-existence lemma build on it.

    v1 scope: linear walks; interior halts semantically zero except the final entry,
    whose halt guard may be any SUBSET of the header's exit guard (the mixed-halt
    frontier's subset parking). -/

namespace GkatRingPlan

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatRingSupport GkatGuardedAlgebra
open GkatResidue

variable {A T : Type}

/-- One interior walk state: a self-loop on `selfG`, a step onward on `stepG`, a halt
    on `hltG`, everything else rejecting.  A state without a self-loop takes
    `selfG = .zero` (the dead arm is harmless and keeps the induction uniform). -/
structure RingEntry (A T : Type) where
  selfG : BExp T
  selfA : A
  stepG : BExp T
  stepA : A
  hltG : BExp T

/-- A ring plan: the header's self/step guards and exit guard, and the interior walk
    in order from the header's successor back around to the header. -/
structure RingPlan (A T : Type) where
  hSelfG : BExp T
  hSelfA : A
  hStepG : BExp T
  hStepA : A
  exitG : BExp T
  entries : List (RingEntry A T)

/-- The raw factor an interior entry contributes to the header's loop body. -/
def entryRaw (e : RingEntry A T) : Exp A T :=
  .seq (.wh e.selfG (.act e.selfA)) (.ite e.stepG (.act e.stepA) (.test e.hltG))

/-- The body's walk chain (nonempty list of factors, right-nested). -/
def rawChain : RingEntry A T → List (RingEntry A T) → Exp A T
  | e, [] => entryRaw e
  | e, f :: r => .seq (entryRaw e) (rawChain f r)

/-- The header's loop body: self-dispatch first, else the step action and the walk. -/
def planBody (P : RingPlan A T) : Exp A T :=
  match P.entries with
  | [] => .ite P.hSelfG (.act P.hSelfA) (.act P.hStepA)
  | e :: r => .ite P.hSelfG (.act P.hSelfA) (.seq (.act P.hStepA) (rawChain e r))

/-- The header's solution. -/
def headerSol (P : RingPlan A T) : Exp A T :=
  .seq (.wh (.or P.hStepG P.hSelfG) (planBody P)) (.test P.exitG)

/-- An interior entry's solution, given the next state's. -/
def entrySol (e : RingEntry A T) (next : Exp A T) : Exp A T :=
  .seq (.wh e.selfG (.act e.selfA))
    (.seq (.ite e.stepG (.act e.stepA) (.test e.hltG)) next)

/-- The suffix solution from a list of remaining entries down to the header. -/
def suffixSol (es : List (RingEntry A T)) (solH : Exp A T) : Exp A T :=
  match es with
  | [] => solH
  | e :: r => entrySol e (suffixSol r solH)

/-- **The spine lemma**: appending the header solution to a raw chain yields the
    suffix solution — the generalized `s1`-push every instance proof performed. -/
theorem rawChain_spine (e : RingEntry A T) (es : List (RingEntry A T))
    (solH : Exp A T) :
    EquivBA (.seq (rawChain e es) solH) (suffixSol (e :: es) solH) := by
  induction es generalizing e with
  | nil =>
      exact EquivBA.base
        (Equiv.s1 (.wh e.selfG (.act e.selfA))
          (.ite e.stepG (.act e.stepA) (.test e.hltG)) solH)
  | cons f r ih =>
      refine EquivBA.trans
        (EquivBA.base (Equiv.s1 (entryRaw e) (rawChain f r) solH)) ?_
      refine EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl (entryRaw e))) (ih f)) ?_
      exact EquivBA.base
        (Equiv.s1 (.wh e.selfG (.act e.selfA))
          (.ite e.stepG (.act e.stepA) (.test e.hltG)) (suffixSol (f :: r) solH))

/-- Semantic guard emptiness. -/
def GuardEmpty (b : BExp T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = false

/-- Semantic disjointness. -/
def GuardDisjoint (b c : BExp T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X), (bval W b x && bval W c x) = false

/-- A semantically-empty test absorbs any continuation. -/
theorem test_empty_absorb {b : BExp T} (h : GuardEmpty b) (q : Exp A T) :
    EquivBA (.seq (.test b) q) (.test b) := by
  refine EquivBA.trans (EquivBA.seq_c
    (EquivBA.baTest (b := b) (c := .zero) (fun X W x => h X W x))
    (EquivBA.base (Equiv.refl q))) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.s2 q)) ?_
  exact EquivBA.baTest (fun X W x => (h X W x).symm)

/-- Well-formedness of a linear ring plan.  Everything is a `bval`-level fact, so
    instances discharge each field by four-way (or 2^|T|-way) case analysis. -/
structure WellFormedRing (P : RingPlan A T) : Prop where
  /-- The walk is nonempty (a pure self-loop header is a plain level, not a ring). -/
  nonempty : P.entries ≠ []
  /-- Header continue-guards are disjoint (determinism at the header). -/
  hdr_disj : GuardDisjoint P.hStepG P.hSelfG
  /-- Interior halts are semantically empty (parks only at the final entry). -/
  interior_dead : ∀ e ∈ P.entries.dropLast, GuardEmpty e.hltG
  /-- The final halt is off the header's loop guard... -/
  last_off : ∀ e ∈ P.entries.getLast?, GuardImplies e.hltG (.not (.or P.hStepG P.hSelfG))
  /-- ...and a subset of the exit guard. -/
  last_sub : ∀ e ∈ P.entries.getLast?,
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      (bval W e.hltG x && bval W P.exitG x) = bval W e.hltG x

/-- **Halt absorption along the suffix**: a (well-formed) entry's halt test absorbs
    the whole remaining suffix solution.  Interior halts are empty; the final halt
    subset-parks into the header. -/
theorem hlt_absorb (P : RingPlan A T) (hwf : WellFormedRing P)
    (e : RingEntry A T) (pre : List (RingEntry A T)) (rest : List (RingEntry A T))
    (hsplit : P.entries = pre ++ e :: rest) :
    EquivBA (.seq (.test e.hltG) (suffixSol rest (headerSol P))) (.test e.hltG) := by
  cases rest with
  | cons f r =>
      -- interior entry: its halt guard is semantically empty
      have hmem : e ∈ P.entries.dropLast := by
        have hne : e :: f :: r ≠ [] := by simp
        rw [hsplit, List.dropLast_append_of_ne_nil hne]
        exact List.mem_append.mpr (Or.inr (by simp))
      exact test_empty_absorb (hwf.interior_dead e hmem) _
  | nil =>
      -- final entry: subset parking into the header
      have hlast : P.entries.getLast? = some e := by
        rw [hsplit]
        simp [List.getLast?_append]
      have hmem : e ∈ P.entries.getLast? := by
        rw [hlast]; rfl
      have h1 := hwf.last_off e hmem
      have h2 := hwf.last_sub e hmem
      exact test_header_absorb_sub e.hltG P.exitG (.or P.hStepG P.hSelfG)
        (planBody P) h1 h2

/-- **The interior obligation**, uniform across every entry: salomaa unroll, U5, and
    the halt absorption.  Note: no guard disjointness is needed for derivability. -/
theorem entry_solves (e : RingEntry A T) (next : Exp A T)
    (habs : EquivBA (.seq (.test e.hltG) next) (.test e.hltG)) :
    EquivBA (entrySol e next)
      (.ite e.selfG (.seq (.act e.selfA) (entrySol e next))
        (.ite e.stepG (.seq (.act e.stepA) next) (.test e.hltG))) :=
  EquivBA.trans
    (EquivBA.base (salomaa_solution_exists e.selfG (.act e.selfA)
      (.seq (.ite e.stepG (.act e.stepA) (.test e.hltG)) next)))
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
      (EquivBA.trans (EquivBA.symm (EquivBA.base
        (Equiv.u5 e.stepG (.act e.stepA) (.test e.hltG) next)))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) habs)))

/-- Disjointness gives one-directional implication into the negation. -/
theorem GuardDisjoint.implies_not {b c : BExp T} (h : GuardDisjoint b c) :
    GuardImplies b (.not c) := by
  intro X W x hb
  have := h X W x
  rw [hb] at this
  show (!(bval W c x)) = true
  cases hc : bval W c x
  · rfl
  · rw [hc] at this; exact absurd this (by simp)

/-- **The header obligation**: salomaa unroll, guard split, and the two under-guard
    branch selections. -/
theorem header_solves (P : RingPlan A T) (hdisj : GuardDisjoint P.hStepG P.hSelfG)
    (e0 : RingEntry A T) (r : List (RingEntry A T)) (hent : P.entries = e0 :: r) :
    EquivBA (headerSol P)
      (.ite P.hStepG (.seq (.act P.hStepA) (suffixSol P.entries (headerSol P)))
        (.ite P.hSelfG (.seq (.act P.hSelfA) (headerSol P)) (.test P.exitG))) := by
  have hbody : planBody P
      = .ite P.hSelfG (.act P.hSelfA) (.seq (.act P.hStepA) (rawChain e0 r)) := by
    unfold planBody
    rw [hent]
  refine EquivBA.trans (EquivBA.base (salomaa_solution_exists
    (.or P.hStepG P.hSelfG) (planBody P) (.test P.exitG))) ?_
  refine EquivBA.trans (ite_or_split P.hStepG P.hSelfG
    (.seq (planBody P) (headerSol P)) (.test P.exitG)) ?_
  have h_step : EquivBA (.seq (.test P.hStepG) (.seq (planBody P) (headerSol P)))
      (.seq (.test P.hStepG)
        (.seq (.act P.hStepA) (suffixSol P.entries (headerSol P)))) := by
    have hsel : EquivBA (.seq (.test P.hStepG) (planBody P))
        (.seq (.test P.hStepG) (.seq (.act P.hStepA) (rawChain e0 r))) := by
      rw [hbody]
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.base (Equiv.u2 P.hSelfG (.act P.hSelfA)
          (.seq (.act P.hStepA) (rawChain e0 r))))) ?_
      exact test_seq_ite_of_implies _ _ hdisj.implies_not
    refine EquivBA.trans (seq_under_guard (headerSol P) hsel) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act P.hStepA)
      (rawChain e0 r) (headerSol P))) ?_
    rw [hent]
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (rawChain_spine e0 r (headerSol P))
  have h_self : EquivBA (.seq (.test P.hSelfG) (.seq (planBody P) (headerSol P)))
      (.seq (.test P.hSelfG) (.seq (.act P.hSelfA) (headerSol P))) := by
    have hsel : EquivBA (.seq (.test P.hSelfG) (planBody P))
        (.seq (.test P.hSelfG) (.act P.hSelfA)) := by
      rw [hbody]
      exact test_seq_ite_of_implies _ _ (himp_self P.hSelfG)
    exact seq_under_guard (headerSol P) hsel
  exact EquivBA.trans (ite_congr_under_guard h_step)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ite_congr_under_guard h_self))

/-- The plan's automaton: state 0 is the header; state `i+1` is walk entry `i`. -/
def planAut (P : RingPlan A T) : GAut Nat A T where
  states := List.range (P.entries.length + 1)
  hlt := fun i =>
    if i = 0 then P.exitG else
      match P.entries[i - 1]? with
      | some e => e.hltG
      | none => .zero
  trans := fun i =>
    if i = 0 then [(P.hStepG, P.hStepA, 1), (P.hSelfG, P.hSelfA, 0)]
    else
      match P.entries[i - 1]? with
      | some e => [(e.selfG, e.selfA, i),
                   (e.stepG, e.stepA, if i = P.entries.length then 0 else i + 1)]
      | none => []
  start := 0

/-- The plan's solutions. -/
def planSol (P : RingPlan A T) : Nat → Exp A T := fun i =>
  if i = 0 then headerSol P else suffixSol (P.entries.drop (i - 1)) (headerSol P)

/-- **THE RING THEOREM (linear walks).**  A well-formed ring plan's solutions solve
    its automaton in the finite axioms — no UA. -/
theorem ringPlan_solves (P : RingPlan A T) (hwf : WellFormedRing P) :
    SolvesBA (planAut P) (planSol P) := by
  intro s hs
  have hslt : s < P.entries.length + 1 := List.mem_range.mp hs
  cases s with
  | zero =>
      obtain ⟨e0, r, hent⟩ : ∃ e0 r, P.entries = e0 :: r := by
        cases hE : P.entries with
        | nil => exact absurd hE hwf.nonempty
        | cons a b => exact ⟨a, b, rfl⟩
      have h := header_solves P hwf.hdr_disj e0 r hent
      show EquivBA (planSol P 0) _
      have hs1 : planSol P 1 = suffixSol P.entries (headerSol P) := by
        show suffixSol (P.entries.drop 0) (headerSol P) = _
        rfl
      exact h
  | succ i =>
      have hi : i < P.entries.length := Nat.lt_of_succ_lt_succ hslt
      have hget : P.entries[i]? = some (P.entries[i]) :=
        List.getElem?_eq_getElem hi
      have hdrop : P.entries.drop i = P.entries[i] :: P.entries.drop (i + 1) :=
        List.drop_eq_getElem_cons hi
      -- the halt-absorption hypothesis for this entry
      have hsplit : P.entries = P.entries.take i ++ P.entries[i] :: P.entries.drop (i + 1) := by
        rw [← hdrop]
        exact (List.take_append_drop i P.entries).symm
      have habs := hlt_absorb P hwf (P.entries[i]) (P.entries.take i) (P.entries.drop (i + 1)) hsplit
      -- the continuation solution at the next state
      have hnext : suffixSol (P.entries.drop (i + 1)) (headerSol P)
          = planSol P (if i + 1 = P.entries.length then 0 else i + 2) := by
        by_cases hlast : i + 1 = P.entries.length
        · rw [if_pos hlast]
          show _ = headerSol P
          rw [hlast, List.drop_length]
          rfl
        · rw [if_neg hlast]
          rfl
      have h := entry_solves (P.entries[i]) (suffixSol (P.entries.drop (i + 1)) (headerSol P)) habs
      show EquivBA (planSol P (i + 1)) _
      have hsol : planSol P (i + 1) = entrySol (P.entries[i]) (suffixSol (P.entries.drop (i + 1)) (headerSol P)) := by
        show suffixSol (P.entries.drop i) (headerSol P) = _
        rw [hdrop]
        rfl
      rw [hsol]
      -- reduce the eqRHS through the get? fact
      show EquivBA _ (eqRHS (planAut P) (planSol P) (i + 1))
      unfold eqRHS
      show EquivBA _ (((planAut P).trans (i + 1)).foldr _ _)
      have htr : (planAut P).trans (i + 1)
          = [((P.entries[i]).selfG, (P.entries[i]).selfA, i + 1),
             ((P.entries[i]).stepG, (P.entries[i]).stepA, if i + 1 = P.entries.length then 0 else i + 2)] := by
        simp [planAut, hget]
      have hhl : (planAut P).hlt (i + 1) = (P.entries[i]).hltG := by
        simp [planAut, hget]
      rw [htr, hhl]
      show EquivBA _
        (.ite (P.entries[i]).selfG (.seq (.act (P.entries[i]).selfA) (planSol P (i + 1)))
          (.ite (P.entries[i]).stepG (.seq (.act (P.entries[i]).stepA)
            (planSol P (if i + 1 = P.entries.length then 0 else i + 2)))
            (.test (P.entries[i]).hltG)))
      rw [← hnext, hsol]
      exact h

#print axioms ringPlan_solves

end GkatRingPlan
