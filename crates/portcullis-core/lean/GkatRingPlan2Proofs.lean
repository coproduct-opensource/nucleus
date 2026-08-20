import GkatRingPlanProofs

/-! # The Ring Theorem, tree case: CPS walk plans

    v1 (`GkatRingPlanProofs`) covered linear walks; the census of the k=6 residue
    also uses nested sub-cycles and direct-to-header branches.  The right
    generalization is a change of SHAPE, not a list of new cases: compose each node's
    remainder INSIDE its step arm (continuation style) instead of sequencing after it.
    Then:

      * a halt arm is a bare `test hltG` that matches the equation's fallback by refl —
        the parking side conditions of v1 (interior emptiness, park position) dissolve;
      * a sub-cycle is just a self-loop whose body is a compound inner pass;
      * a branch is just a nonzero exit-dispatch arm;
      * every interior obligation is `salomaa_solution_exists` alone, and all the
        absorption concentrates in one recursive spine lemma for the header.

    States are pairs: `(0,0)` the header, `(i+1,0)` top node `i`, `(i+1,j+1)` inner
    node `j` of top node `i`, `(0,j+1)` inner node `j` of the header's own loop. -/

namespace GkatRingPlan2

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatRingSupport GkatGuardedAlgebra
open GkatResidue GkatRingPlan

variable {A T : Type}

/-- An inner-pass node: a self-loop, a step onward (the last inner step returns to the
    owner), and a halt arm. -/
structure FlatNode (A T : Type) where
  selfG : BExp T
  selfA : A
  stepG : BExp T
  stepA : A
  hltG : BExp T

/-- A top-level walk node: a local loop (plain self-loop when `loopW = []`, a nested
    sub-cycle otherwise), a direct-to-header exit dispatch, a step onward, and a
    subset-parked halt. -/
structure Node (A T : Type) where
  loopG : BExp T
  loopA : A
  loopW : List (FlatNode A T)
  exitG : BExp T
  exitA : A
  stepG : BExp T
  stepA : A
  hltG : BExp T

/-- The tree plan: the header's own local loop and step, the exit guard, and the walk. -/
structure RingPlan2 (A T : Type) where
  hLoopG : BExp T
  hLoopA : A
  hLoopW : List (FlatNode A T)
  hStepG : BExp T
  hStepA : A
  exitG : BExp T
  nodes : List (Node A T)

/-! ## Raw expressions (the header's loop body) -/

/-- One inner pass, raw and continuation-nested; the terminal step action returns to
    the owner (no trailing unit). -/
def innerRaw : FlatNode A T → List (FlatNode A T) → Exp A T
  | f, [] =>
      .seq (.wh f.selfG (.act f.selfA))
        (.ite f.stepG (.act f.stepA) (.test f.hltG))
  | f, g :: r =>
      .seq (.wh f.selfG (.act f.selfA))
        (.ite f.stepG (.seq (.act f.stepA) (innerRaw g r)) (.test f.hltG))

/-- A local loop's body: the entry action, then the inner pass. -/
def loopRaw (a : A) (w : List (FlatNode A T)) : Exp A T :=
  match w with
  | [] => .act a
  | f :: r => .seq (.act a) (innerRaw f r)

/-- The walk, raw and continuation-nested: each node's remainder sits inside its step
    arm; the terminal step action returns to the header. -/
def walkRaw : List (Node A T) → Exp A T
  | [] => .test .one
  | [n] =>
      .seq (.wh n.loopG (loopRaw n.loopA n.loopW))
        (.ite n.exitG (.act n.exitA)
          (.ite n.stepG (.act n.stepA) (.test n.hltG)))
  | n :: r =>
      .seq (.wh n.loopG (loopRaw n.loopA n.loopW))
        (.ite n.exitG (.act n.exitA)
          (.ite n.stepG (.seq (.act n.stepA) (walkRaw r)) (.test n.hltG)))

/-- The header's loop body: local-loop dispatch, else the step action and the walk. -/
def planBody2 (P : RingPlan2 A T) : Exp A T :=
  .ite P.hLoopG (loopRaw P.hLoopA P.hLoopW)
    (match P.nodes with
     | [] => .act P.hStepA
     | n :: r => .seq (.act P.hStepA) (walkRaw (n :: r)))

/-- The header's solution. -/
def headerSol2 (P : RingPlan2 A T) : Exp A T :=
  .seq (.wh (.or P.hStepG P.hLoopG) (planBody2 P)) (.test P.exitG)

/-! ## Solutions -/

/-- An inner node's solution, given the next inner solution (or the owner's). -/
def flatSol (f : FlatNode A T) (next : Exp A T) : Exp A T :=
  .seq (.wh f.selfG (.act f.selfA))
    (.ite f.stepG (.seq (.act f.stepA) next) (.test f.hltG))

/-- Inner suffix solutions down to the owner's. -/
def innerSuffix (w : List (FlatNode A T)) (owner : Exp A T) : Exp A T :=
  match w with
  | [] => owner
  | f :: r => flatSol f (innerSuffix r owner)

/-- A top node's solution, given the header's and the next node's. -/
def nodeSol (n : Node A T) (solH next : Exp A T) : Exp A T :=
  .seq (.wh n.loopG (loopRaw n.loopA n.loopW))
    (.ite n.exitG (.seq (.act n.exitA) solH)
      (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG)))

/-- Walk suffix solutions down to the header's. -/
def walkSuffix (ns : List (Node A T)) (solH : Exp A T) : Exp A T :=
  match ns with
  | [] => solH
  | n :: r => nodeSol n solH (walkSuffix r solH)

/-! ## The tree spine: pushing the header solution through the raw walk -/

/-- **The tree-spine lemma.**  Sequencing the header's solution after the raw walk
    yields the first suffix solution.  All the u5-splitting and halt absorption of the
    construction lives here; the per-node subset-parking hypothesis arrives as
    `habs`. -/
theorem walkRaw_spine (P : RingPlan2 A T) (ns : List (Node A T))
    (habs : ∀ n ∈ ns, EquivBA (.seq (.test n.hltG) (headerSol2 P)) (.test n.hltG)) :
    ns ≠ [] →
    EquivBA (.seq (walkRaw ns) (headerSol2 P)) (walkSuffix ns (headerSol2 P)) := by
  induction ns with
  | nil => intro h; exact absurd rfl h
  | cons n r ih =>
      intro _
      have hn : EquivBA (.seq (.test n.hltG) (headerSol2 P)) (.test n.hltG) :=
        habs n (by exact List.mem_cons_self)
      cases r with
      | nil =>
          refine EquivBA.trans (EquivBA.base (Equiv.s1
            (.wh n.loopG (loopRaw n.loopA n.loopW))
            (.ite n.exitG (.act n.exitA)
              (.ite n.stepG (.act n.stepA) (.test n.hltG)))
            (headerSol2 P))) ?_
          refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
          refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 n.exitG
            (.act n.exitA)
            (.ite n.stepG (.act n.stepA) (.test n.hltG)) (headerSol2 P)))) ?_
          refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
          refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 n.stepG
            (.act n.stepA) (.test n.hltG) (headerSol2 P)))) ?_
          exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) hn
      | cons m s =>
          refine EquivBA.trans (EquivBA.base (Equiv.s1
            (.wh n.loopG (loopRaw n.loopA n.loopW))
            (.ite n.exitG (.act n.exitA)
              (.ite n.stepG (.seq (.act n.stepA) (walkRaw (m :: s))) (.test n.hltG)))
            (headerSol2 P))) ?_
          refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
          refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 n.exitG
            (.act n.exitA)
            (.ite n.stepG (.seq (.act n.stepA) (walkRaw (m :: s))) (.test n.hltG))
            (headerSol2 P)))) ?_
          refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
          refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 n.stepG
            (.seq (.act n.stepA) (walkRaw (m :: s))) (.test n.hltG)
            (headerSol2 P)))) ?_
          refine EquivBA.ite_c ?_ hn
          refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act n.stepA)
            (walkRaw (m :: s)) (headerSol2 P))) ?_
          exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (ih (fun q hq => habs q (List.mem_cons_of_mem n hq)) (by simp))

/-! ## The interior obligations -/

/-- An inner node's equation: one salomaa unroll, everything else is refl. -/
theorem flatSol_solves (f : FlatNode A T) (next : Exp A T) :
    EquivBA (flatSol f next)
      (.ite f.selfG (.seq (.act f.selfA) (flatSol f next))
        (.ite f.stepG (.seq (.act f.stepA) next) (.test f.hltG))) :=
  EquivBA.base (salomaa_solution_exists f.selfG (.act f.selfA)
    (.ite f.stepG (.seq (.act f.stepA) next) (.test f.hltG)))

/-- A top node's equation, plain self-loop case (`loopW = []`). -/
theorem nodeSol_solves_flat (n : Node A T) (solH next : Exp A T)
    (hW : n.loopW = []) :
    EquivBA (nodeSol n solH next)
      (.ite n.loopG (.seq (.act n.loopA) (nodeSol n solH next))
        (.ite n.exitG (.seq (.act n.exitA) solH)
          (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG)))) := by
  simp only [nodeSol, hW]
  exact EquivBA.base (salomaa_solution_exists n.loopG (loopRaw n.loopA [])
    (.ite n.exitG (.seq (.act n.exitA) solH)
      (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG))))

/-- A top node's equation, sub-cycle case: the loop arm steps into the first inner
    solution; the inner spine below relates the raw pass to the suffix solutions. -/
theorem nodeSol_solves_sub (n : Node A T) (solH next : Exp A T)
    (f : FlatNode A T) (r : List (FlatNode A T)) (hW : n.loopW = f :: r)
    (hspine : EquivBA (.seq (loopRaw n.loopA n.loopW) (nodeSol n solH next))
      (.seq (.act n.loopA) (innerSuffix n.loopW (nodeSol n solH next)))) :
    EquivBA (nodeSol n solH next)
      (.ite n.loopG (.seq (.act n.loopA) (innerSuffix n.loopW (nodeSol n solH next)))
        (.ite n.exitG (.seq (.act n.exitA) solH)
          (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG)))) :=
  EquivBA.trans
    (EquivBA.base (salomaa_solution_exists n.loopG (loopRaw n.loopA n.loopW)
      (.ite n.exitG (.seq (.act n.exitA) solH)
        (.ite n.stepG (.seq (.act n.stepA) next) (.test n.hltG)))))
    (EquivBA.ite_c hspine (EquivBA.base (Equiv.refl _)))

/-! ## The inner spine and the header obligation -/

/-- **The inner-spine lemma**: pushing an owner's solution through a raw inner pass
    yields the inner suffix solutions.  Inner halts must be semantically empty (the
    census: inner halt arms are reject-`0?`). -/
theorem innerRaw_spine (f : FlatNode A T) (r : List (FlatNode A T)) (K : Exp A T)
    (hdead : ∀ g ∈ f :: r, GuardEmpty g.hltG) :
    EquivBA (.seq (innerRaw f r) K) (innerSuffix (f :: r) K) := by
  induction r generalizing f with
  | nil =>
      refine EquivBA.trans (EquivBA.base (Equiv.s1
        (.wh f.selfG (.act f.selfA))
        (.ite f.stepG (.act f.stepA) (.test f.hltG)) K)) ?_
      refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
      refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 f.stepG
        (.act f.stepA) (.test f.hltG) K))) ?_
      exact EquivBA.ite_c (EquivBA.base (Equiv.refl _))
        (test_empty_absorb (hdead f List.mem_cons_self) K)
  | cons g s ih =>
      refine EquivBA.trans (EquivBA.base (Equiv.s1
        (.wh f.selfG (.act f.selfA))
        (.ite f.stepG (.seq (.act f.stepA) (innerRaw g s)) (.test f.hltG)) K)) ?_
      refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
      refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 f.stepG
        (.seq (.act f.stepA) (innerRaw g s)) (.test f.hltG) K))) ?_
      refine EquivBA.ite_c ?_
        (test_empty_absorb (hdead f List.mem_cons_self) K)
      refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act f.stepA)
        (innerRaw g s) K)) ?_
      exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (ih g (fun q hq => hdead q (List.mem_cons_of_mem f hq)))

/-- The local-loop spine: the loop body followed by the owner's solution is the entry
    action into the inner suffix. -/
theorem loopRaw_spine (a : A) (w : List (FlatNode A T)) (K : Exp A T)
    (hdead : ∀ g ∈ w, GuardEmpty g.hltG) :
    EquivBA (.seq (loopRaw a w) K) (.seq (.act a) (innerSuffix w K)) := by
  cases w with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons f r =>
      refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act a) (innerRaw f r) K)) ?_
      exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (innerRaw_spine f r K hdead)

/-- **The header obligation**: salomaa unroll, guard split, and the two under-guard
    selections; the walk arm reduces through the tree spine, the local-loop arm
    through the loop spine. -/
theorem headerSol2_solves (P : RingPlan2 A T)
    (hdisj : GuardDisjoint P.hStepG P.hLoopG)
    (n0 : Node A T) (r : List (Node A T)) (hns : P.nodes = n0 :: r)
    (habs : ∀ n ∈ P.nodes,
      EquivBA (.seq (.test n.hltG) (headerSol2 P)) (.test n.hltG))
    (hdead : ∀ g ∈ P.hLoopW, GuardEmpty g.hltG) :
    EquivBA (headerSol2 P)
      (.ite P.hStepG (.seq (.act P.hStepA) (walkSuffix P.nodes (headerSol2 P)))
        (.ite P.hLoopG
          (.seq (.act P.hLoopA) (innerSuffix P.hLoopW (headerSol2 P)))
          (.test P.exitG))) := by
  have hbody : planBody2 P
      = .ite P.hLoopG (loopRaw P.hLoopA P.hLoopW)
          (.seq (.act P.hStepA) (walkRaw (n0 :: r))) := by
    unfold planBody2
    rw [hns]
  refine EquivBA.trans (EquivBA.base (salomaa_solution_exists
    (.or P.hStepG P.hLoopG) (planBody2 P) (.test P.exitG))) ?_
  refine EquivBA.trans (ite_or_split P.hStepG P.hLoopG
    (.seq (planBody2 P) (headerSol2 P)) (.test P.exitG)) ?_
  have h_step : EquivBA (.seq (.test P.hStepG) (.seq (planBody2 P) (headerSol2 P)))
      (.seq (.test P.hStepG)
        (.seq (.act P.hStepA) (walkSuffix P.nodes (headerSol2 P)))) := by
    have hsel : EquivBA (.seq (.test P.hStepG) (planBody2 P))
        (.seq (.test P.hStepG) (.seq (.act P.hStepA) (walkRaw (n0 :: r)))) := by
      rw [hbody]
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.base (Equiv.u2 P.hLoopG (loopRaw P.hLoopA P.hLoopW)
          (.seq (.act P.hStepA) (walkRaw (n0 :: r)))))) ?_
      exact test_seq_ite_of_implies _ _ hdisj.implies_not
    refine EquivBA.trans (seq_under_guard (headerSol2 P) hsel) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.s1 (.act P.hStepA)
      (walkRaw (n0 :: r)) (headerSol2 P))) ?_
    rw [hns]
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
    exact walkRaw_spine P (n0 :: r) (by rw [← hns]; exact habs) (by simp)
  have h_loop : EquivBA (.seq (.test P.hLoopG) (.seq (planBody2 P) (headerSol2 P)))
      (.seq (.test P.hLoopG)
        (.seq (.act P.hLoopA) (innerSuffix P.hLoopW (headerSol2 P)))) := by
    have hsel : EquivBA (.seq (.test P.hLoopG) (planBody2 P))
        (.seq (.test P.hLoopG) (loopRaw P.hLoopA P.hLoopW)) := by
      rw [hbody]
      exact test_seq_ite_of_implies _ _ (himp_self P.hLoopG)
    refine EquivBA.trans (seq_under_guard (headerSol2 P) hsel) ?_
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (loopRaw_spine P.hLoopA P.hLoopW (headerSol2 P) hdead)
  exact EquivBA.trans (ite_congr_under_guard h_step)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ite_congr_under_guard h_loop))

/-! ## The plan automaton, solutions, and the theorem -/

/-- Inner width at outer index `i`: the header's loop for `i = 0`, node `i-1`'s
    otherwise. -/
def widthAt (P : RingPlan2 A T) (i : Nat) : Nat :=
  if i = 0 then P.hLoopW.length
  else match P.nodes[i - 1]? with
    | some n => n.loopW.length
    | none => 0

/-- The inner walk at outer index `i`. -/
def innerAt (P : RingPlan2 A T) (i : Nat) : List (FlatNode A T) :=
  if i = 0 then P.hLoopW
  else match P.nodes[i - 1]? with
    | some n => n.loopW
    | none => []

def statesOf (P : RingPlan2 A T) : List (Nat × Nat) :=
  (List.range (P.nodes.length + 1)).flatMap (fun i =>
    (List.range (widthAt P i + 1)).map (fun j => (i, j)))

theorem mem_statesOf {P : RingPlan2 A T} {i j : Nat} :
    (i, j) ∈ statesOf P ↔ i < P.nodes.length + 1 ∧ j < widthAt P i + 1 := by
  simp only [statesOf, List.mem_flatMap, List.mem_map, List.mem_range]
  constructor
  · rintro ⟨a, ha, b, hb, hab⟩
    obtain ⟨rfl, rfl⟩ : a = i ∧ b = j := by
      exact ⟨congrArg Prod.fst hab, congrArg Prod.snd hab⟩
    exact ⟨ha, hb⟩
  · rintro ⟨hi, hj⟩
    exact ⟨i, hi, j, hj, rfl⟩

def planAut2 (P : RingPlan2 A T) : GAut (Nat × Nat) A T where
  states := statesOf P
  hlt := fun s =>
    if s.2 = 0 then
      (if s.1 = 0 then P.exitG else
        match P.nodes[s.1 - 1]? with
        | some n => n.hltG
        | none => .zero)
    else
      match (innerAt P s.1)[s.2 - 1]? with
      | some f => f.hltG
      | none => .zero
  trans := fun s =>
    if s.2 = 0 then
      (if s.1 = 0 then
        [(P.hStepG, P.hStepA, (1, 0)),
         (P.hLoopG, P.hLoopA, if P.hLoopW.length = 0 then (0, 0) else (0, 1))]
      else
        match P.nodes[s.1 - 1]? with
        | some n =>
            [(n.loopG, n.loopA,
              if n.loopW.length = 0 then (s.1, 0) else (s.1, 1)),
             (n.exitG, n.exitA, (0, 0)),
             (n.stepG, n.stepA,
              if s.1 = P.nodes.length then (0, 0) else (s.1 + 1, 0))]
        | none => [])
    else
      match (innerAt P s.1)[s.2 - 1]? with
      | some f =>
          [(f.selfG, f.selfA, (s.1, s.2)),
           (f.stepG, f.stepA,
            if s.2 = (innerAt P s.1).length then (s.1, 0) else (s.1, s.2 + 1))]
      | none => []
  start := (0, 0)

/-- The owner solution at outer index `i`. -/
def ownerSol (P : RingPlan2 A T) (i : Nat) : Exp A T :=
  if i = 0 then headerSol2 P
  else walkSuffix (P.nodes.drop (i - 1)) (headerSol2 P)

def planSol2 (P : RingPlan2 A T) : Nat × Nat → Exp A T := fun s =>
  if s.2 = 0 then ownerSol P s.1
  else innerSuffix ((innerAt P s.1).drop (s.2 - 1)) (ownerSol P s.1)

/-- Well-formedness of a tree plan. -/
structure WellFormedRing2 (P : RingPlan2 A T) : Prop where
  nonempty : P.nodes ≠ []
  hdr_disj : GuardDisjoint P.hStepG P.hLoopG
  /-- Every top node's halt parks into the header: off the loop guard... -/
  node_off : ∀ n ∈ P.nodes, GuardImplies n.hltG (.not (.or P.hStepG P.hLoopG))
  /-- ...and below the exit guard. -/
  node_sub : ∀ n ∈ P.nodes,
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      (bval W n.hltG x && bval W P.exitG x) = bval W n.hltG x
  /-- Inner halts (header's and every node's) are semantically empty. -/
  inner_dead : ∀ f ∈ P.hLoopW, GuardEmpty f.hltG
  node_inner_dead : ∀ n ∈ P.nodes, ∀ f ∈ n.loopW, GuardEmpty f.hltG

theorem WellFormedRing2.habs {P : RingPlan2 A T} (hwf : WellFormedRing2 P) :
    ∀ n ∈ P.nodes,
      EquivBA (.seq (.test n.hltG) (headerSol2 P)) (.test n.hltG) := fun n hn =>
  test_header_absorb_sub n.hltG P.exitG (.or P.hStepG P.hLoopG) (planBody2 P)
    (hwf.node_off n hn) (hwf.node_sub n hn)

/-- **THE RING THEOREM, tree case.** -/
theorem ringPlan2_solves (P : RingPlan2 A T) (hwf : WellFormedRing2 P) :
    SolvesBA (planAut2 P) (planSol2 P) := by
  rintro ⟨i, j⟩ hs
  obtain ⟨hi, hj⟩ := mem_statesOf.mp hs
  cases j with
  | succ j =>
      -- an inner node of owner i
      have hjw : j < (innerAt P i).length := by
        have := hj
        simp only [widthAt] at this
        by_cases h0 : i = 0
        · subst h0
          simpa [innerAt] using Nat.lt_of_succ_lt_succ this
        · rw [if_neg h0] at this
          simp only [innerAt, if_neg h0]
          cases hn : P.nodes[i - 1]? with
          | some n => rw [hn] at this; simpa using Nat.lt_of_succ_lt_succ this
          | none => rw [hn] at this; exact absurd (Nat.lt_of_succ_lt_succ this) (by simp)
      have hget : (innerAt P i)[j]? = some ((innerAt P i)[j]) :=
        List.getElem?_eq_getElem hjw
      have hdrop : (innerAt P i).drop j
          = (innerAt P i)[j] :: (innerAt P i).drop (j + 1) :=
        List.drop_eq_getElem_cons hjw
      have htr : (planAut2 P).trans (i, j + 1)
          = [(((innerAt P i)[j]).selfG, ((innerAt P i)[j]).selfA, (i, j + 1)),
             (((innerAt P i)[j]).stepG, ((innerAt P i)[j]).stepA,
              if j + 1 = (innerAt P i).length then (i, 0) else (i, j + 2))] := by
        simp [planAut2, hget]
      have hhl : (planAut2 P).hlt (i, j + 1) = ((innerAt P i)[j]).hltG := by
        simp [planAut2, hget]
      have hnext : innerSuffix ((innerAt P i).drop (j + 1)) (ownerSol P i)
          = planSol2 P (if j + 1 = (innerAt P i).length then (i, 0) else (i, j + 2)) := by
        by_cases hlast : j + 1 = (innerAt P i).length
        · rw [if_pos hlast]
          show _ = planSol2 P (i, 0)
          rw [hlast, List.drop_length]
          rfl
        · rw [if_neg hlast]
          rfl
      have hsol : planSol2 P (i, j + 1)
          = flatSol ((innerAt P i)[j])
              (innerSuffix ((innerAt P i).drop (j + 1)) (ownerSol P i)) := by
        show innerSuffix ((innerAt P i).drop j) (ownerSol P i) = _
        rw [hdrop]
        rfl
      show EquivBA (planSol2 P (i, j + 1)) (eqRHS (planAut2 P) (planSol2 P) (i, j + 1))
      unfold eqRHS
      rw [htr, hhl, hsol]
      show EquivBA _
        (.ite ((innerAt P i)[j]).selfG
          (.seq (.act ((innerAt P i)[j]).selfA) (planSol2 P (i, j + 1)))
          (.ite ((innerAt P i)[j]).stepG
            (.seq (.act ((innerAt P i)[j]).stepA)
              (planSol2 P (if j + 1 = (innerAt P i).length then (i, 0) else (i, j + 2))))
            (.test ((innerAt P i)[j]).hltG)))
      rw [← hnext, hsol]
      exact flatSol_solves _ _
  | zero =>
      cases i with
      | zero =>
          -- the header
          obtain ⟨n0, r, hns⟩ : ∃ n0 r, P.nodes = n0 :: r := by
            cases hE : P.nodes with
            | nil => exact absurd hE hwf.nonempty
            | cons a b => exact ⟨a, b, rfl⟩
          have h := headerSol2_solves P hwf.hdr_disj n0 r hns hwf.habs hwf.inner_dead
          have htr : (planAut2 P).trans (0, 0)
              = [(P.hStepG, P.hStepA, (1, 0)),
                 (P.hLoopG, P.hLoopA,
                  if P.hLoopW.length = 0 then (0, 0) else (0, 1))] := by
            simp [planAut2]
          have hhl : (planAut2 P).hlt (0, 0) = P.exitG := by
            simp [planAut2]
          show EquivBA (planSol2 P (0, 0)) (eqRHS (planAut2 P) (planSol2 P) (0, 0))
          unfold eqRHS
          rw [htr, hhl]
          have hstep1 : planSol2 P (1, 0) = walkSuffix P.nodes (headerSol2 P) := rfl
          have hloop1 : planSol2 P (if P.hLoopW.length = 0 then (0, 0) else (0, 1))
              = innerSuffix P.hLoopW (headerSol2 P) := by
            cases hW : P.hLoopW with
            | nil => simp [planSol2, ownerSol, innerSuffix, hW]
            | cons f w =>
                rw [if_neg (by simp)]
                show innerSuffix ((innerAt P 0).drop 0) (ownerSol P 0) = _
                have hIA : innerAt P 0 = P.hLoopW := by simp [innerAt]
                rw [hIA, hW]
                rfl
          show EquivBA _
            (.ite P.hStepG (.seq (.act P.hStepA) (planSol2 P (1, 0)))
              (.ite P.hLoopG (.seq (.act P.hLoopA)
                (planSol2 P (if P.hLoopW.length = 0 then (0, 0) else (0, 1))))
                (.test P.exitG)))
          rw [hstep1, hloop1]
          exact h
      | succ i =>
          -- top node i
          have hiw : i < P.nodes.length := Nat.lt_of_succ_lt_succ hi
          have hget : P.nodes[i]? = some (P.nodes[i]) :=
            List.getElem?_eq_getElem hiw
          have hdrop : P.nodes.drop i = P.nodes[i] :: P.nodes.drop (i + 1) :=
            List.drop_eq_getElem_cons hiw
          have hmem : P.nodes[i] ∈ P.nodes := List.getElem_mem hiw
          have htr : (planAut2 P).trans (i + 1, 0)
              = [((P.nodes[i]).loopG, (P.nodes[i]).loopA,
                  if (P.nodes[i]).loopW.length = 0 then (i + 1, 0) else (i + 1, 1)),
                 ((P.nodes[i]).exitG, (P.nodes[i]).exitA, (0, 0)),
                 ((P.nodes[i]).stepG, (P.nodes[i]).stepA,
                  if i + 1 = P.nodes.length then (0, 0) else (i + 2, 0))] := by
            simp [planAut2, hget]
          have hhl : (planAut2 P).hlt (i + 1, 0) = (P.nodes[i]).hltG := by
            simp [planAut2, hget]
          have hsolH : planSol2 P (0, 0) = headerSol2 P := rfl
          have hsol : planSol2 P (i + 1, 0)
              = nodeSol (P.nodes[i]) (headerSol2 P)
                  (walkSuffix (P.nodes.drop (i + 1)) (headerSol2 P)) := by
            show walkSuffix (P.nodes.drop i) (headerSol2 P) = _
            rw [hdrop]
            rfl
          have hnext : walkSuffix (P.nodes.drop (i + 1)) (headerSol2 P)
              = planSol2 P (if i + 1 = P.nodes.length then (0, 0) else (i + 2, 0)) := by
            by_cases hlast : i + 1 = P.nodes.length
            · rw [if_pos hlast]
              show _ = headerSol2 P
              rw [hlast, List.drop_length]
              rfl
            · rw [if_neg hlast]
              rfl
          have hloopnext : (P.nodes[i]).loopW.length = 0
              → planSol2 P (i + 1, 0)
                = planSol2 P (if (P.nodes[i]).loopW.length = 0 then (i + 1, 0) else (i + 1, 1)) := by
            intro h0
            rw [if_pos h0]
          show EquivBA (planSol2 P (i + 1, 0)) (eqRHS (planAut2 P) (planSol2 P) (i + 1, 0))
          unfold eqRHS
          rw [htr, hhl]
          cases hW : (P.nodes[i]).loopW with
          | nil =>
              have h := nodeSol_solves_flat (P.nodes[i]) (headerSol2 P)
                (walkSuffix (P.nodes.drop (i + 1)) (headerSol2 P)) hW
              show EquivBA (planSol2 P (i + 1, 0))
                (.ite (P.nodes[i]).loopG
                  (.seq (.act (P.nodes[i]).loopA) (planSol2 P (i + 1, 0)))
                  (.ite (P.nodes[i]).exitG
                    (.seq (.act (P.nodes[i]).exitA) (planSol2 P (0, 0)))
                    (.ite (P.nodes[i]).stepG
                      (.seq (.act (P.nodes[i]).stepA)
                        (planSol2 P (if i + 1 = P.nodes.length then (0, 0) else (i + 2, 0))))
                      (.test (P.nodes[i]).hltG))))
              rw [hsol, hsolH, ← hnext]
              exact h
          | cons f w =>
              have hspine := loopRaw_spine (P.nodes[i]).loopA (P.nodes[i]).loopW
                (nodeSol (P.nodes[i]) (headerSol2 P)
                  (walkSuffix (P.nodes.drop (i + 1)) (headerSol2 P)))
                (hwf.node_inner_dead (P.nodes[i]) hmem)
              have h := nodeSol_solves_sub (P.nodes[i]) (headerSol2 P)
                (walkSuffix (P.nodes.drop (i + 1)) (headerSol2 P)) f w hW hspine
              have hinner1 : planSol2 P (i + 1, 1)
                  = innerSuffix (P.nodes[i]).loopW
                      (nodeSol (P.nodes[i]) (headerSol2 P)
                        (walkSuffix (P.nodes.drop (i + 1)) (headerSol2 P))) := by
                show innerSuffix ((innerAt P (i + 1)).drop 0) (ownerSol P (i + 1)) = _
                have hIA : innerAt P (i + 1) = (P.nodes[i]).loopW := by
                  simp [innerAt, hget]
                rw [hIA]
                show innerSuffix (P.nodes[i]).loopW (ownerSol P (i + 1)) = _
                rw [show ownerSol P (i + 1)
                    = walkSuffix (P.nodes.drop i) (headerSol2 P) from rfl, hdrop]
                rfl
              show EquivBA (planSol2 P (i + 1, 0))
                (.ite (P.nodes[i]).loopG
                  (.seq (.act (P.nodes[i]).loopA) (planSol2 P (i + 1, 1)))
                  (.ite (P.nodes[i]).exitG
                    (.seq (.act (P.nodes[i]).exitA) (planSol2 P (0, 0)))
                    (.ite (P.nodes[i]).stepG
                      (.seq (.act (P.nodes[i]).stepA)
                        (planSol2 P (if i + 1 = P.nodes.length then (0, 0) else (i + 2, 0))))
                      (.test (P.nodes[i]).hltG))))
              rw [hsol, hsolH, ← hnext, hinner1]
              exact h

#print axioms ringPlan2_solves

end GkatRingPlan2
