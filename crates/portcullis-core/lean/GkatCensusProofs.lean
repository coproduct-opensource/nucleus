import GkatElimProofs

/-! # The census layer: reachability rank

    The schedule constructors need a rank that is constant on SCCs and
    strictly descending across them.  The canonical choice needs no
    graph algorithms: `rank s := |{t ∈ states | Reach s t}|`.  Arms
    shrink the reachable set (weakly); mutual reachability equalizes
    it; leaving an SCC forever drops it strictly. -/

namespace GkatCensus

open GkatSyntax GkatKleene GkatElim GkatGuardDecide GkatFaithful

variable {A T : Type}

/-- One-step arm reachability. -/
def Arm {S : Type} (aut : GAut S A T) (s t : S) : Prop :=
  ∃ e ∈ aut.trans s, e.2.2 = t

/-- Reflexive-transitive arm reachability. -/
inductive Reach {S : Type} (aut : GAut S A T) : S → S → Prop where
  | refl (s : S) : Reach aut s s
  | step {s t u : S} : Arm aut s t → Reach aut t u → Reach aut s u

theorem Reach.trans {S : Type} {aut : GAut S A T} :
    ∀ {s t u : S}, Reach aut s t → Reach aut t u → Reach aut s u := by
  intro s t u h₁
  induction h₁ with
  | refl s => intro h; exact h
  | step ha _ ih => intro h₂; exact Reach.step ha (ih h₂)

open Classical in
/-- The reachable-state list. -/
noncomputable def reachSet {S : Type} (aut : GAut S A T) (s : S) :
    List S :=
  aut.states.filter (fun t => decide (Reach aut s t))

open Classical in
/-- **THE REACHABILITY RANK**. -/
noncomputable def reachRank {S : Type} (aut : GAut S A T) (s : S) :
    Nat :=
  (reachSet aut s).length

/-- Filters grow along predicate implication. -/
theorem filter_length_le {α : Type} (p q : α → Bool) :
    ∀ L : List α, (∀ x ∈ L, p x = true → q x = true) →
      (L.filter p).length ≤ (L.filter q).length := by
  intro L
  induction L with
  | nil => intro _; exact Nat.le_refl 0
  | cons x rest ih =>
      intro h
      by_cases hp : p x = true
      · rw [List.filter_cons_of_pos (by exact hp),
          List.filter_cons_of_pos (by exact h x (List.mem_cons_self ..) hp)]
        exact Nat.succ_le_succ (ih (fun y hy hpy =>
          h y (List.mem_cons_of_mem _ hy) hpy))
      · rw [List.filter_cons_of_neg (by
          intro hc; exact hp hc)]
        by_cases hq : q x = true
        · rw [List.filter_cons_of_pos (by exact hq)]
          refine Nat.le_trans (ih (fun y hy hpy =>
            h y (List.mem_cons_of_mem _ hy) hpy)) ?_
          exact Nat.le_succ _
        · rw [List.filter_cons_of_neg (by intro hc; exact hq hc)]
          exact ih (fun y hy hpy => h y (List.mem_cons_of_mem _ hy) hpy)

/-- Filters grow strictly when a witness separates the predicates. -/
theorem filter_length_lt {α : Type} (p q : α → Bool) :
    ∀ L : List α, (∀ x ∈ L, p x = true → q x = true) →
      ∀ x₀ ∈ L, q x₀ = true → p x₀ = false →
      (L.filter p).length < (L.filter q).length := by
  intro L
  induction L with
  | nil => intro _ x₀ hx₀; exact nomatch hx₀
  | cons x rest ih =>
      intro h x₀ hx₀ hq₀ hp₀
      rcases List.mem_cons.mp hx₀ with h1 | h2
      · rw [List.filter_cons_of_neg (by
          intro hc
          rw [← h1] at hc
          rw [hp₀] at hc
          exact nomatch hc),
          List.filter_cons_of_pos (by rw [← h1]; exact hq₀)]
        exact Nat.lt_succ_of_le (filter_length_le p q rest
          (fun y hy hpy => h y (List.mem_cons_of_mem _ hy) hpy))
      · by_cases hp : p x = true
        · rw [List.filter_cons_of_pos (by exact hp),
            List.filter_cons_of_pos
              (by exact h x (List.mem_cons_self ..) hp)]
          exact Nat.succ_lt_succ (ih (fun y hy hpy =>
            h y (List.mem_cons_of_mem _ hy) hpy) x₀ h2 hq₀ hp₀)
        · rw [List.filter_cons_of_neg (by intro hc; exact hp hc)]
          by_cases hq : q x = true
          · rw [List.filter_cons_of_pos (by exact hq)]
            refine Nat.lt_succ_of_le ?_
            exact Nat.le_of_lt (ih (fun y hy hpy =>
              h y (List.mem_cons_of_mem _ hy) hpy) x₀ h2 hq₀ hp₀)
          · rw [List.filter_cons_of_neg (by intro hc; exact hq hc)]
            exact ih (fun y hy hpy =>
              h y (List.mem_cons_of_mem _ hy) hpy) x₀ h2 hq₀ hp₀

open Classical in
/-- **RANK DESCENT**: arms weakly shrink the rank. -/
theorem reachRank_le {S : Type} (aut : GAut S A T) {s t : S}
    (h : Arm aut s t) :
    reachRank aut t ≤ reachRank aut s := by
  refine filter_length_le _ _ aut.states ?_
  intro u _ hu
  have hr : Reach aut t u := of_decide_eq_true hu
  exact decide_eq_true (Reach.step h hr)

open Classical in
/-- **RANK EQUALITY**: mutually reachable states have equal rank. -/
theorem reachRank_eq {S : Type} (aut : GAut S A T) {s t : S}
    (hst : Reach aut s t) (hts : Reach aut t s) :
    reachRank aut s = reachRank aut t := by
  refine Nat.le_antisymm ?_ ?_
  · refine filter_length_le _ _ aut.states ?_
    intro u _ hu
    exact decide_eq_true (Reach.trans hts (of_decide_eq_true hu))
  · refine filter_length_le _ _ aut.states ?_
    intro u _ hu
    exact decide_eq_true (Reach.trans hst (of_decide_eq_true hu))

open Classical in
/-- **STRICT DESCENT**: an arm that leaves an SCC forever drops the
    rank strictly (the source must be a listed state). -/
theorem reachRank_lt {S : Type} (aut : GAut S A T) {s t : S}
    (h : Arm aut s t) (hnoret : ¬ Reach aut t s)
    (hs : s ∈ aut.states) :
    reachRank aut t < reachRank aut s := by
  refine filter_length_lt _ _ aut.states ?_ s hs ?_ ?_
  · intro u _ hu
    exact decide_eq_true (Reach.step h (of_decide_eq_true hu))
  · exact decide_eq_true (Reach.refl s)
  · cases hd : decide (Reach aut t s) with
    | false => rfl
    | true => exact absurd (of_decide_eq_true hd) hnoret

open Classical in
/-- The reachability rank satisfies the assembly's descent
    hypothesis outright. -/
theorem reachRank_hdesc {S : Type} (aut : GAut S A T) :
    ∀ s ∈ aut.states, ∀ e ∈ aut.trans s,
      reachRank aut e.2.2 ≤ reachRank aut s := by
  intro s _ e he
  exact reachRank_le aut ⟨e, he, rfl⟩

open Classical in
/-- **SCC DETECTION**: reachability plus equal rank forces mutual
    reachability — rank classes are unions of SCCs, and rank-preserving
    reachability never leaves an SCC.  (The source must be listed.) -/
theorem reach_back_of_rank_eq {S : Type} (aut : GAut S A T) {s t : S}
    (hst : Reach aut s t) (hrk : reachRank aut s = reachRank aut t)
    (hs : s ∈ aut.states) :
    Reach aut t s := by
  have hsub : ∀ u ∈ aut.states,
      decide (Reach aut t u) = true → decide (Reach aut s u) = true := by
    intro u _ hu
    exact decide_eq_true (Reach.trans hst (of_decide_eq_true hu))
  have hback := filter_eq_of_length_eq
    (fun u => decide (Reach aut t u)) (fun u => decide (Reach aut s u))
    aut.states hsub (by
      show (reachSet aut s).length = (reachSet aut t).length
      exact hrk)
    s hs (decide_eq_true (Reach.refl s))
  exact of_decide_eq_true hback

open Classical in
/-- **CLASS DISJOINTNESS**: same-rank arms are intra-SCC — distinct
    SCCs sharing a rank have no arms between them, so rank classes are
    disjoint unions of SCCs and blocks compose in any order. -/
theorem same_rank_arm_mutual {S : Type} (aut : GAut S A T) {s t : S}
    (h : Arm aut s t) (hrk : reachRank aut s = reachRank aut t)
    (hs : s ∈ aut.states) :
    Reach aut t s :=
  reach_back_of_rank_eq aut (Reach.step h (Reach.refl t)) hrk hs

open Classical in
/-- **HALT INVARIANCE**: bisimilar states agree on halting behaviour at
    the generic valuation — exit patterns are language-invariant, so
    quotient merges preserve exit positions (a halting class never
    absorbs a silent state). -/
theorem bisim_hlt_invariant {S : Type} (aut : GkatKleene.GAut S A T)
    {s t : S} (h : GkatPlanExistence.GenBisimilar aut s t) :
    ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) (aut.hlt s) α
        = GkatGS.bval (GkatPlanExistence.genW T) (aut.hlt t) α :=
  (GkatPlanExistence.genBisimilar_bisim aut s t h).1

open Classical in
/-- **QUOTIENT EQUATIONS ARE REP-COMPOSED SUM EQUATIONS**: the
    canonical quotient's equation at any carrier state is the
    underlying automaton's equation with the solution precomposed by
    the representative map — the bridge every census transport rides. -/
theorem eqRHS_quot {S : Type} (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T) (s : S) :
    GkatKleene.eqRHS (GkatPlanExistence.bisimQuotAut aut) sol s
      = GkatKleene.eqRHS aut
          (fun t => sol (GkatPlanExistence.bisimRep aut t)) s := by
  rw [GkatPlanExistence.eqRHS_foldTL, GkatPlanExistence.eqRHS_foldTL]
  show GkatPlanExistence.foldTL sol (aut.hlt s)
      ((aut.trans s).map (fun e =>
        (e.1, e.2.1, GkatPlanExistence.bisimRep aut e.2.2)))
    = GkatPlanExistence.foldTL
        (fun t => sol (GkatPlanExistence.bisimRep aut t))
        (aut.hlt s) (aut.trans s)
  have haux : ∀ L : List (BExp T × A × S),
      GkatPlanExistence.foldTL sol (aut.hlt s)
        (L.map (fun e =>
          (e.1, e.2.1, GkatPlanExistence.bisimRep aut e.2.2)))
      = GkatPlanExistence.foldTL
          (fun t => sol (GkatPlanExistence.bisimRep aut t))
          (aut.hlt s) L := by
    intro L
    induction L with
    | nil => rfl
    | cons e rest ih =>
        show Exp.ite e.1 (.seq (.act e.2.1)
            (sol (GkatPlanExistence.bisimRep aut e.2.2)))
          (GkatPlanExistence.foldTL sol (aut.hlt s)
            (rest.map (fun e =>
              (e.1, e.2.1, GkatPlanExistence.bisimRep aut e.2.2))))
          = Exp.ite e.1 (.seq (.act e.2.1)
            (sol (GkatPlanExistence.bisimRep aut e.2.2)))
          (GkatPlanExistence.foldTL
            (fun t => sol (GkatPlanExistence.bisimRep aut t))
            (aut.hlt s) rest)
        rw [ih]
  exact haux (aut.trans s)

/-! ## Pair gathering

    Dispatch extensionality needs equations normalized per
    (target, action) pair: the gathered guard of a pair is
    atom-determined by the step function, and the gathered body is a
    single action — after which two bisimilar dispatches differ only
    by pointwise-equal guards.  The gather step mirrors
    `multi_gather` with single-action bodies. -/

open Classical in
/-- The gathered guard of a (target, action) pair. -/
noncomputable def gGuardPA {S : Type} [DecidableEq S] [DecidableEq A]
    (t : S) (a : A) : List (BExp T × A × S) → BExp T
  | [] => .zero
  | (g, b, u) :: rest =>
      if u = t ∧ b = a then .or g (gGuardPA t a rest)
      else .and (gGuardPA t a rest) (.not g)

open Classical in
/-- The remainder after removing a (target, action) pair. -/
noncomputable def gOthersPA {S : Type} [DecidableEq S] [DecidableEq A]
    (t : S) (a : A) :
    List (BExp T × A × S) → List (BExp T × A × S)
  | [] => []
  | (g, b, u) :: rest =>
      if u = t ∧ b = a then gOthersPA t a rest
      else (g, b, u) :: gOthersPA t a rest

open Classical in
/-- **THE PAIR GATHER STEP**: one (target, action) pair collects into
    a single-action Salomaa arm. -/
theorem pair_gather {S : Type} [DecidableEq S] [DecidableEq A]
    (sol : S → Exp A T) (h : BExp T) (t : S) (a : A) :
    ∀ L : List (BExp T × A × S),
      EquivBA (GkatPlanExistence.foldTL sol h L)
        (.ite (gGuardPA t a L) (.seq (.act a) (sol t))
          (GkatPlanExistence.foldTL sol h (gOthersPA t a L))) := by
  intro L
  induction L with
  | nil =>
      exact EquivBA.symm (GkatDeadExitElim.ite_zero_guard _ _
        (fun X W x => rfl))
  | cons hd rest ih =>
      obtain ⟨g, b, u⟩ := hd
      by_cases hu : u = t ∧ b = a
      · have hgu : gGuardPA t a ((g, b, u) :: rest)
            = .or g (gGuardPA t a rest) := by
          show (if u = t ∧ b = a then _ else _) = _
          rw [if_pos hu]
        have hot : gOthersPA t a ((g, b, u) :: rest)
            = gOthersPA t a rest := by
          show (if u = t ∧ b = a then _ else _) = _
          rw [if_pos hu]
        rw [hgu, hot]
        obtain ⟨hu1, hu2⟩ := hu
        subst hu1
        subst hu2
        show EquivBA (.ite g (.seq (.act b) (sol u))
          (GkatPlanExistence.foldTL sol h rest)) _
        refine EquivBA.trans (EquivBA.ite_c
          (EquivBA.base (Equiv.refl _)) ih) ?_
        have := GkatPlanExistence.arms_merge g (gGuardPA u b rest)
          (.act b) (.act b) (sol u)
          (GkatPlanExistence.foldTL sol h (gOthersPA u b rest))
        refine EquivBA.trans this ?_
        refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
        refine EquivBA.seq_c ?_ (EquivBA.base (Equiv.refl _))
        exact EquivBA.base (Equiv.u1 g (.act b))
      · have hgu : gGuardPA t a ((g, b, u) :: rest)
            = .and (gGuardPA t a rest) (.not g) := by
          show (if u = t ∧ b = a then _ else _) = _
          rw [if_neg hu]
        have hot : gOthersPA t a ((g, b, u) :: rest)
            = (g, b, u) :: gOthersPA t a rest := by
          show (if u = t ∧ b = a then _ else _) = _
          rw [if_neg hu]
        rw [hgu, hot]
        show EquivBA (.ite g (.seq (.act b) (sol u))
          (GkatPlanExistence.foldTL sol h rest)) _
        refine EquivBA.trans (EquivBA.ite_c
          (EquivBA.base (Equiv.refl _)) ih) ?_
        exact GkatPlanExistence.arm_commute g (gGuardPA t a rest)
          (.seq (.act b) (sol u)) (.seq (.act a) (sol t))
          (GkatPlanExistence.foldTL sol h (gOthersPA t a rest))

#print axioms reachRank_le
#print axioms reachRank_eq
#print axioms reachRank_lt
#print axioms reachRank_hdesc
#print axioms reach_back_of_rank_eq
#print axioms same_rank_arm_mutual
#print axioms bisim_hlt_invariant
#print axioms eqRHS_quot
#print axioms pair_gather

end GkatCensus
