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

/-! ## Dispatch extensionality

    Two dispatches over DIFFERENT state spaces, matched pair-by-pair —
    pointwise-equal gathered guards, `EquivBA`-related continuations —
    are `EquivBA`-equal.  The zip runs down a list of matched
    (target₁, target₂, action) triples via `pair_gather` on both
    sides; the caller discharges the residual.  This is the lemma that
    lets a quotient class verify against ANY of its members' syntax:
    bisimilar states have matched dispatches. -/

open Classical in
/-- The positional pair certificate: each matched triple's gathered
    guards agree pointwise on the CURRENT residuals, its continuations
    are equivalent, and the rest certifies the stripped residuals. -/
def PairsOk {S₁ S₂ : Type} [DecidableEq S₁] [DecidableEq S₂]
    [DecidableEq A] (sol₁ : S₁ → Exp A T) (sol₂ : S₂ → Exp A T) :
    List (S₁ × S₂ × A) → List (BExp T × A × S₁)
    → List (BExp T × A × S₂) → Prop
  | [], _, _ => True
  | p :: rest, L₁, L₂ =>
      ((∀ (X : Type) (W : T → X → Bool) (x : X),
          GkatGS.bval W (gGuardPA p.1 p.2.2 L₁) x
            = GkatGS.bval W (gGuardPA p.2.1 p.2.2 L₂) x)
        ∧ EquivBA (sol₁ p.1) (sol₂ p.2.1))
      ∧ PairsOk sol₁ sol₂ rest
          (gOthersPA p.1 p.2.2 L₁) (gOthersPA p.2.1 p.2.2 L₂)

open Classical in
/-- **DISPATCH EXTENSIONALITY**: matched dispatches over different
    state spaces are equivalent — pointwise-equal gathered guards,
    equivalent continuations, and a residual bridge. -/
theorem dispatch_ext {S₁ S₂ : Type} [DecidableEq S₁] [DecidableEq S₂]
    [DecidableEq A]
    (sol₁ : S₁ → Exp A T) (sol₂ : S₂ → Exp A T)
    (h₁ h₂ : BExp T) :
    ∀ (pairs : List (S₁ × S₂ × A))
      (L₁ : List (BExp T × A × S₁)) (L₂ : List (BExp T × A × S₂)),
      PairsOk sol₁ sol₂ pairs L₁ L₂ →
      EquivBA
        (GkatPlanExistence.foldTL sol₁ h₁
          (pairs.foldl (fun L p => gOthersPA p.1 p.2.2 L) L₁))
        (GkatPlanExistence.foldTL sol₂ h₂
          (pairs.foldl (fun L p => gOthersPA p.2.1 p.2.2 L) L₂)) →
      EquivBA (GkatPlanExistence.foldTL sol₁ h₁ L₁)
        (GkatPlanExistence.foldTL sol₂ h₂ L₂) := by
  intro pairs
  induction pairs with
  | nil =>
      intro L₁ L₂ _ hres
      exact hres
  | cons p rest ih =>
      intro L₁ L₂ hall hres
      obtain ⟨t₁, t₂, a⟩ := p
      obtain ⟨hp, hrest⟩ := hall
      refine EquivBA.trans (pair_gather sol₁ h₁ t₁ a L₁) ?_
      refine EquivBA.trans ?_
        (EquivBA.symm (pair_gather sol₂ h₂ t₂ a L₂))
      refine EquivBA.trans (EquivBA.ite_guard
        (b := gGuardPA t₁ a L₁) (c := gGuardPA t₂ a L₂)
        (fun X W x => hp.1 X W x)) ?_
      refine EquivBA.ite_c
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hp.2) ?_
      exact ih (gOthersPA t₁ a L₁) (gOthersPA t₂ a L₂) hrest hres

/-! ## Semantic reachability and the partner theorem

    Bisimilarity transports firing steps, so every state reachable
    from one start has a bisimilar partner reachable from the other —
    under ULE, every reachable class of the sum has members from BOTH
    sides.  The unification route's plumbing. -/

/-- Step-reachability at the generic valuation. -/
inductive SReach {S : Type} (aut : GkatKleene.GAut S A T) :
    S → S → Prop where
  | refl (s : S) : SReach aut s s
  | step {s t u : S} {α : T → Bool} {a : A} :
      GkatKleene.autStep (GkatPlanExistence.genW T) aut s α
        = some (a, t) →
      SReach aut t u → SReach aut s u

/-- **THE PARTNER THEOREM**: bisimilarity transports semantic
    reachability. -/
theorem sreach_partner {S : Type} (aut : GkatKleene.GAut S A T) :
    ∀ {s₀ s : S}, SReach aut s₀ s →
      ∀ {t₀ : S}, GkatPlanExistence.GenBisimilar aut s₀ t₀ →
      ∃ t : S, SReach aut t₀ t
        ∧ GkatPlanExistence.GenBisimilar aut s t := by
  intro s₀ s hreach
  induction hreach with
  | refl s =>
      intro t₀ hb
      exact ⟨t₀, SReach.refl t₀, hb⟩
  | step hstep hrest ih =>
      intro t₀ hb
      obtain ⟨h1, h2, h3⟩ :=
        GkatPlanExistence.genBisimilar_bisim aut _ _ hb
      obtain ⟨t', ht', hb'⟩ := h2 _ _ _ hstep
      obtain ⟨u', hu', hb''⟩ := ih hb'
      exact ⟨u', SReach.step ht' hu', hb''⟩

#print axioms reachRank_le
#print axioms reachRank_eq
#print axioms reachRank_lt
#print axioms reachRank_hdesc
#print axioms reach_back_of_rank_eq
#print axioms same_rank_arm_mutual
#print axioms bisim_hlt_invariant
#print axioms eqRHS_quot
#print axioms pair_gather
#print axioms dispatch_ext
/-- The fired arm is listed. -/
theorem firstMatch_mem_of_some {Atom : Type} (V : T → Atom → Bool)
    (x : Atom) {S : Type} :
    ∀ (L : List (BExp T × A × S)) (a : A) (t : S),
      GkatKleene.firstMatch V x L = some (a, t) →
      ∃ g, (g, a, t) ∈ L := by
  intro L
  induction L with
  | nil => intro a t h; exact nomatch h
  | cons e rest ih =>
      intro a t h
      obtain ⟨g₀, a₀, t₀⟩ := e
      have hunf : GkatKleene.firstMatch V x ((g₀, a₀, t₀) :: rest)
          = if GkatGS.bval V g₀ x = true then some (a₀, t₀)
            else GkatKleene.firstMatch V x rest := rfl
      rw [hunf] at h
      by_cases hg : GkatGS.bval V g₀ x = true
      · rw [if_pos hg] at h
        have hp := Option.some.inj h
        have ha : a₀ = a := congrArg Prod.fst hp
        have ht : t₀ = t := congrArg Prod.snd hp
        rw [← ha, ← ht]
        exact ⟨g₀, List.mem_cons_self ..⟩
      · rw [if_neg hg] at h
        obtain ⟨g, hgmem⟩ := ih a t h
        exact ⟨g, List.mem_cons_of_mem _ hgmem⟩

/-- Firing steps are arms. -/
theorem step_arm {S : Type} (aut : GkatKleene.GAut S A T)
    {s t : S} {α : T → Bool} {a : A}
    (h : GkatKleene.autStep (GkatPlanExistence.genW T) aut s α
      = some (a, t)) :
    Arm aut s t := by
  obtain ⟨g, hg⟩ := firstMatch_mem_of_some
    (GkatPlanExistence.genW T) α (aut.trans s) a t h
  exact ⟨(g, a, t), hg, rfl⟩

/-- Semantic reachability refines arm reachability — the rank theory
    applies along firing paths. -/
theorem sreach_reach {S : Type} (aut : GkatKleene.GAut S A T) :
    ∀ {s t : S}, SReach aut s t → Reach aut s t := by
  intro s t h
  induction h with
  | refl s => exact Reach.refl s
  | step hstep _ ih => exact Reach.step (step_arm aut hstep) ih

/-! ## Right multiplication of parametric solutions

    The hybrid-family resolution of the padding circularity: dead
    sub-Thompsons supply their own parametric solutions at ANY
    continuation.  Right multiplication is the generic step: a
    parametric solution times `g` is a parametric solution at
    `finish · g`. -/

open Classical in
private theorem guardedFold_fallback_congr
    {branches : List (BExp T × Exp A T)} {f₁ f₂ : Exp A T}
    (h : EquivBA f₁ f₂) :
    EquivBA (GkatFaithful.guardedFold branches f₁)
      (GkatFaithful.guardedFold branches f₂) := by
  induction branches with
  | nil => exact h
  | cons b rest ih =>
      exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih

open Classical in
private theorem guardedFold_seq_right (g : Exp A T) :
    ∀ (branches : List (BExp T × Exp A T)) (fallback : Exp A T),
      EquivBA (.seq (GkatFaithful.guardedFold branches fallback) g)
        (GkatFaithful.guardedFold
          (branches.map (fun b => (b.1, .seq b.2 g)))
          (.seq fallback g)) := by
  intro branches
  induction branches with
  | nil => intro fallback; exact EquivBA.base (Equiv.refl _)
  | cons b rest ih =>
      intro fallback
      show EquivBA (.seq (.ite b.1 b.2
        (GkatFaithful.guardedFold rest fallback)) g) _
      refine EquivBA.trans (EquivBA.symm
        (EquivBA.base (Equiv.u5 b.1 b.2
          (GkatFaithful.guardedFold rest fallback) g))) ?_
      exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ih fallback)

open Classical in
private theorem guardedFold_map_congr {S : Type}
    (F : Exp A T) (f₁ f₂ : (BExp T × A × S) → Exp A T) :
    ∀ L : List (BExp T × A × S),
      (∀ t ∈ L, EquivBA (f₁ t) (f₂ t)) →
      EquivBA
        (GkatFaithful.guardedFold (L.map (fun t => (t.1, f₁ t))) F)
        (GkatFaithful.guardedFold (L.map (fun t => (t.1, f₂ t))) F) := by
  intro L
  induction L with
  | nil => intro _; exact EquivBA.base (Equiv.refl _)
  | cons t rest ih =>
      intro hall
      exact EquivBA.ite_c (hall t (List.mem_cons_self ..))
        (ih (fun q hq => hall q (List.mem_cons_of_mem _ hq)))

open Classical in
/-- **RIGHT MULTIPLICATION**: parametric solutions compose with a
    common continuation. -/
theorem paramSolves_seq {S : Type}
    (aut : GkatThompson.GSystem S A T) (sol : S → Exp A T)
    (fin g : Exp A T)
    (h : GkatThompson.ParamSolvesBA aut sol fin) :
    GkatThompson.ParamSolvesBA aut (fun s => .seq (sol s) g)
      (.seq fin g) := by
  intro s hs
  refine EquivBA.trans (EquivBA.seq_c (h s hs)
    (EquivBA.base (Equiv.refl g))) ?_
  show EquivBA (.seq (GkatFaithful.guardedFold
      (GkatKleene.transitionBranches (aut.trans s) sol)
      (GkatThompson.paramFallback (aut.hlt s) fin)) g) _
  refine EquivBA.trans (guardedFold_seq_right g _ _) ?_
  have hmap : (GkatKleene.transitionBranches (aut.trans s) sol).map
      (fun b => (b.1, Exp.seq b.2 g))
      = (aut.trans s).map (fun t =>
          (t.1, .seq (.seq (.act t.2.1) (sol t.2.2)) g)) := by
    show ((aut.trans s).map _).map _ = _
    rw [List.map_map]
    rfl
  rw [hmap]
  show EquivBA _ (GkatFaithful.guardedFold
    ((aut.trans s).map (fun t =>
      (t.1, .seq (.act t.2.1) (.seq (sol t.2.2) g))))
    (GkatThompson.paramFallback (aut.hlt s) (.seq fin g)))
  refine EquivBA.trans (guardedFold_map_congr _
    (fun t => .seq (.seq (.act t.2.1) (sol t.2.2)) g)
    (fun t => .seq (.act t.2.1) (.seq (sol t.2.2) g))
    (aut.trans s)
    (fun t _ => EquivBA.base
      (Equiv.s1 (.act t.2.1) (sol t.2.2) g))) ?_
  refine guardedFold_fallback_congr ?_
  show EquivBA (.seq (.seq (.test (aut.hlt s)) fin) g)
    (.seq (.test (aut.hlt s)) (.seq fin g))
  exact EquivBA.base (Equiv.s1 (.test (aut.hlt s)) fin g)

/-! ## Class gathering

    The pair-level certificate is too fine for real bisimulations: a
    counterpart may split one (target, action) guard across several
    bisimilar targets.  Gathering by (target-CLASS, action) — with
    `EquivBA`-equal continuations across the class — is
    bisim-invariant: the gathered guard says "the first firing arm
    does `a` into the class", which the step function preserves. -/

open Classical in
/-- The gathered guard of a (target-class, action) pair. -/
noncomputable def gGuardPC {S : Type} [DecidableEq A]
    (P : S → Bool) (a : A) : List (BExp T × A × S) → BExp T
  | [] => .zero
  | (g, b, u) :: rest =>
      if P u = true ∧ b = a then .or g (gGuardPC P a rest)
      else .and (gGuardPC P a rest) (.not g)

open Classical in
/-- The remainder after removing a (target-class, action) pair. -/
noncomputable def gOthersPC {S : Type} [DecidableEq A]
    (P : S → Bool) (a : A) :
    List (BExp T × A × S) → List (BExp T × A × S)
  | [] => []
  | (g, b, u) :: rest =>
      if P u = true ∧ b = a then gOthersPC P a rest
      else (g, b, u) :: gOthersPC P a rest

open Classical in
/-- **THE CLASS GATHER**: a (class, action) pair collects into one
    Salomaa arm over a common continuation, given the class members'
    solutions are equivalent to it. -/
theorem class_gather {S : Type} [DecidableEq A]
    (sol : S → Exp A T) (h : BExp T) (P : S → Bool) (a : A)
    (V : Exp A T) :
    ∀ L : List (BExp T × A × S),
      (∀ e ∈ L, P e.2.2 = true → e.2.1 = a →
        EquivBA (sol e.2.2) V) →
      EquivBA (GkatPlanExistence.foldTL sol h L)
        (.ite (gGuardPC P a L) (.seq (.act a) V)
          (GkatPlanExistence.foldTL sol h (gOthersPC P a L))) := by
  intro L
  induction L with
  | nil =>
      intro _
      exact EquivBA.symm (GkatDeadExitElim.ite_zero_guard _ _
        (fun X W x => rfl))
  | cons hd rest ih =>
      intro hall
      obtain ⟨g, b, u⟩ := hd
      have ihr := ih (fun q hq => hall q (List.mem_cons_of_mem _ hq))
      by_cases hu : P u = true ∧ b = a
      · have hgu : gGuardPC P a ((g, b, u) :: rest)
            = .or g (gGuardPC P a rest) := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_pos hu]
        have hot : gOthersPC P a ((g, b, u) :: rest)
            = gOthersPC P a rest := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_pos hu]
        rw [hgu, hot]
        show EquivBA (.ite g (.seq (.act b) (sol u))
          (GkatPlanExistence.foldTL sol h rest)) _
        have hVu : EquivBA (sol u) V :=
          hall (g, b, u) (List.mem_cons_self ..) hu.1 hu.2
        obtain ⟨-, hu2⟩ := hu
        subst hu2
        refine EquivBA.trans (EquivBA.ite_c
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hVu) ihr) ?_
        refine EquivBA.trans (GkatPlanExistence.arms_merge g
          (gGuardPC P b rest) (.act b) (.act b) V
          (GkatPlanExistence.foldTL sol h (gOthersPC P b rest))) ?_
        refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
        refine EquivBA.seq_c ?_ (EquivBA.base (Equiv.refl _))
        exact EquivBA.base (Equiv.u1 g (.act b))
      · have hgu : gGuardPC P a ((g, b, u) :: rest)
            = .and (gGuardPC P a rest) (.not g) := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_neg hu]
        have hot : gOthersPC P a ((g, b, u) :: rest)
            = (g, b, u) :: gOthersPC P a rest := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_neg hu]
        rw [hgu, hot]
        show EquivBA (.ite g (.seq (.act b) (sol u))
          (GkatPlanExistence.foldTL sol h rest)) _
        refine EquivBA.trans (EquivBA.ite_c
          (EquivBA.base (Equiv.refl _)) ihr) ?_
        exact GkatPlanExistence.arm_commute g (gGuardPC P a rest)
          (.seq (.act b) (sol u)) (.seq (.act a) V)
          (GkatPlanExistence.foldTL sol h (gOthersPC P a rest))

open Classical in
/-- **CLASS-GUARD SEMANTICS**: the gathered guard fires exactly when
    the dispatch's first match does the action into the class — the
    bridge from bisimulation step-agreement to pointwise guard
    equality. -/
theorem gGuardPC_firstMatch {S : Type} [DecidableEq A]
    {Atom : Type} (V₀ : T → Atom → Bool) (x : Atom)
    (P : S → Bool) (a : A) :
    ∀ L : List (BExp T × A × S),
      GkatGS.bval V₀ (gGuardPC P a L) x = true
        ↔ ∃ t', GkatKleene.firstMatch V₀ x L = some (a, t')
            ∧ P t' = true := by
  intro L
  induction L with
  | nil =>
      constructor
      · intro h; exact nomatch h
      · intro ⟨t', h, _⟩; exact nomatch h
  | cons hd rest ih =>
      obtain ⟨g, b, u⟩ := hd
      have hunf : GkatKleene.firstMatch V₀ x ((g, b, u) :: rest)
          = if GkatGS.bval V₀ g x = true then some (b, u)
            else GkatKleene.firstMatch V₀ x rest := rfl
      by_cases hu : P u = true ∧ b = a
      · have hgu : gGuardPC P a ((g, b, u) :: rest)
            = .or g (gGuardPC P a rest) := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_pos hu]
        rw [hgu, hunf]
        show (GkatGS.bval V₀ g x || GkatGS.bval V₀ (gGuardPC P a rest) x)
          = true ↔ _
        by_cases hg : GkatGS.bval V₀ g x = true
        · rw [if_pos hg, hg]
          constructor
          · intro _
            exact ⟨u, by rw [hu.2], hu.1⟩
          · intro _
            rfl
        · have hgf : GkatGS.bval V₀ g x = false := by
            cases hb : GkatGS.bval V₀ g x
            · rfl
            · exact absurd hb hg
          rw [if_neg hg, hgf]
          show (false || _) = true ↔ _
          rw [Bool.false_or]
          exact ih
      · have hgu : gGuardPC P a ((g, b, u) :: rest)
            = .and (gGuardPC P a rest) (.not g) := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_neg hu]
        rw [hgu, hunf]
        show (GkatGS.bval V₀ (gGuardPC P a rest) x
            && !(GkatGS.bval V₀ g x)) = true ↔ _
        by_cases hg : GkatGS.bval V₀ g x = true
        · rw [if_pos hg, hg]
          constructor
          · intro h
            rw [Bool.and_eq_true_iff] at h
            exact nomatch h.2
          · intro ⟨t', ht', hPt⟩
            have hp := Option.some.inj ht'
            have hb : b = a := congrArg Prod.fst hp
            have hut : u = t' := congrArg Prod.snd hp
            exact absurd ⟨by rw [hut]; exact hPt, hb⟩ hu
        · have hgf : GkatGS.bval V₀ g x = false := by
            cases hb : GkatGS.bval V₀ g x
            · rfl
            · exact absurd hb hg
          rw [if_neg hg, hgf]
          show (_ && !false) = true ↔ _
          show (GkatGS.bval V₀ (gGuardPC P a rest) x && true) = true ↔ _
          rw [Bool.and_true]
          exact ih

open Classical in
/-- The positional class certificate: each (class₁, class₂, action,
    continuation) entry has pointwise-equal gathered guards on the
    CURRENT residuals and class-consistent solutions on both sides. -/
def ClassesOk {S₁ S₂ : Type} [DecidableEq A]
    (sol₁ : S₁ → Exp A T) (sol₂ : S₂ → Exp A T) :
    List ((S₁ → Bool) × (S₂ → Bool) × A × Exp A T)
    → List (BExp T × A × S₁) → List (BExp T × A × S₂) → Prop
  | [], _, _ => True
  | e :: rest, L₁, L₂ =>
      ((∀ (X : Type) (W : T → X → Bool) (x : X),
          GkatGS.bval W (gGuardPC e.1 e.2.2.1 L₁) x
            = GkatGS.bval W (gGuardPC e.2.1 e.2.2.1 L₂) x)
        ∧ (∀ q ∈ L₁, e.1 q.2.2 = true → q.2.1 = e.2.2.1 →
            EquivBA (sol₁ q.2.2) e.2.2.2)
        ∧ (∀ q ∈ L₂, e.2.1 q.2.2 = true → q.2.1 = e.2.2.1 →
            EquivBA (sol₂ q.2.2) e.2.2.2))
      ∧ ClassesOk sol₁ sol₂ rest
          (gOthersPC e.1 e.2.2.1 L₁) (gOthersPC e.2.1 e.2.2.1 L₂)

open Classical in
/-- **CLASS DISPATCH EXTENSIONALITY**: dispatches matched class-by-
    class — pointwise-equal gathered guards, common continuations up
    to `EquivBA` — are equivalent.  The bisim-ready form. -/
theorem dispatch_ext_class {S₁ S₂ : Type} [DecidableEq A]
    (sol₁ : S₁ → Exp A T) (sol₂ : S₂ → Exp A T)
    (h₁ h₂ : BExp T) :
    ∀ (entries : List ((S₁ → Bool) × (S₂ → Bool) × A × Exp A T))
      (L₁ : List (BExp T × A × S₁)) (L₂ : List (BExp T × A × S₂)),
      ClassesOk sol₁ sol₂ entries L₁ L₂ →
      EquivBA
        (GkatPlanExistence.foldTL sol₁ h₁
          (entries.foldl (fun L e => gOthersPC e.1 e.2.2.1 L) L₁))
        (GkatPlanExistence.foldTL sol₂ h₂
          (entries.foldl (fun L e => gOthersPC e.2.1 e.2.2.1 L) L₂)) →
      EquivBA (GkatPlanExistence.foldTL sol₁ h₁ L₁)
        (GkatPlanExistence.foldTL sol₂ h₂ L₂) := by
  intro entries
  induction entries with
  | nil =>
      intro L₁ L₂ _ hres
      exact hres
  | cons e rest ih =>
      intro L₁ L₂ hall hres
      obtain ⟨P₁, P₂, a, V⟩ := e
      obtain ⟨⟨hguard, hV₁, hV₂⟩, hrest⟩ := hall
      refine EquivBA.trans (class_gather sol₁ h₁ P₁ a V L₁ hV₁) ?_
      refine EquivBA.trans ?_
        (EquivBA.symm (class_gather sol₂ h₂ P₂ a V L₂ hV₂))
      refine EquivBA.trans (EquivBA.ite_guard
        (b := gGuardPC P₁ a L₁) (c := gGuardPC P₂ a L₂)
        (fun X W x => hguard X W x)) ?_
      refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
      exact ih (gOthersPC P₁ a L₁) (gOthersPC P₂ a L₂) hrest hres

open Classical in
/-- **THE GENERIC-VALUATION LIFT**: guard agreement at `genW` is guard
    agreement everywhere — `genW` is the free Boolean valuation, and
    every valuation factors through it (`bval_gen`).  Bisimulation
    facts (stated at `genW`) feed `baTest`/`ite_guard` (which demand
    all valuations) with no gap. -/
theorem pointwise_of_genW {b c : BExp T}
    (h : ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α
        = GkatGS.bval (GkatPlanExistence.genW T) c α) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W b x = GkatGS.bval W c x := by
  intro X W x
  rw [GkatPlanExistence.bval_gen W x b, GkatPlanExistence.bval_gen W x c]
  exact h (fun t => W t x)

/-! ## Contextual dispatch extensionality

    Residual guard agreement holds only UNDER the accumulated dispatch
    context (shadowed regions of surviving arms are unconstrained), so
    the zip threads the context as a test prefix: each entry's guards
    agree under the context, and the recursion strengthens it by the
    entry's negation.  Works on RAW lists — no cleanedness. -/

open Classical in
/-- Context-threaded ite splitting: the else inherits the tightened
    context. -/
theorem test_ite_split (C G : BExp T) (X Y : Exp A T) :
    EquivBA (.seq (.test C) (.ite G X Y))
      (.ite (.and C G) X (.seq (.test (.and C (.not G))) Y)) := by
  refine EquivBA.trans
    (GkatGuardedAlgebra.test_seq_ite C G X Y) ?_
  refine EquivBA.trans
    (GkatGuardedAlgebra.ite_restrict_else (.and C G) X
      (.seq (.test C) Y)) ?_
  refine EquivBA.ite_c (EquivBA.base (Equiv.refl X)) ?_
  refine EquivBA.trans (EquivBA.symm
    (EquivBA.base (Equiv.s1 (.test (.not (.and C G))) (.test C) Y))) ?_
  refine EquivBA.seq_c ?_ (EquivBA.base (Equiv.refl Y))
  refine EquivBA.trans (EquivBA.s6 (.not (.and C G)) C) ?_
  refine EquivBA.baTest ?_
  intro Z W x
  show (!(GkatGS.bval W C x && GkatGS.bval W G x)
      && GkatGS.bval W C x)
    = (GkatGS.bval W C x && !(GkatGS.bval W G x))
  cases GkatGS.bval W C x <;> cases GkatGS.bval W G x <;> rfl

open Classical in
/-- The context-threaded class certificate: per-entry guard agreement
    UNDER the context; the recursion strengthens the context by the
    entry guard's negation; the nil case is the residual bridge. -/
def CtxOk {S₁ S₂ : Type} [DecidableEq A]
    (sol₁ : S₁ → Exp A T) (sol₂ : S₂ → Exp A T)
    (h₁ h₂ : BExp T) :
    BExp T → List ((S₁ → Bool) × (S₂ → Bool) × A × Exp A T)
    → List (BExp T × A × S₁) → List (BExp T × A × S₂) → Prop
  | C, [], L₁, L₂ =>
      EquivBA (.seq (.test C) (GkatPlanExistence.foldTL sol₁ h₁ L₁))
        (.seq (.test C) (GkatPlanExistence.foldTL sol₂ h₂ L₂))
  | C, e :: rest, L₁, L₂ =>
      ((∀ (X : Type) (W : T → X → Bool) (x : X),
          GkatGS.bval W C x = true →
          GkatGS.bval W (gGuardPC e.1 e.2.2.1 L₁) x
            = GkatGS.bval W (gGuardPC e.2.1 e.2.2.1 L₂) x)
        ∧ (∀ q ∈ L₁, e.1 q.2.2 = true → q.2.1 = e.2.2.1 →
            EquivBA (sol₁ q.2.2) e.2.2.2)
        ∧ (∀ q ∈ L₂, e.2.1 q.2.2 = true → q.2.1 = e.2.2.1 →
            EquivBA (sol₂ q.2.2) e.2.2.2))
      ∧ CtxOk sol₁ sol₂ h₁ h₂
          (.and C (.not (gGuardPC e.1 e.2.2.1 L₁))) rest
          (gOthersPC e.1 e.2.2.1 L₁) (gOthersPC e.2.1 e.2.2.1 L₂)

open Classical in
/-- **CONTEXTUAL DISPATCH EXTENSIONALITY**: matched dispatches are
    equivalent under a context, with guard agreement required only
    inside it. -/
theorem dispatch_ext_ctx {S₁ S₂ : Type} [DecidableEq A]
    (sol₁ : S₁ → Exp A T) (sol₂ : S₂ → Exp A T)
    (h₁ h₂ : BExp T) :
    ∀ (entries : List ((S₁ → Bool) × (S₂ → Bool) × A × Exp A T))
      (C : BExp T)
      (L₁ : List (BExp T × A × S₁)) (L₂ : List (BExp T × A × S₂)),
      CtxOk sol₁ sol₂ h₁ h₂ C entries L₁ L₂ →
      EquivBA (.seq (.test C) (GkatPlanExistence.foldTL sol₁ h₁ L₁))
        (.seq (.test C) (GkatPlanExistence.foldTL sol₂ h₂ L₂)) := by
  intro entries
  induction entries with
  | nil =>
      intro C L₁ L₂ hok
      exact hok
  | cons e rest ih =>
      intro C L₁ L₂ hok
      obtain ⟨P₁, P₂, a, V⟩ := e
      obtain ⟨⟨hguard, hV₁, hV₂⟩, hrest⟩ := hok
      refine EquivBA.trans (EquivBA.seq_c
        (EquivBA.base (Equiv.refl (.test C)))
        (class_gather sol₁ h₁ P₁ a V L₁ hV₁)) ?_
      refine EquivBA.trans ?_ (EquivBA.symm
        (EquivBA.seq_c (EquivBA.base (Equiv.refl (.test C)))
          (class_gather sol₂ h₂ P₂ a V L₂ hV₂)))
      refine EquivBA.trans (test_ite_split C (gGuardPC P₁ a L₁)
        (.seq (.act a) V)
        (GkatPlanExistence.foldTL sol₁ h₁ (gOthersPC P₁ a L₁))) ?_
      refine EquivBA.trans ?_ (EquivBA.symm
        (test_ite_split C (gGuardPC P₂ a L₂) (.seq (.act a) V)
          (GkatPlanExistence.foldTL sol₂ h₂ (gOthersPC P₂ a L₂))))
      refine EquivBA.trans (EquivBA.ite_guard
        (b := .and C (gGuardPC P₁ a L₁))
        (c := .and C (gGuardPC P₂ a L₂)) ?_) ?_
      · intro Z W x
        show (GkatGS.bval W C x && _) = (GkatGS.bval W C x && _)
        cases hC : GkatGS.bval W C x
        · rfl
        · rw [hguard Z W x hC]
      · refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
        refine EquivBA.trans ?_ (EquivBA.seq_c
          (EquivBA.baTest (b := .and C (.not (gGuardPC P₁ a L₁)))
            (c := .and C (.not (gGuardPC P₂ a L₂))) ?_)
          (EquivBA.base (Equiv.refl _)))
        · exact ih (.and C (.not (gGuardPC P₁ a L₁)))
            (gOthersPC P₁ a L₁) (gOthersPC P₂ a L₂) hrest
        · intro Z W x
          show (GkatGS.bval W C x && !_) = (GkatGS.bval W C x && !_)
          cases hC : GkatGS.bval W C x
          · rfl
          · rw [hguard Z W x hC]

#print axioms sreach_partner
#print axioms firstMatch_mem_of_some
#print axioms step_arm
#print axioms sreach_reach
#print axioms paramSolves_seq
#print axioms class_gather
#print axioms gGuardPC_firstMatch
#print axioms dispatch_ext_class
#print axioms pointwise_of_genW
#print axioms test_ite_split
#print axioms dispatch_ext_ctx

open Classical in
/-- **STRIPPING IS INVISIBLE BELOW THE CONTEXT**: when a (class,
    action) entry's gathered guard is false at an atom, removing its
    arms does not change the dispatch there — the residual's first
    match is the full dispatch's.  The supply-side bridge from
    full-dispatch bisimulation agreement to per-entry under-context
    agreement. -/
theorem firstMatch_gOthersPC {S : Type} [DecidableEq A]
    {Atom : Type} (V₀ : T → Atom → Bool) (x : Atom)
    (P : S → Bool) (a : A) :
    ∀ L : List (BExp T × A × S),
      GkatGS.bval V₀ (gGuardPC P a L) x = false →
      GkatKleene.firstMatch V₀ x (gOthersPC P a L)
        = GkatKleene.firstMatch V₀ x L := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons hd rest ih =>
      intro hfalse
      obtain ⟨g, b, u⟩ := hd
      have hunf : GkatKleene.firstMatch V₀ x ((g, b, u) :: rest)
          = if GkatGS.bval V₀ g x = true then some (b, u)
            else GkatKleene.firstMatch V₀ x rest := rfl
      by_cases hu : P u = true ∧ b = a
      · have hgu : gGuardPC P a ((g, b, u) :: rest)
            = .or g (gGuardPC P a rest) := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_pos hu]
        have hot : gOthersPC P a ((g, b, u) :: rest)
            = gOthersPC P a rest := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_pos hu]
        rw [hgu] at hfalse
        have hfalse' : (GkatGS.bval V₀ g x
            || GkatGS.bval V₀ (gGuardPC P a rest) x) = false := hfalse
        have hg : GkatGS.bval V₀ g x = false := by
          cases hb : GkatGS.bval V₀ g x
          · rfl
          · rw [hb] at hfalse'
            exact nomatch hfalse'
        have hrest : GkatGS.bval V₀ (gGuardPC P a rest) x = false := by
          rw [hg] at hfalse'
          cases hb : GkatGS.bval V₀ (gGuardPC P a rest) x
          · rfl
          · rw [hb] at hfalse'
            exact nomatch hfalse'
        rw [hot, hunf, if_neg (by rw [hg]; exact Bool.false_ne_true)]
        exact ih hrest
      · have hgu : gGuardPC P a ((g, b, u) :: rest)
            = .and (gGuardPC P a rest) (.not g) := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_neg hu]
        have hot : gOthersPC P a ((g, b, u) :: rest)
            = (g, b, u) :: gOthersPC P a rest := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_neg hu]
        rw [hgu] at hfalse
        have hfalse' : (GkatGS.bval V₀ (gGuardPC P a rest) x
            && !(GkatGS.bval V₀ g x)) = false := hfalse
        rw [hot]
        have hunf2 : GkatKleene.firstMatch V₀ x
            ((g, b, u) :: gOthersPC P a rest)
          = if GkatGS.bval V₀ g x = true then some (b, u)
            else GkatKleene.firstMatch V₀ x (gOthersPC P a rest) := rfl
        rw [hunf2, hunf]
        by_cases hg : GkatGS.bval V₀ g x = true
        · rw [if_pos hg, if_pos hg]
        · rw [if_neg hg, if_neg hg]
          have hgf : GkatGS.bval V₀ g x = false := by
            cases hb : GkatGS.bval V₀ g x
            · rfl
            · exact absurd hb hg
          have hrest : GkatGS.bval V₀ (gGuardPC P a rest) x
              = false := by
            rw [hgf] at hfalse'
            have : (GkatGS.bval V₀ (gGuardPC P a rest) x && true)
                = false := hfalse'
            rw [Bool.and_true] at this
            exact this
          exact ih hrest

#print axioms firstMatch_gOthersPC

/-! ## The equation transport theorem

    Bisimilar states have `EquivBA`-equal equations under any
    class-consistent solution — the unification route's workhorse.
    The certificate is built with entries for every arm of both
    states; coverage empties the residuals; the halts bridge by halt
    invariance. -/

open Classical in
/-- Class membership, Boolean form. -/
noncomputable def classB {S : Type} (aut : GkatKleene.GAut S A T)
    (t : S) : S → Bool :=
  fun u => decide (GkatPlanExistence.GenBisimilar aut t u)

open Classical in
/-- Residual arms come from the list, unmatched. -/
theorem gOthersPC_mem {S : Type} [DecidableEq A]
    (P : S → Bool) (a : A) :
    ∀ L : List (BExp T × A × S), ∀ q ∈ gOthersPC P a L,
      q ∈ L ∧ ¬(P q.2.2 = true ∧ q.2.1 = a) := by
  intro L
  induction L with
  | nil => intro q hq; exact nomatch hq
  | cons hd rest ih =>
      intro q hq
      obtain ⟨g, b, u⟩ := hd
      by_cases hu : P u = true ∧ b = a
      · have hot : gOthersPC P a ((g, b, u) :: rest)
            = gOthersPC P a rest := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_pos hu]
        rw [hot] at hq
        obtain ⟨h1, h2⟩ := ih q hq
        exact ⟨List.mem_cons_of_mem _ h1, h2⟩
      · have hot : gOthersPC P a ((g, b, u) :: rest)
            = (g, b, u) :: gOthersPC P a rest := by
          show (if P u = true ∧ b = a then _ else _) = _
          rw [if_neg hu]
        rw [hot] at hq
        rcases List.mem_cons.mp hq with h1 | h2
        · rw [h1]
          exact ⟨List.mem_cons_self .., hu⟩
        · obtain ⟨h1, h2⟩ := ih q h2
          exact ⟨List.mem_cons_of_mem _ h1, h2⟩

open Classical in
/-- **EQUATION TRANSPORT**: bisimilar states' equations are
    equivalent under class-consistent solutions. -/
theorem equation_transport {S : Type} [DecidableEq A]
    (aut : GkatKleene.GAut S A T) {s₁ s₂ : S}
    (hbis : GkatPlanExistence.GenBisimilar aut s₁ s₂)
    (sol : S → Exp A T)
    (hsol : ∀ u u', GkatPlanExistence.GenBisimilar aut u u' →
      EquivBA (sol u) (sol u')) :
    EquivBA (GkatKleene.eqRHS aut sol s₁)
      (GkatKleene.eqRHS aut sol s₂) := by
  have haux : ∀ (entries : List ((S → Bool) × (S → Bool) × A × Exp A T))
      (C : BExp T)
      (R₁ R₂ : List (BExp T × A × S)),
      (∀ e ∈ entries, ∃ t a,
        e = (classB aut t, classB aut t, a, sol t)) →
      (∀ α : T → Bool,
        GkatGS.bval (GkatPlanExistence.genW T) C α = true →
        GkatKleene.firstMatch (GkatPlanExistence.genW T) α R₁
            = GkatKleene.firstMatch (GkatPlanExistence.genW T) α
              (aut.trans s₁)
          ∧ GkatKleene.firstMatch (GkatPlanExistence.genW T) α R₂
            = GkatKleene.firstMatch (GkatPlanExistence.genW T) α
              (aut.trans s₂)) →
      (∀ q ∈ R₁, ∃ e ∈ entries,
        e.1 q.2.2 = true ∧ q.2.1 = e.2.2.1) →
      (∀ q ∈ R₂, ∃ e ∈ entries,
        e.2.1 q.2.2 = true ∧ q.2.1 = e.2.2.1) →
      CtxOk sol sol (aut.hlt s₁) (aut.hlt s₂) C entries R₁ R₂ := by
    intro entries
    induction entries with
    | nil =>
        intro C R₁ R₂ _ _ hC₁ hC₂
        have hR₁ : R₁ = [] := by
          cases hR : R₁ with
          | nil => rfl
          | cons q rest =>
              obtain ⟨e, he, -⟩ := hC₁ q (hR ▸ List.mem_cons_self ..)
              exact nomatch he
        have hR₂ : R₂ = [] := by
          cases hR : R₂ with
          | nil => rfl
          | cons q rest =>
              obtain ⟨e, he, -⟩ := hC₂ q (hR ▸ List.mem_cons_self ..)
              exact nomatch he
        rw [hR₁, hR₂]
        show EquivBA (.seq (.test C) (.test (aut.hlt s₁)))
          (.seq (.test C) (.test (aut.hlt s₂)))
        refine EquivBA.trans (EquivBA.s6 C (aut.hlt s₁)) ?_
        refine EquivBA.trans (EquivBA.baTest
          (b := .and C (aut.hlt s₁)) (c := .and C (aut.hlt s₂)) ?_) ?_
        · refine pointwise_of_genW ?_
          intro α
          show (GkatGS.bval (GkatPlanExistence.genW T) C α
              && GkatGS.bval (GkatPlanExistence.genW T)
                (aut.hlt s₁) α)
            = (GkatGS.bval (GkatPlanExistence.genW T) C α
              && GkatGS.bval (GkatPlanExistence.genW T)
                (aut.hlt s₂) α)
          rw [bisim_hlt_invariant aut hbis α]
        · exact EquivBA.symm (EquivBA.s6 C (aut.hlt s₂))
    | cons e₀ rest ih =>
        intro C R₁ R₂ hE hA hC₁ hC₂
        obtain ⟨t₀, a₀, he₀⟩ := hE e₀ (List.mem_cons_self ..)
        subst he₀
        have hgen : ∀ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) C α = true →
            GkatGS.bval (GkatPlanExistence.genW T)
                (gGuardPC (classB aut t₀) a₀ R₁) α
              = GkatGS.bval (GkatPlanExistence.genW T)
                (gGuardPC (classB aut t₀) a₀ R₂) α := by
          intro α hCα
          obtain ⟨hA₁, hA₂⟩ := hA α hCα
          have hiff : (GkatGS.bval (GkatPlanExistence.genW T)
                (gGuardPC (classB aut t₀) a₀ R₁) α = true)
              ↔ (GkatGS.bval (GkatPlanExistence.genW T)
                (gGuardPC (classB aut t₀) a₀ R₂) α = true) := by
            rw [gGuardPC_firstMatch, gGuardPC_firstMatch, hA₁, hA₂]
            obtain ⟨-, h2, h3⟩ :=
              GkatPlanExistence.genBisimilar_bisim aut s₁ s₂ hbis
            constructor
            · rintro ⟨u, hu, hcls⟩
              obtain ⟨u', hu', hbu⟩ := h2 α a₀ u hu
              refine ⟨u', hu', ?_⟩
              have ht₀u : GkatPlanExistence.GenBisimilar aut t₀ u :=
                of_decide_eq_true hcls
              exact decide_eq_true (ht₀u.trans hbu)
            · rintro ⟨u', hu', hcls⟩
              obtain ⟨u, hu, hbu⟩ := h3 α a₀ u' hu'
              refine ⟨u, hu, ?_⟩
              have ht₀u' : GkatPlanExistence.GenBisimilar aut t₀ u' :=
                of_decide_eq_true hcls
              exact decide_eq_true (ht₀u'.trans hbu.symm)
          cases hb₁ : GkatGS.bval (GkatPlanExistence.genW T)
              (gGuardPC (classB aut t₀) a₀ R₁) α
          · cases hb₂ : GkatGS.bval (GkatPlanExistence.genW T)
                (gGuardPC (classB aut t₀) a₀ R₂) α
            · rfl
            · have := hiff.mpr hb₂
              rw [hb₁] at this
              exact nomatch this
          · rw [hiff.mp hb₁]
        refine ⟨⟨?_, ?_, ?_⟩, ?_⟩
        · -- hguard, all valuations under C
          have hpw := pointwise_of_genW
            (b := .and C (gGuardPC (classB aut t₀) a₀ R₁))
            (c := .and C (gGuardPC (classB aut t₀) a₀ R₂))
            (fun α => by
              show (GkatGS.bval (GkatPlanExistence.genW T) C α && _)
                = (GkatGS.bval (GkatPlanExistence.genW T) C α && _)
              cases hCα : GkatGS.bval (GkatPlanExistence.genW T) C α
              · rfl
              · rw [hgen α hCα])
          intro X W x hCx
          have h' : (GkatGS.bval W C x
              && GkatGS.bval W (gGuardPC (classB aut t₀) a₀ R₁) x)
            = (GkatGS.bval W C x
              && GkatGS.bval W (gGuardPC (classB aut t₀) a₀ R₂) x) :=
            hpw X W x
          rw [hCx] at h'
          exact h'
        · intro q _ hcls hact
          exact hsol q.2.2 t₀ (of_decide_eq_true hcls).symm
        · intro q _ hcls hact
          exact hsol q.2.2 t₀ (of_decide_eq_true hcls).symm
        · refine ih (.and C (.not (gGuardPC (classB aut t₀) a₀ R₁)))
            (gOthersPC (classB aut t₀) a₀ R₁)
            (gOthersPC (classB aut t₀) a₀ R₂)
            (fun e he => hE e (List.mem_cons_of_mem _ he))
            ?_ ?_ ?_
          · intro α hCα'
            have hsplit : (GkatGS.bval (GkatPlanExistence.genW T) C α
                && !(GkatGS.bval (GkatPlanExistence.genW T)
                  (gGuardPC (classB aut t₀) a₀ R₁) α)) = true := hCα'
            rw [Bool.and_eq_true_iff] at hsplit
            have hCα : GkatGS.bval (GkatPlanExistence.genW T) C α
                = true := hsplit.1
            have hG₁ : GkatGS.bval (GkatPlanExistence.genW T)
                (gGuardPC (classB aut t₀) a₀ R₁) α = false := by
              have := hsplit.2
              cases hb : GkatGS.bval (GkatPlanExistence.genW T)
                  (gGuardPC (classB aut t₀) a₀ R₁) α
              · rfl
              · rw [hb] at this
                exact nomatch this
            have hG₂ : GkatGS.bval (GkatPlanExistence.genW T)
                (gGuardPC (classB aut t₀) a₀ R₂) α = false := by
              rw [← hgen α hCα]
              exact hG₁
            obtain ⟨hA₁, hA₂⟩ := hA α hCα
            constructor
            · rw [firstMatch_gOthersPC (GkatPlanExistence.genW T) α
                (classB aut t₀) a₀ R₁ hG₁]
              exact hA₁
            · rw [firstMatch_gOthersPC (GkatPlanExistence.genW T) α
                (classB aut t₀) a₀ R₂ hG₂]
              exact hA₂
          · intro q hq
            obtain ⟨hqL, hqnm⟩ := gOthersPC_mem _ _ R₁ q hq
            obtain ⟨e, he, hcov⟩ := hC₁ q hqL
            rcases List.mem_cons.mp he with h1 | h2
            · exfalso
              rw [h1] at hcov
              exact hqnm ⟨hcov.1, hcov.2⟩
            · exact ⟨e, h2, hcov⟩
          · intro q hq
            obtain ⟨hqL, hqnm⟩ := gOthersPC_mem _ _ R₂ q hq
            obtain ⟨e, he, hcov⟩ := hC₂ q hqL
            rcases List.mem_cons.mp he with h1 | h2
            · exfalso
              rw [h1] at hcov
              exact hqnm ⟨hcov.1, hcov.2⟩
            · exact ⟨e, h2, hcov⟩
  have hctx := haux
    ((aut.trans s₁).map (fun q =>
        (classB aut q.2.2, classB aut q.2.2, q.2.1, sol q.2.2))
      ++ (aut.trans s₂).map (fun q =>
        (classB aut q.2.2, classB aut q.2.2, q.2.1, sol q.2.2)))
    .one (aut.trans s₁) (aut.trans s₂)
    (by
      intro e he
      rcases List.mem_append.mp he with h1 | h1
      all_goals
        obtain ⟨q, hqL, hqe⟩ := List.mem_map.mp h1
        exact ⟨q.2.2, q.2.1, hqe.symm⟩)
    (fun α _ => ⟨rfl, rfl⟩)
    (by
      intro q hq
      refine ⟨(classB aut q.2.2, classB aut q.2.2, q.2.1, sol q.2.2),
        List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨q, hq, rfl⟩)),
        ?_, rfl⟩
      exact decide_eq_true (GkatPlanExistence.GenBisimilar.refl aut _)
      )
    (by
      intro q hq
      refine ⟨(classB aut q.2.2, classB aut q.2.2, q.2.1, sol q.2.2),
        List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨q, hq, rfl⟩)),
        ?_, rfl⟩
      exact decide_eq_true (GkatPlanExistence.GenBisimilar.refl aut _)
      )
  have hext := dispatch_ext_ctx sol sol (aut.hlt s₁) (aut.hlt s₂)
    _ .one (aut.trans s₁) (aut.trans s₂) hctx
  rw [GkatPlanExistence.eqRHS_foldTL, GkatPlanExistence.eqRHS_foldTL]
  refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.s4 _))) ?_
  refine EquivBA.trans hext ?_
  exact EquivBA.base (Equiv.s4 _)

#print axioms equation_transport

/-! ## Subsystem bricks

    The seq construction appends continuation arms guarded by the left
    state's halt; the subsystem lemma factors them back into a
    parametric finish.  Two structural bricks: dispatches split over
    appends, and a common guard factors out of a dispatch. -/

open Classical in
/-- Dispatches split over appended arm lists: the first part's
    fallback is the second part's dispatch. -/
theorem foldTL_append {S : Type} (sol : S → Exp A T) (h : BExp T) :
    ∀ L₁ L₂ : List (BExp T × A × S),
      GkatPlanExistence.foldTL sol h (L₁ ++ L₂)
        = (L₁.foldr (fun t acc =>
            Exp.ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc)
            (GkatPlanExistence.foldTL sol h L₂)) := by
  intro L₁ L₂
  induction L₁ with
  | nil => rfl
  | cons e rest ih =>
      show Exp.ite e.1 (.seq (.act e.2.1) (sol e.2.2))
          (GkatPlanExistence.foldTL sol h (rest ++ L₂)) = _
      rw [ih]
      rfl

open Classical in
/-- **GUARD FACTORING**: a guard conjoined onto every arm and the halt
    factors out as a test prefix. -/
theorem foldTL_guard_factor {S : Type} (sol : S → Exp A T)
    (hG : BExp T) (h : BExp T) :
    ∀ L : List (BExp T × A × S),
      EquivBA
        (GkatPlanExistence.foldTL sol (.and hG h)
          (L.map (fun e => (.and hG e.1, e.2.1, e.2.2))))
        (.seq (.test hG) (GkatPlanExistence.foldTL sol h L)) := by
  intro L
  induction L with
  | nil =>
      show EquivBA (.test (.and hG h)) (.seq (.test hG) (.test h))
      exact EquivBA.symm (EquivBA.s6 hG h)
  | cons e rest ih =>
      show EquivBA (.ite (.and hG e.1)
        (.seq (.act e.2.1) (sol e.2.2))
        (GkatPlanExistence.foldTL sol (.and hG h)
          (rest.map (fun e => (.and hG e.1, e.2.1, e.2.2)))))
        (.seq (.test hG) (.ite e.1
          (.seq (.act e.2.1) (sol e.2.2))
          (GkatPlanExistence.foldTL sol h rest)))
      refine EquivBA.trans (EquivBA.ite_c
        (EquivBA.base (Equiv.refl _)) ih) ?_
      exact EquivBA.symm (GkatGuardedAlgebra.test_seq_ite hG e.1
        (.seq (.act e.2.1) (sol e.2.2))
        (GkatPlanExistence.foldTL sol h rest))

#print axioms foldTL_append
#print axioms foldTL_guard_factor

open Classical in
/-- Guarded folds split over appends. -/
theorem guardedFold_append (F : Exp A T) :
    ∀ B₁ B₂ : List (BExp T × Exp A T),
      GkatFaithful.guardedFold (B₁ ++ B₂) F
        = GkatFaithful.guardedFold B₁
            (GkatFaithful.guardedFold B₂ F) := by
  intro B₁ B₂
  induction B₁ with
  | nil => rfl
  | cons b rest ih =>
      show Exp.ite b.1 b.2
          (GkatFaithful.guardedFold (rest ++ B₂) F) = _
      rw [ih]
      rfl

open Classical in
/-- **PARAMETRIC GUARD FACTORING**: a guard conjoined onto every
    branch and the fallback's halt factors out as a test prefix. -/
theorem guardedFold_guard_factor (hG h : BExp T) (F : Exp A T) :
    ∀ branches : List (BExp T × Exp A T),
      EquivBA
        (GkatFaithful.guardedFold
          (branches.map (fun b => (.and hG b.1, b.2)))
          (GkatThompson.paramFallback (.and hG h) F))
        (.seq (.test hG)
          (GkatFaithful.guardedFold branches
            (GkatThompson.paramFallback h F))) := by
  intro branches
  induction branches with
  | nil =>
      show EquivBA (.seq (.test (.and hG h)) F)
        (.seq (.test hG) (.seq (.test h) F))
      refine EquivBA.trans (EquivBA.seq_c
        (EquivBA.symm (EquivBA.s6 hG h))
        (EquivBA.base (Equiv.refl F))) ?_
      exact EquivBA.base (Equiv.s1 (.test hG) (.test h) F)
  | cons b rest ih =>
      show EquivBA (.ite (.and hG b.1) b.2
        (GkatFaithful.guardedFold
          (rest.map (fun b => (.and hG b.1, b.2)))
          (GkatThompson.paramFallback (.and hG h) F))) _
      refine EquivBA.trans (EquivBA.ite_c
        (EquivBA.base (Equiv.refl _)) ih) ?_
      exact EquivBA.symm (GkatGuardedAlgebra.test_seq_ite hG b.1 b.2
        (GkatFaithful.guardedFold rest
          (GkatThompson.paramFallback h F)))

open Classical in
/-- **THE SEQ SUBSYSTEM LEMMA**: in a sequential composite, a left
    state's parametric equation is the left system's parametric
    equation whose finish is the right system's initial dispatch —
    fully parametric in the ambient continuation. -/
theorem seq_subsystem {S₁ S₂ : Type}
    (Lc : GkatThompson.GSystem S₁ A T)
    (R : GkatThompson.InitializedGAut S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (F : Exp A T) (s : S₁) :
    EquivBA
      (GkatThompson.eqRHSParam (GkatThompson.seqGSystem Lc R) sol F
        (.inl s))
      (GkatThompson.eqRHSParam Lc (fun t => sol (.inl t))
        (GkatThompson.initRHSParam R (fun t => sol (.inr t)) F) s) := by
  show EquivBA
    (GkatFaithful.guardedFold
      (GkatKleene.transitionBranches
        ((Lc.trans s).map (fun tr =>
          (tr.1, tr.2.1, Sum.inl tr.2.2)) ++
         R.initTrans.map (fun tr =>
          (.and (Lc.hlt s) tr.1, tr.2.1, Sum.inr tr.2.2))) sol)
      (GkatThompson.paramFallback (.and (Lc.hlt s) R.initHlt) F))
    _
  have hsplit : GkatKleene.transitionBranches
      ((Lc.trans s).map (fun tr =>
        (tr.1, tr.2.1, Sum.inl tr.2.2)) ++
       R.initTrans.map (fun tr =>
        (.and (Lc.hlt s) tr.1, tr.2.1, Sum.inr tr.2.2))) sol
      = GkatKleene.transitionBranches (Lc.trans s)
          (fun t => sol (.inl t))
        ++ (GkatKleene.transitionBranches R.initTrans
            (fun t => sol (.inr t))).map
          (fun b => (.and (Lc.hlt s) b.1, b.2)) := by
    show (((Lc.trans s).map (fun tr : BExp T × A × S₁ =>
        (tr.1, tr.2.1, Sum.inl tr.2.2)) ++
       R.initTrans.map (fun tr : BExp T × A × S₂ =>
        (BExp.and (Lc.hlt s) tr.1, tr.2.1, Sum.inr tr.2.2))).map
        (fun t : BExp T × A × Sum S₁ S₂ =>
          (t.1, Exp.seq (.act t.2.1) (sol t.2.2))))
      = ((Lc.trans s).map (fun t : BExp T × A × S₁ =>
          (t.1, Exp.seq (.act t.2.1) (sol (.inl t.2.2)))))
        ++ ((R.initTrans.map (fun t : BExp T × A × S₂ =>
          (t.1, Exp.seq (.act t.2.1) (sol (.inr t.2.2))))).map
          (fun b : BExp T × Exp A T =>
            (BExp.and (Lc.hlt s) b.1, b.2)))
    rw [List.map_append, List.map_map, List.map_map, List.map_map]
    rfl
  rw [hsplit, guardedFold_append]
  refine EquivBA.trans (guardedFold_fallback_congr
    (guardedFold_guard_factor (Lc.hlt s) R.initHlt F
      (GkatKleene.transitionBranches R.initTrans
        (fun t => sol (.inr t))))) ?_
  exact EquivBA.base (Equiv.refl _)

#print axioms guardedFold_append
#print axioms guardedFold_guard_factor
#print axioms seq_subsystem

open Classical in
/-- **THE LOOP SUBSYSTEM LEMMA**: a wrapped state's parametric
    equation is the BODY's parametric equation whose finish is the
    loop's own initial dispatch — re-enter through the feedback or
    exit through the ambient continuation.  The statement that makes
    an SCC the body system with a feedback finish, connecting quotient
    cycles to the wrapped certificates canonicity speaks about. -/
theorem loop_subsystem {S : Type} (guard : BExp T)
    (body : GkatThompson.InitializedGAut S A T)
    (sol : S → Exp A T) (F : Exp A T) (s : S) :
    EquivBA
      (GkatThompson.eqRHSParam
        (GkatThompson.loopInitialized guard body).core sol F s)
      (GkatThompson.eqRHSParam body.core sol
        (GkatThompson.initRHSParam
          (GkatThompson.loopInitialized guard body) sol F) s) := by
  show EquivBA
    (GkatFaithful.guardedFold
      (GkatKleene.transitionBranches
        (body.core.trans s ++
         body.initTrans.map (fun tr =>
          (BExp.and (body.core.hlt s) (BExp.and guard tr.1),
            tr.2.1, tr.2.2))) sol)
      (GkatThompson.paramFallback
        (.and (body.core.hlt s) (.not guard)) F))
    _
  have hsplit : GkatKleene.transitionBranches
      (body.core.trans s ++
       body.initTrans.map (fun tr =>
        (BExp.and (body.core.hlt s) (BExp.and guard tr.1),
          tr.2.1, tr.2.2))) sol
      = GkatKleene.transitionBranches (body.core.trans s) sol
        ++ (GkatKleene.transitionBranches
            (body.initTrans.map (fun tr =>
              (BExp.and guard tr.1, tr.2.1, tr.2.2))) sol).map
          (fun b => (.and (body.core.hlt s) b.1, b.2)) := by
    show ((body.core.trans s ++
        body.initTrans.map (fun tr : BExp T × A × S =>
          (BExp.and (body.core.hlt s) (BExp.and guard tr.1),
            tr.2.1, tr.2.2))).map
        (fun t : BExp T × A × S =>
          (t.1, Exp.seq (.act t.2.1) (sol t.2.2))))
      = ((body.core.trans s).map (fun t : BExp T × A × S =>
          (t.1, Exp.seq (.act t.2.1) (sol t.2.2))))
        ++ (((body.initTrans.map (fun tr : BExp T × A × S =>
            (BExp.and guard tr.1, tr.2.1, tr.2.2))).map
            (fun t : BExp T × A × S =>
              (t.1, Exp.seq (.act t.2.1) (sol t.2.2)))).map
          (fun b : BExp T × Exp A T =>
            (BExp.and (body.core.hlt s) b.1, b.2)))
    rw [List.map_append, List.map_map, List.map_map, List.map_map]
    rfl
  rw [hsplit, guardedFold_append]
  refine EquivBA.trans (guardedFold_fallback_congr
    (guardedFold_guard_factor (body.core.hlt s) (.not guard) F
      (GkatKleene.transitionBranches
        (body.initTrans.map (fun tr =>
          (BExp.and guard tr.1, tr.2.1, tr.2.2))) sol))) ?_
  exact EquivBA.base (Equiv.refl _)

#print axioms loop_subsystem

open Classical in
/-- **THE SUM SUBSYSTEM EQUALITIES**: disjoint-union states keep their
    own side's parametric equations verbatim (the `ite` core is a sum;
    branching happens only at the init dispatch). -/
theorem sum_subsystem_inl {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T)
    (R : GkatThompson.GSystem S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (F : Exp A T) (s : S₁) :
    GkatThompson.eqRHSParam (GkatThompson.sumGSystem L R) sol F
        (.inl s)
      = GkatThompson.eqRHSParam L (fun t => sol (.inl t)) F s := by
  show GkatFaithful.guardedFold
      (((L.trans s).map (fun tr : BExp T × A × S₁ =>
        (tr.1, tr.2.1, Sum.inl tr.2.2))).map
        (fun t : BExp T × A × Sum S₁ S₂ =>
          (t.1, Exp.seq (.act t.2.1) (sol t.2.2))))
      (GkatThompson.paramFallback (L.hlt s) F)
    = GkatFaithful.guardedFold
      ((L.trans s).map (fun t : BExp T × A × S₁ =>
        (t.1, Exp.seq (.act t.2.1) (sol (.inl t.2.2)))))
      (GkatThompson.paramFallback (L.hlt s) F)
  rw [List.map_map]
  rfl

open Classical in
theorem sum_subsystem_inr {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T)
    (R : GkatThompson.GSystem S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (F : Exp A T) (s : S₂) :
    GkatThompson.eqRHSParam (GkatThompson.sumGSystem L R) sol F
        (.inr s)
      = GkatThompson.eqRHSParam R (fun t => sol (.inr t)) F s := by
  show GkatFaithful.guardedFold
      (((R.trans s).map (fun tr : BExp T × A × S₂ =>
        (tr.1, tr.2.1, Sum.inr tr.2.2))).map
        (fun t : BExp T × A × Sum S₁ S₂ =>
          (t.1, Exp.seq (.act t.2.1) (sol t.2.2))))
      (GkatThompson.paramFallback (R.hlt s) F)
    = GkatFaithful.guardedFold
      ((R.trans s).map (fun t : BExp T × A × S₂ =>
        (t.1, Exp.seq (.act t.2.1) (sol (.inr t.2.2)))))
      (GkatThompson.paramFallback (R.hlt s) F)
  rw [List.map_map]
  rfl

#print axioms sum_subsystem_inl
#print axioms sum_subsystem_inr

/-! ## The forced-solution theorem

    LOCATE turns out to be UNNECESSARY: `ParametricCanonicalBA` in each
    certificate speaks about the WHOLE program's flattened system at
    once, not about one nesting level, so a sum-solution restricted to
    one side is pinned without ever walking the syntax tree.  The
    ambient sum equation at an internal state IS that side's own
    parametric equation at finish `1` — the two branch lists fuse to
    the same list and the fallbacks differ by `s5` alone. -/

open Classical in
/-- The ambient equation of a left-injected internal state of a Thompson
    sum is that side's own parametric equation at finish `1`. -/
theorem sumGAut_toGAut_eqRHS_inl {S₁ S₂ : Type}
    (a₁ : GkatThompson.InitializedGAut S₁ A T)
    (a₂ : GkatThompson.InitializedGAut S₂ A T)
    (sol : (Option S₁ ⊕ Option S₂) → Exp A T) (s : S₁) :
    EquivBA
      (GkatKleene.eqRHS (GkatKleene.sumGAut a₁.toGAut a₂.toGAut) sol
        (.inl (some s)))
      (GkatThompson.eqRHSParam a₁.core (fun t => sol (.inl (some t)))
        (.test .one) s) := by
  have hbranch : GkatKleene.transitionBranches
      ((GkatKleene.sumGAut a₁.toGAut a₂.toGAut).trans (Sum.inl (some s))) sol
      = GkatKleene.transitionBranches (a₁.core.trans s)
          (fun t => sol (Sum.inl (some t))) := by
    show (((a₁.core.trans s).map (fun tr : BExp T × A × S₁ =>
          (tr.1, tr.2.1, (some tr.2.2 : Option S₁)))).map
        (fun t : BExp T × A × Option S₁ =>
          (t.1, t.2.1, (Sum.inl t.2.2 : Option S₁ ⊕ Option S₂)))).map
        (fun t : BExp T × A × (Option S₁ ⊕ Option S₂) =>
          (t.1, Exp.seq (.act t.2.1) (sol t.2.2)))
      = (a₁.core.trans s).map (fun t : BExp T × A × S₁ =>
          (t.1, Exp.seq (.act t.2.1) (sol (Sum.inl (some t.2.2)))))
    rw [List.map_map, List.map_map]
    rfl
  rw [GkatKleene.eqRHS_eq_guardedFold, hbranch]
  exact guardedFold_fallback_congr
    (EquivBA.symm (EquivBA.base (Equiv.s5 (.test (a₁.core.hlt s)))))

open Classical in
/-- The right-injected mirror. -/
theorem sumGAut_toGAut_eqRHS_inr {S₁ S₂ : Type}
    (a₁ : GkatThompson.InitializedGAut S₁ A T)
    (a₂ : GkatThompson.InitializedGAut S₂ A T)
    (sol : (Option S₁ ⊕ Option S₂) → Exp A T) (s : S₂) :
    EquivBA
      (GkatKleene.eqRHS (GkatKleene.sumGAut a₁.toGAut a₂.toGAut) sol
        (.inr (some s)))
      (GkatThompson.eqRHSParam a₂.core (fun t => sol (.inr (some t)))
        (.test .one) s) := by
  have hbranch : GkatKleene.transitionBranches
      ((GkatKleene.sumGAut a₁.toGAut a₂.toGAut).trans (Sum.inr (some s))) sol
      = GkatKleene.transitionBranches (a₂.core.trans s)
          (fun t => sol (Sum.inr (some t))) := by
    show (((a₂.core.trans s).map (fun tr : BExp T × A × S₂ =>
          (tr.1, tr.2.1, (some tr.2.2 : Option S₂)))).map
        (fun t : BExp T × A × Option S₂ =>
          (t.1, t.2.1, (Sum.inr t.2.2 : Option S₁ ⊕ Option S₂)))).map
        (fun t : BExp T × A × (Option S₁ ⊕ Option S₂) =>
          (t.1, Exp.seq (.act t.2.1) (sol t.2.2)))
      = (a₂.core.trans s).map (fun t : BExp T × A × S₂ =>
          (t.1, Exp.seq (.act t.2.1) (sol (Sum.inr (some t.2.2)))))
    rw [List.map_map, List.map_map]
    rfl
  rw [GkatKleene.eqRHS_eq_guardedFold, hbranch]
  exact guardedFold_fallback_congr
    (EquivBA.symm (EquivBA.base (Equiv.s5 (.test (a₂.core.hlt s)))))

open Classical in
/-- **THE FORCED-SOLUTION THEOREM**: ANY solution of the raw Thompson-sum
    equation system is, at every internal state of the left program's
    automaton, provably that state's canonical Thompson label.  No
    schedule, no elimination, no UA — and no choice of solution: the
    canonical labelling is the ONLY one the axioms permit. -/
theorem sum_solution_forced_left (e f : Exp A T)
    {sol : ((Option (GkatThompson.certifiedThompson A T e).State)
      ⊕ (Option (GkatThompson.certifiedThompson A T f).State)) → Exp A T}
    (hsol : GkatKleene.SolvesBA (GkatTrim.SUMof A T e f) sol) :
    ∀ s ∈ (GkatThompson.certifiedThompson A T e).aut.core.states,
      EquivBA (sol (.inl (some s)))
        ((GkatThompson.certifiedThompson A T e).standard s) := by
  have hparam := (GkatThompson.certifiedThompson A T e).certificate.parametric.states
    (.test .one) (fun t => sol (Sum.inl (some t))) (by
      intro state _
      exact EquivBA.trans (hsol (Sum.inl (some state))
          (GkatDecide.sumof_exhaustive e f _))
        (sumGAut_toGAut_eqRHS_inl _ _ sol state))
  intro s hs
  exact EquivBA.trans (hparam s hs)
    (EquivBA.base (Equiv.s5 ((GkatThompson.certifiedThompson A T e).standard s)))

open Classical in
/-- The right-side mirror of the forced-solution theorem. -/
theorem sum_solution_forced_right (e f : Exp A T)
    {sol : ((Option (GkatThompson.certifiedThompson A T e).State)
      ⊕ (Option (GkatThompson.certifiedThompson A T f).State)) → Exp A T}
    (hsol : GkatKleene.SolvesBA (GkatTrim.SUMof A T e f) sol) :
    ∀ s ∈ (GkatThompson.certifiedThompson A T f).aut.core.states,
      EquivBA (sol (.inr (some s)))
        ((GkatThompson.certifiedThompson A T f).standard s) := by
  have hparam := (GkatThompson.certifiedThompson A T f).certificate.parametric.states
    (.test .one) (fun t => sol (Sum.inr (some t))) (by
      intro state _
      exact EquivBA.trans (hsol (Sum.inr (some state))
          (GkatDecide.sumof_exhaustive e f _))
        (sumGAut_toGAut_eqRHS_inr _ _ sol state))
  intro s hs
  exact EquivBA.trans (hparam s hs)
    (EquivBA.base (Equiv.s5 ((GkatThompson.certifiedThompson A T f).standard s)))

open Classical in
/-- **RIGIDITY**: any two solutions of the raw Thompson sum agree, provably,
    at every internal state of both sides.  The solution space of the sum
    system is a single `EquivBA` class — so `RoleCovered` is NOT a free
    construction: whatever `qsol` it produces is forced to be the canonical
    labelling, and the dead-state obligations come with it. -/
theorem sum_solution_rigid (e f : Exp A T)
    {sol₁ sol₂ : ((Option (GkatThompson.certifiedThompson A T e).State)
      ⊕ (Option (GkatThompson.certifiedThompson A T f).State)) → Exp A T}
    (h₁ : GkatKleene.SolvesBA (GkatTrim.SUMof A T e f) sol₁)
    (h₂ : GkatKleene.SolvesBA (GkatTrim.SUMof A T e f) sol₂) :
    (∀ s ∈ (GkatThompson.certifiedThompson A T e).aut.core.states,
        EquivBA (sol₁ (.inl (some s))) (sol₂ (.inl (some s))))
      ∧ (∀ s ∈ (GkatThompson.certifiedThompson A T f).aut.core.states,
        EquivBA (sol₁ (.inr (some s))) (sol₂ (.inr (some s)))) := by
  refine ⟨fun s hs => ?_, fun s hs => ?_⟩
  · exact EquivBA.trans (sum_solution_forced_left e f h₁ s hs)
      (EquivBA.symm (sum_solution_forced_left e f h₂ s hs))
  · exact EquivBA.trans (sum_solution_forced_right e f h₁ s hs)
      (EquivBA.symm (sum_solution_forced_right e f h₂ s hs))

#print axioms sumGAut_toGAut_eqRHS_inl
#print axioms sumGAut_toGAut_eqRHS_inr
#print axioms sum_solution_forced_left
#print axioms sum_solution_forced_right
#print axioms sum_solution_rigid

/-! ## Existence is free; the whole problem is UNIF

    Iteration 112 recorded that demanding `SolvesBA` of the sum at the
    canonical labelling "reopens the dead-state circularity".  That was
    WRONG, and this section proves it wrong: a solution of the RAW sum
    at the canonical labelling exists outright (each side already solves
    its own system by `certifiedThompson_toGAut_solves`, and equations
    of a disjoint union are the summands' equations).  The circularity
    lives one step later — in TRIMMING, where dead labels must be shown
    to collapse to `0` — and trimming is what `solvesBA_untrim` already
    handles in the useful direction.

    Combined with rigidity, the picture is complete: the raw sum has a
    solution, that solution is unique up to `EquivBA`, and the ONLY
    remaining question is whether bisimilar states carry `EquivBA`-equal
    canonical labels. -/

/-- Equations of a disjoint union are the summands' own equations. -/
theorem eqRHS_sumGAut_inl {S₁ S₂ : Type} (a₁ : GkatKleene.GAut S₁ A T)
    (a₂ : GkatKleene.GAut S₂ A T)
    (sol : (S₁ ⊕ S₂) → Exp A T) (s : S₁) :
    GkatKleene.eqRHS (GkatKleene.sumGAut a₁ a₂) sol (.inl s)
      = GkatKleene.eqRHS a₁ (fun t => sol (.inl t)) s := by
  show ((a₁.trans s).map (fun t : BExp T × A × S₁ =>
      (t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂)))).foldr
      (fun t acc => Exp.ite t.1 (Exp.seq (.act t.2.1) (sol t.2.2)) acc)
      (Exp.test (a₁.hlt s))
    = (a₁.trans s).foldr
      (fun t acc => Exp.ite t.1 (Exp.seq (.act t.2.1) (sol (.inl t.2.2))) acc)
      (Exp.test (a₁.hlt s))
  induction a₁.trans s with
  | nil => rfl
  | cons hd tl ih =>
      show Exp.ite hd.1 (.seq (.act hd.2.1) (sol (.inl hd.2.2))) _
        = Exp.ite hd.1 (.seq (.act hd.2.1) (sol (.inl hd.2.2))) _
      rw [ih]

/-- The right-injected mirror. -/
theorem eqRHS_sumGAut_inr {S₁ S₂ : Type} (a₁ : GkatKleene.GAut S₁ A T)
    (a₂ : GkatKleene.GAut S₂ A T)
    (sol : (S₁ ⊕ S₂) → Exp A T) (s : S₂) :
    GkatKleene.eqRHS (GkatKleene.sumGAut a₁ a₂) sol (.inr s)
      = GkatKleene.eqRHS a₂ (fun t => sol (.inr t)) s := by
  show ((a₂.trans s).map (fun t : BExp T × A × S₂ =>
      (t.1, t.2.1, (Sum.inr t.2.2 : S₁ ⊕ S₂)))).foldr
      (fun t acc => Exp.ite t.1 (Exp.seq (.act t.2.1) (sol t.2.2)) acc)
      (Exp.test (a₂.hlt s))
    = (a₂.trans s).foldr
      (fun t acc => Exp.ite t.1 (Exp.seq (.act t.2.1) (sol (.inr t.2.2))) acc)
      (Exp.test (a₂.hlt s))
  induction a₂.trans s with
  | nil => rfl
  | cons hd tl ih =>
      show Exp.ite hd.1 (.seq (.act hd.2.1) (sol (.inr hd.2.2))) _
        = Exp.ite hd.1 (.seq (.act hd.2.1) (sol (.inr hd.2.2))) _
      rw [ih]

/-- The canonical labelling of a program pair, across the Thompson sum. -/
def stdSum (e f : Exp A T) :
    ((Option (GkatThompson.certifiedThompson A T e).State)
      ⊕ (Option (GkatThompson.certifiedThompson A T f).State)) → Exp A T :=
  Sum.elim
    (GkatThompson.initializedStandard e
      (GkatThompson.certifiedThompson A T e).standard)
    (GkatThompson.initializedStandard f
      (GkatThompson.certifiedThompson A T f).standard)

/-- **EXISTENCE IS FREE**: the canonical labelling solves the raw Thompson
    sum's equation system outright — no schedule, no elimination, no UA,
    and (contra iteration 112) no dead-state obligation whatsoever. -/
theorem sum_solves_std (e f : Exp A T) :
    GkatKleene.SolvesBA (GkatTrim.SUMof A T e f) (stdSum e f) := by
  intro s _
  cases s with
  | inl o =>
      rw [show GkatKleene.eqRHS (GkatTrim.SUMof A T e f) (stdSum e f) (.inl o)
          = GkatKleene.eqRHS (GkatThompson.certifiedThompson A T e).aut.toGAut
              (fun t => stdSum e f (.inl t)) o from
        eqRHS_sumGAut_inl _ _ _ o]
      refine GkatThompson.certifiedThompson_toGAut_solves e o ?_
      cases o with
      | none => exact List.mem_cons_self ..
      | some x =>
          exact List.mem_cons_of_mem _
            (List.mem_map.mpr ⟨x, GkatDecide.thompson_exhaustive e x, rfl⟩)
  | inr o =>
      rw [show GkatKleene.eqRHS (GkatTrim.SUMof A T e f) (stdSum e f) (.inr o)
          = GkatKleene.eqRHS (GkatThompson.certifiedThompson A T f).aut.toGAut
              (fun t => stdSum e f (.inr t)) o from
        eqRHS_sumGAut_inr _ _ _ o]
      refine GkatThompson.certifiedThompson_toGAut_solves f o ?_
      cases o with
      | none => exact List.mem_cons_self ..
      | some x =>
          exact List.mem_cons_of_mem _
            (List.mem_map.mpr ⟨x, GkatDecide.thompson_exhaustive f x, rfl⟩)

/-- **THE WHOLE PROBLEM, IN ONE LINE**: if bisimilar states of the trimmed
    Thompson sum carry provably-equal canonical labels, GKAT completeness
    without the n-ary uniqueness axiom follows immediately — the two start
    states ARE the two programs, and `ule_iff_start_bisim` makes them
    bisimilar.  Every other component of the reduction is already proven. -/
theorem equivBA_of_unif (e f : Exp A T)
    (heq : GkatKleene.UniformLanguageEquivalent e f)
    (hunif : ∀ s t, GkatPlanExistence.GenBisimilar
        (GkatTrim.trimAut (GkatTrim.SUMof A T e f)) s t →
      EquivBA (stdSum e f s) (stdSum e f t)) :
    EquivBA e f :=
  hunif _ _ ((GkatDecide.ule_iff_start_bisim e f).mp heq)

#print axioms eqRHS_sumGAut_inl
#print axioms eqRHS_sumGAut_inr
#print axioms sum_solves_std
#print axioms equivBA_of_unif

/-! ## UNIF holds wherever the class graph is well-founded

    The fixpoint obstruction identified in iteration 114 is REAL but it
    is CONFINED.  Write `sol' := sol ∘ bisimRep` — the "label of my
    class representative" family.  It is class-consistent by
    construction (bisimilar states have EQUAL representatives, so the
    values are literally equal), which is exactly what
    `equation_transport` needs and what `sol` itself does not have.
    That gives a four-step chain

      sol x ≈ eqRHS sol x ≈ eqRHS sol' x ≈ eqRHS sol' (rep x)
            ≈ eqRHS sol (rep x) ≈ sol (rep x)

    whose two outer `≈`s are "sol solves" and whose two inner
    `eqRHS sol ↔ eqRHS sol'` conversions need UNIF only AT THE ARM
    TARGETS.  So along a strictly descending rank the induction closes
    and UNIF is a THEOREM — no uniqueness axiom, no schedules.  The
    residue is precisely the cyclic case: a class that can reach
    itself, where the arm targets do not descend. -/

/-- Arm-wise `EquivBA` congruence for equations. -/
theorem foldr_congr_equivBA {S : Type} (hlt : BExp T)
    {sol₁ sol₂ : S → Exp A T} :
    ∀ L : List (BExp T × A × S),
      (∀ e ∈ L, EquivBA (sol₁ e.2.2) (sol₂ e.2.2)) →
      EquivBA
        (L.foldr (fun t acc =>
          Exp.ite t.1 (Exp.seq (.act t.2.1) (sol₁ t.2.2)) acc) (.test hlt))
        (L.foldr (fun t acc =>
          Exp.ite t.1 (Exp.seq (.act t.2.1) (sol₂ t.2.2)) acc) (.test hlt)) := by
  intro L
  induction L with
  | nil => intro _; exact EquivBA.base (Equiv.refl _)
  | cons hd tl ih =>
      intro hL
      exact EquivBA.ite_c
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (hL hd (List.mem_cons_self ..)))
        (ih (fun e he => hL e (List.mem_cons_of_mem _ he)))

/-- Equations respect `EquivBA` at the arm targets. -/
theorem eqRHS_congr_equivBA {S : Type} (aut : GkatKleene.GAut S A T)
    {sol₁ sol₂ : S → Exp A T} (s : S)
    (h : ∀ e ∈ aut.trans s, EquivBA (sol₁ e.2.2) (sol₂ e.2.2)) :
    EquivBA (GkatKleene.eqRHS aut sol₁ s) (GkatKleene.eqRHS aut sol₂ s) :=
  foldr_congr_equivBA (aut.hlt s) (aut.trans s) h

/-- Representatives are idempotent. -/
theorem bisimRep_idem {S : Type} (aut : GkatKleene.GAut S A T) (s : S) :
    GkatPlanExistence.bisimRep aut (GkatPlanExistence.bisimRep aut s)
      = GkatPlanExistence.bisimRep aut s :=
  (GkatPlanExistence.bisimRep_coherent aut
    (GkatPlanExistence.bisimRep_bisim aut s)).symm

open Classical in
/-- **UNIF ON WELL-FOUNDED CLASS GRAPHS**: if every arm strictly descends
    a rank on classes, then every state's label is provably equal to its
    class representative's label — hence bisimilar states carry
    provably-equal labels.  The acyclic half of the open problem, with
    no uniqueness axiom anywhere. -/
theorem unif_of_wf {S : Type} [DecidableEq A] (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T)
    (hsolves : ∀ s : S, EquivBA (sol s) (GkatKleene.eqRHS aut sol s))
    (rank : S → Nat)
    (hdesc : ∀ s : S, ∀ e ∈ aut.trans s,
      rank (GkatPlanExistence.bisimRep aut e.2.2)
        < rank (GkatPlanExistence.bisimRep aut s)) :
    ∀ s : S, EquivBA (sol s)
      (sol (GkatPlanExistence.bisimRep aut s)) := by
  have hcons : ∀ u u' : S, GkatPlanExistence.GenBisimilar aut u u' →
      EquivBA (sol (GkatPlanExistence.bisimRep aut u))
        (sol (GkatPlanExistence.bisimRep aut u')) := by
    intro u u' hb
    rw [GkatPlanExistence.bisimRep_coherent aut hb]
    exact EquivBA.base (Equiv.refl _)
  intro s
  refine (InvImage.wf (fun x => rank (GkatPlanExistence.bisimRep aut x))
    Nat.lt_wfRel.wf).induction
    (C := fun x => EquivBA (sol x)
      (sol (GkatPlanExistence.bisimRep aut x))) s ?_
  intro x ih
  -- step 2: eqRHS sol x ≈ eqRHS (sol ∘ rep) x
  have hstep2 : EquivBA (GkatKleene.eqRHS aut sol x)
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t)) x) := by
    refine eqRHS_congr_equivBA aut x ?_
    intro e he
    exact ih e.2.2 (hdesc x e he)
  -- step 3: transport across the class
  have hstep3 : EquivBA
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t)) x)
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t))
        (GkatPlanExistence.bisimRep aut x)) :=
    equation_transport aut (GkatPlanExistence.bisimRep_bisim aut x) _ hcons
  -- step 4: back to sol at the representative
  have hstep4 : EquivBA
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t))
        (GkatPlanExistence.bisimRep aut x))
      (GkatKleene.eqRHS aut sol (GkatPlanExistence.bisimRep aut x)) := by
    refine eqRHS_congr_equivBA aut _ ?_
    intro e he
    refine EquivBA.symm (ih e.2.2 ?_)
    have hd := hdesc (GkatPlanExistence.bisimRep aut x) e he
    rw [bisimRep_idem aut x] at hd
    exact hd
  exact EquivBA.trans (hsolves x)
    (EquivBA.trans hstep2
      (EquivBA.trans hstep3
        (EquivBA.trans hstep4
          (EquivBA.symm (hsolves (GkatPlanExistence.bisimRep aut x))))))

open Classical in
/-- Bisimilar states carry provably-equal labels, on a well-founded
    class graph. -/
theorem unif_bisim_of_wf {S : Type} [DecidableEq A]
    (aut : GkatKleene.GAut S A T) (sol : S → Exp A T)
    (hsolves : ∀ s : S, EquivBA (sol s) (GkatKleene.eqRHS aut sol s))
    (rank : S → Nat)
    (hdesc : ∀ s : S, ∀ e ∈ aut.trans s,
      rank (GkatPlanExistence.bisimRep aut e.2.2)
        < rank (GkatPlanExistence.bisimRep aut s))
    {s t : S} (hb : GkatPlanExistence.GenBisimilar aut s t) :
    EquivBA (sol s) (sol t) := by
  refine EquivBA.trans (unif_of_wf aut sol hsolves rank hdesc s) ?_
  rw [GkatPlanExistence.bisimRep_coherent aut hb]
  exact EquivBA.symm (unif_of_wf aut sol hsolves rank hdesc t)

open Classical in
/-- The Thompson-sum instance: on an acyclic class graph, the canonical
    labels of bisimilar states of the RAW sum are provably equal. -/
theorem unif_sum_of_wf (e f : Exp A T) [DecidableEq A]
    (rank : ((Option (GkatThompson.certifiedThompson A T e).State)
      ⊕ (Option (GkatThompson.certifiedThompson A T f).State)) → Nat)
    (hdesc : ∀ s, ∀ arm ∈ (GkatTrim.SUMof A T e f).trans s,
      rank (GkatPlanExistence.bisimRep (GkatTrim.SUMof A T e f) arm.2.2)
        < rank (GkatPlanExistence.bisimRep (GkatTrim.SUMof A T e f) s))
    {s t : _} (hb : GkatPlanExistence.GenBisimilar
      (GkatTrim.SUMof A T e f) s t) :
    EquivBA (stdSum e f s) (stdSum e f t) :=
  unif_bisim_of_wf _ (stdSum e f)
    (fun x => sum_solves_std e f x (GkatDecide.sumof_exhaustive e f x))
    rank hdesc hb

#print axioms foldr_congr_equivBA
#print axioms eqRHS_congr_equivBA
#print axioms bisimRep_idem
#print axioms unif_of_wf
#print axioms unif_bisim_of_wf
#print axioms unif_sum_of_wf

/-! ## UNIF modulo cycles — the residue, formally isolated

    `unif_of_wf` asks every arm to descend.  That is more than needed:
    an arm is harmless as soon as UNIF ALREADY HOLDS AT ITS OWN TARGET,
    whether or not it descends.  Weakening the hypothesis to that
    disjunction turns "the cyclic case is what's left" from a plan into
    a theorem, and localizes the residue as tightly as it goes: not
    "arbitrary bisimilar pairs in a cyclic class", but "the targets of
    the arms that stay inside a class". -/

open Classical in
/-- **UNIF MODULO CYCLES**: UNIF holds as soon as every arm either
    strictly descends the class rank, or already satisfies UNIF at its
    own target.  Strictly stronger than `unif_of_wf`. -/
theorem unif_of_wf_mod_cycles {S : Type} [DecidableEq A]
    (aut : GkatKleene.GAut S A T) (sol : S → Exp A T)
    (hsolves : ∀ s : S, EquivBA (sol s) (GkatKleene.eqRHS aut sol s))
    (rank : S → Nat)
    (hstep : ∀ s : S, ∀ e ∈ aut.trans s,
      rank (GkatPlanExistence.bisimRep aut e.2.2)
          < rank (GkatPlanExistence.bisimRep aut s)
        ∨ EquivBA (sol e.2.2)
          (sol (GkatPlanExistence.bisimRep aut e.2.2))) :
    ∀ s : S, EquivBA (sol s)
      (sol (GkatPlanExistence.bisimRep aut s)) := by
  have hcons : ∀ u u' : S, GkatPlanExistence.GenBisimilar aut u u' →
      EquivBA (sol (GkatPlanExistence.bisimRep aut u))
        (sol (GkatPlanExistence.bisimRep aut u')) := by
    intro u u' hb
    rw [GkatPlanExistence.bisimRep_coherent aut hb]
    exact EquivBA.base (Equiv.refl _)
  intro s
  refine (InvImage.wf (fun x => rank (GkatPlanExistence.bisimRep aut x))
    Nat.lt_wfRel.wf).induction
    (C := fun x => EquivBA (sol x)
      (sol (GkatPlanExistence.bisimRep aut x))) s ?_
  intro x ih
  have hstep2 : EquivBA (GkatKleene.eqRHS aut sol x)
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t)) x) := by
    refine eqRHS_congr_equivBA aut x ?_
    intro e he
    rcases hstep x e he with hlt | hu
    · exact ih e.2.2 hlt
    · exact hu
  have hstep3 : EquivBA
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t)) x)
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t))
        (GkatPlanExistence.bisimRep aut x)) :=
    equation_transport aut (GkatPlanExistence.bisimRep_bisim aut x) _ hcons
  have hstep4 : EquivBA
      (GkatKleene.eqRHS aut
        (fun t => sol (GkatPlanExistence.bisimRep aut t))
        (GkatPlanExistence.bisimRep aut x))
      (GkatKleene.eqRHS aut sol (GkatPlanExistence.bisimRep aut x)) := by
    refine eqRHS_congr_equivBA aut _ ?_
    intro e he
    refine EquivBA.symm ?_
    rcases hstep (GkatPlanExistence.bisimRep aut x) e he with hlt | hu
    · refine ih e.2.2 ?_
      rw [bisimRep_idem aut x] at hlt
      exact hlt
    · exact hu
  exact EquivBA.trans (hsolves x)
    (EquivBA.trans hstep2
      (EquivBA.trans hstep3
        (EquivBA.trans hstep4
          (EquivBA.symm (hsolves (GkatPlanExistence.bisimRep aut x))))))

open Classical in
/-- Bisimilar states carry provably-equal labels, modulo cycles. -/
theorem unif_bisim_of_wf_mod_cycles {S : Type} [DecidableEq A]
    (aut : GkatKleene.GAut S A T) (sol : S → Exp A T)
    (hsolves : ∀ s : S, EquivBA (sol s) (GkatKleene.eqRHS aut sol s))
    (rank : S → Nat)
    (hstep : ∀ s : S, ∀ e ∈ aut.trans s,
      rank (GkatPlanExistence.bisimRep aut e.2.2)
          < rank (GkatPlanExistence.bisimRep aut s)
        ∨ EquivBA (sol e.2.2)
          (sol (GkatPlanExistence.bisimRep aut e.2.2)))
    {s t : S} (hb : GkatPlanExistence.GenBisimilar aut s t) :
    EquivBA (sol s) (sol t) := by
  refine EquivBA.trans
    (unif_of_wf_mod_cycles aut sol hsolves rank hstep s) ?_
  rw [GkatPlanExistence.bisimRep_coherent aut hb]
  exact EquivBA.symm (unif_of_wf_mod_cycles aut sol hsolves rank hstep t)

open Classical in
/-- **THE RESIDUE, ON THE THOMPSON SUM**: completeness of a program pair
    follows from UNIF at the in-class arm targets alone.  Everything
    else — existence, rigidity, acyclic unification, trimming,
    quotienting — is discharged. -/
theorem unif_sum_of_wf_mod_cycles (e f : Exp A T) [DecidableEq A]
    (rank : ((Option (GkatThompson.certifiedThompson A T e).State)
      ⊕ (Option (GkatThompson.certifiedThompson A T f).State)) → Nat)
    (hstep : ∀ s, ∀ arm ∈ (GkatTrim.SUMof A T e f).trans s,
      rank (GkatPlanExistence.bisimRep (GkatTrim.SUMof A T e f) arm.2.2)
          < rank (GkatPlanExistence.bisimRep (GkatTrim.SUMof A T e f) s)
        ∨ EquivBA (stdSum e f arm.2.2)
          (stdSum e f (GkatPlanExistence.bisimRep
            (GkatTrim.SUMof A T e f) arm.2.2)))
    {s t : _} (hb : GkatPlanExistence.GenBisimilar
      (GkatTrim.SUMof A T e f) s t) :
    EquivBA (stdSum e f s) (stdSum e f t) :=
  unif_bisim_of_wf_mod_cycles _ (stdSum e f)
    (fun x => sum_solves_std e f x (GkatDecide.sumof_exhaustive e f x))
    rank hstep hb

#print axioms unif_of_wf_mod_cycles
#print axioms unif_bisim_of_wf_mod_cycles
#print axioms unif_sum_of_wf_mod_cycles

/-! ## The elimination step, and exactly why it is conditional

    Kappé-Schmid-Silva: "there is no general method to transform a
    left-affine system with n+1 unknowns into one with n unknowns,
    even though this is possible in certain cases."  This section
    pins down WHICH cases, and proves the step for them.

    A left-affine system needs every unknown to sit in the position
    `guard → prefix · unknown`, with all guards read AT THE CURRENT
    STATE.  Eliminating `U` means solving its gathered equation by
    `w3` and substituting the closed form `(wh G B) · R` wherever `U`
    occurred, i.e. under an action: `a · (wh G B) · R`.

    * If `R` is `P · V` — a prefix times ONE unknown, no residual guard
      and no residual halt — then `a · (wh G B) · P · V` REASSOCIATES
      (s1) to `(a · (wh G B) · P) · V`: still `prefix · unknown`.  The
      system stays left-affine with one fewer unknown, and the new
      prefix is still productive because it is action-headed, so the
      next `w3` applies.  That is `elim_reduces` below.
    * If `R` branches — `ite h (b·V₁) (ite h' (b'·V₂) …)` — then the
      substituted form is `a · (wh G B) · (ite h …)`, and `h` is read
      AFTER `a` has executed.  No axiom moves a guard leftward past an
      ACTION: `u5` distributes a guard sitting at the FRONT
      (`(ite g p q)·r ≡ ite g (p·r) (q·r)`) and `test_seq_ite` commutes
      a guard past a TEST, but nothing commutes one past an action.
      Left-affineness is destroyed and the reduced system is outside
      the class `w3` can close.

    In Kleene algebra this cannot arise: choice is unconditional, so
    `a(p+q) = ap + aq` redistributes any branching back to the front.
    GKAT's choice is guarded — state-dependent — and that single
    difference is the whole obstruction.  It is also exactly what
    "skip-free"/"uniform exit" restrictions buy: they force `R` into
    the first shape. -/

/-- Any action-headed prefix is productive, so it can serve as a `w3`
    loop body downstream. -/
theorem productive_act_prefix (a : A) (Q : Exp A T) :
    EquivBA (.test (E (.seq (.act a) Q)) : Exp A T) (.test .zero) :=
  EquivBA.baTest (fun _ _ _ => rfl)

open Classical in
/-- **THE ELIMINATION STEP**: a state whose gathered equation is a
    self-loop followed by a UNIFORM single exit closes, by one `w3`, to
    a PREFIX times that exit. -/
theorem elim_to_prefix {G : BExp T} {B P U V : Exp A T}
    (hprod : EquivBA (.test (E B) : Exp A T) (.test .zero))
    (heq : EquivBA U (.ite G (.seq B U) (.seq P V))) :
    EquivBA U (.seq (.seq (.wh G B) P) V) :=
  EquivBA.trans (EquivBA.w3_ba hprod heq)
    (EquivBA.symm (EquivBA.base (Equiv.s1 (.wh G B) P V)))

open Classical in
/-- **LEFT-AFFINENESS IS PRESERVED**: substituting a prefix-form closed
    solution into an arm body yields another arm body. -/
theorem elim_affine_step (a : A) {Q U V : Exp A T}
    (h : EquivBA U (.seq Q V)) :
    EquivBA (.seq (.act a) U) (.seq (.seq (.act a) Q) V) :=
  EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) h)
    (EquivBA.symm (EquivBA.base (Equiv.s1 (.act a) Q V)))

open Classical in
/-- **n+1 → n, UNDER UNIFORM EXIT**: eliminating a uniform-exit unknown
    from a left-affine system yields a left-affine system with one
    fewer unknown, whose new prefix is still productive — so the next
    `w3` applies and the elimination can recurse.  This is the step the
    literature reports as missing in general; it is available exactly
    when the eliminated state's residual is a single prefixed exit. -/
theorem elim_reduces {G : BExp T} {B P U V : Exp A T} (a : A)
    (hprod : EquivBA (.test (E B) : Exp A T) (.test .zero))
    (heq : EquivBA U (.ite G (.seq B U) (.seq P V))) :
    EquivBA (.seq (.act a) U)
        (.seq (.seq (.act a) (.seq (.wh G B) P)) V)
      ∧ EquivBA
        (.test (E (.seq (.act a) (.seq (.wh G B) P))) : Exp A T)
        (.test .zero) :=
  ⟨elim_affine_step a (elim_to_prefix hprod heq),
    productive_act_prefix _ _⟩

open Classical in
/-- The eliminated unknown's own value is recovered by back-substitution
    once the exit is known — so a full elimination schedule reconstructs
    every original unknown, not just the last one. -/
theorem elim_back {G : BExp T} {B P U V : Exp A T}
    (hprod : EquivBA (.test (E B) : Exp A T) (.test .zero))
    (heq : EquivBA U (.ite G (.seq B U) (.seq P V)))
    {W : Exp A T} (hV : EquivBA V W) :
    EquivBA U (.seq (.seq (.wh G B) P) W) :=
  EquivBA.trans (elim_to_prefix hprod heq)
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hV)

#print axioms productive_act_prefix
#print axioms elim_to_prefix
#print axioms elim_affine_step
#print axioms elim_reduces
#print axioms elim_back

/-! ## The guarded patch

    Both measured two-port SCCs (iterations 118-119) have the same
    shape: the two classes' dispatches agree except at ONE atom.  The
    hand derivation for OPEN-SCC #3 produced `s0 ≈ ite α1 p s1` from
    that agreement alone.  This section proves the general fact behind
    it — two states whose equations share a common tail below a guard
    differ by exactly one guarded patch — so the observation becomes a
    reusable brick rather than a per-instance trick.

    The point is that a patch relation costs NOTHING: it needs no
    uniqueness, no productivity, no elimination.  It relates two
    members of an SCC directly, which is what the unification route
    wants and the elimination route cannot use. -/

open Classical in
/-- **THE GUARDED PATCH LEMMA**: if two expressions satisfy equations
    that share a common tail `Q` below the same guard `G`, then each is
    the other patched at `G`. -/
theorem patch_of_common_tail {G : BExp T} {X Y Px Py Q : Exp A T}
    (hX : EquivBA X (.ite G Px Q))
    (hY : EquivBA Y (.ite G Py Q)) :
    EquivBA X (.ite G Px Y) := by
  refine EquivBA.trans hX (EquivBA.symm ?_)
  refine EquivBA.trans
    (EquivBA.ite_c (EquivBA.base (Equiv.refl Px)) hY) ?_
  refine EquivBA.trans
    (GkatFaithful.ite_else_restrict G G Px Py Q) ?_
  refine EquivBA.ite_c (EquivBA.base (Equiv.refl Px)) ?_
  refine EquivBA.trans
    (EquivBA.ite_guard (b := .and (.not G) G) (c := .zero) ?_) ?_
  · intro Z W v
    show (!GkatGS.bval W G v && GkatGS.bval W G v) = false
    cases GkatGS.bval W G v <;> rfl
  · exact EquivBA.base (GkatFaithful.ite_zero Py Q)

open Classical in
/-- The patch is symmetric: each side is the other patched at `G`. -/
theorem patch_symm {G : BExp T} {X Y Px Py Q : Exp A T}
    (hX : EquivBA X (.ite G Px Q))
    (hY : EquivBA Y (.ite G Py Q)) :
    EquivBA X (.ite G Px Y) ∧ EquivBA Y (.ite G Py X) :=
  ⟨patch_of_common_tail hX hY, patch_of_common_tail hY hX⟩

open Classical in
/-- **THE PATCH, AT THE AUTOMATON LEVEL**: two states whose dispatch
    lists share a common suffix and whose halts agree satisfy the patch
    relation under any solution — no hypotheses beyond solving.  This is
    the general form of iteration 119's `s0 ≈ ite α1 p s1`. -/
theorem dispatch_patch {S : Type} (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T) {u v : S}
    (hu : EquivBA (sol u) (GkatKleene.eqRHS aut sol u))
    (hv : EquivBA (sol v) (GkatKleene.eqRHS aut sol v))
    {g : BExp T} {a : A} {t : S} {common : List (BExp T × A × S)}
    {py : BExp T} {ay : A} {ty : S}
    (hlt : aut.hlt u = aut.hlt v)
    (htu : aut.trans u = (g, a, t) :: common)
    (htv : aut.trans v = (py, ay, ty) :: common)
    (hg : py = g) :
    EquivBA (sol u)
      (.ite g (.seq (.act a) (sol t)) (sol v)) := by
  subst hg
  refine patch_of_common_tail
      (Py := .seq (.act ay) (sol ty))
      (Q := GkatPlanExistence.foldTL sol (aut.hlt v) common) ?_ ?_
  · refine EquivBA.trans hu ?_
    rw [GkatPlanExistence.eqRHS_foldTL, htu, hlt]
    exact EquivBA.base (Equiv.refl _)
  · refine EquivBA.trans hv ?_
    rw [GkatPlanExistence.eqRHS_foldTL, htv]
    exact EquivBA.base (Equiv.refl _)

#print axioms patch_of_common_tail
#print axioms patch_symm
#print axioms dispatch_patch

/-! ## The loop-state solution is FORCED — and it is the shape
    elimination could never build

    Iteration 119 found that a two-port SCC reduces to a SINGLE-unknown
    equation `x ≈ ite g P (W·(ite h (q·x) r))` that `w3` cannot close,
    because `w3` needs the exit at the top and here it is reached only
    after `W` runs.  Decoding the source programs the harness printed
    shows what the actual solution looks like: NOT a freshly constructed
    `wh`, but the ORIGINAL program's loop, re-used —
    `(body residual) · (the loop's own re-entry)`.

    That is exactly what `loop_subsystem` plus per-body canonicity
    deliver, and this theorem states it: any parametric solution of a
    loop's equations is FORCED, state by state, to that shape.
    Elimination would have to invent the `wh`; canonicity hands it over.
    This is the concrete mechanism behind 119's conclusion that the
    unification route is strictly stronger than the elimination route. -/

open Classical in
/-- **THE LOOP-STATE SOLUTION IS FORCED**: every state inside a Thompson
    loop has its solution pinned to `body-residual · the loop's own
    re-entry dispatch`, for any ambient continuation `F`. -/
theorem loop_solution_canonical {S : Type} (guard : BExp T)
    (body : GkatThompson.InitializedGAut S A T) (bodyStd : S → Exp A T)
    (hcanon : GkatThompson.ParametricCanonicalBA body.core bodyStd)
    (sol : S → Exp A T) (F : Exp A T)
    (hsol : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol F) :
    ∀ s ∈ body.core.states, EquivBA (sol s)
      (.seq (bodyStd s)
        (GkatThompson.initRHSParam
          (GkatThompson.loopInitialized guard body) sol F)) := by
  refine hcanon _ sol ?_
  intro s hs
  exact EquivBA.trans (hsol s hs) (loop_subsystem guard body sol F s)

open Classical in
/-- **TWO SOLUTIONS OF A LOOP AGREE**, without any uniqueness axiom:
    both are forced to the same body-residual form, and their re-entry
    dispatches are built from themselves.  The n-unknown uniqueness that
    UA would supply, delivered for a Thompson loop by canonicity alone. -/
theorem loop_solutions_agree {S : Type} (guard : BExp T)
    (body : GkatThompson.InitializedGAut S A T) (bodyStd : S → Exp A T)
    (hcanon : GkatThompson.ParametricCanonicalBA body.core bodyStd)
    (sol₁ sol₂ : S → Exp A T) (F₁ F₂ : Exp A T)
    (h₁ : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol₁ F₁)
    (h₂ : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol₂ F₂)
    (hre : EquivBA
      (GkatThompson.initRHSParam
        (GkatThompson.loopInitialized guard body) sol₁ F₁)
      (GkatThompson.initRHSParam
        (GkatThompson.loopInitialized guard body) sol₂ F₂)) :
    ∀ s ∈ body.core.states, EquivBA (sol₁ s) (sol₂ s) := by
  intro s hs
  refine EquivBA.trans
    (loop_solution_canonical guard body bodyStd hcanon sol₁ F₁ h₁ s hs) ?_
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hre) ?_
  exact EquivBA.symm
    (loop_solution_canonical guard body bodyStd hcanon sol₂ F₂ h₂ s hs)

#print axioms loop_solution_canonical
#print axioms loop_solutions_agree

/-! ## The re-entry hypothesis, discharged

    `loop_solutions_agree` needs the two solutions' RE-ENTRY DISPATCHES
    to agree, and those are built from the solutions themselves — the
    same fixpoint, merely localized.  But `ParametricInitialBA`, which
    sits in every certificate, already evaluates a re-entry dispatch:
    for ANY parametric solution it equals `program · finish`.  Feeding
    both solutions through it collapses the re-entry obligation to the
    ambient continuations, and the fixpoint disappears entirely.

    The result is an INDUCTIVE ENGINE: two solutions of a loop agree at
    every body state as soon as their ambient continuations agree.
    Agreement propagates inward, from a program's outside to its
    innermost loop states, with no uniqueness axiom anywhere. -/

open Classical in
/-- **RE-ENTRY DISPATCHES AGREE WHEN CONTINUATIONS DO** — the fixpoint
    in `loop_solutions_agree`'s hypothesis is not a fixpoint at all. -/
theorem reentry_agree_of_finish {S : Type} (guard : BExp T)
    (body : GkatThompson.InitializedGAut S A T) (loopProgram : Exp A T)
    (hinit : GkatThompson.ParametricInitialBA
      (GkatThompson.loopInitialized guard body) loopProgram)
    (sol₁ sol₂ : S → Exp A T) (F₁ F₂ : Exp A T)
    (h₁ : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol₁ F₁)
    (h₂ : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol₂ F₂)
    (hF : EquivBA F₁ F₂) :
    EquivBA
      (GkatThompson.initRHSParam
        (GkatThompson.loopInitialized guard body) sol₁ F₁)
      (GkatThompson.initRHSParam
        (GkatThompson.loopInitialized guard body) sol₂ F₂) :=
  EquivBA.trans (hinit F₁ sol₁ h₁)
    (EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hF)
      (EquivBA.symm (hinit F₂ sol₂ h₂)))

open Classical in
/-- **THE INDUCTIVE ENGINE**: two parametric solutions of a Thompson
    loop agree at EVERY body state as soon as their ambient
    continuations agree.  No uniqueness axiom, no re-entry bookkeeping,
    no fixpoint — agreement simply propagates inward. -/
theorem loop_solutions_agree_of_finish {S : Type} (guard : BExp T)
    (body : GkatThompson.InitializedGAut S A T)
    (bodyStd : S → Exp A T) (loopProgram : Exp A T)
    (hcanon : GkatThompson.ParametricCanonicalBA body.core bodyStd)
    (hinit : GkatThompson.ParametricInitialBA
      (GkatThompson.loopInitialized guard body) loopProgram)
    (sol₁ sol₂ : S → Exp A T) (F₁ F₂ : Exp A T)
    (h₁ : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol₁ F₁)
    (h₂ : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol₂ F₂)
    (hF : EquivBA F₁ F₂) :
    ∀ s ∈ body.core.states, EquivBA (sol₁ s) (sol₂ s) :=
  loop_solutions_agree guard body bodyStd hcanon sol₁ sol₂ F₁ F₂ h₁ h₂
    (reentry_agree_of_finish guard body loopProgram hinit
      sol₁ sol₂ F₁ F₂ h₁ h₂ hF)

open Classical in
/-- The same collapse for the loop's own body labels: any parametric
    solution at continuation `F` is pinned to `bodyStd s · (loop
    program · F)` — the closed form named outright, with the re-entry
    already evaluated. -/
theorem loop_solution_closed {S : Type} (guard : BExp T)
    (body : GkatThompson.InitializedGAut S A T)
    (bodyStd : S → Exp A T) (loopProgram : Exp A T)
    (hcanon : GkatThompson.ParametricCanonicalBA body.core bodyStd)
    (hinit : GkatThompson.ParametricInitialBA
      (GkatThompson.loopInitialized guard body) loopProgram)
    (sol : S → Exp A T) (F : Exp A T)
    (hsol : GkatThompson.ParamSolvesBA
      (GkatThompson.loopInitialized guard body).core sol F) :
    ∀ s ∈ body.core.states,
      EquivBA (sol s) (.seq (bodyStd s) (.seq loopProgram F)) := by
  intro s hs
  refine EquivBA.trans
    (loop_solution_canonical guard body bodyStd hcanon sol F hsol s hs) ?_
  exact EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (hinit F sol hsol)

#print axioms reentry_agree_of_finish
#print axioms loop_solutions_agree_of_finish
#print axioms loop_solution_closed

/-! ## The partner retraction: same-side UNIF ⟹ a solution of the whole

    Iteration 122's conjecture, made precise and proved.  Instead of
    solving the quotient, RETRACT the disjoint union onto ONE side: let
    `π` send every state to a bisimilar state of a distinguished,
    arm-closed subset `S₀` on which the solution is already known, and
    on which `π` is the identity.  Then `sol ∘ π` solves EVERYTHING.

    The proof is three links and the middle one is the point.  At `π u`
    the family `sol ∘ π` agrees with `sol` LITERALLY — not up to
    `EquivBA` — because `S₀` is arm-closed and `π` fixes `S₀`, so every
    arm target of `π u` is already fixed.  That kills the usual
    circularity: no UNIF is needed to rewrite the equation at `π u`.
    Then `equation_transport` carries the equation from `π u` to `u`,
    which is legitimate because `sol ∘ π` is class-consistent — and THAT
    follows from same-side UNIF alone, since bisimilar `u, v` have
    `π u ~ u ~ v ~ π v` with both partners inside `S₀`.

    So the only genuinely new hypothesis is same-side UNIF on `S₀`. -/

open Classical in
/-- A partner-retracted family is class-consistent, given same-side
    UNIF on the retract.  No solving, no canonicity — just transitivity
    of bisimilarity. -/
theorem partner_class_consistent {S : Type}
    (aut : GkatKleene.GAut S A T) (sol : S → Exp A T)
    (S₀ : S → Prop) (π : S → S)
    (hmem : ∀ u, S₀ (π u))
    (hbis : ∀ u, GkatPlanExistence.GenBisimilar aut u (π u))
    (hsame : ∀ x y, S₀ x → S₀ y →
      GkatPlanExistence.GenBisimilar aut x y → EquivBA (sol x) (sol y)) :
    ∀ u v, GkatPlanExistence.GenBisimilar aut u v →
      EquivBA (sol (π u)) (sol (π v)) := by
  intro u v huv
  exact hsame _ _ (hmem u) (hmem v)
    (((hbis u).symm.trans huv).trans (hbis v))

open Classical in
/-- **THE PARTNER RETRACTION THEOREM**: if `S₀` is closed under arms,
    `π` retracts every state onto a bisimilar element of `S₀` and fixes
    `S₀`, `sol` solves on `S₀`, and same-side UNIF holds on `S₀`, then
    `sol ∘ π` solves the WHOLE automaton.

    Same-side UNIF is the only new input; everything else is structure.
    This is the reduction iteration 122 conjectured, now a theorem. -/
theorem solves_of_partner {S : Type} [DecidableEq A]
    (aut : GkatKleene.GAut S A T) (sol : S → Exp A T)
    (S₀ : S → Prop) (π : S → S)
    (hclosed : ∀ s, S₀ s → ∀ e ∈ aut.trans s, S₀ e.2.2)
    (hmem : ∀ u, S₀ (π u))
    (hbis : ∀ u, GkatPlanExistence.GenBisimilar aut u (π u))
    (hfix : ∀ s, S₀ s → π s = s)
    (hsolves : ∀ s, S₀ s → EquivBA (sol s) (GkatKleene.eqRHS aut sol s))
    (hsame : ∀ x y, S₀ x → S₀ y →
      GkatPlanExistence.GenBisimilar aut x y → EquivBA (sol x) (sol y)) :
    ∀ u, EquivBA (sol (π u))
      (GkatKleene.eqRHS aut (fun t => sol (π t)) u) := by
  have hcons := partner_class_consistent aut sol S₀ π hmem hbis hsame
  intro u
  have hstep1 : EquivBA (sol (π u)) (GkatKleene.eqRHS aut sol (π u)) :=
    hsolves _ (hmem u)
  have hstep2 : GkatKleene.eqRHS aut sol (π u)
      = GkatKleene.eqRHS aut (fun t => sol (π t)) (π u) := by
    refine GkatPlanExistence.eqRHS_congr aut (π u) ?_
    intro e he
    exact congrArg sol (hfix _ (hclosed _ (hmem u) e he)).symm
  rw [hstep2] at hstep1
  exact EquivBA.trans hstep1
    (equation_transport aut (hbis u).symm _ hcons)

open Classical in
/-- **CROSS-SIDE UNIF FROM SAME-SIDE UNIF**, on the Thompson sum: with
    a total partner map onto the left side, same-side UNIF there forces
    every RIGHT-side internal state's canonical label to equal its
    partner's.  The decomposition, discharged — modulo the partner map,
    whose existence for dead states is the one remaining gap. -/
theorem cross_unif_of_same_side (e f : Exp A T) [DecidableEq A]
    (π : ((Option (GkatThompson.certifiedThompson A T e).State)
        ⊕ (Option (GkatThompson.certifiedThompson A T f).State))
      → ((Option (GkatThompson.certifiedThompson A T e).State)
        ⊕ (Option (GkatThompson.certifiedThompson A T f).State)))
    (hmem : ∀ u, ∃ x, π u = .inl x)
    (hbis : ∀ u, GkatPlanExistence.GenBisimilar
      (GkatTrim.SUMof A T e f) u (π u))
    (hfix : ∀ x, π (.inl x) = .inl x)
    (hsame : ∀ x y, GkatPlanExistence.GenBisimilar
        (GkatTrim.SUMof A T e f) (.inl x) (.inl y) →
      EquivBA (stdSum e f (.inl x)) (stdSum e f (.inl y))) :
    ∀ s ∈ (GkatThompson.certifiedThompson A T f).aut.core.states,
      EquivBA (stdSum e f (π (.inr (some s))))
        ((GkatThompson.certifiedThompson A T f).standard s) := by
  refine sum_solution_forced_right e f (sol := fun t => stdSum e f (π t))
    (fun u _ => ?_)
  refine solves_of_partner (GkatTrim.SUMof A T e f) (stdSum e f)
    (fun z => ∃ x, z = .inl x) π ?_ ?_ hbis ?_ ?_ ?_ u
  · rintro s ⟨x, rfl⟩ arm harm
    have harm' : arm ∈
        ((GkatThompson.certifiedThompson A T e).aut.toGAut.trans x).map
          (fun t : BExp T × A
              × Option (GkatThompson.certifiedThompson A T e).State =>
            (t.1, t.2.1, (Sum.inl t.2.2 :
              (Option (GkatThompson.certifiedThompson A T e).State)
                ⊕ (Option (GkatThompson.certifiedThompson A T f).State)))) :=
      harm
    obtain ⟨y, _, hy2⟩ := List.mem_map.mp harm'
    exact ⟨y.2.2, (congrArg (fun t => t.2.2) hy2).symm⟩
  · exact hmem
  · rintro s ⟨x, rfl⟩; exact hfix x
  · rintro s ⟨x, rfl⟩
    exact sum_solves_std e f _ (GkatDecide.sumof_exhaustive e f _)
  · rintro x y ⟨a, rfl⟩ ⟨b, rfl⟩ hxy
    exact hsame a b hxy

#print axioms partner_class_consistent
#print axioms solves_of_partner
#print axioms cross_unif_of_same_side

/-! ## Standard-label projections: the interface for the size induction

    Same-side UNIF is now the sole mathematical input, and by iteration
    122's addendum it must be attacked by induction on program SIZE.
    That induction needs to read a compound program's standard labels
    off its subprograms' — and every such projection is DEFINITIONAL,
    because `certifiedThompson` is a structural recursion and each
    constructor's certificate carries the obvious labelling.

    Recording them as named `rfl` lemmas so the induction can cite them
    instead of unfolding constructors, and so the ONE fact the
    literature names as the canonical cause of same-side bisimilarity —
    duplicated subterms, `ite c p p` — is discharged outright. -/

/-- The left branch of an `ite` keeps its own labels. -/
theorem ite_standard_inl (c : BExp T) (p q : Exp A T)
    (s : (GkatThompson.certifiedThompson A T p).State) :
    (GkatThompson.certifiedThompson A T (.ite c p q)).standard (.inl s)
      = (GkatThompson.certifiedThompson A T p).standard s := rfl

/-- The right branch of an `ite` keeps its own labels. -/
theorem ite_standard_inr (c : BExp T) (p q : Exp A T)
    (s : (GkatThompson.certifiedThompson A T q).State) :
    (GkatThompson.certifiedThompson A T (.ite c p q)).standard (.inr s)
      = (GkatThompson.certifiedThompson A T q).standard s := rfl

/-- The left factor of a `seq` keeps its own labels. -/
theorem seq_standard_inl (p q : Exp A T)
    (s : (GkatThompson.certifiedThompson A T p).State) :
    (GkatThompson.certifiedThompson A T (.seq p q)).standard (.inl s)
      = .seq ((GkatThompson.certifiedThompson A T p).standard s) q := rfl

/-- A loop's labels are its body's labels FOLLOWED BY THE LOOP ITSELF.
    `loopInitialized` adds no states, but the labelling is not the
    body's verbatim: a body state's continuation includes re-entering
    the loop.  (Checked — the naive `= bodyStandard s` is NOT
    definitional, which is exactly the feedback showing up in the
    labelling rather than only in the arms.) -/
theorem wh_standard (g : BExp T) (b : Exp A T)
    (s : (GkatThompson.certifiedThompson A T b).State) :
    (GkatThompson.certifiedThompson A T (.wh g b)).standard s
      = .seq ((GkatThompson.certifiedThompson A T b).standard s)
        (.wh g b) := rfl

/-- **THE CANONICAL CAUSE OF SAME-SIDE BISIMILARITY IS FREE**: the two
    branches of a duplicated conditional carry LITERALLY EQUAL labels.
    The literature (position automata are non-reduced; partial-derivative
    automata are their bisimulation quotients) names duplicated subterms
    as the canonical source of distinct-but-bisimilar states in one
    expression's automaton — and for standard labels it costs nothing. -/
theorem dup_branch_standard_eq (c : BExp T) (p : Exp A T)
    (s : (GkatThompson.certifiedThompson A T p).State) :
    (GkatThompson.certifiedThompson A T (.ite c p p)).standard (.inl s)
      = (GkatThompson.certifiedThompson A T (.ite c p p)).standard (.inr s) :=
  rfl

open Classical in
/-- Consequently same-side UNIF is immediate for duplicated branches,
    at any pair of corresponding states. -/
theorem dup_branch_unif (c : BExp T) (p : Exp A T)
    (s : (GkatThompson.certifiedThompson A T p).State) :
    EquivBA
      ((GkatThompson.certifiedThompson A T (.ite c p p)).standard (.inl s))
      ((GkatThompson.certifiedThompson A T (.ite c p p)).standard (.inr s)) :=
  EquivBA.base (Equiv.refl _)

#print axioms ite_standard_inl
#print axioms ite_standard_inr
#print axioms seq_standard_inl
#print axioms wh_standard
#print axioms dup_branch_standard_eq
#print axioms dup_branch_unif

/-! ## The raw/trim scissors, and the single hypothesis that closes them

    Iteration 124's literature check said: don't extend a labelling from
    the live part, normalize the dead part away and work on the trim.
    Making that concrete exposes the gap in its sharpest form yet — a
    pair of scissors:

    * on the RAW sum we have SOLVING (`sum_solves_std`) but the
      bisimilarity we can get from `ULE` is about `trimAut`;
    * on the TRIM we have BISIMILARITY (`ule_iff_start_bisim`) but not
      solving, since `solvesBA_untrim` runs trim → raw and the reverse
      needs dead labels to collapse.

    `equation_transport` and the partner retraction need BOTH at once,
    on one automaton.  The theorem below closes the scissors from a
    single named hypothesis: **dead states carry provably-zero labels.**
    That is exactly the obligation
    `dead_thompson_label_eq_zero_of_complete` warns "any successful
    pruning proof must establish directly for Thompson labels" — and it
    is now the ONLY thing standing between the campaign's assembled
    machinery and a trim-based argument. -/

open Classical in
/-- **THE SCISSORS CLOSE**: a solution of the raw system whose DEAD
    states carry provably-zero labels also solves the TRIM.  The exact
    converse of `solvesBA_untrim`, with the dead-label collapse supplied
    as a hypothesis instead of extracted from a trim solution. -/
theorem solvesBA_trim_of_dead {S : Type} (aut : GkatKleene.GAut S A T)
    {sol : S → Exp A T}
    (hwf1 : ∀ s ∈ aut.states, ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) (aut.hlt s) α = true →
        GkatKleene.autStep (GkatPlanExistence.genW T) aut s α = none)
    (hdead : ∀ t, ¬ GkatPlanExistence.Live aut t →
      EquivBA (sol t) (.test .zero))
    (hsol : GkatKleene.SolvesBA aut sol) :
    GkatKleene.SolvesBA (GkatTrim.trimAut aut) sol := by
  intro s hs
  refine EquivBA.trans (hsol s hs) ?_
  have hd : ∀ e ∈ aut.trans s, ¬ GkatPlanExistence.Live aut e.2.2 →
      EquivBA (sol e.2.2) (.test .zero) := fun e _ hnl => hdead _ hnl
  have hexcl : ∀ e ∈ aut.trans s,
      GkatRingPlan.GuardEmpty (.and (aut.hlt s) e.1) := by
    intro e he X W x
    show (GkatGS.bval W (aut.hlt s) x && GkatGS.bval W e.1 x) = false
    rw [GkatPlanExistence.bval_gen W x (aut.hlt s),
      GkatPlanExistence.bval_gen W x e.1]
    cases hh : GkatGS.bval (GkatPlanExistence.genW T) (aut.hlt s)
        (fun u => W u x) with
    | false => rfl
    | true =>
        rw [GkatTrim.firstMatch_none_all
          (GkatPlanExistence.genW T) (hwf1 s hs _ hh) e he]
        rfl
  refine EquivBA.trans (EquivBA.symm (GkatTrim.not_zero_strip _)) ?_
  refine EquivBA.trans
    (GkatTrim.trim_fold_equiv aut (aut.trans s) .zero hd hexcl) ?_
  exact GkatTrim.not_zero_strip _

#print axioms solvesBA_trim_of_dead

open Classical in
/-- The per-arm form, which is the one an automaton-level liveness fact
    can actually discharge: only the DEAD TARGETS OF ARMS matter, not
    every dead state in the carrier.  Unreachable dead states with no
    incoming arm are irrelevant. -/
theorem solvesBA_trim_of_dead_arms {S : Type} (aut : GkatKleene.GAut S A T)
    {sol : S → Exp A T}
    (hwf1 : ∀ s ∈ aut.states, ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) (aut.hlt s) α = true →
        GkatKleene.autStep (GkatPlanExistence.genW T) aut s α = none)
    (hdead : ∀ s ∈ aut.states, ∀ e ∈ aut.trans s,
      ¬ GkatPlanExistence.Live aut e.2.2 →
        EquivBA (sol e.2.2) (.test .zero))
    (hsol : GkatKleene.SolvesBA aut sol) :
    GkatKleene.SolvesBA (GkatTrim.trimAut aut) sol := by
  intro s hs
  refine EquivBA.trans (hsol s hs) ?_
  have hexcl : ∀ e ∈ aut.trans s,
      GkatRingPlan.GuardEmpty (.and (aut.hlt s) e.1) := by
    intro e he X W x
    show (GkatGS.bval W (aut.hlt s) x && GkatGS.bval W e.1 x) = false
    rw [GkatPlanExistence.bval_gen W x (aut.hlt s),
      GkatPlanExistence.bval_gen W x e.1]
    cases hh : GkatGS.bval (GkatPlanExistence.genW T) (aut.hlt s)
        (fun u => W u x) with
    | false => rfl
    | true =>
        rw [GkatTrim.firstMatch_none_all
          (GkatPlanExistence.genW T) (hwf1 s hs _ hh) e he]
        rfl
  refine EquivBA.trans (EquivBA.symm (GkatTrim.not_zero_strip _)) ?_
  refine EquivBA.trans
    (GkatTrim.trim_fold_equiv aut (aut.trans s) .zero (hdead s hs) hexcl) ?_
  exact GkatTrim.not_zero_strip _

#print axioms solvesBA_trim_of_dead_arms

/-! ## The same-side induction: assembly is free, content is transfer

    With the standard-label projections of iteration 124 in hand, the
    ASSEMBLY half of a size induction on same-side UNIF costs nothing —
    each constructor's label is its subprogram's label in a fixed
    context, so agreement lifts by one `seq_c`.  The lemmas below are
    each a single congruence step.

    That is worth recording precisely because it localizes the
    difficulty: **all remaining content of same-side UNIF is
    BISIMILARITY TRANSFER** — knowing that two states bisimilar in a
    COMPOSITE's automaton are bisimilar in the SUBPROGRAM's automaton.
    For the sum (`ite`) that is immediate, the summands not interacting.
    For the loop it is the real question: `loopInitialized` adds
    feedback arms that both states must match, so loop-bisimilarity is a
    priori neither weaker nor stronger than body-bisimilarity, and the
    induction needs loop ⟹ body. -/

open Classical in
/-- Loop case, assembly half: body-label agreement lifts to the loop. -/
theorem wh_same_side_step (g : BExp T) (b : Exp A T)
    {s t : (GkatThompson.certifiedThompson A T b).State}
    (h : EquivBA ((GkatThompson.certifiedThompson A T b).standard s)
      ((GkatThompson.certifiedThompson A T b).standard t)) :
    EquivBA
      ((GkatThompson.certifiedThompson A T (.wh g b)).standard s)
      ((GkatThompson.certifiedThompson A T (.wh g b)).standard t) := by
  rw [wh_standard, wh_standard]
  exact EquivBA.seq_c h (EquivBA.base (Equiv.refl _))

open Classical in
/-- `ite`, same branch: branch-label agreement lifts verbatim. -/
theorem ite_same_side_inl_step (c : BExp T) (p q : Exp A T)
    {s t : (GkatThompson.certifiedThompson A T p).State}
    (h : EquivBA ((GkatThompson.certifiedThompson A T p).standard s)
      ((GkatThompson.certifiedThompson A T p).standard t)) :
    EquivBA
      ((GkatThompson.certifiedThompson A T (.ite c p q)).standard (.inl s))
      ((GkatThompson.certifiedThompson A T (.ite c p q)).standard (.inl t)) := by
  rw [ite_standard_inl, ite_standard_inl]
  exact h

open Classical in
/-- `ite`, CROSS branch: this is where a same-side instance consumes a
    CROSS-side instance on strictly smaller subprograms — the descent
    that makes the size induction well-founded. -/
theorem ite_same_side_cross_step (c : BExp T) (p q : Exp A T)
    {s : (GkatThompson.certifiedThompson A T p).State}
    {t : (GkatThompson.certifiedThompson A T q).State}
    (h : EquivBA ((GkatThompson.certifiedThompson A T p).standard s)
      ((GkatThompson.certifiedThompson A T q).standard t)) :
    EquivBA
      ((GkatThompson.certifiedThompson A T (.ite c p q)).standard (.inl s))
      ((GkatThompson.certifiedThompson A T (.ite c p q)).standard (.inr t)) := by
  rw [ite_standard_inl, ite_standard_inr]
  exact h

open Classical in
/-- `seq`, left factor: agreement lifts through the appended right
    program. -/
theorem seq_same_side_inl_step (p q : Exp A T)
    {s t : (GkatThompson.certifiedThompson A T p).State}
    (h : EquivBA ((GkatThompson.certifiedThompson A T p).standard s)
      ((GkatThompson.certifiedThompson A T p).standard t)) :
    EquivBA
      ((GkatThompson.certifiedThompson A T (.seq p q)).standard (.inl s))
      ((GkatThompson.certifiedThompson A T (.seq p q)).standard (.inl t)) := by
  rw [seq_standard_inl, seq_standard_inl]
  exact EquivBA.seq_c h (EquivBA.base (Equiv.refl _))

#print axioms wh_same_side_step
#print axioms ite_same_side_inl_step
#print axioms ite_same_side_cross_step
#print axioms seq_same_side_inl_step

/-! ## The clean form S0 will feed

    `solvesBA_trim_of_dead_arms` asks that DEAD arm targets carry
    provably-zero labels.  When there are no dead arm targets at all the
    hypothesis is VACUOUS, and the raw solution solves the trim outright
    — no dead-label obligation, no pruning algebra, nothing.

    That is the precise shape `NormalizationBridge` (S0) has to deliver,
    and it is worth stating separately because it is STRONGER than
    `LiveSteps`: `LiveSteps` constrains only FIRING steps, while this
    constrains every LISTED arm.  A shadowed arm — satisfiable guard, but
    always pre-empted by an earlier arm — can point at a dead state
    without ever firing, so `LiveSteps` alone does not discharge this.
    Recording the distinction so S0 is aimed at the right target. -/

open Classical in
/-- **NO DEAD ARM TARGETS ⟹ THE TRIM IS SOLVED**: with every listed
    arm pointing at a live state, a solution of the raw system solves
    the trimmed one, with no dead-label obligation whatsoever. -/
theorem solvesBA_trim_of_all_live {S : Type} (aut : GkatKleene.GAut S A T)
    {sol : S → Exp A T}
    (hwf1 : ∀ s ∈ aut.states, ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) (aut.hlt s) α = true →
        GkatKleene.autStep (GkatPlanExistence.genW T) aut s α = none)
    (hlive : ∀ s ∈ aut.states, ∀ e ∈ aut.trans s,
      GkatPlanExistence.Live aut e.2.2)
    (hsol : GkatKleene.SolvesBA aut sol) :
    GkatKleene.SolvesBA (GkatTrim.trimAut aut) sol :=
  solvesBA_trim_of_dead_arms aut hwf1
    (fun s hs e he hnl => absurd (hlive s hs e he) hnl) hsol

#print axioms solvesBA_trim_of_all_live

/-! ## Attacking S0 from the LABEL side: the emission scissors

    Iteration 129's addendum graded S0's automaton half as a second open
    problem, because deadness is an atom-indexed GREATEST FIXPOINT and
    that defeats structural induction over states.  But the obligation
    can also be met from the LABEL side, where this repo already has
    half the machinery: `outG_emits` (GkatNormalizationProofs) proves
    `g?·e ≡ g?·(e·(outG g e)?)` unconditionally — every GKAT program
    provably EMITS its output guard.

    The dead-label obligation's hard case is a product `X·Y` that is
    empty even though neither factor is: every `X`-string ends at an
    atom starting no `Y`-string.  That is exactly a guard-disjointness
    statement — `outG X` disjoint from `Y`'s INPUT guard — and given
    both emission facts it closes in six moves with no induction at all.

    The theorem below is that closing step, taking both emissions as
    hypotheses.  The output side is already supplied by `outG_emits`;
    what it names as still missing is the DUAL, an input-guard emission
    `Y ≡ (inG Y)?·Y`, which the repo does not yet have.  So this
    converts "S0's automaton half" into "build `inG` and its admission
    theorem", which IS a structural induction on expressions — the shape
    that worked for `outG` — rather than one on an atom-indexed
    greatest fixpoint over states. -/

open Classical in
/-- **THE EMISSION SCISSORS**: a product whose left factor's output
    guard is disjoint from its right factor's input guard is provably
    zero.  No induction, no uniqueness, no productivity — six moves. -/
theorem zero_of_emission_disjoint {X Y : Exp A T} {o i : BExp T}
    (hout : EquivBA X (.seq X (.test o)))
    (hin : EquivBA Y (.seq (.test i) Y))
    (hdisj : GkatRingPlan.GuardEmpty (.and o i)) :
    EquivBA (.seq X Y) (.test .zero) := by
  refine EquivBA.trans (EquivBA.seq_c hout hin) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.s1 X (.test o) _)) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl X))
    (EquivBA.symm (EquivBA.base (Equiv.s1 (.test o) (.test i) Y)))) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl X))
    (EquivBA.seq_c (EquivBA.s6 o i) (EquivBA.base (Equiv.refl Y)))) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl X))
    (EquivBA.seq_c (GkatNormalization.guard_zero_test hdisj)
      (EquivBA.base (Equiv.refl Y)))) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl X))
    (EquivBA.base (Equiv.s2 Y))) ?_
  exact EquivBA.base (Equiv.s3 X)

#print axioms zero_of_emission_disjoint

/-! ## The homomorphism partner: UNIF for free, when π commutes

    Iteration 129 localized the core difficulty to a structural
    mismatch: canonicity compares two SOLUTIONS, while UNIF compares two
    STATES of ONE solution.  The bridge between them is a second
    solution family built from the first — and `solves_of_partner`
    (iteration 123) builds one, but only by ASSUMING same-side UNIF.

    There is a second, independent sufficient condition, and it needs no
    UNIF at all: **if the partner map COMMUTES WITH THE STRUCTURE — a
    functional bisimulation / coalgebra homomorphism — then `sol ∘ σ`
    solves for free.**  Not up to `EquivBA`: the two equations are
    LITERALLY EQUAL, because retargeting the arm list and reindexing the
    solution are the same operation.  Canonicity then closes, giving
    UNIF along σ outright.

    That explains, retroactively, exactly why `solves_of_partner` needed
    `hsame`: its π was only required to LAND on a bisimilar state, never
    to commute.  Two sufficient conditions for the same conclusion, and
    they trade against each other — commuting is a strong demand on π
    but costs nothing else; landing-bisimilar is cheap but must be paid
    for with same-side UNIF. -/

/-- Retargeting an arm list and reindexing the solution are the same
    operation. -/
theorem foldTL_retarget {S : Type} (sol : S → Exp A T) (h : BExp T)
    (σ : S → S) :
    ∀ L : List (BExp T × A × S),
      GkatPlanExistence.foldTL sol h
          (L.map (fun e => (e.1, e.2.1, σ e.2.2)))
        = GkatPlanExistence.foldTL (fun t => sol (σ t)) h L := by
  intro L
  induction L with
  | nil => rfl
  | cons e rest ih =>
      exact congrArg
        (fun x => Exp.ite e.1 (.seq (.act e.2.1) (sol (σ e.2.2))) x) ih

open Classical in
/-- **THE HOMOMORPHISM PARTNER**: if `σ` commutes with halts and arms,
    then `sol ∘ σ` solves whenever `sol` does — with NO bisimilarity
    hypothesis, NO same-side UNIF, and NO arm-closure.  The two
    equations are literally equal, not merely equivalent. -/
theorem solves_of_hom {S : Type} (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T) (σ : S → S)
    (hhlt : ∀ s, aut.hlt (σ s) = aut.hlt s)
    (htrans : ∀ s, aut.trans (σ s)
      = (aut.trans s).map (fun e => (e.1, e.2.1, σ e.2.2)))
    (hsol : ∀ s, EquivBA (sol s) (GkatKleene.eqRHS aut sol s)) :
    ∀ s, EquivBA (sol (σ s))
      (GkatKleene.eqRHS aut (fun t => sol (σ t)) s) := by
  intro s
  refine EquivBA.trans (hsol (σ s)) ?_
  rw [GkatPlanExistence.eqRHS_foldTL, GkatPlanExistence.eqRHS_foldTL,
    hhlt, htrans, foldTL_retarget]
  exact EquivBA.base (Equiv.refl _)

#print axioms foldTL_retarget
#print axioms solves_of_hom

/-! ## Bisimilarity transfer for `ite`: the size induction's easy rung

    The size induction needs, at each constructor, that two states
    bisimilar in the COMPOSITE's automaton are bisimilar in the
    SUBPROGRAM's.  Iteration 128 refuted this for `wh` (the loop
    rewrites acceptance).  For `ite` the literature calls it immediate —
    summands are subcoalgebras — and here it is, proved.

    The `ite` core is literally `sumGSystem`, so a left-injected state's
    arms are the subprogram's arms retargeted through `Sum.inl` then
    `some`, while the subprogram's own are retargeted through `some`
    alone.  Both therefore run `firstMatch` over the SAME underlying
    list, in lockstep, and the halts coincide definitionally. -/

/-- `firstMatch` commutes with retargeting along ANY map — the existing
    `firstMatch_retarget` is endo-typed (`S' → S'`) and cannot cross
    `Sum.inl` or `some`. -/
theorem firstMatch_map {S₁ S₂ Atom : Type} (V : T → Atom → Bool)
    (x : Atom) (f : S₁ → S₂) :
    ∀ L : List (BExp T × A × S₁),
      GkatKleene.firstMatch V x (L.map (fun e => (e.1, e.2.1, f e.2.2)))
        = (GkatKleene.firstMatch V x L).map (fun y => (y.1, f y.2)) := by
  intro L
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, a, t⟩ := hd
      show (if GkatGS.bval V g x then some (a, f t) else _)
        = (if GkatGS.bval V g x then some (a, t) else _).map _
      by_cases hg : GkatGS.bval V g x
      · rw [if_pos hg, if_pos hg]; rfl
      · rw [if_neg hg, if_neg hg]; exact ih

/-- A core state's step, as a `firstMatch` over the core arm list. -/
theorem step_core (P : Exp A T)
    (s : (GkatThompson.certifiedThompson A T P).State) (α : T → Bool) :
    GkatKleene.autStep (GkatPlanExistence.genW T)
        (GkatThompson.certifiedThompson A T P).aut.toGAut (some s) α
      = (GkatKleene.firstMatch (GkatPlanExistence.genW T) α
          ((GkatThompson.certifiedThompson A T P).aut.core.trans s)).map
        (fun y => (y.1, some y.2)) :=
  firstMatch_map _ _ _ _

/-- A left-injected state's step in an `ite`, over the SAME list. -/
theorem step_ite_inl (c : BExp T) (p q : Exp A T)
    (s : (GkatThompson.certifiedThompson A T p).State) (α : T → Bool) :
    GkatKleene.autStep (GkatPlanExistence.genW T)
        (GkatThompson.certifiedThompson A T (.ite c p q)).aut.toGAut
        (some (.inl s)) α
      = (GkatKleene.firstMatch (GkatPlanExistence.genW T) α
          ((GkatThompson.certifiedThompson A T p).aut.core.trans s)).map
        (fun y => (y.1, some (Sum.inl y.2))) := by
  show GkatKleene.firstMatch _ α
      (List.map (fun e => (e.1, e.2.1, (some e.2.2 : Option _)))
        (List.map (fun e => (e.1, e.2.1, (Sum.inl e.2.2 :
            (GkatThompson.certifiedThompson A T p).State
              ⊕ (GkatThompson.certifiedThompson A T q).State)))
          ((GkatThompson.certifiedThompson A T p).aut.core.trans s))) = _
  rw [firstMatch_map, firstMatch_map]
  cases GkatKleene.firstMatch (GkatPlanExistence.genW T) α
    ((GkatThompson.certifiedThompson A T p).aut.core.trans s) <;> rfl

open Classical in
/-- **`ite` REFLECTS BISIMILARITY into its left branch.** -/
theorem ite_bisim_reflect_inl (c : BExp T) (p q : Exp A T)
    {s t : (GkatThompson.certifiedThompson A T p).State}
    (h : GkatPlanExistence.GenBisimilar
      (GkatThompson.certifiedThompson A T (.ite c p q)).aut.toGAut
      (some (.inl s)) (some (.inl t))) :
    GkatPlanExistence.GenBisimilar
      (GkatThompson.certifiedThompson A T p).aut.toGAut (some s) (some t) := by
  refine ⟨fun x y => ∃ s' t', x = some s' ∧ y = some t' ∧
      GkatPlanExistence.GenBisimilar
        (GkatThompson.certifiedThompson A T (.ite c p q)).aut.toGAut
        (some (.inl s')) (some (.inl t')), ?_, ⟨s, t, rfl, rfl, h⟩⟩
  rintro x y ⟨s', t', rfl, rfl, hb⟩
  obtain ⟨h1, h2, h3⟩ := GkatPlanExistence.genBisimilar_bisim _ _ _ hb
  refine ⟨h1, ?_, ?_⟩
  · intro α a u hstep
    rw [step_core] at hstep
    cases hfm : GkatKleene.firstMatch (GkatPlanExistence.genW T) α
        ((GkatThompson.certifiedThompson A T p).aut.core.trans s') with
    | none => rw [hfm] at hstep; exact nomatch hstep
    | some y =>
        rw [hfm] at hstep
        have hy := Option.some.inj hstep
        have ha : y.1 = a := congrArg Prod.fst hy
        have hu : some y.2 = u := congrArg Prod.snd hy
        have hcs := h2 α a (some (Sum.inl y.2))
          (by rw [step_ite_inl, hfm, ← ha]; rfl)
        obtain ⟨v, hv, hbv⟩ := hcs
        rw [step_ite_inl] at hv
        cases hfm2 : GkatKleene.firstMatch (GkatPlanExistence.genW T) α
            ((GkatThompson.certifiedThompson A T p).aut.core.trans t') with
        | none => rw [hfm2] at hv; exact nomatch hv
        | some z =>
            rw [hfm2] at hv
            have hz := Option.some.inj hv
            have hza : z.1 = a := congrArg Prod.fst hz
            refine ⟨some z.2, ?_, ?_⟩
            · rw [step_core, hfm2]
              show some (z.1, some z.2) = some (a, some z.2)
              rw [hza]
            refine ⟨y.2, z.2, hu.symm, rfl, ?_⟩
            have : some (Sum.inl z.2) = v := congrArg Prod.snd hz
            rw [← this] at hbv
            exact hbv
  · intro α a u hstep
    rw [step_core] at hstep
    cases hfm : GkatKleene.firstMatch (GkatPlanExistence.genW T) α
        ((GkatThompson.certifiedThompson A T p).aut.core.trans t') with
    | none => rw [hfm] at hstep; exact nomatch hstep
    | some y =>
        rw [hfm] at hstep
        have hy := Option.some.inj hstep
        have ha : y.1 = a := congrArg Prod.fst hy
        have hu : some y.2 = u := congrArg Prod.snd hy
        have hcs := h3 α a (some (Sum.inl y.2))
          (by rw [step_ite_inl, hfm, ← ha]; rfl)
        obtain ⟨v, hv, hbv⟩ := hcs
        rw [step_ite_inl] at hv
        cases hfm2 : GkatKleene.firstMatch (GkatPlanExistence.genW T) α
            ((GkatThompson.certifiedThompson A T p).aut.core.trans s') with
        | none => rw [hfm2] at hv; exact nomatch hv
        | some z =>
            rw [hfm2] at hv
            have hz := Option.some.inj hv
            have hza : z.1 = a := congrArg Prod.fst hz
            refine ⟨some z.2, ?_, ?_⟩
            · rw [step_core, hfm2]
              show some (z.1, some z.2) = some (a, some z.2)
              rw [hza]
            refine ⟨z.2, y.2, rfl, hu.symm, ?_⟩
            have : some (Sum.inl z.2) = v := congrArg Prod.snd hz
            rw [← this] at hbv
            exact hbv

#print axioms firstMatch_map
#print axioms step_core
#print axioms step_ite_inl
#print axioms ite_bisim_reflect_inl

/-! ## The scissors, restated against `prune` — no `inG` needed

    Iteration 130 re-routed S0's dead-label obligation from states to
    labels via `zero_of_emission_disjoint`, and named the missing piece
    as `inG`, an INPUT-guard dual to `outG`.  Working that out shows the
    fixpoint 129 identified does not actually disappear under that
    re-routing — it MOVES.  A tight `inG` for `wh b e` asks "from which
    atoms does this loop terminate", which is a genuine fixpoint, the
    same atom-indexed one.  (The OUTPUT side is fine: `wh_emits_exit_all`
    gives a loop's output guard as exactly `¬b`, tight and cheap.  It is
    the INPUT side that carries the fixpoint.)

    But `inG` is avoidable.  The repo already HAS the guard-relative
    deadness detector — `prune` — with `prune_equiv` proving
    `g?·e ≡ g?·(prune g e)` unconditionally.  So the scissors can be
    restated to consume `prune g Y = 0` directly, and the obligation
    becomes a COMPLETENESS property of an existing function rather than
    the construction of a new one. -/

open Classical in
/-- **THE SCISSORS, VIA `prune`**: if `X` emits `g` and `Y` prunes to
    zero under `g`, then `X·Y` is provably zero.  No input guard, no new
    construction — `prune_equiv` does the work. -/
theorem zero_of_prune_zero {X Y : Exp A T} {g : BExp T}
    (hout : EquivBA X (.seq X (.test g)))
    (hprune : GkatNormalization.prune g Y = (.test .zero : Exp A T)) :
    EquivBA (.seq X Y) (.test .zero) := by
  refine EquivBA.trans (EquivBA.seq_c hout (EquivBA.base (Equiv.refl Y))) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.s1 X (.test g) Y)) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl X))
    (GkatNormalization.prune_equiv Y g)) ?_
  rw [hprune]
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl X))
    (EquivBA.base (Equiv.s3 (.test g)))) ?_
  exact EquivBA.base (Equiv.s3 X)

#print axioms zero_of_prune_zero

/-! ## The loop case of dead-label-zero, by divergence region

    Iteration 134 localized S0's fixpoint to loop INPUT guards: "from
    which atoms does this loop diverge" is a greatest fixpoint, not a
    structural property.  But the fixpoint need not be COMPUTED — it can
    be supplied as a parameter and CERTIFIED by two guard implications,
    and then the loop's deadness on it is provable outright.

    Given a region `D` with (i) `D ⊆ b` — the loop never exits inside
    `D` — and (ii) `outG D e ⊆ D` — one pass of the body stays inside
    `D` — the loop provably diverges on `D`.  Unroll by `w1`, kill the
    exit arm by (i), emit the output guard by `outG_emits`, re-absorb it
    into `D` by (ii), and the result is `X ≈ BODY · X` with NO exit
    branch — a Salomaa equation whose fallback is `0`.  One `w3` closes
    it, and `s3` collapses `(wh 1 BODY)·0` to `0`.

    So the greatest fixpoint becomes a CERTIFICATE rather than a
    construction: whoever knows the divergence region hands over two
    implications, and the algebra does the rest with no UA. -/

open Classical in
/-- **DIVERGENCE REGIONS ARE PROVABLY ZERO**: a loop that cannot exit
    inside `D` and whose body maps `D` back into `D` is provably `0` on
    `D` — the loop case of the dead-label obligation, with the fixpoint
    supplied as a certificate. -/
theorem diverging_region_zero {D b : BExp T} {e : Exp A T}
    (hprod : GkatRingPlan.GuardEmpty (E e))
    (hDb : GuardImplies D b)
    (hstable : GuardImplies (GkatNormalization.outG D e) D) :
    EquivBA (.seq (.test D) (.wh b e) : Exp A T) (.test .zero) := by
  have hX : EquivBA (.seq (.test D) (.wh b e) : Exp A T)
      (.seq (.seq (.test D) (.seq e (.test (GkatNormalization.outG D e))))
        (.seq (.test D) (.wh b e))) := by
    -- unroll, then kill the exit arm using D ⊆ b
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.base (Equiv.w1 b e))) ?_
    refine EquivBA.trans
      (GkatGuardedAlgebra.test_seq_ite_of_implies _ _ hDb) ?_
    -- D?·(e·W) : emit the output guard, then re-absorb it into D
    refine EquivBA.trans
      (EquivBA.symm (EquivBA.base (Equiv.s1 (.test D) e (.wh b e)))) ?_
    refine EquivBA.trans (EquivBA.seq_c
      (GkatNormalization.outG_emits e D) (EquivBA.base (Equiv.refl _))) ?_
    refine EquivBA.trans (EquivBA.base
      (Equiv.s1 (.test D) (.seq e (.test (GkatNormalization.outG D e)))
        (.wh b e))) ?_
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.trans (EquivBA.base
          (Equiv.s1 e (.test (GkatNormalization.outG D e)) (.wh b e)))
        (EquivBA.seq_c (EquivBA.base (Equiv.refl e))
          (EquivBA.symm (GkatTrim.test_absorb_left hstable (.wh b e)))))) ?_
    refine EquivBA.symm (EquivBA.trans
      (EquivBA.base (Equiv.s1 (.test D)
        (.seq e (.test (GkatNormalization.outG D e)))
        (.seq (.test D) (.wh b e))))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.base (Equiv.s1 e
          (.test (GkatNormalization.outG D e))
          (.seq (.test D) (.wh b e))))))
  -- a Salomaa equation with no exit: w3 closes it against 0
  have hprodBody : EquivBA
      (.test (E (.seq (.test D)
        (.seq e (.test (GkatNormalization.outG D e))))) : Exp A T)
      (.test .zero) := by
    refine EquivBA.baTest ?_
    intro Y W x
    show (GkatGS.bval W D x
        && (GkatGS.bval W (E e) x
          && GkatGS.bval W (GkatNormalization.outG D e) x))
      = GkatGS.bval W (.zero : BExp T) x
    rw [hprod Y W x]
    cases GkatGS.bval W D x <;> rfl
  refine EquivBA.trans (EquivBA.w3_ba (b := .one) (f := (.test .zero : Exp A T)) hprodBody ?_) ?_
  · refine EquivBA.trans hX ?_
    exact EquivBA.symm (GkatElim.ite_true_collapse (fun _ _ _ => rfl) _ _)
  · exact EquivBA.base (Equiv.s3 _)

#print axioms diverging_region_zero

end GkatCensus
