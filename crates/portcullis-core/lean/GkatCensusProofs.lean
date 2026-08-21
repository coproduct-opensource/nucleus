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

end GkatCensus
