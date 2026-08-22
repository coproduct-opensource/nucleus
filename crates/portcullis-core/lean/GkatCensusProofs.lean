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

/-! ## Degenerate-guard collapses for the two-loop program

    Iteration 138's audit found that `twoloops_complete` and
    `chordloops_complete` carry satisfiability hypotheses their four
    siblings do not, so "unconditional" was the wrong word for them.
    `chainloops_complete_free` shows the fix: handle degenerate guards
    by case analysis instead of assuming them away.

    These are the collapse lemmas that case analysis needs for
    `twoLoop b c q r = wh b ((wh c (act q)); act r)`.  Each degenerate
    guard sends the program to something already covered by an earlier
    stratum, which is why the hypotheses are removable rather than
    load-bearing. -/

open Classical in
/-- An unenterable outer guard makes the two-loop `skip`. -/
theorem twoLoop_b_unsat (c : BExp T) (q r : A) {b : BExp T}
    (h : ∀ α : T → Bool, GkatGS.bval (GkatPlanExistence.genW T) b α = false) :
    EquivBA (GkatTwoLoop.twoLoop b c q r) (.test .one) :=
  GkatChainFragment.wh_guard_semantic_zero _ h

open Classical in
/-- **When the two guards never hold together, the inner loop is
    invisible** and the two-loop collapses to an ATOMIC loop — a program
    already covered by `atomicloops_complete`.  This is the degenerate
    case that looks like it might hide content and does not. -/
theorem twoLoop_no_overlap {b c : BExp T} (q r : A)
    (h : ¬ ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true
        ∧ GkatGS.bval (GkatPlanExistence.genW T) c α = true) :
    EquivBA (GkatTwoLoop.twoLoop b c q r) (.wh b (.act r)) := by
  have hbc : GuardImplies b (.not c) := by
    intro X W x hb
    show (!GkatGS.bval W c x) = true
    rw [GkatPlanExistence.bval_gen W x c]
    cases hc : GkatGS.bval (GkatPlanExistence.genW T) c (fun t => W t x) with
    | false => rfl
    | true =>
        refine absurd ⟨fun t => W t x, ?_, hc⟩ h
        rw [← GkatPlanExistence.bval_gen W x b]; exact hb
  -- under `b`, the inner loop takes its exit branch immediately
  have hinner : EquivBA (.seq (.test b) (.wh c (.act q)) : Exp A T)
      (.seq (.test b) (.test .one)) := by
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.trans (EquivBA.base (Equiv.w1 c (.act q)))
        (EquivBA.base (Equiv.u2 c _ (.test .one))))) ?_
    exact GkatGuardedAlgebra.test_seq_ite_of_implies _ _ hbc
  -- so the body agrees with `act r` under `b`
  have hbody : EquivBA
      (.seq (.test b) (.seq (.wh c (.act q)) (.act r)) : Exp A T)
      (.seq (.test b) (.act r)) := by
    refine EquivBA.trans
      (EquivBA.symm (EquivBA.base (Equiv.s1 (.test b) (.wh c (.act q)) (.act r)))) ?_
    refine EquivBA.trans (EquivBA.seq_c hinner (EquivBA.base (Equiv.refl _))) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.s1 (.test b) (.test .one) (.act r))) ?_
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.base (Equiv.s4 (.act r)))
  exact GkatNormalization.wh_congr_under_guard
    (EquivBA.base (Equiv.refl _)) hbody

#print axioms twoLoop_b_unsat
#print axioms twoLoop_no_overlap

open Classical in
/-- **A LOOP WITH A VALID GUARD IS `0`, WITHOUT LOOP-GUARD TRANSPORT.**
    `wh_emits_exit_all` says every loop provably ends in its exit guard
    `¬b`; when `b` is valid that guard is `0`, and `s3` finishes.  No
    `EquivBA.wh_guard`, no productivity hypothesis, any body.

    This replaces the `wh_guard (c := .one)` idiom used throughout, and
    with it the whole development's use of loop-guard transport reduces
    to the two wrappers in `GkatChainFragmentProofs` — both of which
    have transport-free derivations too (`GkatGuardTransport.wh_zero_free`
    for the `0` case, this lemma for the `1` case). -/
theorem wh_valid_zero {b : BExp T} (e : Exp A T)
    (h : ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true) :
    EquivBA (.wh b e) (.test .zero) := by
  refine EquivBA.trans (GkatNormalization.wh_emits_exit_all b e) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
    (EquivBA.baTest (b := .not b) (c := .zero) ?_)) ?_
  · intro X W x
    show (!GkatGS.bval W b x) = GkatGS.bval W (.zero : BExp T) x
    rw [GkatPlanExistence.bval_gen W x b, h (fun t => W t x)]
    rfl
  · exact EquivBA.base (Equiv.s3 _)

#print axioms wh_valid_zero

open Classical in
/-- An outer guard that always holds makes the two-loop divergent, hence
    `0` — `wh_one_zero` needs no side condition at all. -/
theorem twoLoop_b_valid (c : BExp T) (q r : A) {b : BExp T}
    (h : ∀ α : T → Bool, GkatGS.bval (GkatPlanExistence.genW T) b α = true) :
    EquivBA (GkatTwoLoop.twoLoop b c q r) (.test .zero) := by
  exact wh_valid_zero _ h

open Classical in
/-- An inner guard that always holds makes the INNER loop divergent, so
    the body is `0` and the whole two-loop is the test `¬b`. -/
theorem twoLoop_c_valid (b : BExp T) (q r : A) {c : BExp T}
    (h : ∀ α : T → Bool, GkatGS.bval (GkatPlanExistence.genW T) c α = true) :
    EquivBA (GkatTwoLoop.twoLoop b c q r) (.test (.not b)) := by
  have hinner : EquivBA (.wh c (.act q) : Exp A T) (.test .zero) := by
    exact wh_valid_zero _ h
  have hbody : EquivBA
      (.seq (.wh c (.act q)) (.act r) : Exp A T) (.test .zero) :=
    EquivBA.trans (EquivBA.seq_c hinner (EquivBA.base (Equiv.refl _)))
      (EquivBA.base (Equiv.s2 (.act r)))
  exact EquivBA.trans (EquivBA.wh_c hbody)
    (GkatNormalization.wh_test_collapse b .zero)

#print axioms twoLoop_b_valid
#print axioms twoLoop_c_valid

/-! ## Step 1 of the vacuity argument, formalized

    Iteration 142 derived by hand that the mixed degenerate case of
    `twoloops_complete_free` is impossible, in four steps.  Its FIRST
    step — that language-equivalent loops must have pointwise-equal
    guards — is not special to two-loops at all: it holds for ANY two
    loops, because a loop accepts an action-free guarded string exactly
    where its guard fails, and nothing about the body enters.

    The repo already had both halves of that equivalence without ever
    stating it: `InLoop_nil` gives one direction and the `InLoop.exit`
    constructor the other. -/

/-- **A loop accepts an action-free string exactly where its guard
    fails.**  The body is irrelevant. -/
theorem wh_den_nil {Atom : Type} (V : T → Atom → Bool) (b : BExp T)
    (e : Exp A T) (a : Atom) :
    GkatGS.den V (.wh b e) (a, []) ↔ GkatGS.bval V b a = false :=
  ⟨fun h => GkatGS.InLoop_nil V h rfl, fun h => GkatGS.InLoop.exit a h⟩

/-- **STEP 1, in full generality**: language-equivalent loops have
    pointwise-equal guards — whatever their bodies.  Iteration 142's
    `b₁ ≡ b₂`, and it needed neither side to be a two-loop. -/
theorem wh_guards_agree_of_ule {b₁ b₂ : BExp T} {e₁ e₂ : Exp A T}
    (h : GkatKleene.UniformLanguageEquivalent (.wh b₁ e₁) (.wh b₂ e₂)) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W b₁ x = GkatGS.bval W b₂ x := by
  intro X W x
  have hiff : GkatGS.bval W b₁ x = false ↔ GkatGS.bval W b₂ x = false :=
    Iff.trans (wh_den_nil W b₁ e₁ x).symm
      (Iff.trans (h X W (x, [])) (wh_den_nil W b₂ e₂ x))
  cases h₁ : GkatGS.bval W b₁ x with
  | false => exact (hiff.mp h₁).symm
  | true =>
      cases h₂ : GkatGS.bval W b₂ x with
      | false =>
          have := hiff.mpr h₂
          rw [h₁] at this
          exact nomatch this
      | true => rfl

#print axioms wh_den_nil
#print axioms wh_guards_agree_of_ule

/-! ## Step 3: the structural core of the vacuity argument

    Iteration 142's step 3 said side 2 "cannot halt mid-body".  Stated
    positively and without reference to any comparison: **at an atom
    where BOTH guards hold, a two-loop's accepted strings carry at
    least TWO actions.**  The inner loop must fire at least once
    (`wh_den_nil`, contrapositive) and the body's tail `act r` always
    fires exactly once, so the first outer iteration alone already owes
    two.

    That is what makes the mixed case impossible: an atomic loop emits
    ONE action per iteration and can halt straight after, so it accepts
    one-action strings the two-loop cannot. -/

open Classical in
/-- **A two-loop entered with both guards true owes at least two
    actions.** -/
theorem twoLoop_two_actions {Atom : Type} (V : T → Atom → Bool)
    (b c : BExp T) (q r : A) (a : Atom)
    (hb : GkatGS.bval V b a = true) (hc : GkatGS.bval V c a = true)
    (l : List (A × Atom))
    (h : GkatGS.den V (GkatTwoLoop.twoLoop b c q r) (a, l)) :
    2 ≤ l.length := by
  have h' : GkatGS.InLoop V b
      (GkatGS.den V (GkatTwoLoop.twoLoopBody c q r)) (a, l) := h
  cases h' with
  | exit a hexit => rw [hexit] at hb; exact nomatch hb
  | step a l1 rest _ hbody _ =>
      obtain ⟨m1, m2, hsplit, hinner, htail⟩ := hbody
      -- the tail action fires exactly once
      obtain ⟨a2, b2, htail'⟩ := htail
      have hm2 : m2 = [(r, b2)] := congrArg Prod.snd htail'
      -- the inner loop cannot be silent, since `c` holds here
      have hm1 : m1 ≠ [] := by
        intro hnil
        have := (wh_den_nil V c (.act q) a).mp (by rw [← hnil]; exact hinner)
        rw [this] at hc
        exact nomatch hc
      have hlen1 : 1 ≤ m1.length := by
        cases m1 with
        | nil => exact absurd rfl hm1
        | cons _ _ => exact Nat.succ_le_succ (Nat.zero_le _)
      have hsplit' : l1 = m1 ++ m2 := hsplit
      have hl1 : 2 ≤ l1.length := by
        rw [hsplit', List.length_append, hm2]
        exact Nat.succ_le_succ hlen1
      rw [List.length_append]
      exact Nat.le_trans hl1 (Nat.le_add_right _ _)

#print axioms twoLoop_two_actions

open Classical in
/-- **An atomic loop emits exactly ONE action and can stop.**  The other
    half of the contradiction: where the guard holds now and fails next,
    a one-action string is accepted. -/
theorem atomicLoop_one_action {Atom : Type} (V : T → Atom → Bool)
    (b : BExp T) (r : A) (a a₁ : Atom)
    (hb : GkatGS.bval V b a = true) (hb₁ : GkatGS.bval V b a₁ = false) :
    GkatGS.den V (.wh b (.act r)) (a, [(r, a₁)]) := by
  have hstep : GkatGS.InLoop V b (GkatGS.den V (.act r : Exp A T))
      (a, [(r, a₁)] ++ []) :=
    GkatGS.InLoop.step a [(r, a₁)] [] hb ⟨a, a₁, rfl⟩
      (GkatGS.InLoop.exit a₁ hb₁)
  exact hstep

open Classical in
/-- **★ THE MIXED CASE IS VACUOUS ★** — iteration 142's four-step
    argument, assembled.  A no-overlap two-loop (an atomic loop) cannot
    be language-equivalent to a LIVE two-loop.

    Guards agree by `wh_guards_agree_of_ule`; at the both-guards witness
    the live side owes two actions while the atomic side emits one and
    stops; the exit atom needed to stop is supplied by the live side's
    own exit hypothesis, transported across the agreed guards. -/
theorem no_overlap_vs_live_absurd
    {b₁ b₂ c₂ : BExp T} {r₁ q₂ r₂ : A}
    (hule : GkatKleene.UniformLanguageEquivalent
      (.wh b₁ (.act r₁)) (GkatTwoLoop.twoLoop b₂ c₂ q₂ r₂))
    (hbc₂ : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b₂ α = true
        ∧ GkatGS.bval (GkatPlanExistence.genW T) c₂ α = true)
    (hexitB₂ : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b₂ α = false) :
    False := by
  -- step 1: the guards coincide
  have hguards := wh_guards_agree_of_ule hule (T → Bool)
    (GkatPlanExistence.genW T)
  obtain ⟨α, hb₂, hc₂⟩ := hbc₂
  obtain ⟨α₁, hx₂⟩ := hexitB₂
  have hb₁ : GkatGS.bval (GkatPlanExistence.genW T) b₁ α = true := by
    rw [hguards α]; exact hb₂
  have hx₁ : GkatGS.bval (GkatPlanExistence.genW T) b₁ α₁ = false := by
    rw [hguards α₁]; exact hx₂
  -- the atomic side accepts a ONE-action string
  have hone := atomicLoop_one_action (GkatPlanExistence.genW T)
    b₁ r₁ α α₁ hb₁ hx₁
  -- so the live side must too — but it owes two
  have htwo := twoLoop_two_actions (GkatPlanExistence.genW T)
    b₂ c₂ q₂ r₂ α hb₂ hc₂ [(r₁, α₁)]
    ((hule (T → Bool) (GkatPlanExistence.genW T) (α, [(r₁, α₁)])).mp hone)
  exact nomatch htwo

#print axioms atomicLoop_one_action
#print axioms no_overlap_vs_live_absurd

/-! ## The last non-mechanical ingredient: a live two-loop emits

    The remaining assembly cases pair a collapsed side that is a pure
    TEST against a LIVE two-loop.  A test accepts only action-free
    strings, so the contradiction needs a witness that a live two-loop
    accepts SOMETHING with an action — and its three liveness
    hypotheses supply exactly the atoms to build one: enter where both
    guards hold, leave the inner loop where `c` fails, leave the outer
    loop where `b` fails. -/

open Classical in
/-- **A live two-loop accepts a two-action string.**  Enter at `a`
    (both guards), exit the inner loop at `a₂` (`¬c`), exit the outer
    loop at `a₃` (`¬b`). -/
theorem twoLoop_live_accepts {Atom : Type} (V : T → Atom → Bool)
    (b c : BExp T) (q r : A) (a a₂ a₃ : Atom)
    (hb : GkatGS.bval V b a = true) (hc : GkatGS.bval V c a = true)
    (hc₂ : GkatGS.bval V c a₂ = false)
    (hb₃ : GkatGS.bval V b a₃ = false) :
    GkatGS.den V (GkatTwoLoop.twoLoop b c q r) (a, [(q, a₂), (r, a₃)]) := by
  have hinner : GkatGS.den V (.wh c (.act q) : Exp A T) (a, [(q, a₂)]) :=
    GkatGS.InLoop.step a [(q, a₂)] [] hc ⟨a, a₂, rfl⟩
      (GkatGS.InLoop.exit a₂ hc₂)
  have hbody : GkatGS.den V (GkatTwoLoop.twoLoopBody c q r)
      (a, [(q, a₂), (r, a₃)]) :=
    ⟨[(q, a₂)], [(r, a₃)], rfl, hinner, ⟨a₂, a₃, rfl⟩⟩
  exact GkatGS.InLoop.step a [(q, a₂), (r, a₃)] [] hb hbody
    (GkatGS.InLoop.exit a₃ hb₃)

open Classical in
/-- A test accepts no string that performs an action. -/
theorem test_no_action {Atom : Type} (V : T → Atom → Bool) (t : BExp T)
    {a : Atom} {l : List (A × Atom)}
    (h : GkatGS.den V (.test t : Exp A T) (a, l)) : l = [] := h.2

open Classical in
/-- **A live two-loop is never a test.**  With `twoLoop_live_accepts`
    and `test_no_action`, the remaining mixed cases of
    `twoloops_complete_free` close the same way the no-overlap case
    does. -/
theorem live_twoLoop_ne_test {b c : BExp T} {q r : A} (t : BExp T)
    (hbc : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true
        ∧ GkatGS.bval (GkatPlanExistence.genW T) c α = true)
    (hexitC : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) c α = false)
    (hexitB : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hule : GkatKleene.UniformLanguageEquivalent
      (GkatTwoLoop.twoLoop b c q r) (.test t)) :
    False := by
  obtain ⟨α, hb, hc⟩ := hbc
  obtain ⟨α₂, hc₂⟩ := hexitC
  obtain ⟨α₃, hb₃⟩ := hexitB
  have hacc := twoLoop_live_accepts (GkatPlanExistence.genW T)
    b c q r α α₂ α₃ hb hc hc₂ hb₃
  have := test_no_action (GkatPlanExistence.genW T) t
    ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
  exact nomatch this

#print axioms twoLoop_live_accepts
#print axioms test_no_action
#print axioms live_twoLoop_ne_test

open Classical in
/-- A non-degenerate atomic loop is never a test either. -/
theorem live_atomicLoop_ne_test {b : BExp T} {r : A} (t : BExp T)
    (hsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true)
    (hexit : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hule : GkatKleene.UniformLanguageEquivalent
      (.wh b (.act r)) (.test t)) :
    False := by
  obtain ⟨α, hb⟩ := hsat
  obtain ⟨α₁, hb₁⟩ := hexit
  have hacc := atomicLoop_one_action (GkatPlanExistence.genW T) b r α α₁ hb hb₁
  have := test_no_action (GkatPlanExistence.genW T) t
    ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
  exact nomatch this

open Classical in
private theorem all_false_of_not_sat {b : BExp T}
    (h : ¬ ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true) :
    ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false := by
  intro α
  cases hb : GkatGS.bval (GkatPlanExistence.genW T) b α with
  | false => rfl
  | true => exact absurd ⟨α, hb⟩ h

open Classical in
private theorem all_true_of_not_exit {b : BExp T}
    (h : ¬ ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false) :
    ∀ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true := by
  intro α
  cases hb : GkatGS.bval (GkatPlanExistence.genW T) b α with
  | true => rfl
  | false => exact absurd ⟨α, hb⟩ h

open Classical in
/-- **THE TWO-LOOP TRICHOTOMY**: every two-loop is provably a TEST, or
    provably a NON-DEGENERATE ATOMIC LOOP, or LIVE.  This is the shape
    that turns `twoloops_complete_free`'s case analysis from a
    six-hypothesis scramble into a 3 × 3 table, with the four collapse
    lemmas of iterations 139-140 doing the work and the atomic branch's
    own degeneracies already pushed into the test branch. -/
theorem twoLoop_trichotomy (b c : BExp T) (q r : A) :
    (∃ t : BExp T, EquivBA (GkatTwoLoop.twoLoop b c q r) (.test t))
    ∨ (∃ (b' : BExp T) (r' : A),
        EquivBA (GkatTwoLoop.twoLoop b c q r) (.wh b' (.act r'))
          ∧ (∃ α : T → Bool,
              GkatGS.bval (GkatPlanExistence.genW T) b' α = true)
          ∧ (∃ α : T → Bool,
              GkatGS.bval (GkatPlanExistence.genW T) b' α = false))
    ∨ ((∃ α : T → Bool,
          GkatGS.bval (GkatPlanExistence.genW T) b α = true
            ∧ GkatGS.bval (GkatPlanExistence.genW T) c α = true)
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) b α = false)
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) c α = false)) := by
  by_cases hbc : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true
        ∧ GkatGS.bval (GkatPlanExistence.genW T) c α = true
  · by_cases hxb : ∃ α : T → Bool,
        GkatGS.bval (GkatPlanExistence.genW T) b α = false
    · by_cases hxc : ∃ α : T → Bool,
          GkatGS.bval (GkatPlanExistence.genW T) c α = false
      · exact Or.inr (Or.inr ⟨hbc, hxb, hxc⟩)
      · -- `c` valid: the inner loop diverges, the whole thing is `¬b?`
        exact Or.inl ⟨.not b, twoLoop_c_valid b q r
          (all_true_of_not_exit hxc)⟩
    · -- `b` valid: the outer loop diverges
      exact Or.inl ⟨.zero, twoLoop_b_valid c q r
        (all_true_of_not_exit hxb)⟩
  · -- no overlap: an atomic loop, whose own degeneracies are tests
    have hcol := twoLoop_no_overlap (b := b) (c := c) q r hbc
    by_cases hsat : ∃ α : T → Bool,
        GkatGS.bval (GkatPlanExistence.genW T) b α = true
    · by_cases hexit : ∃ α : T → Bool,
          GkatGS.bval (GkatPlanExistence.genW T) b α = false
      · exact Or.inr (Or.inl ⟨b, r, hcol, hsat, hexit⟩)
      · exact Or.inl ⟨.zero, EquivBA.trans hcol
          (wh_valid_zero _ (all_true_of_not_exit hexit))⟩
    · exact Or.inl ⟨.one, EquivBA.trans hcol
        (GkatChainFragment.wh_guard_semantic_zero _
          (all_false_of_not_sat hsat))⟩

#print axioms live_atomicLoop_ne_test
#print axioms twoLoop_trichotomy

private theorem ule_symm {e f : Exp A T}
    (h : GkatKleene.UniformLanguageEquivalent e f) :
    GkatKleene.UniformLanguageEquivalent f e :=
  fun X W gs => (h X W gs).symm

open Classical in
/-- **★ `twoloops_complete`, HYPOTHESIS-FREE ★** — the repair of the
    overclaim found at iteration 138.  No satisfiability assumptions on
    any guard; the six that `twoloops_complete` carries are discharged
    by the trichotomy and the vacuity results.

    Nine cases, each a proved theorem: tests compare by BA, atomic loops
    by `atomicloops_complete`, live pairs by `twoloops_complete`, and
    every mixed pair is impossible. -/
theorem twoloops_complete_free (b₁ c₁ b₂ c₂ : BExp T) (q₁ r₁ q₂ r₂ : A)
    (heq : GkatKleene.UniformLanguageEquivalent
      (GkatTwoLoop.twoLoop b₁ c₁ q₁ r₁) (GkatTwoLoop.twoLoop b₂ c₂ q₂ r₂)) :
    EquivBA (GkatTwoLoop.twoLoop b₁ c₁ q₁ r₁)
      (GkatTwoLoop.twoLoop b₂ c₂ q₂ r₂) := by
  rcases twoLoop_trichotomy b₁ c₁ q₁ r₁ with
    ⟨t₁, h₁⟩ | ⟨a₁, s₁, h₁, hsat₁, hex₁⟩ | ⟨hbc₁, hxb₁, hxc₁⟩
  · rcases twoLoop_trichotomy b₂ c₂ q₂ r₂ with
      ⟨t₂, h₂⟩ | ⟨a₂, s₂, h₂, hsat₂, hex₂⟩ | ⟨hbc₂, hxb₂, hxc₂⟩
    · exact EquivBA.trans h₁ (EquivBA.trans
        (GkatChainFragment.test_test_equiv
          (GkatChainFragment.ule_congr_right h₂
            (GkatChainFragment.ule_congr_left h₁ heq)))
        (EquivBA.symm h₂))
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_right h₂
        (GkatChainFragment.ule_congr_left h₁ heq)))
        (fun hu => live_atomicLoop_ne_test t₁ hsat₂ hex₂ hu)
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_left h₁ heq))
        (fun hu => live_twoLoop_ne_test t₁ hbc₂ hxc₂ hxb₂ hu)
  · rcases twoLoop_trichotomy b₂ c₂ q₂ r₂ with
      ⟨t₂, h₂⟩ | ⟨a₂, s₂, h₂, hsat₂, hex₂⟩ | ⟨hbc₂, hxb₂, hxc₂⟩
    · exact absurd (GkatChainFragment.ule_congr_right h₂
        (GkatChainFragment.ule_congr_left h₁ heq))
        (fun hu => live_atomicLoop_ne_test t₂ hsat₁ hex₁ hu)
    · exact EquivBA.trans h₁ (EquivBA.trans
        (GkatAtomicLoop.atomicloops_complete _ _
          (GkatAtomicLoop.AtomicLoops.wh a₁ s₁)
          (GkatAtomicLoop.AtomicLoops.wh a₂ s₂)
          (GkatChainFragment.ule_congr_right h₂
            (GkatChainFragment.ule_congr_left h₁ heq)))
        (EquivBA.symm h₂))
    · exact absurd (GkatChainFragment.ule_congr_left h₁ heq)
        (fun hu => no_overlap_vs_live_absurd hu hbc₂ hxb₂)
  · rcases twoLoop_trichotomy b₂ c₂ q₂ r₂ with
      ⟨t₂, h₂⟩ | ⟨a₂, s₂, h₂, hsat₂, hex₂⟩ | ⟨hbc₂, hxb₂, hxc₂⟩
    · exact absurd (GkatChainFragment.ule_congr_right h₂ heq)
        (fun hu => live_twoLoop_ne_test t₂ hbc₁ hxc₁ hxb₁ hu)
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_right h₂ heq))
        (fun hu => no_overlap_vs_live_absurd hu hbc₁ hxb₁)
    · exact GkatTwoLoop.twoloops_complete b₁ c₁ b₂ c₂ q₁ r₁ q₂ r₂
        hxc₁ hxb₁ hbc₁ hxc₂ hxb₂ hbc₂ heq

#print axioms twoloops_complete_free

/-! ## Toward `chordloops_complete_free`: the collapses land in `Chain2`

    `chordLoop b c p x y = wh b (p; ite c (x·y) y)`.  Its inner guard
    `c` degenerates two ways, and — the piece that makes this tractable —
    **both collapse targets are CHAIN bodies**, so they land in
    `chainloops_complete_free`, which is already hypothesis-free.

    `Chain` is any nested sequence of actions, so `p; y` and `p; (x; y)`
    are both `Chain2`.  That is a better landing spot than the two-loop
    repair had: there the no-overlap case fell into `AtomicLoops` and
    needed a fresh vacuity argument, whereas here the earlier stratum
    absorbing the collapse is itself already free of side conditions.

    Note also that `chordloops_complete`'s THREE `b`-side hypotheses
    (shared entry `b ∧ b'`, and exit for `b` and `b'` separately)
    collapse to TWO under `wh_guards_agree_of_ule` (iteration 143):
    both sides are loops, so `b ≡ b'`, and shared entry is just
    satisfiability of `b`. -/

open Classical in
/-- A chord loop whose inner guard always holds is a CHAIN loop with a
    three-action body. -/
theorem chordLoop_c_valid (b : BExp T) (p x y : A) {c : BExp T}
    (h : ∀ α : T → Bool, GkatGS.bval (GkatPlanExistence.genW T) c α = true) :
    EquivBA (GkatThreeLoop.chordLoop b c p x y)
      (.wh b (.seq (.act p) (.seq (.act x) (.act y)))) := by
  refine EquivBA.wh_c (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_)
  refine GkatElim.ite_true_collapse ?_ _ _
  intro Z W v
  rw [GkatPlanExistence.bval_gen W v c, h (fun t => W t v)]

open Classical in
/-- A chord loop whose inner guard never holds is a CHAIN loop with a
    two-action body. -/
theorem chordLoop_c_unsat (b : BExp T) (p x y : A) {c : BExp T}
    (h : ∀ α : T → Bool, GkatGS.bval (GkatPlanExistence.genW T) c α = false) :
    EquivBA (GkatThreeLoop.chordLoop b c p x y)
      (.wh b (.seq (.act p) (.act y))) := by
  refine EquivBA.wh_c (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_)
  refine EquivBA.trans (EquivBA.ite_guard (b := c) (c := .zero) ?_) ?_
  · intro Z W v
    rw [GkatPlanExistence.bval_gen W v c, h (fun t => W t v)]
    rfl
  · exact EquivBA.base (GkatFaithful.ite_zero _ _)

/-- Both collapse targets are `Chain2` bodies, so
    `chainloops_complete_free` applies to them with no side conditions. -/
theorem chordLoop_collapse_chain2 (p x y : A) :
    GkatChainFragment.Chain2 (.seq (.act p) (.act y) : Exp A T)
      ∧ GkatChainFragment.Chain2
        (.seq (.act p) (.seq (.act x) (.act y)) : Exp A T) :=
  ⟨GkatChainFragment.Chain2.seq (GkatChainFragment.Chain.act p)
      (GkatChainFragment.Chain.act y),
   GkatChainFragment.Chain2.seq (GkatChainFragment.Chain.act p)
      (GkatChainFragment.Chain.seq (GkatChainFragment.Chain.act x)
        (GkatChainFragment.Chain.act y))⟩

#print axioms chordLoop_c_valid
#print axioms chordLoop_c_unsat
#print axioms chordLoop_collapse_chain2

/-! ## The action-count invariant: a chain loop has a fixed STRIDE

    Iteration 147 named the chord repair's remaining piece as an
    ARITHMETIC vacuity rather than a structural one.  Here is its core:
    a loop whose body is a fixed chain of `k` actions accepts only
    strings whose action count is a MULTIPLE OF `k`.  A live chord loop
    emits two actions on `¬c` iterations and three on `c` ones, so it
    accepts strings of both lengths — and neither stride can absorb
    both.

    The invariant is a two-line induction on `InLoop`: the exit case
    contributes zero, and each step contributes exactly the body's
    length. -/

/-- A two-action chain body forces even action counts. -/
theorem chain2_even {Atom : Type} (V : T → Atom → Bool) (b : BExp T)
    (p y : A) {gs : GkatGS.GS A Atom}
    (h : GkatGS.den V (.wh b (.seq (.act p) (.act y)) : Exp A T) gs) :
    gs.2.length % 2 = 0 := by
  have h' : GkatGS.InLoop V b
      (GkatGS.den V (.seq (.act p) (.act y) : Exp A T)) gs := h
  induction h' with
  | exit a _ => rfl
  | step a l1 rest _ hbody hrec ih =>
      obtain ⟨m1, m2, hsp, ⟨u1, v1, h1⟩, ⟨u2, v2, h2⟩⟩ := hbody
      have hm1 : m1 = [(p, v1)] := congrArg Prod.snd h1
      have hm2 : m2 = [(y, v2)] := congrArg Prod.snd h2
      have hsp' : l1 = m1 ++ m2 := hsp
      have hl1 : l1.length = 2 := by
        rw [hsp', hm1, hm2]; rfl
      show (l1 ++ rest).length % 2 = 0
      rw [List.length_append, hl1, Nat.add_mod_left]
      exact ih hrec

/-- A three-action chain body forces action counts divisible by three. -/
theorem chain3_mod {Atom : Type} (V : T → Atom → Bool) (b : BExp T)
    (p x y : A) {gs : GkatGS.GS A Atom}
    (h : GkatGS.den V
      (.wh b (.seq (.act p) (.seq (.act x) (.act y))) : Exp A T) gs) :
    gs.2.length % 3 = 0 := by
  have h' : GkatGS.InLoop V b
      (GkatGS.den V (.seq (.act p) (.seq (.act x) (.act y)) : Exp A T))
      gs := h
  induction h' with
  | exit a _ => rfl
  | step a l1 rest _ hbody hrec ih =>
      obtain ⟨m1, m2, hsp, ⟨u1, v1, h1⟩, hrest⟩ := hbody
      obtain ⟨n1, n2, hsp2, ⟨u2, v2, h2⟩, ⟨u3, v3, h3⟩⟩ := hrest
      have hm1 : m1 = [(p, v1)] := congrArg Prod.snd h1
      have hn1 : n1 = [(x, v2)] := congrArg Prod.snd h2
      have hn2 : n2 = [(y, v3)] := congrArg Prod.snd h3
      have hsp' : l1 = m1 ++ m2 := hsp
      have hsp2' : m2 = n1 ++ n2 := hsp2
      have hl1 : l1.length = 3 := by
        rw [hsp', hm1, hsp2', hn1, hn2]; rfl
      show (l1 ++ rest).length % 3 = 0
      rw [List.length_append, hl1, Nat.add_mod_left]
      exact ih hrec

#print axioms chain2_even
#print axioms chain3_mod

/-! ## Chord acceptance witnesses, and the two arithmetic vacuities

    A live chord emits THREE actions on a `c`-iteration and TWO on a
    `¬c` one.  Note where `c` is read: `chordBody = p · (x·y +_c y)`,
    so the branch guard is tested at the POST-`p` atom, not at the loop
    head.  The witnesses below thread that correctly. -/

open Classical in
/-- **A chord loop accepts a THREE-action string** when the branch guard
    holds after `p`. -/
theorem chordLoop_accepts_three {Atom : Type} (V : T → Atom → Bool)
    (b c : BExp T) (p x y : A) (a a₁ a₂ a₃ : Atom)
    (hb : GkatGS.bval V b a = true) (hc : GkatGS.bval V c a₁ = true)
    (hb₃ : GkatGS.bval V b a₃ = false) :
    GkatGS.den V (GkatThreeLoop.chordLoop b c p x y)
      (a, [(p, a₁), (x, a₂), (y, a₃)]) :=
  GkatGS.InLoop.step a [(p, a₁), (x, a₂), (y, a₃)] [] hb
    ⟨[(p, a₁)], [(x, a₂), (y, a₃)], rfl, ⟨a, a₁, rfl⟩,
      Or.inl ⟨hc, ⟨[(x, a₂)], [(y, a₃)], rfl, ⟨a₁, a₂, rfl⟩, ⟨a₂, a₃, rfl⟩⟩⟩⟩
    (GkatGS.InLoop.exit a₃ hb₃)

open Classical in
/-- **A chord loop accepts a TWO-action string** when the branch guard
    fails after `p`. -/
theorem chordLoop_accepts_two {Atom : Type} (V : T → Atom → Bool)
    (b c : BExp T) (p x y : A) (a a₁ a₂ : Atom)
    (hb : GkatGS.bval V b a = true) (hc : GkatGS.bval V c a₁ = false)
    (hb₂ : GkatGS.bval V b a₂ = false) :
    GkatGS.den V (GkatThreeLoop.chordLoop b c p x y)
      (a, [(p, a₁), (y, a₂)]) :=
  GkatGS.InLoop.step a [(p, a₁), (y, a₂)] [] hb
    ⟨[(p, a₁)], [(y, a₂)], rfl, ⟨a, a₁, rfl⟩,
      Or.inr ⟨hc, ⟨a₁, a₂, rfl⟩⟩⟩
    (GkatGS.InLoop.exit a₂ hb₂)

open Classical in
/-- **A live chord is never a two-stride chain loop** — its three-action
    string has odd length. -/
theorem live_chord_ne_chain2 {b c : BExp T} {p x y : A}
    {b' : BExp T} {p' y' : A}
    (hbsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true)
    (hcsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) c α = true)
    (hbex : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hule : GkatKleene.UniformLanguageEquivalent
      (GkatThreeLoop.chordLoop b c p x y)
      (.wh b' (.seq (.act p') (.act y')))) :
    False := by
  obtain ⟨α, hb⟩ := hbsat
  obtain ⟨α₁, hc⟩ := hcsat
  obtain ⟨α₃, hb₃⟩ := hbex
  have hacc := chordLoop_accepts_three (GkatPlanExistence.genW T)
    b c p x y α α₁ α₁ α₃ hb hc hb₃
  have h3 : (3 : Nat) % 2 = 0 := chain2_even (GkatPlanExistence.genW T) b' p' y'
    ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
  exact absurd h3 (by decide)

open Classical in
/-- **A live chord is never a three-stride chain loop** — its two-action
    string is not a multiple of three. -/
theorem live_chord_ne_chain3 {b c : BExp T} {p x y : A}
    {b' : BExp T} {p' x' y' : A}
    (hbsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true)
    (hcex : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) c α = false)
    (hbex : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hule : GkatKleene.UniformLanguageEquivalent
      (GkatThreeLoop.chordLoop b c p x y)
      (.wh b' (.seq (.act p') (.seq (.act x') (.act y'))))) :
    False := by
  obtain ⟨α, hb⟩ := hbsat
  obtain ⟨α₁, hc⟩ := hcex
  obtain ⟨α₂, hb₂⟩ := hbex
  have hacc := chordLoop_accepts_two (GkatPlanExistence.genW T)
    b c p x y α α₁ α₂ hb hc hb₂
  have := chain3_mod (GkatPlanExistence.genW T) b' p' x' y'
    ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
  exact nomatch this

#print axioms chordLoop_accepts_three
#print axioms chordLoop_accepts_two
#print axioms live_chord_ne_chain2
#print axioms live_chord_ne_chain3

open Classical in
/-- **A chord loop with a usable outer guard is never a test.**  Only
    the OUTER guard's non-degeneracy is needed: whichever way the branch
    guard falls at the post-`p` atom, some action-carrying string is
    accepted. -/
theorem live_chord_ne_test {b c : BExp T} {p x y : A} (t : BExp T)
    (hbsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true)
    (hbex : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hule : GkatKleene.UniformLanguageEquivalent
      (GkatThreeLoop.chordLoop b c p x y) (.test t)) :
    False := by
  obtain ⟨α, hb⟩ := hbsat
  obtain ⟨α₂, hb₂⟩ := hbex
  cases hcv : GkatGS.bval (GkatPlanExistence.genW T) c α₂ with
  | true =>
      have hacc := chordLoop_accepts_three (GkatPlanExistence.genW T)
        b c p x y α α₂ α₂ α₂ hb hcv hb₂
      have := test_no_action (GkatPlanExistence.genW T) t
        ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
      exact nomatch this
  | false =>
      have hacc := chordLoop_accepts_two (GkatPlanExistence.genW T)
        b c p x y α α₂ α₂ hb hcv hb₂
      have := test_no_action (GkatPlanExistence.genW T) t
        ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
      exact nomatch this

open Classical in
/-- **THE CHORD TETRACHOTOMY**: every chord loop is provably a TEST, or
    a TWO-STRIDE chain loop, or a THREE-STRIDE chain loop, or LIVE —
    with the outer guard's degeneracies already pushed into the test
    branch, so the chain branches carry a usable guard.

    Note the chain branches are both `Chain2` bodies, so they are
    absorbed by `chainloops_complete_free`, which is already free of
    side conditions. -/
theorem chordLoop_tetrachotomy (b c : BExp T) (p x y : A) :
    (∃ t : BExp T, EquivBA (GkatThreeLoop.chordLoop b c p x y) (.test t))
    ∨ (EquivBA (GkatThreeLoop.chordLoop b c p x y)
          (.wh b (.seq (.act p) (.act y)))
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) b α = true)
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) b α = false))
    ∨ (EquivBA (GkatThreeLoop.chordLoop b c p x y)
          (.wh b (.seq (.act p) (.seq (.act x) (.act y))))
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) b α = true)
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) b α = false))
    ∨ ((∃ α : T → Bool,
          GkatGS.bval (GkatPlanExistence.genW T) b α = true)
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) b α = false)
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) c α = true)
        ∧ (∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) c α = false)) := by
  by_cases hbsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true
  · by_cases hbex : ∃ α : T → Bool,
        GkatGS.bval (GkatPlanExistence.genW T) b α = false
    · by_cases hcsat : ∃ α : T → Bool,
          GkatGS.bval (GkatPlanExistence.genW T) c α = true
      · by_cases hcex : ∃ α : T → Bool,
            GkatGS.bval (GkatPlanExistence.genW T) c α = false
        · exact Or.inr (Or.inr (Or.inr ⟨hbsat, hbex, hcsat, hcex⟩))
        · exact Or.inr (Or.inr (Or.inl
            ⟨chordLoop_c_valid b p x y (all_true_of_not_exit hcex),
              hbsat, hbex⟩))
      · exact Or.inr (Or.inl
          ⟨chordLoop_c_unsat b p x y (all_false_of_not_sat hcsat),
            hbsat, hbex⟩)
    · exact Or.inl ⟨.zero, wh_valid_zero _ (all_true_of_not_exit hbex)⟩
  · exact Or.inl ⟨.one, GkatChainFragment.wh_guard_semantic_zero _
      (all_false_of_not_sat hbsat)⟩

#print axioms live_chord_ne_test
#print axioms chordLoop_tetrachotomy

open Classical in
/-- A two-stride chain loop with a usable guard accepts a two-action
    string, hence is never a test. -/
theorem chain2_ne_test {b : BExp T} {p y : A} (t : BExp T)
    (hbsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true)
    (hbex : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hule : GkatKleene.UniformLanguageEquivalent
      (.wh b (.seq (.act p) (.act y))) (.test t)) :
    False := by
  obtain ⟨α, hb⟩ := hbsat
  obtain ⟨α₂, hb₂⟩ := hbex
  have hacc : GkatGS.den (GkatPlanExistence.genW T)
      (.wh b (.seq (.act p) (.act y)) : Exp A T) (α, [(p, α₂), (y, α₂)]) :=
    GkatGS.InLoop.step α [(p, α₂), (y, α₂)] [] hb
      ⟨[(p, α₂)], [(y, α₂)], rfl, ⟨α, α₂, rfl⟩, ⟨α₂, α₂, rfl⟩⟩
      (GkatGS.InLoop.exit α₂ hb₂)
  have := test_no_action (GkatPlanExistence.genW T) t
    ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
  exact nomatch this

open Classical in
/-- A three-stride chain loop with a usable guard is never a test. -/
theorem chain3_ne_test {b : BExp T} {p x y : A} (t : BExp T)
    (hbsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true)
    (hbex : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hule : GkatKleene.UniformLanguageEquivalent
      (.wh b (.seq (.act p) (.seq (.act x) (.act y)))) (.test t)) :
    False := by
  obtain ⟨α, hb⟩ := hbsat
  obtain ⟨α₂, hb₂⟩ := hbex
  have hacc : GkatGS.den (GkatPlanExistence.genW T)
      (.wh b (.seq (.act p) (.seq (.act x) (.act y))) : Exp A T)
      (α, [(p, α₂), (x, α₂), (y, α₂)]) :=
    GkatGS.InLoop.step α [(p, α₂), (x, α₂), (y, α₂)] [] hb
      ⟨[(p, α₂)], [(x, α₂), (y, α₂)], rfl, ⟨α, α₂, rfl⟩,
        ⟨[(x, α₂)], [(y, α₂)], rfl, ⟨α₂, α₂, rfl⟩, ⟨α₂, α₂, rfl⟩⟩⟩
      (GkatGS.InLoop.exit α₂ hb₂)
  have := test_no_action (GkatPlanExistence.genW T) t
    ((hule (T → Bool) (GkatPlanExistence.genW T) _).mp hacc)
  exact nomatch this

#print axioms chain2_ne_test
#print axioms chain3_ne_test

/-! ## `hentC` is derivable after all — and by a much shorter route

    Iteration 150 sketched a five-step derivation of shared inner-guard
    entry (all six action letters forced equal, then a mid-body halt
    contradiction).  Working it properly collapses it to ONE step, and
    the earlier sketch turns out to have been the long way round.

    The observation: at a post-`p` atom where `c` HOLDS, a chord loop's
    body owes TWO MORE actions, so it cannot accept a two-action string
    through such an atom.  If `c` and `c'` were disjoint, the other side
    — whose branch guard FAILS there — accepts exactly such a string.
    No action letters need to be matched at all. -/

open Classical in
/-- **A chord loop owes THREE actions through a `c`-atom.**  At the
    post-`p` atom the branch guard holds, so the body still owes `x` and
    `y`; two actions cannot suffice. -/
theorem chord_three_at_c {Atom : Type} (V : T → Atom → Bool)
    (b c : BExp T) (p x y : A) {gs : GkatGS.GS A Atom}
    (h : GkatGS.den V (GkatThreeLoop.chordLoop b c p x y) gs)
    {u : A} {a₁ : Atom} {tl : List (A × Atom)}
    (hgs : gs.2 = (u, a₁) :: tl)
    (hc : GkatGS.bval V c a₁ = true) :
    3 ≤ gs.2.length := by
  have h' : GkatGS.InLoop V b
      (GkatGS.den V (GkatThreeLoop.chordBody c p x y)) gs := h
  cases h' with
  | exit a hb => exact nomatch (hgs : ([] : List (A × Atom)) = (u, a₁) :: tl)
  | step a l1 rest _ hbody _ =>
      obtain ⟨m1, m2, hsp, ⟨w0, w1, hp⟩, hite⟩ := hbody
      have hm1 : m1 = [(p, w1)] := congrArg Prod.snd hp
      have hsp' : l1 = m1 ++ m2 := hsp
      have hcons : l1 ++ rest = (u, a₁) :: tl := hgs
      have hw1 : w1 = a₁ := by
        rw [hsp', hm1] at hcons
        exact congrArg Prod.snd (List.head_eq_of_cons_eq hcons)
      have hthen : GkatGS.den V (.seq (.act x) (.act y) : Exp A T)
          (GkatGS.lastAtom a m1, m2) := by
        rcases hite with ⟨_, hh⟩ | ⟨hf, _⟩
        · exact hh
        · exfalso
          rw [hm1] at hf
          have : GkatGS.bval V c w1 = false := hf
          rw [hw1, hc] at this
          exact nomatch this
      obtain ⟨n1, n2, hsp2, ⟨_, v1, h1⟩, ⟨_, v2, h2⟩⟩ := hthen
      have hn1 : n1 = [(x, v1)] := congrArg Prod.snd h1
      have hn2 : n2 = [(y, v2)] := congrArg Prod.snd h2
      have hm2 : m2 = n1 ++ n2 := hsp2
      have hl1 : l1.length = 3 := by
        rw [hsp', hm1, hm2, hn1, hn2]; rfl
      show 3 ≤ (l1 ++ rest).length
      rw [List.length_append, hl1]
      exact Nat.le_add_right _ _

#print axioms chord_three_at_c

open Classical in
/-- **★ SHARED INNER-GUARD ENTRY IS DERIVABLE ★** — the hypothesis
    iteration 150 could not remove.  If `c` and `c'` were disjoint, then
    at an atom where `c` holds the OTHER side's branch guard fails, so
    that side accepts a two-action string through it — while this side,
    whose guard holds there, still owes `x` and `y`.

    Iteration 150's sketch forced all six action letters equal first.
    That was the long way round: no letters need matching at all. -/
theorem chord_shared_entry {b c b' c' : BExp T} {p x y p' x' y' : A}
    (hule : GkatKleene.UniformLanguageEquivalent
      (GkatThreeLoop.chordLoop b c p x y)
      (GkatThreeLoop.chordLoop b' c' p' x' y'))
    (hbsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = true)
    (hbex : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) b α = false)
    (hcsat : ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) c α = true) :
    ∃ α : T → Bool,
      GkatGS.bval (GkatPlanExistence.genW T) c α = true
        ∧ GkatGS.bval (GkatPlanExistence.genW T) c' α = true := by
  refine Classical.byContradiction (fun hno => ?_)
  obtain ⟨γ, hcγ⟩ := hcsat
  have hc'γ : GkatGS.bval (GkatPlanExistence.genW T) c' γ = false := by
    cases hv : GkatGS.bval (GkatPlanExistence.genW T) c' γ with
    | false => rfl
    | true => exact absurd ⟨γ, hcγ, hv⟩ hno
  obtain ⟨α, hb⟩ := hbsat
  obtain ⟨δ, hbδ⟩ := hbex
  have hga := wh_guards_agree_of_ule hule (T → Bool) (GkatPlanExistence.genW T)
  have hb' : GkatGS.bval (GkatPlanExistence.genW T) b' α = true := by
    rw [← hga α]; exact hb
  have hb'δ : GkatGS.bval (GkatPlanExistence.genW T) b' δ = false := by
    rw [← hga δ]; exact hbδ
  have hacc := chordLoop_accepts_two (GkatPlanExistence.genW T)
    b' c' p' x' y' α γ δ hb' hc'γ hb'δ
  have h1 := (hule (T → Bool) (GkatPlanExistence.genW T) _).mpr hacc
  have h3 : (3 : Nat) ≤ 2 :=
    chord_three_at_c (GkatPlanExistence.genW T) b c p x y h1 rfl hcγ
  exact absurd h3 (by decide)

#print axioms chord_shared_entry

open Classical in
/-- **★ `chordloops_complete`, HYPOTHESIS-FREE ★** — all six
    satisfiability conditions are gone.  Guard agreement supplies the
    outer ones; `chord_shared_entry` supplies the inner one.

    Sixteen cases; every mixed one is impossible, and the diagonal is
    `test_test_equiv`, `chainloops_complete_free` (both collapse targets
    are `Chain2`), and `chordloops_complete`. -/
theorem chordloops_complete_free
    (b c : BExp T) (p x y : A) (b' c' : BExp T) (p' x' y' : A)
    (heq : GkatKleene.UniformLanguageEquivalent
      (GkatThreeLoop.chordLoop b c p x y)
      (GkatThreeLoop.chordLoop b' c' p' x' y')) :
    EquivBA (GkatThreeLoop.chordLoop b c p x y)
      (GkatThreeLoop.chordLoop b' c' p' x' y') := by
  have hga := wh_guards_agree_of_ule heq (T → Bool) (GkatPlanExistence.genW T)
  rcases chordLoop_tetrachotomy b c p x y with
    ⟨t₁, h₁⟩ | ⟨h₁, hs₁, he₁⟩ | ⟨h₁, hs₁, he₁⟩ | ⟨hbs₁, hbe₁, hcs₁, hce₁⟩
  · rcases chordLoop_tetrachotomy b' c' p' x' y' with
      ⟨t₂, h₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨hbs₂, hbe₂, hcs₂, hce₂⟩
    · exact EquivBA.trans h₁ (EquivBA.trans
        (GkatChainFragment.test_test_equiv
          (GkatChainFragment.ule_congr_right h₂
            (GkatChainFragment.ule_congr_left h₁ heq)))
        (EquivBA.symm h₂))
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_right h₂
        (GkatChainFragment.ule_congr_left h₁ heq)))
        (fun hu => chain2_ne_test t₁ hs₂ he₂ hu)
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_right h₂
        (GkatChainFragment.ule_congr_left h₁ heq)))
        (fun hu => chain3_ne_test t₁ hs₂ he₂ hu)
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_left h₁ heq))
        (fun hu => live_chord_ne_test t₁ hbs₂ hbe₂ hu)
  · rcases chordLoop_tetrachotomy b' c' p' x' y' with
      ⟨t₂, h₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨hbs₂, hbe₂, hcs₂, hce₂⟩
    · exact absurd (GkatChainFragment.ule_congr_right h₂
        (GkatChainFragment.ule_congr_left h₁ heq))
        (fun hu => chain2_ne_test t₂ hs₁ he₁ hu)
    · exact EquivBA.trans h₁ (EquivBA.trans
        (GkatChainFragment.chainloops_complete_free b b'
          (chordLoop_collapse_chain2 p x y).1
          (chordLoop_collapse_chain2 p' x' y').1
          (GkatChainFragment.ule_congr_right h₂
            (GkatChainFragment.ule_congr_left h₁ heq)))
        (EquivBA.symm h₂))
    · exact EquivBA.trans h₁ (EquivBA.trans
        (GkatChainFragment.chainloops_complete_free b b'
          (chordLoop_collapse_chain2 p x y).1
          (chordLoop_collapse_chain2 p' x' y').2
          (GkatChainFragment.ule_congr_right h₂
            (GkatChainFragment.ule_congr_left h₁ heq)))
        (EquivBA.symm h₂))
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_left h₁ heq))
        (fun hu => live_chord_ne_chain2 hbs₂ hcs₂ hbe₂ hu)
  · rcases chordLoop_tetrachotomy b' c' p' x' y' with
      ⟨t₂, h₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨hbs₂, hbe₂, hcs₂, hce₂⟩
    · exact absurd (GkatChainFragment.ule_congr_right h₂
        (GkatChainFragment.ule_congr_left h₁ heq))
        (fun hu => chain3_ne_test t₂ hs₁ he₁ hu)
    · exact EquivBA.trans h₁ (EquivBA.trans
        (GkatChainFragment.chainloops_complete_free b b'
          (chordLoop_collapse_chain2 p x y).2
          (chordLoop_collapse_chain2 p' x' y').1
          (GkatChainFragment.ule_congr_right h₂
            (GkatChainFragment.ule_congr_left h₁ heq)))
        (EquivBA.symm h₂))
    · exact EquivBA.trans h₁ (EquivBA.trans
        (GkatChainFragment.chainloops_complete_free b b'
          (chordLoop_collapse_chain2 p x y).2
          (chordLoop_collapse_chain2 p' x' y').2
          (GkatChainFragment.ule_congr_right h₂
            (GkatChainFragment.ule_congr_left h₁ heq)))
        (EquivBA.symm h₂))
    · exact absurd (ule_symm (GkatChainFragment.ule_congr_left h₁ heq))
        (fun hu => live_chord_ne_chain3 hbs₂ hce₂ hbe₂ hu)
  · rcases chordLoop_tetrachotomy b' c' p' x' y' with
      ⟨t₂, h₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨h₂, hs₂, he₂⟩ | ⟨hbs₂, hbe₂, hcs₂, hce₂⟩
    · exact absurd (GkatChainFragment.ule_congr_right h₂ heq)
        (fun hu => live_chord_ne_test t₂ hbs₁ hbe₁ hu)
    · exact absurd (GkatChainFragment.ule_congr_right h₂ heq)
        (fun hu => live_chord_ne_chain2 hbs₁ hcs₁ hbe₁ hu)
    · exact absurd (GkatChainFragment.ule_congr_right h₂ heq)
        (fun hu => live_chord_ne_chain3 hbs₁ hce₁ hbe₁ hu)
    · obtain ⟨α, hb⟩ := id hbs₁
      exact GkatThreeLoop.chordloops_complete b c p x y b' c' p' x' y'
        ⟨α, hb, by rw [← hga α]; exact hb⟩
        (chord_shared_entry heq hbs₁ hbe₁ hcs₁) hce₁ hbe₁ hce₂ hbe₂ heq

#print axioms chordloops_complete_free


/-! ## Model equivalence: is `UniformLanguageEquivalent` the PAPER's semantics?

    Every completeness theorem here has the shape
    `UniformLanguageEquivalent e f → EquivBA e f`, and ULE quantifies
    over ALL carriers and valuations, whereas POPL'20 fixes a finite `T`
    and takes guarded strings over its ATOMS.  If ULE were STRICTLY
    STRONGER — harder to satisfy — the theorems would cover fewer pairs
    than the paper's completeness statement, and calling them
    completeness would overclaim.

    They coincide, and the reduction was already implicit in
    `ule_iff_start_bisim`: `bval` factors through the generic valuation
    (`bval_gen`), so a language is determined by its behaviour at
    `genW T`, whose atoms ARE the truth-assignments `T → Bool`.  Stated
    outright here rather than left inside another proof. -/

open Classical in
/-- **ULE IS GENERIC-VALUATION EQUIVALENCE** — quantifying over all
    carriers adds nothing beyond the truth-assignment model, so these
    theorems' hypothesis is the paper's semantic equality and no
    stronger. -/
theorem ule_iff_generic (e f : Exp A T) :
    GkatKleene.UniformLanguageEquivalent e f
      ↔ ∀ gs : GkatGS.GS A (T → Bool),
          GkatGS.den (GkatPlanExistence.genW T) e gs
            ↔ GkatGS.den (GkatPlanExistence.genW T) f gs := by
  constructor
  · intro h gs
    exact h (T → Bool) (GkatPlanExistence.genW T) gs
  · intro h X W gs
    have hstart : ∀ (Y : Type) (V : T → Y → Bool),
        GkatKleene.autLang V (GkatTrim.SUMof A T e f) (Sum.inl none)
          = GkatGS.den V e
        ∧ GkatKleene.autLang V (GkatTrim.SUMof A T e f) (Sum.inr none)
          = GkatGS.den V f := by
      intro Y V
      refine ⟨?_, ?_⟩
      · show GkatKleene.autLang V (GkatKleene.sumGAut
            (GkatThompson.certifiedThompson A T e).aut.toGAut
            (GkatThompson.certifiedThompson A T f).aut.toGAut)
            (Sum.inl none) = _
        rw [GkatDecide.autLang_sum_inl,
          GkatThompson.certifiedThompson_start_language e]
      · show GkatKleene.autLang V (GkatKleene.sumGAut
            (GkatThompson.certifiedThompson A T e).aut.toGAut
            (GkatThompson.certifiedThompson A T f).aut.toGAut)
            (Sum.inr none) = _
        rw [GkatDecide.autLang_sum_inr,
          GkatThompson.certifiedThompson_start_language f]
    have hgen : GkatKleene.autLang (GkatPlanExistence.genW T)
        (GkatTrim.SUMof A T e f) (Sum.inl none)
        = GkatKleene.autLang (GkatPlanExistence.genW T)
          (GkatTrim.SUMof A T e f) (Sum.inr none) := by
      rw [(hstart (T → Bool) (GkatPlanExistence.genW T)).1,
        (hstart (T → Bool) (GkatPlanExistence.genW T)).2]
      funext gs'
      exact propext (h gs')
    have hU := GkatPlanExistence.uniformStateEquiv_of_gen hgen X W
    rw [(hstart X W).1, (hstart X W).2] at hU
    exact iff_of_eq (congrFun hU gs)

#print axioms ule_iff_generic

/-! ## Executable smoke tests for the decider

    Every audit so far has been about STATEMENTS.  These check
    COMPUTATION: `uleDec` is a genuine decision procedure, so it can be
    RUN, and running it exercises the whole stack — Thompson
    construction, trimming, bisimilarity — against expected answers a
    proof about those same definitions could not catch. -/

section DecideSmoke

abbrev Tst := Fin 1
abbrev Act := Fin 2

private def t0 : BExp Tst := .prim 0
private def pa : Exp Act Tst := .act 0
private def pb : Exp Act Tst := .act 1

-- reflexive: an action equals itself
#eval @decide _ (GkatDecide.uleDec pa pa)                        -- expect true
-- distinct actions differ
#eval @decide _ (GkatDecide.uleDec pa pb)                        -- expect false
-- U1 idempotence, semantically
#eval @decide _ (GkatDecide.uleDec (.ite t0 pa pa) pa)           -- expect true
-- a test is not an action
#eval @decide _ (GkatDecide.uleDec (.test .one) pa)              -- expect false
-- W5: a loop whose guard never holds is skip
#eval @decide _ (GkatDecide.uleDec (.wh .zero pa) (.test .one))  -- expect true
-- W6: a productive loop that never exits has EMPTY language
#eval @decide _ (GkatDecide.uleDec (.wh .one pa) (.test .zero))  -- expect true
-- S5: e·1 = e
#eval @decide _ (GkatDecide.uleDec (.seq pa (.test .one)) pa)    -- expect true
-- S3: e·0 = 0
#eval @decide _ (GkatDecide.uleDec (.seq pa (.test .zero)) (.test .zero)) -- expect true
-- guard negation is invisible: b and ¬¬b
#eval @decide _ (GkatDecide.uleDec (.ite t0 pa pb)
  (.ite (.not (.not t0)) pa pb))                                 -- expect true
-- but swapping the branches is NOT invisible
#eval @decide _ (GkatDecide.uleDec (.ite t0 pa pb) (.ite t0 pb pa)) -- expect false

/-! ### The paper's Figure-2 derivable facts, checked by EXECUTION

    Figure 2 of POPL'20 lists twelve facts DERIVABLE from the axioms.
    None is an axiom here, so the decider agreeing with all twelve is
    independent evidence that this development's model computes the
    paper's semantics.  A disagreement would be a serious finding. -/

abbrev T2 := Fin 2
private def bb : BExp T2 := .prim 0
private def cc : BExp T2 := .prim 1
private def ea : Exp Act T2 := .act 0
private def fa : Exp Act T2 := .act 1
private def ga : Exp Act T2 := .act 0

-- U3'  e +_b (f +_c g) ≡ (e +_b f) +_{b+c} g
#eval @decide _ (GkatDecide.uleDec (.ite bb ea (.ite cc fa ga))
  (.ite (.or bb cc) (.ite bb ea fa) ga))
-- U4'  e +_b f ≡ e +_b b̄f
#eval @decide _ (GkatDecide.uleDec (.ite bb ea fa)
  (.ite bb ea (.seq (.test (.not bb)) fa)))
-- U5'  b(e +_c f) ≡ be +_c bf   (the VALID fragment of left distribution)
#eval @decide _ (GkatDecide.uleDec (.seq (.test bb) (.ite cc ea fa))
  (.ite cc (.seq (.test bb) ea) (.seq (.test bb) fa)))
-- U6   e +_b 0 ≡ be
#eval @decide _ (GkatDecide.uleDec (.ite bb ea (.test .zero))
  (.seq (.test bb) ea))
-- U7   e +_0 f ≡ f
#eval @decide _ (GkatDecide.uleDec (.ite .zero ea fa) fa)
-- U8   b(e +_b f) ≡ be
#eval @decide _ (GkatDecide.uleDec (.seq (.test bb) (.ite bb ea fa))
  (.seq (.test bb) ea))
-- W4   e^(b) ≡ e^(b)·b̄
#eval @decide _ (GkatDecide.uleDec (.wh bb ea)
  (.seq (.wh bb ea) (.test (.not bb))))
-- W4'  e^(b) ≡ (be)^(b)
#eval @decide _ (GkatDecide.uleDec (.wh bb ea)
  (.wh bb (.seq (.test bb) ea)))
-- W6'  b^(c) ≡ c̄
#eval @decide _ (GkatDecide.uleDec (.wh cc (.test bb) : Exp Act T2)
  (.test (.not cc)))
-- W7   e^(c) ≡ e^(bc)·e^(c)
#eval @decide _ (GkatDecide.uleDec (.wh cc ea)
  (.seq (.wh (.and bb cc) ea) (.wh cc ea)))
-- NEGATIVE CONTROL: full left distribution is NOT valid (refuted in-repo)
#eval @decide _ (GkatDecide.uleDec (.seq ea (.ite cc fa (.test .zero)))
  (.ite cc (.seq ea fa) (.seq ea (.test .zero))))

/-! ### Does same-side unification have NON-TRIVIAL content?

    Iteration 164 measured that ~97% of Thompson automata have distinct
    bisimilar states, so same-side UNIF is never vacuous in practice.
    But bisimilar does not mean HARD: iteration 124 showed duplicated
    subterms give LITERALLY EQUAL labels, where UNIF is `rfl`.

    The discriminating question is whether a pair can be language-equal
    with SYNTACTICALLY DIFFERENT labels.  Bisimilar states have
    language-equal labels, so `uleDec` on the labels plus decidable
    syntactic equality answers it — no separate bisimilarity decision.

    (Counting such pairs across a whole automaton is too slow to run at
    elaboration time — `uleDec` rebuilds and trims a Thompson sum per
    pair.  A single decisive witness suffices.) -/

-- The witness: inside `ite b (p ; (q +_b q)) (p ; q)`, the two post-`p`
-- continuations are `q +_b q` and `q`.  Language-equal, syntactically
-- different — so same-side unification is NOT always `rfl`.
#eval @decide _ (GkatDecide.uleDec (.ite t0 pb pb : Exp Act Tst) pb)  -- true
#eval decide ((.ite t0 pb pb : Exp Act Tst) = pb)                     -- false

end DecideSmoke

/-! ## THE MASKING LEMMA — pricing the `seq` half of same-side unification

    Iteration 133 refuted bisimilarity reflection at `seq`: two states of
    `e` can be bisimilar inside `seq e f` while `e` alone distinguishes
    them.  The refutation said only THAT reflection fails.  This section
    says exactly WHAT it costs, and then pays it.

    A state's standard label is a guarded fold whose fallback is its
    exit.  Inside `seq e f` that exit becomes `exit ; F`, with `F` the
    label of `f`'s start.  So two states of `e` whose exit tests differ
    still carry EquivBA-equal labels inside `seq e f` whenever `F` is
    dead on the region where the exits differ.  Masking is nothing else:
    a difference survives the composite iff the continuation is live
    where it lives.

    `seq_mask_of_dead_region` discharges it from the base axioms alone —
    U1, U2, U4, S1, S3, S6, `baTest`, congruence.  No uniqueness axiom,
    not even W3.  Paired with `diverging_region_zero`, which certifies
    exactly such regions for loops, the `seq` half of same-side
    unification stops being an obstruction and becomes a side condition
    with a named discharger. -/

/-- Two tests in front of `F` fuse into their conjunction (S1 + S6). -/
private theorem test_absorb (g c : BExp T) (F : Exp A T) :
    EquivBA (.seq (.test g) (.seq (.test c) F)) (.seq (.test (.and g c)) F) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.s1 _ _ _)))
    (EquivBA.seq_c (EquivBA.s6 g c) (EquivBA.base (Equiv.refl F)))

/-- Conjunction of tests commutes, through `baTest`. -/
private theorem and_comm_test (b c : BExp T) :
    EquivBA (.test (.and b c) : Exp A T) (.test (.and c b)) :=
  EquivBA.baTest (by
    intro X W x
    show (GkatGS.bval W b x && GkatGS.bval W c x)
      = (GkatGS.bval W c x && GkatGS.bval W b x)
    cases h₁ : GkatGS.bval W b x <;> cases h₂ : GkatGS.bval W c x <;> rfl)

/-- Anything conjoined with a certified-dead region still kills `F`. -/
private theorem dead_conj {r : BExp T} {F : Exp A T}
    (hdead : EquivBA (.seq (.test r) F) (.test .zero)) (c : BExp T) :
    EquivBA (.seq (.test (.and r c)) F) (.test .zero) :=
  EquivBA.trans
    (EquivBA.seq_c
      (EquivBA.symm (EquivBA.trans (EquivBA.s6 c r) (and_comm_test c r)))
      (EquivBA.base (Equiv.refl F)))
    (EquivBA.trans (EquivBA.base (Equiv.s1 _ _ _))
      (EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hdead)
        (EquivBA.base (Equiv.s3 _))))

/-- U4 gates the THEN branch; this gates the ELSE branch, by flipping
    with U2, gating, and flipping back through the guard `¬¬r = r`. -/
private theorem gate_else (r : BExp T) (u v : Exp A T) :
    EquivBA (.ite r u v) (.ite r u (.seq (.test (.not r)) v)) :=
  EquivBA.trans (EquivBA.base (Equiv.u2 r u v))
    (EquivBA.trans (EquivBA.base (Equiv.u4 (.not r) v u))
      (EquivBA.trans
        (EquivBA.base (Equiv.u2 (.not r) (.seq (.test (.not r)) v) u))
        (EquivBA.ite_guard (b := .not (.not r)) (c := r) (by
          intro X W x
          show (!(!GkatGS.bval W r x)) = GkatGS.bval W r x
          cases h : GkatGS.bval W r x <;> rfl))))

/-- **THE MASKING LEMMA.**  If `F` is provably zero on a region `r`, then
    two exit tests agreeing OFF `r` are interchangeable in front of `F` —
    their difference is invisible because it lives only where `F` is
    dead.

    This is the exact price of the failed reflection at `seq`, and it is
    payable from the finite axioms: the proof splits on `r` with U1/U4/U2,
    kills the `r` branch with the dead-region certificate, and matches the
    `¬r` branches by Boolean-algebra subsumption. -/
theorem seq_mask_of_dead_region {r c d : BExp T} {F : Exp A T}
    (hdead : EquivBA (.seq (.test r) F) (.test .zero))
    (hagree : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W (.and (.not r) c) x
          = GkatGS.bval W (.and (.not r) d) x) :
    EquivBA (.seq (.test c) F) (.seq (.test d) F) := by
  have split : ∀ g : BExp T,
      EquivBA (.seq (.test g) F : Exp A T)
        (.ite r (.test .zero) (.seq (.test (.and (.not r) g)) F)) := by
    intro g
    refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u1 r _))) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.u4 r _ _)) ?_
    refine EquivBA.trans (gate_else r _ _) ?_
    exact EquivBA.ite_c
      (EquivBA.trans (test_absorb r g F) (dead_conj hdead g))
      (test_absorb (.not r) g F)
  exact EquivBA.trans (split c)
    (EquivBA.trans
      (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
        (EquivBA.seq_c (EquivBA.baTest hagree) (EquivBA.base (Equiv.refl F))))
      (EquivBA.symm (split d)))

/-- The masking lemma with the region taken to be the whole atom space:
    a DEAD continuation absorbs every exit difference.  This is the
    degenerate case the `seq` reflection counterexample actually lived
    in, now discharged outright. -/
theorem seq_mask_of_dead_tail {c d : BExp T} {F : Exp A T}
    (hdead : EquivBA F (.test .zero)) :
    EquivBA (.seq (.test c) F : Exp A T) (.seq (.test d) F) :=
  EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hdead)
    (EquivBA.trans (EquivBA.base (Equiv.s3 _))
      (EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.s3 (.test d))))
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.symm hdead))))

/-- `foldr_congr_equivBA` varies the SOLUTION under a fixed fallback.
    This is its dual: vary the FALLBACK under fixed branches.  The exit
    of a state is exactly the fallback of its guarded fold, so this is
    the lemma that lifts masking from an exit test to a whole label. -/
theorem guardedFold_congr_fallback (branches : List (BExp T × Exp A T))
    {fb₁ fb₂ : Exp A T} (h : EquivBA fb₁ fb₂) :
    EquivBA (guardedFold branches fb₁) (guardedFold branches fb₂) := by
  induction branches with
  | nil => exact h
  | cons _ _ ih => exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih

/-- **MASKING, AT THE LABEL.**  Two states of `e` that agree on every
    transition and differ only in their halt test carry EquivBA-equal
    labels inside `seq e f`, provided the difference is confined to a
    region where `f`'s label is certified dead.

    This is the `seq` half of same-side unification, discharged: the
    reflection failure of iteration 133 costs exactly one dead-region
    certificate, and nothing more.  Zero axioms — not even W3. -/
theorem label_mask_of_dead_region (branches : List (BExp T × Exp A T))
    {r c d : BExp T} {F : Exp A T}
    (hdead : EquivBA (.seq (.test r) F) (.test .zero))
    (hagree : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W (.and (.not r) c) x
          = GkatGS.bval W (.and (.not r) d) x) :
    EquivBA (guardedFold branches (.seq (.test c) F))
      (guardedFold branches (.seq (.test d) F)) :=
  guardedFold_congr_fallback branches (seq_mask_of_dead_region hdead hagree)

#print axioms seq_mask_of_dead_region
#print axioms seq_mask_of_dead_tail
#print axioms guardedFold_congr_fallback
#print axioms label_mask_of_dead_region

/-! ### MASKING NEEDS NO CERTIFICATE: the dead region is `c ∧ ¬d`

    Iteration 167 left the masking lemma with a hypothesis — a region `r`
    on which `F` is provably zero — and named `diverging_region_zero` as
    the intended supplier.  That was one step too timid.  The region is
    not something to be searched for or certified separately: it is
    already determined by the two exit tests themselves.

    Take `r := c ∧ ¬d`, the region where the exits DISAGREE.  If the two
    composites are language-equal at all, then `test (c ∧ ¬d) ; F` has
    empty language outright — the hypothesis says so directly — and
    `nullLanguage_complete` turns empty language into a proof of `0` from
    the finite axioms.  The dead-region hypothesis discharges itself.

    So masking is UNCONDITIONAL: language equivalence of two test-gated
    copies of the same continuation is provable, full stop.  This closes
    the halt-only case of same-side unification with no side condition,
    no expressibility question about "where `F` is dead", and no appeal
    to the S0 divergence region after all. -/

/-- A test in front of `F` gates `F` at the start atom and nothing else. -/
private theorem den_test_seq {X : Type} (W : T → X → Bool) (c : BExp T)
    (F : Exp A T) (α : X) (w : List (A × X)) :
    GkatGS.den W (.seq (.test c) F) (α, w)
      ↔ (GkatGS.bval W c α = true ∧ GkatGS.den W F (α, w)) := by
  constructor
  · intro h
    obtain ⟨l1, l2, hsplit, hc, hF⟩ := h
    obtain ⟨hcv, hl1⟩ := hc
    subst hl1
    have hw : w = l2 := hsplit
    subst hw
    exact ⟨hcv, hF⟩
  · intro h
    exact ⟨[], w, rfl, ⟨h.1, rfl⟩, h.2⟩

/-- **The disagreement region is uniformly empty.**  If `test c ; F` and
    `test d ; F` accept the same guarded strings, then no guarded string
    at all survives `test (c ∧ ¬d) ; F` — at such an atom the first
    composite reduces to `F` and the second to nothing. -/
private theorem mask_region_empty {c d : BExp T} {F : Exp A T}
    (h : GkatKleene.UniformLanguageEquivalent
      (.seq (.test c) F : Exp A T) (.seq (.test d) F)) :
    GkatThompson.UniformExpLempty
      (.seq (.test (.and c (.not d))) F : Exp A T) := by
  intro X W gs
  obtain ⟨α, w⟩ := gs
  intro hmem
  obtain ⟨hcd, hF⟩ := (den_test_seq W _ F α w).mp hmem
  have hcd' : (GkatGS.bval W c α && !(GkatGS.bval W d α)) = true := hcd
  have hc : GkatGS.bval W c α = true := by
    revert hcd'
    cases GkatGS.bval W c α
    · intro hh; exact Bool.noConfusion hh
    · intro _; rfl
  have hd : GkatGS.bval W d α = false := by
    revert hcd'
    rw [hc]
    cases GkatGS.bval W d α
    · intro _; rfl
    · intro hh; exact Bool.noConfusion hh
  have h2 := (h X W (α, w)).mp ((den_test_seq W c F α w).mpr ⟨hc, hF⟩)
  have h3 := (den_test_seq W d F α w).mp h2
  rw [hd] at h3
  exact Bool.noConfusion h3.1

/-- **MASKING, UNCONDITIONALLY.**  Two test-gated copies of the same
    continuation that are language-equivalent are provably equal — from
    the finite axioms, with W3 entering only inside
    `nullLanguage_complete` and the n-ary uniqueness axiom nowhere.

    This is the halt-only case of same-side unification, closed.  Two
    states of one automaton that agree on every transition and differ
    only in their halt test carry provably equal labels the moment their
    languages agree; the difference they carry is confined, by the
    language hypothesis itself, to atoms where the continuation is dead,
    and a dead continuation is provably `0`. -/
theorem seq_mask_complete {c d : BExp T} {F : Exp A T}
    (h : GkatKleene.UniformLanguageEquivalent
      (.seq (.test c) F : Exp A T) (.seq (.test d) F)) :
    EquivBA (.seq (.test c) F : Exp A T) (.seq (.test d) F) := by
  have hcd : EquivBA (.seq (.test c) F : Exp A T)
      (.seq (.test (.and c d)) F) := by
    refine seq_mask_of_dead_region
      (GkatNullLanguage.nullLanguage_complete _ (mask_region_empty h)) ?_
    intro X W x
    show (!(GkatGS.bval W c x && !(GkatGS.bval W d x)) && GkatGS.bval W c x)
      = (!(GkatGS.bval W c x && !(GkatGS.bval W d x))
          && (GkatGS.bval W c x && GkatGS.bval W d x))
    cases GkatGS.bval W c x <;> cases GkatGS.bval W d x <;> rfl
  have hdc : EquivBA (.seq (.test d) F : Exp A T)
      (.seq (.test (.and c d)) F) := by
    refine seq_mask_of_dead_region
      (GkatNullLanguage.nullLanguage_complete _
        (mask_region_empty (fun X W gs => (h X W gs).symm))) ?_
    intro X W x
    show (!(GkatGS.bval W d x && !(GkatGS.bval W c x)) && GkatGS.bval W d x)
      = (!(GkatGS.bval W d x && !(GkatGS.bval W c x))
          && (GkatGS.bval W c x && GkatGS.bval W d x))
    cases GkatGS.bval W c x <;> cases GkatGS.bval W d x <;> rfl
  exact EquivBA.trans hcd (EquivBA.symm hdc)

/-- The label-level form: same branches, language-equivalent exits, one
    provable equality.  No hypothesis beyond language equivalence. -/
theorem label_mask_complete (branches : List (BExp T × Exp A T))
    {c d : BExp T} {F : Exp A T}
    (h : GkatKleene.UniformLanguageEquivalent
      (.seq (.test c) F : Exp A T) (.seq (.test d) F)) :
    EquivBA (guardedFold branches (.seq (.test c) F))
      (guardedFold branches (.seq (.test d) F)) :=
  guardedFold_congr_fallback branches (seq_mask_complete h)

#print axioms seq_mask_complete
#print axioms label_mask_complete

/-! ### THE FALLBACK IS ONLY OBSERVED WHERE EVERY GUARD FAILS

    `guardedFold_congr_fallback` asks the two fallbacks to be equal
    everywhere.  That is far more than a label needs: the fallback of a
    state is its EXIT, reached only at atoms where no transition guard
    fires.  Two states may therefore have wildly different exits and
    still be provably equal, as long as they agree on the fallback
    region.

    `fallbackRegion B` names that region — every guard of `B` false — and
    `guardedFold_congr_fallback_gated` proves the fold only depends on
    the fallback there.  The proof is a relativized induction: each `ite`
    contributes its own `¬g` to the accumulated assertion, pushed inward
    by `test_seq_ite` (the valid test-only fragment of left distribution)
    and re-associated by `test_seq_guard_congr`.

    Composed with `seq_mask_complete`, this gives the same-branches case
    of same-side unification outright. -/

/-- The region where a guarded fold reaches its fallback. -/
def fallbackRegion : List (BExp T × Exp A T) → BExp T
  | [] => .one
  | br :: tl => .and (.not br.1) (fallbackRegion tl)

/-- **Congruence in the ELSE arm, with the guard available.**  The else
    arm of `ite g` is only entered when `g` fails, so it need only agree
    UNDER `¬g`.  U2 flips, U4 asserts, `¬¬g = g` flips back. -/
theorem ite_else_congr_gated {g : BExp T} {u v v' : Exp A T}
    (h : EquivBA (.seq (.test (.not g)) v) (.seq (.test (.not g)) v')) :
    EquivBA (.ite g u v) (.ite g u v') :=
  EquivBA.trans (gate_else g u v)
    (EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl u)) h)
      (EquivBA.symm (gate_else g u v')))

/-- An assertion pushes through a whole guarded fold: it conjoins itself
    onto every branch guard and survives into the fallback. -/
theorem seq_test_guardedFold (h : BExp T) :
    ∀ (B : List (BExp T × Exp A T)) (fb : Exp A T),
      EquivBA (.seq (.test h) (guardedFold B fb))
        (guardedFold (B.map (fun br => (.and h br.1, br.2)))
          (.seq (.test h) fb))
  | [], _ => EquivBA.base (Equiv.refl _)
  | br :: tl, fb =>
      EquivBA.trans
        (GkatGuardedAlgebra.test_seq_ite h br.1 br.2 (guardedFold tl fb))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl br.2))
          (seq_test_guardedFold h tl fb))

/-- The relativized induction: under an assertion `r`, a guarded fold
    depends on its fallback only where `r` holds and every guard fails. -/
private theorem fold_fallback_gated_aux (B : List (BExp T × Exp A T)) :
    ∀ (r : BExp T) (fb₁ fb₂ : Exp A T),
      EquivBA (.seq (.test (.and r (fallbackRegion B))) fb₁)
        (.seq (.test (.and r (fallbackRegion B))) fb₂) →
      EquivBA (.seq (.test r) (guardedFold B fb₁))
        (.seq (.test r) (guardedFold B fb₂)) := by
  induction B with
  | nil =>
      intro r fb₁ fb₂ h
      have hconv : ∀ (Y : Type) (W : T → Y → Bool) (x : Y),
          GkatGS.bval W r x = GkatGS.bval W (.and r .one) x := by
        intro Y W x
        show GkatGS.bval W r x = (GkatGS.bval W r x && true)
        cases GkatGS.bval W r x <;> rfl
      exact EquivBA.trans (GkatGuardedAlgebra.test_seq_guard_congr fb₁ hconv)
        (EquivBA.trans h (EquivBA.symm
          (GkatGuardedAlgebra.test_seq_guard_congr fb₂ hconv)))
  | cons br tl ih =>
      intro r fb₁ fb₂ h
      obtain ⟨g, u⟩ := br
      have key : ∀ fb : Exp A T,
          EquivBA (.seq (.test r) (guardedFold ((g, u) :: tl) fb))
            (.ite (.and r g) u (.seq (.test r) (guardedFold tl fb))) :=
        fun fb => GkatGuardedAlgebra.test_seq_ite r g u (guardedFold tl fb)
      refine EquivBA.trans (key fb₁) (EquivBA.trans ?_ (EquivBA.symm (key fb₂)))
      refine ite_else_congr_gated ?_
      have merge : ∀ fb : Exp A T,
          EquivBA (.seq (.test (.not (.and r g)))
              (.seq (.test r) (guardedFold tl fb)))
            (.seq (.test (.and r (.not g))) (guardedFold tl fb)) := by
        intro fb
        refine EquivBA.trans
          (GkatGuardedAlgebra.test_seq_merge _ _ (guardedFold tl fb)) ?_
        refine GkatGuardedAlgebra.test_seq_guard_congr _ ?_
        intro Y W x
        show (!(GkatGS.bval W r x && GkatGS.bval W g x) && GkatGS.bval W r x)
          = (GkatGS.bval W r x && !(GkatGS.bval W g x))
        cases GkatGS.bval W r x <;> cases GkatGS.bval W g x <;> rfl
      refine EquivBA.trans (merge fb₁)
        (EquivBA.trans ?_ (EquivBA.symm (merge fb₂)))
      refine ih (.and r (.not g)) fb₁ fb₂ ?_
      have hassoc : ∀ (Y : Type) (W : T → Y → Bool) (x : Y),
          GkatGS.bval W (.and (.and r (.not g)) (fallbackRegion tl)) x
            = GkatGS.bval W (.and r (.and (.not g) (fallbackRegion tl))) x := by
        intro Y W x
        show ((GkatGS.bval W r x && !(GkatGS.bval W g x))
            && GkatGS.bval W (fallbackRegion tl) x)
          = (GkatGS.bval W r x
            && (!(GkatGS.bval W g x) && GkatGS.bval W (fallbackRegion tl) x))
        cases GkatGS.bval W r x <;> cases GkatGS.bval W g x <;>
          cases GkatGS.bval W (fallbackRegion tl) x <;> rfl
      exact EquivBA.trans (GkatGuardedAlgebra.test_seq_guard_congr fb₁ hassoc)
        (EquivBA.trans h (EquivBA.symm
          (GkatGuardedAlgebra.test_seq_guard_congr fb₂ hassoc)))

/-- **Fallback congruence, gated.**  A guarded fold depends on its
    fallback ONLY on the region where every guard fails.  This is the
    honest form of `guardedFold_congr_fallback`, whose blanket hypothesis
    asks for far more than a label ever observes. -/
theorem guardedFold_congr_fallback_gated (B : List (BExp T × Exp A T))
    {fb₁ fb₂ : Exp A T}
    (h : EquivBA (.seq (.test (fallbackRegion B)) fb₁)
      (.seq (.test (fallbackRegion B)) fb₂)) :
    EquivBA (guardedFold B fb₁) (guardedFold B fb₂) :=
  have hconv : ∀ (Y : Type) (W : T → Y → Bool) (x : Y),
      GkatGS.bval W (fallbackRegion B) x
        = GkatGS.bval W (.and .one (fallbackRegion B)) x :=
    fun _ _ _ => rfl
  have hone : EquivBA (.seq (.test (.and .one (fallbackRegion B))) fb₁)
      (.seq (.test (.and .one (fallbackRegion B))) fb₂) :=
    EquivBA.trans (EquivBA.symm
        (GkatGuardedAlgebra.test_seq_guard_congr fb₁ hconv))
      (EquivBA.trans h (GkatGuardedAlgebra.test_seq_guard_congr fb₂ hconv))
  EquivBA.trans (EquivBA.symm (GkatGuardedAlgebra.one_seq _))
    (EquivBA.trans (fold_fallback_gated_aux B .one fb₁ fb₂ hone)
      (GkatGuardedAlgebra.one_seq _))

/-- **THE SAME-BRANCHES CASE OF SAME-SIDE UNIFICATION.**  Two states of
    one automaton that agree on every transition carry provably equal
    labels as soon as their exits are language-equivalent ON THE REGION
    WHERE THE EXIT IS ACTUALLY TAKEN.

    Nothing else is assumed: no minimality, no productivity, no
    dead-region certificate, no uniqueness axiom.  The n-ary UA is
    nowhere; W3 enters only inside `nullLanguage_complete`. -/
theorem label_mask_complete_gated (B : List (BExp T × Exp A T))
    {c d : BExp T} {F : Exp A T}
    (h : GkatKleene.UniformLanguageEquivalent
      (.seq (.test (.and (fallbackRegion B) c)) F : Exp A T)
      (.seq (.test (.and (fallbackRegion B) d)) F)) :
    EquivBA (guardedFold B (.seq (.test c) F))
      (guardedFold B (.seq (.test d) F)) := by
  refine guardedFold_congr_fallback_gated B ?_
  refine EquivBA.trans (GkatGuardedAlgebra.test_seq_merge _ c F) ?_
  exact EquivBA.trans (seq_mask_complete h)
    (EquivBA.symm (GkatGuardedAlgebra.test_seq_merge _ d F))

#print axioms ite_else_congr_gated
#print axioms seq_test_guardedFold
#print axioms guardedFold_congr_fallback_gated
#print axioms label_mask_complete_gated

/-! ### DECISION LISTS THAT DECIDE THE SAME THING ARE PROVABLY EQUAL

    Iteration 168 closed the EXIT dimension of same-side unification.
    What is left is the TRANSITION dimension: two bisimilar states whose
    branch lists are different lists.  But bisimilarity never compares
    lists — it compares what they SELECT.  So the lemma the size
    induction actually needs is not about lists at all:

      two guarded folds that select EquivBA-equal expressions at every
      atom are EquivBA-equal.

    `guardedFold_select_congr` proves exactly that, from the finite
    axioms.  Neither list is assumed ordered, deduplicated, irredundant,
    or even satisfiable: branches that never fire are killed by their own
    unsatisfiability, and branches firing on overlapping regions are
    reconciled region by region.

    The engine is a relativized induction — the same shape as
    `fold_fallback_gated_aux`, and for the same reason.  Every statement
    carries an accumulated assertion `r`; `test_seq_ite` pushes it
    inward and `split_assertion` splits it on the next guard.  The
    classical step is small and isolated in `const_under`: whether a
    region is SATISFIABLE.  On an unsatisfiable region both sides are
    `0`; on a satisfiable one, a single witness atom transports the
    hypothesis. -/

/-- The expression a guarded fold actually runs at a given atom. -/
def selectFull {X : Type} (W : T → X → Bool) (x : X) :
    List (BExp T × Exp A T) → Exp A T → Exp A T
  | [], fb => fb
  | br :: tl, fb =>
      match GkatGS.bval W br.1 x with
      | true => br.2
      | false => selectFull W x tl fb

private theorem selectFull_cons_true {X : Type} (W : T → X → Bool) (x : X)
    {g : BExp T} (u : Exp A T) (tl : List (BExp T × Exp A T)) (fb : Exp A T)
    (hg : GkatGS.bval W g x = true) :
    selectFull W x ((g, u) :: tl) fb = u := by
  show (match GkatGS.bval W g x with
    | true => u
    | false => selectFull W x tl fb) = u
  rw [hg]

private theorem selectFull_cons_false {X : Type} (W : T → X → Bool) (x : X)
    {g : BExp T} (u : Exp A T) (tl : List (BExp T × Exp A T)) (fb : Exp A T)
    (hg : GkatGS.bval W g x = false) :
    selectFull W x ((g, u) :: tl) fb = selectFull W x tl fb := by
  show (match GkatGS.bval W g x with
    | true => u
    | false => selectFull W x tl fb) = selectFull W x tl fb
  rw [hg]

private theorem and_true_split {a b : Bool} (h : (a && b) = true) :
    a = true ∧ b = true := by
  cases a <;> cases b <;> first | exact ⟨rfl, rfl⟩ | exact Bool.noConfusion h

private theorem and_not_true_split {a b : Bool} (h : (a && !b) = true) :
    a = true ∧ b = false := by
  cases a <;> cases b <;> first | exact ⟨rfl, rfl⟩ | exact Bool.noConfusion h

/-- Splitting an assertion on an arbitrary guard, with both halves
    re-asserted.  U1 duplicates, U4 asserts the then arm, `gate_else`
    asserts the else arm, and the assertions merge by S1/S6. -/
private theorem split_assertion (r g : BExp T) (u : Exp A T) :
    EquivBA (.seq (.test r) u)
      (.ite (.and r g) (.seq (.test (.and r g)) u)
        (.seq (.test (.and r (.not g))) u)) := by
  refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u1 (.and r g) _))) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.u4 (.and r g) _ _)) ?_
  refine EquivBA.trans (gate_else (.and r g) _ _) ?_
  refine EquivBA.ite_c ?_ ?_
  · refine EquivBA.trans (GkatGuardedAlgebra.test_seq_merge _ _ u) ?_
    refine GkatGuardedAlgebra.test_seq_guard_congr _ ?_
    intro Y W y
    show ((GkatGS.bval W r y && GkatGS.bval W g y) && GkatGS.bval W r y)
      = (GkatGS.bval W r y && GkatGS.bval W g y)
    cases GkatGS.bval W r y <;> cases GkatGS.bval W g y <;> rfl
  · refine EquivBA.trans (GkatGuardedAlgebra.test_seq_merge _ _ u) ?_
    refine GkatGuardedAlgebra.test_seq_guard_congr _ ?_
    intro Y W y
    show ((!(GkatGS.bval W r y && GkatGS.bval W g y)) && GkatGS.bval W r y)
      = (GkatGS.bval W r y && !(GkatGS.bval W g y))
    cases GkatGS.bval W r y <;> cases GkatGS.bval W g y <;> rfl

/-- **The classical step, isolated.**  Under an assertion, a constant may
    be replaced by anything it is provably equal to at SOME atom of the
    region — and if the region has no atoms at all, both sides are `0`. -/
private theorem const_under {u target : Exp A T} {r : BExp T}
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W r x = true → EquivBA u target) :
    EquivBA (.seq (.test r) u) (.seq (.test r) target) := by
  refine Or.elim (Classical.em (∃ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W r x = true)) ?_ ?_
  · intro hsat
    obtain ⟨Y, W, y, hy⟩ := hsat
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (h Y W y hy)
  · intro hunsat
    have hz : ∀ (Y : Type) (W : T → Y → Bool) (y : Y),
        GkatGS.bval W r y = false := by
      intro Y W y
      cases hb : GkatGS.bval W r y
      · rfl
      · exact absurd ⟨Y, W, y, hb⟩ hunsat
    exact EquivBA.trans (GkatGuardedAlgebra.test_unsat_seq u hz)
      (EquivBA.symm (GkatGuardedAlgebra.test_unsat_seq target hz))

/-- A fold that selects a FIXED expression throughout a region equals
    that expression on the region — however many branches it takes to get
    there, and whichever of them fire. -/
private theorem fold_const_under (B : List (BExp T × Exp A T)) :
    ∀ (fb target : Exp A T) (r : BExp T),
      (∀ (X : Type) (W : T → X → Bool) (x : X),
          GkatGS.bval W r x = true → EquivBA (selectFull W x B fb) target) →
      EquivBA (.seq (.test r) (guardedFold B fb)) (.seq (.test r) target) := by
  induction B with
  | nil => intro fb target r h; exact const_under h
  | cons br tl ih =>
      intro fb target r h
      obtain ⟨g, u⟩ := br
      refine EquivBA.trans
        (GkatGuardedAlgebra.test_seq_ite r g u (guardedFold tl fb)) ?_
      refine EquivBA.trans (EquivBA.base (Equiv.u4 (.and r g) _ _)) ?_
      refine EquivBA.trans (gate_else (.and r g) _ _) ?_
      refine EquivBA.trans ?_ (EquivBA.symm (split_assertion r g target))
      refine EquivBA.ite_c ?_ ?_
      · refine const_under ?_
        intro Y W y hy
        obtain ⟨hr, hgv⟩ := and_true_split hy
        have hsel := h Y W y hr
        rw [selectFull_cons_true W y u tl fb hgv] at hsel
        exact hsel
      · refine EquivBA.trans
          (GkatGuardedAlgebra.test_seq_merge _ _ (guardedFold tl fb)) ?_
        refine EquivBA.trans (GkatGuardedAlgebra.test_seq_guard_congr
          (b := .and (.not (.and r g)) r) (c := .and r (.not g))
          (guardedFold tl fb) ?_) ?_
        · intro Y W y
          show ((!(GkatGS.bval W r y && GkatGS.bval W g y))
              && GkatGS.bval W r y)
            = (GkatGS.bval W r y && !(GkatGS.bval W g y))
          cases GkatGS.bval W r y <;> cases GkatGS.bval W g y <;> rfl
        refine ih fb target (.and r (.not g)) ?_
        intro Y W y hy
        obtain ⟨hr, hgv⟩ := and_not_true_split hy
        have hsel := h Y W y hr
        rw [selectFull_cons_false W y u tl fb hgv] at hsel
        exact hsel

/-- The relativized form of the headline theorem. -/
private theorem fold_select_under (B : List (BExp T × Exp A T)) :
    ∀ (fb : Exp A T) (B' : List (BExp T × Exp A T)) (fb' : Exp A T) (r : BExp T),
      (∀ (X : Type) (W : T → X → Bool) (x : X),
          GkatGS.bval W r x = true →
          EquivBA (selectFull W x B fb) (selectFull W x B' fb')) →
      EquivBA (.seq (.test r) (guardedFold B fb))
        (.seq (.test r) (guardedFold B' fb')) := by
  induction B with
  | nil =>
      intro fb B' fb' r h
      exact EquivBA.symm (fold_const_under B' fb' fb r
        (fun Y W y hy => EquivBA.symm (h Y W y hy)))
  | cons br tl ih =>
      intro fb B' fb' r h
      obtain ⟨g, u⟩ := br
      refine EquivBA.trans
        (GkatGuardedAlgebra.test_seq_ite r g u (guardedFold tl fb)) ?_
      refine EquivBA.trans (EquivBA.base (Equiv.u4 (.and r g) _ _)) ?_
      refine EquivBA.trans (gate_else (.and r g) _ _) ?_
      refine EquivBA.trans ?_
        (EquivBA.symm (split_assertion r g (guardedFold B' fb')))
      refine EquivBA.ite_c ?_ ?_
      · refine EquivBA.symm (fold_const_under B' fb' u (.and r g) ?_)
        intro Y W y hy
        obtain ⟨hr, hgv⟩ := and_true_split hy
        have hsel := h Y W y hr
        rw [selectFull_cons_true W y u tl fb hgv] at hsel
        exact EquivBA.symm hsel
      · refine EquivBA.trans
          (GkatGuardedAlgebra.test_seq_merge _ _ (guardedFold tl fb)) ?_
        refine EquivBA.trans (GkatGuardedAlgebra.test_seq_guard_congr
          (b := .and (.not (.and r g)) r) (c := .and r (.not g))
          (guardedFold tl fb) ?_) ?_
        · intro Y W y
          show ((!(GkatGS.bval W r y && GkatGS.bval W g y))
              && GkatGS.bval W r y)
            = (GkatGS.bval W r y && !(GkatGS.bval W g y))
          cases GkatGS.bval W r y <;> cases GkatGS.bval W g y <;> rfl
        refine ih fb B' fb' (.and r (.not g)) ?_
        intro Y W y hy
        obtain ⟨hr, hgv⟩ := and_not_true_split hy
        have hsel := h Y W y hr
        rw [selectFull_cons_false W y u tl fb hgv] at hsel
        exact hsel

/-- **DECISION LISTS THAT DECIDE THE SAME THING ARE PROVABLY EQUAL.**
    If two guarded folds run EquivBA-equal expressions at every atom,
    they are EquivBA-equal — from the finite GKAT axioms, with no
    uniqueness axiom and no assumption whatsoever about the shape,
    length, order, or satisfiability of either branch list.

    This is the transition dimension of same-side unification stated in
    the only form bisimilarity can supply it: bisimilarity compares
    SELECTIONS, never lists. -/
theorem guardedFold_select_congr (B B' : List (BExp T × Exp A T))
    (fb fb' : Exp A T)
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X),
        EquivBA (selectFull W x B fb) (selectFull W x B' fb')) :
    EquivBA (guardedFold B fb) (guardedFold B' fb') :=
  EquivBA.trans (EquivBA.symm (GkatGuardedAlgebra.one_seq _))
    (EquivBA.trans
      (fold_select_under B fb B' fb' .one (fun Y W y _ => h Y W y))
      (GkatGuardedAlgebra.one_seq _))

#print axioms split_assertion
#print axioms const_under
#print axioms guardedFold_select_congr

/-- The selection of a labelled transition list IS `firstMatch`, read
    through the labelling.  This is the bridge from the automaton to the
    decision-list lemma. -/
theorem selectFull_transitionBranches {S X : Type} (W : T → X → Bool) (x : X)
    (sol : S → Exp A T) (h : BExp T) :
    ∀ L : List (BExp T × A × S),
      selectFull W x (transitionBranches L sol) (.test h)
        = (match firstMatch W x L with
           | some qt => .seq (.act qt.1) (sol qt.2)
           | none => .test h)
  | [] => rfl
  | (g, q, t) :: tl => by
      show (match GkatGS.bval W g x with
        | true => Exp.seq (.act q) (sol t)
        | false => selectFull W x (transitionBranches tl sol) (.test h))
        = _
      cases hb : GkatGS.bval W g x
      · rw [selectFull_transitionBranches W x sol h tl]
        show _ = (match (if GkatGS.bval W g x = true then some (q, t)
                         else firstMatch W x tl) with
          | some qt => Exp.seq (.act qt.1) (sol qt.2)
          | none => Exp.test h)
        rw [hb]
        rfl
      · show _ = (match (if GkatGS.bval W g x = true then some (q, t)
                         else firstMatch W x tl) with
          | some qt => Exp.seq (.act qt.1) (sol qt.2)
          | none => Exp.test h)
        rw [hb]
        rfl

/-- **THE ONE-STEP SAME-SIDE UNIFICATION LEMMA, AT THE AUTOMATON.**  Two
    states of one automaton whose Salomaa right-hand sides SELECT
    EquivBA-equal expressions at every atom have EquivBA-equal right-hand
    sides — whatever their transition lists look like.

    This is the shape bisimilarity can actually feed: `GAutBisim` gives
    global halt agreement (its first conjunct) and, at each atom, the
    same action into related targets.  What it never gives is a relation
    between the two branch LISTS, and this lemma never asks for one. -/
theorem eqRHS_congr_of_select {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (s t : S)
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X),
        EquivBA
          (selectFull W x (transitionBranches (aut.trans s) sol)
            (.test (aut.hlt s)))
          (selectFull W x (transitionBranches (aut.trans t) sol)
            (.test (aut.hlt t)))) :
    EquivBA (eqRHS aut sol s) (eqRHS aut sol t) := by
  rw [eqRHS_eq_guardedFold, eqRHS_eq_guardedFold]
  exact guardedFold_select_congr _ _ _ _ h

#print axioms selectFull_transitionBranches
#print axioms eqRHS_congr_of_select

/-! ### CLASS-CONSTANT SOLUTIONS: the quotient's equations lift for free

    This repository has been carrying TWO open hypotheses under two
    names.  `GkatSumQuotient.SumQuotientSolvable` asks for a solution of
    a behavioural QUOTIENT of the Thompson sum; the rewired-summit line
    asks for same-side unification, that bisimilar states of ONE
    automaton carry EquivBA-equal labels.  They are the same hypothesis,
    and this section proves it.

    The bridge is a labelling that is CONSTANT on bisimilarity classes —
    a quotient solution, read back on the original state space.  Two
    facts make the identification work, and the first is new:

    * `class_constant_solves_of_reps`: a class-constant labelling that
      satisfies the equations at ONE REPRESENTATIVE of each class
      satisfies them EVERYWHERE.  So solving the quotient really is
      enough; nothing is lost in reading the solution back.  This is what
      `guardedFold_select_congr` was built for — bisimilar states select
      the same action into bisimilar targets, and on a class-constant
      labelling those targets carry LITERALLY EQUAL labels, so no
      circularity arises.

    * `unif_of_class_constant_solution` / `class_constant_solution_of_unif`:
      given uniqueness of solutions (which
      `certifiedThompson_solution_unique` supplies unconditionally for
      Thompson automata), same-side unification holds IFF a
      class-constant solution exists.

    The consequence worth stating plainly: what remains of the open
    problem is EXISTENTIAL, not coinductive.  There is nothing left to
    prove about bisimulation; there is an expression to exhibit. -/

private theorem equivBA_of_eq {e f : Exp A T} (h : e = f) : EquivBA e f := by
  cases h
  exact EquivBA.base (Equiv.refl _)

/-- **Bisimilar states select equal labels — when the labelling is
    class-constant.**  This is the non-circular use of bisimilarity: the
    targets are merely bisimilar, but a class-constant labelling gives
    them the SAME expression, so no inductive hypothesis is consumed. -/
theorem select_congr_of_bisim {S : Type} (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T)
    (hconst : ∀ u v, GkatPlanExistence.GenBisimilar aut u v → sol u = sol v)
    {u v : S} (hb : GkatPlanExistence.GenBisimilar aut u v)
    (X : Type) (W : T → X → Bool) (x : X) :
    EquivBA
      (selectFull W x (transitionBranches (aut.trans u) sol)
        (.test (aut.hlt u)))
      (selectFull W x (transitionBranches (aut.trans v) sol)
        (.test (aut.hlt v))) := by
  obtain ⟨R, hR, huv⟩ := hb
  obtain ⟨hhlt, hfwd, hbwd⟩ := hR u v huv
  rw [selectFull_transitionBranches, selectFull_transitionBranches,
    GkatPlanExistence.firstMatch_gen W x (aut.trans u),
    GkatPlanExistence.firstMatch_gen W x (aut.trans v)]
  cases hu : firstMatch (GkatPlanExistence.genW T)
      (fun t => W t x) (aut.trans u) with
  | some qt =>
      obtain ⟨q, u'⟩ := qt
      obtain ⟨v', hv, hrel⟩ := hfwd (fun t => W t x) q u' hu
      have hv' : firstMatch (GkatPlanExistence.genW T)
          (fun t => W t x) (aut.trans v) = some (q, v') := hv
      rw [hv']
      show EquivBA (.seq (.act q) (sol u')) (.seq (.act q) (sol v'))
      rw [hconst u' v' ⟨R, hR, hrel⟩]
      exact EquivBA.base (Equiv.refl _)
  | none =>
      cases hv : firstMatch (GkatPlanExistence.genW T)
          (fun t => W t x) (aut.trans v) with
      | some qt =>
          obtain ⟨q, v'⟩ := qt
          obtain ⟨u', hu', _⟩ := hbwd (fun t => W t x) q v' hv
          have hu'' : firstMatch (GkatPlanExistence.genW T)
              (fun t => W t x) (aut.trans u) = some (q, u') := hu'
          rw [hu''] at hu
          simp at hu
      | none =>
          show EquivBA (.test (aut.hlt u) : Exp A T) (.test (aut.hlt v))
          refine EquivBA.baTest ?_
          intro Y W' y
          rw [GkatPlanExistence.bval_gen W' y (aut.hlt u),
            GkatPlanExistence.bval_gen W' y (aut.hlt v)]
          exact hhlt (fun t => W' t y)

/-- **THE QUOTIENT'S EQUATIONS LIFT.**  A class-constant labelling that
    satisfies the system at one REPRESENTATIVE of each bisimilarity class
    satisfies it at EVERY state.

    So "solve the quotient" and "solve the automaton with a
    class-constant labelling" are the same task.  Reading a quotient
    solution back onto the original state space costs nothing. -/
theorem class_constant_solves_of_reps {S : Type} (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T) (rep : S → S)
    (hrep : ∀ s, GkatPlanExistence.GenBisimilar aut s (rep s))
    (hconst : ∀ u v, GkatPlanExistence.GenBisimilar aut u v → sol u = sol v)
    (hreps : ∀ s, EquivBA (sol (rep s)) (GkatKleene.eqRHS aut sol (rep s))) :
    ∀ s, EquivBA (sol s) (GkatKleene.eqRHS aut sol s) := fun s =>
  EquivBA.trans (equivBA_of_eq (hconst s (rep s) (hrep s)))
    (EquivBA.trans (hreps s)
      (eqRHS_congr_of_select aut sol (rep s) s
        (select_congr_of_bisim aut sol hconst
          (GkatPlanExistence.GenBisimilar.symm (hrep s)))))

/-- **Same-side unification FROM a class-constant solution.**  With
    solution uniqueness in hand — which `certifiedThompson_solution_unique`
    supplies for Thompson automata from the finite axioms alone — a
    class-constant solution collapses the whole statement. -/
theorem unif_of_class_constant_solution {S : Type}
    (aut : GkatKleene.GAut S A T) (sol solQ : S → Exp A T)
    (hsol : ∀ s, EquivBA (sol s) (GkatKleene.eqRHS aut sol s))
    (hsolQ : ∀ s, EquivBA (solQ s) (GkatKleene.eqRHS aut solQ s))
    (huniq : ∀ l r : S → Exp A T,
        (∀ s, EquivBA (l s) (GkatKleene.eqRHS aut l s)) →
        (∀ s, EquivBA (r s) (GkatKleene.eqRHS aut r s)) →
        ∀ s, EquivBA (l s) (r s))
    (hconst : ∀ u v, GkatPlanExistence.GenBisimilar aut u v → solQ u = solQ v) :
    ∀ u v, GkatPlanExistence.GenBisimilar aut u v →
      EquivBA (sol u) (sol v) := fun u v hb =>
  EquivBA.trans (huniq sol solQ hsol hsolQ u)
    (EquivBA.trans (equivBA_of_eq (hconst u v hb))
      (EquivBA.symm (huniq sol solQ hsol hsolQ v)))

/-- **A class-constant solution FROM same-side unification.**  The
    converse: under unification the standard labelling, restricted to
    representatives, is itself a class-constant solution.  Together with
    `unif_of_class_constant_solution` this is an equivalence — the
    project's two open hypotheses are one. -/
theorem class_constant_solution_of_unif {S : Type}
    (aut : GkatKleene.GAut S A T) (sol : S → Exp A T)
    (hsol : ∀ s, EquivBA (sol s) (GkatKleene.eqRHS aut sol s))
    (hunif : ∀ u v, GkatPlanExistence.GenBisimilar aut u v →
      EquivBA (sol u) (sol v)) :
    (∀ s, EquivBA (sol (GkatPlanExistence.bisimRep aut s))
        (GkatKleene.eqRHS aut
          (fun t => sol (GkatPlanExistence.bisimRep aut t)) s))
      ∧ (∀ u v, GkatPlanExistence.GenBisimilar aut u v →
          sol (GkatPlanExistence.bisimRep aut u)
            = sol (GkatPlanExistence.bisimRep aut v)) := by
  constructor
  · intro s
    refine EquivBA.trans (EquivBA.symm
      (hunif s (GkatPlanExistence.bisimRep aut s)
        (GkatPlanExistence.bisimRep_bisim aut s))) ?_
    refine EquivBA.trans (hsol s) ?_
    exact foldr_congr_equivBA (sol₁ := sol)
      (sol₂ := fun t => sol (GkatPlanExistence.bisimRep aut t))
      (aut.hlt s) (aut.trans s)
      (fun e _ => hunif e.2.2 (GkatPlanExistence.bisimRep aut e.2.2)
        (GkatPlanExistence.bisimRep_bisim aut e.2.2))
  · intro u v hb
    rw [GkatPlanExistence.bisimRep_coherent aut hb]

#print axioms select_congr_of_bisim
#print axioms class_constant_solves_of_reps
#print axioms unif_of_class_constant_solution
#print axioms class_constant_solution_of_unif

/-! ### UNIQUENESS TRANSFERS DOWN A SURJECTIVE HOMOMORPHISM

    Literature check (ICALP 2021, Smolka-Kappe-Foster-Rot-Silva), which
    changes the map in two ways; both are load-bearing and both are
    recorded here so they are not re-derived:

    * **The route through well-nestedness is REFUTED by the authors
      themselves.**  Their Figure 4 exhibits a well-nested automaton
      whose quotient (identifying `v1` with `v4` and `v3` with `v6`) is
      NOT well-nested.  So "the behavioural quotient of a Thompson sum is
      well-nested" is false, and no amount of searching will make it true.
    * **But the quotient does satisfy the nesting coequation.**  `Cov(W)`
      is a covariety, closed under homomorphic images (Prop. 13/14), and
      a quotient is a homomorphic image.  The quotient therefore stays
      inside the expressible class; what it loses is only the syntactic
      witness.

    Their completeness proof uses UA at exactly one place: the
    bisimulation yields a Salomaa system admitting BOTH derivative
    labellings as solutions, and UA collapses them (Thm. 17, Cor. 22).
    So in their argument, as in ours, EXISTENCE is free and UNIQUENESS is
    the whole of what UA buys.

    This section buys part of it back.  A surjective homomorphism carries
    uniqueness DOWNWARD: two solutions of the target pull back along the
    homomorphism (`GAutHom.lift_solvesBA`), uniqueness upstairs
    identifies the pullbacks, and surjectivity carries the identification
    back down.

    The consequence for this project: a behavioural quotient of a
    Thompson sum inherits uniqueness from
    `certifiedThompson_solution_unique` with NO uniqueness axiom.  **Any
    class-constant solution that exists is THE solution** — nothing is
    lost by choosing badly, and the entire remaining gap is existence. -/

/-- **UNIQUENESS TRANSFERS DOWN A SURJECTIVE HOMOMORPHISM.**  If the
    source system has provably unique solutions and `phi` is onto the
    target's listed states, the target system has provably unique
    solutions too.

    Uniqueness is precisely what UA is used for in the published
    completeness proof.  This recovers it, from the finite axioms, for
    every automaton this development actually quotients. -/
theorem unique_of_surjective_hom {S Q : Type}
    {aut : GAut S A T} {quot : GAut Q A T} (phi : GAutHom aut quot)
    (hsurj : ∀ q ∈ quot.states, ∃ s ∈ aut.states, phi.mapState s = q)
    (huniq : ∀ l r : S → Exp A T, SolvesBA aut l → SolvesBA aut r →
      ∀ s ∈ aut.states, EquivBA (l s) (r s))
    {l r : Q → Exp A T} (hl : SolvesBA quot l) (hr : SolvesBA quot r) :
    ∀ q ∈ quot.states, EquivBA (l q) (r q) := by
  intro q hq
  obtain ⟨s, hs, hmap⟩ := hsurj q hq
  have hkey := huniq _ _ (phi.lift_solvesBA hl) (phi.lift_solvesBA hr) s hs
  rw [hmap] at hkey
  exact hkey

#print axioms unique_of_surjective_hom

/-! ### GATED UNKNOWN IDENTIFICATION — the elimination move that was missing

    Iteration 185 exhibited a pair whose every admissible quotient has a
    two-exit SCC, and showed classical elimination stalls on it: after
    `w3` closes one unknown, the other occurs in BOTH branches.  Iteration
    186 solved it anyway, by a move classical Gaussian elimination does
    not have.

    Ordinary elimination SUBSTITUTES an unknown's definition.  The move
    below REWRITES ONE UNKNOWN AS ANOTHER on a region where their
    dispatches agree.  In the resistant instance the two loop states
    differ only at a single atom; off that atom they select identically,
    so under `¬a0` one may stand for the other, and the equation

        X₁ = ite a0 (p ; X₂) X₁      (trivially)

    becomes

        X₁ = ite a0 (p ; X₂) X₀      (by the gated rewrite)

    which IS a Salomaa equation in `X₁` with `X₀` as its exit — and `w3`
    closes it.  The two-exit obstruction dissolves because the second exit
    was never a separate exit; it was the same exit reached through a
    state that agrees off one atom.

    The engine is the relativized selection congruence proved in
    iteration 169 (`fold_select_under`), which has been sitting private in
    this file since then.  It is exposed here at the automaton level. -/

/-- **SELECTION CONGRUENCE, RELATIVIZED.**  Two states whose dispatches
    select EquivBA-equal expressions THROUGHOUT A REGION have
    EquivBA-equal right-hand sides under that region's assertion.

    The unrelativized form (`eqRHS_congr_of_select`) needs agreement at
    every atom; this needs it only where the assertion holds. -/
theorem eqRHS_congr_of_select_under {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (u v : S) (r : BExp T)
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W r x = true →
        EquivBA
          (selectFull W x (transitionBranches (aut.trans u) sol)
            (.test (aut.hlt u)))
          (selectFull W x (transitionBranches (aut.trans v) sol)
            (.test (aut.hlt v)))) :
    EquivBA (.seq (.test r) (eqRHS aut sol u))
      (.seq (.test r) (eqRHS aut sol v)) := by
  rw [eqRHS_eq_guardedFold, eqRHS_eq_guardedFold]
  exact fold_select_under _ _ _ _ r h

/-- **GATED UNKNOWN IDENTIFICATION.**  In a solved system, two states
    whose dispatches agree throughout a region are interchangeable under
    that region's assertion — so an occurrence of one inside a branch
    guarded by the region may be replaced by the other.

    This is the elimination move classical Gaussian elimination lacks: it
    does not unfold a definition, it identifies two unknowns where they
    cannot be told apart.  Iteration 186's resistant instance is solved by
    exactly one application. -/
theorem gated_unknown_identification {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (u v : S) (r : BExp T)
    (hsol : ∀ s, EquivBA (sol s) (eqRHS aut sol s))
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W r x = true →
        EquivBA
          (selectFull W x (transitionBranches (aut.trans u) sol)
            (.test (aut.hlt u)))
          (selectFull W x (transitionBranches (aut.trans v) sol)
            (.test (aut.hlt v)))) :
    EquivBA (.seq (.test r) (sol u)) (.seq (.test r) (sol v)) :=
  EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (hsol u))
    (EquivBA.trans (eqRHS_congr_of_select_under aut sol u v r h)
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.symm (hsol v))))

/-- The rewrite the move licenses: an else arm may be replaced by anything
    the region `¬g` cannot distinguish from it.  Combined with
    `gated_unknown_identification` at `r := ¬g`, this is the whole step. -/
theorem ite_else_swap {g : BExp T} {u v v' : Exp A T}
    (h : EquivBA (.seq (.test (.not g)) v) (.seq (.test (.not g)) v')) :
    EquivBA (.ite g u v) (.ite g u v') :=
  EquivBA.trans (GkatGuardedAlgebra.ite_restrict_else g u v)
    (EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl u)) h)
      (EquivBA.symm (GkatGuardedAlgebra.ite_restrict_else g u v')))

#print axioms eqRHS_congr_of_select_under
#print axioms gated_unknown_identification
#print axioms ite_else_swap

/-! ### THE GATED REWRITE, as the calculus uses it

    Iterations 186–193 built a three-rule calculus and measured it: over six
    populations and about 1.44 million program pairs, every lattice-resistant
    SCC is solved, and every solution is a constructed expression checked
    against the quotient's language.  The rules are elimination (`w3`,
    already `self_gather_role`), exit absorption (`exit_absorb`), and the
    GATED REWRITE.

    This is the gated rewrite in the form the solver applies it.  Not the
    semantic statement of iteration 186 — the EQUATIONAL one: an unknown may
    be replaced by another INSIDE THE ELSE ARM of the region where they
    differ, because the else arm is only ever observed there.

        sol u  ≡  ite d (sol u) (sol v)

    `u1` duplicates, `ite_else_swap` rewrites the else arm, and the
    hypothesis is `gated_unknown_identification` at `¬d`.  Three lines, and
    it is the whole rule.

    `gated_rewrite_reject` is the special case that closed the last three
    measured instances: when `u` merely REJECTS throughout `d`, its own arm
    collapses to `0` and the equation becomes CLOSED — no self-reference —
    which is exactly what let `w3` finish. -/

/-- **THE GATED REWRITE.**  Two states agreeing off a region `d` are
    interchangeable in the else arm of `d`. -/
theorem gated_rewrite {S : Type} (aut : GAut S A T) (sol : S → Exp A T)
    (u v : S) (d : BExp T)
    (hsol : ∀ s, EquivBA (sol s) (eqRHS aut sol s))
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W (.not d) x = true →
        EquivBA
          (selectFull W x (transitionBranches (aut.trans u) sol)
            (.test (aut.hlt u)))
          (selectFull W x (transitionBranches (aut.trans v) sol)
            (.test (aut.hlt v)))) :
    EquivBA (sol u) (.ite d (sol u) (sol v)) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u1 d (sol u))))
    (ite_else_swap (gated_unknown_identification aut sol u v (.not d) hsol h))

/-- **THE REJECTING CASE.**  If `u` rejects throughout `d`, the rewrite makes
    its equation CLOSED — the self-reference is gone and `w3` can finish.

    This is the shape that resisted the solver until iteration 193: two
    states with identical transitions whose halt masks differ at one atom,
    one accepting there and the other rejecting.  The rewritten equation has
    no branches at all, and everything is in the fallback. -/
theorem gated_rewrite_reject {S : Type} (aut : GAut S A T) (sol : S → Exp A T)
    (u v : S) (d : BExp T)
    (hsol : ∀ s, EquivBA (sol s) (eqRHS aut sol s))
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W (.not d) x = true →
        EquivBA
          (selectFull W x (transitionBranches (aut.trans u) sol)
            (.test (aut.hlt u)))
          (selectFull W x (transitionBranches (aut.trans v) sol)
            (.test (aut.hlt v))))
    (hzero : EquivBA (.seq (.test d) (sol u)) (.test .zero)) :
    EquivBA (sol u) (.ite d (.test .zero) (sol v)) :=
  EquivBA.trans (gated_rewrite aut sol u v d hsol h)
    (EquivBA.trans (EquivBA.base (Equiv.u4 d (sol u) (sol v)))
      (EquivBA.ite_c hzero (EquivBA.base (Equiv.refl _))))

#print axioms gated_rewrite
#print axioms gated_rewrite_reject

/-! ### THE GATED RULE, CONSTRUCTIVELY

    `gated_rewrite` is the ANALYTIC form: given a labelling that already
    solves the system, two states agreeing off `d` are interchangeable in the
    else arm.  That is the right statement for reasoning about a solution,
    and the wrong one for BUILDING one — the calculus does not have a
    solution yet, it is making one.

    `gated_solves` is the constructive form.  It says: DEFINE `sol u` to be
    `ite d D (sol v)`, where `D` agrees with `u`'s own equation on `d`; then
    `sol u` satisfies `u`'s equation.  Nothing about the rest of the system
    is assumed beyond `v` satisfying its own.

    That is what the elimination loop needs at each GATED step, and it is the
    last rule to have both forms. -/

/-- Any expression splits on any region. -/
private theorem split_on (d : BExp T) (e : Exp A T) :
    EquivBA e (.ite d (.seq (.test d) e) (.seq (.test (.not d)) e)) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u1 d e)))
    (EquivBA.trans (EquivBA.base (Equiv.u4 d e e))
      (GkatGuardedAlgebra.ite_restrict_else d (.seq (.test d) e) e))

/-- …and the assertions come back off. -/
private theorem unsplit (d : BExp T) (a b : Exp A T) :
    EquivBA (.ite d (.seq (.test d) a) (.seq (.test (.not d)) b)) (.ite d a b) :=
  EquivBA.trans
    (EquivBA.symm
      (GkatGuardedAlgebra.ite_restrict_else d (.seq (.test d) a) b))
    (EquivBA.symm (EquivBA.base (Equiv.u4 d a b)))

/-- Congruence in the THEN arm, with the guard available — the dual of
    `ite_else_swap`, by `u4` on both sides. -/
theorem ite_then_swap {g : BExp T} {a a' b : Exp A T}
    (h : EquivBA (.seq (.test g) a) (.seq (.test g) a')) :
    EquivBA (.ite g a b) (.ite g a' b) :=
  EquivBA.trans (EquivBA.base (Equiv.u4 g a b))
    (EquivBA.trans (EquivBA.ite_c h (EquivBA.base (Equiv.refl b)))
      (EquivBA.symm (EquivBA.base (Equiv.u4 g a' b))))

/-- **THE GATED RULE, CONSTRUCTIVELY.**  Define `sol u := ite d D (sol v)`
    with `D` agreeing with `u`'s equation on `d`, where `u` and `v` select
    EquivBA-equal expressions off `d`.  Then `sol u` SATISFIES `u`'s
    equation — so the definition is a legitimate step of the elimination,
    not merely an identity that holds once a solution exists.

    In the rejecting case the caller takes `D := 0`, and `hD` is then the
    statement that `u` rejects throughout `d`. -/
theorem gated_solves {S : Type} (aut : GAut S A T) (sol : S → Exp A T)
    (u v : S) (d : BExp T) (D : Exp A T)
    (hsolv : EquivBA (sol v) (eqRHS aut sol v))
    (hagree : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W (.not d) x = true →
        EquivBA
          (selectFull W x (transitionBranches (aut.trans u) sol)
            (.test (aut.hlt u)))
          (selectFull W x (transitionBranches (aut.trans v) sol)
            (.test (aut.hlt v))))
    (hD : EquivBA (.seq (.test d) D) (.seq (.test d) (eqRHS aut sol u)))
    (hu : sol u = .ite d D (sol v)) :
    EquivBA (sol u) (eqRHS aut sol u) :=
  EquivBA.trans (equivBA_of_eq hu)
    (EquivBA.symm
      (EquivBA.trans (split_on d (eqRHS aut sol u))
        (EquivBA.trans
          (EquivBA.ite_c (EquivBA.symm hD)
            (EquivBA.trans
              (eqRHS_congr_of_select_under aut sol u v (.not d) hagree)
              (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
                (EquivBA.symm hsolv))))
          (unsplit d D (sol v)))))

#print axioms ite_then_swap
#print axioms gated_solves

/-- **THE GATED RULE AS A ROLE.**  `gated_solves` feeds straight into
    `StateRole.equivFold`, so a GATED step is a role like any other and
    `decomp_solves` assembles it with the rest.

    That closes the SOUNDNESS half of the elimination loop.  Every rule now
    has a constructive form producing a role for the state it assigns —

        SUBST            definitional
        LOOPIFY          `StateRole.salomaaE`, discharged by
                         `salomaa_solution_exists`, with `exit_absorb` for
                         the absorbing case
        GATED            this

    — and `decomp_solves` turns a full assignment of roles into `SolvesBA`.
    What remains open is SUFFICIENCY: that the rules can always be applied
    until every state is assigned.  Soundness is a packaging question and is
    now finished; sufficiency is the mathematics. -/
theorem gated_role {S : Type} (aut : GAut S A T) (sol : S → Exp A T)
    (u v : S) (d : BExp T) (D : Exp A T)
    (hsolv : EquivBA (sol v) (eqRHS aut sol v))
    (hagree : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W (.not d) x = true →
        EquivBA
          (selectFull W x (transitionBranches (aut.trans u) sol)
            (.test (aut.hlt u)))
          (selectFull W x (transitionBranches (aut.trans v) sol)
            (.test (aut.hlt v))))
    (hD : EquivBA (.seq (.test d) D) (.seq (.test d) (eqRHS aut sol u)))
    (hu : sol u = .ite d D (sol v)) :
    GkatDecomp.StateRole aut sol u :=
  GkatDecomp.StateRole.equivFold
    (gated_solves aut sol u v d D hsolv hagree hD hu)

#print axioms gated_role

/-! ### ENTRY RESTRICTION — the fourth rule

    Iteration 197 found the first SCC neither the lattice nor the calculus
    handles; 198 solved it by hand and checked the answer.  The move is:
    PRE-GUARD the loop and ASSERT at the end of its body, so that the
    trailing test can be WIDENED to cover a mid-body exit that exit
    absorption cannot reach.

    The algebra behind it is a loop invariant, in the Hoare sense.  If the
    body always terminates inside a region `R` and the loop is ENTERED
    inside `R`, then `R` holds at every arrival at the loop head, so the
    trailing test is only ever evaluated on `R ∧ ¬g` — and any two trailing
    tests agreeing there are interchangeable.

    `exit_absorb` (188) is the case where the restriction is vacuous.  This
    is the first of the four rules whose Lean form was not already in the
    corpus. -/

/-- **ENTRY RESTRICTION.**  Under a body that preserves `R` and an entry
    inside `R`, the trailing test after the loop only ever sees `R ∧ ¬g`.

    Proved by `w3`: both sides satisfy the SAME Salomaa equation once `R` is
    carried through the body, so uniqueness identifies them.  `hprod` is
    `w3`'s productivity side condition on the body. -/
theorem entry_restricted_trailing {g R F₁ F₂ : BExp T} {B : Exp A T}
    (hprod : EquivBA (.test (E B) : Exp A T) (.test .zero))
    (hB : EquivBA (.seq B (.test R)) B)
    (hF : ∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W (.and (.not (.and R g)) (.and R F₂)) x
          = GkatGS.bval W (.and (.not (.and R g)) (.and R F₁)) x) :
    EquivBA (.seq (.test R) (.seq (.wh g B) (.test F₁)))
      (.seq (.test R) (.seq (.wh g B) (.test F₂))) := by
  have step : ∀ F : BExp T,
      EquivBA (.seq (.test R) (.seq (.wh g B) (.test F)))
        (.ite (.and R g)
          (.seq B (.seq (.test R) (.seq (.wh g B) (.test F))))
          (.test (.and R F))) := by
    intro F
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.base (salomaa_solution_exists g B (.test F)))) ?_
    refine EquivBA.trans (GkatGuardedAlgebra.test_seq_ite R g _ _) ?_
    refine EquivBA.ite_c ?_ (EquivBA.s6 R F)
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.symm hB) (EquivBA.base (Equiv.refl _))) ?_
    exact EquivBA.base (Equiv.s1 B (.test R) _)
  have h1 := EquivBA.w3_ba hprod (step F₁)
  have h2 := EquivBA.w3_ba hprod
    (EquivBA.trans (step F₂)
      (ite_else_swap
        (EquivBA.trans (EquivBA.s6 (.not (.and R g)) (.and R F₂))
          (EquivBA.trans (EquivBA.baTest hF)
            (EquivBA.symm (EquivBA.s6 (.not (.and R g)) (.and R F₁)))))))
  exact EquivBA.trans h1 (EquivBA.symm h2)

#print axioms entry_restricted_trailing

/-- A guard that is identically `0` selects the else arm. -/
theorem ite_zero_guard (e f : Exp A T) :
    EquivBA (.ite .zero e f : Exp A T) f :=
  EquivBA.trans (EquivBA.base (Equiv.u2 .zero e f))
    (EquivBA.trans
      (EquivBA.ite_guard (b := (.not .zero : BExp T)) (c := .one)
        (fun _ _ _ => rfl))
      (ite_one f e))

#print axioms ite_zero_guard

/-- **RULE 5: HALT-IN-BODY LOOPIFICATION.**

    Iteration 201's census resister is a three-state SCC whose solution
    recurses under a test (`c`) that DIFFERS from its entry test (`g`), with
    the recursion site sitting inside an `ite` whose *other* branch is a HALT
    rather than a dead end:

        X ≡ ite g (D · ite c (P · X) 1) 1        with  D · ¬g ≡ D

    The four rules proved so far cannot close this: `exit_absorb` needs the
    mid-body exit to be reachable from the loop head's own halt, and
    `entry_restricted_trailing` needs one trailing test to cover every exit.
    Here the second exit lives *inside* the body.

    It loopifies anyway, because the halt branch is subsumed by the loop guard
    already being false where it sits.  `D · ¬g ≡ D` says the body lands
    outside `g`; so in the else arm of `c`, `X` unrolls to `1` — and dropping
    the recursive call there is exactly what turns the body into `D · ite c P 1`
    with `g` alone as the loop guard.  One trailing conditional action then
    serves as both the back-edge and the second exit.

    No auxiliary variable, no n-ary uniqueness: `w3_ba` at one unknown. -/
theorem halt_in_body_loopify {g c : BExp T} {D P X : Exp A T}
    (hprod : EquivBA
      (.test (E (.seq D (.ite c P (.test .one)))) : Exp A T) (.test .zero))
    (hD : EquivBA (.seq D (.test (.not g))) D)
    (hX : EquivBA X
      (.ite g (.seq D (.ite c (.seq P X) (.test .one))) (.test .one))) :
    EquivBA X (.wh g (.seq D (.ite c P (.test .one)))) := by
  -- Outside the loop guard the unknown is inert: `¬g · X ≡ ¬g · 1`.
  have hXng : EquivBA (.seq (.test (.not g)) X)
      (.seq (.test (.not g)) (.test .one)) := by
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hX) ?_
    refine EquivBA.trans (GkatGuardedAlgebra.test_seq_ite (.not g) g _ _) ?_
    refine EquivBA.trans
      (EquivBA.ite_guard (GkatGuardedAlgebra.bnot_and_self g)) ?_
    exact ite_zero_guard _ _
  -- Sequencing the folded body with the unknown reproduces the equation's RHS.
  have hbody : EquivBA
      (.seq (.seq D (.ite c P (.test .one))) X)
      (.seq D (.ite c (.seq P X) (.test .one))) := by
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc _ _ _) ?_
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl D))
      (GkatGuardedAlgebra.ite_seq_right c P (.test .one) X)) ?_
    -- Insert the landing assertion `¬g` supplied by `hD`, then use `hXng`.
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.symm hD)
      (EquivBA.base (Equiv.refl _))) ?_
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc _ _ _) ?_
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl D))
      (GkatGuardedAlgebra.test_seq_ite (.not g) c (.seq P X)
        (.seq (.test .one) X))) ?_
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl D))
      (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
        (EquivBA.trans
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (GkatGuardedAlgebra.one_seq X))
          hXng))) ?_
    -- Retract the assertion and restore the `c` guard.
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl D))
      (EquivBA.symm (GkatGuardedAlgebra.test_seq_ite (.not g) c
        (.seq P X) (.test .one)))) ?_
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc' _ _ _) ?_
    exact EquivBA.seq_c hD (EquivBA.base (Equiv.refl _))
  have hX' : EquivBA X
      (.ite g (.seq (.seq D (.ite c P (.test .one))) X) (.test .one)) :=
    EquivBA.trans hX
      (EquivBA.ite_c (EquivBA.symm hbody) (EquivBA.base (Equiv.refl _)))
  exact EquivBA.trans (EquivBA.w3_ba hprod hX')
    (GkatGuardedAlgebra.seq_one _)

#print axioms halt_in_body_loopify

/-- **RULE 6: TRAILING-SUFFIX SHARING.**

    Iteration 206's resister — the only SCC in 600 000 census pairs the
    five-rule calculus could not solve — is a 3-cycle carrying BOTH a
    halt-exit and a continuation-exit.  Rule 5 cannot reach it: its mid-body
    exit must be a halt, and here it is `p ; c5` with `c5 = wh{a1}(p) ; p`, an
    arbitrary continuation.

    The observation that closes it: `c5` ENDS in `p`, and the loop's own
    trailing expression is `p`.  Take the mid-body exit to be `p ; wh{a1}(p)`,
    which exits at `¬a1` — so the outer guard is then false, the loop exits,
    and the SHARED trailing `p` fires, reconstituting `c5` exactly.

    So a mid-body exit need not be a halt.  It needs to LAND OUTSIDE THE GUARD
    and SHARE THE LOOP'S TRAILING SUFFIX:

        X ≡ ite g (D · ite c (P · X) (H · F)) F     and     H · ¬g ≡ H
        ─────────────────────────────────────────────────────────────
        X ≡ wh g (D · ite c P H) · F

    Note `D` needs NO landing hypothesis here, unlike `halt_in_body_loopify`:
    the else arm is discharged entirely by `H`'s own landing, since `H · ¬g ≡ H`
    lets `¬g` be carried across `H` to meet the unknown.  Rule 5 is NOT a
    special case — at `H = 1` the hypothesis `1 · ¬g ≡ 1` would force `g ≡ 0` —
    so the two rules are genuinely different, and rule 5 pays for its halt with
    a hypothesis on `D` instead.

    `w3_ba` at one unknown; no n-ary uniqueness, no auxiliary variable. -/
theorem trailing_suffix_shared {g c : BExp T} {D P H F X : Exp A T}
    (hprod : EquivBA
      (.test (E (.seq D (.ite c P H))) : Exp A T) (.test .zero))
    (hH : EquivBA (.seq H (.test (.not g))) H)
    (hX : EquivBA X
      (.ite g (.seq D (.ite c (.seq P X) (.seq H F))) F)) :
    EquivBA X (.seq (.wh g (.seq D (.ite c P H))) F) := by
  -- Outside the loop guard the unknown is its own exit: `¬g · X ≡ ¬g · F`.
  have hXng : EquivBA (.seq (.test (.not g)) X)
      (.seq (.test (.not g)) F) := by
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hX) ?_
    refine EquivBA.trans (GkatGuardedAlgebra.test_seq_ite (.not g) g _ _) ?_
    refine EquivBA.trans
      (EquivBA.ite_guard (GkatGuardedAlgebra.bnot_and_self g)) ?_
    exact ite_zero_guard _ _
  -- `H` lands outside the guard, so it carries `¬g` across to the unknown.
  have hHX : EquivBA (.seq H X) (.seq H F) := by
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.symm hH) (EquivBA.base (Equiv.refl X))) ?_
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc _ _ _) ?_
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl H)) hXng) ?_
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc' _ _ _) ?_
    exact EquivBA.seq_c hH (EquivBA.base (Equiv.refl F))
  -- Sequencing the folded body with the unknown reproduces the equation's RHS.
  have hbody : EquivBA (.seq (.seq D (.ite c P H)) X)
      (.seq D (.ite c (.seq P X) (.seq H F))) := by
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc _ _ _) ?_
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl D))
      (GkatGuardedAlgebra.ite_seq_right c P H X)) ?_
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl D))
      (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) hHX)
  exact EquivBA.w3_ba hprod
    (EquivBA.trans hX
      (EquivBA.ite_c (EquivBA.symm hbody) (EquivBA.base (Equiv.refl F))))

#print axioms trailing_suffix_shared

/-- **THE 2-STATE LOOP WITH A GUARD-DISJOINT MID-BODY HALT.**

    Read a 2-state loop as an equation at its head `u`: guard `g = C_u` (the
    atoms continuing there), body `D` reaching `v`, continuation test
    `c = C_v`, back-edge action `P`, and — in the else arm — a HALT with region
    `h = H_v`:

        X ≡ ite g (D · ite c (P · X) (h · F)) F

    Iteration 211 verified exhaustively, over all 32 043 strongly connected
    2-state automata at NA = 2, 3, 4 with zero exceptions, that solvability
    REQUIRES `H_v ∩ C_u = ∅` — which says exactly `h ⟹ ¬g`.  And that is
    verbatim `trailing_suffix_shared`'s hypothesis `H · ¬g ≡ H` at `H = test h`:
    a test already implying `¬g` is unchanged by asserting `¬g` after it.  So
    the measured necessary condition IS the hypothesis rule 6 needs, and the
    loop closes with no new axiom.

    **This is NOT completeness at two states, and the reason is worth keeping.**
    An earlier draft of this docstring claimed it was.  Working rule 6's
    CONCLUSION through the same shape refutes that: the solution
    `wh g (D · ite c P (test h)) · F` puts the trailing `F` after the loop, so a
    mid-body exit at an atom of `H_v` must still pass `F = test H_u`.  That
    needs `H_v ⊆ H_u`, strictly stronger than `H_v ∩ C_u = ∅` (halts and
    transitions being disjoint at `u`, the former implies the latter).  Measured
    at iteration 212, `H_v ⊆ H_u ∨ H_u ⊆ H_v` also has zero false negatives in
    those 32 043 automata — so it too is necessary — and it raises agreement
    with the solvability oracle from 96/83/69% to 96/90/85% at NA = 2/3/4.

    Both conditions remain merely NECESSARY: 138 automata at NA=3 and 4 454 at
    NA=4 satisfy the refined one and are still unsolvable.  Further
    obstructions exist that neither sees.  What this theorem gives is one
    sufficient case, arrived at by deriving its hypothesis from a measurement
    rather than by guessing. -/
theorem two_state_solvable {g c h : BExp T} {D P F X : Exp A T}
    (hprod : EquivBA
      (.test (E (.seq D (.ite c P (.test h)))) : Exp A T) (.test .zero))
    (himp : GuardImplies h (.not g))
    (hX : EquivBA X
      (.ite g (.seq D (.ite c (.seq P X) (.seq (.test h) F))) F)) :
    EquivBA X (.seq (.wh g (.seq D (.ite c P (.test h)))) F) := by
  -- `h ⟹ ¬g` is exactly rule 6's landing hypothesis for `H = test h`.
  have hH : EquivBA (.seq (.test h) (.test (.not g)) : Exp A T) (.test h) :=
    EquivBA.trans (EquivBA.s6 h (.not g))
      (EquivBA.baTest (GkatGuardedAlgebra.band_of_implies himp))
  exact trailing_suffix_shared hprod hH hX

#print axioms two_state_solvable

/-! ## The remainder, as an induction on expressions

Every instrument this development has tried for deciding whether an ARBITRARY
automaton is solvable has failed, and not by accident: that is the literature's
own open problem.  `nested` turned out necessary but not sufficient; the
elimination oracle is wrong in both directions; the brute-force search gives
only size-bounded negatives.

But the target theorem never quantifies over arbitrary automata.  Its automata
are behavioural quotients of Thompson automata of EXPRESSIONS, and the
expression is always in hand.  So induct on the expression, where the
constructors — and `GkatThompson`'s `seqGSystem` / `loopInitialized` /
`sumGSystem` decomposition — give exactly the case structure the six rules
already have.

Iteration 170 reduced the whole remainder to same-side unification.  Written
against `certifiedThompson`, whose `standard` labelling already solves its
automaton by construction, that is: -/

/-- **THE WHOLE REMAINDER, AS ONE PREDICATE ON EXPRESSIONS.**  Bisimilar states
    of `e`'s Thompson automaton carry `EquivBA`-equal standard labels.

    By `unif_of_class_constant_solution` / `class_constant_solution_of_unif`
    (iteration 170) this is EQUIVALENT to `SumQuotientSolvable`, and
    `completeness_of_sumQuotientSolvable` turns that into completeness.  So
    `∀ e, ThompsonUnif e` IS the theorem. -/
def coreGAut (e : Exp A T)
    (s₀ : (GkatThompson.certifiedThompson A T e).State) :
    GkatKleene.GAut (GkatThompson.certifiedThompson A T e).State A T where
  states := (GkatThompson.certifiedThompson A T e).aut.core.states
  hlt := (GkatThompson.certifiedThompson A T e).aut.core.hlt
  trans := (GkatThompson.certifiedThompson A T e).aut.core.trans
  start := s₀

def ThompsonUnif (e : Exp A T) : Prop :=
  ∀ s₀ u v, GkatPlanExistence.GenBisimilar (coreGAut e s₀) u v →
    EquivBA ((GkatThompson.certifiedThompson A T e).standard u)
      ((GkatThompson.certifiedThompson A T e).standard v)

/-- Base case: `test t`'s Thompson automaton has NO states at all, so there is
    no `s₀` to quantify over and the statement is vacuous. -/
theorem thompsonUnif_test (t : BExp T) : ThompsonUnif (A := A) (.test t) :=
  fun s₀ _ _ _ => nomatch s₀

/-- Base case: `act a`'s Thompson automaton has ONE state, so any two states
    are equal and reflexivity finishes. -/
theorem thompsonUnif_act (a : A) : ThompsonUnif (A := A) (T := T) (.act a) :=
  fun _ _ _ _ => EquivBA.base (Equiv.refl _)

/-- **THE REMAINDER, REDUCED TO THREE INDUCTIVE STEPS.**

    The induction itself is discharged here and the base cases are proved, so
    what stands between this development and completeness is exactly the three
    hypotheses below — one per compound constructor.  Nothing is assumed about
    automata in general, and there is no `sorry`: the open content is carried
    as explicit hypotheses, which is what makes it checkable that they are ALL
    that is open.

    The `wh` step is the one that decides it, and it is where rules 5 and 6 have
    to earn their place: a loop's Thompson automaton is where bisimilar states
    can sit on opposite sides of the back edge. -/
theorem thompsonUnif_of_steps
    (hseq : ∀ e f : Exp A T, ThompsonUnif e → ThompsonUnif f →
      ThompsonUnif (.seq e f))
    (hite : ∀ (b : BExp T) (e f : Exp A T), ThompsonUnif e → ThompsonUnif f →
      ThompsonUnif (.ite b e f))
    (hwh : ∀ (b : BExp T) (e : Exp A T), ThompsonUnif e →
      ThompsonUnif (.wh b e)) :
    ∀ e : Exp A T, ThompsonUnif e := by
  intro e
  induction e with
  | test t => exact thompsonUnif_test t
  | act a => exact thompsonUnif_act a
  | seq e f ihe ihf => exact hseq e f ihe ihf
  | ite b e f ihe ihf => exact hite b e f ihe ihf
  | wh b e ihe => exact hwh b e ihe

#print axioms thompsonUnif_test
#print axioms thompsonUnif_act
#print axioms thompsonUnif_of_steps

/-- **THE `wh` CASE, ANATOMISED.**  Two structural facts make this step
    tractable, and both are definitional:

    * `loopInitialized` keeps the body's state set EXACTLY — a loop adds back
      EDGES, never states.  So `(.wh b e)`'s Thompson states ARE `e`'s.
    * the loop's standard labelling is the body's, postcomposed with the loop:
      `std_loop s = std_body s ; wh b e`.

    Together they turn the `wh` step into: loop-bisimilar `u`, `v` must satisfy
    `std_body u · wh b e ≡ std_body v · wh b e`.  Note this is WEAKER than
    `std_body u ≡ std_body v` — the trailing loop may equalise labels the body
    keeps apart, which is exactly the trailing-suffix phenomenon rule 6 was
    proved for. -/
theorem loop_state_eq (b : BExp T) (e : Exp A T) :
    (GkatThompson.certifiedThompson A T (.wh b e)).State
      = (GkatThompson.certifiedThompson A T e).State := rfl

theorem loop_standard_eq (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State) :
    (GkatThompson.certifiedThompson A T (.wh b e)).standard s
      = .seq ((GkatThompson.certifiedThompson A T e).standard s) (.wh b e) := rfl

/-- **The `wh` step, given the body case.**  When loop-bisimilar states are also
    BODY-bisimilar, the induction hypothesis discharges the step immediately:
    congruence of `seq` carries `std_body u ≡ std_body v` through the trailing
    loop.  What this does NOT cover is the residual case — loop-bisimilar but
    not body-bisimilar — which is possible because the loop's halt is
    `hlt_body ∧ ¬b`, so two states may differ in the body exactly where `b`
    holds and the back edge fires.  That residual is the real content of the
    `wh` step, and it is isolated here as an explicit hypothesis. -/
theorem thompsonUnif_wh_of_residual (b : BExp T) (e : Exp A T)
    (ih : ThompsonUnif e)
    (hresid : ∀ s₀ u v,
      GkatPlanExistence.GenBisimilar (coreGAut (.wh b e) s₀) u v →
      ¬ GkatPlanExistence.GenBisimilar (coreGAut e s₀) u v →
      EquivBA (.seq ((GkatThompson.certifiedThompson A T e).standard u) (.wh b e))
        (.seq ((GkatThompson.certifiedThompson A T e).standard v) (.wh b e))) :
    ThompsonUnif (.wh b e) := by
  intro s₀ u v hb
  by_cases hbody : GkatPlanExistence.GenBisimilar (coreGAut e s₀) u v
  · exact EquivBA.seq_c (ih s₀ u v hbody) (EquivBA.base (Equiv.refl _))
  · exact hresid s₀ u v hb hbody

#print axioms loop_state_eq
#print axioms loop_standard_eq
#print axioms thompsonUnif_wh_of_residual

/-- The loop's halt is the body's, restricted to `¬b`.  Definitional, and it
    pins where a loop can differ from its body: only where the body halts and
    the guard holds. -/
theorem loop_core_hlt (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State) :
    (GkatThompson.certifiedThompson A T (.wh b e)).aut.core.hlt s
      = .and ((GkatThompson.certifiedThompson A T e).aut.core.hlt s) (.not b) :=
  rfl

/-- And there the halt becomes a BACK EDGE into the body's own entry
    transitions, guarded by `hlt_body ∧ b`. -/
theorem loop_core_trans (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State) :
    (GkatThompson.certifiedThompson A T (.wh b e)).aut.core.trans s
      = (GkatThompson.certifiedThompson A T e).aut.core.trans s
        ++ (GkatThompson.certifiedThompson A T e).aut.initTrans.map
            (fun tr => (BExp.and ((GkatThompson.certifiedThompson A T e).aut.core.hlt s)
              (BExp.and b tr.1), tr.2)) :=
  rfl

/-- **WHAT THE `wh` STEP ACTUALLY NEEDS: A PARAMETRIC INDUCTION HYPOTHESIS.**

    219 measured the residual — loop-bisimilar but not body-bisimilar — and
    found it non-empty at 3-6%, so `ThompsonUnif e` is too weak to carry the
    `wh` step.  The diagnosis is visible in `loop_core_hlt` and
    `loop_core_trans`: a loop is the body with its halts REDIRECTED, halting
    only under `¬b` and looping back under `b`.  Asking about the body's own
    bisimilarity is asking the wrong question, because the states in question
    are never compared in the body — they are compared in the REDIRECTED body.

    The repo's Thompson development is already parametric for exactly this
    reason (`ParamSolvesBA sys sol finish`, and uniqueness quantified over
    `finish`).  The induction hypothesis has to be parametric too: unification
    for the body under ANY loop-redirection, with an ARBITRARY trailing
    continuation.

    **⚠ REFUTED AT ITERATION 221.  THIS PREDICATE IS FALSE, and everything
    below it is therefore VACUOUS.**  Quantifying over an ARBITRARY `F`
    includes `F = test 1`, at which the conclusion collapses to
    `std u ≡ std v`.  But the hypothesis only asks for bisimilarity in the
    REDIRECTED body, and iteration 219 measured 3-6% of loops containing states
    that are redirect-bisimilar while NOT body-bisimilar — their body
    behaviours differ, so `std u ≡ std v` is refuted by soundness.  Concretely,
    at guard `a1` with body `q0 : hl={a0}, a1 → q0` and `q2 : hl={a0,a1}`.

    Tying `F` to the redirection instead (`F := wh c e`) repairs the truth but
    destroys the content: the predicate becomes `∀ c, ThompsonUnif (.wh c e)`,
    so the `wh` step it was meant to discharge becomes its own hypothesis.

    Kept in the file, marked, rather than deleted: 219's measurement was RIGHT
    and this was the shortcut that ignored it. -/
def ThompsonUnifP (e : Exp A T) : Prop :=
  ∀ (c : BExp T) (F : Exp A T) s₀ u v,
    GkatPlanExistence.GenBisimilar (coreGAut (.wh c e) s₀) u v →
      EquivBA (.seq ((GkatThompson.certifiedThompson A T e).standard u) F)
        (.seq ((GkatThompson.certifiedThompson A T e).standard v) F)

/-- **VACUOUS — see the refutation on `ThompsonUnifP` above.**  The implication
    is true and machine-checked, but its hypothesis is unsatisfiable, so it
    proves nothing about the `wh` step.  219 stands: the residual is real.

    Original note, kept for the record:
    Instantiate the redirection at the loop's own guard and the continuation at
    the loop itself.  `loop_state_eq` and `loop_standard_eq` make both sides
    definitionally the right thing, so this is a direct application: the
    residual case 219 measured is absorbed because the parametric hypothesis
    compares states in the redirected body, which is where the loop compares
    them. -/
theorem thompsonUnif_wh_of_param (b : BExp T) (e : Exp A T)
    (h : ThompsonUnifP e) : ThompsonUnif (.wh b e) :=
  fun s₀ u v hb => h b (.wh b e) s₀ u v hb

#print axioms loop_core_hlt
#print axioms loop_core_trans
#print axioms thompsonUnif_wh_of_param

/-! ## The remainder as ONE closure property

Iterations 224-225 read Grabmayer's completeness proof for Milner's system.  Its
architecture is not an induction that survives quotienting; it is a STRUCTURAL
CERTIFICATE (LLEE) that is (i) present on every chart of an expression, (ii)
sufficient for a solution to exist, and (iii) CLOSED UNDER BISIMULATION COLLAPSE
for proper-step charts.  GKAT's transitions all carry actions, so GKAT is the
proper-step case — the one where closure holds.

Reading this development against that architecture, (i) and (ii) are ALREADY
DONE here:

  * `sum_solves_std` — the Thompson SUM of `e` and `f` is solvable, outright;
  * `completeness_of_sumQuotientSolvable` — quotient-solvability gives
    completeness;
  * `decomp_solves` — role-coverage gives `SolvesBA`.

So the entire remainder is (iii): **that a solvable automaton has a solvable
behavioural quotient.**  Not an induction over expressions with three open
steps, as 217 framed it — ONE closure property, and the one Grabmayer proves in
the neighbouring setting. -/

/-- **THE WHOLE REMAINDER, AS A CLOSURE PROPERTY.**  If a `SolvesBA` labelling
    exists upstairs, one exists downstairs.

    The naive transport — label each block by a representative's label — is
    exactly what fails: it needs bisimilar states to carry provably equal
    labels, which is same-side unification, which is the thing being proved.
    Grabmayer's answer is not to transport the solution but to RE-DERIVE it from
    a certificate that survives the collapse.  Stated here so the obligation is
    a single named property rather than a shape spread over three cases.

    **The minimality hypothesis is not decoration — iteration 227 measured that
    without it the property is FALSE.**  Over 61 937 behavioural quotients of
    solvable Thompson automata, 4 failed, and every one was NON-MINIMAL: the
    failing quotient had four pairwise-bisimilar states left unmerged, which the
    solver treats as distinct opaque oracles.  `SumQuotientSolvable` needs only
    SOME quotient and the natural one is the full collapse, so quantifying over
    all behavioural quotients — including deliberately un-collapsed ones — was
    strictly stronger than anything the theorem needs.  Restricted to minimal
    quotients the measurement is 0 failures in 131 714 automata (iteration
    223). -/
def QuotientClosure (A T : Type) : Prop :=
  ∀ {S Q : Type} (aut : GkatKleene.GAut S A T) (quot : GkatKleene.GAut Q A T),
    GkatKleene.UniformBehavioralGAutQuotient aut quot →
    -- the quotient is bisimulation-MINIMAL: no two distinct states are
    -- bisimilar.  Without this the property is refuted; see above.
    (∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v) →
    ∀ sol : S → Exp A T, GkatKleene.SolvesBA aut sol →
      ∃ qsol : Q → Exp A T, GkatKleene.SolvesBA quot qsol

/-- **The reduction: closure plus a start-identifying quotient gives
    `SumQuotientSolvable`** — hence, through
    `completeness_of_sumQuotientSolvable`, completeness itself.

    The second hypothesis is not the hard one: the two start pseudostates of a
    language-equivalent pair ARE bisimilar, so the full bisimulation collapse
    identifies them.  It is carried as a hypothesis only because building that
    collapse as a `UniformBehavioralGAutQuotient` is construction work, not
    mathematics.  The content is `QuotientClosure`. -/
theorem sumQuotientSolvable_of_closure
    (hstart : ∀ e f : Exp A T, GkatKleene.UniformLanguageEquivalent e f →
      ∃ (Q : Type) (quot : GkatKleene.GAut Q A T)
        (π : GkatKleene.UniformBehavioralGAutQuotient
              (GkatTrim.SUMof A T e f) quot),
        (∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v) ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none))
    (hclose : QuotientClosure A T) :
    GkatSumQuotient.SumQuotientSolvable A T := by
  intro e f hef
  obtain ⟨Q, quot, π, hmin, hπ⟩ := hstart e f hef
  obtain ⟨qsol, hqsol⟩ := hclose _ _ π hmin (stdSum e f) (sum_solves_std e f)
  exact ⟨Q, quot, π, qsol, hqsol, hπ⟩

#print axioms sumQuotientSolvable_of_closure

/-! ## The architecture, abstract over the certificate

226 reduced the remainder to `QuotientClosure`, and 227 showed the naive proof
of it cannot work: transporting a solution across a quotient needs bisimilar
states to carry provably equal labels, which is the thing being proved.
Grabmayer's answer is to RE-DERIVE the solution downstairs from a STRUCTURAL
CERTIFICATE that survives the collapse.

Iterations 228-238 searched for that certificate empirically and found it at
237, once LLEE's conditions were read rather than reconstructed.  A loop
sub-chart with start `vₛ` must satisfy (L1) an infinite path leaves `vₛ`,
(L2) every infinite path from `vₛ` RETURNS to it, and (L3) termination happens
only at `vₛ` — with (L3) relativised to guards, since GKAT's `hlt` is a test
rather than a state property.  Measured over 26 000 Thompson automata at
NA = 2 and 3: every one carries the certificate, and it survives bisimulation
collapse every time.

What follows abstracts over the certificate so the architecture itself is
machine-checked, and completeness reduces to three properties of ONE predicate.
Each has been measured; none is yet proved. -/

/-- **COMPLETENESS FROM ANY CERTIFICATE WITH THREE PROPERTIES.**

    `Cert` is any predicate on automata such that

      * `hsum`      — the Thompson SUM of two expressions carries it;
      * `hcollapse` — it survives passage to a MINIMAL behavioural quotient;
      * `hsolve`    — carrying it implies a solution exists.

    Then `SumQuotientSolvable` holds, and `completeness_of_sumQuotientSolvable`
    carries that to completeness of the finite axioms.

    This is Grabmayer's architecture, stated for GKAT: not an induction that must
    survive quotienting, but a certificate that does.  The candidate for `Cert`
    is the L1/L2/L3 loop-sub-chart property; `hsum` and `hcollapse` are what
    iterations 237-238 measured at 100%, and `hsolve` is the analogue of "every
    prechart with LLEE admits a solution", which is proved in the
    regular-expression setting.

    The start-identifying hypothesis is bookkeeping, as at 226: the two start
    pseudostates of a language-equivalent pair are bisimilar, so the full
    collapse identifies them. -/
theorem sumQuotientSolvable_of_certificate
    (Cert : {S : Type} → GkatKleene.GAut S A T → Prop)
    (hstart : ∀ e f : Exp A T, GkatKleene.UniformLanguageEquivalent e f →
      ∃ (Q : Type) (quot : GkatKleene.GAut Q A T)
        (π : GkatKleene.UniformBehavioralGAutQuotient
              (GkatTrim.SUMof A T e f) quot),
        (∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v) ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none))
    (hsum : ∀ e f : Exp A T, Cert (GkatTrim.SUMof A T e f))
    (hcollapse : ∀ {S Q : Type} (aut : GkatKleene.GAut S A T)
        (quot : GkatKleene.GAut Q A T),
        GkatKleene.UniformBehavioralGAutQuotient aut quot →
        (∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v) →
        Cert aut → Cert quot)
    (hsolve : ∀ {Q : Type} (quot : GkatKleene.GAut Q A T),
        Cert quot → ∃ qsol : Q → Exp A T, GkatKleene.SolvesBA quot qsol) :
    GkatSumQuotient.SumQuotientSolvable A T := by
  intro e f hef
  obtain ⟨Q, quot, π, hmin, hπ⟩ := hstart e f hef
  obtain ⟨qsol, hqsol⟩ := hsolve quot (hcollapse _ _ π hmin (hsum e f))
  exact ⟨Q, quot, π, qsol, hqsol, hπ⟩

/-- **Minimality is only plumbing.**  In `sumQuotientSolvable_of_certificate` the
`GenBisimilar quot u v → u = v` conjunct is produced by `hstart` and consumed by
`hcollapse`, and it appears nowhere in `SumQuotientSolvable` itself.  Drop the
`Cert` layer and it disappears: all the conclusion ever needed is SOME quotient
identifying the two starts that happens to be solvable. -/
theorem sumQuotientSolvable_of_solver
    (hquot : ∀ e f : Exp A T, GkatKleene.UniformLanguageEquivalent e f →
      ∃ (Q : Type) (quot : GkatKleene.GAut Q A T)
        (π : GkatKleene.UniformBehavioralGAutQuotient
              (GkatTrim.SUMof A T e f) quot),
        (∃ qsol : Q → Exp A T, GkatKleene.SolvesBA quot qsol) ∧
          π.mapState (Sum.inl none) = π.mapState (Sum.inr none)) :
    GkatSumQuotient.SumQuotientSolvable A T := by
  intro e f hef
  obtain ⟨Q, quot, π, ⟨qsol, hqsol⟩, hπ⟩ := hquot e f hef
  exact ⟨Q, quot, π, qsol, hqsol, hπ⟩

/-- Nothing is lost: the certificate architecture factors through the solver form,
so the leaner statement is a strict generalisation rather than a rival. -/
theorem sumQuotientSolvable_of_certificate_via_solver
    (Cert : {S : Type} → GkatKleene.GAut S A T → Prop)
    (hstart : ∀ e f : Exp A T, GkatKleene.UniformLanguageEquivalent e f →
      ∃ (Q : Type) (quot : GkatKleene.GAut Q A T)
        (π : GkatKleene.UniformBehavioralGAutQuotient
              (GkatTrim.SUMof A T e f) quot),
        (∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v) ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none))
    (hsum : ∀ e f : Exp A T, Cert (GkatTrim.SUMof A T e f))
    (hcollapse : ∀ {S Q : Type} (aut : GkatKleene.GAut S A T)
        (quot : GkatKleene.GAut Q A T),
        GkatKleene.UniformBehavioralGAutQuotient aut quot →
        (∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v) →
        Cert aut → Cert quot)
    (hsolve : ∀ {Q : Type} (quot : GkatKleene.GAut Q A T),
        Cert quot → ∃ qsol : Q → Exp A T, GkatKleene.SolvesBA quot qsol) :
    GkatSumQuotient.SumQuotientSolvable A T :=
  sumQuotientSolvable_of_solver (fun e f hef =>
    match hstart e f hef with
    | ⟨Q, quot, π, hmin, hπ⟩ =>
        ⟨Q, quot, π, hsolve quot (hcollapse _ _ π hmin (hsum e f)), hπ⟩)

#print axioms sumQuotientSolvable_of_solver
#print axioms sumQuotientSolvable_of_certificate_via_solver

#print axioms sumQuotientSolvable_of_certificate

/-- The certificate architecture SUBSUMES 226's closure property: a certificate
    with the three properties yields `QuotientClosure` on the automata it covers,
    without the transport argument 227 showed cannot work. -/
theorem quotientClosure_of_certificate
    (Cert : {S : Type} → GkatKleene.GAut S A T → Prop)
    (hcollapse : ∀ {S Q : Type} (aut : GkatKleene.GAut S A T)
        (quot : GkatKleene.GAut Q A T),
        GkatKleene.UniformBehavioralGAutQuotient aut quot →
        (∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v) →
        Cert aut → Cert quot)
    (hsolve : ∀ {Q : Type} (quot : GkatKleene.GAut Q A T),
        Cert quot → ∃ qsol : Q → Exp A T, GkatKleene.SolvesBA quot qsol)
    {S Q : Type} (aut : GkatKleene.GAut S A T) (quot : GkatKleene.GAut Q A T)
    (π : GkatKleene.UniformBehavioralGAutQuotient aut quot)
    (hmin : ∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v)
    (hcert : Cert aut) :
    ∃ qsol : Q → Exp A T, GkatKleene.SolvesBA quot qsol :=
  hsolve quot (hcollapse aut quot π hmin hcert)

#print axioms quotientClosure_of_certificate

/-- **(L3) HOLDS FOR THE LOOP A `wh` INTRODUCES.**

    LLEE's third condition — immediate termination only at the loop's start —
    becomes, in the guarded setting, that no body state terminates INSIDE the
    loop's guard.  Iterations 228-236 spent nine attempts guessing at the guard
    before 237 read (L1)-(L3) from the source; this is the one piece of the
    certificate that is settled outright rather than measured, and it falls
    straight out of `loop_core_hlt`.

    In `wh b e`, every body state's halt is `hlt_body s ∧ ¬b`, so conjoining `b`
    gives `0` at every valuation — for EVERY state, EVERY expression, EVERY
    guard.  This is `hsum`'s `wh` case for condition (L3), proved rather than
    sampled. -/
theorem wh_loop_L3 (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State)
    (X : Type) (W : T → X → Bool) (x : X) :
    GkatGS.bval W
      (.and ((GkatThompson.certifiedThompson A T (.wh b e)).aut.core.hlt s) b)
      x = false := by
  show GkatGS.bval W
    (.and (.and ((GkatThompson.certifiedThompson A T e).aut.core.hlt s)
      (.not b)) b) x = false
  simp only [GkatGS.bval]
  cases GkatGS.bval W b x <;>
    cases GkatGS.bval W ((GkatThompson.certifiedThompson A T e).aut.core.hlt s) x <;>
    rfl

#print axioms wh_loop_L3

/-- The same fact stated as the certificate uses it: the loop's halt guard and
    its loop guard are disjoint, so `GuardImplies (hlt s) (.not b)` — a body
    state can only terminate where the loop is already leaving. -/
theorem wh_loop_halt_implies (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State) :
    GuardImplies ((GkatThompson.certifiedThompson A T (.wh b e)).aut.core.hlt s)
      (.not b) := by
  intro X W x h
  show (!GkatGS.bval W b x) = true
  have := wh_loop_L3 b e s X W x
  simp only [GkatGS.bval] at this ⊢
  cases hb : GkatGS.bval W b x
  · rfl
  · rw [hb] at this; rw [h] at this; exact absurd this (by simp)

#print axioms wh_loop_halt_implies

/-! ### `seq` and `ite` introduce no new loops

`hsum` needs the certificate for EVERY loop of a Thompson automaton, so the
compound constructors must not create loops of their own — otherwise each would
need its own (L1)/(L2)/(L3) argument rather than inheriting from its parts.

They do not, and the reason is one-directional edges.  In `seqGSystem`, a right
state's transitions all target right states: control passes from left to right
when the left half halts, and NEVER back.  In `sumGSystem` — which `ite` uses —
the two halves are disjoint and neither reaches the other at all; the choice is
made once, at the initial pseudostate.  So every cycle lies wholly inside one
sub-automaton, and `wh` is the ONLY constructor that creates a cycle. -/

/-- In a sequential composition, the right half is CLOSED: no transition leaves
    it.  Hence no cycle crosses the seam, and `seq` adds no loop. -/
theorem seq_inr_closed {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T)
    (s : S₂) (tr : BExp T × A × (Sum S₁ S₂))
    (h : tr ∈ (GkatThompson.seqGSystem L R).trans (.inr s)) :
    ∃ t : S₂, tr.2.2 = .inr t := by
  simp only [GkatThompson.seqGSystem, List.mem_map] at h
  obtain ⟨tr', _, rfl⟩ := h
  exact ⟨tr'.2.2, rfl⟩

/-- In a guarded choice the two halves are mutually unreachable: a left state's
    transitions stay left. -/
theorem sum_inl_closed {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (s : S₁) (tr : BExp T × A × (Sum S₁ S₂))
    (h : tr ∈ (GkatThompson.sumGSystem L R).trans (.inl s)) :
    ∃ t : S₁, tr.2.2 = .inl t := by
  simp only [GkatThompson.sumGSystem, List.mem_map] at h
  obtain ⟨tr', _, rfl⟩ := h
  exact ⟨tr'.2.2, rfl⟩

/-- …and a right state's stay right. -/
theorem sum_inr_closed {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (s : S₂) (tr : BExp T × A × (Sum S₁ S₂))
    (h : tr ∈ (GkatThompson.sumGSystem L R).trans (.inr s)) :
    ∃ t : S₂, tr.2.2 = .inr t := by
  simp only [GkatThompson.sumGSystem, List.mem_map] at h
  obtain ⟨tr', _, rfl⟩ := h
  exact ⟨tr'.2.2, rfl⟩

#print axioms seq_inr_closed
#print axioms sum_inl_closed
#print axioms sum_inr_closed

/-! ### The `wh` layer, characterised

244 established that every PER-SCC formulation of (L2) fails — an SCC holds a
whole nest of loops — and that the working formulation is PER LAYER, with
`loop_core_trans` (`rfl`, 220) supplying the layer step:

    trans of (wh b e)  =  trans of e  ++  the back edges

so removing a layer's back edges returns exactly `e`'s own automaton, and the
remaining obligation is the induction hypothesis.

What that leaves is to characterise the back edges themselves.  A note on why
this must be done at the automaton level: `Cert` is a predicate on AUTOMATA, not
expressions, because `hcollapse` applies it to the quotient — which has no
expression.  So `Cert` is the existential over layered decompositions (what
iteration 237 tests, at 100% for `hsum` and `hcollapse`), and `hsum`'s proof
EXHIBITS the witness from the expression structure. -/

/-- **EVERY BACK EDGE OF A `wh` LAYER LIES INSIDE THE LAYER'S GUARD.**

    The transitions `loopInitialized` appends carry guard
    `hlt_body s ∧ (b ∧ gᵢ)`, which implies `b`.  So the layer's guard is `b`
    itself — determined by the expression, not recovered from the graph.

    This is the fact nine iterations of measurement (228-236) were trying to
    reconstruct from transition data, and 234 concluded must be "tied to graph
    structure" after a free guard search broke soundness.  Read off the
    construction it is immediate: the guard is the `wh`'s own test. -/
theorem wh_backedge_guard_implies (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State)
    (tr : BExp T × A × (GkatThompson.certifiedThompson A T e).State)
    (h : tr ∈ ((GkatThompson.certifiedThompson A T e).aut.initTrans.map
      (fun t => (BExp.and ((GkatThompson.certifiedThompson A T e).aut.core.hlt s)
        (BExp.and b t.1), t.2)))) :
    GuardImplies tr.1 b := by
  simp only [List.mem_map] at h
  obtain ⟨t, _, rfl⟩ := h
  intro X W x hx
  simp only [GkatGS.bval] at hx ⊢
  cases hb : GkatGS.bval W b x
  · rw [hb] at hx; simp at hx
  · rfl

#print axioms wh_backedge_guard_implies

/-- And dually, the layer's halt is disjoint from its guard — 240's `wh_loop_L3`
    restated as the pair of facts a layer needs: back edges INSIDE the guard,
    halts OUTSIDE it.  Together these say the guard `b` separates "iterate" from
    "leave" at every state of the layer, which is the guarded form of "you exit a
    loop only at its head". -/
theorem wh_layer_separates (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State) :
    GuardImplies ((GkatThompson.certifiedThompson A T (.wh b e)).aut.core.hlt s)
        (.not b)
      ∧ ∀ tr ∈ ((GkatThompson.certifiedThompson A T e).aut.initTrans.map
          (fun t => (BExp.and ((GkatThompson.certifiedThompson A T e).aut.core.hlt s)
            (BExp.and b t.1), t.2))),
        GuardImplies tr.1 b :=
  ⟨wh_loop_halt_implies b e s, fun tr h => wh_backedge_guard_implies b e s tr h⟩

#print axioms wh_layer_separates

/-- **POINTWISE GUARD RESTRICTION**, Mathlib-free (this cluster has no
    `List.Forall₂`).  `RestrictedTo b post post'` says the two lists have the
    same targets and actions in the same order, with each guard of `post'`
    EQUIVALENT to `¬b ∧` the corresponding guard of `post`.

    255 established why equivalence rather than equality is required: in the
    `seq` case `sys`'s trailing guards come out as `(hlt ∧ ¬b) ∧ g` while the
    restriction produces `¬b ∧ (hlt ∧ g)` — the same Boolean function written
    two ways.  Keeping the LIST STRUCTURE syntactic protects the rank proofs
    (they decompose membership through `pre`/`extra`/`post'`); making only the
    GUARDS semantic makes associativity and commutativity a non-issue. -/
inductive RestrictedTo {S : Type} (b : BExp T) :
    List (BExp T × A × S) → List (BExp T × A × S) → Prop where
  | nil : RestrictedTo b [] []
  | cons {g g' : BExp T} {a : A} {s : S} {l l' : List (BExp T × A × S)} :
      (∀ (X : Type) (W : T → X → Bool) (x : X),
        GkatGS.bval W g' x = (!GkatGS.bval W b x && GkatGS.bval W g x)) →
      RestrictedTo b l l' →
      RestrictedTo b ((g, a, s) :: l) ((g', a, s) :: l')

/-- `RestrictedTo` survives a retargeting injection — needed to lift a layer
    into a `Sum`. -/
theorem RestrictedTo.map {S S' : Type} {b : BExp T} {l l' : List (BExp T × A × S)}
    (f : S → S') (h : RestrictedTo b l l') :
    RestrictedTo (S := S') b (l.map (fun t => (t.1, t.2.1, f t.2.2)))
      (l'.map (fun t => (t.1, t.2.1, f t.2.2))) := by
  induction h with
  | nil => exact RestrictedTo.nil
  | cons hg _ ih => exact RestrictedTo.cons hg ih

/-- `RestrictedTo` is compatible with concatenation. -/
theorem RestrictedTo.append {S : Type} {b : BExp T}
    {l₁ l₁' l₂ l₂' : List (BExp T × A × S)}
    (h₁ : RestrictedTo b l₁ l₁') (h₂ : RestrictedTo b l₂ l₂') :
    RestrictedTo b (l₁ ++ l₂) (l₁' ++ l₂') := by
  induction h₁ with
  | nil => exact h₂
  | cons hg _ ih => exact RestrictedTo.cons hg ih

/-- Two maps over the SAME list, whose guards are pointwise related, are
    `RestrictedTo`.  This is how the trailing entry-block of a sequence relates
    across a layer: same transitions, guards conjoined with the layer's guard on
    one side. -/
theorem RestrictedTo.of_map {S S' : Type} {b : BExp T}
    (l : List (BExp T × A × S)) (f g : BExp T × A × S → BExp T × A × S')
    (htgt : ∀ t, (f t).2 = (g t).2)
    (hg : ∀ t, ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W (g t).1 x = (!GkatGS.bval W b x && GkatGS.bval W (f t).1 x)) :
    RestrictedTo b (l.map f) (l.map g) := by
  induction l with
  | nil => exact RestrictedTo.nil
  | cons t ts ih =>
      have := htgt t
      obtain ⟨g1, gr⟩ : ∃ a c, f t = (a, c) := ⟨(f t).1, (f t).2, rfl⟩
      simp only [List.map_cons]
      cases hft : f t with
      | mk a1 c1 =>
        cases hgt : g t with
        | mk a2 c2 =>
          have hc : c1 = c2 := by
            rw [hft] at this; rw [hgt] at this; exact this
          subst hc
          exact RestrictedTo.cons (by
            intro X W x
            have := hg t X W x
            rw [hft, hgt] at this
            exact this) ih

structure IsLayer {S : Type} (sys base : GkatThompson.GSystem S A T)
    (b : BExp T) (dom : S → Prop) : Prop where
  /-- **ON THE LAYER** (iteration 256's shape).  A layer splits a state's
      transition list into a `pre` block it leaves alone, its own BACK EDGES
      (guards implying `b`), and a `post'` block that RESTRICTS `base`'s
      trailing block to `¬b`.

      252 established why both parts are needed, and 255 why the restriction is
      up to guard EQUIVALENCE.  For `wh` the trailing block is EMPTY —
      `CoreHaltDisjoint` keeps the back edges from colliding — so appending
      sufficed and 246's shape worked.  For `seq` the trailing block is the
      right half's ENTRY transitions, guarded by `hlt`, exactly where the back
      edges live; they must be separated by `b` and `¬b`. -/
  split : ∀ s, dom s → ∃ pre extra post post',
    base.trans s = pre ++ post ∧
    sys.trans s = pre ++ extra ++ post' ∧
    (∀ tr ∈ extra, GuardImplies tr.1 b) ∧
    RestrictedTo b post post'
  /-- ON THE LAYER: halts are `base`'s, restricted to outside the guard.
      SEMANTIC for the same reason the guards are (255): in a sequence
      `sys.hlt (inl s)` comes out as `(L'.hlt s ∧ ¬b) ∧ R.initHlt` while the
      equation wants `(L'.hlt s ∧ R.initHlt) ∧ ¬b` — the same Boolean function,
      associated differently. -/
  hlt_eq : ∀ s, dom s → ∀ (X : Type) (W : T → X → Bool) (x : X),
    GkatGS.bval W (sys.hlt s) x
      = (GkatGS.bval W (base.hlt s) x && !GkatGS.bval W b x)
  /-- OFF THE LAYER: `sys` and `base` agree (248). -/
  outside : ∀ s, ¬ dom s → sys.trans s = base.trans s ∧ sys.hlt s = base.hlt s
  /-- A layer adds back EDGES, never states (258).  True of every construction —
      `loopInitialized` keeps the body's state list verbatim, and `sum`/`seq`
      build theirs from the components' — and needed because
      `InitTargetsListed` must survive passage to the base. -/
  states_eq : sys.states = base.states

/-- **`wh b e`'s automaton is exactly ONE LAYER over `e`'s.**

    The whole point of the per-layer formulation: after removing the layer, what
    is left is not "an acyclic graph" but `e`'s OWN Thompson automaton — so the
    remaining obligation is the induction hypothesis rather than a fresh
    condition.  Proved from `loop_core_trans` and `loop_core_hlt`, both `rfl`
    since iteration 220, plus 245's guard characterisation. -/
theorem wh_isLayer (b : BExp T) (e : Exp A T) :
    IsLayer (GkatThompson.certifiedThompson A T (.wh b e)).aut.core
      (GkatThompson.certifiedThompson A T e).aut.core b (fun _ => True) where
  split s _ :=
    ⟨(GkatThompson.certifiedThompson A T e).aut.core.trans s,
     (GkatThompson.certifiedThompson A T e).aut.initTrans.map
       (fun tr => (BExp.and ((GkatThompson.certifiedThompson A T e).aut.core.hlt s)
         (BExp.and b tr.1), tr.2)),
     [], [],
     by simp,
     by simpa using loop_core_trans b e s,
     fun tr h => wh_backedge_guard_implies b e s tr h,
     RestrictedTo.nil⟩
  hlt_eq s _ := by
    intro X W x
    rw [loop_core_hlt b e s]
    rfl
  outside s h := absurd trivial h
  states_eq := rfl

#print axioms wh_isLayer

/-- Membership extraction for a sum's state list, needed once
    `Layered.acyclic` is restricted to LISTED states (261). -/
theorem sum_states_inl {S₁ S₂ : Type}
    {L : GkatThompson.GSystem S₁ A T} {R : GkatThompson.GSystem S₂ A T} {x : S₁}
    (h : Sum.inl x ∈ (GkatThompson.sumGSystem L R).states) : x ∈ L.states := by
  simp only [GkatThompson.sumGSystem, List.mem_append, List.mem_map] at h
  rcases h with ⟨y, hy, hxy⟩ | ⟨y, _, hxy⟩
  · cases hxy; exact hy
  · cases hxy

theorem sum_states_inr {S₁ S₂ : Type}
    {L : GkatThompson.GSystem S₁ A T} {R : GkatThompson.GSystem S₂ A T} {y : S₂}
    (h : Sum.inr y ∈ (GkatThompson.sumGSystem L R).states) : y ∈ R.states := by
  simp only [GkatThompson.sumGSystem, List.mem_append, List.mem_map] at h
  rcases h with ⟨z, _, hzy⟩ | ⟨z, hz, hzy⟩
  · cases hzy
  · cases hzy; exact hz

theorem seq_states_inl {S₁ S₂ : Type}
    {L : GkatThompson.GSystem S₁ A T} {R : GkatThompson.InitializedGAut S₂ A T} {x : S₁}
    (h : Sum.inl x ∈ (GkatThompson.seqGSystem L R).states) : x ∈ L.states := by
  simp only [GkatThompson.seqGSystem, List.mem_append, List.mem_map] at h
  rcases h with ⟨y, hy, hxy⟩ | ⟨y, _, hxy⟩
  · cases hxy; exact hy
  · cases hxy

theorem seq_states_inr {S₁ S₂ : Type}
    {L : GkatThompson.GSystem S₁ A T} {R : GkatThompson.InitializedGAut S₂ A T} {y : S₂}
    (h : Sum.inr y ∈ (GkatThompson.seqGSystem L R).states) : y ∈ R.core.states := by
  simp only [GkatThompson.seqGSystem, List.mem_append, List.mem_map] at h
  rcases h with ⟨z, _, hzy⟩ | ⟨z, hz, hzy⟩
  · cases hzy
  · cases hzy; exact hz

/-- **THE CERTIFICATE, AS AN INDUCTIVE PREDICATE ON AUTOMATA.**

    An automaton is layered when it is acyclic, or is one loop layer over
    something layered.  This is the certificate `Cert` of 239's architecture,
    and it is stated on the AUTOMATON — not on an expression — because
    `hcollapse` must apply it to the quotient, which has no expression (245).

    Acyclicity is witnessed by a rank that every transition strictly decreases;
    that is the finite-state form of LLEE's "elimination terminates at a chart
    without infinite paths", and it avoids needing a path predicate. -/
inductive Layered {S : Type} : GkatThompson.GSystem S A T → Prop where
  | acyclic {sys : GkatThompson.GSystem S A T} :
      (∃ rank : S → Nat, ∀ s ∈ sys.states, ∀ tr ∈ sys.trans s,
        rank tr.2.2 < rank s) →
      Layered sys
  | layer {sys base : GkatThompson.GSystem S A T} {b : BExp T} {dom : S → Prop} :
      IsLayer sys base b dom → Layered base → Layered sys

/-- **`wh` PRESERVES THE CERTIFICATE — the `wh` case of `hsum`, discharged.**

    Immediate from `wh_isLayer`: `wh b e`'s automaton IS one layer over `e`'s, so
    if `e`'s is layered, so is it.  Sixteen iterations of graph search for this
    step; three lines once the layer is the right object. -/
theorem layered_wh (b : BExp T) (e : Exp A T)
    (h : Layered (GkatThompson.certifiedThompson A T e).aut.core) :
    Layered (GkatThompson.certifiedThompson A T (.wh b e)).aut.core :=
  Layered.layer (wh_isLayer b e) h

#print axioms layered_wh

/-- **The base cases.**  `test t`'s automaton has no states, so the empty rank
    function witnesses acyclicity vacuously; `act a`'s single state has no
    transitions at all. -/
theorem layered_test (t : BExp T) :
    Layered (GkatThompson.certifiedThompson A T (.test t)).aut.core := by
  apply Layered.acyclic
  refine ⟨fun s => (nomatch s : Nat), ?_⟩
  intro s
  exact nomatch s

theorem layered_act (a : A) :
    Layered (GkatThompson.certifiedThompson A T (.act a)).aut.core :=
  Layered.acyclic ⟨fun _ => 0, by intro s _ tr h; cases h⟩

#print axioms layered_test
#print axioms layered_act

/-- **A LAYER IN ONE COMPONENT IS A LAYER OF THE SUM.**  This is what 248's
    relativisation buys: the layer's domain is carried into the left component
    and is empty on the right, so the right half is untouched and `outside`
    discharges it. -/
theorem sum_isLayer_left {S₁ S₂ : Type}
    (L L' : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    {b : BExp T} {dom : S₁ → Prop} (h : IsLayer L L' b dom) :
    IsLayer (GkatThompson.sumGSystem L R) (GkatThompson.sumGSystem L' R) b
      (fun x => match x with | .inl s => dom s | .inr _ => False) where
  split
    | .inl s, hs => by
        obtain ⟨pre, extra, post, post', hbase, hsys, hg, hr⟩ := h.split s hs
        refine ⟨pre.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)),
                extra.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)),
                post.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)),
                post'.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)), ?_, ?_, ?_, ?_⟩
        · show (L'.trans s).map _ = _
          rw [hbase, List.map_append]
        · show (L.trans s).map _ = _
          rw [hsys, List.map_append, List.map_append]
        · intro tr htr
          simp only [List.mem_map] at htr
          obtain ⟨t, ht, rfl⟩ := htr
          exact hg t ht
        · exact hr.map _
    | .inr _, hs => absurd hs (by simp)
  hlt_eq
    | .inl s, hs => h.hlt_eq s hs
    | .inr _, hs => absurd hs (by simp)
  outside
    | .inl s, hs => by
        obtain ⟨ht, hh⟩ := h.outside s hs
        exact ⟨by simp only [GkatThompson.sumGSystem, ht], by
          simp only [GkatThompson.sumGSystem, hh]⟩
    | .inr _, _ => ⟨rfl, rfl⟩
  states_eq := by
    show _ ++ _ = _ ++ _
    rw [h.states_eq]

/-- Symmetric: a layer in the RIGHT component is a layer of the sum. -/
theorem sum_isLayer_right {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R R' : GkatThompson.GSystem S₂ A T)
    {b : BExp T} {dom : S₂ → Prop} (h : IsLayer R R' b dom) :
    IsLayer (GkatThompson.sumGSystem L R) (GkatThompson.sumGSystem L R') b
      (fun x => match x with | .inl _ => False | .inr s => dom s) where
  split
    | .inl _, hs => absurd hs (by simp)
    | .inr s, hs => by
        obtain ⟨pre, extra, post, post', hbase, hsys, hg, hr⟩ := h.split s hs
        refine ⟨pre.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)),
                extra.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)),
                post.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)),
                post'.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)), ?_, ?_, ?_, ?_⟩
        · show (R'.trans s).map _ = _
          rw [hbase, List.map_append]
        · show (R.trans s).map _ = _
          rw [hsys, List.map_append, List.map_append]
        · intro tr htr
          simp only [List.mem_map] at htr
          obtain ⟨t, ht, rfl⟩ := htr
          exact hg t ht
        · exact hr.map _
  hlt_eq
    | .inl _, hs => absurd hs (by simp)
    | .inr s, hs => h.hlt_eq s hs
  outside
    | .inl _, _ => ⟨rfl, rfl⟩
    | .inr s, hs => by
        obtain ⟨ht, hh⟩ := h.outside s hs
        exact ⟨by simp only [GkatThompson.sumGSystem, ht], by
          simp only [GkatThompson.sumGSystem, hh]⟩
  states_eq := by
    show _ ++ _ = _ ++ _
    rw [h.states_eq]

#print axioms sum_isLayer_left
#print axioms sum_isLayer_right

/-- **THE SUM OF TWO LAYERED AUTOMATA IS LAYERED** — the `ite` case of `hsum`.

    By induction on both derivations.  When both are ACYCLIC the ranks combine
    componentwise, which is sound precisely because 241 proved cycles never
    cross the seam: a left state.s transitions stay left and a right state.s stay
    right, so each transition decreases its own component.s rank.  When either
    side is a LAYER, 248/249.s lifting lemmas carry it into the sum. -/
theorem layered_sum {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (hL : Layered L) (hR : Layered R) :
    Layered (GkatThompson.sumGSystem L R) := by
  induction hL with
  | acyclic h1 =>
      induction hR with
      | acyclic h2 =>
          obtain ⟨r1, hr1⟩ := h1
          obtain ⟨r2, hr2⟩ := h2
          refine Layered.acyclic ⟨Sum.elim r1 r2, ?_⟩
          rintro (x | y) hmem tr htr
          · simp only [GkatThompson.sumGSystem, List.mem_map] at htr
            obtain ⟨t, ht, rfl⟩ := htr
            exact hr1 x (sum_states_inl hmem) t ht
          · simp only [GkatThompson.sumGSystem, List.mem_map] at htr
            obtain ⟨t, ht, rfl⟩ := htr
            exact hr2 y (sum_states_inr hmem) t ht
      | layer hlay _ ih =>
          exact Layered.layer (sum_isLayer_right _ _ _ hlay) ih
  | layer hlay _ ih =>
      exact Layered.layer (sum_isLayer_left _ _ _ hlay) ih

#print axioms layered_sum

/-- **THE `ite` CASE OF `hsum`.**  `iteInitialized`.s core IS `sumGSystem` of the
    two branches, so this is `layered_sum` applied definitionally. -/
theorem layered_ite (b : BExp T) (e f : Exp A T)
    (he : Layered (GkatThompson.certifiedThompson A T e).aut.core)
    (hf : Layered (GkatThompson.certifiedThompson A T f).aut.core) :
    Layered (GkatThompson.certifiedThompson A T (.ite b e f)).aut.core :=
  layered_sum _ _ he hf

#print axioms layered_ite

/-- Fold-max of a list, Mathlib-free. -/
private def maxOf : List Nat → Nat
  | [] => 0
  | x :: xs => max x (maxOf xs)

private theorem le_maxOf {l : List Nat} {x : Nat} (h : x ∈ l) : x ≤ maxOf l := by
  induction l with
  | nil => cases h
  | cons y ys ih =>
      cases h with
      | head => exact Nat.le_max_left _ _
      | tail _ h' => exact Nat.le_trans (ih h') (Nat.le_max_right _ _)

/-- **THE `seq` CASE OF `hsum`.**

    `seqGSystem` is NOT `sumGSystem`: a LEFT state's transitions include the
    RIGHT half's ENTRY transitions, guarded by `left.hlt s`, so control crosses
    the seam ONE-WAY when the left half halts (241's `seq_inr_closed` says only
    that the right half is closed).  So the componentwise rank of `layered_sum`
    does not transfer — the crossing must itself be a DECREASE.

    It is, once every left state outranks every right one.  `GSystem.states` is a
    `List`, so the right ranks are bounded by a fold-max `M`, and
    `InitTargetsListed` puts every crossing target in that list; ranking left
    states at `r₁ x + M + 1` makes the one-way crossing strictly decreasing. -/
theorem layered_seq_acyclic {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T)
    (hR : GkatThompson.InitTargetsListed R)
    (r₁ : S₁ → Nat) (h₁ : ∀ s ∈ L.states, ∀ tr ∈ L.trans s, r₁ tr.2.2 < r₁ s)
    (r₂ : S₂ → Nat) (h₂ : ∀ s ∈ R.core.states, ∀ tr ∈ R.core.trans s,
      r₂ tr.2.2 < r₂ s) :
    Layered (GkatThompson.seqGSystem L R) := by
  refine Layered.acyclic ⟨Sum.elim
    (fun x => r₁ x + maxOf (R.core.states.map r₂) + 1) r₂, ?_⟩
  rintro (x | y) hmem tr htr
  · show Sum.elim _ _ tr.2.2 < r₁ x + _ + 1
    simp only [GkatThompson.seqGSystem, List.mem_append, List.mem_map] at htr
    cases htr with
    | inl h =>
        obtain ⟨t, ht, rfl⟩ := h
        exact Nat.add_lt_add_right
          (Nat.add_lt_add_right (h₁ x (seq_states_inl hmem) t ht) _) 1
    | inr h =>
        obtain ⟨t, ht, rfl⟩ := h
        have : r₂ t.2.2 ≤ maxOf (R.core.states.map r₂) :=
          le_maxOf (List.mem_map_of_mem (hR t ht))
        exact Nat.lt_succ_of_le (Nat.le_add_left_of_le this)
  · show Sum.elim _ _ tr.2.2 < r₂ y
    simp only [GkatThompson.seqGSystem, List.mem_map] at htr
    obtain ⟨t, ht, rfl⟩ := htr
    exact h₂ y (seq_states_inr hmem) t ht

#print axioms layered_seq_acyclic

/-- **A LAYER IN THE LEFT HALF OF A SEQUENCE IS A LAYER OF THE SEQUENCE.**

    The case 251 found blocked and 252-256 rebuilt the definition for.  Two
    things happen at once, and the shape now expresses both: the back edges are
    INSERTED (they sit between the left half's own transitions and the right
    half's entry block), and the entry block is RESTRICTED — its guards pick up
    `¬b`, because control may proceed to the right half only where the loop is
    not iterating.

    `pre` and `extra` come from the layer; `post` is the left half's remaining
    transitions FOLLOWED BY the right half's entry block, and `post'` is the
    same with `¬b` conjoined — the first part by `RestrictedTo.map`, the second
    by `RestrictedTo.of_map`, joined by `RestrictedTo.append`. -/
theorem seq_isLayer_left {S₁ S₂ : Type}
    (L L' : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T)
    {b : BExp T} {dom : S₁ → Prop} (h : IsLayer L L' b dom) :
    IsLayer (GkatThompson.seqGSystem L R) (GkatThompson.seqGSystem L' R) b
      (fun x => match x with | .inl s => dom s | .inr _ => False) where
  split
    | .inl s, hs => by
        obtain ⟨pre, extra, post, post', hbase, hsys, hg, hr⟩ := h.split s hs
        refine ⟨pre.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)),
                extra.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)),
                post.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)) ++
                  R.initTrans.map (fun t =>
                    (BExp.and (L'.hlt s) t.1, t.2.1, Sum.inr t.2.2)),
                post'.map (fun t => (t.1, t.2.1, Sum.inl t.2.2)) ++
                  R.initTrans.map (fun t =>
                    (BExp.and (L.hlt s) t.1, t.2.1, Sum.inr t.2.2)),
                ?_, ?_, ?_, ?_⟩
        · show (L'.trans s).map _ ++ _ = _
          rw [hbase, List.map_append]
          simp [List.append_assoc]
        · show (L.trans s).map _ ++ _ = _
          rw [hsys, List.map_append, List.map_append]
          simp [List.append_assoc]
        · intro tr htr
          simp only [List.mem_map] at htr
          obtain ⟨t, ht, rfl⟩ := htr
          exact hg t ht
        · refine RestrictedTo.append (hr.map _) (RestrictedTo.of_map _ _ _
            (fun _ => rfl) ?_)
          intro t X W x
          simp only [GkatGS.bval, h.hlt_eq s hs X W x]
          cases GkatGS.bval W (L'.hlt s) x <;>
            cases GkatGS.bval W b x <;> cases GkatGS.bval W t.1 x <;> rfl
    | .inr _, hs => absurd hs (by simp)
  hlt_eq
    | .inl s, hs => by
        intro X W x
        simp only [GkatThompson.seqGSystem, GkatGS.bval, h.hlt_eq s hs X W x]
        cases GkatGS.bval W (L'.hlt s) x <;>
          cases GkatGS.bval W b x <;> cases GkatGS.bval W R.initHlt x <;> rfl
    | .inr _, hs => absurd hs (by simp)
  outside
    | .inl s, hs => by
        obtain ⟨ht, hh⟩ := h.outside s hs
        exact ⟨by simp only [GkatThompson.seqGSystem, ht, hh], by
          simp only [GkatThompson.seqGSystem, hh]⟩
    | .inr _, _ => ⟨rfl, rfl⟩
  states_eq := by
    show _ ++ _ = _ ++ _
    rw [h.states_eq]

#print axioms seq_isLayer_left

/-- **A LAYER IN THE RIGHT HALF OF A SEQUENCE IS A LAYER OF THE SEQUENCE.**

    Simpler than the left case, and 241 said why: `seqGSystem` touches the right
    half not at all — a right state's transitions are its own, retargeted.  So
    the layer passes straight through, and the entire left half is discharged by
    `outside`.  Only the CORE varies; the initial data is shared, which is what
    lets the sequence itself stay fixed. -/
theorem seq_isLayer_right {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T)
    (core base : GkatThompson.GSystem S₂ A T)
    (ih : BExp T) (it : List (BExp T × A × S₂))
    {b : BExp T} {dom : S₂ → Prop} (h : IsLayer core base b dom) :
    IsLayer (GkatThompson.seqGSystem L ⟨core, ih, it⟩)
      (GkatThompson.seqGSystem L ⟨base, ih, it⟩) b
      (fun x => match x with | .inl _ => False | .inr s => dom s) where
  split
    | .inl _, hs => absurd hs (by simp)
    | .inr s, hs => by
        obtain ⟨pre, extra, post, post', hbase, hsys, hg, hr⟩ := h.split s hs
        refine ⟨pre.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)),
                extra.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)),
                post.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)),
                post'.map (fun t => (t.1, t.2.1, Sum.inr t.2.2)), ?_, ?_, ?_, ?_⟩
        · show (base.trans s).map _ = _
          rw [hbase, List.map_append]
        · show (core.trans s).map _ = _
          rw [hsys, List.map_append, List.map_append]
        · intro tr htr
          simp only [List.mem_map] at htr
          obtain ⟨t, ht, rfl⟩ := htr
          exact hg t ht
        · exact hr.map _
  hlt_eq
    | .inl _, hs => absurd hs (by simp)
    | .inr s, hs => h.hlt_eq s hs
  outside
    | .inl _, _ => ⟨rfl, rfl⟩
    | .inr s, hs => by
        obtain ⟨ht, hh⟩ := h.outside s hs
        exact ⟨by simp only [GkatThompson.seqGSystem, ht], by
          simp only [GkatThompson.seqGSystem, hh]⟩
  states_eq := by
    show _ ++ _ = _ ++ _
    rw [h.states_eq]

#print axioms seq_isLayer_right

/-- **THE `seq` CASE OF `hsum`, ASSEMBLED.**  Induction on both derivations, the
    same shape as `layered_sum` (250): acyclic/acyclic is `layered_seq_acyclic`,
    and a layer on either side lifts by the two lemmas above. -/
theorem layered_seq {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T)
    (hinit : GkatThompson.InitTargetsListed R)
    (hL : Layered L) (hR : Layered R.core) :
    Layered (GkatThompson.seqGSystem L R) := by
  -- `R.core` must be a variable for the inner induction; destructure, then
  -- restate the hypothesis against the bare core.
  obtain ⟨Rc, Rh, Rt⟩ := R
  have hRc : Layered Rc := hR
  clear hR
  induction hL with
  | acyclic h1 =>
      induction hRc with
      | acyclic h2 =>
          obtain ⟨r1, hr1⟩ := h1
          obtain ⟨r2, hr2⟩ := h2
          exact layered_seq_acyclic _ _ hinit r1 hr1 r2 hr2
      | layer hlay _ ih =>
          exact Layered.layer (seq_isLayer_right _ _ _ Rh Rt hlay)
            (ih (fun tr htr => hlay.states_eq ▸ hinit tr htr))
  | layer hlay _ ih =>
      exact Layered.layer (seq_isLayer_left _ _ ⟨Rc, Rh, Rt⟩ hlay) ih

#print axioms layered_seq





/-- **`hsum`: EVERY THOMPSON AUTOMATON CARRIES THE CERTIFICATE.**

    By induction on the expression, with every case now proved:

        test, act   no transitions at all                     (247)
        ite         `layered_ite` via `layered_sum`           (250)
        seq         `layered_seq`                             (258)
        wh          `layered_wh` — `Layered.layer` applied to
                    a fact that has been `rfl` since 220      (247)

    This is the first of 239's three obligations, closed.  The `seq` case needs
    the right component's `InitTargetsListed`, which its own certificate
    supplies. -/
theorem thompson_layered : ∀ e : Exp A T,
    Layered (GkatThompson.certifiedThompson A T e).aut.core
  | .test t => layered_test t
  | .act a => layered_act a
  | .ite b e f => layered_ite b e f (thompson_layered e) (thompson_layered f)
  | .seq e f =>
      layered_seq _ _ (GkatThompson.certifiedThompson A T f).certificate.initTargets
        (thompson_layered e) (thompson_layered f)
  | .wh b e => layered_wh b e (thompson_layered e)

#print axioms thompson_layered



/-! ### Minimum of a nonempty list, Mathlib-free

`Nat.find` does not exist in this environment (no Mathlib), so `hcollapse`'s
"least rank among the preimages" is built directly: `minOf1 x l` is the minimum
of `x :: l`, with the two facts the argument needs — it is a LOWER BOUND, and it
is ACHIEVED. -/

private def minOf1 : Nat → List Nat → Nat
  | x, [] => x
  | x, y :: ys => minOf1 (min x y) ys

private theorem minOf1_le_head : ∀ (l : List Nat) (x : Nat), minOf1 x l ≤ x := by
  intro l
  induction l with
  | nil => intro x; exact Nat.le_refl x
  | cons y ys ih =>
      intro x
      exact Nat.le_trans (ih (min x y)) (Nat.min_le_left x y)

private theorem minOf1_le_mem : ∀ (l : List Nat) (x y : Nat), y ∈ l →
    minOf1 x l ≤ y := by
  intro l
  induction l with
  | nil => intro x y h; cases h
  | cons z zs ih =>
      intro x y h
      cases h with
      | head => exact Nat.le_trans (minOf1_le_head zs (min x z)) (Nat.min_le_right x z)
      | tail _ h' => exact ih (min x z) y h'

private theorem minOf1_achieved : ∀ (l : List Nat) (x : Nat),
    minOf1 x l = x ∨ minOf1 x l ∈ l := by
  intro l
  induction l with
  | nil => intro x; exact Or.inl rfl
  | cons y ys ih =>
      intro x
      show minOf1 (min x y) ys = x ∨ minOf1 (min x y) ys ∈ y :: ys
      rcases ih (min x y) with h | h
      · rcases Nat.le_total x y with hxy | hxy
        · exact Or.inl (by rw [h, Nat.min_eq_left hxy])
        · exact Or.inr (by rw [h, Nat.min_eq_right hxy]; exact List.Mem.head _)
      · exact Or.inr (List.Mem.tail _ h)

private def minOfList : List Nat → Nat
  | [] => 0
  | x :: xs => minOf1 x xs

private theorem minOfList_le : ∀ (l : List Nat) (y : Nat), y ∈ l →
    minOfList l ≤ y := by
  intro l
  cases l with
  | nil => intro y h; cases h
  | cons z zs =>
      intro y h
      show minOf1 z zs ≤ y
      cases h with
      | head => exact minOf1_le_head zs z
      | tail _ h' => exact minOf1_le_mem zs z y h'

private theorem minOfList_mem : ∀ (l : List Nat), l ≠ [] → minOfList l ∈ l := by
  intro l
  cases l with
  | nil => intro h; exact absurd rfl h
  | cons z zs =>
      intro _
      show minOf1 z zs ∈ z :: zs
      rcases minOf1_achieved zs z with hh | hh
      · rw [hh]; exact List.Mem.head _
      · exact List.Mem.tail _ hh

/-- The `GSystem` underlying a `GAut` — 239's architecture states `Cert` on
    `GAut`s, while `Layered` is a property of the transition structure alone. -/
def gautSystem {S : Type} (aut : GkatKleene.GAut S A T) :
    GkatThompson.GSystem S A T :=
  ⟨aut.states, aut.hlt, aut.trans⟩

/-- **`hcollapse`, ACYCLIC CASE: a behavioural quotient of an acyclic automaton
    is acyclic.**

    261's argument, now writable because 263 made `Layered.acyclic` speak in
    `firstMatch` steps — which is exactly `autStep`, so the certificate and the
    bisimulation quantify over the same edges.

    `rank' q` is the MINIMUM rank over `q`'s preimages, obtained from `Nat.find`
    rather than from any finiteness machinery: `Nat.find_spec` supplies a
    preimage ACHIEVING the minimum, `Nat.find_min'` its minimality.  Given a step
    `q → r.2`, take the minimising preimage `s` and push the step BACKWARDS
    through the bisimulation to `s → s'` with `π s' = r.2`; then

        rank' r.2  ≤  rank s'  <  rank s  =  rank' q

    The `targets` hypothesis is what places `s'` back in `aut.states` so it
    counts as a preimage; Thompson automata supply it from `CoreTargetsListed`. -/
theorem acyclic_quotient {S Q : Type}
    (aut : GkatKleene.GAut S A T) (quot : GkatKleene.GAut Q A T)
    (π : GkatKleene.UniformBehavioralGAutQuotient aut quot)
    (targets : ∀ s ∈ aut.states, ∀ tr ∈ aut.trans s, tr.2.2 ∈ aut.states)
    (rank : S → Nat)
    (hrank : ∀ s ∈ aut.states, ∀ (X : Type) (W : T → X → Bool) (x : X)
      (r : A × S), GkatKleene.firstMatch W x (aut.trans s) = some r →
        rank r.2 < rank s) :
    ∃ rank' : Q → Nat, ∀ q ∈ quot.states, ∀ (X : Type) (W : T → X → Bool)
      (x : X) (r : A × Q),
      GkatKleene.firstMatch W x (quot.trans q) = some r → rank' r.2 < rank' q := by
  classical
  -- `rank' q` = least rank among `q`'s preimages that are listed in `aut`
  let pre : Q → List Nat := fun q =>
    (aut.states.filter (fun s => decide (π.mapState s = q))).map rank
  refine ⟨fun q => minOfList (pre q), ?_⟩
  intro q hq X W x r hstep
  -- the minimum at `q` is achieved by an actual preimage
  have hne : pre q ≠ [] := by
    obtain ⟨s, hs, hps⟩ := π.onto_states q hq
    intro hempty
    have : rank s ∈ pre q :=
      List.mem_map_of_mem (List.mem_filter.mpr ⟨hs, by simp [hps]⟩)
    rw [hempty] at this; cases this
  obtain ⟨s, hsf, hsr⟩ := List.mem_map.mp (minOfList_mem (pre q) hne)
  obtain ⟨hsmem, hps⟩ := List.mem_filter.mp hsf
  have hps : π.mapState s = q := by simpa using hps
  -- push the step backwards through the bisimulation
  obtain ⟨s', hs', hps'⟩ :=
    (((π.bisim_graph X W) s q hps).2.2) x r.1 r.2 (by
      show GkatKleene.firstMatch W x (quot.trans q) = some (r.1, r.2)
      simpa using hstep)
  have hmem' : s' ∈ aut.states := by
    obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x _ r.1 s' hs'
    exact targets s hsmem _ hg
  have hlt : rank s' < rank s := hrank s hsmem X W x (r.1, s') hs'
  have hmemlist : rank s' ∈ pre r.2 :=
    List.mem_map_of_mem (List.mem_filter.mpr ⟨hmem', by simp [hps']⟩)
  show minOfList (pre r.2) < minOfList (pre q)
  rw [← hsr]
  exact Nat.lt_of_le_of_lt (minOfList_le _ _ hmemlist) hlt

#print axioms acyclic_quotient


/-! ### `hsolve`, acyclic case: the solution is built, not imported

269 established that Grabmayer's `hsolve` cannot be imported — his existence
proof uses layeredness, which 268/269 showed GKAT's Thompson automata do not
have under this translation.  But a constructive replacement has been in the
development since iteration 206: the calculus takes a decomposition to a
solution, and `decomp_solves` turns "every state's label IS its equation's
right-hand side" into `SolvesBA`.

For an ACYCLIC system that is a direct recursion: a state's label is the guarded
fold of its transitions over its successors' labels, which terminates because
every transition strictly decreases the rank.  Lean wants that recursion
fuelled, so it is written with an explicit budget and a stability lemma. -/

/-- The solution of an acyclic system, computed with a fuel budget: at fuel
    `n+1` a state's label is the guarded fold of its transitions over the labels
    computed at fuel `n`. -/
def solFuel {S : Type} (sys : GkatThompson.GSystem S A T) : Nat → S → Exp A T
  | 0, s => .test (sys.hlt s)
  | n + 1, s => GkatFaithful.guardedFold
      (GkatKleene.transitionBranches (sys.trans s) (solFuel sys n))
      (.test (sys.hlt s))

/-- Folding two labellings that agree on the targets gives the same result. -/
theorem guardedFold_trans_congr {S : Type} (fb : Exp A T) (f g : S → Exp A T) :
    ∀ l : List (BExp T × A × S), (∀ tr ∈ l, f tr.2.2 = g tr.2.2) →
      GkatFaithful.guardedFold (GkatKleene.transitionBranches l f) fb
        = GkatFaithful.guardedFold (GkatKleene.transitionBranches l g) fb := by
  intro l
  induction l with
  | nil => intro _; rfl
  | cons tr rest ih =>
      intro h
      show Exp.ite tr.1 (.seq (.act tr.2.1) (f tr.2.2)) _
        = Exp.ite tr.1 (.seq (.act tr.2.1) (g tr.2.2)) _
      rw [h tr (List.Mem.head _)]
      exact congrArg _ (ih (fun t ht => h t (List.Mem.tail _ ht)))

/-- **STABILITY.**  Once the fuel exceeds a state's rank the computed label no
    longer changes — every transition drops the rank, so the recursion has
    already bottomed out.  This is what lets a single `sol` be read off the
    fuelled family. -/
theorem solFuel_stable {S : Type} (sys : GkatThompson.GSystem S A T)
    (rank : S → Nat)
    (hmem : ∀ s, ∀ tr ∈ sys.trans s, rank tr.2.2 < rank s) :
    ∀ n m s, rank s ≤ n → rank s ≤ m → solFuel sys n s = solFuel sys m s := by
  have hnil : ∀ s, rank s = 0 → sys.trans s = [] := by
    intro s h0
    cases hl : sys.trans s with
    | nil => rfl
    | cons tr rest =>
        have := hmem s tr (by rw [hl]; exact List.Mem.head _)
        rw [h0] at this
        exact absurd this (Nat.not_lt_zero _)
  have base : ∀ m s, rank s = 0 → solFuel sys m s = .test (sys.hlt s) := by
    intro m s h0
    cases m with
    | zero => rfl
    | succ m' =>
        show GkatFaithful.guardedFold
          (GkatKleene.transitionBranches (sys.trans s) _) _ = _
        rw [hnil s h0]
        rfl
  intro n
  induction n with
  | zero =>
      intro m s hn hm
      have h0 : rank s = 0 := Nat.le_zero.mp hn
      rw [base 0 s h0, base m s h0]
  | succ n' ih =>
      intro m s hn hm
      cases m with
      | zero =>
          have h0 : rank s = 0 := Nat.le_zero.mp hm
          rw [base (n' + 1) s h0, base 0 s h0]
      | succ m' =>
          show GkatFaithful.guardedFold _ _ = GkatFaithful.guardedFold _ _
          refine guardedFold_trans_congr _ _ _ _ (fun tr htr => ?_)
          have hlt : rank tr.2.2 < rank s := hmem s tr htr
          exact ih m' tr.2.2
            (Nat.le_of_lt_succ (Nat.lt_of_lt_of_le hlt hn))
            (Nat.le_of_lt_succ (Nat.lt_of_lt_of_le hlt hm))

#print axioms solFuel


/-- **THE ACYCLIC CASE OF `hsolve`: the fuelled solution satisfies its own
    equation.**

    Reading `sol s := solFuel sys (rank s) s`, each state's label IS the guarded
    fold of its transitions over the labels of its targets — which is exactly the
    right-hand side of that state's equation.  At rank `0` a state has no
    transitions and the fold is its halt test; above `0` the fuel is one more
    than every target's rank, so `solFuel_stable` replaces the lower-fuel labels
    by `sol` itself.

    No `EquivBA` reasoning is needed: the equation holds ON THE NOSE, which is
    `StateRole.fold` and hence `decomp_solves`'s easiest case. -/
theorem solFuel_solves {S : Type} (sys : GkatThompson.GSystem S A T)
    (rank : S → Nat)
    (hmem : ∀ s, ∀ tr ∈ sys.trans s, rank tr.2.2 < rank s) (s : S) :
    solFuel sys (rank s) s
      = GkatFaithful.guardedFold
          (GkatKleene.transitionBranches (sys.trans s)
            (fun t => solFuel sys (rank t) t))
          (.test (sys.hlt s)) := by
  cases hr : rank s with
  | zero =>
      have hnil : sys.trans s = [] := by
        cases hl : sys.trans s with
        | nil => rfl
        | cons tr rest =>
            have := hmem s tr (by rw [hl]; exact List.Mem.head _)
            rw [hr] at this
            exact absurd this (Nat.not_lt_zero _)
      rw [hnil]
      rfl
  | succ n =>
      show GkatFaithful.guardedFold
        (GkatKleene.transitionBranches (sys.trans s) (solFuel sys n)) _ = _
      refine guardedFold_trans_congr _ _ _ _ (fun tr htr => ?_)
      have hlt : rank tr.2.2 < rank s := hmem s tr htr
      rw [hr] at hlt
      exact solFuel_stable sys rank hmem n (rank tr.2.2) tr.2.2
        (Nat.le_of_lt_succ hlt) (Nat.le_refl _)

#print axioms solFuel_solves

/-- **THE ACYCLIC CASE OF `hsolve`, AS A SOLUTION.**  An acyclic system has a
    labelling solving its equations — built, not assumed, and satisfying them
    definitionally rather than up to `EquivBA`. -/
theorem acyclic_has_solution {S : Type} (sys : GkatThompson.GSystem S A T)
    (rank : S → Nat)
    (hmem : ∀ s, ∀ tr ∈ sys.trans s, rank tr.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s, sol s
      = GkatFaithful.guardedFold
          (GkatKleene.transitionBranches (sys.trans s) sol)
          (.test (sys.hlt s)) :=
  ⟨fun s => solFuel sys (rank s) s, solFuel_solves sys rank hmem⟩

#print axioms acyclic_has_solution


/-! ### 274 — THE LAYER NORMAL FORM

    **A correction to 272 first.**  272 read 218's `loop_standard_eq` as saying
    the layer's solution is `sol_sys s := sol_base s ; W`.  That is FALSE for a
    layer sitting inside a SEQUENCE.  Take `seq (wh b e) f`.  At a left state
    `inl s` the true solution is

        (e-solution at s) ; W ; (f-solution)

    whereas `sol_base (inl s) ; W` is `(e-solution at s) ; (f-solution) ; W`.
    **`W` is INSERTED where the layer's back edges sit, not APPENDED at the
    end.**  218's shape is the special case `post = []`, which is exactly what
    `wh` gives and what made the misreading invisible.

    So the layer lemma cannot have the form "`base`'s equation with a different
    trailing continuation" — `loop_subsystem`'s form — because `post` sits
    between the insertion point and the end.  What IS true is a NORMAL FORM: the
    layer rewrites a state's decision list into `pre`, then `b`-gated back
    edges, then `¬b`-gated tail.  That is this lemma, and it holds for an
    ABSTRACT `IsLayer` with no constructor in sight.

    The proof is by SELECTION (`guardedFold_select_congr`, 233): two guarded
    decision lists are `EquivBA` as soon as their first-matches agree at every
    world.  Here they agree SYNTACTICALLY — gating `extra` by `b` changes no
    guard's value (its guards already imply `b`), and gating `post` by `¬b`
    reproduces `post'` exactly (that is what `RestrictedTo` says).  No case
    analysis on the automaton, and no axioms. -/
private theorem selectFull_append {X : Type} (W : T → X → Bool) (x : X)
    (R : List (BExp T × Exp A T)) (fb : Exp A T) :
    ∀ L : List (BExp T × Exp A T),
      selectFull W x (L ++ R) fb = selectFull W x L (selectFull W x R fb)
  | [] => rfl
  | br :: tl => by
      cases hb : GkatGS.bval W br.1 x
      · simp only [List.cons_append, selectFull, hb]
        exact selectFull_append W x R fb tl
      · simp only [List.cons_append, selectFull, hb]

/-- Gating a branch by a guard it already implies changes no selection. -/
private theorem selectFull_gate_implies {S X : Type} (W : T → X → Bool) (x : X)
    (b : BExp T) (sol : S → Exp A T) (k : Exp A T) :
    ∀ l : List (BExp T × A × S), (∀ tr ∈ l, GuardImplies tr.1 b) →
      selectFull W x
          (transitionBranches (l.map (fun tr => (BExp.and b tr.1, tr.2))) sol) k
        = selectFull W x (transitionBranches l sol) k
  | [], _ => rfl
  | tr :: tl, h => by
      have hb : GkatGS.bval W (BExp.and b tr.1) x = GkatGS.bval W tr.1 x := by
        have himp := h tr (List.mem_cons_self ..)
        show (GkatGS.bval W b x && GkatGS.bval W tr.1 x) = GkatGS.bval W tr.1 x
        cases htr : GkatGS.bval W tr.1 x
        · cases GkatGS.bval W b x <;> rfl
        · rw [himp X W x htr]; rfl
      cases hv : GkatGS.bval W tr.1 x
      · simp only [List.map_cons, transitionBranches, selectFull, hb, hv]
        exact selectFull_gate_implies W x b sol k tl
            (fun t ht => h t (List.mem_cons_of_mem _ ht))
      · simp only [List.map_cons, transitionBranches, selectFull, hb, hv]

/-- `RestrictedTo` IS `¬b`-gating, read through selection. -/
private theorem selectFull_restricted {S X : Type} (W : T → X → Bool) (x : X)
    {b : BExp T} (sol : S → Exp A T) (k : Exp A T) :
    ∀ {post post' : List (BExp T × A × S)}, RestrictedTo b post post' →
      selectFull W x (transitionBranches post' sol) k
        = selectFull W x
            (transitionBranches
              (post.map (fun tr => (BExp.and (BExp.not b) tr.1, tr.2))) sol) k := by
  intro post post' h
  induction h with
  | nil => rfl
  | @cons g g' a q l l' hg _ ih =>
      have hval : GkatGS.bval W g' x
          = GkatGS.bval W (BExp.and (BExp.not b) g) x := by
        rw [hg X W x]; rfl
      cases h2 : GkatGS.bval W (BExp.and (BExp.not b) g) x
      · simp only [List.map_cons, transitionBranches, selectFull, hval, h2]
        exact ih
      · simp only [List.map_cons, transitionBranches, selectFull, hval, h2]

/-- **THE LAYER NORMAL FORM.**  Stated for an abstract split — no `IsLayer`
    field is used beyond `split`, and no Thompson constructor appears. -/
theorem layer_normal_form {S : Type} {sys : GkatThompson.GSystem S A T}
    {b : BExp T} (sol : S → Exp A T) (F : Exp A T) (s : S)
    (pre extra post post' : List (BExp T × A × S))
    (hsys : sys.trans s = pre ++ extra ++ post')
    (hg : ∀ tr ∈ extra, GuardImplies tr.1 b)
    (hr : RestrictedTo b post post') :
    EquivBA (GkatThompson.eqRHSParam sys sol F s)
      (guardedFold
        (transitionBranches pre sol
          ++ transitionBranches (extra.map (fun tr => (BExp.and b tr.1, tr.2))) sol
          ++ transitionBranches
              (post.map (fun tr => (BExp.and (BExp.not b) tr.1, tr.2))) sol)
        (GkatThompson.paramFallback (sys.hlt s) F)) := by
  simp only [GkatThompson.eqRHSParam, hsys]
  refine guardedFold_select_congr _ _ _ _ ?_
  intro X W x
  have e1 : transitionBranches (pre ++ extra ++ post') sol
      = transitionBranches pre sol ++ transitionBranches extra sol
        ++ transitionBranches post' sol := by
    simp only [transitionBranches, List.map_append]
  rw [e1, selectFull_append, selectFull_append, selectFull_append,
    selectFull_append, selectFull_restricted W x sol _ hr,
    selectFull_gate_implies W x b sol _ extra hg]
  exact EquivBA.base (Equiv.refl _)

#print axioms layer_normal_form


/-- Gating every guard of a transition list commutes with labelling it. -/
private theorem transitionBranches_gate {S : Type} (c : BExp T)
    (sol : S → Exp A T) (l : List (BExp T × A × S)) :
    transitionBranches (l.map (fun tr => (BExp.and c tr.1, tr.2))) sol
      = (transitionBranches l sol).map (fun br => (BExp.and c br.1, br.2)) := by
  simp only [transitionBranches, List.map_map, Function.comp_def]

/-- **THE LAYER, IN LOOP FORM.**  275.  Folding 274's two gated blocks back
    together under a single top-level conditional gives the shape `hsolve`
    actually consumes:

        pre , then  IF b THEN (back edges) ELSE (base's own tail)

    — a state of the layer runs its `pre` block, and where `pre` does not fire
    it takes the loop if the guard holds and behaves like `base` if it does not.
    This is `loop_subsystem`'s content for an ABSTRACT layer, in the form 274
    showed is forced: the conditional sits at the INSERTION POINT (after `pre`),
    not at the end, which is exactly why the `seq` case broke 272's shape.

    The proof is 274 plus `ite_guardedFold_partition` run BACKWARDS, with `u1`
    (`ite b e e ≈ e`) collapsing the duplicated fallback the partition law
    introduces.  Still no `IsLayer` field beyond `split`, and still no Thompson
    constructor. -/
theorem layer_ite_form {S : Type} {sys : GkatThompson.GSystem S A T}
    {b : BExp T} (sol : S → Exp A T) (F : Exp A T) (s : S)
    (pre extra post post' : List (BExp T × A × S))
    (hsys : sys.trans s = pre ++ extra ++ post')
    (hg : ∀ tr ∈ extra, GuardImplies tr.1 b)
    (hr : RestrictedTo b post post') :
    EquivBA (GkatThompson.eqRHSParam sys sol F s)
      (guardedFold (transitionBranches pre sol)
        (.ite b
          (guardedFold (transitionBranches extra sol)
            (GkatThompson.paramFallback (sys.hlt s) F))
          (guardedFold (transitionBranches post sol)
            (GkatThompson.paramFallback (sys.hlt s) F)))) := by
  refine EquivBA.trans
    (layer_normal_form sol F s pre extra post post' hsys hg hr) ?_
  rw [transitionBranches_gate, transitionBranches_gate, List.append_assoc,
    guardedFold_append]
  refine guardedFold_fallback_congr ?_
  refine EquivBA.symm (EquivBA.trans
    (ite_guardedFold_partition b (transitionBranches extra sol)
      (transitionBranches post sol)
      (GkatThompson.paramFallback (sys.hlt s) F)
      (GkatThompson.paramFallback (sys.hlt s) F)) ?_)
  exact guardedFold_fallback_congr (EquivBA.base (Equiv.u1 b _))

#print axioms layer_ite_form


/-! ### 276 — THE LOOP IS GLOBAL TO THE LAYER

    273 derived — and Grabmayer's own loop-chart definition confirmed — that a
    layer's back edges must be ONE shared entry list gated by each state's own
    halt.  This is what that condition BUYS, and it is the whole reason to want
    it: under `b`, every state of the layer does

        test (base.hlt s) ; E

    with ONE `E` shared by the entire layer.  The only per-state part is the
    halt test; the loop body itself does not depend on which state fell into it.
    That is the algebraic content of "the back edge returns to the layer's ENTRY
    rather than to `s`", and it is what will let a single `wh b E` serve every
    state of the layer.

    Proved by `guardedFold_guard_factor` (parametric guard factoring): the
    per-state halt conjoined onto every back edge factors out as a test prefix,
    leaving a fold that mentions `s` nowhere.  The layer's halt semantics
    (`base.hlt ∧ ¬b`) is exactly what makes the fallback factor with it. -/
theorem layer_entry_shared {S : Type} {sys base : GkatThompson.GSystem S A T}
    {b : BExp T} (sol : S → Exp A T) (F : Exp A T) (s : S)
    (entry extra : List (BExp T × A × S))
    (hextra : extra = entry.map (fun tr =>
      (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2)))
    (hhlt : ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W (sys.hlt s) x
        = (GkatGS.bval W (base.hlt s) x && !GkatGS.bval W b x)) :
    EquivBA
      (guardedFold (transitionBranches extra sol)
        (GkatThompson.paramFallback (sys.hlt s) F))
      (.seq (.test (base.hlt s))
        (guardedFold
          (transitionBranches (entry.map (fun tr => (BExp.and b tr.1, tr.2))) sol)
          (GkatThompson.paramFallback (BExp.not b) F))) := by
  have hmap : extra
      = (entry.map (fun tr => (BExp.and b tr.1, tr.2))).map
          (fun tr => (BExp.and (base.hlt s) tr.1, tr.2)) := by
    rw [hextra]
    simp only [List.map_map, Function.comp_def]
  have hfb : EquivBA (GkatThompson.paramFallback (sys.hlt s) F)
      (GkatThompson.paramFallback
        (BExp.and (base.hlt s) (BExp.not b)) F) :=
    EquivBA.seq_c (EquivBA.baTest (fun X W x => hhlt X W x))
      (EquivBA.base (Equiv.refl F))
  rw [hmap, transitionBranches_gate]
  exact EquivBA.trans (guardedFold_fallback_congr hfb)
    (guardedFold_guard_factor (base.hlt s) (BExp.not b) F _)

#print axioms layer_entry_shared


/-- **THE LAYER'S EQUATION, IN THE FORM `hsolve` CONSUMES.**  276.  275 and the
    lemma above, composed.  A state of the layer runs its `pre` block; where
    `pre` does not fire it takes the loop — `test (base.hlt s) ; E` for the
    ONE `E` the whole layer shares — if the guard holds, and behaves like
    `base` if it does not:

        pre , then  IF b THEN (test (base.hlt s) ; E) ELSE (base's own tail)

    Every trace of the layer's identity is now confined to two places: the halt
    test `base.hlt s`, and `base`'s tail.  `E` is the same expression at every
    state.  This is the statement 272 was reaching for and mis-stated, 273
    identified the missing hypothesis for, 274 and 275 proved the split of, and
    that the shared entry list finally pays for. -/
theorem layer_loop_form {S : Type} {sys base : GkatThompson.GSystem S A T}
    {b : BExp T} (sol : S → Exp A T) (F : Exp A T) (s : S)
    (pre entry extra post post' : List (BExp T × A × S))
    (hsys : sys.trans s = pre ++ extra ++ post')
    (hextra : extra = entry.map (fun tr =>
      (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2)))
    (hhlt : ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W (sys.hlt s) x
        = (GkatGS.bval W (base.hlt s) x && !GkatGS.bval W b x))
    (hr : RestrictedTo b post post') :
    EquivBA (GkatThompson.eqRHSParam sys sol F s)
      (guardedFold (transitionBranches pre sol)
        (.ite b
          (.seq (.test (base.hlt s))
            (guardedFold
              (transitionBranches
                (entry.map (fun tr => (BExp.and b tr.1, tr.2))) sol)
              (GkatThompson.paramFallback (BExp.not b) F)))
          (guardedFold (transitionBranches post sol)
            (GkatThompson.paramFallback (sys.hlt s) F)))) := by
  have hg : ∀ tr ∈ extra, GuardImplies tr.1 b := by
    intro tr htr X W x hx
    rw [hextra] at htr
    simp only [List.mem_map] at htr
    obtain ⟨t, _, rfl⟩ := htr
    have hval : (GkatGS.bval W (base.hlt s) x
        && (GkatGS.bval W b x && GkatGS.bval W t.1 x)) = true := hx
    cases hb : GkatGS.bval W b x
    · rw [hb] at hval
      cases GkatGS.bval W (base.hlt s) x <;>
        cases GkatGS.bval W t.1 x <;> simp at hval
    · rfl
  refine EquivBA.trans
    (layer_ite_form sol F s pre extra post post' hsys hg hr) ?_
  exact guardedFold_fallback_congr
    (EquivBA.ite_c
      (layer_entry_shared sol F s entry extra hextra hhlt)
      (EquivBA.base (Equiv.refl _)))

#print axioms layer_loop_form


/-! ### 277 — `loop_subsystem` FOR AN ABSTRACT LAYER

    273 wanted `loop_subsystem` generalised from `loopInitialized` to an
    abstract layer.  274 showed the generalisation is FALSE in general, because
    the layer's conditional sits at the INSERTION POINT and `post` sits between
    it and the end.  What 274 did not say, and what is true, is that the
    obstruction is EXACTLY `post ≠ []`:

    with `post = []` the insertion point IS the end, and 276's shared-`E` lemma
    turns the whole back-edge block into `test (base.hlt s) ; E` — which is
    literally `paramFallback (base.hlt s) E`.  So the layer's parametric
    equation is `base`'s parametric equation at the finish `E`, with no algebra
    left to do.

    **Why this is not a weakening.**  `wh_isLayer` ALREADY has `post = []` —
    `CoreHaltDisjoint` keeps the back edges from colliding, which is what 246
    observed and what made 246's original shape work.  `post` becomes nonempty
    only when a layer is LIFTED through a `seq`, and there the right move is to
    peel the `seq` first (`seq_subsystem`, already proved) and apply this lemma
    to the left component, where `post` is empty again.  The recursion follows
    the construction; it does not strip an abstract layer off an arbitrary
    automaton.  That is a real constraint on `Layered`, recorded in the ledger. -/
theorem layer_subsystem {S : Type} {sys base : GkatThompson.GSystem S A T}
    {b : BExp T} (sol : S → Exp A T) (F : Exp A T) (s : S)
    (entry : List (BExp T × A × S))
    (hsys : sys.trans s = base.trans s ++ entry.map (fun tr =>
      (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2)))
    (hhlt : ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W (sys.hlt s) x
        = (GkatGS.bval W (base.hlt s) x && !GkatGS.bval W b x)) :
    EquivBA (GkatThompson.eqRHSParam sys sol F s)
      (GkatThompson.eqRHSParam base sol
        (guardedFold
          (transitionBranches (entry.map (fun tr => (BExp.and b tr.1, tr.2))) sol)
          (GkatThompson.paramFallback (BExp.not b) F)) s) := by
  have hsplit : transitionBranches (sys.trans s) sol
      = transitionBranches (base.trans s) sol
        ++ transitionBranches (entry.map (fun tr =>
            (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2))) sol := by
    rw [hsys]
    simp only [transitionBranches, List.map_append]
  show EquivBA (guardedFold (transitionBranches (sys.trans s) sol) _) _
  rw [hsplit, guardedFold_append]
  exact guardedFold_fallback_congr
    (layer_entry_shared sol F s entry _ rfl hhlt)

#print axioms layer_subsystem

/-- **AND IT SPECIALISES BACK TO `loop_subsystem`.**  A sanity check that the
    abstract lemma really covers the concrete one it generalises: a `wh`'s core
    is a layer over its body's core with `post = []`, entry list the body's own
    initial transitions, and the halt semantics `body.hlt ∧ ¬guard` — all three
    hypotheses hold by `rfl` or by 220's `loop_core_hlt`. -/
theorem loop_subsystem_of_layer {S : Type} (guard : BExp T)
    (body : GkatThompson.InitializedGAut S A T)
    (sol : S → Exp A T) (F : Exp A T) (s : S) :
    EquivBA
      (GkatThompson.eqRHSParam
        (GkatThompson.loopInitialized guard body).core sol F s)
      (GkatThompson.eqRHSParam body.core sol
        (guardedFold
          (transitionBranches
            (body.initTrans.map (fun tr => (BExp.and guard tr.1, tr.2))) sol)
          (GkatThompson.paramFallback (BExp.not guard) F)) s) :=
  layer_subsystem sol F s body.initTrans rfl (fun _ _ _ => rfl)

#print axioms loop_subsystem_of_layer


/-! ### 278 — `hsolve` IS ALREADY DONE FOR THOMPSON AUTOMATA, AND THAT RESHAPES
    THE REMAINDER

    Before spending a ninth `Layered` migration on making `hsolve` provable by
    recursion on the CONSTRUCTION (277's conclusion), check what the repository
    already gives for construction-shaped automata.  It gives everything:
    `certifiedThompson` carries `standard`, and its certificate carries
    `standardSolves : ParamSolvesBA aut.core standard (.test .one)`, which
    `StandardSolvesBA.withContinuation` lifts to EVERY finish.

    So a Thompson automaton is solvable, parametrically, with no work at all.
    **A `Layered` restructured to follow the construction would therefore prove
    nothing new** — it would re-derive by recursion exactly what the certificate
    already hands over.  The ninth migration is cancelled.

    **What this means for the architecture.**  `hsolve` was never needed for
    Thompson automata; it was only ever needed for the QUOTIENT.  Reading the
    three obligations again with that in mind:

      hsum       every Thompson automaton carries the certificate    PROVED
      hcollapse  the certificate survives the quotient               OPEN
      hsolve     the certificate implies a solution exists           free for
                                                                     Thompson,
                                                                     needed only
                                                                     for the
                                                                     quotient

    — `hsolve` and `hcollapse` are not two independent obligations.  They are
    one: **produce a solution for the minimal behavioural quotient.**  Every
    layer lemma 274-277 proved is a tool for that single statement, and the
    `Layered` predicate matters only insofar as the QUOTIENT satisfies it.

    That is now the measurement to make, and it is measurable: 265's harness
    already builds minimal quotients of Thompson automata. -/
theorem thompson_has_solution (e : Exp A T) (F : Exp A T) :
    ∃ sol : (GkatThompson.certifiedThompson A T e).State → Exp A T,
      GkatThompson.ParamSolvesBA
        (GkatThompson.certifiedThompson A T e).aut.core sol F :=
  ⟨fun s => .seq ((GkatThompson.certifiedThompson A T e).standard s) F,
   GkatThompson.StandardSolvesBA.withContinuation _ _
     (GkatThompson.certifiedThompson A T e).certificate.standardSolves F⟩

#print axioms thompson_has_solution


/-! ### 279 — LOOP LAYERS, AND WHY THE BASE IS DETERMINED ALONG A HOMOMORPHISM

    278 pointed the remainder at ONE statement — produce a solution for the
    minimal behavioural quotient — and the literature's technique for it:
    prove preservation along an arbitrary FUNCTIONAL BISIMILARITY and take the
    collapse as the special case.

    Pushing a layer forward along `f : S → S'` means building `base'` from
    `base`, and that needs `base` to be DETERMINED by its image: if `f s = f t`,
    the two states' base data must agree, or `base'` is not well defined.  For
    the general `IsLayer` this FAILS — the split is existential, so two states
    with the same image may split their (equal) images differently, and nothing
    forces the same cut.  **That is why 265 found the layer case blocked.**

    For 277's `post = []` form it SUCCEEDS, and this is the payoff of that
    restriction: the back-edge block has the SAME LENGTH at every state (it is
    `entry` gated, and `entry` is shared), so the cut point is forced, and
    `List.append_inj'` recovers the base transitions.  The base HALT comes back
    too, from the head of the back-edge block — its guard is syntactically
    `base.hlt s ∧ b ∧ g₀`, so `base.hlt s` is readable off it, provided the
    layer has at least one entry.  A layer with no entries is not a loop.

    So: the `post = []` restriction, forced on `hsolve` by 277, is exactly what
    makes `hcollapse`'s pushforward well defined.  The two obligations 278
    merged into one want the same hypothesis. -/
structure LoopLayer {S : Type} (sys base : GkatThompson.GSystem S A T)
    (b : BExp T) (entry : List (BExp T × A × S)) : Prop where
  trans_eq : ∀ s, sys.trans s = base.trans s ++ entry.map (fun tr =>
    (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2))
  hlt_eq : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X),
    GkatGS.bval W (sys.hlt s) x
      = (GkatGS.bval W (base.hlt s) x && !GkatGS.bval W b x)
  states_eq : sys.states = base.states

/-- `wh b e`'s automaton is a LOOP LAYER over `e`'s, with `e`'s own initial
    transitions as the shared entry list.  All three fields are `rfl` or 220. -/
theorem wh_loopLayer (b : BExp T) (e : Exp A T) :
    LoopLayer (GkatThompson.certifiedThompson A T (.wh b e)).aut.core
      (GkatThompson.certifiedThompson A T e).aut.core b
      (GkatThompson.certifiedThompson A T e).aut.initTrans where
  trans_eq s := loop_core_trans b e s
  hlt_eq s := by
    intro X W x
    rw [loop_core_hlt b e s]
    rfl
  states_eq := rfl

#print axioms wh_loopLayer

/-- **THE BASE IS DETERMINED BY ITS IMAGE.**  If two states of a loop layer have
    the same retargeted transition list, then so do their bases, and their base
    halts are EQUAL — syntactically, not merely semantically.  This is the
    well-definedness `hcollapse`'s pushforward needs, and it is false without
    the `post = []` shape. -/
theorem loopLayer_fiber_agree {S S' : Type}
    {sys base : GkatThompson.GSystem S A T} {b : BExp T}
    {tr₀ : BExp T × A × S} {rest : List (BExp T × A × S)}
    (h : LoopLayer sys base b (tr₀ :: rest)) (f : S → S') (s t : S)
    (hf : (sys.trans s).map (fun tr => (tr.1, tr.2.1, f tr.2.2))
        = (sys.trans t).map (fun tr => (tr.1, tr.2.1, f tr.2.2))) :
    (base.trans s).map (fun tr => (tr.1, tr.2.1, f tr.2.2))
        = (base.trans t).map (fun tr => (tr.1, tr.2.1, f tr.2.2))
      ∧ base.hlt s = base.hlt t := by
  rw [h.trans_eq s, h.trans_eq t, List.map_append, List.map_append] at hf
  have hlen : (((tr₀ :: rest).map (fun tr =>
        (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2))).map
        (fun tr => (tr.1, tr.2.1, f tr.2.2))).length
      = (((tr₀ :: rest).map (fun tr =>
        (BExp.and (base.hlt t) (BExp.and b tr.1), tr.2))).map
        (fun tr => (tr.1, tr.2.1, f tr.2.2))).length := by
    simp only [List.length_map]
  obtain ⟨hpre, hsuf⟩ := List.append_inj' hf hlen
  refine ⟨hpre, ?_⟩
  simp only [List.map_cons] at hsuf
  injection hsuf with hhd _
  injection hhd with hg _
  injection hg with h1 _

#print axioms loopLayer_fiber_agree


/-! ### 280 — THE PUSHFORWARD

    279 showed a loop layer's base is determined by its image.  That is exactly
    the well-definedness a pushforward needs, so the pushforward can now be
    BUILT: choose a section of the surjection, define the base downstairs by
    transporting the base upstairs through it, and 279 says the choice of
    representative does not matter.

    This is `hcollapse`'s layer case in the generality 278's search pointed at —
    an arbitrary surjective structural homomorphism, not a minimal quotient.
    The minimal quotient is one instance; a single merged pair (the step-wise
    construction Grabmayer–Fokkink use, 279) is another. -/
noncomputable def pushBase {S S' : Type} (f : S → S')
    (hsurj : ∀ s' : S', ∃ s, f s = s')
    (base : GkatThompson.GSystem S A T)
    (sys' : GkatThompson.GSystem S' A T) :
    GkatThompson.GSystem S' A T where
  states := sys'.states
  hlt s' := base.hlt (Classical.choose (hsurj s'))
  trans s' := (base.trans (Classical.choose (hsurj s'))).map
    (fun tr => (tr.1, tr.2.1, f tr.2.2))

/-- **A LOOP LAYER PUSHES FORWARD ALONG A SURJECTIVE STRUCTURAL HOMOMORPHISM.**
    The layer downstairs has the SAME guard and the image of the entry list. -/
theorem loopLayer_pushforward {S S' : Type}
    {sys base : GkatThompson.GSystem S A T} {b : BExp T}
    {tr₀ : BExp T × A × S} {rest : List (BExp T × A × S)}
    (h : LoopLayer sys base b (tr₀ :: rest))
    (f : S → S') (hsurj : ∀ s' : S', ∃ s, f s = s')
    (sys' : GkatThompson.GSystem S' A T)
    (htrans : ∀ s, sys'.trans (f s)
      = (sys.trans s).map (fun tr => (tr.1, tr.2.1, f tr.2.2)))
    (hhlt : ∀ s, sys'.hlt (f s) = sys.hlt s) :
    LoopLayer sys' (pushBase f hsurj base sys') b
      ((tr₀ :: rest).map (fun tr => (tr.1, tr.2.1, f tr.2.2))) := by
  have hsec : ∀ s' : S', f (Classical.choose (hsurj s')) = s' :=
    fun s' => Classical.choose_spec (hsurj s')
  have hfib : ∀ s : S,
      (base.trans (Classical.choose (hsurj (f s)))).map
          (fun tr => (tr.1, tr.2.1, f tr.2.2))
        = (base.trans s).map (fun tr => (tr.1, tr.2.1, f tr.2.2))
      ∧ base.hlt (Classical.choose (hsurj (f s))) = base.hlt s := by
    intro s
    refine loopLayer_fiber_agree h f (Classical.choose (hsurj (f s))) s ?_
    rw [← htrans, ← htrans, hsec (f s)]
  refine ⟨?_, ?_, rfl⟩
  · intro s'
    obtain ⟨s, rfl⟩ : ∃ s, f s = s' := hsurj s'
    simp only [pushBase]
    rw [htrans s, (hfib s).1, (hfib s).2, h.trans_eq s, List.map_append]
    congr 1
    simp only [List.map_map, Function.comp_def]
  · intro s' X W x
    obtain ⟨s, rfl⟩ : ∃ s, f s = s' := hsurj s'
    simp only [pushBase]
    rw [hhlt s, (hfib s).2]
    exact h.hlt_eq s X W x

#print axioms loopLayer_pushforward


/-! ### 281 — THE PUSHFORWARD WITHOUT THE STRUCTURAL-HOM ASSUMPTION

    280 closed `hcollapse`'s layer case but left a gap it named: the theorem
    assumed the quotient map is a STRUCTURAL homomorphism — transition lists
    map exactly, same order, same guards — and a BEHAVIOURAL quotient need not
    be one.  Two bisimilar states can carry syntactically different guarded
    decision lists that induce the same first-match behaviour, so the
    assumption is genuinely strong, and it was the gap most likely to sink the
    route.

    It dissolves on re-reading 280's proof: **the proof only ever touches
    REPRESENTATIVES.**  Every use of `htrans` and `hhlt` is at
    `Classical.choose (hsurj s')`, never at an arbitrary fibre member.  So the
    hypothesis can be weakened to

        sys'.trans s' = (sys.trans (rep s')).map (retarget f)
        sys'.hlt   s' =  sys.hlt   (rep s')

    — "the quotient's dynamics at each class is a REPRESENTATIVE's, retargeted"
    — which a behavioural quotient satisfies BY CONSTRUCTION, since that is how
    one builds it.  The structural-hom assumption is gone, and with it 280's
    second scope gap.

    `entry` no longer needs to be nonempty either: 279's fibre lemma was what
    required a head to read the base halt off, and this route does not use it.
    (`loopLayer_fiber_agree` remains the well-definedness fact for the
    structural version, and remains proved.)

    **What is NOT proved here, stated plainly.**  That the `sys'` so described
    is behaviourally equivalent to `sys` — i.e. that `f` is a bisimulation — is
    a separate obligation.  It is a statement about the QUOTIENT's correctness,
    not about the layer, and it is where the remaining work on `hcollapse`
    lives. -/
theorem loopLayer_pushforward_rep {S S' : Type}
    {sys base : GkatThompson.GSystem S A T} {b : BExp T}
    {entry : List (BExp T × A × S)}
    (h : LoopLayer sys base b entry)
    (f : S → S') (hsurj : ∀ s' : S', ∃ s, f s = s')
    (sys' : GkatThompson.GSystem S' A T)
    (htrans : ∀ s' : S', sys'.trans s'
      = (sys.trans (Classical.choose (hsurj s'))).map
          (fun tr => (tr.1, tr.2.1, f tr.2.2)))
    (hhlt : ∀ s' : S', sys'.hlt s' = sys.hlt (Classical.choose (hsurj s'))) :
    LoopLayer sys' (pushBase f hsurj base sys') b
      (entry.map (fun tr => (tr.1, tr.2.1, f tr.2.2))) := by
  refine ⟨?_, ?_, rfl⟩
  · intro s'
    simp only [pushBase]
    rw [htrans s', h.trans_eq (Classical.choose (hsurj s')), List.map_append]
    congr 1
    simp only [List.map_map, Function.comp_def]
  · intro s' X W x
    simp only [pushBase]
    rw [hhlt s']
    exact h.hlt_eq (Classical.choose (hsurj s')) X W x

#print axioms loopLayer_pushforward_rep


/-! ### 282 — A LOOP NESTED IN A SEQUENCE, PEELED

    280's FIRST scope gap: `LoopLayer` is total and has `post = []`, so only a
    TOP-LEVEL `wh` satisfies it — `seq (wh b e) f` is not a `LoopLayer` over
    anything.  277 explained why and named the fix: the recursion follows the
    construction, so PEEL THE SEQUENCE FIRST and apply the layer lemma to the
    left component, where `post` is empty again.

    Here that fix is carried out.  `seq_subsystem` (already proved) reduces a
    left state's equation in `seq L R` to `L`'s own equation at the finish "R's
    initial dispatch"; `layer_subsystem` (277) then strips the loop off `L`.
    The two compose by transitivity and nothing else — the ambient continuation
    `F` that `seq_subsystem` hands down is exactly the parameter
    `layer_subsystem` is stated to accept, which is why both were kept
    parametric from the start.

    Worth noting what this shows about 277's constraint.  "The recursion must
    follow the construction" sounded like a restriction; here it is a two-line
    proof.  The layer lemmas are not weaker for being applied at the right
    place — they are applied there by COMPOSITION, and the composition is the
    identity on the difficulty. -/
theorem seq_layer_subsystem {S₁ S₂ : Type}
    {sysL baseL : GkatThompson.GSystem S₁ A T} {b : BExp T}
    {entry : List (BExp T × A × S₁)}
    (h : LoopLayer sysL baseL b entry)
    (R : GkatThompson.InitializedGAut S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (F : Exp A T) (s : S₁) :
    EquivBA
      (GkatThompson.eqRHSParam (GkatThompson.seqGSystem sysL R) sol F (.inl s))
      (GkatThompson.eqRHSParam baseL (fun t => sol (.inl t))
        (guardedFold
          (transitionBranches (entry.map (fun tr => (BExp.and b tr.1, tr.2)))
            (fun t => sol (.inl t)))
          (GkatThompson.paramFallback (BExp.not b)
            (GkatThompson.initRHSParam R (fun t => sol (.inr t)) F))) s) :=
  EquivBA.trans (seq_subsystem sysL R sol F s)
    (layer_subsystem (fun t => sol (.inl t)) _ s entry (h.trans_eq s) (h.hlt_eq s))

#print axioms seq_layer_subsystem

/-- The same for a loop in the LEFT half of a SUM (hence of an `ite`). -/
theorem sum_layer_subsystem {S₁ S₂ : Type}
    {sysL baseL : GkatThompson.GSystem S₁ A T} {b : BExp T}
    {entry : List (BExp T × A × S₁)}
    (h : LoopLayer sysL baseL b entry)
    (Rc : GkatThompson.GSystem S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (F : Exp A T) (s : S₁) :
    EquivBA
      (GkatThompson.eqRHSParam (GkatThompson.sumGSystem sysL Rc) sol F (.inl s))
      (GkatThompson.eqRHSParam baseL (fun t => sol (.inl t))
        (guardedFold
          (transitionBranches (entry.map (fun tr => (BExp.and b tr.1, tr.2)))
            (fun t => sol (.inl t)))
          (GkatThompson.paramFallback (BExp.not b) F)) s) :=
  by
    rw [sum_subsystem_inl sysL Rc sol F s]
    exact layer_subsystem (fun t => sol (.inl t)) F s entry
      (h.trans_eq s) (h.hlt_eq s)

#print axioms sum_layer_subsystem


/-! ### 283 — THE JOIN: FIRSTMATCH-ACYCLIC AUTOMATA ARE SOLVABLE

    Assembling `hcollapse`'s acyclic case with `hsolve`'s exposes a mismatch
    that 270 knew about and left standing.  `acyclic_quotient` (264) produces
    the FIRSTMATCH rank condition — every step the automaton can actually TAKE
    decreases the rank — because that is the only form a bisimulation can
    supply, bisimilarity comparing selections rather than lists.
    `acyclic_has_solution` (271) consumes the LIST condition — every LISTED
    transition decreases.  The list form is strictly stronger: a branch whose
    guard is covered by earlier guards never wins a first match, so it may point
    anywhere at all without making the automaton cyclic.

    So the two halves do not compose, and the gap is real rather than
    bureaucratic: after a quotient, dead branches are exactly what one expects
    to find.

    **The join.**  A dead branch cannot be pruned constructively — deciding
    whether a guard is ever reached first is not a computation available here —
    but it does not need to be.  `solFuel` still builds the right expression;
    what fails is `solFuel_stable`, which asked for SYNTACTIC equality of two
    fuel levels and gets it only when every listed target is smaller.  Replace
    it by EquivBA-stability, proved by selection: two fuel levels agree at every
    world because at every world only a LIVE branch is selected, and live
    branches do decrease.  Dead branches are carried along, differing
    syntactically and observed by nothing.

    That is 233's lemma doing the work it was built for — `guardedFold` is
    compared by what it SELECTS, never by what it lists — and it turns the
    weaker hypothesis into the same conclusion. -/
theorem firstMatch_none_of_rank_zero {S : Type}
    (sys : GkatThompson.GSystem S A T) (rank : S → Nat)
    (hstep : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → rank r.2 < rank s)
    (s : S) (hz : rank s = 0) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatKleene.firstMatch W x (sys.trans s) = none := by
  intro X W x
  cases hfm : GkatKleene.firstMatch W x (sys.trans s) with
  | none => rfl
  | some r =>
      exact absurd (hstep s X W x r hfm) (by rw [hz]; exact Nat.not_lt_zero _)

/-- A state no step can leave solves to its halt test alone — whatever its
    transition list happens to contain. -/
theorem solFuel_none {S : Type} (sys : GkatThompson.GSystem S A T) (s : S)
    (hnone : ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatKleene.firstMatch W x (sys.trans s) = none)
    (sol : S → Exp A T) :
    EquivBA (guardedFold (transitionBranches (sys.trans s) sol)
      (.test (sys.hlt s))) (.test (sys.hlt s)) := by
  refine guardedFold_select_congr _ [] _ (.test (sys.hlt s)) ?_
  intro X W x
  rw [selectFull_transitionBranches W x sol (sys.hlt s), hnone X W x]
  exact EquivBA.base (Equiv.refl _)

/-- Two labellings that agree on every LIVE target give equivalent folds.  Dead
    branches may disagree freely. -/
theorem solFuel_congr_step {S : Type} (sys : GkatThompson.GSystem S A T) (s : S)
    (sol sol' : S → Exp A T)
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → EquivBA (sol r.2) (sol' r.2)) :
    EquivBA (guardedFold (transitionBranches (sys.trans s) sol) (.test (sys.hlt s)))
      (guardedFold (transitionBranches (sys.trans s) sol') (.test (sys.hlt s))) := by
  refine guardedFold_select_congr _ _ _ _ ?_
  intro X W x
  rw [selectFull_transitionBranches W x sol (sys.hlt s),
    selectFull_transitionBranches W x sol' (sys.hlt s)]
  cases hfm : GkatKleene.firstMatch W x (sys.trans s) with
  | none => exact EquivBA.base (Equiv.refl _)
  | some r => exact EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (h X W x r hfm)

/-- **EquivBA-STABILITY OF THE FUELLED SOLUTION**, under the FIRSTMATCH rank
    condition.  271's `solFuel_stable` gave syntactic equality and needed every
    LISTED target to be smaller; this gives equivalence and needs it only of
    targets a world can actually reach. -/
theorem solFuel_stable_sem {S : Type} (sys : GkatThompson.GSystem S A T)
    (rank : S → Nat)
    (hstep : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → rank r.2 < rank s) :
    ∀ (n m : Nat) (s : S), rank s ≤ n → rank s ≤ m →
      EquivBA (solFuel sys n s) (solFuel sys m s) := by
  intro n
  induction n with
  | zero =>
      intro m s hn _
      have hnone := firstMatch_none_of_rank_zero sys rank hstep s (Nat.le_zero.mp hn)
      cases m with
      | zero => exact EquivBA.base (Equiv.refl _)
      | succ m' => exact EquivBA.symm (solFuel_none sys s hnone (solFuel sys m'))
  | succ n ih =>
      intro m s hn hm
      cases m with
      | zero =>
          have hnone := firstMatch_none_of_rank_zero sys rank hstep s (Nat.le_zero.mp hm)
          exact solFuel_none sys s hnone (solFuel sys n)
      | succ m' =>
          refine solFuel_congr_step sys s (solFuel sys n) (solFuel sys m') ?_
          intro X W x r hfm
          have hr := hstep s X W x r hfm
          exact ih m' r.2 (Nat.le_of_lt_succ (Nat.lt_of_lt_of_le hr hn))
            (Nat.le_of_lt_succ (Nat.lt_of_lt_of_le hr hm))

/-- **`hsolve`'s ACYCLIC CASE, FROM THE HYPOTHESIS `hcollapse` ACTUALLY
    SUPPLIES.**  The two halves now compose. -/
theorem acyclic_has_solution_sem {S : Type} (sys : GkatThompson.GSystem S A T)
    (rank : S → Nat)
    (hstep : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → rank r.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s, EquivBA (sol s)
      (guardedFold (transitionBranches (sys.trans s) sol) (.test (sys.hlt s))) := by
  refine ⟨fun s => solFuel sys (rank s) s, ?_⟩
  intro s
  show EquivBA (solFuel sys (rank s) s)
    (guardedFold (transitionBranches (sys.trans s) (fun t => solFuel sys (rank t) t))
      (.test (sys.hlt s)))
  cases hr : rank s with
  | zero =>
      have hnone := firstMatch_none_of_rank_zero sys rank hstep s hr
      exact EquivBA.symm (solFuel_none sys s hnone _)
  | succ k =>
      refine solFuel_congr_step sys s (solFuel sys k)
        (fun t => solFuel sys (rank t) t) ?_
      intro X W x r hfm
      have hlt := hstep s X W x r hfm
      rw [hr] at hlt
      exact solFuel_stable_sem sys rank hstep k (rank r.2) r.2
        (Nat.le_of_lt_succ hlt) (Nat.le_refl _)

#print axioms acyclic_has_solution_sem


/-! ### 284 — `hsolve`'s LAYER CASE.  IT NEEDS W1, NOT W3.

    The fixpoint 276 pointed at, resolved.  Given a loop layer over a base that
    already has a standard solution `std`, put

        D   := the ENTRY DISPATCH,  `guardedFold (transitionBranches entry std) 0`
        W   := `wh b D`
        sol := `fun s => std s ; W`

    and `sol` solves `sys`.  The chain is three steps:

      1. `layer_subsystem` (277) turns `sys`'s equation at `s` into `base`'s
         equation at the finish `E`, where `E` is the entry fold under `sol`;
      2. `E ≈ W`, by gating (`ite_guardedFold_partition`), by distributing the
         trailing `W` out of the entry fold, and then by **W1** — the loop's own
         UNFOLDING law;
      3. `StandardSolvesBA.withContinuation` closes it: `base`'s standard
         solution times any finish solves `base` at that finish, and here the
         finish is `W`.

    **Only W1 is used.**  This is worth stating plainly, because the whole
    programme is about eliminating a loop axiom.  W3 — the Salomaa rule, the
    one restricted to a single unknown — is a UNIQUENESS principle, and
    uniqueness is what the certificate already supplies.  EXISTENCE needs only
    that a loop unfolds, and `W` is not FOUND by solving a fixpoint equation, it
    is BUILT and then checked.  The knot ties itself. -/
private theorem selectFull_map_label {X : Type} (W : T → X → Bool) (x : X)
    (F : Exp A T → Exp A T) (fb : Exp A T) :
    ∀ B : List (BExp T × Exp A T),
      selectFull W x (B.map (fun br => (br.1, F br.2))) (F fb)
        = F (selectFull W x B fb)
  | [] => rfl
  | br :: tl => by
      cases hb : GkatGS.bval W br.1 x
      · simp only [List.map_cons, selectFull, hb]
        exact selectFull_map_label W x F fb tl
      · simp only [List.map_cons, selectFull, hb]

/-- A trailing continuation distributes out of an entry fold. -/
theorem entryFold_seq {S : Type} (L : List (BExp T × A × S))
    (sol : S → Exp A T) (g : Exp A T) :
    EquivBA
      (guardedFold (transitionBranches L (fun t => .seq (sol t) g)) (.test .zero))
      (.seq (guardedFold (transitionBranches L sol) (.test .zero)) g) := by
  refine EquivBA.trans ?_
    (EquivBA.symm (guardedFold_seq_right g (transitionBranches L sol) (.test .zero)))
  refine guardedFold_select_congr _ _ _ _ ?_
  intro X W x
  rw [selectFull_transitionBranches W x (fun t => Exp.seq (sol t) g) BExp.zero,
    selectFull_map_label W x (fun e => Exp.seq e g) (.test .zero),
    selectFull_transitionBranches W x sol BExp.zero]
  cases GkatKleene.firstMatch W x L with
  | none => exact EquivBA.symm (EquivBA.base (Equiv.s2 g))
  | some qt =>
      exact EquivBA.symm (EquivBA.base (Equiv.s1 (.act qt.1) (sol qt.2) g))

/-- The `¬b` fallback of a gated entry block, as a conditional. -/
private theorem notb_fallback (b : BExp T) :
    EquivBA (A := A) (GkatThompson.paramFallback (BExp.not b) (.test .one))
      (.ite b (.test .zero) (.test .one)) := by
  show EquivBA (Exp.seq (Exp.test (BExp.not b)) (Exp.test BExp.one)) _
  exact EquivBA.trans (GkatGuardedAlgebra.seq_one (.test (.not b)))
    (EquivBA.trans (test_eq_ite_one_zero (.not b))
      (EquivBA.symm (EquivBA.base (Equiv.u2 b (.test .zero) (.test .one)))))

/-- **`hsolve`'s LAYER CASE.**  A loop layer over a solved base is solved, by
    the base's standard solution followed by the loop the layer names.  `D` is
    the ENTRY DISPATCH and `W` the loop built on it; both are supplied rather
    than inlined, so the statement reads as the construction it is. -/
theorem loopLayer_has_solution {S : Type}
    {sys base : GkatThompson.GSystem S A T} {b : BExp T}
    {entry : List (BExp T × A × S)} (h : LoopLayer sys base b entry)
    (std : S → Exp A T)
    (hstd : ∀ s ∈ base.states, EquivBA (std s)
      (GkatThompson.eqRHSParam base std (.test .one) s))
    (D W : Exp A T)
    (hD : D = guardedFold (transitionBranches entry std) (.test .zero))
    (hW : W = .wh b D) :
    ∀ s ∈ sys.states, EquivBA (.seq (std s) W)
      (GkatThompson.eqRHSParam sys (fun t => .seq (std t) W) (.test .one) s) := by
  intro s hs
  have hEW : EquivBA
      (guardedFold
        (transitionBranches (entry.map (fun tr => (BExp.and b tr.1, tr.2)))
          (fun t => Exp.seq (std t) W))
        (GkatThompson.paramFallback (BExp.not b) (.test .one))) W := by
    rw [transitionBranches_gate]
    refine EquivBA.trans (guardedFold_fallback_congr (notb_fallback b)) ?_
    have hpart : EquivBA
        (Exp.ite b (guardedFold
            (transitionBranches entry (fun t => Exp.seq (std t) W)) (.test .zero))
          (Exp.test BExp.one))
        (guardedFold
          ((transitionBranches entry (fun t => Exp.seq (std t) W)).map
            (fun br => (BExp.and b br.1, br.2)))
          (Exp.ite b (.test .zero) (.test .one))) := by
      have hp := ite_guardedFold_partition b
        (transitionBranches entry (fun t => Exp.seq (std t) W)) []
        (Exp.test BExp.zero) (Exp.test BExp.one)
      simpa only [List.map_nil, List.append_nil] using hp
    refine EquivBA.trans (EquivBA.symm hpart) ?_
    refine EquivBA.trans (EquivBA.ite_c (entryFold_seq entry std W)
      (EquivBA.base (Equiv.refl _))) ?_
    rw [← hD, hW]
    exact EquivBA.symm (EquivBA.base (Equiv.w1 b D))
  refine EquivBA.symm (EquivBA.trans
    (layer_subsystem (fun t => Exp.seq (std t) W) (.test .one) s entry
      (h.trans_eq s) (h.hlt_eq s)) ?_)
  refine EquivBA.trans (guardedFold_fallback_congr
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hEW)) ?_
  exact EquivBA.symm (GkatThompson.StandardSolvesBA.withContinuation
    ⟨base, .one, []⟩ std hstd W s (h.states_eq ▸ hs))

#print axioms loopLayer_has_solution


/-! ### 285 — `hsolve`, CLOSED.

    Both cases are now proved from the hypotheses the other obligation actually
    supplies — acyclic by 283 (firstMatch form, dead branches and all), loop by
    284 — so the induction closes.  Note the shape: `loopLayer_has_solution`
    consumes a solution of `base` at finish `1` and produces a solution of `sys`
    at finish `1`.  Input and output are the same predicate, which is what makes
    the recursion go through without a separate parametric invariant. -/
inductive LayeredL : {S : Type} → GkatThompson.GSystem S A T → Prop where
  | acyclic {S : Type} {sys : GkatThompson.GSystem S A T} :
      (∃ rank : S → Nat, ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
        GkatKleene.firstMatch W x (sys.trans s) = some r → rank r.2 < rank s) →
      LayeredL sys
  | loop {S : Type} {sys base : GkatThompson.GSystem S A T} {b : BExp T}
      {entry : List (BExp T × A × S)} :
      LoopLayer sys base b entry → LayeredL base → LayeredL sys
  | sum {S₁ S₂ : Type} {L : GkatThompson.GSystem S₁ A T}
      {R : GkatThompson.GSystem S₂ A T} :
      LayeredL L → LayeredL R → LayeredL (GkatThompson.sumGSystem L R)
  | seq {S₁ S₂ : Type} {L : GkatThompson.GSystem S₁ A T}
      {R : GkatThompson.InitializedGAut S₂ A T} :
      LayeredL L → LayeredL R.core → LayeredL (GkatThompson.seqGSystem L R)

/-- The right half of a sequence is untouched by the construction, so its
    equations are its own — the same fact `sum_subsystem_inr` states, and
    definitionally the same proof. -/
theorem seq_subsystem_inr {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T)
    (R : GkatThompson.InitializedGAut S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (F : Exp A T) (s : S₂) :
    GkatThompson.eqRHSParam (GkatThompson.seqGSystem L R) sol F (.inr s)
      = GkatThompson.eqRHSParam R.core (fun t => sol (.inr t)) F s :=
  sum_subsystem_inr L R.core sol F s

/-- **EVERY LAYERED AUTOMATON HAS A SOLUTION.**  `hsolve`, for the predicate
    283, 284 and 282 were built to consume.  The four cases use, in order:
    283 (acyclic, in the firstMatch form a bisimulation can supply), 284 (the
    loop, needing only W1), and 282's composition for the two lifts — where the
    ambient continuation is exactly `withContinuation`'s parameter. -/
theorem layeredL_has_solution : ∀ {S : Type} {sys : GkatThompson.GSystem S A T},
    LayeredL sys → ∃ std : S → Exp A T, ∀ s ∈ sys.states,
      EquivBA (std s) (GkatThompson.eqRHSParam sys std (.test .one) s) := by
  intro S sys h
  induction h with
  | @acyclic S sys hr =>
      obtain ⟨rank, hrank⟩ := hr
      obtain ⟨sol, hsol⟩ := acyclic_has_solution_sem sys rank hrank
      refine ⟨sol, fun s _ => EquivBA.trans (hsol s) ?_⟩
      exact guardedFold_fallback_congr
        (EquivBA.symm (GkatGuardedAlgebra.seq_one (.test (sys.hlt s))))
  | @loop S sys base b entry hlay _ ih =>
      obtain ⟨std, hstd⟩ := ih
      exact ⟨fun t => .seq (std t)
          (.wh b (guardedFold (transitionBranches entry std) (.test .zero))),
        loopLayer_has_solution hlay std hstd _ _ rfl rfl⟩
  | @sum S₁ S₂ L R _ _ ihL ihR =>
      obtain ⟨stdL, hL⟩ := ihL
      obtain ⟨stdR, hR⟩ := ihR
      refine ⟨fun x => match x with | .inl t => stdL t | .inr t => stdR t, ?_⟩
      intro x hs
      cases x with
      | inl s =>
          rw [sum_subsystem_inl]
          exact hL s (sum_states_inl hs)
      | inr s =>
          rw [sum_subsystem_inr]
          exact hR s (sum_states_inr hs)
  | @seq S₁ S₂ L R _ _ ihL ihR =>
      obtain ⟨stdL, hL⟩ := ihL
      obtain ⟨stdR, hR⟩ := ihR
      refine ⟨fun x => match x with
        | .inl t => .seq (stdL t) (GkatThompson.initRHSParam R stdR (.test .one))
        | .inr t => stdR t, ?_⟩
      intro x hs
      cases x with
      | inl s =>
          refine EquivBA.trans ?_
            (EquivBA.symm (seq_subsystem L R _ (.test .one) s))
          exact GkatThompson.StandardSolvesBA.withContinuation ⟨L, .one, []⟩ stdL hL
            _ s (seq_states_inl hs)
      | inr s =>
          rw [seq_subsystem_inr]
          exact hR s (seq_states_inr hs)

/-- **`hsum` FOR `LayeredL`: every Thompson automaton is layered.**  One
    constructor per syntactic form, and every case is definitional or 279. -/
theorem thompson_layeredL : ∀ e : Exp A T,
    LayeredL (GkatThompson.certifiedThompson A T e).aut.core
  | .test _ => LayeredL.acyclic ⟨fun s => (nomatch s : Nat), fun s => nomatch s⟩
  | .act _ => LayeredL.acyclic ⟨fun _ => 0, by
      intro s X W x r hfm
      cases hfm⟩
  | .ite _ e f => LayeredL.sum (thompson_layeredL e) (thompson_layeredL f)
  | .seq e f => LayeredL.seq (thompson_layeredL e) (thompson_layeredL f)
  | .wh b e => LayeredL.loop (wh_loopLayer b e) (thompson_layeredL e)

#print axioms thompson_layeredL

/-- **THE REMAINDER, IN ONE STATEMENT.**  `hsum` and `hsolve` now meet: every
    Thompson automaton is `LayeredL` (285), and every `LayeredL` automaton has a
    solution (285).  So the ONLY thing still wanted is that the QUOTIENT is
    `LayeredL` — and `loopLayer_pushforward_rep` (281) and `acyclic_quotient`
    (264) are its two cases. -/
theorem thompson_has_solution_via_layers (e : Exp A T) :
    ∃ std : (GkatThompson.certifiedThompson A T e).State → Exp A T,
      ∀ s ∈ (GkatThompson.certifiedThompson A T e).aut.core.states,
        EquivBA (std s) (GkatThompson.eqRHSParam
          (GkatThompson.certifiedThompson A T e).aut.core std (.test .one) s) :=
  layeredL_has_solution (thompson_layeredL e)

#print axioms thompson_has_solution_via_layers

#print axioms layeredL_has_solution


/-! ### 287 — WHAT A QUOTIENT DOES TO `sum` AND `seq`

    286 left one statement open — the quotient is `LayeredL` — and named the
    `sum`/`seq` constructors as the hard part.  They are hard for a concrete
    reason: **the quotient of a sum is not a sum of quotients.**  In the
    architecture the whole POINT of the sum is that the two expressions' start
    states are bisimilar, so the collapse merges ACROSS the halves and the
    partition into `inl`/`inr` is destroyed.

    But it is not destroyed symmetrically, and that is the opening.  Choose
    representatives that PREFER one block.  Then:

      * a class containing a member of the preferred block gets a representative
        IN that block;
      * so if the block was closed under transitions upstairs, the classes with
        a representative in it are closed downstairs.

    So a quotient turns a two-block automaton into a two-block automaton — with
    one block closed and the other feeding into it — even though it does not
    turn a SUM into a sum.  That is exactly the structure `sum` and `seq`
    already have: `sum_inr_closed` and `seq_inr_closed` (both proved) say the
    right half is closed, and nothing else about either constructor is used by
    `layeredL_has_solution` beyond the equations that closure justifies.

    This is the general fact, and it needs neither `hrep` nor minimality — only
    that the representative choice prefers the block. -/
theorem quotient_closed_block {S Q : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop)
    (hclosed : ∀ s, P s → ∀ tr ∈ sys.trans s, P tr.2.2)
    (q : S → Q) (rep : Q → S)
    (hpref : ∀ (c : Q) (t : S), q t = c → P t → P (rep c))
    (Qsys : GkatThompson.GSystem Q A T)
    (htrans : ∀ c, Qsys.trans c = (sys.trans (rep c)).map
      (fun tr => (tr.1, tr.2.1, q tr.2.2))) :
    ∀ c : Q, P (rep c) → ∀ tr ∈ Qsys.trans c, P (rep tr.2.2) := by
  intro c hc tr htr
  rw [htrans] at htr
  simp only [List.mem_map] at htr
  obtain ⟨tr₀, htr₀, rfl⟩ := htr
  exact hpref (q tr₀.2.2) tr₀.2.2 rfl (hclosed (rep c) hc tr₀ htr₀)

section PreferringRep
open Classical

/-- A preferring representative choice EXISTS whenever the block is decidable —
    take a member of the block if the class has one, and anything otherwise.
    Stated with `Classical.choice`, so no decidability is actually needed. -/
noncomputable def preferringRep {S Q : Type} (P : S → Prop)
    (q : S → Q) (rep₀ : Q → S) : Q → S :=
  fun c => if h : ∃ t, q t = c ∧ P t then Classical.choose h else rep₀ c

theorem preferringRep_prefers {S Q : Type} (P : S → Prop)
    (q : S → Q) (rep₀ : Q → S) :
    ∀ (c : Q) (t : S), q t = c → P t → P (preferringRep P q rep₀ c) := by
  intro c t hq hP
  have hex : ∃ t, q t = c ∧ P t := ⟨t, hq, hP⟩
  show P (if h : ∃ t, q t = c ∧ P t then Classical.choose h else rep₀ c)
  rw [dif_pos hex]
  exact (Classical.choose_spec hex).2

/-- And it is still a section, on classes that have a member of the block. -/
theorem preferringRep_section {S Q : Type} (P : S → Prop)
    (q : S → Q) (rep₀ : Q → S) (hrep₀ : ∀ c, q (rep₀ c) = c) :
    ∀ c : Q, q (preferringRep P q rep₀ c) = c := by
  intro c
  show q (if h : ∃ t, q t = c ∧ P t then Classical.choose h else rep₀ c) = c
  by_cases hex : ∃ t, q t = c ∧ P t
  · rw [dif_pos hex]
    exact (Classical.choose_spec hex).1
  · rw [dif_neg hex]
    exact hrep₀ c

#print axioms quotient_closed_block
#print axioms preferringRep_prefers
#print axioms preferringRep_section

end PreferringRep


/-! ### 288 — SOLVING OUTSIDE A CLOSED BLOCK

    287's `split` needs to solve a block that is NOT an automaton on its own:
    its transitions leave into the closed block, so the single trailing `finish`
    that `eqRHSParam` carries cannot express what happens at the boundary.  Each
    outgoing transition needs its OWN continuation — the closed block's already
    known solution at that target.

    The generalisation turns out not to need new algebra, only a new SEED.
    `solFuel` (271) starts from the halt test; `solExt` starts from a supplied
    `sol₀` on the block and the halt test off it, and never touches the block
    again.  A boundary transition is then handled by the recursion itself: its
    target is in the block, so every fuel level returns the SAME expression
    there, and stability sees no difference at all.

    The rank condition weakens accordingly: a step out of the block-complement
    must either LAND IN THE BLOCK — in which case nothing more is asked of it —
    or decrease.  That is the honest content of "the complement is acyclic
    RELATIVE to the block".

    One subtlety, and it is what forces `rank s < n` rather than `rank s ≤ n`
    in the stability statement: a state of rank `0` may still step INTO the
    block, so fuel `0` is not enough to unfold it.  Every state needs one level
    of fuel more than its rank, and the base case then becomes vacuous. -/
open Classical in
noncomputable def solExt {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) : Nat → S → Exp A T
  | 0, s => if P s then sol₀ s else .test (sys.hlt s)
  | n + 1, s => if P s then sol₀ s else
      guardedFold (transitionBranches (sys.trans s) (solExt sys P sol₀ n))
        (.test (sys.hlt s))

open Classical in
theorem solExt_block {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (n : Nat) (s : S) (hs : P s) :
    solExt sys P sol₀ n s = sol₀ s := by
  cases n with
  | zero => show (if P s then sol₀ s else _) = _; rw [if_pos hs]
  | succ n => show (if P s then sol₀ s else _) = _; rw [if_pos hs]

open Classical in
theorem solExt_out {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (n : Nat) (s : S) (hs : ¬ P s) :
    solExt sys P sol₀ (n + 1) s
      = guardedFold (transitionBranches (sys.trans s) (solExt sys P sol₀ n))
          (.test (sys.hlt s)) := by
  show (if P s then sol₀ s else _) = _
  rw [if_neg hs]

/-- **STABILITY, RELATIVE TO A BLOCK.** -/
theorem solExt_stable {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s) :
    ∀ (n m : Nat) (s : S), rank s < n → rank s < m →
      EquivBA (solExt sys P sol₀ n s) (solExt sys P sol₀ m s) := by
  intro n
  induction n with
  | zero => intro m s hn _; exact absurd hn (Nat.not_lt_zero _)
  | succ k ih =>
      intro m s hn hm
      cases m with
      | zero => exact absurd hm (Nat.not_lt_zero _)
      | succ j =>
          by_cases hP : P s
          · rw [solExt_block sys P sol₀ _ s hP, solExt_block sys P sol₀ _ s hP]
            exact EquivBA.base (Equiv.refl _)
          · rw [solExt_out sys P sol₀ k s hP, solExt_out sys P sol₀ j s hP]
            refine solFuel_congr_step sys s _ _ ?_
            intro X W x r hfm
            rcases hstep s hP X W x r hfm with hPr | hlt
            · rw [solExt_block sys P sol₀ _ r.2 hPr,
                solExt_block sys P sol₀ _ r.2 hPr]
              exact EquivBA.base (Equiv.refl _)
            · exact ih j r.2 (Nat.lt_of_lt_of_le hlt (Nat.le_of_lt_succ hn))
                (Nat.lt_of_lt_of_le hlt (Nat.le_of_lt_succ hm))

/-- **THE EXTENSION.**  A solution on a closed block extends to one on the whole
    system, as soon as the complement is acyclic RELATIVE to the block. -/
theorem solExt_has_solution {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s) :
    ∃ sol : S → Exp A T,
      (∀ s, P s → sol s = sol₀ s) ∧
      (∀ s, ¬ P s → EquivBA (sol s)
        (guardedFold (transitionBranches (sys.trans s) sol) (.test (sys.hlt s)))) := by
  refine ⟨fun s => solExt sys P sol₀ (rank s + 1) s, ?_, ?_⟩
  · intro s hs
    exact solExt_block sys P sol₀ _ s hs
  · intro s hs
    show EquivBA (solExt sys P sol₀ (rank s + 1) s) _
    rw [solExt_out sys P sol₀ (rank s) s hs]
    refine solFuel_congr_step sys s _ _ ?_
    intro X W x r hfm
    rcases hstep s hs X W x r hfm with hPr | hlt
    · rw [solExt_block sys P sol₀ _ r.2 hPr, solExt_block sys P sol₀ _ r.2 hPr]
      exact EquivBA.base (Equiv.refl _)
    · exact solExt_stable sys P sol₀ rank hstep (rank s) (rank r.2 + 1) r.2
        hlt (Nat.lt_succ_self _)

/-- **A CLOSED BLOCK SOLVED, PLUS A RELATIVELY ACYCLIC COMPLEMENT, SOLVES THE
    WHOLE SYSTEM.**  The block's own equations survive because the block is
    CLOSED: they mention no state outside it, and the extension changes nothing
    inside. -/
theorem split_acyclic_has_solution {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop)
    (hclosed : ∀ s, P s → ∀ tr ∈ sys.trans s, P tr.2.2)
    (sol₀ : S → Exp A T)
    (h₀ : ∀ s ∈ sys.states, P s → EquivBA (sol₀ s)
      (GkatThompson.eqRHSParam sys sol₀ (.test .one) s))
    (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ sys.states,
      EquivBA (sol s) (GkatThompson.eqRHSParam sys sol (.test .one) s) := by
  obtain ⟨sol, hin, hout⟩ := solExt_has_solution sys P sol₀ rank hstep
  refine ⟨sol, fun s hsmem => ?_⟩
  by_cases hP : P s
  · rw [hin s hP]
    refine EquivBA.trans (h₀ s hsmem hP) ?_
    show EquivBA (guardedFold (transitionBranches (sys.trans s) sol₀) _)
      (guardedFold (transitionBranches (sys.trans s) sol) _)
    rw [guardedFold_trans_congr _ sol₀ sol (sys.trans s)
      (fun tr htr => (hin tr.2.2 (hclosed s hP tr htr)).symm)]
    exact EquivBA.base (Equiv.refl _)
  · refine EquivBA.trans (hout s hP) ?_
    exact guardedFold_fallback_congr
      (EquivBA.symm (GkatGuardedAlgebra.seq_one (.test (sys.hlt s))))

#print axioms solExt_has_solution
#print axioms split_acyclic_has_solution


/-! ### 289 — A SEQUENCE IS A LAYER TOO

    286 and 287 called the `seq` constructor the hard case for the quotient.
    Looking at what `seqGSystem` actually DOES to a left state:

        sys.trans s = base.trans s ++ (R's ENTRY block, gated by `base.hlt s`)

    — which is, letter for letter, `LoopLayer`'s shape.  **A sequence and a loop
    are the same construction.**  Both append ONE SHARED entry list to every
    state of a region, gated by that state's own halt.  They differ in exactly
    two places: the loop's entry block carries the loop guard `b` and targets
    the region itself, while the sequence's carries nothing and targets a CLOSED
    BLOCK; and the loop's halt becomes `base.hlt ∧ ¬b` where the sequence's
    becomes `base.hlt ∧ R.initHlt`.

    That is worth having, because everything 279-281 proved about loop layers
    was proved about the SHAPE, not about the loop.  In particular the
    pushforward: the base downstairs is built from representatives, and the
    entry block — being shared and of fixed length — pins the cut.  So the
    sequence constructor pushes through a quotient by the same argument, and the
    case 286 called hard is the case already solved.

    `base` for a sequence is the DISJOINT UNION of its two halves:
    `sumGSystem L R.core`, the sequence with its connecting block removed.  So
    removing a `seq` layer leaves a `sum`, which is what makes the recursion
    terminate. -/
structure SeqLayer {S : Type} (sys base : GkatThompson.GSystem S A T)
    (h₀ : BExp T) (entry : List (BExp T × A × S)) (dom : S → Prop) : Prop where
  trans_eq : ∀ s, dom s → sys.trans s = base.trans s ++ entry.map (fun tr =>
    (BExp.and (base.hlt s) tr.1, tr.2))
  hlt_eq : ∀ s, dom s → sys.hlt s = BExp.and (base.hlt s) h₀
  outside : ∀ s, ¬ dom s → sys.trans s = base.trans s ∧ sys.hlt s = base.hlt s
  states_eq : sys.states = base.states

/-- **A SEQUENCE IS A LAYER OVER THE DISJOINT UNION OF ITS HALVES.**  Entry list
    the right half's own initial transitions, injected; guard-free; domain the
    left half.  Every field is `rfl` or one `List.map_map`. -/
theorem seq_seqLayer {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T) :
    SeqLayer (GkatThompson.seqGSystem L R)
      (GkatThompson.sumGSystem L R.core) R.initHlt
      (R.initTrans.map (fun tr => (tr.1, tr.2.1, Sum.inr tr.2.2)))
      (fun x => match x with | .inl _ => True | .inr _ => False) where
  trans_eq
    | .inl s, _ => by
        show (L.trans s).map _ ++ _ = (L.trans s).map _ ++ _
        simp only [List.map_map, Function.comp_def, GkatThompson.sumGSystem]
    | .inr _, hs => absurd hs (by simp)
  hlt_eq
    | .inl _, _ => rfl
    | .inr _, hs => absurd hs (by simp)
  outside
    | .inl _, hs => absurd trivial hs
    | .inr _, _ => ⟨rfl, rfl⟩
  states_eq := rfl

/-- **AND IT PUSHES FORWARD**, by 281's argument verbatim: the base downstairs
    is built from representatives, and the shared entry block pins the cut. -/
theorem seqLayer_pushforward_rep {S S' : Type}
    {sys base : GkatThompson.GSystem S A T} {h₀ : BExp T}
    {entry : List (BExp T × A × S)} {dom : S → Prop}
    (h : SeqLayer sys base h₀ entry dom)
    (f : S → S') (hsurj : ∀ s' : S', ∃ s, f s = s')
    (sys' : GkatThompson.GSystem S' A T)
    (htrans : ∀ s' : S', sys'.trans s'
      = (sys.trans (Classical.choose (hsurj s'))).map
          (fun tr => (tr.1, tr.2.1, f tr.2.2)))
    (hhlt : ∀ s' : S', sys'.hlt s' = sys.hlt (Classical.choose (hsurj s'))) :
    SeqLayer sys' (pushBase f hsurj base sys') h₀
      (entry.map (fun tr => (tr.1, tr.2.1, f tr.2.2)))
      (fun s' => dom (Classical.choose (hsurj s'))) where
  trans_eq s' hs := by
    simp only [pushBase]
    rw [htrans s', h.trans_eq (Classical.choose (hsurj s')) hs, List.map_append]
    congr 1
    simp only [List.map_map, Function.comp_def]
  hlt_eq s' hs := by
    simp only [pushBase]
    rw [hhlt s', h.hlt_eq (Classical.choose (hsurj s')) hs]
  outside s' hs := by
    obtain ⟨ht, hh⟩ := h.outside (Classical.choose (hsurj s')) hs
    exact ⟨by simp only [pushBase]; rw [htrans s', ht],
      by simp only [pushBase]; rw [hhlt s', hh]⟩
  states_eq := rfl

#print axioms seq_seqLayer
#print axioms seqLayer_pushforward_rep


/-! ### 290 — THE SUM'S QUOTIENT, END TO END (RELATIVELY ACYCLIC COMPLEMENT)

    287 and 288 are the two halves of the `sum` case and were proved separately.
    Here they meet.  Take a quotient of `sumGSystem L R` whose representatives
    PREFER the left half.  Then:

      * the classes with a left representative form a CLOSED block (287), because
        `inl` is closed upstairs and the preference transports that;
      * a solution on the block extends over the complement (288), as soon as
        the complement is acyclic RELATIVE to the block.

    So the quotient is solvable.  This is the first end-to-end statement about
    the collapse in the whole series: quotient in, solution out, no hypothesis
    about the quotient beyond how its dynamics is read off representatives.

    **The restriction, and it is the honest one.**  The complement must be
    RELATIVELY ACYCLIC.  A loop in the complement is not covered, and cannot be
    by simply relativising `loopLayer_has_solution`: 284's construction needs
    the base's solutions to have the form `std s ; W`, and a state whose run can
    EXIT into the block does not have that form — the exit branch carries no
    `W`.  That is not an artifact.  In a Thompson automaton a loop's body never
    escapes except through the halt-gate, which is exactly why `LoopLayer` is
    TOTAL; a collapse that merges a loop-body state with an outside state can
    destroy that, and it is precisely the failure the literature records for
    LLEE with empty-step transitions.  **The relatively-acyclic complement is
    the case where no such merge has happened.** -/
theorem sum_quotient_has_solution {S₁ S₂ Q : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (q : Sum S₁ S₂ → Q) (rep : Q → Sum S₁ S₂)
    (hpref : ∀ (c : Q) (t : Sum S₁ S₂), q t = c → (∃ u, t = .inl u) →
      ∃ u, rep c = .inl u)
    (sys' : GkatThompson.GSystem Q A T)
    (htrans : ∀ c, sys'.trans c = ((GkatThompson.sumGSystem L R).trans (rep c)).map
      (fun tr => (tr.1, tr.2.1, q tr.2.2)))
    (sol₀ : Q → Exp A T)
    (h₀ : ∀ c ∈ sys'.states, (∃ u, rep c = .inl u) →
      EquivBA (sol₀ c) (GkatThompson.eqRHSParam sys' sol₀ (.test .one) c))
    (rank : Q → Nat)
    (hstep : ∀ c, ¬ (∃ u, rep c = .inl u) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × Q),
      GkatKleene.firstMatch W x (sys'.trans c) = some r →
        (∃ u, rep r.2 = .inl u) ∨ rank r.2 < rank c) :
    ∃ sol : Q → Exp A T, ∀ c ∈ sys'.states,
      EquivBA (sol c) (GkatThompson.eqRHSParam sys' sol (.test .one) c) := by
  have hclosedUp : ∀ t : Sum S₁ S₂, (∃ u, t = .inl u) →
      ∀ tr ∈ (GkatThompson.sumGSystem L R).trans t, ∃ u, tr.2.2 = .inl u := by
    intro t ht tr htr
    obtain ⟨u, rfl⟩ := ht
    show ∃ v, tr.2.2 = Sum.inl v
    have : tr ∈ (L.trans u).map (fun x => (x.1, x.2.1, Sum.inl x.2.2)) := htr
    simp only [List.mem_map] at this
    obtain ⟨x, _, rfl⟩ := this
    exact ⟨x.2.2, rfl⟩
  exact split_acyclic_has_solution sys' (fun c => ∃ u, rep c = .inl u)
    (quotient_closed_block (GkatThompson.sumGSystem L R)
      (fun t => ∃ u, t = .inl u) hclosedUp q rep hpref sys' htrans)
    sol₀ h₀ rank hstep

#print axioms sum_quotient_has_solution


/-! ### 291 — `seq_subsystem` FOR AN ABSTRACT SEQUENCE LAYER

    290 restricted the complement to being relatively ACYCLIC and read that as
    the case "no destructive merge has happened".  That reading was too gloomy.
    A loop in the complement is ORDINARY, not pathological: in
    `ite c e f` with `f` containing a loop and `f`'s states unmerged, the
    complement simply contains `f`'s loop.

    What matters is how such a loop EXITS into the block.  It exits the way
    every loop in a Thompson automaton exits — through the halt-gate, into a
    SHARED entry block.  In `seq (wh d g) h` the body's states carry
    `g.hlt ∧ ¬d`-gated transitions into `h`'s entry; after a collapse that puts
    `h` in the block, those are halt-gated shared entry transitions whose
    TARGETS LIE IN THE BLOCK.  That is exactly `SeqLayer`, whose `entry` list is
    unconstrained as to where it points (289).

    So the complement is a `SeqLayer` over something, and removing it leaves the
    loop total again.  What was missing to say so is the equation-level lemma —
    277's `layer_subsystem` for sequences rather than loops.  It is the same
    proof, and it uses the same tool `seq_subsystem` itself uses: parametric
    guard factoring.  The per-state halt conjoined onto every entry transition
    factors out as a test prefix, turning the whole entry block into a FINISH. -/
theorem seqLayer_subsystem {S : Type} {sys base : GkatThompson.GSystem S A T}
    {h₀ : BExp T} {entry : List (BExp T × A × S)} {dom : S → Prop}
    (h : SeqLayer sys base h₀ entry dom)
    (sol : S → Exp A T) (F : Exp A T) (s : S) (hs : dom s) :
    EquivBA (GkatThompson.eqRHSParam sys sol F s)
      (GkatThompson.eqRHSParam base sol
        (guardedFold (transitionBranches entry sol)
          (GkatThompson.paramFallback h₀ F)) s) := by
  have hsplit : transitionBranches (sys.trans s) sol
      = transitionBranches (base.trans s) sol
        ++ (transitionBranches entry sol).map
            (fun br => (BExp.and (base.hlt s) br.1, br.2)) := by
    rw [h.trans_eq s hs]
    simp only [transitionBranches, List.map_append, List.map_map, Function.comp_def]
  show EquivBA (guardedFold (transitionBranches (sys.trans s) sol) _) _
  rw [hsplit, guardedFold_append, h.hlt_eq s hs]
  exact guardedFold_fallback_congr
    (guardedFold_guard_factor (base.hlt s) h₀ F (transitionBranches entry sol))

#print axioms seqLayer_subsystem

/-- **AND IT SPECIALISES BACK TO `seq_subsystem`**, the same check 277 ran for
    the loop: a concrete sequence is an abstract sequence layer over the
    disjoint union of its halves, and reducing through the layer and then
    through the sum reproduces the concrete lemma. -/
theorem seq_subsystem_of_layer {S₁ S₂ : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (F : Exp A T) (s : S₁) :
    EquivBA
      (GkatThompson.eqRHSParam (GkatThompson.seqGSystem L R) sol F (.inl s))
      (GkatThompson.eqRHSParam L (fun t => sol (.inl t))
        (GkatThompson.initRHSParam R (fun t => sol (.inr t)) F) s) := by
  refine EquivBA.trans (seqLayer_subsystem (seq_seqLayer L R) sol F (.inl s) trivial) ?_
  rw [sum_subsystem_inl]
  have : transitionBranches
      (R.initTrans.map (fun tr => (tr.1, tr.2.1, Sum.inr tr.2.2))) sol
      = transitionBranches R.initTrans (fun t => sol (.inr t)) := by
    simp only [transitionBranches, List.map_map, Function.comp_def]
  rw [this]
  exact EquivBA.base (Equiv.refl _)

#print axioms seq_subsystem_of_layer


/-! ### 292 — THE SAME MACHINERY AT AN ARBITRARY FINISH

    The relativised recursion needs its pieces at an ARBITRARY finish, not only
    at `1`.  291's `seqLayer_subsystem` hands the base a finish built from the
    entry block, so whatever solves the base must solve it THERE.

    288's `solExt` was written with the halt test as its leaf.  Generalising it
    to `paramFallback (hlt s) F` needs one thing 283 did not provide: selection
    through `transitionBranches` at an ARBITRARY fallback rather than a test.
    That is the same induction, with the fallback carried instead of fixed. -/
private theorem selectFull_tb_gen {S X : Type} (W : T → X → Bool) (x : X)
    (sol : S → Exp A T) (fb : Exp A T) :
    ∀ L : List (BExp T × A × S),
      selectFull W x (transitionBranches L sol) fb
        = (match GkatKleene.firstMatch W x L with
           | some qt => Exp.seq (.act qt.1) (sol qt.2)
           | none => fb)
  | [] => rfl
  | tr :: tl => by
      obtain ⟨g, a, t⟩ := tr
      cases hb : GkatGS.bval W g x
      · simp only [transitionBranches, List.map_cons, selectFull, hb,
          GkatKleene.firstMatch, if_neg]
        exact selectFull_tb_gen W x sol fb tl
      · simp only [transitionBranches, List.map_cons, selectFull, hb,
          GkatKleene.firstMatch, if_pos]

/-- Two labellings agreeing on every LIVE target give equivalent folds — at any
    fallback.  283's `solFuel_congr_step`, freed of its test. -/
theorem fold_congr_step {S : Type} (sys : GkatThompson.GSystem S A T) (s : S)
    (fb : Exp A T) (sol sol' : S → Exp A T)
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → EquivBA (sol r.2) (sol' r.2)) :
    EquivBA (guardedFold (transitionBranches (sys.trans s) sol) fb)
      (guardedFold (transitionBranches (sys.trans s) sol') fb) := by
  refine guardedFold_select_congr _ _ _ _ ?_
  intro X W x
  rw [selectFull_tb_gen W x sol fb, selectFull_tb_gen W x sol' fb]
  cases hfm : GkatKleene.firstMatch W x (sys.trans s) with
  | none => exact EquivBA.base (Equiv.refl _)
  | some r => exact EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (h X W x r hfm)

open Classical in
noncomputable def solExtF {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (F : Exp A T) : Nat → S → Exp A T
  | 0, s => if P s then sol₀ s else GkatThompson.paramFallback (sys.hlt s) F
  | n + 1, s => if P s then sol₀ s else
      guardedFold (transitionBranches (sys.trans s) (solExtF sys P sol₀ F n))
        (GkatThompson.paramFallback (sys.hlt s) F)

open Classical in
theorem solExtF_block {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (F : Exp A T) (n : Nat) (s : S) (hs : P s) :
    solExtF sys P sol₀ F n s = sol₀ s := by
  cases n with
  | zero => show (if P s then sol₀ s else _) = _; rw [if_pos hs]
  | succ n => show (if P s then sol₀ s else _) = _; rw [if_pos hs]

open Classical in
theorem solExtF_out {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (F : Exp A T) (n : Nat) (s : S) (hs : ¬ P s) :
    solExtF sys P sol₀ F (n + 1) s
      = guardedFold (transitionBranches (sys.trans s) (solExtF sys P sol₀ F n))
          (GkatThompson.paramFallback (sys.hlt s) F) := by
  show (if P s then sol₀ s else _) = _
  rw [if_neg hs]

theorem solExtF_stable {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (F : Exp A T) (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s) :
    ∀ (n m : Nat) (s : S), rank s < n → rank s < m →
      EquivBA (solExtF sys P sol₀ F n s) (solExtF sys P sol₀ F m s) := by
  intro n
  induction n with
  | zero => intro m s hn _; exact absurd hn (Nat.not_lt_zero _)
  | succ k ih =>
      intro m s hn hm
      cases m with
      | zero => exact absurd hm (Nat.not_lt_zero _)
      | succ j =>
          by_cases hP : P s
          · rw [solExtF_block sys P sol₀ F _ s hP, solExtF_block sys P sol₀ F _ s hP]
            exact EquivBA.base (Equiv.refl _)
          · rw [solExtF_out sys P sol₀ F k s hP, solExtF_out sys P sol₀ F j s hP]
            refine fold_congr_step sys s _ _ _ ?_
            intro X W x r hfm
            rcases hstep s hP X W x r hfm with hPr | hlt
            · rw [solExtF_block sys P sol₀ F _ r.2 hPr,
                solExtF_block sys P sol₀ F _ r.2 hPr]
              exact EquivBA.base (Equiv.refl _)
            · exact ih j r.2 (Nat.lt_of_lt_of_le hlt (Nat.le_of_lt_succ hn))
                (Nat.lt_of_lt_of_le hlt (Nat.le_of_lt_succ hm))

/-- **THE EXTENSION, AT AN ARBITRARY FINISH.** -/
theorem solExtF_has_solution {S : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (sol₀ : S → Exp A T) (F : Exp A T) (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s) :
    ∃ sol : S → Exp A T,
      (∀ s, P s → sol s = sol₀ s) ∧
      (∀ s, ¬ P s → EquivBA (sol s)
        (GkatThompson.eqRHSParam sys sol F s)) := by
  refine ⟨fun s => solExtF sys P sol₀ F (rank s + 1) s, ?_, ?_⟩
  · intro s hs
    exact solExtF_block sys P sol₀ F _ s hs
  · intro s hs
    show EquivBA (solExtF sys P sol₀ F (rank s + 1) s) _
    rw [solExtF_out sys P sol₀ F (rank s) s hs]
    refine fold_congr_step sys s _ _ _ ?_
    intro X W x r hfm
    rcases hstep s hs X W x r hfm with hPr | hlt
    · rw [solExtF_block sys P sol₀ F _ r.2 hPr, solExtF_block sys P sol₀ F _ r.2 hPr]
      exact EquivBA.base (Equiv.refl _)
    · exact solExtF_stable sys P sol₀ F rank hstep (rank s) (rank r.2 + 1) r.2
        hlt (Nat.lt_succ_self _)

/-- **A SEQUENCE LAYER EXTENDS A SOLUTION.**  291's reduction, in the form the
    relativised recursion consumes: whatever solves the base at the finish the
    entry block builds, solves the layer at `F`. -/
theorem seqLayer_extends {S : Type} {sys base : GkatThompson.GSystem S A T}
    {h₀ : BExp T} {entry : List (BExp T × A × S)} {dom : S → Prop}
    (h : SeqLayer sys base h₀ entry dom)
    (sol : S → Exp A T) (F : Exp A T)
    (hbase : ∀ s, dom s → EquivBA (sol s)
      (GkatThompson.eqRHSParam base sol
        (guardedFold (transitionBranches entry sol)
          (GkatThompson.paramFallback h₀ F)) s)) :
    ∀ s, dom s → EquivBA (sol s) (GkatThompson.eqRHSParam sys sol F s) :=
  fun s hs => EquivBA.trans (hbase s hs)
    (EquivBA.symm (seqLayer_subsystem h sol F s hs))

#print axioms solExtF_has_solution
#print axioms seqLayer_extends


/-! ### 293 — THE LOOP CASE, RELATIVISED

    The last case of the relativised recursion.  A loop confined to a DOMAIN,
    over a base on which the domain is closed, solves exactly as 284's total
    loop does — the construction never looks outside the domain, because the
    entry list points into it and the base's own transitions stay in it.

    One mechanical obstacle, and its fix is worth recording.  284 finished with
    `StandardSolvesBA.withContinuation`, whose hypothesis quantifies over
    `aut.states` while the relativised hypothesis holds only on the domain.  But
    `withContinuation`'s proof is PER-STATE: it uses the hypothesis at the state
    it is proving about and nowhere else, and `eqRHSParam` reads only `trans`
    and `hlt`, never `states`.  So it can be applied to the system with its
    state list replaced by the SINGLETON `[s]`, which is definitionally the same
    automaton everywhere `eqRHSParam` looks.  A hypothesis over one state is
    exactly what is available. -/
structure LoopLayerOn {S : Type} (sys base : GkatThompson.GSystem S A T)
    (b : BExp T) (entry : List (BExp T × A × S)) (dom : S → Prop) : Prop where
  trans_eq : ∀ s, dom s → sys.trans s = base.trans s ++ entry.map (fun tr =>
    (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2))
  hlt_eq : ∀ s, dom s → ∀ (X : Type) (W : T → X → Bool) (x : X),
    GkatGS.bval W (sys.hlt s) x
      = (GkatGS.bval W (base.hlt s) x && !GkatGS.bval W b x)
  outside : ∀ s, ¬ dom s → sys.trans s = base.trans s ∧ sys.hlt s = base.hlt s
  states_eq : sys.states = base.states

/-- A total loop layer is a loop layer on every state. -/
theorem LoopLayer.toOn {S : Type} {sys base : GkatThompson.GSystem S A T}
    {b : BExp T} {entry : List (BExp T × A × S)} (h : LoopLayer sys base b entry) :
    LoopLayerOn sys base b entry (fun _ => True) where
  trans_eq s _ := h.trans_eq s
  hlt_eq s _ := h.hlt_eq s
  outside _ hs := absurd trivial hs
  states_eq := h.states_eq

/-- **`hsolve`'s LOOP CASE, ON A DOMAIN.** -/
theorem loopLayerOn_has_solution {S : Type}
    {sys base : GkatThompson.GSystem S A T} {b : BExp T}
    {entry : List (BExp T × A × S)} {dom : S → Prop}
    (h : LoopLayerOn sys base b entry dom)
    (std : S → Exp A T)
    (hstd : ∀ s, dom s → EquivBA (std s)
      (GkatThompson.eqRHSParam base std (.test .one) s))
    (D W : Exp A T)
    (hD : D = guardedFold (transitionBranches entry std) (.test .zero))
    (hW : W = .wh b D) :
    ∀ s, dom s → EquivBA (.seq (std s) W)
      (GkatThompson.eqRHSParam sys (fun t => .seq (std t) W) (.test .one) s) := by
  intro s hs
  have hEW : EquivBA
      (guardedFold
        (transitionBranches (entry.map (fun tr => (BExp.and b tr.1, tr.2)))
          (fun t => Exp.seq (std t) W))
        (GkatThompson.paramFallback (BExp.not b) (.test .one))) W := by
    rw [transitionBranches_gate]
    refine EquivBA.trans (guardedFold_fallback_congr (notb_fallback b)) ?_
    have hpart : EquivBA
        (Exp.ite b (guardedFold
            (transitionBranches entry (fun t => Exp.seq (std t) W)) (.test .zero))
          (Exp.test BExp.one))
        (guardedFold
          ((transitionBranches entry (fun t => Exp.seq (std t) W)).map
            (fun br => (BExp.and b br.1, br.2)))
          (Exp.ite b (.test .zero) (.test .one))) := by
      have hp := ite_guardedFold_partition b
        (transitionBranches entry (fun t => Exp.seq (std t) W)) []
        (Exp.test BExp.zero) (Exp.test BExp.one)
      simpa only [List.map_nil, List.append_nil] using hp
    refine EquivBA.trans (EquivBA.symm hpart) ?_
    refine EquivBA.trans (EquivBA.ite_c (entryFold_seq entry std W)
      (EquivBA.base (Equiv.refl _))) ?_
    rw [← hD, hW]
    exact EquivBA.symm (EquivBA.base (Equiv.w1 b D))
  refine EquivBA.symm (EquivBA.trans
    (layer_subsystem (fun t => Exp.seq (std t) W) (.test .one) s entry
      (h.trans_eq s hs) (h.hlt_eq s hs)) ?_)
  refine EquivBA.trans (guardedFold_fallback_congr
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hEW)) ?_
  exact EquivBA.symm (GkatThompson.StandardSolvesBA.withContinuation
    ⟨⟨[s], base.hlt, base.trans⟩, .one, []⟩ std
    (fun t ht => by
      have hts : t = s := by simpa using ht
      subst hts
      exact hstd t hs) W s (by simp))

#print axioms loopLayerOn_has_solution


/-- A state that can neither move nor halt.  Its solution is `0` (323), which is
    why 322's split entry lists are harmless. -/
def StuckAt {S : Type} (sys : GkatThompson.GSystem S A T) (t : S) : Prop :=
  sys.trans t = [] ∧ ∀ (X : Type) (W : T → X → Bool) (x : X),
    GkatGS.bval W (sys.hlt t) x = false

theorem fold_congr_list {S : Type} (l : List (BExp T × A × S)) (fb : Exp A T)
    (solA solB : S → Exp A T)
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x l = some r → EquivBA (solA r.2) (solB r.2)) :
    EquivBA (guardedFold (transitionBranches l solA) fb)
      (guardedFold (transitionBranches l solB) fb) := by
  refine guardedFold_select_congr _ _ _ _ ?_
  intro X W x
  rw [selectFull_tb_gen W x solA fb, selectFull_tb_gen W x solB fb]
  cases hfm : GkatKleene.firstMatch W x l with
  | none => exact EquivBA.base (Equiv.refl _)
  | some r => exact EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (h X W x r hfm)

theorem stuck_solution_zero {S : Type} (sys : GkatThompson.GSystem S A T)
    (sol : S → Exp A T) (F : Exp A T) (t : S)
    (htr : sys.trans t = [])
    (hhl : ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W (sys.hlt t) x = false)
    (heq : EquivBA (sol t) (GkatThompson.eqRHSParam sys sol F t)) :
    EquivBA (sol t) (.test .zero) := by
  refine EquivBA.trans heq ?_
  show EquivBA (guardedFold (transitionBranches (sys.trans t) sol)
    (GkatThompson.paramFallback (sys.hlt t) F)) _
  rw [htr]
  show EquivBA (Exp.seq (Exp.test (sys.hlt t)) F) _
  refine EquivBA.trans (EquivBA.seq_c
    (EquivBA.baTest (c := BExp.zero) (fun X W x => hhl X W x))
    (EquivBA.base (Equiv.refl F))) ?_
  exact EquivBA.base (Equiv.s2 F)

theorem zero_targets_agree {S : Type} (sol sol' : S → Exp A T) (t : S)
    (h : EquivBA (sol t) (.test .zero)) (h' : EquivBA (sol' t) (.test .zero)) :
    EquivBA (sol t) (sol' t) :=
  EquivBA.trans h (EquivBA.symm h')

theorem seq_seq_zero (x w F : Exp A T) (h : EquivBA x (.test .zero)) :
    EquivBA (Exp.seq (Exp.seq x w) F) (.test .zero) := by
  refine EquivBA.trans (EquivBA.seq_c
    (EquivBA.trans (EquivBA.seq_c h (EquivBA.base (Equiv.refl w)))
      (EquivBA.base (Equiv.s2 w)))
    (EquivBA.base (Equiv.refl F))) ?_
  exact EquivBA.base (Equiv.s2 F)

section LayeredRelative
open Classical

/-! ### 294 — THE RELATIVISED RECURSION, ASSEMBLED

    `LayeredOn sys P` — "given a solution on the block `P`, the rest of `sys`
    can be solved".  Three constructors, one per lemma proved over the last
    six iterations:

      * **acyclic**, relative to the block (288/292);
      * **sequence layer** whose shared entry points INTO the block (289/291) —
        the finish it needs is then computable from the block's solution alone,
        which is exactly why the entry must point there and not back;
      * **loop layer** confined to the complement, over a base on which the
        complement is CLOSED (284/293) — the loop must not be able to leave, and
        it cannot, because the sequence layers that carry the exits have already
        been peeled.

    The loop case delivers its solution at finish `1`, since 284's construction
    is tied to `w1`; the recursion needs it at `F`.  That is repaired by
    right-multiplication, which is sound HERE precisely because the complement
    is closed: no branch escapes into the block, so every branch carries the
    `F`. -/
inductive LayeredOn : {S : Type} → GkatThompson.GSystem S A T → (S → Prop) → Prop where
  | acyclic {S : Type} {sys : GkatThompson.GSystem S A T} {P : S → Prop} :
      (∃ rank : S → Nat, ∀ s, ¬ P s →
        ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
        GkatKleene.firstMatch W x (sys.trans s) = some r →
          P r.2 ∨ rank r.2 < rank s) →
      LayeredOn sys P
  | seq {S : Type} {sys base : GkatThompson.GSystem S A T} {P : S → Prop}
      {h₀ : BExp T} {entry : List (BExp T × A × S)} :
      SeqLayer sys base h₀ entry (fun s => ¬ P s) →
      (∀ tr ∈ entry, P tr.2.2) →
      LayeredOn base P → LayeredOn sys P
  | loop {S : Type} {sys base : GkatThompson.GSystem S A T} {P : S → Prop}
      {b : BExp T} {entry : List (BExp T × A × S)} :
      LoopLayerOn sys base b entry (fun s => ¬ P s) →
      (∀ tr ∈ entry, ¬ P tr.2.2 ∨ StuckAt sys tr.2.2) →
      (∀ s, ¬ P s → ∀ tr ∈ base.trans s, ¬ P tr.2.2 ∨ StuckAt sys tr.2.2) →
      LayeredOn base P → LayeredOn sys P
  /-- **GROW THE BLOCK.**  The `seq` constructor demands that a layer's entry
      point INTO the block, so a recursion that starts from an empty block must
      be able to ENLARGE it.  Splitting off a CLOSED region `C` does exactly
      that: solve `C` first — legitimate at any input, since a closed region's
      equations mention nothing outside it — and then solve the rest with
      `P ∪ C` as the block.  This is what turns `seqGSystem`'s right half into
      something a sequence layer may point at. -/
  | split {S : Type} {sys : GkatThompson.GSystem S A T} {P C : S → Prop} :
      (∀ s, P s → ¬ C s) →
      (∀ s, C s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
        GkatKleene.firstMatch W x (sys.trans s) = some r → C r.2 ∨ P r.2) →
      LayeredOn sys (fun s => ¬ C s) →
      LayeredOn sys (fun s => P s ∨ C s) →
      LayeredOn sys P

/-- **`hsolve`, RELATIVISED.**  325's final shape.  Two changes from 294:

    * the input carries `hz` — **`sol₀` is ZERO at STUCK block states** — which is
      what 322-324 showed the loop case needs once its entry list may touch the
      block;
    * the conclusion agrees with `sol₀` on the block only up to `EquivBA`, which
      is what lets `split` NORMALISE its first call's input to zero at stuck
      states.  325 found that normalisation unavoidable: `hz` is known on `P`
      and `split`'s first call needs it on `¬C ⊇ P`, with nothing supplying the
      difference.

    The weakening is affordable because a block's values are only ever CONSUMED
    through a guarded fold, and folds are compared by `fold_congr_step`. -/
theorem layeredOn_has_solution : ∀ {S : Type} {sys : GkatThompson.GSystem S A T}
    {P : S → Prop}, LayeredOn sys P → ∀ (sol₀ : S → Exp A T) (F : Exp A T),
      (∀ t, P t → StuckAt sys t → EquivBA (sol₀ t) (.test .zero)) →
      ∃ sol : S → Exp A T, (∀ s, P s → EquivBA (sol s) (sol₀ s)) ∧
        (∀ s, ¬ P s → EquivBA (sol s) (GkatThompson.eqRHSParam sys sol F s)) := by
  intro S sys P h
  induction h with
  | @acyclic sys P hr =>
      intro sol₀ F _
      obtain ⟨rank, hrank⟩ := hr
      obtain ⟨sol, hin, hout⟩ := solExtF_has_solution sys P sol₀ F rank hrank
      exact ⟨sol, fun s hs => by rw [hin s hs]; exact EquivBA.base (Equiv.refl _), hout⟩
  | @seq sys base P h₀ entry hlay hentry _ ih =>
      intro sol₀ F hz
      obtain ⟨solB, hin, hout⟩ := ih sol₀
        (guardedFold (transitionBranches entry sol₀)
          (GkatThompson.paramFallback h₀ F))
        (fun t hp hst => hz t hp ⟨(hlay.outside t (fun h => h hp)).1.trans hst.1,
          fun X W x => by rw [(hlay.outside t (fun h => h hp)).2]; exact hst.2 X W x⟩)
      refine ⟨solB, hin, ?_⟩
      have hGeq : EquivBA (guardedFold (transitionBranches entry sol₀)
            (GkatThompson.paramFallback h₀ F))
          (guardedFold (transitionBranches entry solB)
            (GkatThompson.paramFallback h₀ F)) := by
        refine fold_congr_list entry _ sol₀ solB ?_
        intro X W x r hfm
        obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x entry r.1 r.2 (by rw [← hfm])
        exact EquivBA.symm (hin r.2 (hentry (g, r.1, r.2) hg))
      refine seqLayer_extends hlay solB F (fun s hs => EquivBA.trans (hout s hs) ?_)
      exact guardedFold_fallback_congr
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hGeq)
  | @loop sys base P b entry hlay hentry hclosed _ ih =>
      intro sol₀ F hz
      obtain ⟨solB, hin, hout⟩ := ih sol₀ (.test .one)
        (fun t hp hst => hz t hp ⟨(hlay.outside t (fun h => h hp)).1.trans hst.1,
          fun X W x => by rw [(hlay.outside t (fun h => h hp)).2]; exact hst.2 X W x⟩)
      have hloop := loopLayerOn_has_solution hlay solB hout
        (guardedFold (transitionBranches entry solB) (.test .zero))
        (.wh b (guardedFold (transitionBranches entry solB) (.test .zero)))
        rfl rfl
      refine ⟨fun t => if P t then sol₀ t else
        Exp.seq (Exp.seq (solB t)
          (.wh b (guardedFold (transitionBranches entry solB) (.test .zero)))) F,
        ?_, ?_⟩
      · intro s hs
        show EquivBA (if P s then sol₀ s else _) _
        rw [if_pos hs]
        exact EquivBA.base (Equiv.refl _)
      · intro s hs
        have htargets : ∀ tr ∈ sys.trans s, ¬ P tr.2.2 ∨ StuckAt sys tr.2.2 := by
          intro tr htr
          rw [hlay.trans_eq s hs, List.mem_append] at htr
          rcases htr with htr | htr
          · exact hclosed s hs tr htr
          · simp only [List.mem_map] at htr
            obtain ⟨t, ht, rfl⟩ := htr
            exact hentry t ht
        have hcongr : EquivBA (GkatThompson.eqRHSParam sys
              (fun t => Exp.seq (Exp.seq (solB t)
                (.wh b (guardedFold (transitionBranches entry solB) (.test .zero)))) F)
              F s)
            (GkatThompson.eqRHSParam sys
              (fun t => if P t then sol₀ t else
                Exp.seq (Exp.seq (solB t)
                  (.wh b (guardedFold (transitionBranches entry solB)
                    (.test .zero)))) F) F s) := by
          refine fold_congr_list (sys.trans s) _ _ _ ?_
          intro X W x r hfm
          obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x (sys.trans s) r.1 r.2 (by rw [← hfm])
          by_cases hPr : P r.2
          · have hst : StuckAt sys r.2 :=
              (htargets (g, r.1, r.2) hg).resolve_left (fun hnp => hnp hPr)
            have hz0 : EquivBA (sol₀ r.2) (.test .zero) := hz r.2 hPr hst
            refine EquivBA.trans (seq_seq_zero _ _ _ ?_) (EquivBA.symm ?_)
            · exact EquivBA.trans (hin r.2 hPr) hz0
            · show EquivBA (if P r.2 then sol₀ r.2 else _) _
              rw [if_pos hPr]
              exact hz0
          · show EquivBA _ (if P r.2 then _ else _)
            rw [if_neg hPr]
            exact EquivBA.base (Equiv.refl _)
        show EquivBA (if P s then sol₀ s else _) _
        rw [if_neg hs]
        refine EquivBA.trans ?_ hcongr
        exact GkatThompson.StandardSolvesBA.withContinuation
          ⟨⟨[s], sys.hlt, sys.trans⟩, .one, []⟩
          (fun t => Exp.seq (solB t)
            (.wh b (guardedFold (transitionBranches entry solB) (.test .zero))))
          (fun t ht => by
            have hts : t = s := by simpa using ht
            subst hts
            exact hloop t hs) F s (by simp)
  | @split sys P C hdisj hCclosed _ _ ih1 ih2 =>
      intro sol₀ F hz
      obtain ⟨sol1, hin1, hout1⟩ := ih1
        (fun t => if StuckAt sys t then Exp.test BExp.zero else sol₀ t) F
        (fun t _ hst => by
          show EquivBA (if StuckAt sys t then _ else _) _
          rw [if_pos hst]
          exact EquivBA.base (Equiv.refl _))
      obtain ⟨sol2, hin2, hout2⟩ := ih2 sol1 F (fun t ht hst => by
        rcases ht with hP | hC
        · refine EquivBA.trans (hin1 t (hdisj t hP)) ?_
          show EquivBA (if StuckAt sys t then _ else _) _
          rw [if_pos hst]
          exact EquivBA.base (Equiv.refl _)
        · exact stuck_solution_zero sys sol1 F t hst.1 hst.2 (hout1 t (fun h => h hC)))
      refine ⟨sol2, ?_, ?_⟩
      · intro s hs
        refine EquivBA.trans (hin2 s (Or.inl hs))
          (EquivBA.trans (hin1 s (hdisj s hs)) ?_)
        show EquivBA (if StuckAt sys s then _ else _) (sol₀ s)
        by_cases hst : StuckAt sys s
        · rw [if_pos hst]
          exact EquivBA.symm (hz s hs hst)
        · rw [if_neg hst]
          exact EquivBA.base (Equiv.refl _)
      · intro s hs
        by_cases hC : C s
        · have hcongr : EquivBA (GkatThompson.eqRHSParam sys sol2 F s)
              (GkatThompson.eqRHSParam sys sol1 F s) := by
            refine fold_congr_list (sys.trans s) _ sol2 sol1 ?_
            intro X W x r hfm
            exact hin2 r.2 (hCclosed s hC X W x r hfm).symm
          exact EquivBA.trans (EquivBA.trans (hin2 s (Or.inr hC))
            (hout1 s (fun h => h hC))) (EquivBA.symm hcongr)
        · exact hout2 s (fun h => h.elim hs hC)

#print axioms layeredOn_has_solution

end LayeredRelative


/-! ### 295 — THE ACYCLIC CASE PUSHES FORWARD WITHOUT A BISIMULATION

    264 proved the acyclic case of `hcollapse` using the bisimulation: `rank'`
    was the MINIMUM rank over a class's preimages, and a step downstairs was
    pushed BACKWARDS through the bisimulation to find a preimage achieving it.

    Relativised, it needs neither.  Choose the representative to be RANK-MINIMAL
    in its class — among the class's members outside the block — and then
    `rank' := rank ∘ rep` works directly:

      * if the step's target has a preimage IN the block, the preferring
        representative puts the target's representative in the block too, and
        the first disjunct discharges it with no rank comparison at all;
      * otherwise every member of the target's class is outside the block, so
        the rank-minimal representative has rank at most the actual target's,
        which is already below `rank (rep c)`.

    The two properties do not conflict, because they apply to DISJOINT cases:
    preference decides classes that meet the block, minimality decides the rest.
    Taken as hypotheses here; both are satisfiable, `preferringRep` (287) being
    the first half. -/
/-- **THE ACYCLIC CASE OF THE PUSHFORWARD, RELATIVISED.** -/
theorem acyclic_rel_pushforward {S S' : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s)
    (f : S → S') (rep : S' → S)
    (hpref : ∀ (c : S') (t : S), f t = c → P t → P (rep c))
    (hmin : ∀ (c : S') (t : S), f t = c → ¬ P (rep c) → rank (rep c) ≤ rank t)
    (sys' : GkatThompson.GSystem S' A T)
    (htrans : ∀ c, sys'.trans c
      = (sys.trans (rep c)).map (fun tr => (tr.1, tr.2.1, f tr.2.2))) :
    ∀ c, ¬ P (rep c) → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S'),
      GkatKleene.firstMatch W x (sys'.trans c) = some r →
        P (rep r.2) ∨ rank (rep r.2) < rank (rep c) := by
  intro c hc X W x r hfm
  rw [htrans, firstMatch_map] at hfm
  cases hfm0 : GkatKleene.firstMatch W x (sys.trans (rep c)) with
  | none => rw [hfm0] at hfm; exact absurd hfm (by simp)
  | some qt =>
      rw [hfm0] at hfm
      have hr : r = (qt.1, f qt.2) := by
        have := hfm
        simp only [Option.map_some] at this
        exact (Option.some.inj this).symm
      subst hr
      rcases hstep (rep c) hc X W x qt hfm0 with hP | hlt
      · exact Or.inl (hpref (f qt.2) qt.2 rfl hP)
      · by_cases hP2 : P (rep (f qt.2))
        · exact Or.inl hP2
        · exact Or.inr (Nat.lt_of_le_of_lt (hmin (f qt.2) qt.2 rfl hP2) hlt)

/-- Packaged as the constructor it feeds. -/
theorem layeredOn_acyclic_push {S S' : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s)
    (f : S → S') (rep : S' → S)
    (hpref : ∀ (c : S') (t : S), f t = c → P t → P (rep c))
    (hmin : ∀ (c : S') (t : S), f t = c → ¬ P (rep c) → rank (rep c) ≤ rank t)
    (sys' : GkatThompson.GSystem S' A T)
    (htrans : ∀ c, sys'.trans c
      = (sys.trans (rep c)).map (fun tr => (tr.1, tr.2.1, f tr.2.2))) :
    LayeredOn sys' (fun c => P (rep c)) :=
  LayeredOn.acyclic ⟨fun c => rank (rep c),
    acyclic_rel_pushforward sys P rank hstep f rep hpref hmin sys' htrans⟩

#print axioms layeredOn_acyclic_push


/-! ### 296 — THE LOOP PUSHFORWARD, RELATIVISED

    The last LAYER-LEVEL pushforward.  281 proved it for a total loop layer;
    289 proved the sequence version with a domain.  This is the loop version
    with a domain, and it is 289's proof with the two extra fields the loop
    carries — the semantic halt equation, and the `outside` clause.

    With this, all three layer shapes push forward along a representative
    quotient: acyclic (295), sequence (289), loop (296).  What is NOT yet
    assembled is the INDUCTION over `LayeredOn`, and 295 identified the one
    thing standing in its way: the acyclic case wants the representative to be
    RANK-MINIMAL, but the rank is existential INSIDE each acyclic node while
    the representative is global to the quotient, so a single representative
    cannot be minimal for every node at once.  The resolution is 264's: use the
    BISIMULATION to transfer the step, which is available in the application and
    is what `acyclic_quotient` already assumes. -/
theorem loopLayerOn_pushforward_rep {S S' : Type}
    {sys base : GkatThompson.GSystem S A T} {b : BExp T}
    {entry : List (BExp T × A × S)} {dom : S → Prop}
    (h : LoopLayerOn sys base b entry dom)
    (f : S → S') (hsurj : ∀ s' : S', ∃ s, f s = s')
    (sys' : GkatThompson.GSystem S' A T)
    (htrans : ∀ s' : S', sys'.trans s'
      = (sys.trans (Classical.choose (hsurj s'))).map
          (fun tr => (tr.1, tr.2.1, f tr.2.2)))
    (hhlt : ∀ s' : S', sys'.hlt s' = sys.hlt (Classical.choose (hsurj s'))) :
    LoopLayerOn sys' (pushBase f hsurj base sys') b
      (entry.map (fun tr => (tr.1, tr.2.1, f tr.2.2)))
      (fun s' => dom (Classical.choose (hsurj s'))) where
  trans_eq s' hs := by
    simp only [pushBase]
    rw [htrans s', h.trans_eq (Classical.choose (hsurj s')) hs, List.map_append]
    congr 1
    simp only [List.map_map, Function.comp_def]
  hlt_eq s' hs := by
    intro X W x
    simp only [pushBase]
    rw [hhlt s']
    exact h.hlt_eq (Classical.choose (hsurj s')) hs X W x
  outside s' hs := by
    obtain ⟨ht, hh⟩ := h.outside (Classical.choose (hsurj s')) hs
    exact ⟨by simp only [pushBase]; rw [htrans s', ht],
      by simp only [pushBase]; rw [hhlt s', hh]⟩
  states_eq := rfl

#print axioms loopLayerOn_pushforward_rep


section AcyclicBisimPush
open Classical

/-! ### 297 — THE ACYCLIC PUSHFORWARD VIA THE BISIMULATION

    **Retracting 296.**  296 claimed `Nat.find` is in scope in this file, citing
    four occurrences.  All four are inside DOC COMMENTS, and one of them says
    the opposite: `Nat.find` does NOT exist here (no Mathlib).  The minimum must
    come from `minOf1`/`minOfList` (6831-6884), which is exactly why 264 built
    them.  The claim was made from a grep that did not distinguish code from
    prose.

    With that corrected, here is the case 295 could not reach.  295 needed the
    representative to be RANK-MINIMAL, which a single global representative
    cannot be for every acyclic node at once.  The bisimulation removes the
    need: define `rank'` as the minimum rank over a class's LISTED preimages
    OUTSIDE the block, take the preimage ACHIEVING it, and push the step
    backwards to that preimage rather than to the representative.

    The block downstairs is "SOME listed preimage lies in the block", which
    agrees with 295's `P ∘ rep` whenever the representative prefers the block
    (287).  The two halves of the disjunction then fall to a case split on
    whether the step's target is in the block — and, crucially, in the branch
    where it is NOT, the target is a legitimate member of its own class's
    minimising set, so `rank'` decreases. -/
private noncomputable def fibreOut {S S' : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (rank : S → Nat) (f : S → S') (c : S') : List Nat :=
  (sys.states.filter (fun s => decide (f s = c ∧ ¬ P s))).map rank

private theorem fibreOut_le {S S' : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (rank : S → Nat) (f : S → S') (c : S') (s : S)
    (hmem : s ∈ sys.states) (hf : f s = c) (hP : ¬ P s) :
    minOfList (fibreOut sys P rank f c) ≤ rank s := by
  refine minOfList_le _ (rank s) ?_
  refine List.mem_map.2 ⟨s, ?_, rfl⟩
  exact List.mem_filter.2 ⟨hmem, by simp [hf, hP]⟩

private theorem fibreOut_achieved {S S' : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (rank : S → Nat) (f : S → S') (c : S') (s : S)
    (hmem : s ∈ sys.states) (hf : f s = c) (hP : ¬ P s) :
    ∃ s₀, s₀ ∈ sys.states ∧ f s₀ = c ∧ ¬ P s₀ ∧
      rank s₀ = minOfList (fibreOut sys P rank f c) := by
  have hne : fibreOut sys P rank f c ≠ [] := by
    intro hnil
    have : rank s ∈ fibreOut sys P rank f c :=
      List.mem_map.2 ⟨s, List.mem_filter.2 ⟨hmem, by simp [hf, hP]⟩, rfl⟩
    rw [hnil] at this
    exact absurd this (by simp)
  obtain ⟨s₀, hs₀, hrk⟩ := List.mem_map.1 (minOfList_mem _ hne)
  obtain ⟨hmem₀, hcond⟩ := List.mem_filter.1 hs₀
  have hcond' : f s₀ = c ∧ ¬ P s₀ := by simpa using hcond
  exact ⟨s₀, hmem₀, hcond'.1, hcond'.2, hrk⟩

/-- **THE ACYCLIC CASE OF THE PUSHFORWARD, VIA THE BISIMULATION.**  Stated with
    the block downstairs as `P ∘ rep`, which is the form the induction consumes
    and is also the shorter proof: `¬ P (rep c)` is then immediate rather than
    derived, and the in-block branch is exactly `hpref`. -/
theorem acyclic_bisim_pushforward {S S' : Type} (sys : GkatThompson.GSystem S A T)
    (P : S → Prop) (rank : S → Nat)
    (hstep : ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → P r.2 ∨ rank r.2 < rank s)
    (f : S → S') (rep : S' → S)
    (hrep : ∀ c, f (rep c) = c) (hrepmem : ∀ c, rep c ∈ sys.states)
    (hpref : ∀ (c : S') (t : S), f t = c → P t → P (rep c))
    (htargets : ∀ s ∈ sys.states, ∀ tr ∈ sys.trans s, tr.2.2 ∈ sys.states)
    (hbisim : ∀ s t : S, f s = f t → ∀ (X : Type) (W : T → X → Bool) (x : X),
      (GkatKleene.firstMatch W x (sys.trans s)).map (fun q => (q.1, f q.2))
        = (GkatKleene.firstMatch W x (sys.trans t)).map (fun q => (q.1, f q.2)))
    (sys' : GkatThompson.GSystem S' A T)
    (htrans : ∀ c, sys'.trans c
      = (sys.trans (rep c)).map (fun tr => (tr.1, tr.2.1, f tr.2.2))) :
    LayeredOn sys' (fun c => P (rep c)) := by
  refine LayeredOn.acyclic ⟨fun c => minOfList (fibreOut sys P rank f c), ?_⟩
  intro c hc X W x r hfm
  obtain ⟨s₀, hs₀mem, hs₀f, hs₀P, hs₀rk⟩ :=
    fibreOut_achieved sys P rank f c (rep c) (hrepmem c) (hrep c) hc
  rw [htrans, firstMatch_map] at hfm
  have hb := hbisim (rep c) s₀ (by rw [hrep c, hs₀f]) X W x
  rw [hfm] at hb
  cases hfm0 : GkatKleene.firstMatch W x (sys.trans s₀) with
  | none => rw [hfm0] at hb; exact absurd hb.symm (by simp)
  | some qt =>
      rw [hfm0] at hb
      have hrq : r = (qt.1, f qt.2) := by
        simp only [Option.map_some] at hb
        exact Option.some.inj hb
      subst hrq
      by_cases hPq : P qt.2
      · exact Or.inl (hpref (f qt.2) qt.2 rfl hPq)
      · rcases hstep s₀ hs₀P X W x qt hfm0 with hP | hlt
        · exact absurd hP hPq
        · refine Or.inr ?_
          obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x (sys.trans s₀) qt.1 qt.2 hfm0
          have hqmem : qt.2 ∈ sys.states :=
            htargets s₀ hs₀mem (g, qt.1, qt.2) hg
          calc minOfList (fibreOut sys P rank f (f qt.2))
              ≤ rank qt.2 := fibreOut_le sys P rank f _ qt.2 hqmem rfl hPq
            _ < rank s₀ := hlt
            _ = minOfList (fibreOut sys P rank f c) := hs₀rk

#print axioms acyclic_bisim_pushforward

end AcyclicBisimPush


/-! ### 299 — BLOCKS CAN BE SATURATED

    298 showed the pushforward induction closes exactly when every block in the
    derivation is a UNION OF CLASSES, and left that as a condition the collapse
    might not grant.  But the blocks come from `split`, and `split`'s blocks are
    OURS to choose.  So the question is whether a block can always be REPLACED
    by its class-saturation while staying admissible, and the answer is yes for
    the property `split` actually needs:

        the saturation of a CLOSED set is CLOSED.

    If `s ~ t` with `t` in the block and `s` steps to `s'`, the bisimulation
    gives `t` a matching step to some `t'` with `s' ~ t'`, and closure puts `t'`
    in the block — so `s'` is in the saturation.

    **Why this required weakening `split` first.**  The argument produces a
    matching step, and steps are SELECTIONS, not list members: a dead branch of
    `s` has no counterpart at `t` at all.  So the saturation is closed under
    `firstMatch` steps and NOT under list membership.  `split` asked for the
    latter.  It has been weakened to the former, and its case in
    `layeredOn_has_solution` now goes through `fold_congr_step` (292) instead of
    `guardedFold_trans_congr` — the same list-versus-selection trade 283 made,
    paying syntactic equality for `EquivBA` and getting the weaker hypothesis in
    return.

    **What is still open.**  Saturating a block enlarges it, so the two
    subderivations `split` demands must survive the enlargement: the block must
    still be solvable, and it must still be disjoint from `P`.  Neither is
    automatic. -/
theorem saturation_closed {S S' : Type} (sys : GkatThompson.GSystem S A T)
    (f : S → S') (C : S → Prop)
    (hC : ∀ s, C s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → C r.2)
    (hbisim : ∀ s t : S, f s = f t → ∀ (X : Type) (W : T → X → Bool) (x : X),
      (GkatKleene.firstMatch W x (sys.trans s)).map (fun q => (q.1, f q.2))
        = (GkatKleene.firstMatch W x (sys.trans t)).map (fun q => (q.1, f q.2))) :
    ∀ s, (∃ t, f t = f s ∧ C t) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
        GkatKleene.firstMatch W x (sys.trans s) = some r →
          ∃ u, f u = f r.2 ∧ C u := by
  intro s hs X W x r hfm
  obtain ⟨t, hft, hCt⟩ := hs
  have hb := hbisim t s hft X W x
  rw [hfm] at hb
  cases hfm0 : GkatKleene.firstMatch W x (sys.trans t) with
  | none => rw [hfm0] at hb; exact absurd hb (by simp)
  | some qt =>
      rw [hfm0] at hb
      have hq : f qt.2 = f r.2 := by
        simp only [Option.map_some] at hb
        exact congrArg Prod.snd (Option.some.inj hb)
      exact ⟨qt.2, hq, hC t hCt X W x qt hfm0⟩

/-- And a saturated block is a UNION OF CLASSES by construction — the property
    298 showed the induction needs. -/
theorem saturation_is_union {S S' : Type} (f : S → S') (C : S → Prop)
    (s t : S) (hf : f s = f t) :
    (∃ u, f u = f s ∧ C u) → (∃ u, f u = f t ∧ C u) :=
  fun ⟨u, hu, hCu⟩ => ⟨u, by rw [hu, hf], hCu⟩

#print axioms saturation_closed
#print axioms saturation_is_union


/-! ### 300 — SATURATEDNESS IS AN INVARIANT, SO DISJOINTNESS IS FREE

    299 left two things to check when a block is replaced by its saturation:
    the enlarged block must still be DISJOINT from `P`, and it must still be
    SOLVABLE.  The first is free, and for a reason worth stating: **saturatedness
    is an INVARIANT of the recursion.**

      * the recursion starts at `P = ∅`, which is saturated vacuously;
      * `split` replaces `P` by `P ∪ C`, and a union of saturated sets is
        saturated;
      * `seq` and `loop` do not change the block at all.

    So at every node the block is a union of classes — and then disjointness
    transports: if `P` is a union of classes and misses `C`, it misses
    everything class-equivalent to `C` as well, because a member of `P`
    equivalent to a member of `C` would drag that member into `P`.

    **This reduces 299's two open sub-conditions to ONE.**  What remains is
    whether the ENLARGED block is still layered — and that is the whole
    difficulty, not a side condition: the saturation of a `seq`'s right half
    contains every left-half state bisimilar to a right-half one, so the block
    a `split` must solve mixes the two halves. -/
theorem saturated_empty {S S' : Type} (f : S → S') :
    ∀ s t : S, f s = f t → (fun _ : S => False) s → (fun _ : S => False) t :=
  fun _ _ _ h => h.elim

theorem saturated_or {S S' : Type} (f : S → S') (P C : S → Prop)
    (hP : ∀ s t, f s = f t → P s → P t) (hC : ∀ s t, f s = f t → C s → C t) :
    ∀ s t, f s = f t → (P s ∨ C s) → (P t ∨ C t) :=
  fun s t h => Or.imp (hP s t h) (hC s t h)

/-- **DISJOINTNESS SURVIVES SATURATION**, provided the block it must miss is
    itself a union of classes — which the invariant guarantees. -/
theorem saturation_disjoint {S S' : Type} (f : S → S') (P C : S → Prop)
    (hPsat : ∀ s t, f s = f t → P s → P t)
    (hdisj : ∀ s, P s → ¬ C s) :
    ∀ s, P s → ¬ (∃ u, f u = f s ∧ C u) := by
  intro s hPs hsat
  obtain ⟨u, hu, hCu⟩ := hsat
  exact hdisj u (hPsat s u hu.symm hPs) hCu

#print axioms saturated_or
#print axioms saturation_disjoint


/-! ### 301 — SATURATION DIES AT THE TOP-LEVEL SUM; BUILD THE DERIVATION DOWNSTAIRS

    **The negative first.**  299 and 300 developed saturation as the way to make
    every block a union of classes.  Test it where it matters.  In the
    completeness application `sys = sumGSystem L R` with `start_L ~ start_R`, so
    by bisimulation EVERY REACHABLE `L`-state is bisimilar to some `R`-state.
    The top-level split takes `C = R`'s states; its saturation therefore
    contains every reachable state, and "solve `C'` given the rest" IS the
    original problem.  **Saturation destroys the top-level split exactly in the
    case the whole programme is about.**  299 and 300's lemmas stay true and
    stay useful; the STRATEGY of saturating a `sum`'s split does not.

    **And the fix is to stop pushing derivations forward at all.**  A quotient's
    blocks are SETS OF CLASSES, so they are saturated for free — the entire
    condition 298 derived is vacuous downstairs.  So build `Q`'s derivation
    DIRECTLY, using 287's preferring representative to supply the split:
    the classes with an `inl` representative are closed, so they are a legal
    `C`, and the two obligations that remain are about `L` and `R` separately —
    **structurally smaller expressions, which is a well-founded recursion where
    saturation was a circular one.**

    This is that first step: the top-level split, downstairs. -/
theorem sum_quotient_layered_of_split {S₁ S₂ Q : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (q : Sum S₁ S₂ → Q) (rep : Q → Sum S₁ S₂)
    (hpref : ∀ (c : Q) (t : Sum S₁ S₂), q t = c → (∃ u, t = .inl u) →
      ∃ u, rep c = .inl u)
    (Qsys : GkatThompson.GSystem Q A T)
    (htrans : ∀ c, Qsys.trans c = ((GkatThompson.sumGSystem L R).trans (rep c)).map
      (fun tr => (tr.1, tr.2.1, q tr.2.2)))
    (hleft : LayeredOn Qsys (fun c => ¬ ∃ u, rep c = Sum.inl u))
    (hrest : LayeredOn Qsys (fun c => ∃ u, rep c = Sum.inl u)) :
    LayeredOn Qsys (fun _ => False) := by
  have hclosedUp : ∀ t : Sum S₁ S₂, (∃ u, t = .inl u) →
      ∀ tr ∈ (GkatThompson.sumGSystem L R).trans t, ∃ u, tr.2.2 = .inl u := by
    intro t ht tr htr
    obtain ⟨u, rfl⟩ := ht
    have hmem : tr ∈ (L.trans u).map (fun x => (x.1, x.2.1, Sum.inl x.2.2)) := htr
    simp only [List.mem_map] at hmem
    obtain ⟨x, _, rfl⟩ := hmem
    exact ⟨x.2.2, rfl⟩
  have hlist := quotient_closed_block (GkatThompson.sumGSystem L R)
    (fun t => ∃ u, t = .inl u) hclosedUp q rep hpref Qsys htrans
  have hclosed' : ∀ c : Q, (∃ u, rep c = Sum.inl u) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × Q),
      GkatKleene.firstMatch W x (Qsys.trans c) = some r →
        ∃ u, rep r.2 = Sum.inl u := by
    intro c hc X W x r hfm
    obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x (Qsys.trans c) r.1 r.2 (by
      rw [← hfm])
    exact hlist c hc (g, r.1, r.2) hg
  have heq : (fun c : Q => ∃ u, rep c = Sum.inl u)
      = (fun s : Q => False ∨ ∃ u, rep s = Sum.inl u) := by
    funext s
    exact propext ⟨Or.inr, fun h => h.elim (fun x => x.elim) id⟩
  exact LayeredOn.split (fun _ h => h.elim)
    (fun c hc X W x r hfm => Or.inl (hclosed' c hc X W x r hfm)) hleft (heq ▸ hrest)

#print axioms sum_quotient_layered_of_split


/-! ### 302 — THE RECURSION IS WELL-FOUNDED DOWNSTAIRS, AND 299 SURVIVES ITS STRATEGY

    301 redirected to building the quotient's derivation directly, and left the
    worry that the same circularity recurs one level down: inside `ite c e₁ e₂`
    a split at `e₂`'s states need not be a union of classes either, and
    saturating it mixes `e₁` with `e₂` again.

    **It does not recur, and the reason is worth stating.**  Bisimilar states
    have the SAME CLASS, so the IMAGE of a saturated block is the image of the
    half it started from — the extra states saturation pulled in contribute no
    new classes.  Mixing is an UPSTAIRS phenomenon; downstairs a block is always
    "the image of a sub-automaton", and the recursion is on EXPRESSION
    STRUCTURE, which is well-founded.  That is the difference between 299's
    route and 301's, stated exactly: same construction, but measured downstairs
    it decreases and measured upstairs it does not.

    **And 299's lemma survives its strategy's death.**  Obligation B needs: the
    `R`-states having an `L`-partner form a CLOSED set in the sum.  That is
    `saturation_closed` applied with `C` = "is `inl`" — the saturation of
    "is `inl`" IS "has an `L`-partner".  The lemma proved for a dead strategy is
    exactly the lemma the live one wants. -/
theorem inl_partner_closed {S₁ S₂ Q : Type} (L : GkatThompson.GSystem S₁ A T)
    (R : GkatThompson.GSystem S₂ A T) (q : Sum S₁ S₂ → Q)
    (hbisim : ∀ s t : Sum S₁ S₂, q s = q t →
      ∀ (X : Type) (W : T → X → Bool) (x : X),
      (GkatKleene.firstMatch W x ((GkatThompson.sumGSystem L R).trans s)).map
          (fun z => (z.1, q z.2))
        = (GkatKleene.firstMatch W x ((GkatThompson.sumGSystem L R).trans t)).map
          (fun z => (z.1, q z.2))) :
    ∀ s : Sum S₁ S₂, (∃ t, q t = q s ∧ ∃ u, t = Sum.inl u) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × Sum S₁ S₂),
        GkatKleene.firstMatch W x ((GkatThompson.sumGSystem L R).trans s) = some r →
          ∃ t, q t = q r.2 ∧ ∃ u, t = Sum.inl u := by
  refine saturation_closed (GkatThompson.sumGSystem L R) q
    (fun t => ∃ u, t = Sum.inl u) ?_ hbisim
  intro s hs X W x r hfm
  obtain ⟨u, rfl⟩ := hs
  obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x
    ((GkatThompson.sumGSystem L R).trans (Sum.inl u)) r.1 r.2 (by rw [← hfm])
  have hmem : (g, r.1, r.2)
      ∈ (L.trans u).map (fun z => (z.1, z.2.1, Sum.inl z.2.2)) := hg
  simp only [List.mem_map] at hmem
  obtain ⟨z, _, hz⟩ := hmem
  exact ⟨z.2.2, (congrArg (fun w => w.2.2) hz).symm⟩

#print axioms inl_partner_closed


/-! ### 303 — THE EXPRESSION INDUCTION: ITS SHAPE, AND ITS BASE CASES

    302 established that the recursion belongs downstairs and runs on EXPRESSION
    STRUCTURE.  Writing its statement is the next commitment, and the shape is
    the thing to get right, because every later case has to fit it.

        for every expression `g`, every quotient `Qsys` of `g`'s Thompson
        automaton, and every block `B` lying OUTSIDE the quotient's image,
        `Qsys` is `LayeredOn B`

    Three points about the shape.

    **The block is outside the image.**  `B` is what has already been solved —
    the classes this call is not responsible for — and the image of `j` is what
    it must solve.  `hout` says exactly that, and it makes `¬ B c` synonymous
    with "`c` is a class of `g`'s automaton", which is what lets `rep` be a
    section only where it is needed.

    **The dynamics is read off representatives, only off the block.**  A
    quotient's dynamics elsewhere is not this call's business, and demanding it
    everywhere would make the `ite` case unusable — there `Qsys` also carries
    the other branch's classes.

    **`rep` need not be total in any useful sense.**  For `test` its codomain is
    `Empty`, and that is not a degenerate case to be worked around: it is what
    PROVES the base case.  A class outside the block would have to have a
    representative, and there are none, so the block is everything and the
    acyclic constructor fires vacuously.

    `act` is the same shape one step up: one state, no transitions, so no
    `firstMatch` step exists to decrease anything. -/
theorem quotient_layered_test (t : BExp T) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (rep : Q → (GkatThompson.certifiedThompson A T (.test t)).State) :
    LayeredOn Qsys B :=
  LayeredOn.acyclic ⟨fun _ => 0, fun c _ => nomatch (rep c)⟩

theorem quotient_layered_act (a : A) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T (.act a)).State → Q)
    (rep : Q → (GkatThompson.certifiedThompson A T (.act a)).State)
    (htrans : ∀ c, ¬ B c → Qsys.trans c
      = ((GkatThompson.certifiedThompson A T (.act a)).aut.core.trans (rep c)).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))) :
    LayeredOn Qsys B := by
  refine LayeredOn.acyclic ⟨fun _ => 0, ?_⟩
  intro c hc X W x r hfm
  rw [htrans c hc] at hfm
  have hnil : (GkatThompson.certifiedThompson A T (.act a)).aut.core.trans (rep c) = [] :=
    rfl
  rw [hnil] at hfm
  exact absurd hfm (by simp [GkatKleene.firstMatch])

#print axioms quotient_layered_test
#print axioms quotient_layered_act


section QuotientLayeredWh
open Classical

private theorem map_append' {α β : Type} (f : α → β) :
    ∀ l₁ l₂ : List α, (l₁ ++ l₂).map f = l₁.map f ++ l₂.map f
  | [], _ => rfl
  | a :: t, l₂ => by
      show f a :: ((t ++ l₂).map f) = f a :: (t.map f ++ l₂.map f)
      rw [map_append' f t l₂]

private theorem gate_map_comm {S S' : Type} (H b : BExp T) (j : S → S') :
    ∀ l : List (BExp T × A × S),
      (l.map (fun tr => (BExp.and H (BExp.and b tr.1), tr.2))).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))
        = (l.map (fun tr => (tr.1, tr.2.1, j tr.2.2))).map
          (fun tr => (BExp.and H (BExp.and b tr.1), tr.2))
  | [] => rfl
  | a :: t => by
      show (BExp.and H (BExp.and b a.1), a.2.1, j a.2.2) :: _
        = (BExp.and H (BExp.and b a.1), a.2.1, j a.2.2) :: _
      rw [gate_map_comm H b j t]

private theorem map_map' {α β γ : Type} (g : β → γ) (f : α → β) :
    ∀ l : List α, (l.map f).map g = l.map (fun a => g (f a))
  | [] => rfl
  | a :: t => by
      show g (f a) :: ((t.map f).map g) = g (f a) :: t.map (fun a => g (f a))
      rw [map_map' g f t]


/-- **THE `wh` CASE OF THE EXPRESSION INDUCTION.**  The base system downstairs
    is BUILT, not assumed: off the block it is `e`'s dynamics read through the
    representative, and on the block it is whatever `Qsys` already had — which
    makes `LoopLayerOn`'s `outside` clause true by construction rather than by
    hypothesis.  That is the trick that lets a TOTAL loop upstairs become a
    loop CONFINED TO THE IMAGE downstairs, which is what the recursion needs. -/
theorem quotient_layered_wh (b : BExp T) (e : Exp A T) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T e).State → Q)
    (rep : Q → (GkatThompson.certifiedThompson A T e).State)
    (hout : ∀ s, ¬ B (j s))
    (htrans : ∀ c, ¬ B c → Qsys.trans c
      = ((GkatThompson.certifiedThompson A T (.wh b e)).aut.core.trans (rep c)).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    (hhlt : ∀ c, ¬ B c → Qsys.hlt c
      = (GkatThompson.certifiedThompson A T (.wh b e)).aut.core.hlt (rep c))
    (ih : ∀ base : GkatThompson.GSystem Q A T,
      (∀ c, ¬ B c → base.trans c
        = ((GkatThompson.certifiedThompson A T e).aut.core.trans (rep c)).map
            (fun tr => (tr.1, tr.2.1, j tr.2.2))) →
      (∀ c, ¬ B c → base.hlt c
        = (GkatThompson.certifiedThompson A T e).aut.core.hlt (rep c)) →
      LayeredOn base B) :
    LayeredOn Qsys B := by
  refine LayeredOn.loop
    (base := ⟨Qsys.states,
      fun c => if B c then Qsys.hlt c
        else (GkatThompson.certifiedThompson A T e).aut.core.hlt (rep c),
      fun c => if B c then Qsys.trans c
        else ((GkatThompson.certifiedThompson A T e).aut.core.trans (rep c)).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))⟩)
    (b := b)
    (entry := (GkatThompson.certifiedThompson A T e).aut.initTrans.map
      (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    ⟨?_, ?_, ?_, rfl⟩ ?_ ?_ (ih _ ?_ ?_)
  · -- trans_eq
    intro c hc
    show Qsys.trans c = (if B c then _ else _) ++ _
    simp only [if_neg hc]
    rw [htrans c hc, loop_core_trans b e (rep c)]
    refine Eq.trans (map_append' _ _ _) ?_
    congr 1
    exact gate_map_comm _ _ _ _
  · -- hlt_eq
    intro c hc X W x
    show GkatGS.bval W (Qsys.hlt c) x = (GkatGS.bval W (if B c then _ else _) x && _)
    rw [hhlt c hc, loop_core_hlt b e (rep c), if_neg hc]
    rfl
  · -- outside
    intro c hc
    have hB : B c := Classical.not_not.mp hc
    exact ⟨by show Qsys.trans c = (if B c then _ else _); rw [if_pos hB],
      by show Qsys.hlt c = (if B c then _ else _); rw [if_pos hB]⟩
  · -- entry targets are outside the block
    intro tr htr
    simp only [List.mem_map] at htr
    obtain ⟨t, _, rfl⟩ := htr
    exact Or.inl (hout t.2.2)
  · -- the base's targets are outside the block
    intro c hc tr htr
    simp only [if_neg hc, List.mem_map] at htr
    obtain ⟨t, _, rfl⟩ := htr
    exact Or.inl (hout t.2.2)
  · intro c hc; show (if B c then _ else _) = _; rw [if_neg hc]
  · intro c hc; show (if B c then _ else _) = _; rw [if_neg hc]

#print axioms quotient_layered_wh

end QuotientLayeredWh


/-! ### 304 — THE `ite` CASE'S CONTENT: THE LEFT BLOCK IS CLOSED

    With the shape fixed by 303, the `ite` case reduces to `LayeredOn.split`
    applied at `C` = "the classes of the LEFT branch", plus two recursive calls.
    The split constructor itself is immediate; what has to be PROVED is that `C`
    is closed, and that is where the quotient's structure enters.

    It needs exactly two facts and no more: the image misses the block (`hout`),
    and the representative PREFERS the left branch (`hpref`, 287).  A step out of
    a left class lands, upstairs, in the left half — sums have no cross
    edges — so its class has a LEFT PREIMAGE; preference then makes the class's
    own representative left, which is the definition of `C`.

    Stated for an arbitrary `sumGSystem` rather than for `ite`'s automaton, so
    that the `seq` case can reuse it: a sequence's left half is closed for the
    same reason once its connecting block has been peeled by 289. -/
theorem sum_left_block_closed {S₁ S₂ Q : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : Sum S₁ S₂ → Q) (rep : Q → Sum S₁ S₂)
    (hout : ∀ s, ¬ B (j s))
    (hpref : ∀ (c : Q) (u : S₁), j (Sum.inl u) = c → ∃ v, rep c = Sum.inl v)
    (htrans : ∀ c, ¬ B c → Qsys.trans c
      = ((GkatThompson.sumGSystem L R).trans (rep c)).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))) :
    ∀ c, (¬ B c ∧ ∃ u, rep c = Sum.inl u) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × Q),
        GkatKleene.firstMatch W x (Qsys.trans c) = some r →
          (¬ B r.2 ∧ ∃ u, rep r.2 = Sum.inl u) := by
  intro c hc X W x r hfm
  obtain ⟨hcB, u, hcu⟩ := hc
  obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x (Qsys.trans c) r.1 r.2 (by rw [← hfm])
  rw [htrans c hcB, hcu] at hg
  simp only [List.mem_map] at hg
  obtain ⟨z, hz, hzeq⟩ := hg
  have hz' : z ∈ (L.trans u).map (fun w => (w.1, w.2.1, Sum.inl w.2.2)) := hz
  simp only [List.mem_map] at hz'
  obtain ⟨w, _, rfl⟩ := hz'
  have hr2 : r.2 = j (Sum.inl w.2.2) := (congrArg (fun y => y.2.2) hzeq).symm
  rw [hr2]
  exact ⟨hout _, hpref _ w.2.2 rfl⟩

#print axioms sum_left_block_closed


/-- **THE `ite` CASE, ASSEMBLED.**  Split at the left branch's classes; the two
    obligations are then the recursive calls on `e` and `f`.  Note which block
    each receives: the LEFT call is given "everything that is not a left class",
    so its own image is exactly `e`'s classes; the RIGHT call is given `B`
    TOGETHER WITH the left classes, which is what makes it a call about `f`
    alone.  That asymmetry is the split, and it is why the recursion descends. -/
theorem quotient_layered_ite {S₁ S₂ Q : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : Sum S₁ S₂ → Q) (rep : Q → Sum S₁ S₂)
    (hout : ∀ s, ¬ B (j s))
    (hpref : ∀ (c : Q) (u : S₁), j (Sum.inl u) = c → ∃ v, rep c = Sum.inl v)
    (htrans : ∀ c, ¬ B c → Qsys.trans c
      = ((GkatThompson.sumGSystem L R).trans (rep c)).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    (hleft : LayeredOn Qsys (fun c => ¬ (¬ B c ∧ ∃ u, rep c = Sum.inl u)))
    (hright : LayeredOn Qsys (fun c => B c ∨ (¬ B c ∧ ∃ u, rep c = Sum.inl u))) :
    LayeredOn Qsys B :=
  LayeredOn.split (fun _ hB hC => hC.1 hB)
    (fun c hc X W x r hfm =>
      Or.inl (sum_left_block_closed L R Qsys B j rep hout hpref htrans c hc X W x r hfm))
    hleft hright

#print axioms quotient_layered_ite


/-! ### 305 — THE PREFERENCE DIRECTION IS FORCED, AND ONE LEMMA SERVES BOTH CASES

    304 split `ite` at the LEFT branch, using a representative that prefers
    `inl`.  The `seq` case cannot do that: **only a sequence's RIGHT half is
    closed** — the left half runs into the right through the connecting block —
    so a sequence must split at its right classes, which needs a representative
    preferring `inr`.

    A representative is GLOBAL to the quotient, so the two preferences cannot
    both hold at the same node.  They do not have to: `ite`'s halves are BOTH
    closed, so `ite` may split either way, while `seq` may not.  **The uniform
    choice is therefore forced to `inr`**, and 304's left-handed version becomes
    an alternative rather than the main line.

    (The preference is still per-node, not per-quotient: at an inner node it
    ranks that node's own two halves.  A single global representative satisfies
    all of them at once by ranking the expression tree's LEAVES — right before
    left, consistently — which is a construction to discharge later, not an
    obstruction.)

    Stated once, for any system whose `inr` transitions are the right
    component's retargeted — which is true of `sumGSystem` and `seqGSystem`
    alike, both by `rfl`. -/
theorem right_block_closed {S₁ S₂ Q : Type}
    (sys : GkatThompson.GSystem (Sum S₁ S₂) A T)
    (Rt : S₂ → List (BExp T × A × S₂))
    (hinr : ∀ t, sys.trans (Sum.inr t)
      = (Rt t).map (fun w => (w.1, w.2.1, Sum.inr w.2.2)))
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : Sum S₁ S₂ → Q) (rep : Q → Sum S₁ S₂)
    (hout : ∀ s, ¬ B (j s))
    (hpref : ∀ (c : Q) (u : S₂), j (Sum.inr u) = c → ∃ v, rep c = Sum.inr v)
    (htrans : ∀ c, ¬ B c → Qsys.trans c
      = (sys.trans (rep c)).map (fun tr => (tr.1, tr.2.1, j tr.2.2))) :
    ∀ c, (¬ B c ∧ ∃ u, rep c = Sum.inr u) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × Q),
        GkatKleene.firstMatch W x (Qsys.trans c) = some r →
          (¬ B r.2 ∧ ∃ u, rep r.2 = Sum.inr u) := by
  intro c hc X W x r hfm
  obtain ⟨hcB, u, hcu⟩ := hc
  obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x (Qsys.trans c) r.1 r.2 (by rw [← hfm])
  rw [htrans c hcB, hcu, hinr u] at hg
  simp only [List.mem_map] at hg
  obtain ⟨z, hz, hzeq⟩ := hg
  obtain ⟨w, _, rfl⟩ := hz
  have hr2 : r.2 = j (Sum.inr w.2.2) := (congrArg (fun y => y.2.2) hzeq).symm
  rw [hr2]
  exact ⟨hout _, hpref _ w.2.2 rfl⟩

/-- **THE SPLIT AT THE RIGHT CLASSES**, serving `ite` and `seq` alike.  For
    `seq` this is the FORCED order: the connecting block's entry points at the
    right classes, and `LayeredOn.seq` demands a layer's entry point INTO the
    block — so the right part must join the block BEFORE the layer is peeled. -/
theorem quotient_layered_split_right {S₁ S₂ Q : Type}
    (sys : GkatThompson.GSystem (Sum S₁ S₂) A T)
    (Rt : S₂ → List (BExp T × A × S₂))
    (hinr : ∀ t, sys.trans (Sum.inr t)
      = (Rt t).map (fun w => (w.1, w.2.1, Sum.inr w.2.2)))
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : Sum S₁ S₂ → Q) (rep : Q → Sum S₁ S₂)
    (hout : ∀ s, ¬ B (j s))
    (hpref : ∀ (c : Q) (u : S₂), j (Sum.inr u) = c → ∃ v, rep c = Sum.inr v)
    (htrans : ∀ c, ¬ B c → Qsys.trans c
      = (sys.trans (rep c)).map (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    (hright : LayeredOn Qsys (fun c => ¬ (¬ B c ∧ ∃ u, rep c = Sum.inr u)))
    (hleft : LayeredOn Qsys (fun c => B c ∨ (¬ B c ∧ ∃ u, rep c = Sum.inr u))) :
    LayeredOn Qsys B :=
  LayeredOn.split (fun _ hB hC => hC.1 hB)
    (fun c hc X W x r hfm =>
      Or.inl (right_block_closed sys Rt hinr Qsys B j rep hout hpref htrans
        c hc X W x r hfm))
    hright hleft

#print axioms right_block_closed
#print axioms quotient_layered_split_right


section QuotientLayeredSeq
open Classical

private theorem seq_gate_comm {S₁ S₂ S' : Type} (H : BExp T) (j : Sum S₁ S₂ → S') :
    ∀ l : List (BExp T × A × S₂),
      (l.map (fun tr => (BExp.and H tr.1, tr.2.1, Sum.inr tr.2.2))).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))
        = (l.map (fun tr => (tr.1, tr.2.1, j (Sum.inr tr.2.2)))).map
            (fun tr => (BExp.and H tr.1, tr.2))
  | [] => rfl
  | a :: t => by
      show (BExp.and H a.1, a.2.1, j (Sum.inr a.2.2)) :: _
        = (BExp.and H a.1, a.2.1, j (Sum.inr a.2.2)) :: _
      rw [seq_gate_comm H j t]

/-! ### 306 — THE `seq` LAYER STEP.  THE FIFTH CASE.

    After 305's split has put the right classes into the block, what is left is
    to peel the connecting block.  The construction mirrors 303's `wh` exactly:
    **the base system downstairs is BUILT, not assumed** — off the block it is
    the DISJOINT UNION `sumGSystem L R.core` read through the representative, on
    the block it is whatever `Qsys` already had — so `SeqLayer`'s `outside`
    clause holds by construction and the layer is confined to the image.

    That the base is the disjoint union is 289's observation doing its work:
    **a sequence is a layer over the sum of its halves**, so removing the layer
    leaves an `ite`-shaped node, and the recursion continues on `e` with the
    right classes already in the block.

    The entry targets land in the block for the reason 305 arranged: they are
    `R`'s initial targets, so their classes have `inr` preimages, and the
    preferring representative puts them in the right-class block. -/
theorem quotient_layered_seq_left {S₁ S₂ Q : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T)
    (Qsys : GkatThompson.GSystem Q A T) (P : Q → Prop)
    (j : Sum S₁ S₂ → Q) (rep : Q → Sum S₁ S₂)
    (hinl : ∀ c, ¬ P c → ∃ u, rep c = Sum.inl u)
    (hentryP : ∀ tr ∈ R.initTrans, P (j (Sum.inr tr.2.2)))
    (htrans : ∀ c, ¬ P c → Qsys.trans c
      = ((GkatThompson.seqGSystem L R).trans (rep c)).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    (hhlt : ∀ c, ¬ P c → Qsys.hlt c
      = (GkatThompson.seqGSystem L R).hlt (rep c))
    (ih : ∀ base : GkatThompson.GSystem Q A T,
      (∀ c, ¬ P c → base.trans c
        = ((GkatThompson.sumGSystem L R.core).trans (rep c)).map
            (fun tr => (tr.1, tr.2.1, j tr.2.2))) →
      (∀ c, ¬ P c → base.hlt c
        = (GkatThompson.sumGSystem L R.core).hlt (rep c)) →
      LayeredOn base P) :
    LayeredOn Qsys P := by
  refine LayeredOn.seq
    (base := ⟨Qsys.states,
      fun c => if P c then Qsys.hlt c
        else (GkatThompson.sumGSystem L R.core).hlt (rep c),
      fun c => if P c then Qsys.trans c
        else ((GkatThompson.sumGSystem L R.core).trans (rep c)).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))⟩)
    (h₀ := R.initHlt)
    (entry := R.initTrans.map (fun tr => (tr.1, tr.2.1, j (Sum.inr tr.2.2))))
    ⟨?_, ?_, ?_, rfl⟩ ?_ (ih _ ?_ ?_)
  · -- trans_eq
    intro c hc
    obtain ⟨u, hu⟩ := hinl c hc
    show Qsys.trans c = (if P c then _ else _) ++ _
    simp only [if_neg hc]
    rw [htrans c hc, hu]
    show ((L.trans u).map (fun tr : BExp T × A × S₁ => (tr.1, tr.2.1, Sum.inl tr.2.2)) ++
        R.initTrans.map (fun tr : BExp T × A × S₂ =>
          (BExp.and (L.hlt u) tr.1, tr.2.1, Sum.inr tr.2.2))).map
          (fun tr : BExp T × A × Sum S₁ S₂ => (tr.1, tr.2.1, j tr.2.2))
      = ((L.trans u).map (fun tr : BExp T × A × S₁ => (tr.1, tr.2.1, Sum.inl tr.2.2))).map
          (fun tr : BExp T × A × Sum S₁ S₂ => (tr.1, tr.2.1, j tr.2.2)) ++ _
    refine Eq.trans (map_append' _ _ _) ?_
    congr 1
    exact seq_gate_comm _ _ _
  · -- hlt_eq
    intro c hc
    obtain ⟨u, hu⟩ := hinl c hc
    show Qsys.hlt c = BExp.and (if P c then _ else _) _
    simp only [if_neg hc]
    rw [hhlt c hc, hu]
    rfl
  · -- outside
    intro c hc
    exact ⟨by show Qsys.trans c = (if P c then _ else _); rw [if_pos (Classical.not_not.mp hc)],
      by show Qsys.hlt c = (if P c then _ else _); rw [if_pos (Classical.not_not.mp hc)]⟩
  · -- entry targets lie in the block
    intro tr htr
    simp only [List.mem_map] at htr
    obtain ⟨t, ht, rfl⟩ := htr
    exact hentryP t ht
  · intro c hc; show (if P c then _ else _) = _; rw [if_neg hc]
  · intro c hc; show (if P c then _ else _) = _; rw [if_neg hc]

#print axioms quotient_layered_seq_left

end QuotientLayeredSeq


section QuotientLayeredWitness
open Classical

/-! ### 307 — 303's SHAPE CANNOT BE INSTANTIATED.  USE A WITNESS, NOT A FUNCTION.

    **A defect found by trying to construct the representative.**  303 gave each
    case a total `rep : Q → State`.  For `test` the state type is `Empty`, so
    supplying such a function REQUIRES `Q` ITSELF TO BE EMPTY.
    `quotient_layered_test`'s proof is correct and its statement is true, and it
    can never be applied to anything.  The same defect blocks every recursive
    call whose sub-expression has no states.

    That is why the "leaf ordering" of 305 kept feeling heavier than it should:
    it was trying to build a total function into a type that may be empty.

    **The fix is to ask for a WITNESS PER CLASS instead of a function.**  The
    hypothesis becomes "for every class outside the block there EXISTS a state
    whose dynamics it carries" — which is what a quotient actually provides, and
    which needs no inhabitant when there are no classes to witness.  `test` then
    proves itself: a class outside the block would produce an element of
    `Empty`.

    **And the preference becomes a property of the witness rather than of a
    global choice function**, which is what dissolves 305's obligation: each
    node picks its own witness, and "prefer `inr`" is a condition on that pick,
    not on one function serving every node at once. -/
theorem quotient_layered_test' (t : BExp T) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T (.test t)).State → Q)
    (hwit : ∀ c, ¬ B c → ∃ s, Qsys.trans c
      = ((GkatThompson.certifiedThompson A T (.test t)).aut.core.trans s).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))) :
    LayeredOn Qsys B :=
  LayeredOn.acyclic ⟨fun _ => 0, fun c hc => (hwit c hc).elim (fun s _ => nomatch s)⟩

theorem quotient_layered_act' (a : A) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T (.act a)).State → Q)
    (hwit : ∀ c, ¬ B c → ∃ s, Qsys.trans c
      = ((GkatThompson.certifiedThompson A T (.act a)).aut.core.trans s).map
          (fun tr => (tr.1, tr.2.1, j tr.2.2))) :
    LayeredOn Qsys B := by
  refine LayeredOn.acyclic ⟨fun _ => 0, ?_⟩
  intro c hc X W x r hfm
  obtain ⟨s, hs⟩ := hwit c hc
  rw [hs] at hfm
  have hnil : (GkatThompson.certifiedThompson A T (.act a)).aut.core.trans s = [] := rfl
  rw [hnil] at hfm
  exact absurd hfm (by simp [GkatKleene.firstMatch])

#print axioms quotient_layered_test'
#print axioms quotient_layered_act'

end QuotientLayeredWitness


/-! ### 308 — THE SPLIT IN WITNESS FORM, AND A BETTER BLOCK

    Migrating 305's split to 307's witness form does more than remove the
    unusable `rep`.  With a representative, the block had to be stated as "the
    representative is `inr`" — a fact about a CHOICE.  With witnesses it becomes

        the class HAS an `inr` preimage

    which is a fact about the QUOTIENT, needs no choice function, and is
    manifestly a union of classes.  The preference likewise stops being a
    property of a global function and becomes a hypothesis about what witnesses
    the dynamics: **if a class has an `inr` preimage, then its dynamics is
    witnessed by an `inr` state.**  That is a condition one can actually verify
    of a quotient one is building, which the `rep`-based version never was. -/
theorem right_block_closed' {S₁ S₂ Q : Type}
    (sys : GkatThompson.GSystem (Sum S₁ S₂) A T)
    (Rt : S₂ → List (BExp T × A × S₂))
    (hinr : ∀ t, sys.trans (Sum.inr t)
      = (Rt t).map (fun w => (w.1, w.2.1, Sum.inr w.2.2)))
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : Sum S₁ S₂ → Q)
    (hout : ∀ s, ¬ B (j s))
    (hwitR : ∀ c, ¬ B c → (∃ u : S₂, j (Sum.inr u) = c) →
      ∃ t : S₂, Qsys.trans c
        = (sys.trans (Sum.inr t)).map (fun tr => (tr.1, tr.2.1, j tr.2.2))) :
    ∀ c, (¬ B c ∧ ∃ u : S₂, j (Sum.inr u) = c) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × Q),
        GkatKleene.firstMatch W x (Qsys.trans c) = some r →
          (¬ B r.2 ∧ ∃ u : S₂, j (Sum.inr u) = r.2) := by
  intro c hc X W x r hfm
  obtain ⟨hcB, hpre⟩ := hc
  obtain ⟨t, ht⟩ := hwitR c hcB hpre
  obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x (Qsys.trans c) r.1 r.2 (by rw [← hfm])
  rw [ht, hinr t] at hg
  simp only [List.mem_map] at hg
  obtain ⟨z, hz, hzeq⟩ := hg
  obtain ⟨w, _, rfl⟩ := hz
  have hr2 : r.2 = j (Sum.inr w.2.2) := (congrArg (fun y => y.2.2) hzeq).symm
  exact ⟨by rw [hr2]; exact hout _, ⟨w.2.2, hr2.symm⟩⟩

/-- **THE SPLIT, IN WITNESS FORM.**  Serves `ite` and `seq` alike, and is now
    applicable: nothing in it demands a function into a possibly-empty type. -/
theorem quotient_layered_split_right' {S₁ S₂ Q : Type}
    (sys : GkatThompson.GSystem (Sum S₁ S₂) A T)
    (Rt : S₂ → List (BExp T × A × S₂))
    (hinr : ∀ t, sys.trans (Sum.inr t)
      = (Rt t).map (fun w => (w.1, w.2.1, Sum.inr w.2.2)))
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : Sum S₁ S₂ → Q)
    (hout : ∀ s, ¬ B (j s))
    (hwitR : ∀ c, ¬ B c → (∃ u : S₂, j (Sum.inr u) = c) →
      ∃ t : S₂, Qsys.trans c
        = (sys.trans (Sum.inr t)).map (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    (hright : LayeredOn Qsys (fun c => ¬ (¬ B c ∧ ∃ u : S₂, j (Sum.inr u) = c)))
    (hleft : LayeredOn Qsys
      (fun c => B c ∨ (¬ B c ∧ ∃ u : S₂, j (Sum.inr u) = c))) :
    LayeredOn Qsys B :=
  LayeredOn.split (fun _ hB hC => hC.1 hB)
    (fun c hc X W x r hfm =>
      Or.inl (right_block_closed' sys Rt hinr Qsys B j hout hwitR c hc X W x r hfm))
    hright hleft

#print axioms right_block_closed'
#print axioms quotient_layered_split_right'


section QuotientLayeredWhWitness
open Classical

/-! ### 309 — `wh` IN WITNESS FORM

    The construction of 303 survives the migration unchanged in spirit: the base
    system downstairs is still BUILT rather than assumed, so `LoopLayerOn`'s
    `outside` clause holds by construction.  What changes is what it is built
    FROM — a `dite` on the class lying outside the block, whose positive branch
    has the very proof it needs to name the witness.  That is the shape 307's
    fix makes available and the `rep` version could not express: the witness
    exists only where there is something to witness.

    Note the two uses of the SAME witness — transitions and halt — which is why
    `hwit` must package them in one existential.  Splitting it into two
    existentials would let the halt come from a different state than the
    transitions, and the layer's halt equation would then be about the wrong
    automaton. -/
theorem quotient_layered_wh' (b : BExp T) (e : Exp A T) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T e).State → Q)
    (hout : ∀ s, ¬ B (j s))
    (hwit : ∀ c, ¬ B c → ∃ s, Qsys.trans c
        = ((GkatThompson.certifiedThompson A T (.wh b e)).aut.core.trans s).map
            (fun tr => (tr.1, tr.2.1, j tr.2.2))
      ∧ Qsys.hlt c = (GkatThompson.certifiedThompson A T (.wh b e)).aut.core.hlt s)
    (ih : ∀ base : GkatThompson.GSystem Q A T,
      (∀ c, ¬ B c → ∃ s, base.trans c
          = ((GkatThompson.certifiedThompson A T e).aut.core.trans s).map
              (fun tr => (tr.1, tr.2.1, j tr.2.2))
        ∧ base.hlt c = (GkatThompson.certifiedThompson A T e).aut.core.hlt s) →
      LayeredOn base B) :
    LayeredOn Qsys B := by
  refine LayeredOn.loop
    (base := ⟨Qsys.states,
      fun c => if h : ¬ B c then
          (GkatThompson.certifiedThompson A T e).aut.core.hlt
            (Classical.choose (hwit c h))
        else Qsys.hlt c,
      fun c => if h : ¬ B c then
          ((GkatThompson.certifiedThompson A T e).aut.core.trans
            (Classical.choose (hwit c h))).map (fun tr => (tr.1, tr.2.1, j tr.2.2))
        else Qsys.trans c⟩)
    (b := b)
    (entry := (GkatThompson.certifiedThompson A T e).aut.initTrans.map
      (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    ⟨?_, ?_, ?_, rfl⟩ ?_ ?_ (ih _ ?_)
  · -- trans_eq
    intro c hc
    have hs := (Classical.choose_spec (hwit c hc)).1
    show Qsys.trans c = (dite _ _ _) ++ _
    simp only [dif_pos hc]
    refine Eq.trans hs ?_
    refine Eq.trans (congrArg (List.map (fun tr => (tr.1, tr.2.1, j tr.2.2)))
      (loop_core_trans b e _)) ?_
    refine Eq.trans (map_append' _ _ _) ?_
    congr 1
    exact gate_map_comm _ _ _ _
  · -- hlt_eq
    intro c hc X W x
    have hh := (Classical.choose_spec (hwit c hc)).2
    show GkatGS.bval W (Qsys.hlt c) x = (GkatGS.bval W (dite _ _ _) x && _)
    simp only [dif_pos hc]
    refine Eq.trans (congrArg (fun z => GkatGS.bval W z x) hh) ?_
    exact congrArg (fun z => GkatGS.bval W z x) (loop_core_hlt b e _)
  · -- outside
    intro c hc
    exact ⟨by show Qsys.trans c = dite _ _ _; rw [dif_neg hc],
      by show Qsys.hlt c = dite _ _ _; rw [dif_neg hc]⟩
  · -- entry targets outside the block
    intro tr htr
    simp only [List.mem_map] at htr
    obtain ⟨t, _, rfl⟩ := htr
    exact Or.inl (hout t.2.2)
  · -- base targets outside the block
    intro c hc tr htr
    simp only [dif_pos hc, List.mem_map] at htr
    obtain ⟨t, _, rfl⟩ := htr
    exact Or.inl (hout t.2.2)
  · -- the recursive hypothesis' data
    intro c hc
    exact ⟨Classical.choose (hwit c hc),
      by show dite _ _ _ = _; rw [dif_pos hc],
      by show dite _ _ _ = _; rw [dif_pos hc]⟩

#print axioms quotient_layered_wh'

end QuotientLayeredWhWitness


section QuotientLayeredSeqWitness
open Classical

/-! ### 310 — `seq` IN WITNESS FORM.  THE MIGRATION IS COMPLETE.

    The last case.  One thing gets SIMPLER in the migration and is worth saying:
    the `rep` version needed a separate hypothesis `hinl` saying the
    representative of a non-block class is a left state.  In witness form that
    hypothesis disappears into the witness's TYPE — the witness is drawn from
    `S₁` directly.  It is justified for the same reason it was assumed: the
    block already contains every right class (305's split ran first), so a class
    outside it has no right preimage at all.

    A hypothesis that becomes a type is a hypothesis that can no longer be
    forgotten at a call site, which is the second thing 307's shape bought. -/
theorem quotient_layered_seq_left' {S₁ S₂ Q : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.InitializedGAut S₂ A T)
    (Qsys : GkatThompson.GSystem Q A T) (P : Q → Prop)
    (j : Sum S₁ S₂ → Q)
    (hentryP : ∀ tr ∈ R.initTrans, P (j (Sum.inr tr.2.2)))
    (hwit : ∀ c, ¬ P c → ∃ u : S₁, Qsys.trans c
        = ((GkatThompson.seqGSystem L R).trans (Sum.inl u)).map
            (fun tr => (tr.1, tr.2.1, j tr.2.2))
      ∧ Qsys.hlt c = (GkatThompson.seqGSystem L R).hlt (Sum.inl u))
    (ih : ∀ base : GkatThompson.GSystem Q A T,
      (∀ c, ¬ P c → ∃ u : S₁, base.trans c
          = ((GkatThompson.sumGSystem L R.core).trans (Sum.inl u)).map
              (fun tr => (tr.1, tr.2.1, j tr.2.2))
        ∧ base.hlt c = (GkatThompson.sumGSystem L R.core).hlt (Sum.inl u)) →
      LayeredOn base P) :
    LayeredOn Qsys P := by
  refine LayeredOn.seq
    (base := ⟨Qsys.states,
      fun c => if h : ¬ P c then
          (GkatThompson.sumGSystem L R.core).hlt
            (Sum.inl (Classical.choose (hwit c h)))
        else Qsys.hlt c,
      fun c => if h : ¬ P c then
          ((GkatThompson.sumGSystem L R.core).trans
            (Sum.inl (Classical.choose (hwit c h)))).map
              (fun tr => (tr.1, tr.2.1, j tr.2.2))
        else Qsys.trans c⟩)
    (h₀ := R.initHlt)
    (entry := R.initTrans.map (fun tr => (tr.1, tr.2.1, j (Sum.inr tr.2.2))))
    ⟨?_, ?_, ?_, rfl⟩ ?_ (ih _ ?_)
  · -- trans_eq
    intro c hc
    show Qsys.trans c = (dite _ _ _) ++ _
    simp only [dif_pos hc]
    refine Eq.trans (Classical.choose_spec (hwit c hc)).1 ?_
    show ((L.trans (Classical.choose (hwit c hc))).map
          (fun tr : BExp T × A × S₁ => (tr.1, tr.2.1, Sum.inl tr.2.2)) ++
        R.initTrans.map (fun tr : BExp T × A × S₂ =>
          (BExp.and (L.hlt (Classical.choose (hwit c hc))) tr.1,
            tr.2.1, Sum.inr tr.2.2))).map
          (fun tr : BExp T × A × Sum S₁ S₂ => (tr.1, tr.2.1, j tr.2.2))
      = ((L.trans (Classical.choose (hwit c hc))).map
          (fun tr : BExp T × A × S₁ => (tr.1, tr.2.1, Sum.inl tr.2.2))).map
          (fun tr : BExp T × A × Sum S₁ S₂ => (tr.1, tr.2.1, j tr.2.2)) ++ _
    refine Eq.trans (map_append' _ _ _) ?_
    congr 1
    exact seq_gate_comm _ _ _
  · -- hlt_eq
    intro c hc
    show Qsys.hlt c = BExp.and (dite _ _ _) _
    simp only [dif_pos hc]
    exact (Classical.choose_spec (hwit c hc)).2
  · -- outside
    intro c hc
    exact ⟨by show Qsys.trans c = dite _ _ _; rw [dif_neg hc],
      by show Qsys.hlt c = dite _ _ _; rw [dif_neg hc]⟩
  · -- entry targets lie in the block
    intro tr htr
    simp only [List.mem_map] at htr
    obtain ⟨t, ht, rfl⟩ := htr
    exact hentryP t ht
  · -- the recursive hypothesis' data
    intro c hc
    exact ⟨Classical.choose (hwit c hc),
      by show dite _ _ _ = _; rw [dif_pos hc],
      by show dite _ _ _ = _; rw [dif_pos hc]⟩

#print axioms quotient_layered_seq_left'

end QuotientLayeredSeqWitness


/-! ### 311 — THE PREFERENCE HYPOTHESIS IS UNNECESSARY

    305 introduced a PREFERRING representative so that the block "the class is a
    right class" would be closed, and 308 kept it as a condition on the witness.
    **Neither is needed.**

    The block downstairs is "the class HAS an `inr` preimage" — and that is
    exactly the SATURATION of "is `inr`", whose closure 299 already proved from
    the BISIMULATION.  The bisimulation is a hypothesis the acyclic case (297)
    needs regardless, so this costs nothing new and removes a hypothesis that
    had to be threaded through every node.

    The argument downstairs: a class with an `inr` preimage `u` has its dynamics
    witnessed by SOME preimage `s`, possibly a left one.  It does not matter.
    `u` and `s` are in the same class, so the bisimulation gives `u` a matching
    step; the right half is closed upstairs, so `u`'s step lands in the right
    half; and the two steps agree after `j`.  So the target class has an `inr`
    preimage — established without ever asking which preimage the quotient chose.

    **This is what 305's "leaf ordering" obligation really was**: an artefact of
    insisting the block be about a CHOICE rather than about the quotient.  307
    made the block about the quotient; 311 removes the last trace of the choice. -/
theorem right_block_closed_bisim {S₁ S₂ Q : Type}
    (sys : GkatThompson.GSystem (Sum S₁ S₂) A T)
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : Sum S₁ S₂ → Q)
    (hout : ∀ s, ¬ B (j s))
    (hbisim : ∀ s t : Sum S₁ S₂, j s = j t →
      ∀ (X : Type) (W : T → X → Bool) (x : X),
      (GkatKleene.firstMatch W x (sys.trans s)).map (fun z => (z.1, j z.2))
        = (GkatKleene.firstMatch W x (sys.trans t)).map (fun z => (z.1, j z.2)))
    (hclosedR : ∀ (u : S₂) (X : Type) (W : T → X → Bool) (x : X)
        (r : A × Sum S₁ S₂),
      GkatKleene.firstMatch W x (sys.trans (Sum.inr u)) = some r →
        ∃ v : S₂, r.2 = Sum.inr v)
    (hwit : ∀ c, ¬ B c → ∃ s, j s = c ∧ Qsys.trans c
      = (sys.trans s).map (fun tr => (tr.1, tr.2.1, j tr.2.2))) :
    ∀ c, (¬ B c ∧ ∃ u : S₂, j (Sum.inr u) = c) →
      ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × Q),
        GkatKleene.firstMatch W x (Qsys.trans c) = some r →
          (¬ B r.2 ∧ ∃ u : S₂, j (Sum.inr u) = r.2) := by
  intro c hc X W x r hfm
  obtain ⟨hcB, u, hu⟩ := hc
  obtain ⟨s, hjs, hts⟩ := hwit c hcB
  rw [hts, firstMatch_map] at hfm
  cases hq : GkatKleene.firstMatch W x (sys.trans s) with
  | none => rw [hq] at hfm; exact absurd hfm (by simp)
  | some q =>
      rw [hq] at hfm
      have hr : r = (q.1, j q.2) := (Option.some.inj (by simpa using hfm)).symm
      have hb := hbisim (Sum.inr u) s (by rw [hu, hjs]) X W x
      rw [hq] at hb
      cases hq' : GkatKleene.firstMatch W x (sys.trans (Sum.inr u)) with
      | none => rw [hq'] at hb; exact absurd hb (by simp)
      | some q' =>
          rw [hq'] at hb
          obtain ⟨v, hv⟩ := hclosedR u X W x q' hq'
          have hb' : q'.1 = q.1 ∧ j q'.2 = j q.2 := by simpa using hb
          have hjeq : j q'.2 = j q.2 := hb'.2
          refine ⟨by rw [hr]; exact hout _, ⟨v, ?_⟩⟩
          rw [hr]
          show j (Sum.inr v) = j q.2
          rw [← hv]
          exact hjeq

#print axioms right_block_closed_bisim


/-! ### 312 — `hbisim` TRANSPORTS THROUGH `ite`, AND NOT THROUGH `wh` OR `seq`

    Assembling the induction, `hbisim` is needed at each `ite`/`seq` node by
    311, and the recursive calls need it for the SUB-automata.  So the question
    is whether it transports, and the answer splits.

    **Through `ite` it does, and the reason is that a SUM CHANGES NOTHING.**  A
    left state's transitions in `sumGSystem L R` are exactly `L`'s, retargeted;
    so agreeing in the sum is agreeing in `L`.  That is this theorem.

    **Through `wh` and `seq` it does NOT**, for the same reason in both: those
    constructors ADD transitions to the sub-automaton — back edges for `wh`, the
    entry block for `seq` — and behaviour in the WHOLE can agree where behaviour
    in the PART does not.  Concretely for `seq`: let `s, t` be left states with
    `j (inl s) = j (inl t)`.  Suppose `L` fires at `s` and not at `t`, and `t`
    instead takes an `R`-entry step whose target lands in the same class as
    `s`'s target.  Then the two agree in `seqGSystem` and differ in `L` — `s`
    steps, `t` does not.  This needs an `L`-state and an `R`-state to be
    bisimilar, which nothing forbids.  `wh` is the same with back edges in place
    of the entry block.

    **So the induction cannot carry `hbisim` for `g` alone.**  The candidate fix
    is to carry it for EVERY SUB-AUTOMATON — a predicate `BisimAll g j` defined
    by recursion on `g`, conjoining each node's own `hbisim` with those of its
    children.  That is definable and each case can destruct it; the cost moves
    to the FINAL application, which must then supply a quotient respecting every
    sub-automaton's bisimilarity while still identifying the two start states.
    Whether such a quotient exists is the next real question, and it is a
    genuine one — this is 298's second obstruction, which the move downstairs
    did not remove but did localise. -/
theorem sum_bisim_restrict {S₁ S₂ Q : Type}
    (L : GkatThompson.GSystem S₁ A T) (R : GkatThompson.GSystem S₂ A T)
    (j : Sum S₁ S₂ → Q)
    (hbisim : ∀ s t : Sum S₁ S₂, j s = j t →
      ∀ (X : Type) (W : T → X → Bool) (x : X),
      (GkatKleene.firstMatch W x ((GkatThompson.sumGSystem L R).trans s)).map
          (fun z => (z.1, j z.2))
        = (GkatKleene.firstMatch W x ((GkatThompson.sumGSystem L R).trans t)).map
          (fun z => (z.1, j z.2))) :
    ∀ s t : S₁, j (Sum.inl s) = j (Sum.inl t) →
      ∀ (X : Type) (W : T → X → Bool) (x : X),
      (GkatKleene.firstMatch W x (L.trans s)).map
          (fun z => (z.1, j (Sum.inl z.2)))
        = (GkatKleene.firstMatch W x (L.trans t)).map
          (fun z => (z.1, j (Sum.inl z.2))) := by
  intro s t hst X W x
  have h := hbisim (Sum.inl s) (Sum.inl t) hst X W x
  have hs' : (GkatThompson.sumGSystem L R).trans (Sum.inl s)
      = (L.trans s).map (fun w => (w.1, w.2.1, Sum.inl w.2.2)) := rfl
  have ht' : (GkatThompson.sumGSystem L R).trans (Sum.inl t)
      = (L.trans t).map (fun w => (w.1, w.2.1, Sum.inl w.2.2)) := rfl
  rw [hs', ht', firstMatch_map, firstMatch_map] at h
  cases hs : GkatKleene.firstMatch W x (L.trans s) with
  | none =>
      cases ht : GkatKleene.firstMatch W x (L.trans t) with
      | none => rfl
      | some q => rw [hs, ht] at h; exact absurd h (by simp)
  | some p =>
      cases ht : GkatKleene.firstMatch W x (L.trans t) with
      | none => rw [hs, ht] at h; exact absurd h (by simp)
      | some q =>
          rw [hs, ht] at h
          simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at h ⊢
          exact h

#print axioms sum_bisim_restrict


/-! ### 313 — HOW NARROW 312's CORNER ACTUALLY IS

    312 said `hbisim` does not transport through `wh` or `seq`.  True, but the
    statement was looser than the facts, and the correction matters because it
    is the difference between "usually broken" and "broken only in a corner one
    can hope to rule out".

    **A layer's added transitions come AFTER the sub-automaton's.**  Both
    `loop_core_trans` and `seqGSystem` append the entry block to the component's
    own list, and `firstMatch` scans in order.  So **wherever the component
    FIRES, the composite takes the component's step, unchanged** — that is this
    lemma, and it holds with no hypothesis about halts or guards at all.

    So a divergence between "bisimilar in the whole" and "bisimilar in the part"
    cannot happen at a world where BOTH states' components fire: there the two
    behaviours are literally the same steps.  It requires a world where one
    component fires and the OTHER does not, and where the second state's ENTRY
    step matches the first's component step in BOTH action and target class.

    That is a much narrower requirement than 312 stated, and it is the kind of
    coincidence that a structural property of Thompson automata might exclude.
    Whether it does is now a sharp, checkable question rather than a worry. -/
theorem firstMatch_append_left {S X : Type} (W : T → X → Bool) (x : X)
    (l₂ : List (BExp T × A × S)) (r : A × S) :
    ∀ l₁ : List (BExp T × A × S),
      GkatKleene.firstMatch W x l₁ = some r →
      GkatKleene.firstMatch W x (l₁ ++ l₂) = some r
  | [], h => by exact absurd h (by simp [GkatKleene.firstMatch])
  | tr :: tl, h => by
      obtain ⟨g, a, t⟩ := tr
      cases hb : GkatGS.bval W g x
      · simp only [List.cons_append, GkatKleene.firstMatch, hb, if_neg]
        simp only [GkatKleene.firstMatch, hb, if_neg] at h
        exact firstMatch_append_left W x l₂ r tl h
      · simp only [List.cons_append, GkatKleene.firstMatch, hb, if_pos]
        simp only [GkatKleene.firstMatch, hb, if_pos] at h
        exact h

/-- **WHERE THE BODY FIRES, THE LOOP TAKES THE BODY'S STEP.**  No hypothesis
    about halts or guards — the back edges are simply LATER in the list. -/
theorem wh_step_eq_body_step (b : BExp T) (e : Exp A T)
    (s : (GkatThompson.certifiedThompson A T e).State)
    {X : Type} (W : T → X → Bool) (x : X)
    (r : A × (GkatThompson.certifiedThompson A T e).State)
    (h : GkatKleene.firstMatch W x
      ((GkatThompson.certifiedThompson A T e).aut.core.trans s) = some r) :
    GkatKleene.firstMatch W x
      ((GkatThompson.certifiedThompson A T (.wh b e)).aut.core.trans s) = some r := by
  rw [loop_core_trans b e s]
  exact firstMatch_append_left W x _ r _ h

#print axioms firstMatch_append_left
#print axioms wh_step_eq_body_step


/-! ### 315 — 311 WAS A REGRESSION.  THE PREFERENCE ROUTE IS BISIMULATION-FREE.

    311 removed 305/308's PREFERENCE hypothesis by proving the split's closure
    from the BISIMULATION instead.  That looked like a simplification.  314
    measured what it cost: `hbisim` does not transport from a composite to its
    components, and fails at TWO STATES, so a route that needs `hbisim` at every
    node of a recursion over sub-expressions cannot work.

    **Preference needs no transport, because it is not a property the quotient
    must happen to have — it is a property of the WITNESS WE CHOOSE.**  The
    quotient's dynamics at a class is DEFINED from a witness, and every preimage
    of a class is behaviourally equivalent, so any choice yields a correct
    quotient.  We are free to choose the witness, and choosing it right is a
    construction rather than a hope.

    **And the whole construction reduces to this.**  Weight the states so that
    at the node in question every RIGHT state outweighs every LEFT state; take
    the witness of maximal weight in its class; then a class containing a right
    state has a right witness.  That is the entire content of 305's "leaf
    ordering" — the rest is arranging such a weight by recursion on the
    expression, and the recursion is available because a class whose witness is
    LEFT has ALL its members left (otherwise the maximum would be right), so
    inside the left half the order restricts to the left half's own.

    Stated with the weight abstract, since what the recursion must supply is
    exactly `hlt` and nothing else. -/
theorem max_is_inr {S₁ S₂ : Type} (w : Sum S₁ S₂ → Nat)
    (hlt : ∀ (u : S₁) (t : S₂), w (Sum.inl u) < w (Sum.inr t))
    (P : Sum S₁ S₂ → Prop) (s : Sum S₁ S₂) (hs : P s)
    (hmax : ∀ y, P y → w y ≤ w s)
    (t : S₂) (ht : P (Sum.inr t)) :
    ∃ v : S₂, s = Sum.inr v := by
  cases s with
  | inl u => exact absurd (hmax (Sum.inr t) ht) (Nat.not_le.mpr (hlt u t))
  | inr v => exact ⟨v, rfl⟩

/-- The other half of the recursion: a class whose maximal member is LEFT has
    ALL its members left.  This is why the order restricts to the left half at
    an inner node, and it is the same fact read contrapositively. -/
theorem max_inl_all_inl {S₁ S₂ : Type} (w : Sum S₁ S₂ → Nat)
    (hlt : ∀ (u : S₁) (t : S₂), w (Sum.inl u) < w (Sum.inr t))
    (P : Sum S₁ S₂ → Prop) (u : S₁) (hmax : ∀ y, P y → w y ≤ w (Sum.inl u)) :
    ∀ y, P y → ∃ v : S₁, y = Sum.inl v := by
  intro y hy
  cases y with
  | inl v => exact ⟨v, rfl⟩
  | inr t => exact absurd (hmax (Sum.inr t) hy) (Nat.not_le.mpr (hlt u t))

#print axioms max_is_inr
#print axioms max_inl_all_inl


/-! ### 316 — THE WEIGHT, BY RECURSION ON THE EXPRESSION

    315 reduced 305's "leaf ordering" to supplying, at each `ite`/`seq` node, a
    weight in which every RIGHT state outweighs every LEFT one.  Here it is,
    and the only wrinkle is that the recursion must carry a BOUND alongside the
    weight: to place the right half strictly above the left, one needs to know
    where the left half ends.

    So `stateWeight g` returns a PAIR — the weight and an upper bound for it —
    and the two are built together:

      * `test` has no states, `act` has one; both bound `0`;
      * `ite` and `seq` place the left half at its own weights and the right
        half OFFSET past the left's bound, so the strict inequality is by
        construction rather than by comparison;
      * `wh` inherits its body's, unchanged — a loop adds transitions, never
        states, which is the same fact `LoopLayer.states_eq` records.

    That `ite` and `seq` get the identical clause is 289's observation once
    more: they differ in what they connect, never in what states they have. -/
def stateWeight : (g : Exp A T) →
    ((GkatThompson.certifiedThompson A T g).State → Nat) × Nat
  | .test _ => ((fun s => nomatch s), 0)
  | .act _ => ((fun _ => 0), 0)
  | .ite _ e f =>
      ((fun s => match s with
        | .inl u => (stateWeight e).1 u
        | .inr t => (stateWeight e).2 + 1 + (stateWeight f).1 t),
       (stateWeight e).2 + 1 + (stateWeight f).2)
  | .seq e f =>
      ((fun s => match s with
        | .inl u => (stateWeight e).1 u
        | .inr t => (stateWeight e).2 + 1 + (stateWeight f).1 t),
       (stateWeight e).2 + 1 + (stateWeight f).2)
  | .wh _ e => stateWeight e

/-- The bound is a bound. -/
theorem stateWeight_le : ∀ (g : Exp A T)
    (s : (GkatThompson.certifiedThompson A T g).State),
    (stateWeight g).1 s ≤ (stateWeight g).2
  | .test _, s => nomatch s
  | .act _, _ => Nat.le_refl 0
  | .ite _ e f, s => by
      cases s with
      | inl u =>
          exact Nat.le_trans (stateWeight_le e u)
            (Nat.le_trans (Nat.le_succ _) (Nat.le_add_right _ _))
      | inr t =>
          exact Nat.add_le_add_left (stateWeight_le f t) _
  | .seq e f, s => by
      cases s with
      | inl u =>
          exact Nat.le_trans (stateWeight_le e u)
            (Nat.le_trans (Nat.le_succ _) (Nat.le_add_right _ _))
      | inr t =>
          exact Nat.add_le_add_left (stateWeight_le f t) _
  | .wh _ e, s => stateWeight_le e s

/-- **RIGHT OUTWEIGHS LEFT**, at an `ite` node — the hypothesis `max_is_inr`
    consumes. -/
theorem stateWeight_ite_lt (b : BExp T) (e f : Exp A T)
    (u : (GkatThompson.certifiedThompson A T e).State)
    (t : (GkatThompson.certifiedThompson A T f).State) :
    (stateWeight (.ite b e f)).1 (Sum.inl u)
      < (stateWeight (.ite b e f)).1 (Sum.inr t) := by
  show (stateWeight e).1 u < (stateWeight e).2 + 1 + (stateWeight f).1 t
  exact Nat.lt_of_le_of_lt (stateWeight_le e u)
    (Nat.lt_of_lt_of_le (Nat.lt_succ_self _) (Nat.le_add_right _ _))

/-- And at a `seq` node, by the same clause. -/
theorem stateWeight_seq_lt (e f : Exp A T)
    (u : (GkatThompson.certifiedThompson A T e).State)
    (t : (GkatThompson.certifiedThompson A T f).State) :
    (stateWeight (.seq e f)).1 (Sum.inl u)
      < (stateWeight (.seq e f)).1 (Sum.inr t) := by
  show (stateWeight e).1 u < (stateWeight e).2 + 1 + (stateWeight f).1 t
  exact Nat.lt_of_le_of_lt (stateWeight_le e u)
    (Nat.lt_of_lt_of_le (Nat.lt_succ_self _) (Nat.le_add_right _ _))

#print axioms stateWeight_le
#print axioms stateWeight_ite_lt
#print axioms stateWeight_seq_lt


section WitnessSelection
open Classical

/-! ### 317 — THE WITNESS SELECTION.  THE LAST CONSTRUCTION.

    316 built the weight; what remains is to pick, in each class, a preimage of
    MAXIMAL weight.  264 built minima over a list of naturals for `hcollapse`'s
    acyclic case; here the natural object is an ARGMAX over a list of STATES,
    which is slightly different and worth having directly: carrying the element
    rather than its weight avoids having to recover a witness from an achieved
    minimum afterwards.

    The selection needs a starting element, and there always is one — a class is
    by definition the image of something.  That is why the statement takes
    `s₀ ∈ L` with `j s₀ = c` as a hypothesis rather than asserting the class is
    nonempty: the caller has the preimage in hand, and asking for it keeps the
    lemma choice-free in its conclusion. -/
private def argMax {S : Type} (w : S → Nat) : S → List S → S
  | best, [] => best
  | best, y :: ys => argMax w (if w best < w y then y else best) ys

private theorem argMax_start {S : Type} (w : S → Nat) :
    ∀ (l : List S) (b : S), w b ≤ w (argMax w b l)
  | [], b => Nat.le_refl _
  | y :: ys, b => by
      show w b ≤ w (argMax w (if w b < w y then y else b) ys)
      refine Nat.le_trans ?_ (argMax_start w ys _)
      by_cases h : w b < w y
      · rw [if_pos h]; exact Nat.le_of_lt h
      · rw [if_neg h]; exact Nat.le_refl _

private theorem argMax_or {S : Type} (w : S → Nat) :
    ∀ (l : List S) (b : S), argMax w b l = b ∨ argMax w b l ∈ l
  | [], _ => Or.inl rfl
  | y :: ys, b => by
      show argMax w (if w b < w y then y else b) ys = b
        ∨ argMax w (if w b < w y then y else b) ys ∈ y :: ys
      by_cases hb : w b < w y
      · rw [if_pos hb]
        rcases argMax_or w ys y with h | h
        · exact Or.inr (by rw [h]; exact List.mem_cons_self ..)
        · exact Or.inr (List.mem_cons_of_mem _ h)
      · rw [if_neg hb]
        rcases argMax_or w ys b with h | h
        · exact Or.inl h
        · exact Or.inr (List.mem_cons_of_mem _ h)

private theorem argMax_ge {S : Type} (w : S → Nat) :
    ∀ (l : List S) (b : S) (y : S), y ∈ l → w y ≤ w (argMax w b l)
  | [], _, _, h => absurd h (by simp)
  | z :: zs, b, y, h => by
      show w y ≤ w (argMax w (if w b < w z then z else b) zs)
      rcases List.mem_cons.1 h with rfl | h'
      · refine Nat.le_trans ?_ (argMax_start w zs _)
        by_cases hb : w b < w y
        · rw [if_pos hb]; exact Nat.le_refl _
        · rw [if_neg hb]; exact Nat.le_of_not_lt hb
      · exact argMax_ge w zs _ y h'

/-- **A MAXIMAL WITNESS EXISTS IN EVERY INHABITED CLASS.**  This is the
    hypothesis `max_is_inr` (315) consumes, and with 316's weight it delivers
    each node's preference. -/
theorem exists_max_witness {S Q : Type} (w : S → Nat) (j : S → Q)
    (L : List S) (c : Q) (s₀ : S) (hs₀ : s₀ ∈ L) (hjs₀ : j s₀ = c) :
    ∃ s, s ∈ L ∧ j s = c ∧ ∀ y, y ∈ L → j y = c → w y ≤ w s := by
  have hfib : s₀ ∈ L.filter (fun s => decide (j s = c)) :=
    List.mem_filter.2 ⟨hs₀, by simp [hjs₀]⟩
  have hsub : ∀ z, z ∈ L.filter (fun s => decide (j s = c)) → z ∈ L ∧ j z = c := by
    intro z hz
    obtain ⟨hzL, hzc⟩ := List.mem_filter.1 hz
    exact ⟨hzL, by simpa using hzc⟩
  refine ⟨argMax w s₀ (L.filter (fun s => decide (j s = c))), ?_, ?_, ?_⟩
  · rcases argMax_or w (L.filter (fun s => decide (j s = c))) s₀ with h | h
    · rw [h]; exact hs₀
    · exact (hsub _ h).1
  · rcases argMax_or w (L.filter (fun s => decide (j s = c))) s₀ with h | h
    · rw [h]; exact hjs₀
    · exact (hsub _ h).2
  · intro y hyL hyc
    exact argMax_ge w _ s₀ y (List.mem_filter.2 ⟨hyL, by simp [hyc]⟩)

#print axioms exists_max_witness

end WitnessSelection


section QuotWitCases
open Classical

/-! ### 318 — THE WITNESS BUNDLE, AND THE FIRST THREE CASES ON IT

    Assembling the induction shows the 307-form witness is not quite enough.
    The recursive call needs two things the case lemmas were not passing on:

      * **`j s = c`** — that the witness really is a PREIMAGE of the class, which
        the cases never used but the IH does;
      * **MAXIMALITY** of the witness in its class, which is how 315-317 deliver
        each node's preference.

    Rather than thread four conjuncts through five lemmas by hand, name the
    bundle.  `QuotWit` says: every class outside the block is carried by a
    preimage of maximal weight, and the quotient's dynamics there is that
    preimage's.

    **Maximality is stated over the TYPE, not over the state list.**  That is
    what the cases consume, and it keeps the finiteness bookkeeping in ONE
    place — the eventual top-level construction — instead of in every case.
    `exists_max_witness` (317) supplies it from a list when the time comes. -/
def QuotWit {S Q : Type} (core : GkatThompson.GSystem S A T) (w : S → Nat)
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop) (j : S → Q) : Prop :=
  ∀ c, ¬ B c → ∃ s, j s = c ∧ (∀ y, j y = c → w y ≤ w s)
    ∧ Qsys.trans c = (core.trans s).map (fun tr => (tr.1, tr.2.1, j tr.2.2))
    ∧ Qsys.hlt c = core.hlt s

theorem quotient_layered_test'' (t : BExp T) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T (.test t)).State → Q)
    (hw : QuotWit (GkatThompson.certifiedThompson A T (.test t)).aut.core
      (stateWeight (.test t)).1 Qsys B j) :
    LayeredOn Qsys B :=
  LayeredOn.acyclic ⟨fun _ => 0, fun c hc => (hw c hc).elim (fun s _ => nomatch s)⟩

theorem quotient_layered_act'' (a : A) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T (.act a)).State → Q)
    (hw : QuotWit (GkatThompson.certifiedThompson A T (.act a)).aut.core
      (stateWeight (.act a)).1 Qsys B j) :
    LayeredOn Qsys B := by
  refine LayeredOn.acyclic ⟨fun _ => 0, ?_⟩
  intro c hc X W x r hfm
  obtain ⟨s, _, _, hts, _⟩ := hw c hc
  rw [hts] at hfm
  have hnil : (GkatThompson.certifiedThompson A T (.act a)).aut.core.trans s = [] := rfl
  rw [hnil] at hfm
  exact absurd hfm (by simp [GkatKleene.firstMatch])

/-- **THE `wh` CASE ON THE BUNDLE.**  The base system downstairs is built as in
    309; its bundle inherits BOTH extra conjuncts from the parent's — the
    preimage fact verbatim, and maximality because
    `stateWeight (.wh b e) = stateWeight e` by definition.  **A loop adds
    transitions, never states, so it cannot change the weights.**

    **327: the blanket `hout` is gone.**  319 found "the block misses the image"
    false in the target case; 326 made the constructor accept STUCK targets in
    the block.  So this asks for exactly what the constructor needs and no more
    — the disjunction at the ENTRY targets and at the BODY's targets — rather
    than at every state of the image.  A hypothesis that quantifies over more
    than the proof consumes is the same defect 307 found in a different guise:
    it can be true of the proof and false at the call site. -/
theorem quotient_layered_wh'' (b : BExp T) (e : Exp A T) {Q : Type}
    (Qsys : GkatThompson.GSystem Q A T) (B : Q → Prop)
    (j : (GkatThompson.certifiedThompson A T e).State → Q)
    (hentry : ∀ tr ∈ (GkatThompson.certifiedThompson A T e).aut.initTrans,
      ¬ B (j tr.2.2) ∨ StuckAt Qsys (j tr.2.2))
    (hbody : ∀ (s : (GkatThompson.certifiedThompson A T e).State) (tr),
      tr ∈ (GkatThompson.certifiedThompson A T e).aut.core.trans s →
        ¬ B (j tr.2.2) ∨ StuckAt Qsys (j tr.2.2))
    (hw : QuotWit (GkatThompson.certifiedThompson A T (.wh b e)).aut.core
      (stateWeight (.wh b e)).1 Qsys B j)
    (ih : ∀ base : GkatThompson.GSystem Q A T,
      QuotWit (GkatThompson.certifiedThompson A T e).aut.core
        (stateWeight e).1 base B j → LayeredOn base B) :
    LayeredOn Qsys B := by
  refine LayeredOn.loop
    (base := ⟨Qsys.states,
      fun c => if h : ¬ B c then
          (GkatThompson.certifiedThompson A T e).aut.core.hlt
            (Classical.choose (hw c h))
        else Qsys.hlt c,
      fun c => if h : ¬ B c then
          ((GkatThompson.certifiedThompson A T e).aut.core.trans
            (Classical.choose (hw c h))).map (fun tr => (tr.1, tr.2.1, j tr.2.2))
        else Qsys.trans c⟩)
    (b := b)
    (entry := (GkatThompson.certifiedThompson A T e).aut.initTrans.map
      (fun tr => (tr.1, tr.2.1, j tr.2.2)))
    ⟨?_, ?_, ?_, rfl⟩ ?_ ?_ (ih _ ?_)
  · intro c hc
    have hs := (Classical.choose_spec (hw c hc)).2.2.1
    show Qsys.trans c = (dite _ _ _) ++ _
    simp only [dif_pos hc]
    refine Eq.trans hs ?_
    refine Eq.trans (congrArg (List.map (fun tr => (tr.1, tr.2.1, j tr.2.2)))
      (loop_core_trans b e _)) ?_
    refine Eq.trans (map_append' _ _ _) ?_
    congr 1
    exact gate_map_comm _ _ _ _
  · intro c hc X W x
    have hh := (Classical.choose_spec (hw c hc)).2.2.2
    show GkatGS.bval W (Qsys.hlt c) x = (GkatGS.bval W (dite _ _ _) x && _)
    simp only [dif_pos hc]
    refine Eq.trans (congrArg (fun z => GkatGS.bval W z x) hh) ?_
    exact congrArg (fun z => GkatGS.bval W z x) (loop_core_hlt b e _)
  · intro c hc
    exact ⟨by show Qsys.trans c = dite _ _ _; rw [dif_neg hc],
      by show Qsys.hlt c = dite _ _ _; rw [dif_neg hc]⟩
  · intro tr htr
    simp only [List.mem_map] at htr
    obtain ⟨t, ht, rfl⟩ := htr
    exact hentry t ht
  · intro c hc tr htr
    simp only [dif_pos hc, List.mem_map] at htr
    obtain ⟨t, ht, rfl⟩ := htr
    exact hbody (Classical.choose (hw c hc)) t ht
  · intro c hc
    exact ⟨Classical.choose (hw c hc),
      (Classical.choose_spec (hw c hc)).1,
      (Classical.choose_spec (hw c hc)).2.1,
      by show dite _ _ _ = _; rw [dif_pos hc],
      by show dite _ _ _ = _; rw [dif_pos hc]⟩

#print axioms quotient_layered_test''
#print axioms quotient_layered_act''
#print axioms quotient_layered_wh''

end QuotWitCases


/-! ### 323 — A STUCK STATE'S SOLUTION IS ZERO, AND THAT IS THE WEAKENING

    322 measured that every SPLIT entry list has only NON-PRODUCTIVE targets in
    the block, and argued the requirement should weaken from

        every entry target lies outside the block

    to

        every entry target lies outside the block OR is behaviourally zero.

    Here is the fact that makes the weakening sound.  `LayeredOn.loop`'s entry
    condition exists so that, at a non-block state, the family `stdL · F` and the
    actual `sol` agree at every target.  **They agree at a target where BOTH are
    zero**, and a target that cannot move and cannot halt forces exactly that of
    ANY solution: its equation collapses to `paramFallback 0 F`, which is
    `0 ; F`, which is `0` by `s2`.

    So the offending targets need no special constructor — they need the
    congruence to be `EquivBA` rather than syntactic, which `fold_congr_step`
    (292) already provides, plus this lemma to supply the two `≈ 0` facts.  **The
    list-versus-selection trade once more**, and for the fourth time in the same
    direction: 283, 292, 299, now 323.

    Stated for a state that is IMMEDIATELY stuck.  322's non-productive states
    are more general — one may reach a stuck state after several steps — and
    that generalisation is a separate induction along the productivity ordering,
    not needed until the plumbing demands it.

    (Both lemmas, and `seq_seq_zero`, now live earlier in the file — the
    relativised solution theorem consumes them.) -/

#print axioms stuck_solution_zero
#print axioms zero_targets_agree


/-! ### 324 — THE CONGRUENCE THAT ADMITS ZERO TARGETS, AND WHERE THE ZEROS COME FROM

    323 supplied the two `≈ 0` facts; this is the step that consumes them.  Two
    labellings give equivalent folds as soon as, at every SELECTED target, they
    are either literally equal or both zero.  The first disjunct is the old
    requirement; the second is 322's escape hatch.

    **And the missing piece is now identifiable.**  In the loop case the two
    labellings are `sol` — which is `sol₀` on the block — and the family
    `solB · W · F`, which is `sol₀ · W · F` there.  Those agree only if `sol₀`
    is zero at the target, and `sol₀` is an ARBITRARY input to
    `layeredOn_has_solution`, so nothing forces it.

    **The fix is to strengthen the contract**: require `sol₀` to SOLVE the
    block, not merely to be some function on it.  Then 323 applies to `sol₀` at
    a stuck target and delivers `sol₀ t ≈ 0` for free.  And the hypothesis is
    available at every call site —

      * `split` already produces a solution on `C` from its first
        subderivation, and its second call's `sol₀` is that solution;
      * `acyclic` (via `solExtF_has_solution`) leaves `sol₀` untouched on the
        block, so the hypothesis passes straight through;
      * `loop` and `seq` likewise pass it down.

    So the strengthening costs nothing at the call sites and buys the zeros.
    That it was not needed until now is why the contract was weaker: the block's
    values were never READ before, only carried. -/
theorem congr_with_zero_targets {S : Type} (sys : GkatThompson.GSystem S A T)
    (s : S) (fb : Exp A T) (solA solB : S → Exp A T)
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r →
        solA r.2 = solB r.2
        ∨ (EquivBA (solA r.2) (.test .zero) ∧ EquivBA (solB r.2) (.test .zero))) :
    EquivBA (guardedFold (transitionBranches (sys.trans s) solA) fb)
      (guardedFold (transitionBranches (sys.trans s) solB) fb) := by
  refine fold_congr_step sys s fb solA solB ?_
  intro X W x r hfm
  rcases h X W x r hfm with heq | ⟨hA, hB⟩
  · rw [heq]
    exact EquivBA.base (Equiv.refl _)
  · exact zero_targets_agree solA solB r.2 hA hB

#print axioms congr_with_zero_targets


/-! ### 325 — THE ZERO PROPAGATES, AND WHERE THE HYPOTHESIS DOES NOT COMPOSE

    324 identified the missing hypothesis as "`sol₀` is zero at stuck block
    states".  Two things about it, one good and one not.

    **The good: zero propagates through the loop case's family.**  The family
    there is `(sol₀ t ; W) ; F`, and if `sol₀ t ≈ 0` the whole thing is `0` by
    `s2` applied twice.  So at a stuck block target both labellings are zero and
    324's congruence fires.  That is `seq_seq_zero`.

    **The not: the hypothesis does NOT compose through `split`'s FIRST call.**
    `split` passes the OUTER `sol₀` to a call whose block is `¬C`, and the
    hypothesis is known only on `P`.  Since `P ∩ C = ∅` gives `P ⊆ ¬C`, that
    covers part of the new block and not the rest — and `sol₀` is arbitrary
    there, so nothing supplies the missing part.

    **The fix, and its cost.**  NORMALISE: pass `fun t => if stuck t then 0 else
    sol₀ t` to the first call, which satisfies the hypothesis by construction.
    The cost is that the theorem's conclusion `sol s = sol₀ s` on the block must
    weaken to `EquivBA`, because the normalised input differs from `sol₀` at
    stuck block states — where, by the hypothesis itself, the two are equivalent
    anyway.

    That weakening is affordable for the same reason everything else in this
    stretch has been: the block's values are only ever CONSUMED through a
    guarded fold, and 292's `fold_congr_step` compares folds up to `EquivBA`.
    **Fifth instance of the same trade.**  What it costs is re-proving the
    `split` case's gluing step, which currently uses `rw` on a syntactic
    equality. -/

#print axioms seq_seq_zero


/-! ### 329 — CORRECTING 328, AND WHAT IS ACTUALLY TRUE ABOUT CLOSED BLOCKS

    **328's redesign does not work, and I should say so before building it.**
    The claim was that carrying STANDARD solutions would let block values scale
    with the continuation and so stop being special.  Working it through: at a
    block target inside a loop's region, the base's equation at finish `W ; F`
    supplies `std₀ t ; (W ; F)`, while the contract fixes the block's value at
    the AMBIENT `F`.  The mismatch survives the reshaping.

    **And it survives because it is structural, not notational.**  A state inside
    a loop's body has a value that genuinely depends on the loop's continuation —
    the run reaches it, the body finishes, the loop re-tests its guard.  Calling
    such a state "already solved at the ambient finish" is simply false.  So the
    fix cannot be to re-parametrise; it has to be to stop putting such states in
    the block.

    **Here is the fact that makes that tractable.**  A block closed under steps
    is closed under REACHABILITY, so **any cycle through a block state lies
    entirely in the block**.  A closed block therefore cannot cut a cycle in
    half: every strongly connected region is wholly inside it or wholly outside.
    That is exactly the property "the block does not cut through a loop" needs,
    and it is free — no hypothesis beyond closure.

    What is NOT free, and is what 328 measured, is that a NON-cyclic part of a
    loop's body can still lie in the block: closure propagates forward, and a
    body state that never returns has no forward path back into the loop to drag
    the loop in with it. -/
inductive Reaches {S : Type} (sys : GkatThompson.GSystem S A T) : S → S → Prop where
  | refl (s : S) : Reaches sys s s
  | step {s t u : S} :
      (∃ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
        GkatKleene.firstMatch W x (sys.trans s) = some r ∧ r.2 = t) →
      Reaches sys t u → Reaches sys s u

/-- **A CLOSED BLOCK IS CLOSED UNDER REACHABILITY.** -/
theorem closed_reaches {S : Type} (sys : GkatThompson.GSystem S A T) (C : S → Prop)
    (hC : ∀ s, C s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → C r.2) :
    ∀ s t, Reaches sys s t → C s → C t := by
  intro s t h
  induction h with
  | refl _ => exact fun hs => hs
  | step hstep _ ih =>
      intro hs
      obtain ⟨X, W, x, r, hfm, hr⟩ := hstep
      exact ih (hr ▸ hC _ hs X W x r hfm)

/-- **SO A CLOSED BLOCK CANNOT CUT A CYCLE IN HALF.**  If two states are
    mutually reachable and either is in the block, both are.  Every strongly
    connected region is wholly inside the block or wholly outside it — with no
    hypothesis beyond closure. -/
theorem closed_scc_saturated {S : Type} (sys : GkatThompson.GSystem S A T)
    (C : S → Prop)
    (hC : ∀ s, C s → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → C r.2)
    (s t : S) (hst : Reaches sys s t) (hts : Reaches sys t s) :
    (C s → C t) ∧ (C t → C s) :=
  ⟨closed_reaches sys C hC s t hst, closed_reaches sys C hC t s hts⟩

#print axioms closed_reaches
#print axioms closed_scc_saturated


/-! ### 331 — BLOCKS FOR FREE: THE REACHABLE CLOSURE OF ANYTHING IS CLOSED

    330 established the quotient is ours to CHOOSE, which reframes the question
    from "does the collapse decompose?" to "what shape of decomposition can we
    always arrange?".  The natural answer is not the EXPRESSION's shape — that
    is what 319-329 kept fighting — but the quotient's own **SCC CONDENSATION**:
    solve bottom-up, giving each strongly connected region the ones below it as
    a block.

    Two things make that attractive.  329 already shows such a block cannot cut a
    cycle in half.  And the blocks themselves come for free: **the set of states
    reachable from ANY set is closed**, so every down-set of the condensation is
    a legal block with no further argument.  That is this lemma, plus the `snoc`
    it needs.

    **The obstacle, named so it is not rediscovered.**  Exits from a strongly
    connected region into the block are what `LayeredOn.seq` is FOR — its entry
    points into the block by design (305/306) — but `SeqLayer`'s shape demands
    those exits be ONE SHARED list gated by each state's own halt.  Arbitrary
    exits from an SCC are not of that shape.  In a Thompson automaton they are,
    since they come from `seq` constructions; whether they survive quotienting
    is the next thing to measure. -/
theorem Reaches.snoc {S : Type} {sys : GkatThompson.GSystem S A T} :
    ∀ {u s t : S}, Reaches sys u s →
      (∃ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
        GkatKleene.firstMatch W x (sys.trans s) = some r ∧ r.2 = t) →
      Reaches sys u t := by
  intro u s t h
  induction h with
  | refl s => intro hstep; exact Reaches.step hstep (Reaches.refl t)
  | step hst _ ih => intro hstep; exact Reaches.step hst (ih hstep)

/-- **THE REACHABLE CLOSURE OF ANY SET IS CLOSED.**  So every down-set of the
    SCC condensation is a legal block, with no argument beyond this. -/
theorem reachClosure_closed {S : Type} (sys : GkatThompson.GSystem S A T)
    (X : S → Prop) :
    ∀ s, (∃ u, X u ∧ Reaches sys u s) →
      ∀ (Y : Type) (W : T → Y → Bool) (x : Y) (r : A × S),
        GkatKleene.firstMatch W x (sys.trans s) = some r →
          ∃ u, X u ∧ Reaches sys u r.2 := by
  intro s hs Y W x r hfm
  obtain ⟨u, hu, hru⟩ := hs
  exact ⟨u, hu, Reaches.snoc hru ⟨Y, W, x, r, hfm, rfl⟩⟩

#print axioms Reaches.snoc
#print axioms reachClosure_closed


/-! ### 333 — THE CONDENSATION FRAME, MADE CONCRETE

    331 proposed it and 332 measured its one obstacle away.  The frame consists
    of exactly two moves, and both are now statable against the existing
    constructors.

    **The block move.**  Take any set of states, close it under reachability, and
    split there.  331 proves such a set is closed, so `LayeredOn.split` accepts
    it with no further argument — and 329 adds that it never cuts a cycle in
    half.  Every down-set of the condensation is therefore a legal block, and
    the recursion down the condensation is just this move iterated.

    **The single-region move.**  A strongly connected region sitting immediately
    above a block: peel its EXITS as a `SeqLayer` whose entry points into the
    block — which is what `LayeredOn.seq` is for and what 332 measured to be
    per-atom single-valued — leaving a region closed w.r.t. the block, then peel
    that as a `LoopLayerOn`.

    Both are short.  That is the point: **the frame's content is choosing the
    decomposition, not proving anything new about it**, and the constructors
    built over 294-326 already accept exactly this shape.  What remains is the
    induction over the condensation and the construction of the two layers at
    each region — neither of which needs a new constructor. -/
theorem layeredOn_split_reach {S : Type} (sys : GkatThompson.GSystem S A T)
    (P X : S → Prop)
    (hdisj : ∀ s, P s → ¬ (∃ u, X u ∧ Reaches sys u s))
    (h1 : LayeredOn sys (fun s => ¬ ∃ u, X u ∧ Reaches sys u s))
    (h2 : LayeredOn sys (fun s => P s ∨ ∃ u, X u ∧ Reaches sys u s)) :
    LayeredOn sys P :=
  LayeredOn.split hdisj
    (fun s hs Y W x r hfm => Or.inl (reachClosure_closed sys X s hs Y W x r hfm)) h1 h2

/-- **THE SINGLE-REGION MOVE.**  Exits first, then the loop — and the order is
    forced, exactly as 305 found for `seq`: the loop constructor needs its region
    closed w.r.t. the block, which it is only after the exits have been peeled. -/
theorem layeredOn_region {S : Type} {sys mid base : GkatThompson.GSystem S A T}
    {P : S → Prop} {h₀ : BExp T} {entry : List (BExp T × A × S)}
    (hseq : SeqLayer sys mid h₀ entry (fun s => ¬ P s))
    (hentryP : ∀ tr ∈ entry, P tr.2.2)
    {b : BExp T} {loopEntry : List (BExp T × A × S)}
    (hloop : LoopLayerOn mid base b loopEntry (fun s => ¬ P s))
    (hle : ∀ tr ∈ loopEntry, ¬ P tr.2.2 ∨ StuckAt mid tr.2.2)
    (hlc : ∀ s, ¬ P s → ∀ tr ∈ base.trans s,
      ¬ P tr.2.2 ∨ StuckAt mid tr.2.2)
    (hbase : LayeredOn base P) :
    LayeredOn sys P :=
  LayeredOn.seq hseq hentryP (LayeredOn.loop hloop hle hlc hbase)

#print axioms layeredOn_split_reach
#print axioms layeredOn_region


/-- **The region move, with its side conditions discharged.**  After the exits are
peeled into `mid` and one loop layer into `base`, what `layeredOn_region` still
demands is that the region be *closed in `mid`* and that `base` be acyclic on it.
Both are properties of the peeled system, not of the expression that built it. -/
theorem layeredOn_region_closed {S : Type} {sys mid base : GkatThompson.GSystem S A T}
    {P : S → Prop} {h₀ b : BExp T} {entry loopEntry : List (BExp T × A × S)}
    (hseq : SeqLayer sys mid h₀ entry (fun s => ¬ P s))
    (hentryP : ∀ tr ∈ entry, P tr.2.2)
    (hloop : LoopLayerOn mid base b loopEntry (fun s => ¬ P s))
    (hin : ∀ s, ¬ P s → ∀ tr ∈ mid.trans s, ¬ P tr.2.2)
    (hwit : ∃ t, ¬ P t)
    (hacyc : ∃ rank : S → Nat, ∀ s, ¬ P s → ∀ (X : Type) (W : T → X → Bool) (x : X)
      (r : A × S), GkatKleene.firstMatch W x (base.trans s) = some r →
        P r.2 ∨ rank r.2 < rank s) :
    LayeredOn sys P := by
  refine layeredOn_region hseq hentryP hloop (fun tr htr => Or.inl ?_)
    (fun s hs tr htr => Or.inl ?_) (LayeredOn.acyclic hacyc)
  · obtain ⟨t, ht⟩ := hwit
    refine hin t ht (BExp.and (base.hlt t) (BExp.and b tr.1), tr.2) ?_
    rw [hloop.trans_eq t ht]
    exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨tr, htr, rfl⟩))
  · refine hin s hs tr ?_
    rw [hloop.trans_eq s hs]
    exact List.mem_append.mpr (Or.inl htr)

/-- **The singleton region.**  94.5% of the non-trivial regions the census finds
are ONE state with a self-loop.  There `base` is empty at the region, so both
side conditions of `layeredOn_region_closed` collapse: nothing is left to be
acyclic about, and closure is vacuous. -/
theorem layeredOn_singleton_region {S : Type} {sys mid base : GkatThompson.GSystem S A T}
    {P : S → Prop} {t : S} {h₀ b : BExp T} {entry loopEntry : List (BExp T × A × S)}
    (hreg : ∀ s, ¬ P s → s = t) (hnt : ¬ P t)
    (hseq : SeqLayer sys mid h₀ entry (fun s => ¬ P s))
    (hentryP : ∀ tr ∈ entry, P tr.2.2)
    (hloop : LoopLayerOn mid base b loopEntry (fun s => ¬ P s))
    (hself : ∀ tr ∈ loopEntry, tr.2.2 = t)
    (htrim : base.trans t = []) :
    LayeredOn sys P := by
  refine layeredOn_region hseq hentryP hloop (fun tr htr => Or.inl ?_)
    (fun s hs tr htr => ?_) (LayeredOn.acyclic ⟨fun _ => 0, fun s hs X W x r hfm => ?_⟩)
  · rw [hself tr htr]; exact hnt
  · rw [hreg s hs, htrim] at htr; cases htr
  · rw [hreg s hs, htrim] at hfm
    have hnone : GkatKleene.firstMatch W x ([] : List (BExp T × A × S)) = none := rfl
    rw [hnone] at hfm
    exact (Option.some_ne_none r hfm.symm).elim

/-- **The condensation induction.**  Let `lvl` be a level function on states that
never increases along a step — a topological numbering of the SCC condensation.
If each single level can be solved in isolation (with every *other* level as its
block), then the whole system is solvable with an EMPTY block.

The peel is `C := {lvl = n}` against the block `P := {lvl < n}`.  That block is
non-empty from `n = 1` on, and `{lvl = n}` is NOT closed — its steps drop into
the block.  It is exactly the relative closure of `LayeredOn.split` that makes
this legal; with the absolute closure the peel is impossible after the first
level, since every non-empty closed set reaches the bottom. -/
theorem layeredOn_of_levels {S : Type} {sys : GkatThompson.GSystem S A T}
    (lvl : S → Nat)
    (hmono : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → lvl r.2 ≤ lvl s)
    (hregion : ∀ n : Nat, LayeredOn sys (fun s => ¬ (lvl s = n))) :
    ∀ (k n : Nat), (∀ s, lvl s < n + k) → LayeredOn sys (fun s => lvl s < n)
  | 0, n, hb =>
      LayeredOn.acyclic ⟨fun _ => 0, fun s hs => absurd (hb s) hs⟩
  | k + 1, n, hb => by
      have hcast : (fun s => lvl s < n ∨ lvl s = n) = (fun s => lvl s < n + 1) := by
        refine funext (fun s => propext ⟨?_, ?_⟩)
        · intro h
          cases h with
          | inl hlt => exact Nat.lt_succ_of_lt hlt
          | inr he => exact he ▸ Nat.lt_succ_self _
        · intro h
          cases Nat.lt_or_ge (lvl s) n with
          | inl hlt => exact Or.inl hlt
          | inr hge => exact Or.inr (Nat.le_antisymm (Nat.le_of_lt_succ h) hge)
      have hIH : LayeredOn sys (fun s => lvl s < n + 1) := by
        refine layeredOn_of_levels lvl hmono hregion k (n + 1) (fun s => ?_)
        have hEq : n + (k + 1) = n + 1 + k := by
          rw [Nat.add_succ, Nat.succ_add]
        exact hEq ▸ hb s
      refine LayeredOn.split (C := fun s => lvl s = n)
        (fun s hs he => absurd he (Nat.ne_of_lt hs)) (fun s hs X W x r hfm => ?_)
        (hregion n) (hcast ▸ hIH)
      cases Nat.lt_or_ge (lvl r.2) n with
      | inl hlt => exact Or.inr hlt
      | inr hge => exact Or.inl (Nat.le_antisymm (hs ▸ hmono s X W x r hfm) hge)

/-- The condensation induction, discharged: a bounded level function whose levels
are each individually solvable gives a solution over the whole system. -/
theorem layeredOn_empty_of_levels {S : Type} {sys : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (B : Nat) (hbound : ∀ s, lvl s < B)
    (hmono : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → lvl r.2 ≤ lvl s)
    (hregion : ∀ n : Nat, LayeredOn sys (fun s => ¬ (lvl s = n))) :
    LayeredOn sys (fun _ => False) := by
  have h := layeredOn_of_levels lvl hmono hregion B 0 (fun s => by
    rw [Nat.zero_add]; exact hbound s)
  have hcast : (fun s : S => lvl s < 0) = (fun _ : S => False) :=
    funext (fun s => propext ⟨fun h => absurd h (Nat.not_lt_zero _), fun h => h.elim⟩)
  exact hcast ▸ h

/-- **The level theorem lands on the obligation.**  A bounded, step-non-increasing
level function with each level individually solvable yields a FULL parametric
solution — the shape `hcollapse` asks for.  This is the non-vacuity check: an
empty block turns `layeredOn_has_solution`'s conditional conclusion into an
unconditional one. -/
theorem solves_of_levels {S : Type} {sys : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (B : Nat) (hbound : ∀ s, lvl s < B)
    (hmono : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → lvl r.2 ≤ lvl s)
    (hregion : ∀ n : Nat, LayeredOn sys (fun s => ¬ (lvl s = n)))
    (F : Exp A T) :
    ∃ sol : S → Exp A T,
      ∀ s, EquivBA (sol s) (GkatThompson.eqRHSParam sys sol F s) :=
  match layeredOn_has_solution (layeredOn_empty_of_levels lvl B hbound hmono hregion)
      (fun _ => Exp.test BExp.zero) F (fun _ ht _ => ht.elim) with
  | ⟨sol, _, hout⟩ => ⟨sol, fun s => hout s (fun h => h)⟩

/-- The block of `layeredOn_of_levels`'s region hypothesis is `lvl s ≠ n`, so its
complement arrives double-negated.  Level equality is decidable, so stripping it
costs nothing — in particular it does NOT pull in `choice`. -/
theorem level_dom {S : Type} (lvl : S → Nat) (n : Nat) (s : S)
    (h : ¬ (lvl s ≠ n)) : lvl s = n :=
  Decidable.not_not.mp h

/-- **The singleton level, assembled.**  This is the form the induction consumes:
one level of the condensation, occupied by a single self-looping state, peeled
into `mid` (exits) and `base` (the loop) and discharged.  Nothing here mentions
the expression that built the automaton. -/
theorem layeredOn_level_singleton {S : Type} {sys mid base : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (n : Nat) {t : S} {h₀ b : BExp T}
    {entry loopEntry : List (BExp T × A × S)}
    (hlt : lvl t = n) (huniq : ∀ s, lvl s = n → s = t)
    (hseq : SeqLayer sys mid h₀ entry (fun s => ¬ (lvl s ≠ n)))
    (hentryP : ∀ tr ∈ entry, lvl tr.2.2 ≠ n)
    (hloop : LoopLayerOn mid base b loopEntry (fun s => ¬ (lvl s ≠ n)))
    (hself : ∀ tr ∈ loopEntry, tr.2.2 = t)
    (htrim : base.trans t = []) :
    LayeredOn sys (fun s => lvl s ≠ n) :=
  layeredOn_singleton_region
    (fun s hs => huniq s (level_dom lvl n s hs)) (fun h => h hlt)
    hseq hentryP hloop hself htrim

/-- `hregion` is quantified over ALL `n`, including levels no state occupies.
Those are free: the complement of the block is empty. -/
theorem layeredOn_level_empty {S : Type} {sys : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (n : Nat) (hno : ∀ s, lvl s ≠ n) :
    LayeredOn sys (fun s => lvl s ≠ n) :=
  LayeredOn.acyclic ⟨fun _ => 0, fun s hs => absurd (hno s) hs⟩

/-- **One level's peel data**, packaged.  A level of the condensation is
*regional* when it can be peeled into exits (`mid`) and one loop layer (`base`)
leaving a region that is closed in `mid` and acyclic in `base`.  Everything is
stated on the peeled systems; the expression that built the automaton does not
appear, which is the point of the whole condensation frame. -/
def RegionLevel {S : Type} (sys : GkatThompson.GSystem S A T)
    (lvl : S → Nat) (n : Nat) : Prop :=
  ∃ (mid base : GkatThompson.GSystem S A T) (h₀ b : BExp T)
    (entry loopEntry : List (BExp T × A × S)) (rank : S → Nat) (t : S),
    lvl t = n ∧
    SeqLayer sys mid h₀ entry (fun s => ¬ (lvl s ≠ n)) ∧
    (∀ tr ∈ entry, lvl tr.2.2 ≠ n) ∧
    LoopLayerOn mid base b loopEntry (fun s => ¬ (lvl s ≠ n)) ∧
    (∀ s, lvl s = n → ∀ tr ∈ mid.trans s, lvl tr.2.2 = n) ∧
    (∀ s, lvl s = n → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (base.trans s) = some r →
        lvl r.2 ≠ n ∨ rank r.2 < rank s)

theorem layeredOn_of_regionLevel {S : Type} {sys : GkatThompson.GSystem S A T}
    {lvl : S → Nat} {n : Nat} (h : RegionLevel sys lvl n) :
    LayeredOn sys (fun s => lvl s ≠ n) := by
  obtain ⟨mid, base, h₀, b, entry, loopEntry, rank, t, hlt, hseq, hentry,
    hloop, hin, hacyc⟩ := h
  exact layeredOn_region_closed hseq hentry hloop
    (fun s hs tr htr hne => hne (hin s (level_dom lvl n s hs) tr htr))
    ⟨t, fun hne => hne hlt⟩
    ⟨rank, fun s hs => hacyc s (level_dom lvl n s hs)⟩

/-- A singleton self-looping level is regional: `base.trans t = []` supplies both
side conditions.  `mid`'s only transitions at `t` are the gated self-loops, so
closure holds; and there is nothing left to rank. -/
theorem regionLevel_of_singleton {S : Type} {sys mid base : GkatThompson.GSystem S A T}
    {lvl : S → Nat} {n : Nat} {t : S} {h₀ b : BExp T}
    {entry loopEntry : List (BExp T × A × S)}
    (hlt : lvl t = n) (huniq : ∀ s, lvl s = n → s = t)
    (hseq : SeqLayer sys mid h₀ entry (fun s => ¬ (lvl s ≠ n)))
    (hentry : ∀ tr ∈ entry, lvl tr.2.2 ≠ n)
    (hloop : LoopLayerOn mid base b loopEntry (fun s => ¬ (lvl s ≠ n)))
    (hself : ∀ tr ∈ loopEntry, tr.2.2 = t)
    (htrim : base.trans t = []) :
    RegionLevel sys lvl n := by
  refine ⟨mid, base, h₀, b, entry, loopEntry, fun _ => 0, t, hlt, hseq, hentry,
    hloop, fun s hs tr htr => ?_, fun s hs X W x r hfm => ?_⟩
  · rw [huniq s hs, hloop.trans_eq t (fun hne => hne hlt), htrim] at htr
    have hmem := (List.mem_append.mp htr).resolve_left (fun h => by cases h)
    obtain ⟨tr', htr', heq⟩ := List.mem_map.mp hmem
    rw [← heq, hself tr' htr']
    exact hlt
  · rw [huniq s hs, htrim] at hfm
    have hnone : GkatKleene.firstMatch W x ([] : List (BExp T × A × S)) = none := rfl
    rw [hnone] at hfm
    exact (Option.some_ne_none r hfm.symm).elim

/-- **END TO END.**  A bounded, step-non-increasing level function whose every
level is either unoccupied or regional gives the automaton a full parametric
solution — the shape `hcollapse` demands, with no residual hypothesis about the
expression that built it. -/
theorem solves_of_region_levels {S : Type} {sys : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (B : Nat) (hbound : ∀ s, lvl s < B)
    (hmono : ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → lvl r.2 ≤ lvl s)
    (hlevels : ∀ n, (∀ s, lvl s ≠ n) ∨ RegionLevel sys lvl n)
    (F : Exp A T) :
    ∃ sol : S → Exp A T,
      ∀ s, EquivBA (sol s) (GkatThompson.eqRHSParam sys sol F s) :=
  solves_of_levels lvl B hbound hmono
    (fun n => (hlevels n).elim (layeredOn_level_empty lvl n) layeredOn_of_regionLevel) F

section RegionDemo

/-! **A concrete instance.**  The chain above is only worth anything if the layer
equations — several of which are SYNTACTIC, not semantic — can actually be
satisfied.  So here is a real automaton satisfying them: one state, halting
except on `p`, looping back to itself on `p`.  That is `while p do a`, the very
shape for which the Uniqueness Axiom is classically invoked. -/

/-- Fully trimmed: no transitions, halts everywhere. -/
def demoBase : GkatThompson.GSystem Unit Unit Unit :=
  { states := [()], hlt := fun _ => BExp.one, trans := fun _ => [] }

def demoLoopEntry : List (BExp Unit × Unit × Unit) := [(BExp.one, (), ())]

/-- One loop layer on top of `demoBase`, with the gating `LoopLayerOn` demands. -/
def demoMid : GkatThompson.GSystem Unit Unit Unit :=
  { states := [()]
    hlt := fun _ => BExp.and BExp.one (BExp.not (BExp.prim ()))
    trans := fun s => demoBase.trans s ++ demoLoopEntry.map (fun tr =>
      (BExp.and (demoBase.hlt s) (BExp.and (BExp.prim ()) tr.1), tr.2)) }

/-- No exits to peel, so the seq layer only reshapes the halt test. -/
def demoSys : GkatThompson.GSystem Unit Unit Unit :=
  { states := [()]
    hlt := fun s => BExp.and (demoMid.hlt s) BExp.one
    trans := demoMid.trans }

theorem demo_regionLevel : RegionLevel demoSys (fun _ => 0) 0 := by
  refine regionLevel_of_singleton (mid := demoMid) (base := demoBase)
    (t := ()) (h₀ := BExp.one) (b := BExp.prim ())
    (entry := []) (loopEntry := demoLoopEntry) rfl (fun _ _ => rfl) ?_ ?_ ?_ ?_ rfl
  · exact { trans_eq := fun _ _ => (List.append_nil _).symm
            hlt_eq := fun _ _ => rfl
            outside := fun _ hs => absurd (fun h => h rfl) hs
            states_eq := rfl }
  · intro tr htr; cases htr
  · exact { trans_eq := fun _ _ => rfl
            hlt_eq := fun _ _ _ _ _ => rfl
            outside := fun _ hs => absurd (fun h => h rfl) hs
            states_eq := rfl }
  · intro tr htr
    cases htr with
    | head => rfl
    | tail _ h => cases h

/-- **The chain, instantiated.**  `while p do a` gets a parametric solution out of
`solves_of_region_levels` with nothing assumed about the expression that built
it.  This is the non-vacuity check for the whole condensation frame. -/
theorem demo_solves :
    ∃ sol : Unit → Exp Unit Unit,
      ∀ s, EquivBA (sol s)
        (GkatThompson.eqRHSParam demoSys sol (Exp.test BExp.one) s) := by
  refine solves_of_region_levels (fun _ => 0) 1 (fun _ => Nat.zero_lt_one)
    (fun _ _ _ _ _ _ => Nat.le_refl 0) (fun n => ?_) (Exp.test BExp.one)
  cases n with
  | zero => exact Or.inr demo_regionLevel
  | succ k => exact Or.inl (fun _ h => Nat.noConfusion h)

end RegionDemo

/-! ### Making the frame checkable

Three of the chain's hypotheses quantify over EVERY atom type `X`, assignment `W`
and atom `x` — `hmono`, the region's rank, and `LoopLayerOn.hlt_eq`.  A
construction cannot discharge those by inspection.  Each has a syntactic form
that implies it, so the whole frame reduces to finite checks on transition lists
and one `BExp` equation. -/

/-- A `firstMatch` step is always a member of the list it searched. -/
theorem step_mem {S : Type} {sys : GkatThompson.GSystem S A T} {s : S}
    {X : Type} {W : T → X → Bool} {x : X} {r : A × S}
    (h : GkatKleene.firstMatch W x (sys.trans s) = some r) :
    ∃ g, (g, r) ∈ sys.trans s :=
  firstMatch_mem_of_some W x (sys.trans s) r.1 r.2 h

/-- `hmono`, checkable: it suffices that no *syntactic* transition raises the level. -/
theorem mono_of_syntactic {S : Type} {sys : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (h : ∀ s, ∀ tr ∈ sys.trans s, lvl tr.2.2 ≤ lvl s) :
    ∀ s, ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (sys.trans s) = some r → lvl r.2 ≤ lvl s := by
  intro s X W x r hfm
  obtain ⟨g, hg⟩ := step_mem hfm
  exact h s (g, r) hg

/-- The region's rank condition, checkable. -/
theorem rank_of_syntactic {S : Type} {base : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (n : Nat) (rank : S → Nat)
    (h : ∀ s, lvl s = n → ∀ tr ∈ base.trans s,
      lvl tr.2.2 ≠ n ∨ rank tr.2.2 < rank s) :
    ∀ s, lvl s = n → ∀ (X : Type) (W : T → X → Bool) (x : X) (r : A × S),
      GkatKleene.firstMatch W x (base.trans s) = some r →
        lvl r.2 ≠ n ∨ rank r.2 < rank s := by
  intro s hs X W x r hfm
  obtain ⟨g, hg⟩ := firstMatch_mem_of_some W x (base.trans s) r.1 r.2 hfm
  exact h s hs (g, r) hg

/-- `LoopLayerOn.hlt_eq` is a `bval` equation; this syntactic halt shape implies
it, and it is the shape the peel produces anyway. -/
theorem LoopLayerOn.ofSyntactic {S : Type} {sys base : GkatThompson.GSystem S A T}
    {b : BExp T} {entry : List (BExp T × A × S)} {dom : S → Prop}
    (htrans : ∀ s, dom s → sys.trans s = base.trans s ++ entry.map (fun tr =>
      (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2)))
    (hhlt : ∀ s, dom s → sys.hlt s = BExp.and (base.hlt s) (BExp.not b))
    (houtside : ∀ s, ¬ dom s → sys.trans s = base.trans s ∧ sys.hlt s = base.hlt s)
    (hstates : sys.states = base.states) :
    LoopLayerOn sys base b entry dom where
  trans_eq := htrans
  hlt_eq := fun s hs _ _ _ => by rw [hhlt s hs]; rfl
  outside := houtside
  states_eq := hstates

/-- **The fully checkable per-level obligation.**  Every conjunct is a finite
statement about transition lists and `BExp`s; nothing quantifies over atoms. -/
def RegionLevelSyn {S : Type} (sys : GkatThompson.GSystem S A T)
    (lvl : S → Nat) (n : Nat) : Prop :=
  ∃ (mid base : GkatThompson.GSystem S A T) (h₀ b : BExp T)
    (entry loopEntry : List (BExp T × A × S)) (rank : S → Nat) (t : S),
    lvl t = n ∧
    SeqLayer sys mid h₀ entry (fun s => ¬ (lvl s ≠ n)) ∧
    (∀ tr ∈ entry, lvl tr.2.2 ≠ n) ∧
    LoopLayerOn mid base b loopEntry (fun s => ¬ (lvl s ≠ n)) ∧
    (∀ s, lvl s = n → ∀ tr ∈ mid.trans s, lvl tr.2.2 = n) ∧
    (∀ s, lvl s = n → ∀ tr ∈ base.trans s, lvl tr.2.2 ≠ n ∨ rank tr.2.2 < rank s)

theorem regionLevel_of_syn {S : Type} {sys : GkatThompson.GSystem S A T}
    {lvl : S → Nat} {n : Nat} (h : RegionLevelSyn sys lvl n) :
    RegionLevel sys lvl n := by
  obtain ⟨mid, base, h₀, b, entry, loopEntry, rank, t, hlt, hseq, hentry,
    hloop, hin, hrank⟩ := h
  exact ⟨mid, base, h₀, b, entry, loopEntry, rank, t, hlt, hseq, hentry, hloop,
    hin, rank_of_syntactic lvl n rank hrank⟩

/-- **END TO END, CHECKABLE.**  Same conclusion as `solves_of_region_levels`, but
every hypothesis is a finite inspection of the automaton's own lists. -/
theorem solves_of_syntactic_levels {S : Type} {sys : GkatThompson.GSystem S A T}
    (lvl : S → Nat) (B : Nat) (hbound : ∀ s, lvl s < B)
    (hmono : ∀ s, ∀ tr ∈ sys.trans s, lvl tr.2.2 ≤ lvl s)
    (hlevels : ∀ n, (∀ s, lvl s ≠ n) ∨ RegionLevelSyn sys lvl n)
    (F : Exp A T) :
    ∃ sol : S → Exp A T,
      ∀ s, EquivBA (sol s) (GkatThompson.eqRHSParam sys sol F s) :=
  solves_of_region_levels lvl B hbound (mono_of_syntactic lvl hmono)
    (fun n => (hlevels n).elim Or.inl (fun h => Or.inr (regionLevel_of_syn h))) F

/-- **THE REMAINING OBLIGATION, AS ONE PREDICATE.**  Everything the condensation
route needs of an automaton, with no quantification over atoms anywhere: a
bounded level function that no transition raises, each of whose levels is either
unoccupied or peelable into a seq layer and a loop layer over a ranked base.

This is the `Cert` the certificate architecture wants.  `hsolve` for it is the
theorem below; what stays open is `hcollapse` — that a behavioural quotient of a
`SyntacticallyLayered` automaton is again `SyntacticallyLayered`. -/
def SyntacticallyLayered {S : Type} (sys : GkatThompson.GSystem S A T) : Prop :=
  ∃ (lvl : S → Nat) (B : Nat), (∀ s, lvl s < B) ∧
    (∀ s, ∀ tr ∈ sys.trans s, lvl tr.2.2 ≤ lvl s) ∧
    (∀ n, (∀ s, lvl s ≠ n) ∨ RegionLevelSyn sys lvl n)

/-- `hsolve`, for the condensation certificate. -/
theorem solves_of_syntacticallyLayered {S : Type} {sys : GkatThompson.GSystem S A T}
    (h : SyntacticallyLayered sys) (F : Exp A T) :
    ∃ sol : S → Exp A T,
      ∀ s, EquivBA (sol s) (GkatThompson.eqRHSParam sys sol F s) := by
  obtain ⟨lvl, B, hbound, hmono, hlevels⟩ := h
  exact solves_of_syntactic_levels lvl B hbound hmono hlevels F


section LevelExistence
open Classical

/-! ### The level function always exists

`SyntacticallyLayered` asks for a bounded level function that no transition
raises.  The condensation supplies one, but computing a condensation is graph
theory.  It is not needed: **the number of states reachable from `s`** is already
non-increasing along every edge, because a successor's reachable set is contained
in its predecessor's.  No SCC computation, no pigeonhole, no decidability. -/

/-- Reachability along *syntactic* transitions.  `firstMatch` steps are a subset
(`step_mem`), so a level function monotone for this is monotone for those. -/
inductive SReaches {S : Type} (sys : GkatThompson.GSystem S A T) : S → S → Prop where
  | refl (s : S) : SReaches sys s s
  | step {s t u : S} : (∃ g a, (g, a, t) ∈ sys.trans s) →
      SReaches sys t u → SReaches sys s u

/-- How many of `l`'s entries `s` can reach. -/
noncomputable def countReach {S : Type} (sys : GkatThompson.GSystem S A T)
    (s : S) : List S → Nat
  | [] => 0
  | u :: rest => (if SReaches sys s u then 1 else 0) + countReach sys s rest

theorem countReach_le {S : Type} (sys : GkatThompson.GSystem S A T) (s : S) :
    ∀ l : List S, countReach sys s l ≤ l.length
  | [] => Nat.le_refl 0
  | u :: rest => by
      show (if SReaches sys s u then 1 else 0) + countReach sys s rest ≤ rest.length + 1
      by_cases hu : SReaches sys s u
      · rw [if_pos hu, Nat.add_comm]
        exact Nat.succ_le_succ (countReach_le sys s rest)
      · rw [if_neg hu, Nat.zero_add]
        exact Nat.le_succ_of_le (countReach_le sys s rest)

theorem countReach_mono {S : Type} (sys : GkatThompson.GSystem S A T) (s t : S)
    (h : ∀ u, SReaches sys t u → SReaches sys s u) :
    ∀ l : List S, countReach sys t l ≤ countReach sys s l
  | [] => Nat.le_refl 0
  | u :: rest => by
      show (if SReaches sys t u then 1 else 0) + countReach sys t rest
        ≤ (if SReaches sys s u then 1 else 0) + countReach sys s rest
      refine Nat.add_le_add ?_ (countReach_mono sys s t h rest)
      by_cases hu : SReaches sys t u
      · rw [if_pos hu, if_pos (h u hu)]
        exact Nat.le_refl 1
      · rw [if_neg hu]; exact Nat.zero_le _

/-- **The level function, for any system whatsoever.**  No finiteness assumption
is needed beyond the state list the system already carries, and the proof is
three inductions on that list. -/
noncomputable def reachLevel {S : Type} (sys : GkatThompson.GSystem S A T) (s : S) : Nat :=
  countReach sys s sys.states

theorem reachLevel_bound {S : Type} (sys : GkatThompson.GSystem S A T) (s : S) :
    reachLevel sys s < sys.states.length + 1 :=
  Nat.lt_succ_of_le (countReach_le sys s sys.states)

theorem reachLevel_mono {S : Type} (sys : GkatThompson.GSystem S A T) :
    ∀ s, ∀ tr ∈ sys.trans s, reachLevel sys tr.2.2 ≤ reachLevel sys s := by
  intro s tr htr
  refine countReach_mono sys s tr.2.2 (fun u hu => ?_) sys.states
  exact SReaches.step ⟨tr.1, tr.2.1, htr⟩ hu

/-- **`hmono` and the bound are free.**  Whatever else `SyntacticallyLayered`
needs, its first two conjuncts are discharged for every system by
`reachLevel` — the entire remaining content is the per-level peel. -/
theorem syntacticallyLayered_of_regions {S : Type}
    (sys : GkatThompson.GSystem S A T)
    (hlevels : ∀ n, (∀ s, reachLevel sys s ≠ n) ∨ RegionLevelSyn sys (reachLevel sys) n) :
    SyntacticallyLayered sys :=
  ⟨reachLevel sys, sys.states.length + 1, reachLevel_bound sys,
    reachLevel_mono sys, hlevels⟩

/-- Reachability composes. -/
theorem SReaches.trans {S : Type} {sys : GkatThompson.GSystem S A T} {s t u : S}
    (h1 : SReaches sys s t) : SReaches sys t u → SReaches sys s u := by
  induction h1 with
  | refl _ => exact fun h => h
  | step hstep _ ih => exact fun h => SReaches.step hstep (ih h)

theorem add_eq_left {a b c d : Nat} (hac : a ≤ c) (hbd : b ≤ d)
    (h : a + b = c + d) : a = c := by
  cases Nat.lt_or_ge a c with
  | inl hlt => exact absurd h (Nat.ne_of_lt (Nat.add_lt_add_of_lt_of_le hlt hbd))
  | inr hge => exact Nat.le_antisymm hac hge

/-- If `t`'s reachable set is inside `s`'s and the two counts agree, the sets
agree pointwise on the counted list.  A sum of pointwise-`≤` terms can only tie
if every term ties. -/
theorem countReach_pointwise {S : Type} (sys : GkatThompson.GSystem S A T) (s t : S)
    (h : ∀ u, SReaches sys t u → SReaches sys s u) :
    ∀ (l : List S), countReach sys t l = countReach sys s l →
      ∀ u ∈ l, SReaches sys s u → SReaches sys t u := by
  intro l
  induction l with
  | nil => intro _ u hu; cases hu
  | cons v rest ih =>
      intro heq u hu hsu
      have hhead : (if SReaches sys t v then 1 else 0)
          ≤ (if SReaches sys s v then 1 else 0) := by
        by_cases hv : SReaches sys t v
        · rw [if_pos hv, if_pos (h v hv)]
          exact Nat.le_refl 1
        · rw [if_neg hv]; exact Nat.zero_le _
      have htail := countReach_mono sys s t h rest
      have heq' : (if SReaches sys t v then 1 else 0) + countReach sys t rest
          = (if SReaches sys s v then 1 else 0) + countReach sys s rest := heq
      have hh := add_eq_left hhead htail heq'
      have ht : countReach sys t rest = countReach sys s rest :=
        Nat.add_left_cancel (hh ▸ heq')
      cases hu with
      | head =>
          by_cases hv : SReaches sys t v
          · exact hv
          · rw [if_neg hv, if_pos hsu] at hh
            exact absurd hh (fun hc => Nat.noConfusion hc)
      | tail _ hmem => exact ih ht u hmem hsu

/-- **The levels ARE the strongly connected components.**  If `s` reaches `t` and
the two sit at the same `reachLevel`, then `t` reaches `s`.  So a level is a
disjoint union of SCCs, and any edge leaving a level drops it strictly.  This is
what keeps regions small — the census measures max region size 3. -/
theorem reachLevel_scc {S : Type} (sys : GkatThompson.GSystem S A T) {s t : S}
    (hs : s ∈ sys.states) (hst : SReaches sys s t)
    (hlvl : reachLevel sys t = reachLevel sys s) :
    SReaches sys t s :=
  countReach_pointwise sys s t (fun _ hu => hst.trans hu) sys.states hlvl s hs
    (SReaches.refl s)

end LevelExistence

#print axioms reachLevel_mono
#print axioms reachLevel_scc
#print axioms syntacticallyLayered_of_regions


section ShapeFreedom

/-! ### The quotient's SHAPE is free

`UniformBehavioralGAutQuotient` carries `mapState`, `maps_states`, `onto_states`
and `bisim_graph` — and **nothing syntactic about `quot.trans` or `quot.hlt`**.
Two candidate quotients that select the same transition at every atom and halt on
the same atoms are equally valid quotients of the same automaton.

That is only useful if solutions survive the reshaping, which is what this
section proves.  It is the same move as 283/292/299/323/325 — compare folds by
SELECTION, not by list — applied one level up, to the automaton itself. -/

/-- **Reshaping is free.**  Automata that pick the same transition at every atom
and halt on the same atoms have `EquivBA`-equal Salomaa right-hand sides — even
when their transition LISTS differ in length, order, and guards. -/
theorem eqRHS_equiv_of_behaviour {S : Type} (aut aut' : GkatKleene.GAut S A T)
    (sol : S → Exp A T) (s : S)
    (htr : ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatKleene.firstMatch W x (aut.trans s) = GkatKleene.firstMatch W x (aut'.trans s))
    (hh : ∀ (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W (aut.hlt s) x = GkatGS.bval W (aut'.hlt s) x) :
    EquivBA (GkatKleene.eqRHS aut sol s) (GkatKleene.eqRHS aut' sol s) := by
  rw [GkatKleene.eqRHS_eq_guardedFold, GkatKleene.eqRHS_eq_guardedFold]
  refine guardedFold_select_congr _ _ _ _ (fun X W x => ?_)
  rw [selectFull_transitionBranches W x sol (aut.hlt s) (aut.trans s),
    selectFull_transitionBranches W x sol (aut'.hlt s) (aut'.trans s), htr X W x]
  cases GkatKleene.firstMatch W x (aut'.trans s) with
  | none => exact EquivBA.baTest hh
  | some r => exact EquivBA.base (Equiv.refl _)

/-- **A solution transports across any behaviour-preserving reshaping.**  So a
peel-shaped automaton may be solved in place of the one that was handed over. -/
theorem solvesBA_of_behaviour {S : Type} (aut aut' : GkatKleene.GAut S A T)
    (hstates : ∀ s, s ∈ aut.states → s ∈ aut'.states)
    (htr : ∀ (s : S) (X : Type) (W : T → X → Bool) (x : X),
      GkatKleene.firstMatch W x (aut.trans s) = GkatKleene.firstMatch W x (aut'.trans s))
    (hh : ∀ (s : S) (X : Type) (W : T → X → Bool) (x : X),
      GkatGS.bval W (aut.hlt s) x = GkatGS.bval W (aut'.hlt s) x)
    (sol : S → Exp A T) (h : GkatKleene.SolvesBA aut' sol) :
    GkatKleene.SolvesBA aut sol := fun s hs =>
  EquivBA.trans (h s (hstates s hs))
    (EquivBA.symm (eqRHS_equiv_of_behaviour aut aut' sol s (htr s) (hh s)))

/-- The Salomaa right-hand side and the parametric one at ending `1` differ only
in their fallback, and those agree by S5. -/
theorem eqRHS_equiv_eqRHSParam {S : Type} (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T) (s : S) :
    EquivBA (GkatKleene.eqRHS aut sol s)
      (GkatThompson.eqRHSParam
        { states := aut.states, hlt := aut.hlt, trans := aut.trans } sol
        (Exp.test BExp.one) s) := by
  rw [GkatKleene.eqRHS_eq_guardedFold]
  exact guardedFold_fallback_congr (GkatSumQuotient.fallback_equiv _)

/-- **The chain's output IS `hsolve`.**  A parametric solution at ending `1` for
the system underlying a G-automaton is a `SolvesBA` solution for that automaton —
which is exactly what `sumQuotientSolvable_of_certificate` consumes. -/
theorem solvesBA_of_paramSolution {S : Type} (aut : GkatKleene.GAut S A T)
    (sol : S → Exp A T)
    (h : ∀ s, EquivBA (sol s) (GkatThompson.eqRHSParam
      { states := aut.states, hlt := aut.hlt, trans := aut.trans } sol
      (Exp.test BExp.one) s)) :
    GkatKleene.SolvesBA aut sol := fun s _ =>
  EquivBA.trans (h s) (EquivBA.symm (eqRHS_equiv_eqRHSParam aut sol s))

/-- **`hsolve` for the condensation certificate, in the target's own language.** -/
theorem solvesBA_of_syntacticallyLayered {S : Type} (aut : GkatKleene.GAut S A T)
    (h : SyntacticallyLayered
      { states := aut.states, hlt := aut.hlt, trans := aut.trans }) :
    ∃ sol : S → Exp A T, GkatKleene.SolvesBA aut sol :=
  match solves_of_syntacticallyLayered h (Exp.test BExp.one) with
  | ⟨sol, hsol⟩ => ⟨sol, solvesBA_of_paramSolution aut sol hsol⟩

#print axioms solvesBA_of_paramSolution
#print axioms solvesBA_of_syntacticallyLayered

end ShapeFreedom

#print axioms eqRHS_equiv_of_behaviour
#print axioms solvesBA_of_behaviour


section GenericPeel

/-! ### The peel, constructed rather than exhibited

340 established that a quotient's transition lists are ours to choose.  So the
layers need not be found in a system handed over — they can be *built*.  These
two constructors are the generic form of `d2Base`/`d2Mid`/`d2Sys`: given the
trimmed system and the loop and exit data, they emit the intermediate and outer
systems, and the layer structures hold by construction.

Level equality is decidable, so the `if`s cost nothing — no `Classical` here. -/

/-- Add one loop layer over `base` at the states of level `n`. -/
def loopPeel {S : Type} (base : GkatThompson.GSystem S A T) (b : BExp T)
    (loopEntry : List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    GkatThompson.GSystem S A T where
  states := base.states
  hlt := fun s => if lvl s = n then BExp.and (base.hlt s) (BExp.not b) else base.hlt s
  trans := fun s => if lvl s = n then base.trans s ++ loopEntry.map (fun tr =>
      (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2)) else base.trans s

/-- Add the exit layer over `mid` at the states of level `n`. -/
def seqPeel {S : Type} (mid : GkatThompson.GSystem S A T) (h₀ : BExp T)
    (entry : List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    GkatThompson.GSystem S A T where
  states := mid.states
  hlt := fun s => if lvl s = n then BExp.and (mid.hlt s) h₀ else mid.hlt s
  trans := fun s => if lvl s = n then mid.trans s ++ entry.map (fun tr =>
      (BExp.and (mid.hlt s) tr.1, tr.2)) else mid.trans s

theorem loopPeel_layer {S : Type} (base : GkatThompson.GSystem S A T) (b : BExp T)
    (loopEntry : List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    LoopLayerOn (loopPeel base b loopEntry lvl n) base b loopEntry
      (fun s => ¬ (lvl s ≠ n)) := by
  refine LoopLayerOn.ofSyntactic (fun s hs => ?_) (fun s hs => ?_) (fun s hs => ?_) rfl
  · show (if lvl s = n then _ else _) = _
    rw [if_pos (level_dom lvl n s hs)]
  · show (if lvl s = n then _ else _) = _
    rw [if_pos (level_dom lvl n s hs)]
  · have hne : lvl s ≠ n := Decidable.not_not.mp hs
    exact ⟨by show (if lvl s = n then _ else _) = _; rw [if_neg hne],
           by show (if lvl s = n then _ else _) = _; rw [if_neg hne]⟩

theorem seqPeel_layer {S : Type} (mid : GkatThompson.GSystem S A T) (h₀ : BExp T)
    (entry : List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    SeqLayer (seqPeel mid h₀ entry lvl n) mid h₀ entry (fun s => ¬ (lvl s ≠ n)) where
  trans_eq := fun s hs => by
    show (if lvl s = n then _ else _) = _
    rw [if_pos (level_dom lvl n s hs)]
  hlt_eq := fun s hs => by
    show (if lvl s = n then _ else _) = _
    rw [if_pos (level_dom lvl n s hs)]
  outside := fun s hs => by
    have hne : lvl s ≠ n := Decidable.not_not.mp hs
    exact ⟨by show (if lvl s = n then _ else _) = _; rw [if_neg hne],
           by show (if lvl s = n then _ else _) = _; rw [if_neg hne]⟩
  states_eq := rfl

/-- **THE GENERIC PEEL.**  From the trimmed system and the loop/exit data, plus
four finite checks on the lists, the constructed system's level `n` is regional.
Nothing is exhibited by hand — `d2_region_one` is this theorem's instance. -/
theorem regionLevelSyn_of_peel {S : Type} (base : GkatThompson.GSystem S A T)
    (lvl : S → Nat) (n : Nat) (b h₀ : BExp T)
    (entry loopEntry : List (BExp T × A × S)) (rank : S → Nat) (t : S)
    (hlt : lvl t = n)
    (hentry : ∀ tr ∈ entry, lvl tr.2.2 ≠ n)
    (hloopIn : ∀ tr ∈ loopEntry, lvl tr.2.2 = n)
    (hbaseIn : ∀ s, lvl s = n → ∀ tr ∈ base.trans s, lvl tr.2.2 = n)
    (hrank : ∀ s, lvl s = n → ∀ tr ∈ base.trans s,
      lvl tr.2.2 ≠ n ∨ rank tr.2.2 < rank s) :
    RegionLevelSyn (seqPeel (loopPeel base b loopEntry lvl n) h₀ entry lvl n) lvl n := by
  refine ⟨loopPeel base b loopEntry lvl n, base, h₀, b, entry, loopEntry, rank, t,
    hlt, seqPeel_layer _ _ _ _ _, hentry, loopPeel_layer _ _ _ _ _,
    fun s hs tr htr => ?_, hrank⟩
  have htr' : tr ∈ base.trans s ++ loopEntry.map (fun tr =>
      (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2)) := by
    have : (loopPeel base b loopEntry lvl n).trans s
        = base.trans s ++ loopEntry.map (fun tr =>
            (BExp.and (base.hlt s) (BExp.and b tr.1), tr.2)) := by
      show (if lvl s = n then _ else _) = _
      rw [if_pos hs]
    rw [← this]; exact htr
  cases List.mem_append.mp htr' with
  | inl hl => exact hbaseIn s hs tr hl
  | inr hr =>
      obtain ⟨tr', htr', heq⟩ := List.mem_map.mp hr
      rw [← heq]
      exact hloopIn tr' htr'

end GenericPeel

#print axioms loopPeel_layer
#print axioms seqPeel_layer
#print axioms regionLevelSyn_of_peel


section SimultaneousPeel

/-! ### Every level peeled at once

`regionLevelSyn_of_peel` peels ONE level, but `SyntacticallyLayered` needs every
level regional **for the same system**, and the layer structures' `outside`
fields insist that `mid` and `base` agree off the region.  So the intermediate
systems for level `n` cannot be "the raw system plus level `n`'s layers" — they
must be the fully peeled system with level `n`'s two layers *removed*.

That is what these three definitions do: `peeledSys` carries every level's layers
simultaneously, and `midSys n` / `baseSys n` strip level `n`'s back to the raw
lists while leaving all other levels alone. -/

variable {S : Type}

/-- Every level's exit layer over every level's loop layer, at once. -/
def peeledSys (raw : GkatThompson.GSystem S A T) (bs h₀s : Nat → BExp T)
    (loops exits : Nat → List (BExp T × A × S)) (lvl : S → Nat) :
    GkatThompson.GSystem S A T where
  states := raw.states
  hlt := fun s => BExp.and (BExp.and (raw.hlt s) (BExp.not (bs (lvl s)))) (h₀s (lvl s))
  trans := fun s =>
    (raw.trans s ++ (loops (lvl s)).map (fun tr =>
      (BExp.and (raw.hlt s) (BExp.and (bs (lvl s)) tr.1), tr.2)))
    ++ (exits (lvl s)).map (fun tr =>
      (BExp.and (BExp.and (raw.hlt s) (BExp.not (bs (lvl s)))) tr.1, tr.2))

/-- The peeled system with level `n`'s EXIT layer removed. -/
def midSys (raw : GkatThompson.GSystem S A T) (bs h₀s : Nat → BExp T)
    (loops exits : Nat → List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    GkatThompson.GSystem S A T where
  states := raw.states
  hlt := fun s => if lvl s = n then BExp.and (raw.hlt s) (BExp.not (bs n))
    else (peeledSys raw bs h₀s loops exits lvl).hlt s
  trans := fun s => if lvl s = n then
      raw.trans s ++ (loops n).map (fun tr =>
        (BExp.and (raw.hlt s) (BExp.and (bs n) tr.1), tr.2))
    else (peeledSys raw bs h₀s loops exits lvl).trans s

/-- The peeled system with BOTH of level `n`'s layers removed. -/
def baseSys (raw : GkatThompson.GSystem S A T) (bs h₀s : Nat → BExp T)
    (loops exits : Nat → List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    GkatThompson.GSystem S A T where
  states := raw.states
  hlt := fun s => if lvl s = n then raw.hlt s
    else (peeledSys raw bs h₀s loops exits lvl).hlt s
  trans := fun s => if lvl s = n then raw.trans s
    else (peeledSys raw bs h₀s loops exits lvl).trans s

theorem midSys_loopLayer (raw : GkatThompson.GSystem S A T) (bs h₀s : Nat → BExp T)
    (loops exits : Nat → List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    LoopLayerOn (midSys raw bs h₀s loops exits lvl n)
      (baseSys raw bs h₀s loops exits lvl n) (bs n) (loops n)
      (fun s => ¬ (lvl s ≠ n)) := by
  refine LoopLayerOn.ofSyntactic (fun s hs => ?_) (fun s hs => ?_) (fun s hs => ?_) rfl
  · have h : lvl s = n := level_dom lvl n s hs
    show (if lvl s = n then _ else _) = _
    rw [if_pos h]
    show _ = (if lvl s = n then _ else _) ++ _
    rw [if_pos h]
    show _ = _ ++ (loops n).map (fun tr =>
      (BExp.and ((baseSys raw bs h₀s loops exits lvl n).hlt s) (BExp.and (bs n) tr.1), tr.2))
    have hb : (baseSys raw bs h₀s loops exits lvl n).hlt s = raw.hlt s := by
      show (if lvl s = n then _ else _) = _; rw [if_pos h]
    rw [hb]
  · have h : lvl s = n := level_dom lvl n s hs
    show (if lvl s = n then _ else _) = _
    rw [if_pos h]
    have hb : (baseSys raw bs h₀s loops exits lvl n).hlt s = raw.hlt s := by
      show (if lvl s = n then _ else _) = _; rw [if_pos h]
    rw [hb]
  · have hne : lvl s ≠ n := Decidable.not_not.mp hs
    refine ⟨?_, ?_⟩
    · show (if lvl s = n then _ else _) = _
      rw [if_neg hne]
      show _ = (if lvl s = n then _ else _)
      rw [if_neg hne]
    · show (if lvl s = n then _ else _) = _
      rw [if_neg hne]
      show _ = (if lvl s = n then _ else _)
      rw [if_neg hne]

theorem peeledSys_seqLayer (raw : GkatThompson.GSystem S A T) (bs h₀s : Nat → BExp T)
    (loops exits : Nat → List (BExp T × A × S)) (lvl : S → Nat) (n : Nat) :
    SeqLayer (peeledSys raw bs h₀s loops exits lvl)
      (midSys raw bs h₀s loops exits lvl n) (h₀s n) (exits n)
      (fun s => ¬ (lvl s ≠ n)) where
  trans_eq := fun s hs => by
    have h : lvl s = n := level_dom lvl n s hs
    show (raw.trans s ++ _) ++ _ = _
    have hm : (midSys raw bs h₀s loops exits lvl n).trans s
        = raw.trans s ++ (loops n).map (fun tr =>
          (BExp.and (raw.hlt s) (BExp.and (bs n) tr.1), tr.2)) := by
      show (if lvl s = n then _ else _) = _; rw [if_pos h]
    have hmh : (midSys raw bs h₀s loops exits lvl n).hlt s
        = BExp.and (raw.hlt s) (BExp.not (bs n)) := by
      show (if lvl s = n then _ else _) = _; rw [if_pos h]
    rw [hm, hmh, h]
  hlt_eq := fun s hs => by
    have h : lvl s = n := level_dom lvl n s hs
    have hmh : (midSys raw bs h₀s loops exits lvl n).hlt s
        = BExp.and (raw.hlt s) (BExp.not (bs n)) := by
      show (if lvl s = n then _ else _) = _; rw [if_pos h]
    show BExp.and (BExp.and (raw.hlt s) (BExp.not (bs (lvl s)))) (h₀s (lvl s)) = _
    rw [hmh, h]
  outside := fun s hs => by
    have hne : lvl s ≠ n := Decidable.not_not.mp hs
    refine ⟨?_, ?_⟩
    · show _ = (if lvl s = n then _ else _); rw [if_neg hne]
    · show _ = (if lvl s = n then _ else _); rw [if_neg hne]
  states_eq := rfl

/-- Level `n` of the simultaneously peeled system is regional, from four finite
checks on the raw lists and the two entry lists. -/
theorem regionLevelSyn_peeled {S : Type} (raw : GkatThompson.GSystem S A T)
    (bs h₀s : Nat → BExp T) (loops exits : Nat → List (BExp T × A × S))
    (lvl : S → Nat) (rank : Nat → S → Nat) (n : Nat) (t : S) (hlt : lvl t = n)
    (hexit : ∀ tr ∈ exits n, lvl tr.2.2 ≠ n)
    (hloopIn : ∀ tr ∈ loops n, lvl tr.2.2 = n)
    (hrawIn : ∀ s, lvl s = n → ∀ tr ∈ raw.trans s, lvl tr.2.2 = n)
    (hrawRank : ∀ s, lvl s = n → ∀ tr ∈ raw.trans s, rank n tr.2.2 < rank n s) :
    RegionLevelSyn (peeledSys raw bs h₀s loops exits lvl) lvl n := by
  refine ⟨midSys raw bs h₀s loops exits lvl n, baseSys raw bs h₀s loops exits lvl n,
    h₀s n, bs n, exits n, loops n, rank n, t, hlt,
    peeledSys_seqLayer raw bs h₀s loops exits lvl n, hexit,
    midSys_loopLayer raw bs h₀s loops exits lvl n, fun s hs tr htr => ?_,
    fun s hs tr htr => ?_⟩
  · have hm : (midSys raw bs h₀s loops exits lvl n).trans s
        = raw.trans s ++ (loops n).map (fun tr =>
          (BExp.and (raw.hlt s) (BExp.and (bs n) tr.1), tr.2)) := by
      show (if lvl s = n then _ else _) = _; rw [if_pos hs]
    rw [hm] at htr
    cases List.mem_append.mp htr with
    | inl hl => exact hrawIn s hs tr hl
    | inr hr =>
        obtain ⟨tr', htr', heq⟩ := List.mem_map.mp hr
        rw [← heq]; exact hloopIn tr' htr'
  · have hb : (baseSys raw bs h₀s loops exits lvl n).trans s = raw.trans s := by
      show (if lvl s = n then _ else _) = _; rw [if_pos hs]
    rw [hb] at htr
    exact Or.inr (hrawRank s hs tr htr)

/-- `hmono` for the peeled system, from the same finite checks.  The peel adds
only loop entries (which stay in the level) and exit entries (which leave it
downward), so no transition raises the level. -/
theorem peeled_mono {S : Type} (raw : GkatThompson.GSystem S A T)
    (bs h₀s : Nat → BExp T) (loops exits : Nat → List (BExp T × A × S))
    (lvl : S → Nat)
    (hraw : ∀ s, ∀ tr ∈ raw.trans s, lvl tr.2.2 ≤ lvl s)
    (hloop : ∀ n, ∀ tr ∈ loops n, lvl tr.2.2 ≤ n)
    (hexit : ∀ n, ∀ tr ∈ exits n, lvl tr.2.2 ≤ n) :
    ∀ s, ∀ tr ∈ (peeledSys raw bs h₀s loops exits lvl).trans s,
      lvl tr.2.2 ≤ lvl s := by
  intro s tr htr
  have hs : (peeledSys raw bs h₀s loops exits lvl).trans s
      = (raw.trans s ++ (loops (lvl s)).map (fun tr =>
          (BExp.and (raw.hlt s) (BExp.and (bs (lvl s)) tr.1), tr.2)))
        ++ (exits (lvl s)).map (fun tr =>
          (BExp.and (BExp.and (raw.hlt s) (BExp.not (bs (lvl s)))) tr.1, tr.2)) := rfl
  rw [hs] at htr
  cases List.mem_append.mp htr with
  | inr hr =>
      obtain ⟨tr', htr', heq⟩ := List.mem_map.mp hr
      rw [← heq]; exact hexit (lvl s) tr' htr'
  | inl hl =>
      cases List.mem_append.mp hl with
      | inl h => exact hraw s tr h
      | inr hr =>
          obtain ⟨tr', htr', heq⟩ := List.mem_map.mp hr
          rw [← heq]; exact hloop (lvl s) tr' htr'

#print axioms regionLevelSyn_peeled
#print axioms peeled_mono

/-- **THE CONSTRUCTION, ASSEMBLED.**  A raw system whose transitions never raise
the level and whose intra-level edges are ranked, plus per-level loop and exit
lists that respect the level, yields a peeled system that is
`SyntacticallyLayered` — hence solvable. Nothing is exhibited by hand. -/
theorem syntacticallyLayered_peeled {S : Type} (raw : GkatThompson.GSystem S A T)
    (bs h₀s : Nat → BExp T) (loops exits : Nat → List (BExp T × A × S))
    (lvl : S → Nat) (rank : Nat → S → Nat) (B : Nat)
    (hbound : ∀ s, lvl s < B)
    (hraw : ∀ s, ∀ tr ∈ raw.trans s, lvl tr.2.2 ≤ lvl s)
    (hloopIn : ∀ n, ∀ tr ∈ loops n, lvl tr.2.2 = n)
    (hexitLe : ∀ n, ∀ tr ∈ exits n, lvl tr.2.2 ≤ n)
    (hexit : ∀ n, ∀ tr ∈ exits n, lvl tr.2.2 ≠ n)
    (hrawIn : ∀ n s, lvl s = n → ∀ tr ∈ raw.trans s, lvl tr.2.2 = n)
    (hrawRank : ∀ n s, lvl s = n → ∀ tr ∈ raw.trans s, rank n tr.2.2 < rank n s) :
    SyntacticallyLayered (peeledSys raw bs h₀s loops exits lvl) := by
  refine ⟨lvl, B, hbound,
    peeled_mono raw bs h₀s loops exits lvl hraw
      (fun n tr htr => Nat.le_of_eq (hloopIn n tr htr)) hexitLe, fun n => ?_⟩
  cases Classical.em (∃ t, lvl t = n) with
  | inr hno => exact Or.inl (fun s hsn => hno ⟨s, hsn⟩)
  | inl hyes =>
      exact Or.inr (regionLevelSyn_peeled raw bs h₀s loops exits lvl rank n
        (Classical.choose hyes) (Classical.choose_spec hyes) (hexit n) (hloopIn n)
        (hrawIn n) (hrawRank n))

/-- The same, delivered as a `SolvesBA` solution of the corresponding
G-automaton — the form `sumQuotientSolvable_of_certificate`'s `hsolve` consumes. -/
theorem solvesBA_peeled {S : Type} (raw : GkatThompson.GSystem S A T)
    (bs h₀s : Nat → BExp T) (loops exits : Nat → List (BExp T × A × S))
    (lvl : S → Nat) (rank : Nat → S → Nat) (B : Nat) (start : S)
    (hbound : ∀ s, lvl s < B)
    (hraw : ∀ s, ∀ tr ∈ raw.trans s, lvl tr.2.2 ≤ lvl s)
    (hloopIn : ∀ n, ∀ tr ∈ loops n, lvl tr.2.2 = n)
    (hexitLe : ∀ n, ∀ tr ∈ exits n, lvl tr.2.2 ≤ n)
    (hexit : ∀ n, ∀ tr ∈ exits n, lvl tr.2.2 ≠ n)
    (hrawIn : ∀ n s, lvl s = n → ∀ tr ∈ raw.trans s, lvl tr.2.2 = n)
    (hrawRank : ∀ n s, lvl s = n → ∀ tr ∈ raw.trans s, rank n tr.2.2 < rank n s) :
    ∃ sol : S → Exp A T, GkatKleene.SolvesBA
      { states := (peeledSys raw bs h₀s loops exits lvl).states
        hlt := (peeledSys raw bs h₀s loops exits lvl).hlt
        trans := (peeledSys raw bs h₀s loops exits lvl).trans
        start := start } sol :=
  solvesBA_of_syntacticallyLayered _
    (syntacticallyLayered_peeled raw bs h₀s loops exits lvl rank B hbound hraw
      hloopIn hexitLe hexit hrawIn hrawRank)

#print axioms syntacticallyLayered_peeled
#print axioms solvesBA_peeled

end SimultaneousPeel

#print axioms midSys_loopLayer
#print axioms peeledSys_seqLayer


section GuardNormalisation

/-! ### Making `firstMatch` order-independent

The split of a quotient's list into `raw`/`loops`/`exits` is a PARTITION, but
`firstMatch` is order-sensitive: an entry fires only if no earlier guard holds.
Both facts can be reconciled at once by normalising the guards — fold the
negations of all preceding guards into each guard.  That changes no behaviour and
makes the guards pairwise exclusive, after which "the first entry that fires" and
"the entry that fires" are the same thing, and a partition is safe. -/

/-- Fold `acc` (the negations of the guards seen so far) into each guard. -/
def disjoinAux {S : Type} (acc : BExp T) :
    List (BExp T × A × S) → List (BExp T × A × S)
  | [] => []
  | (g, r) :: tl => (BExp.and acc g, r) :: disjoinAux (BExp.and acc (BExp.not g)) tl

def disjoin {S : Type} (L : List (BExp T × A × S)) : List (BExp T × A × S) :=
  disjoinAux BExp.one L

theorem firstMatch_disjoinAux {S X : Type} (W : T → X → Bool) (x : X) :
    ∀ (L : List (BExp T × A × S)) (acc : BExp T),
      GkatKleene.firstMatch W x (disjoinAux acc L)
        = if GkatGS.bval W acc x then GkatKleene.firstMatch W x L else none := by
  intro L
  induction L with
  | nil => intro acc; cases GkatGS.bval W acc x <;> rfl
  | cons e tl ih =>
      intro acc
      obtain ⟨g, q, s'⟩ := e
      cases hacc : GkatGS.bval W acc x with
      | false => simp [disjoinAux, GkatKleene.firstMatch, GkatGS.bval, hacc, ih]
      | true =>
          cases hg : GkatGS.bval W g x with
          | false => simp [disjoinAux, GkatKleene.firstMatch, GkatGS.bval, hacc, hg, ih]
          | true => simp [disjoinAux, GkatKleene.firstMatch, GkatGS.bval, hacc, hg]

/-- **Normalising the guards changes no behaviour.** -/
theorem firstMatch_disjoin {S X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) :
    GkatKleene.firstMatch W x (disjoin L) = GkatKleene.firstMatch W x L := by
  rw [disjoin, firstMatch_disjoinAux]
  rfl

/-- **And it makes the guards pairwise exclusive.**  At any atom at most one entry
of a normalised list has a true guard — so its `firstMatch` no longer depends on
the order, and the list may be partitioned freely. -/
theorem disjoinAux_exclusive {S X : Type} (W : T → X → Bool) (x : X) :
    ∀ (L : List (BExp T × A × S)) (acc : BExp T),
      (∀ tr ∈ disjoinAux acc L, GkatGS.bval W tr.1 x = true →
          GkatGS.bval W acc x = true) ∧
      (∀ tr ∈ disjoinAux acc L, ∀ tr' ∈ disjoinAux acc L,
          GkatGS.bval W tr.1 x = true → GkatGS.bval W tr'.1 x = true → tr = tr') := by
  intro L
  induction L with
  | nil =>
      intro acc
      constructor
      · intro tr htr; cases htr
      · intro tr htr; cases htr
  | cons e tl ih =>
      intro acc
      obtain ⟨g, q, s'⟩ := e
      have hhead : ∀ tr ∈ disjoinAux (BExp.and acc (BExp.not g)) tl,
          GkatGS.bval W tr.1 x = true →
            GkatGS.bval W acc x = true ∧ GkatGS.bval W g x = false := by
        intro tr htr hb
        have h1 := (ih (BExp.and acc (BExp.not g))).1 tr htr hb
        simpa only [GkatGS.bval, Bool.and_eq_true, Bool.not_eq_true'] using h1
      have hsplit : ∀ (p q' : BExp T), GkatGS.bval W (BExp.and p q') x = true →
          GkatGS.bval W p x = true ∧ GkatGS.bval W q' x = true := by
        intro p q' hpq
        simpa only [GkatGS.bval, Bool.and_eq_true] using hpq
      refine ⟨fun tr htr hb => ?_, fun tr htr tr' htr' hb hb' => ?_⟩
      · cases htr with
        | head => exact (hsplit _ _ hb).1
        | tail _ h => exact (hhead tr h hb).1
      · cases htr with
        | head =>
            cases htr' with
            | head => rfl
            | tail _ h' =>
                have hgf := (hhead tr' h' hb').2
                have hgt := (hsplit _ _ hb).2
                rw [hgf] at hgt
                exact absurd hgt Bool.false_ne_true
        | tail _ h =>
            cases htr' with
            | head =>
                have hgf := (hhead tr h hb).2
                have hgt := (hsplit _ _ hb').2
                rw [hgf] at hgt
                exact absurd hgt Bool.false_ne_true
            | tail _ h' => exact (ih (BExp.and acc (BExp.not g))).2 tr h tr' h' hb hb'

theorem disjoin_exclusive {S X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) :
    ∀ tr ∈ disjoin L, ∀ tr' ∈ disjoin L,
      GkatGS.bval W tr.1 x = true → GkatGS.bval W tr'.1 x = true → tr = tr' :=
  (disjoinAux_exclusive W x L BExp.one).2

/-- Exclusivity at one atom: at most one entry's guard holds. -/
def ExclusiveAt {S X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) : Prop :=
  ∀ tr ∈ L, ∀ tr' ∈ L,
    GkatGS.bval W tr.1 x = true → GkatGS.bval W tr'.1 x = true → tr = tr'

theorem firstMatch_none_of_all_false {S X : Type} (W : T → X → Bool) (x : X) :
    ∀ (L : List (BExp T × A × S)), (∀ tr ∈ L, GkatGS.bval W tr.1 x = false) →
      GkatKleene.firstMatch W x L = none := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons e rest ih =>
      intro h
      obtain ⟨g, q, s'⟩ := e
      have hg : GkatGS.bval W g x = false := h _ (List.mem_cons_self ..)
      show (if GkatGS.bval W g x then _ else _) = _
      rw [if_neg (by rw [hg]; exact Bool.false_ne_true)]
      exact ih (fun tr htr => h tr (List.mem_cons_of_mem _ htr))

/-- In an exclusive list, "the first entry that fires" is "the entry that fires":
`firstMatch` no longer depends on the order. -/
theorem firstMatch_of_exclusiveAt {S X : Type} (W : T → X → Bool) (x : X) :
    ∀ (L : List (BExp T × A × S)), ExclusiveAt W x L →
      ∀ tr ∈ L, GkatGS.bval W tr.1 x = true →
        GkatKleene.firstMatch W x L = some tr.2 := by
  intro L
  induction L with
  | nil => intro _ tr htr; cases htr
  | cons e rest ih =>
      intro hex tr htr hb
      obtain ⟨g, q, s'⟩ := e
      cases hg : GkatGS.bval W g x with
      | true =>
          have : tr = (g, q, s') :=
            hex tr htr _ (List.mem_cons_self ..) hb hg
          show (if GkatGS.bval W g x then _ else _) = _
          rw [if_pos (by rw [hg]), this]
      | false =>
          have hne : tr ≠ (g, q, s') := by
            intro heq; rw [heq] at hb; rw [hg] at hb; exact Bool.noConfusion hb
          have htr' : tr ∈ rest := by
            cases htr with
            | head => exact absurd rfl hne
            | tail _ h => exact h
          show (if GkatGS.bval W g x then _ else _) = _
          rw [if_neg (by rw [hg]; exact Bool.false_ne_true)]
          exact ih (fun a ha b hb' => hex a (List.mem_cons_of_mem _ ha) b
            (List.mem_cons_of_mem _ hb')) tr htr' hb

/-- **The reassembly tool.**  Two exclusive lists with the same firing entries
have the same `firstMatch` — so a normalised transition list may be split into
`raw`, `loops` and `exits` and put back in any order. -/
theorem firstMatch_eq_of_exclusiveAt {S X : Type} (W : T → X → Bool) (x : X)
    (L L' : List (BExp T × A × S)) (hex : ExclusiveAt W x L) (hex' : ExclusiveAt W x L')
    (hmem : ∀ tr, GkatGS.bval W tr.1 x = true → (tr ∈ L ↔ tr ∈ L')) :
    GkatKleene.firstMatch W x L = GkatKleene.firstMatch W x L' := by
  cases Classical.em (∃ tr ∈ L, GkatGS.bval W tr.1 x = true) with
  | inl hyes =>
      obtain ⟨tr, htr, hb⟩ := hyes
      rw [firstMatch_of_exclusiveAt W x L hex tr htr hb,
        firstMatch_of_exclusiveAt W x L' hex' tr ((hmem tr hb).mp htr) hb]
  | inr hno =>
      have hL : ∀ tr ∈ L, GkatGS.bval W tr.1 x = false := by
        intro tr htr
        cases hb : GkatGS.bval W tr.1 x with
        | false => rfl
        | true => exact absurd ⟨tr, htr, hb⟩ hno
      have hL' : ∀ tr ∈ L', GkatGS.bval W tr.1 x = false := by
        intro tr htr
        cases hb : GkatGS.bval W tr.1 x with
        | false => rfl
        | true => exact absurd ⟨tr, (hmem tr hb).mpr htr, hb⟩ hno
      rw [firstMatch_none_of_all_false W x L hL,
        firstMatch_none_of_all_false W x L' hL']

#print axioms firstMatch_of_exclusiveAt
#print axioms firstMatch_eq_of_exclusiveAt

/-- **Any transition list is behaviourally its normalisation, split three ways.**
The order is `(raw ++ loops) ++ exits` — exactly the shape `peeledSys.trans`
has.  `p` picks the raw part, `q` the loop part among the rest, and what remains
is the exit part; no side condition on `p` or `q` at all, because exclusivity
does the work. -/
theorem firstMatch_partition3 {S X : Type} (W : T → X → Bool) (x : X)
    (D : List (BExp T × A × S)) (hex : ExclusiveAt W x D)
    (p q : (BExp T × A × S) → Bool) :
    GkatKleene.firstMatch W x D
      = GkatKleene.firstMatch W x
          ((D.filter p ++ D.filter (fun tr => !p tr && q tr))
            ++ D.filter (fun tr => !p tr && !q tr)) := by
  have hsub : ∀ tr, tr ∈ ((D.filter p ++ D.filter (fun tr => !p tr && q tr))
      ++ D.filter (fun tr => !p tr && !q tr)) → tr ∈ D := by
    intro tr h
    cases List.mem_append.mp h with
    | inr h3 => exact (List.mem_filter.mp h3).1
    | inl h12 =>
        cases List.mem_append.mp h12 with
        | inl h1 => exact (List.mem_filter.mp h1).1
        | inr h2 => exact (List.mem_filter.mp h2).1
  refine firstMatch_eq_of_exclusiveAt W x D _ hex
    (fun a ha b hb => hex a (hsub a ha) b (hsub b hb))
    (fun tr _ => ⟨fun htr => ?_, fun htr => hsub tr htr⟩)
  cases hp : p tr with
  | true =>
      exact List.mem_append.mpr (Or.inl
        (List.mem_append.mpr (Or.inl (List.mem_filter.mpr ⟨htr, hp⟩))))
  | false =>
      cases hq : q tr with
      | true =>
          refine List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inr
            (List.mem_filter.mpr ⟨htr, ?_⟩))))
          simp [hp, hq]
      | false =>
          refine List.mem_append.mpr (Or.inr (List.mem_filter.mpr ⟨htr, ?_⟩))
          simp [hp, hq]

/-- **The split, end to end.**  A state's transition list has the same behaviour
as the three-way partition of its normalisation.  This is the shape obligation of
`solvesBA_of_behaviour` discharged at the level of a single list: whatever `raw`,
`loops` and `exits` are chosen, as long as they partition the normalised list in
that order, `firstMatch` is unchanged. -/
theorem firstMatch_split {S X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) (p q : (BExp T × A × S) → Bool) :
    GkatKleene.firstMatch W x L
      = GkatKleene.firstMatch W x
          (((disjoin L).filter p ++ (disjoin L).filter (fun tr => !p tr && q tr))
            ++ (disjoin L).filter (fun tr => !p tr && !q tr)) :=
  (firstMatch_disjoin W x L).symm.trans
    (firstMatch_partition3 W x (disjoin L) (disjoin_exclusive W x L) p q)

#print axioms firstMatch_partition3
#print axioms firstMatch_split

/-- **Re-gating a guard is invisible where the gate covers it.**  The peel wraps
each entry's guard `g` as `hlt ∧ b ∧ g`; that changes nothing at an atom where
`g`'s truth already forces both `hlt` and `b`.  For the loop entries this is
exactly what 343 measured: `raw.hlt s` is true on every non-raw non-dead atom,
and `bs n` is true on every back-edge atom of the level. -/
theorem bval_gate_eq {X : Type} (W : T → X → Bool) (x : X) (hlt b g : BExp T)
    (h : GkatGS.bval W g x = true →
      GkatGS.bval W hlt x = true ∧ GkatGS.bval W b x = true) :
    GkatGS.bval W (BExp.and hlt (BExp.and b g)) x = GkatGS.bval W g x := by
  cases hg : GkatGS.bval W g x with
  | false => show (_ && (_ && GkatGS.bval W g x)) = _; rw [hg]; simp
  | true =>
      obtain ⟨h1, h2⟩ := h hg
      show (GkatGS.bval W hlt x && (GkatGS.bval W b x && GkatGS.bval W g x)) = _
      rw [h1, h2, hg]
      rfl

/-- A list whose guards are replaced by pointwise-equivalent ones fires the same
way — so the shared, gated list of the peel may stand in for the state's own
filtered part. -/
theorem firstMatch_map_guard {S X : Type} (W : T → X → Bool) (x : X)
    (f : BExp T → BExp T) :
    ∀ (L : List (BExp T × A × S)),
      (∀ tr ∈ L, GkatGS.bval W (f tr.1) x = GkatGS.bval W tr.1 x) →
      GkatKleene.firstMatch W x (L.map (fun tr => (f tr.1, tr.2)))
        = GkatKleene.firstMatch W x L := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons e tl ih =>
      intro h
      obtain ⟨g, q, s'⟩ := e
      have hg : GkatGS.bval W (f g) x = GkatGS.bval W g x :=
        h _ (List.mem_cons_self ..)
      show (if GkatGS.bval W (f g) x then _ else
        GkatKleene.firstMatch W x (tl.map (fun tr => (f tr.1, tr.2))))
        = (if GkatGS.bval W g x then _ else _)
      rw [hg, ih (fun tr htr => h tr (List.mem_cons_of_mem _ htr))]

/-- **The gated stand-in, at one state.**  If every entry's guard forces the
state's halt test and the level's loop test, then the peel's gated copy of a list
fires exactly as the list did. -/
theorem firstMatch_gated {S X : Type} (W : T → X → Bool) (x : X)
    (hlt b : BExp T) (L : List (BExp T × A × S))
    (h : ∀ tr ∈ L, GkatGS.bval W tr.1 x = true →
      GkatGS.bval W hlt x = true ∧ GkatGS.bval W b x = true) :
    GkatKleene.firstMatch W x
        (L.map (fun tr => (BExp.and hlt (BExp.and b tr.1), tr.2)))
      = GkatKleene.firstMatch W x L :=
  firstMatch_map_guard W x (fun g => BExp.and hlt (BExp.and b g)) L
    (fun tr htr => bval_gate_eq W x hlt b tr.1 (h tr htr))

#print axioms bval_gate_eq
#print axioms firstMatch_gated

/-- The exit gate has a different shape — `(hlt ∧ ¬b) ∧ g` — and needs `b` FALSE
where the guard holds, which is the other half of 343's condition. -/
theorem bval_exit_gate_eq {X : Type} (W : T → X → Bool) (x : X) (hlt b g : BExp T)
    (h : GkatGS.bval W g x = true →
      GkatGS.bval W hlt x = true ∧ GkatGS.bval W b x = false) :
    GkatGS.bval W (BExp.and (BExp.and hlt (BExp.not b)) g) x = GkatGS.bval W g x := by
  cases hg : GkatGS.bval W g x with
  | false => show ((_ && _) && GkatGS.bval W g x) = _; rw [hg]; simp
  | true =>
      obtain ⟨h1, h2⟩ := h hg
      show ((GkatGS.bval W hlt x && !GkatGS.bval W b x) && GkatGS.bval W g x) = _
      rw [h1, h2, hg]
      rfl

theorem firstMatch_exit_gated {S X : Type} (W : T → X → Bool) (x : X)
    (hlt b : BExp T) (L : List (BExp T × A × S))
    (h : ∀ tr ∈ L, GkatGS.bval W tr.1 x = true →
      GkatGS.bval W hlt x = true ∧ GkatGS.bval W b x = false) :
    GkatKleene.firstMatch W x
        (L.map (fun tr => (BExp.and (BExp.and hlt (BExp.not b)) tr.1, tr.2)))
      = GkatKleene.firstMatch W x L :=
  firstMatch_map_guard W x (fun g => BExp.and (BExp.and hlt (BExp.not b)) g) L
    (fun tr htr => bval_exit_gate_eq W x hlt b tr.1 (h tr htr))

theorem firstMatch_append_congr {S X : Type} (W : T → X → Bool) (x : X)
    (A₁ A₂ B₁ B₂ : List (BExp T × A × S))
    (hA : GkatKleene.firstMatch W x A₁ = GkatKleene.firstMatch W x A₂)
    (hB : GkatKleene.firstMatch W x B₁ = GkatKleene.firstMatch W x B₂) :
    GkatKleene.firstMatch W x (A₁ ++ B₁) = GkatKleene.firstMatch W x (A₂ ++ B₂) := by
  cases hA₁ : GkatKleene.firstMatch W x A₁ with
  | some r =>
      rw [GkatKleene.firstMatch_append_some W x A₁ B₁ hA₁,
        GkatKleene.firstMatch_append_some W x A₂ B₂ (hA ▸ hA₁)]
  | none =>
      rw [GkatKleene.firstMatch_append_none W x A₁ B₁ hA₁,
        GkatKleene.firstMatch_append_none W x A₂ B₂ (hA ▸ hA₁), hB]

/-- **THE STATE-LEVEL AGREEMENT.**  A state's transition list fires exactly as the
peel's reassembly of it does — `raw` first, then the gated loop entries, then the
gated exit entries.  The two hypotheses are precisely 343's measured condition,
stated at one atom: where a loop entry fires, the state's halt test and the
level's loop test both hold; where an exit entry fires, the halt test holds and
the loop test does not. -/
theorem firstMatch_peel_agrees {S X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) (hltE b : BExp T)
    (p q : (BExp T × A × S) → Bool)
    (hloop : ∀ tr ∈ (disjoin L).filter (fun tr => !p tr && q tr),
      GkatGS.bval W tr.1 x = true →
        GkatGS.bval W hltE x = true ∧ GkatGS.bval W b x = true)
    (hexit : ∀ tr ∈ (disjoin L).filter (fun tr => !p tr && !q tr),
      GkatGS.bval W tr.1 x = true →
        GkatGS.bval W hltE x = true ∧ GkatGS.bval W b x = false) :
    GkatKleene.firstMatch W x L
      = GkatKleene.firstMatch W x
          (((disjoin L).filter p
             ++ ((disjoin L).filter (fun tr => !p tr && q tr)).map
                  (fun tr => (BExp.and hltE (BExp.and b tr.1), tr.2)))
            ++ ((disjoin L).filter (fun tr => !p tr && !q tr)).map
                  (fun tr => (BExp.and (BExp.and hltE (BExp.not b)) tr.1, tr.2))) := by
  refine (firstMatch_split W x L p q).trans ?_
  refine (firstMatch_append_congr W x _ _ _ _
    (firstMatch_append_congr W x _ _ _ _ rfl ?_) ?_).symm
  · exact firstMatch_gated W x hltE b _ hloop
  · exact firstMatch_exit_gated W x hltE b _ hexit

#print axioms firstMatch_append_congr
#print axioms firstMatch_peel_agrees

end GuardNormalisation

#print axioms firstMatch_disjoin
#print axioms disjoin_exclusive


section HaltAgreement

/-! ### The halt test

`peeledSys.hlt s = (raw.hlt s ∧ ¬ bs n) ∧ h₀s n`, and `bs n`, `h₀s n` are shared
by the whole level.  They cannot be defined as sets of atoms — `T` is abstract —
but they do not have to be: both are finite `BExp` folds over the level's own
tests.  `bs n` is the disjunction of the level's loop guards, `h₀s n` the
disjunction of the level's halt tests. -/

def bigOr : List (BExp T) → BExp T
  | [] => BExp.zero
  | g :: tl => BExp.or g (bigOr tl)

theorem bval_bigOr_true {X : Type} (W : T → X → Bool) (x : X) :
    ∀ (L : List (BExp T)), GkatGS.bval W (bigOr L) x = true ↔
      ∃ g ∈ L, GkatGS.bval W g x = true := by
  intro L
  induction L with
  | nil => exact ⟨fun h => Bool.noConfusion h, fun ⟨_, hg, _⟩ => by cases hg⟩
  | cons g tl ih =>
      constructor
      · intro h
        have h' : (GkatGS.bval W g x || GkatGS.bval W (bigOr tl) x) = true := h
        cases (Bool.or_eq_true _ _).mp h' with
        | inl hg => exact ⟨g, List.mem_cons_self .., hg⟩
        | inr ht =>
            obtain ⟨g', hg', hb⟩ := ih.mp ht
            exact ⟨g', List.mem_cons_of_mem _ hg', hb⟩
      · rintro ⟨g', hg', hb⟩
        show (GkatGS.bval W g x || GkatGS.bval W (bigOr tl) x) = true
        refine (Bool.or_eq_true _ _).mpr ?_
        cases hg' with
        | head => exact Or.inl hb
        | tail _ h => exact Or.inr (ih.mpr ⟨g', h, hb⟩)

theorem bval_bigOr_false {X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T)) :
    GkatGS.bval W (bigOr L) x = false ↔ ∀ g ∈ L, GkatGS.bval W g x = false := by
  constructor
  · intro h g hg
    cases hb : GkatGS.bval W g x with
    | false => rfl
    | true =>
        have := (bval_bigOr_true W x L).mpr ⟨g, hg, hb⟩
        rw [h] at this; exact Bool.noConfusion this
  · intro h
    cases hb : GkatGS.bval W (bigOr L) x with
    | false => rfl
    | true =>
        obtain ⟨g, hg, hgt⟩ := (bval_bigOr_true W x L).mp hb
        rw [h g hg] at hgt; exact Bool.noConfusion hgt

/-- **The halt agreement.**  The peel's halt test at `s` has the same value as the
quotient's, given exactly 343's condition read on the halt side: where `s` halts
it is not raw and no loop guard of the level fires; and where `s` does NOT halt
but is still non-raw, either a loop guard fires (so `¬ bs n` kills it) or nothing
in the level halts (so `h₀s n` kills it) — the latter being the "exits shadow
halting" clause. -/
theorem bval_peel_hlt_eq {X : Type} (W : T → X → Bool) (x : X)
    (rawHlt qh : BExp T) (levelLoops levelHlts : List (BExp T))
    (hmem : qh ∈ levelHlts)
    (hraw : GkatGS.bval W qh x = true → GkatGS.bval W rawHlt x = true)
    (hloopoff : GkatGS.bval W qh x = true → ∀ g ∈ levelLoops,
      GkatGS.bval W g x = false)
    (hnot : GkatGS.bval W qh x = false → GkatGS.bval W rawHlt x = true →
      (∃ g ∈ levelLoops, GkatGS.bval W g x = true) ∨
      (∀ h ∈ levelHlts, GkatGS.bval W h x = false)) :
    GkatGS.bval W (BExp.and (BExp.and rawHlt (BExp.not (bigOr levelLoops)))
      (bigOr levelHlts)) x = GkatGS.bval W qh x := by
  show ((GkatGS.bval W rawHlt x && !GkatGS.bval W (bigOr levelLoops) x)
    && GkatGS.bval W (bigOr levelHlts) x) = _
  cases hq : GkatGS.bval W qh x with
  | true =>
      rw [hraw hq, (bval_bigOr_false W x levelLoops).mpr (hloopoff hq),
        (bval_bigOr_true W x levelHlts).mpr ⟨qh, hmem, hq⟩]
      rfl
  | false =>
      cases hr : GkatGS.bval W rawHlt x with
      | false => rfl
      | true =>
          cases hnot hq hr with
          | inl hloop =>
              rw [(bval_bigOr_true W x levelLoops).mpr hloop]
              simp
          | inr hnone =>
              rw [(bval_bigOr_false W x levelHlts).mpr hnone]
              simp

end HaltAgreement

#print axioms bval_bigOr_true
#print axioms bval_peel_hlt_eq

section CycleDemo

/-! **The two-state cycle.**  336's demo had one state, so `LoopLayerOn`'s shared
`entry` never had to distinguish between region states.  Here it does, and the
question 332 measured is answered mechanically: the shared entry is appended at
EVERY region state, so a back-edge belonging to one state appears, syntactically,
in the other's transition list too.  What makes that harmless is that the gate is
`BExp.and (base.hlt s) (BExp.and b tr.1)` — and `base.hlt` is **per state**, and
on `b`-atoms it is left completely free by `LoopLayerOn.hlt_eq`, which only
constrains `base.hlt` where `b` is false.  So `base.hlt` doubles as the selector
saying at which region states the shared entry actually fires. -/

/-- `none` is a level-0 sink; `some false → some true → some false` is a level-1
    two-cycle that exits to the sink. -/
def lvl2 : Option Bool → Nat
  | none => 0
  | some _ => 1

def d2Base : GkatThompson.GSystem (Option Bool) Unit Unit where
  states := [none, some false, some true]
  hlt := fun s => match s with
    | none => BExp.and (BExp.and BExp.one (BExp.not BExp.zero)) BExp.one
    | some false => BExp.zero
    | some true => BExp.one
  trans := fun s => match s with
    | none => []
    | some false => [(BExp.one, (), some true)]
    | some true => []

def d2Entry : List (BExp Unit × Unit × Option Bool) := [(BExp.one, (), none)]
def d2Loop : List (BExp Unit × Unit × Option Bool) := [(BExp.one, (), some false)]

def d2Mid : GkatThompson.GSystem (Option Bool) Unit Unit where
  states := d2Base.states
  hlt := fun s => match s with
    | none => d2Base.hlt none
    | some x => BExp.and (d2Base.hlt (some x)) (BExp.not (BExp.prim ()))
  trans := fun s => match s with
    | none => []
    | some x => d2Base.trans (some x) ++ d2Loop.map (fun tr =>
        (BExp.and (d2Base.hlt (some x)) (BExp.and (BExp.prim ()) tr.1), tr.2))

def d2Sys : GkatThompson.GSystem (Option Bool) Unit Unit where
  states := d2Base.states
  hlt := fun s => match s with
    | none => d2Mid.hlt none
    | some x => BExp.and (d2Mid.hlt (some x)) BExp.zero
  trans := fun s => match s with
    | none => []
    | some x => d2Mid.trans (some x) ++ d2Entry.map (fun tr =>
        (BExp.and (d2Mid.hlt (some x)) tr.1, tr.2))

theorem d2_region_one : RegionLevel d2Sys lvl2 1 := by
  refine ⟨d2Mid, d2Base, BExp.zero, BExp.prim (), d2Entry, d2Loop,
    (fun s => match s with | some false => 1 | _ => 0), some false, rfl,
    ?_, ?_, ?_, ?_, ?_⟩
  · exact { trans_eq := fun s hs => by
              cases s with
              | none => exact absurd (fun h => Nat.noConfusion h) hs
              | some x => rfl
            hlt_eq := fun s hs => by
              cases s with
              | none => exact absurd (fun h => Nat.noConfusion h) hs
              | some x => rfl
            outside := fun s hs => by
              cases s with
              | none => exact ⟨rfl, rfl⟩
              | some x => exact absurd (fun h => h rfl) hs
            states_eq := rfl }
  · intro tr htr
    cases htr with
    | head => intro h; exact Nat.noConfusion h
    | tail _ h => cases h
  · exact { trans_eq := fun s hs => by
              cases s with
              | none => exact absurd (fun h => Nat.noConfusion h) hs
              | some x => rfl
            hlt_eq := fun s hs X W x => by
              cases s with
              | none => exact absurd (fun h => Nat.noConfusion h) hs
              | some y => rfl
            outside := fun s hs => by
              cases s with
              | none => exact ⟨rfl, rfl⟩
              | some x => exact absurd (fun h => h rfl) hs
            states_eq := rfl }
  · intro s hs tr htr
    cases s with
    | none => exact Nat.noConfusion hs
    | some x =>
      have htr' : tr ∈ d2Base.trans (some x) ++ d2Loop.map (fun t =>
          (BExp.and (d2Base.hlt (some x)) (BExp.and (BExp.prim ()) t.1), t.2)) := htr
      cases List.mem_append.mp htr' with
      | inl hl =>
          cases x with
          | false => cases hl with
            | head => rfl
            | tail _ h => cases h
          | true => cases hl
      | inr hr =>
          obtain ⟨t, ht, heq⟩ := List.mem_map.mp hr
          cases ht with
          | head => rw [← heq]; rfl
          | tail _ h => cases h
  · intro s hs X W x r hfm
    cases s with
    | none => exact Nat.noConfusion hs
    | some y =>
      cases y with
      | false =>
          have h1 : GkatKleene.firstMatch W x (d2Base.trans (some false))
              = some ((), some true) := rfl
          rw [h1] at hfm
          have : r = ((), some true) := (Option.some.inj hfm).symm
          rw [this]
          exact Or.inr (Nat.lt_succ_self 0)
      | true =>
          have h0 : GkatKleene.firstMatch W x (d2Base.trans (some true)) = none := rfl
          rw [h0] at hfm
          exact (Option.some_ne_none r hfm.symm).elim

/-- The level-0 sink, peeled with empty exit and empty loop lists. -/
def d2Mid0 : GkatThompson.GSystem (Option Bool) Unit Unit where
  states := d2Base.states
  hlt := fun s => match s with
    | none => BExp.and BExp.one (BExp.not BExp.zero)
    | some x => d2Sys.hlt (some x)
  trans := fun s => match s with
    | none => []
    | some x => d2Sys.trans (some x)

def d2Base0 : GkatThompson.GSystem (Option Bool) Unit Unit where
  states := d2Base.states
  hlt := fun s => match s with
    | none => BExp.one
    | some x => d2Mid0.hlt (some x)
  trans := fun s => match s with
    | none => []
    | some x => d2Mid0.trans (some x)

theorem d2_region_zero : RegionLevel d2Sys lvl2 0 := by
  refine regionLevel_of_singleton (mid := d2Mid0) (base := d2Base0) (t := none)
    (h₀ := BExp.one) (b := BExp.zero) (entry := []) (loopEntry := []) rfl
    (fun s hs => by cases s with
      | none => rfl
      | some x => exact Nat.noConfusion hs) ?_ ?_ ?_ ?_ rfl
  · exact { trans_eq := fun s hs => by
              cases s with
              | none => rfl
              | some x => exact absurd (fun h => Nat.noConfusion h) hs
            hlt_eq := fun s hs => by
              cases s with
              | none => rfl
              | some x => exact absurd (fun h => Nat.noConfusion h) hs
            outside := fun s hs => by
              cases s with
              | none => exact absurd (fun h => h rfl) hs
              | some x => exact ⟨rfl, rfl⟩
            states_eq := rfl }
  · intro tr htr; cases htr
  · exact { trans_eq := fun s hs => by
              cases s with
              | none => rfl
              | some x => exact absurd (fun h => Nat.noConfusion h) hs
            hlt_eq := fun s hs X W x => by
              cases s with
              | none => rfl
              | some y => exact absurd (fun h => Nat.noConfusion h) hs
            outside := fun s hs => by
              cases s with
              | none => exact absurd (fun h => h rfl) hs
              | some x => exact ⟨rfl, rfl⟩
            states_eq := rfl }
  · intro tr htr; cases htr

theorem lvl2_le_one : ∀ u, lvl2 u ≤ 1
  | none => Nat.zero_le 1
  | some _ => Nat.le_refl 1

/-- **THE TWO-STATE CYCLE, SOLVED.**  Every level of `d2Sys` is regional, so the
condensation chain hands back a parametric solution — for an automaton whose
level-1 region is a genuine two-state cycle with an exit, i.e. the first case
where `LoopLayerOn`'s shared entry has to distinguish region states. -/
theorem d2_solves :
    ∃ sol : Option Bool → Exp Unit Unit,
      ∀ s, EquivBA (sol s)
        (GkatThompson.eqRHSParam d2Sys sol (Exp.test BExp.one) s) := by
  refine solves_of_region_levels lvl2 2
    (fun s => match s with | none => Nat.zero_lt_succ 1 | some _ => Nat.lt_succ_self 1)
    (fun s X W x r hfm => ?_) (fun n => ?_) (Exp.test BExp.one)
  · cases s with
    | none =>
        have h0 : GkatKleene.firstMatch W x (d2Sys.trans none) = none := rfl
        rw [h0] at hfm
        exact (Option.some_ne_none r hfm.symm).elim
    | some y => exact lvl2_le_one r.2
  · cases n with
    | zero => exact Or.inr d2_region_zero
    | succ k =>
        cases k with
        | zero => exact Or.inr d2_region_one
        | succ m =>
            refine Or.inl (fun s h => ?_)
            cases s with
            | none => exact Nat.noConfusion h
            | some x => exact Nat.noConfusion h (fun h1 => Nat.noConfusion h1)

#print axioms d2_region_zero
#print axioms d2_solves

end CycleDemo

#print axioms d2_region_one
#print axioms mono_of_syntactic
#print axioms solves_of_syntactic_levels
#print axioms solves_of_syntacticallyLayered
#print axioms layeredOn_of_levels
#print axioms layeredOn_empty_of_levels
#print axioms solves_of_levels
#print axioms layeredOn_region_closed
#print axioms layeredOn_singleton_region
#print axioms layeredOn_level_singleton
#print axioms layeredOn_level_empty
#print axioms layeredOn_of_regionLevel
#print axioms regionLevel_of_singleton
#print axioms solves_of_region_levels
#print axioms demo_regionLevel
#print axioms demo_solves


end GkatCensus
