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

end GkatCensus