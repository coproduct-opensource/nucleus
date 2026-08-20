import GkatLoopFreeProofs

/-! # The self-loop engine — toward completeness with loops

    `bounded_quot_solvesBA` handled strictly ranked automata.  This file
    generalizes to RANK-MODULO-SELF-LOOP automata (every arm is a self-loop or
    strictly descends): their canonical quotients are still singleton-SCC.

    The heart is MINIMAL-RANK-REALIZER DESCENT: a firing quotient arm between
    DISTINCT states takes languages to derivatives; the minimal-rank source
    realizer of the source language must fire to a realizer of the target
    language that is either itself (forcing the two quotient states equal) or
    of strictly smaller rank — so the minimal realizer rank strictly descends,
    and no cycle among distinct quotient states can fire. -/

namespace GkatAtomicLoop

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree

variable {S A T : Type}

/-- The step-derivative characterization: after a step, membership is exactly
    prefixed membership. -/
theorem step_derivative {Atom : Type} {V : T → Atom → Bool} {aut : GAut S A T}
    {s t : S} {x : Atom} {q : A}
    (hstep : autStep V aut s x = some (q, t)) :
    ∀ (β : Atom) (w : List (A × Atom)),
      autRun V aut t β w ↔ autRun V aut s x ((q, β) :: w) := by
  intro β w
  constructor
  · intro hr
    exact ⟨t, hstep, hr⟩
  · intro hr
    obtain ⟨t', hstep', hr'⟩ : ∃ t', autStep V aut s x = some (q, t')
        ∧ autRun V aut t' β w := hr
    have hp : (q, t) = (q, t') := Option.some.inj (hstep.symm.trans hstep')
    have ht : t = t' := congrArg Prod.snd hp
    rw [ht]
    exact hr'

open Classical in
/-- The least budget at which a monotone predicate holds, scanned downward. -/
noncomputable def minUpTo (P : Nat → Prop) : Nat → Nat
  | 0 => 0
  | b + 1 => if P b then minUpTo P b else b + 1

open Classical in
private theorem minUpTo_succ (P : Nat → Prop) (b : Nat) :
    minUpTo P (b + 1) = if P b then minUpTo P b else b + 1 := rfl

open Classical in
theorem minUpTo_spec (P : Nat → Prop) :
    ∀ b, P b → P (minUpTo P b) := by
  intro b
  induction b with
  | zero => intro h; exact h
  | succ b ih =>
      intro h
      rw [minUpTo_succ]
      by_cases hb : P b
      · rw [if_pos hb]; exact ih hb
      · rw [if_neg hb]; exact h

open Classical in
theorem minUpTo_min (P : Nat → Prop)
    (mono : ∀ i j, i ≤ j → P i → P j) :
    ∀ b, P b → ∀ k, P k → minUpTo P b ≤ k := by
  intro b
  induction b with
  | zero => intro _ k _; exact Nat.zero_le _
  | succ b ih =>
      intro h k hk
      rw [minUpTo_succ]
      by_cases hb : P b
      · rw [if_pos hb]; exact ih hb k hk
      · rw [if_neg hb]
        by_cases hkb : k ≤ b
        · exact absurd (mono k b hkb hk) hb
        · omega

open Classical in
/-- The minimal rank of a realizer of a state's generic language. -/
noncomputable def minRank (aut : GAut S A T) (rank : S → Nat) (c : S) : Nat :=
  minUpTo (fun n => ∃ u, rank u ≤ n ∧
    autLang (genW T) aut u = autLang (genW T) aut c) (rank c)

open Classical in
private theorem minRank_mono (aut : GAut S A T) (rank : S → Nat) (c : S) :
    ∀ i j, i ≤ j →
    (∃ u, rank u ≤ i ∧ autLang (genW T) aut u = autLang (genW T) aut c) →
    (∃ u, rank u ≤ j ∧ autLang (genW T) aut u = autLang (genW T) aut c) := by
  intro i j hij h
  obtain ⟨u, hu, hL⟩ := h
  exact ⟨u, Nat.le_trans hu hij, hL⟩

open Classical in
theorem minRank_spec (aut : GAut S A T) (rank : S → Nat) (c : S) :
    ∃ u, rank u ≤ minRank aut rank c ∧
      autLang (genW T) aut u = autLang (genW T) aut c :=
  minUpTo_spec (fun n => ∃ u, rank u ≤ n ∧
    autLang (genW T) aut u = autLang (genW T) aut c) (rank c)
    ⟨c, Nat.le_refl _, rfl⟩

open Classical in
theorem minRank_le (aut : GAut S A T) (rank : S → Nat) {c u : S}
    (h : autLang (genW T) aut u = autLang (genW T) aut c) :
    minRank aut rank c ≤ rank u :=
  minUpTo_min (fun n => ∃ u, rank u ≤ n ∧
    autLang (genW T) aut u = autLang (genW T) aut c)
    (minRank_mono aut rank c) (rank c)
    ⟨c, Nat.le_refl _, rfl⟩ (rank u) ⟨u, Nat.le_refl _, h⟩

open Classical in
/-- Representatives are fixed points of `bisimRep`. -/
theorem bisimRep_idem (aut : GAut S A T) (w : S) :
    bisimRep aut (bisimRep aut w) = bisimRep aut w :=
  bisimRep_coherent aut (GenBisimilar.symm (bisimRep_bisim aut w))

open Classical in
/-- Two `bisimRep`-fixed states of the trim with equal generic languages are
    EQUAL. -/
theorem trim_repfixed_lang_eq (aut : GAut S A T) {c t' : S}
    (hc : bisimRep (trimAut aut) c = c)
    (ht : bisimRep (trimAut aut) t' = t')
    (hL : autLang (genW T) (trimAut aut) t'
      = autLang (genW T) (trimAut aut) c) :
    t' = c := by
  have hU : UniformStateEquiv (trimAut aut) t' c :=
    uniformStateEquiv_of_gen hL
  have hB : GenBisimilar (trimAut aut) t' c :=
    genBisimilar_of_uniformStateEquiv (liveSteps_trimAut aut) hU
  have := bisimRep_coherent (trimAut aut) hB
  rw [hc, ht] at this
  exact this

open Classical in
/-- **THE SELF-LOOP ENGINE**: the canonical quotient of a
    rank-modulo-self-loop automaton is provably solvable. -/
theorem rankSelf_quot_solvesBA (aut : GAut S A T) (rank : S → Nat)
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ qsol : S → Exp A T,
      SolvesBA (bisimQuotAut (trimAut aut)) qsol := by
  have hdecT : ∀ s, ∀ e ∈ (trimAut aut).trans s,
      e.2.2 = s ∨ rank e.2.2 < rank s := by
    intro s e he
    obtain ⟨g₀, hg₀⟩ := trimList_target_mem aut (aut.trans s) .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀
  have hshape : ∀ c ∈ (cleanAut (bisimQuotAut (trimAut aut))).states,
      ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans c,
      e.2.2 = c ∨ minRank (trimAut aut) rank e.2.2
        < minRank (trimAut aut) rank c := by
    intro c hc e he
    by_cases hself : e.2.2 = c
    · exact Or.inl hself
    · refine Or.inr ?_
      -- the arm fires at some generic atom
      obtain ⟨α, -, hfm⟩ := cleanList_fires
        (bisimQuotAut (trimAut aut))
        ((bisimQuotAut (trimAut aut)).trans c) .zero e he
      have hstepC : autStep (genW T)
          (cleanAut (bisimQuotAut (trimAut aut))) c α
          = some (e.2.1, e.2.2) := hfm
      have hstepQ : autStep (genW T) (bisimQuotAut (trimAut aut)) c α
          = some (e.2.1, e.2.2) := by
        rw [← autStep_cleanAut (genW T)]
        exact hstepC
      -- rep-fixedness of c and the target
      have hcfix : bisimRep (trimAut aut) c = c := by
        obtain ⟨w, -, hw⟩ := List.mem_map.mp hc
        rw [← hw]
        exact bisimRep_idem (trimAut aut) w
      have heQ : e ∈ (bisimQuotAut (trimAut aut)).trans c :=
        cleanList_sub _ .zero e he
      obtain ⟨v'', hv'', hrep⟩ : ∃ v'', v'' ∈ (trimAut aut).trans c ∧
          bisimRep (trimAut aut) v''.2.2 = e.2.2 := by
        obtain ⟨v'', hv'', heq⟩ := List.mem_map.mp heQ
        exact ⟨v'', hv'', congrArg (fun z => z.2.2) heq⟩
      have htfix : bisimRep (trimAut aut) e.2.2 = e.2.2 := by
        rw [← hrep]
        exact bisimRep_idem (trimAut aut) v''.2.2
      -- the quotient step is a language derivative (in trim terms)
      have hDT : ∀ (β : T → Bool) (w : List (A × (T → Bool))),
          autRun (genW T) (trimAut aut) e.2.2 β w ↔
            autRun (genW T) (trimAut aut) c α ((e.2.1, β) :: w) := by
        intro β w
        have h1 := step_derivative hstepQ β w
        have h2 : autRun (genW T) (bisimQuotAut (trimAut aut)) e.2.2 β w
            ↔ autRun (genW T) (trimAut aut) e.2.2 β w :=
          iff_of_eq (congrFun (quot_lang_eq aut e.2.2) (β, w))
        have h3 : autRun (genW T) (bisimQuotAut (trimAut aut)) c α
              ((e.2.1, β) :: w)
            ↔ autRun (genW T) (trimAut aut) c α ((e.2.1, β) :: w) :=
          iff_of_eq (congrFun (quot_lang_eq aut c) (α, (e.2.1, β) :: w))
        exact (h2.symm.trans h1).trans h3
      -- the target is live
      have htlive : ∃ (β : T → Bool) (w : List (A × (T → Bool))),
          autRun (genW T) (trimAut aut) e.2.2 β w := by
        have hlv : Live aut v''.2.2 :=
          trimList_target_live aut (aut.trans c) .zero v'' hv''
        have hlvT : Live (trimAut aut) v''.2.2 := live_trimAut hlv
        obtain ⟨β, w, hw⟩ := hlvT
        have hle : autLang (genW T) (trimAut aut) v''.2.2
            = autLang (genW T) (trimAut aut) e.2.2 := by
          rw [← hrep]
          exact autLang_eq_of_gautBisim (genBisimilar_bisim (trimAut aut))
            (bisimRep_bisim (trimAut aut) v''.2.2)
        exact ⟨β, w, (iff_of_eq (congrFun hle (β, w))).mp hw⟩
      -- the minimal realizer of c's language
      obtain ⟨u, hule, huL⟩ := minRank_spec (trimAut aut) rank c
      -- u fires at α with the same letter, to a realizer of the target
      obtain ⟨β₀, w₀, hw₀⟩ := htlive
      have hword : autRun (genW T) (trimAut aut) c α ((e.2.1, β₀) :: w₀) :=
        (hDT β₀ w₀).mp hw₀
      have hwordU : autRun (genW T) (trimAut aut) u α ((e.2.1, β₀) :: w₀) :=
        (iff_of_eq (congrFun huL (α, (e.2.1, β₀) :: w₀))).mpr hword
      obtain ⟨v, hstepU, -⟩ : ∃ v,
          autStep (genW T) (trimAut aut) u α = some (e.2.1, v)
          ∧ autRun (genW T) (trimAut aut) v β₀ w₀ := hwordU
      -- v's language is the same derivative, hence the target's language
      have hvL : autLang (genW T) (trimAut aut) v
          = autLang (genW T) (trimAut aut) e.2.2 := by
        funext gs
        obtain ⟨β, w⟩ := gs
        apply propext
        have hDU := step_derivative hstepU β w
        have hDc := hDT β w
        have hcu : autRun (genW T) (trimAut aut) u α ((e.2.1, β) :: w)
            ↔ autRun (genW T) (trimAut aut) c α ((e.2.1, β) :: w) :=
          iff_of_eq (congrFun huL (α, (e.2.1, β) :: w))
        exact hDU.trans (hcu.trans hDc.symm)
      -- v is an arm target of u: itself or strictly lower
      obtain ⟨ea, hea, -, heat⟩ := firstMatch_mem (genW T) hstepU
      have heat' : ea.2.2 = v := heat
      rcases hdecT u ea hea with hEq | hLt
      · -- v = u: the target's language equals c's, forcing target = c
        exfalso
        have hvu : v = u := heat'.symm.trans hEq
        have hLtc : autLang (genW T) (trimAut aut) e.2.2
            = autLang (genW T) (trimAut aut) c := by
          rw [← hvL, hvu, huL]
        exact hself (trim_repfixed_lang_eq aut hcfix htfix hLtc)
      · -- strict descent of the minimal realizer rank
        have hvrank : rank v < rank u := by
          rw [heat'] at hLt
          exact hLt
        have h1 : minRank (trimAut aut) rank e.2.2 ≤ rank v :=
          minRank_le (trimAut aut) rank hvL
        -- minimality: rank u ≤ minRank c since u realizes c
        omega
  obtain ⟨qsol, hroles⟩ := singleton_scc_roles
    (cleanAut (bisimQuotAut (trimAut aut)))
    (fun c => minRank (trimAut aut) rank c) hshape
  exact ⟨qsol, solvesBA_unclean _ (decomp_solves _ _ hroles)⟩

#print axioms rankSelf_quot_solvesBA

/-! ## The atomic-loop fragment: loops over single actions -/

/-- Loop-free structure plus loops whose bodies are single actions. -/
inductive AtomicLoops : Exp A T → Prop where
  | act (p : A) : AtomicLoops (.act p)
  | test (b : BExp T) : AtomicLoops (.test b)
  | seq {e f : Exp A T} : AtomicLoops e → AtomicLoops f →
      AtomicLoops (.seq e f)
  | ite (b : BExp T) {e f : Exp A T} : AtomicLoops e → AtomicLoops f →
      AtomicLoops (.ite b e f)
  | wh (b : BExp T) (p : A) : AtomicLoops (.wh b (.act p))

/-- A ranked-modulo-self initialized automaton. -/
structure InitRankedSelf {S' : Type} (aut : InitializedGAut S' A T)
    (r : S' → Nat) (top : Nat) : Prop where
  init : ∀ t ∈ aut.initTrans, r t.2.2 < top
  core : ∀ s, ∀ t ∈ aut.core.trans s, t.2.2 = s ∨ r t.2.2 < r s
  bound : ∀ s, r s < top

/-- Atomic-loop Thompson automata are ranked modulo self-loops. -/
theorem atomicLoops_initRankedSelf {e : Exp A T} (h : AtomicLoops e) :
    ∃ (r : (certifiedThompson A T e).State → Nat) (top : Nat),
      InitRankedSelf (certifiedThompson A T e).aut r top := by
  induction h with
  | act p =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_cons.mp ht with heq | hmem
        · subst heq; exact Nat.zero_lt_one
        · exact nomatch hmem
      · intro s t ht
        exact nomatch ht
      · intro _; exact Nat.zero_lt_one
  | test b =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht; exact nomatch ht
      · intro s; exact nomatch s
      · intro s; exact nomatch s
  | wh b p =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        exact Nat.zero_lt_one
      · intro s t ht
        exact Or.inl rfl
      · intro _; exact Nat.zero_lt_one
  | @seq e f _ _ ihe ihf =>
      obtain ⟨r₁, t₁, h₁⟩ := ihe
      obtain ⟨r₂, t₂, h₂⟩ := ihf
      refine ⟨Sum.elim (fun s => r₁ s + t₂) r₂, t₁ + t₂, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_append.mp ht with hL | hR
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
          rw [← heq]
          have := h₁.init t₀ ht₀
          show r₁ t₀.2.2 + t₂ < t₁ + t₂
          omega
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
          rw [← heq]
          have := h₂.init t₀ ht₀
          have := h₂.bound t₀.2.2
          show r₂ t₀.2.2 < t₁ + t₂
          omega
      · intro s t ht
        cases s with
        | inl u =>
            rcases List.mem_append.mp ht with hL | hR
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
              rcases h₁.core u t₀ ht₀ with hEq | hLt
              · refine Or.inl ?_
                rw [← heq]
                show Sum.inl t₀.2.2 = Sum.inl u
                rw [hEq]
              · refine Or.inr ?_
                rw [← heq]
                show r₁ t₀.2.2 + t₂ < r₁ u + t₂
                omega
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
              refine Or.inr ?_
              rw [← heq]
              have := h₂.init t₀ ht₀
              show r₂ t₀.2.2 < r₁ u + t₂
              omega
        | inr u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rcases h₂.core u t₀ ht₀ with hEq | hLt
            · refine Or.inl ?_
              rw [← heq]
              show Sum.inr t₀.2.2 = Sum.inr u
              rw [hEq]
            · refine Or.inr ?_
              rw [← heq]
              show r₂ t₀.2.2 < r₂ u
              omega
      · intro s
        cases s with
        | inl u =>
            have := h₁.bound u
            show r₁ u + t₂ < t₁ + t₂
            omega
        | inr u =>
            have := h₂.bound u
            show r₂ u < t₁ + t₂
            omega
  | @ite b e f _ _ ihe ihf =>
      obtain ⟨r₁, t₁, h₁⟩ := ihe
      obtain ⟨r₂, t₂, h₂⟩ := ihf
      refine ⟨Sum.elim r₁ r₂, t₁ + t₂, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_append.mp ht with hL | hR
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
          rw [← heq]
          have := h₁.init t₀ ht₀
          show r₁ t₀.2.2 < t₁ + t₂
          omega
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
          rw [← heq]
          have := h₂.init t₀ ht₀
          show r₂ t₀.2.2 < t₁ + t₂
          omega
      · intro s t ht
        cases s with
        | inl u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rcases h₁.core u t₀ ht₀ with hEq | hLt
            · refine Or.inl ?_
              rw [← heq]
              show Sum.inl t₀.2.2 = Sum.inl u
              rw [hEq]
            · refine Or.inr ?_
              rw [← heq]
              show r₁ t₀.2.2 < r₁ u
              omega
        | inr u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rcases h₂.core u t₀ ht₀ with hEq | hLt
            · refine Or.inl ?_
              rw [← heq]
              show Sum.inr t₀.2.2 = Sum.inr u
              rw [hEq]
            · refine Or.inr ?_
              rw [← heq]
              show r₂ t₀.2.2 < r₂ u
              omega
      · intro s
        cases s with
        | inl u =>
            have := h₁.bound u
            show r₁ u < t₁ + t₂
            omega
        | inr u =>
            have := h₂.bound u
            show r₂ u < t₁ + t₂
            omega

theorem toGAut_rankedSelf {S' : Type} {aut : InitializedGAut S' A T}
    {r : S' → Nat} {top : Nat} (h : InitRankedSelf aut r top) :
    ∀ s, ∀ e ∈ aut.toGAut.trans s,
      e.2.2 = s ∨ optRank r top e.2.2 < optRank r top s := by
  intro s e he
  cases s with
  | none =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      refine Or.inr ?_
      rw [← heq]
      exact h.init t₀ ht₀
  | some u =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      rcases h.core u t₀ ht₀ with hEq | hLt
      · refine Or.inl ?_
        rw [← heq]
        show some t₀.2.2 = some u
        rw [hEq]
      · refine Or.inr ?_
        rw [← heq]
        exact hLt

theorem sumGAut_rankedSelf {S₁ S₂ : Type} {aut₁ : GAut S₁ A T}
    {aut₂ : GAut S₂ A T} {rk₁ : S₁ → Nat} {rk₂ : S₂ → Nat}
    (h₁ : ∀ s, ∀ e ∈ aut₁.trans s, e.2.2 = s ∨ rk₁ e.2.2 < rk₁ s)
    (h₂ : ∀ s, ∀ e ∈ aut₂.trans s, e.2.2 = s ∨ rk₂ e.2.2 < rk₂ s) :
    ∀ s, ∀ e ∈ (sumGAut aut₁ aut₂).trans s,
      e.2.2 = s ∨ Sum.elim rk₁ rk₂ e.2.2 < Sum.elim rk₁ rk₂ s := by
  intro s e he
  cases s with
  | inl u =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      rcases h₁ u t₀ ht₀ with hEq | hLt
      · refine Or.inl ?_
        rw [← heq]
        show Sum.inl t₀.2.2 = Sum.inl u
        rw [hEq]
      · refine Or.inr ?_
        rw [← heq]
        exact hLt
  | inr u =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      rcases h₂ u t₀ ht₀ with hEq | hLt
      · refine Or.inl ?_
        rw [← heq]
        show Sum.inr t₀.2.2 = Sum.inr u
        rw [hEq]
      · refine Or.inr ?_
        rw [← heq]
        exact hLt

open GkatSumQuotient in
/-- **ATOMIC-LOOP COMPLETENESS** — unconditional: the finite GKAT axioms with
    the test Boolean algebra are complete for uniformly-language-equivalent
    programs whose loops range over single actions.  Strictly extends
    `loopfree_complete`; no uniqueness axiom, no hypotheses. -/
theorem atomicloops_complete (e f : Exp A T)
    (he : AtomicLoops e) (hf : AtomicLoops f)
    (heq : UniformLanguageEquivalent e f) : EquivBA e f := by
  obtain ⟨r₁, t₁, h₁⟩ := atomicLoops_initRankedSelf he
  obtain ⟨r₂, t₂, h₂⟩ := atomicLoops_initRankedSelf hf
  obtain ⟨qsol, hq⟩ := rankSelf_quot_solvesBA (SUMof A T e f)
    (Sum.elim (optRank r₁ t₁) (optRank r₂ t₂))
    (sumGAut_rankedSelf (toGAut_rankedSelf h₁) (toGAut_rankedSelf h₂))
  exact equivBA_of_quot_solvesBA e f heq hq

#print axioms atomicloops_complete

/-! ## Guarded one-action loops: real WHILE loops

    `wh b body` where the body carries AT MOST ONE action with arbitrary test
    padding — `wh b (g?; p; h?)` and friends.  The structural key: a
    zero-action body has an UNINHABITED Thompson carrier, and a one-action
    body a SUBSINGLETON one — so every loop back-edge is a self-arm for
    free. -/

/-- Pure-test programs (no actions). -/
inductive NoAct : Exp A T → Prop where
  | test (b : BExp T) : NoAct (.test b)
  | seq {e f : Exp A T} : NoAct e → NoAct f → NoAct (.seq e f)
  | ite (b : BExp T) {e f : Exp A T} : NoAct e → NoAct f →
      NoAct (.ite b e f)

/-- Programs with exactly one action occurrence (test padding free). -/
inductive OneAct : Exp A T → Prop where
  | act (p : A) : OneAct (.act p)
  | seqL {e f : Exp A T} : OneAct e → NoAct f → OneAct (.seq e f)
  | seqR {e f : Exp A T} : NoAct e → OneAct f → OneAct (.seq e f)
  | iteL (b : BExp T) {e f : Exp A T} : OneAct e → NoAct f →
      OneAct (.ite b e f)
  | iteR (b : BExp T) {e f : Exp A T} : NoAct e → OneAct f →
      OneAct (.ite b e f)

theorem noAct_empty {e : Exp A T} (h : NoAct e) :
    (certifiedThompson A T e).State → False := by
  induction h with
  | test b => exact fun s => nomatch s
  | seq _ _ ihe ihf =>
      intro s
      cases s with
      | inl u => exact ihe u
      | inr u => exact ihf u
  | ite b _ _ ihe ihf =>
      intro s
      cases s with
      | inl u => exact ihe u
      | inr u => exact ihf u

theorem oneAct_subsingleton {e : Exp A T} (h : OneAct e) :
    ∀ x y : (certifiedThompson A T e).State, x = y := by
  induction h with
  | act p => intro x y; rfl
  | seqL _ hf ihe =>
      intro x y
      cases x with
      | inl u =>
          cases y with
          | inl v => exact congrArg Sum.inl (ihe u v)
          | inr v => exact (noAct_empty hf v).elim
      | inr u => exact (noAct_empty hf u).elim
  | seqR he _ ihf =>
      intro x y
      cases x with
      | inl u => exact (noAct_empty he u).elim
      | inr u =>
          cases y with
          | inl v => exact (noAct_empty he v).elim
          | inr v => exact congrArg Sum.inr (ihf u v)
  | iteL b _ hf ihe =>
      intro x y
      cases x with
      | inl u =>
          cases y with
          | inl v => exact congrArg Sum.inl (ihe u v)
          | inr v => exact (noAct_empty hf v).elim
      | inr u => exact (noAct_empty hf u).elim
  | iteR b he _ ihf =>
      intro x y
      cases x with
      | inl u => exact (noAct_empty he u).elim
      | inr u =>
          cases y with
          | inl v => exact (noAct_empty he v).elim
          | inr v => exact congrArg Sum.inr (ihf u v)

/-- The guarded-loop fragment: loop-free structure plus loops whose bodies
    carry at most one action, with arbitrary test padding. -/
inductive GLoops : Exp A T → Prop where
  | act (p : A) : GLoops (.act p)
  | test (b : BExp T) : GLoops (.test b)
  | seq {e f : Exp A T} : GLoops e → GLoops f → GLoops (.seq e f)
  | ite (b : BExp T) {e f : Exp A T} : GLoops e → GLoops f →
      GLoops (.ite b e f)
  | whOne (b : BExp T) {body : Exp A T} (h : OneAct body) :
      GLoops (.wh b body)
  | whZero (b : BExp T) {body : Exp A T} (h : NoAct body) :
      GLoops (.wh b body)

/-- Guarded-loop Thompson automata are ranked modulo self-loops. -/
theorem gLoops_initRankedSelf {e : Exp A T} (h : GLoops e) :
    ∃ (r : (certifiedThompson A T e).State → Nat) (top : Nat),
      InitRankedSelf (certifiedThompson A T e).aut r top := by
  induction h with
  | act p =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_cons.mp ht with heq | hmem
        · subst heq; exact Nat.zero_lt_one
        · exact nomatch hmem
      · intro s t ht
        exact nomatch ht
      · intro _; exact Nat.zero_lt_one
  | test b =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht; exact nomatch ht
      · intro s; exact nomatch s
      · intro s; exact nomatch s
  | whOne b hbody =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        exact Nat.zero_lt_one
      · intro s t ht
        exact Or.inl (oneAct_subsingleton hbody t.2.2 s)
      · intro _; exact Nat.zero_lt_one
  | whZero b hbody =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        exact (noAct_empty hbody t.2.2).elim
      · intro s
        exact (noAct_empty hbody s).elim
      · intro s
        exact (noAct_empty hbody s).elim
  | @seq e f _ _ ihe ihf =>
      obtain ⟨r₁, t₁, h₁⟩ := ihe
      obtain ⟨r₂, t₂, h₂⟩ := ihf
      refine ⟨Sum.elim (fun s => r₁ s + t₂) r₂, t₁ + t₂, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_append.mp ht with hL | hR
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
          rw [← heq]
          have := h₁.init t₀ ht₀
          show r₁ t₀.2.2 + t₂ < t₁ + t₂
          omega
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
          rw [← heq]
          have := h₂.init t₀ ht₀
          have := h₂.bound t₀.2.2
          show r₂ t₀.2.2 < t₁ + t₂
          omega
      · intro s t ht
        cases s with
        | inl u =>
            rcases List.mem_append.mp ht with hL | hR
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
              rcases h₁.core u t₀ ht₀ with hEq | hLt
              · refine Or.inl ?_
                rw [← heq]
                show Sum.inl t₀.2.2 = Sum.inl u
                rw [hEq]
              · refine Or.inr ?_
                rw [← heq]
                show r₁ t₀.2.2 + t₂ < r₁ u + t₂
                omega
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
              refine Or.inr ?_
              rw [← heq]
              have := h₂.init t₀ ht₀
              show r₂ t₀.2.2 < r₁ u + t₂
              omega
        | inr u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rcases h₂.core u t₀ ht₀ with hEq | hLt
            · refine Or.inl ?_
              rw [← heq]
              show Sum.inr t₀.2.2 = Sum.inr u
              rw [hEq]
            · refine Or.inr ?_
              rw [← heq]
              show r₂ t₀.2.2 < r₂ u
              omega
      · intro s
        cases s with
        | inl u =>
            have := h₁.bound u
            show r₁ u + t₂ < t₁ + t₂
            omega
        | inr u =>
            have := h₂.bound u
            show r₂ u < t₁ + t₂
            omega
  | @ite b e f _ _ ihe ihf =>
      obtain ⟨r₁, t₁, h₁⟩ := ihe
      obtain ⟨r₂, t₂, h₂⟩ := ihf
      refine ⟨Sum.elim r₁ r₂, t₁ + t₂, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_append.mp ht with hL | hR
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
          rw [← heq]
          have := h₁.init t₀ ht₀
          show r₁ t₀.2.2 < t₁ + t₂
          omega
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
          rw [← heq]
          have := h₂.init t₀ ht₀
          show r₂ t₀.2.2 < t₁ + t₂
          omega
      · intro s t ht
        cases s with
        | inl u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rcases h₁.core u t₀ ht₀ with hEq | hLt
            · refine Or.inl ?_
              rw [← heq]
              show Sum.inl t₀.2.2 = Sum.inl u
              rw [hEq]
            · refine Or.inr ?_
              rw [← heq]
              show r₁ t₀.2.2 < r₁ u
              omega
        | inr u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rcases h₂.core u t₀ ht₀ with hEq | hLt
            · refine Or.inl ?_
              rw [← heq]
              show Sum.inr t₀.2.2 = Sum.inr u
              rw [hEq]
            · refine Or.inr ?_
              rw [← heq]
              show r₂ t₀.2.2 < r₂ u
              omega
      · intro s
        cases s with
        | inl u =>
            have := h₁.bound u
            show r₁ u < t₁ + t₂
            omega
        | inr u =>
            have := h₂.bound u
            show r₂ u < t₁ + t₂
            omega

open GkatSumQuotient in
/-- **GUARDED-LOOP COMPLETENESS** — unconditional: the finite GKAT axioms
    with the test Boolean algebra are complete for uniformly-language-
    equivalent programs whose loop bodies carry at most one action with
    arbitrary test padding — real WHILE loops `wh b (g?; p; h?)`.  Strictly
    extends `atomicloops_complete` and `loopfree_complete`. -/
theorem gloops_complete (e f : Exp A T)
    (he : GLoops e) (hf : GLoops f)
    (heq : UniformLanguageEquivalent e f) : EquivBA e f := by
  obtain ⟨r₁, t₁, h₁⟩ := gLoops_initRankedSelf he
  obtain ⟨r₂, t₂, h₂⟩ := gLoops_initRankedSelf hf
  obtain ⟨qsol, hq⟩ := rankSelf_quot_solvesBA (SUMof A T e f)
    (Sum.elim (optRank r₁ t₁) (optRank r₂ t₂))
    (sumGAut_rankedSelf (toGAut_rankedSelf h₁) (toGAut_rankedSelf h₂))
  exact equivBA_of_quot_solvesBA e f heq hq

#print axioms gloops_complete

end GkatAtomicLoop
