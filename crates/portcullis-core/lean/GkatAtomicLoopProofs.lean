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

end GkatAtomicLoop
