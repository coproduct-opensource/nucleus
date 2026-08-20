import GkatAtomicLoopProofs

/-! # The cycle dichotomy — quotient closure for chain loops

    Toward completeness for multi-action loop bodies (`wh b (p;q;…)`).  Their
    Thompson automata are RANK-MODULO-SIMPLE-CYCLE: a successor function `nxt`
    such that every arm targets `nxt s` or strictly descends (self-loops are
    `nxt s = s`, subsuming the previous stratum).

    **THE DICHOTOMY**: in the cleaned canonical quotient of such a source,
    every arm out of a state `c` is (i) a self-arm, (ii) strictly descending in
    minimal-realizer rank, or (iii) THE unique cycle-successor — the class of
    `nxt u` for `c`'s minimal realizer `u`.  In other words, the
    rank-modulo-simple-cycle class is CLOSED under canonical quotients — the
    quotient-side `nxt` is `c ↦ ⟦nxt u_c⟧`.

    This is the GKAT analog of the closure facts behind Grabmayer's
    crystallization (LLEE-preservation under near-collapse) and the coequation
    paper's minimization-preserves-nesting: the structural invariant survives
    the collapse. -/

namespace GkatChainLoop

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop

variable {S A T : Type}

open Classical in
private theorem trimList_cons₃ (aut : GAut S A T) (g : BExp T) (a : A)
    (t : S) (rest : List (BExp T × A × S)) (D : BExp T) :
    trimList aut ((g, a, t) :: rest) D
      = if Live aut t then (.and g (.not D), a, t) :: trimList aut rest D
        else trimList aut rest (.or D g) := rfl

open Classical in
/-- Strengthened trim membership: the original guard fires wherever the
    trimmed guard does. -/
theorem trimList_target_mem_fires (aut : GAut S A T) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T), ∀ e ∈ trimList aut L D,
      ∃ g₀, (g₀, e.2.1, e.2.2) ∈ L ∧
        ∀ α : T → Bool, bval (genW T) e.1 α = true →
          bval (genW T) g₀ α = true := by
  intro L
  induction L with
  | nil => intro D e he; exact nomatch he
  | cons hd rest ih =>
      intro D e he
      obtain ⟨g, a, t⟩ := hd
      rw [trimList_cons₃] at he
      by_cases hl : Live aut t
      · rw [if_pos hl] at he
        rcases List.mem_cons.mp he with heq | hmem
        · subst heq
          refine ⟨g, by simp, ?_⟩
          intro α hb
          have hb' : (bval (genW T) g α
              && !(bval (genW T) D α)) = true := hb
          rw [Bool.and_eq_true] at hb'
          exact hb'.1
        · obtain ⟨g₀, hg₀, himp⟩ := ih D e hmem
          exact ⟨g₀, by simp [hg₀], himp⟩
      · rw [if_neg hl] at he
        obtain ⟨g₀, hg₀, himp⟩ := ih (.or D g) e he
        exact ⟨g₀, by simp [hg₀], himp⟩

open Classical in
/-- `firstMatch` returns a firing arm. -/
theorem firstMatch_mem_fires {Atom : Type} (V : T → Atom → Bool) {x : Atom}
    {L : List (BExp T × A × S)} {y : A × S}
    (h : firstMatch V x L = some y) :
    ∃ e ∈ L, bval V e.1 x = true ∧ e.2.1 = y.1 ∧ e.2.2 = y.2 := by
  induction L with
  | nil => exact nomatch h
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      rw [show firstMatch V x ((g, a, t) :: rest)
          = if bval V g x = true then some (a, t)
            else firstMatch V x rest from rfl] at h
      by_cases hb : bval V g x = true
      · rw [if_pos hb] at h
        have hinj := Option.some.inj h
        refine ⟨(g, a, t), by simp, hb, ?_, ?_⟩
        · rw [← hinj]
        · rw [← hinj]
      · rw [if_neg hb] at h
        obtain ⟨e, he, h1, h2, h3⟩ := ih h
        exact ⟨e, by simp [he], h1, h2, h3⟩


open Classical in
/-- **THE CYCLE DICHOTOMY**: each state of the cleaned canonical quotient of a
    rank-modulo-simple-cycle automaton carries a minimal realizer `u` such
    that every cleaned arm is a self-arm, strictly descends in minimal-realizer
    rank, or targets exactly the class of `nxt u`. -/
theorem quot_cycle_dichotomy (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s) :
    ∀ c ∈ (bisimQuotAut (trimAut aut)).states,
    ∃ u, rank u ≤ minRank (trimAut aut) rank c ∧
      autLang (genW T) (trimAut aut) u = autLang (genW T) (trimAut aut) c ∧
      ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans c,
        e.2.2 = c ∨
        minRank (trimAut aut) rank e.2.2 < minRank (trimAut aut) rank c ∨
        e.2.2 = bisimRep (trimAut aut) (nxt u) := by
  have hdecT : ∀ s (α : T → Bool), ∀ e ∈ (trimAut aut).trans s,
      bval (genW T) e.1 α = true →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
    intro s α e he hb
    obtain ⟨g₀, hg₀, himp⟩ := trimList_target_mem_fires aut (aut.trans s)
      .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀ ⟨α, himp α hb⟩
  intro c hc
  obtain ⟨u, hule, huL⟩ := minRank_spec (trimAut aut) rank c
  refine ⟨u, hule, huL, ?_⟩
  intro e he
  by_cases hself : e.2.2 = c
  · exact Or.inl hself
  · -- the arm fires at some generic atom
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
    -- rep-fixedness of the target
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
    -- the realizer fires at α with the same letter
    obtain ⟨β₀, w₀, hw₀⟩ := htlive
    have hword : autRun (genW T) (trimAut aut) c α ((e.2.1, β₀) :: w₀) :=
      (hDT β₀ w₀).mp hw₀
    have hwordU : autRun (genW T) (trimAut aut) u α ((e.2.1, β₀) :: w₀) :=
      (iff_of_eq (congrFun huL (α, (e.2.1, β₀) :: w₀))).mpr hword
    obtain ⟨v, hstepU, -⟩ : ∃ v,
        autStep (genW T) (trimAut aut) u α = some (e.2.1, v)
        ∧ autRun (genW T) (trimAut aut) v β₀ w₀ := hwordU
    -- v's language is the target's language
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
    -- v is an arm target of u: the cycle successor or strictly lower
    obtain ⟨ea, hea, hbea, -, heat⟩ := firstMatch_mem_fires (genW T) hstepU
    have heat' : ea.2.2 = v := heat
    rcases hdecT u α ea hea hbea with hEq | hLt
    · -- the cycle case: the target IS the class of `nxt u`
      refine Or.inr (Or.inr ?_)
      have hvn : v = nxt u := heat'.symm.trans hEq
      have hLnxt : autLang (genW T) (trimAut aut)
          (bisimRep (trimAut aut) (nxt u))
          = autLang (genW T) (trimAut aut) e.2.2 := by
        have h0 : autLang (genW T) (trimAut aut) (nxt u)
            = autLang (genW T) (trimAut aut)
              (bisimRep (trimAut aut) (nxt u)) :=
          autLang_eq_of_gautBisim (genBisimilar_bisim (trimAut aut))
            (bisimRep_bisim (trimAut aut) (nxt u))
        rw [← h0, ← hvn]
        exact hvL
      exact (trim_repfixed_lang_eq aut htfix
        (bisimRep_idem (trimAut aut) (nxt u)) hLnxt).symm
    · -- the descending case
      refine Or.inr (Or.inl ?_)
      have hvrank : rank v < rank u := by
        rw [heat'] at hLt
        exact hLt
      have h1 : minRank (trimAut aut) rank e.2.2 ≤ rank v :=
        minRank_le (trimAut aut) rank hvL
      omega

#print axioms quot_cycle_dichotomy

end GkatChainLoop
