import GkatOrbitProofs

/-! # The walked orbit layer — nested loops, first stones

    Nested loops break the two-way fired-arm discipline: a state carrying
    an inner loop has BOTH a self-arm (the inner cycle) and an advance arm
    (the outer cycle).  The walked discipline is three-way:

        fired arm ⟹ self ∨ successor ∨ strict rank descent.

    The walked assembly (`walked_exit_cycle_roles`) already tolerates
    member self-loops; what must generalize is the ORBIT layer.  The
    first stones: minimal-level firings land on self-or-successor, and
    the class successor is still well-defined at NON-DEGENERATE positions
    — where the advance changes the language, which `qorb_injective`
    guarantees along genuine quotient cycles. -/

namespace GkatWalkedOrbit

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop GkatChainLoop GkatOrbit

variable {S A T : Type}

/-- The three-way fired-arm discipline. -/
def WalkedDec (aut : GAut S A T) (rank : S → Nat) (nxt : S → S) : Prop :=
  ∀ s, ∀ e ∈ aut.trans s,
    (∃ α : T → Bool, bval (genW T) e.1 α = true) →
    e.2.2 = s ∨ e.2.2 = nxt s ∨ rank e.2.2 < rank s

open Classical in
/-- **WALKED MIN-LEVEL FIRING**: a firing whose target's rank is not
    below the source's lands on self or the successor. -/
theorem walked_min_fire (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : WalkedDec aut rank nxt)
    {s v : S} {α : T → Bool} {a : A}
    (hstep : autStep (genW T) (trimAut aut) s α = some (a, v))
    (hvmin : rank s ≤ rank v) :
    v = s ∨ v = nxt s := by
  have hdecT : ∀ s (α : T → Bool), ∀ e ∈ (trimAut aut).trans s,
      bval (genW T) e.1 α = true →
      e.2.2 = s ∨ e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
    intro s α e he hb
    obtain ⟨g₀, hg₀, himp⟩ := trimList_target_mem_fires aut (aut.trans s)
      .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀ ⟨α, himp α hb⟩
  obtain ⟨ea, hea, hbea, -, heat⟩ := firstMatch_mem_fires (genW T) hstep
  have heat' : ea.2.2 = v := heat
  rcases hdecT s α ea hea hbea with hSelf | hEq | hLt
  · exact Or.inl (heat'.symm.trans hSelf)
  · exact Or.inr (heat'.symm.trans hEq)
  · rw [heat'] at hLt
    omega

open Classical in
/-- **WALKED CLASS-SUCCESSOR WELL-DEFINEDNESS**: at a non-degenerate
    position — the advance changes the language — the successor class is
    still a function of the class, despite self-arms.  The self-case is
    refuted: a self-landing at the advance atom would identify the
    class with its successor. -/
theorem walked_class_succ_eq (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    {s₁ s₂ : S} {α : T → Bool} {a : A}
    (hL : autLang (genW T) (trimAut aut) s₁
      = autLang (genW T) (trimAut aut) s₂)
    (hrank : rank s₂ = rank s₁)
    (hstep₁ : autStep (genW T) (trimAut aut) s₁ α = some (a, nxt s₁))
    (hnontriv : autLang (genW T) (trimAut aut) (nxt s₁)
      ≠ autLang (genW T) (trimAut aut) s₁)
    (hlive : Live (trimAut aut) (nxt s₁))
    (hmin₂ : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) (nxt s₁) → rank s₁ ≤ rank w) :
    autLang (genW T) (trimAut aut) (nxt s₂)
      = autLang (genW T) (trimAut aut) (nxt s₁) := by
  obtain ⟨β, ws, hwits⟩ := hlive
  have hword₁ : autRun (genW T) (trimAut aut) s₁ α ((a, β) :: ws) :=
    ⟨nxt s₁, hstep₁, hwits⟩
  have hword₂ : autRun (genW T) (trimAut aut) s₂ α ((a, β) :: ws) :=
    (iff_of_eq (congrFun hL (α, (a, β) :: ws))).mp hword₁
  obtain ⟨v, hstep₂, -⟩ : ∃ v,
      autStep (genW T) (trimAut aut) s₂ α = some (a, v)
      ∧ autRun (genW T) (trimAut aut) v β ws := hword₂
  have hvL : autLang (genW T) (trimAut aut) v
      = autLang (genW T) (trimAut aut) (nxt s₁) := by
    funext gs
    obtain ⟨γ, l⟩ := gs
    apply propext
    have h1 := step_derivative hstep₂ γ l
    have h2 := step_derivative hstep₁ γ l
    have h3 : autRun (genW T) (trimAut aut) s₂ α ((a, γ) :: l)
        ↔ autRun (genW T) (trimAut aut) s₁ α ((a, γ) :: l) :=
      (iff_of_eq (congrFun hL (α, (a, γ) :: l))).symm
    exact h1.trans (h3.trans h2.symm)
  have hv : v = s₂ ∨ v = nxt s₂ := by
    refine walked_min_fire aut rank nxt hdec hstep₂ ?_
    have := hmin₂ v hvL
    omega
  rcases hv with hself | hnext
  · exfalso
    apply hnontriv
    have hs₂L : autLang (genW T) (trimAut aut) s₂
        = autLang (genW T) (trimAut aut) (nxt s₁) := by
      rw [← hself]
      exact hvL
    exact hs₂L.symm.trans hL.symm
  · rw [← hnext]
    exact hvL

#print axioms walked_min_fire
#print axioms walked_class_succ_eq

end GkatWalkedOrbit
