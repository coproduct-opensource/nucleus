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

/-! ## Propagation and cycle levels under the walked discipline

    Realizer propagation gains a trivial third case — a self-landing
    realizer keeps its own rank.  Cycle-level minimality and the
    quotient-successor tracking then re-thread, with non-degeneracy
    (`hnontriv`, fragment-supplied adjacent-language distinctness)
    passed to each successor-well-definedness site. -/

open Classical in
theorem walked_realizer_propagate (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    (u₀ : S) (hlive : Live (trimAut aut) u₀) (k : Nat)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀) :
    ∀ steps j, j + steps ≤ k →
    ∀ w, autLang (genW T) (trimAut aut) w
        = autLang (genW T) (trimAut aut) (nxtIter nxt j u₀) →
    ∃ w', autLang (genW T) (trimAut aut) w'
        = autLang (genW T) (trimAut aut) (nxtIter nxt (j + steps) u₀)
      ∧ rank w' ≤ rank w := by
  have hdecT : ∀ s (α : T → Bool), ∀ e ∈ (trimAut aut).trans s,
      bval (genW T) e.1 α = true →
      e.2.2 = s ∨ e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
    intro s α e he hb
    obtain ⟨g₀, hg₀, himp⟩ := trimList_target_mem_fires aut (aut.trans s)
      .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀ ⟨α, himp α hb⟩
  intro steps
  induction steps with
  | zero =>
      intro j hjk w hw
      exact ⟨w, by rw [Nat.add_zero]; exact hw, Nat.le_refl _⟩
  | succ steps ih =>
      intro j hjk w hw
      have hlj : Live (trimAut aut) (nxtIter nxt j u₀) :=
        orbit_track aut rank nxt hfire u₀ hlive j
          (fun i hi => hnofix i (by omega))
      obtain ⟨α, a, hstepS⟩ := hfire (nxtIter nxt j u₀) hlj
        (hnofix j (by omega))
      have hlnext : Live (trimAut aut) (nxtIter nxt (j + 1) u₀) :=
        orbit_track aut rank nxt hfire u₀ hlive (j + 1)
          (fun i hi => hnofix i (by omega))
      obtain ⟨β, ws, hwits⟩ := hlnext
      have hword_s : autRun (genW T) (trimAut aut) (nxtIter nxt j u₀) α
          ((a, β) :: ws) := ⟨nxtIter nxt (j + 1) u₀, hstepS, hwits⟩
      have hword_w : autRun (genW T) (trimAut aut) w α ((a, β) :: ws) :=
        (iff_of_eq (congrFun hw (α, (a, β) :: ws))).mpr hword_s
      obtain ⟨v, hstepW, -⟩ : ∃ v,
          autStep (genW T) (trimAut aut) w α = some (a, v)
          ∧ autRun (genW T) (trimAut aut) v β ws := hword_w
      have hvL : autLang (genW T) (trimAut aut) v
          = autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
        funext gs
        obtain ⟨γ, l⟩ := gs
        apply propext
        have h1 := step_derivative hstepW γ l
        have h2 := step_derivative hstepS γ l
        have h3 : autRun (genW T) (trimAut aut) w α ((a, γ) :: l)
            ↔ autRun (genW T) (trimAut aut) (nxtIter nxt j u₀) α
              ((a, γ) :: l) :=
          iff_of_eq (congrFun hw (α, (a, γ) :: l))
        exact h1.trans (h3.trans h2.symm)
      obtain ⟨ea, hea, hbea, -, heat⟩ :=
        firstMatch_mem_fires (genW T) hstepW
      have heat' : ea.2.2 = v := heat
      have hvrank : rank v ≤ rank w := by
        rcases hdecT w α ea hea hbea with hSelf | hEq | hLt
        · rw [← heat', hSelf]
          exact Nat.le_refl _
        · rw [← heat', hEq, hnxt_rank]
          exact Nat.le_refl _
        · rw [heat'] at hLt
          omega
      obtain ⟨w', hw'L, hw'r⟩ := ih (j + 1) (by omega) v hvL
      refine ⟨w', ?_, Nat.le_trans hw'r hvrank⟩
      rw [show j + (steps + 1) = (j + 1) + steps from by omega]
      exact hw'L

open Classical in
theorem walked_cycle_level_min (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    (u₀ : S) (k : Nat) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w) :
    ∀ j, j ≤ k →
      minRank (trimAut aut) rank
          (bisimRep (trimAut aut) (nxtIter nxt j u₀))
        = rank u₀ := by
  intro j hj
  refine Nat.le_antisymm ?_ ?_
  · have h1 : autLang (genW T) (trimAut aut) (nxtIter nxt j u₀)
        = autLang (genW T) (trimAut aut)
          (bisimRep (trimAut aut) (nxtIter nxt j u₀)) :=
      (rep_lang aut (nxtIter nxt j u₀)).symm
    have h2 := minRank_le (trimAut aut) rank h1
    rw [nxtIter_rank hnxt_rank u₀ j] at h2
    exact h2
  · obtain ⟨w, hwle, hwL⟩ := minRank_spec (trimAut aut) rank
      (bisimRep (trimAut aut) (nxtIter nxt j u₀))
    have hwL' : autLang (genW T) (trimAut aut) w
        = autLang (genW T) (trimAut aut) (nxtIter nxt j u₀) := by
      rw [hwL]
      exact rep_lang aut (nxtIter nxt j u₀)
    obtain ⟨w', hw'L, hw'r⟩ := walked_realizer_propagate aut rank nxt
      hdec hnxt_rank hfire u₀ hlive k hnofix (k - j) j (by omega) w hwL'
    have hw'u : autLang (genW T) (trimAut aut) w'
        = autLang (genW T) (trimAut aut) u₀ := by
      rw [show j + (k - j) = k from by omega, hper] at hw'L
      exact hw'L
    have := hmin w' hw'u
    omega

open Classical in
theorem walked_cycle_level_all (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w) :
    ∀ j, minRank (trimAut aut) rank
      (bisimRep (trimAut aut) (nxtIter nxt j u₀)) = rank u₀ := by
  intro j
  rw [show nxtIter nxt j u₀ = nxtIter nxt (j % k) u₀
    from nxtIter_mod hk hper j]
  exact walked_cycle_level_min aut rank nxt hdec hnxt_rank hfire u₀ k
    hper hlive hnofix hmin (j % k)
    (by have := Nat.mod_lt j (y := k) (by omega); omega)

open Classical in
/-- Walked quotient-successor well-definedness, at non-degenerate
    positions. -/
theorem walked_qsucc_well_defined (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    {i j : Nat}
    (h : bisimRep (trimAut aut) (nxtIter nxt i u₀)
      = bisimRep (trimAut aut) (nxtIter nxt j u₀)) :
    bisimRep (trimAut aut) (nxtIter nxt (i + 1) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
  have hL : autLang (genW T) (trimAut aut) (nxtIter nxt i u₀)
      = autLang (genW T) (trimAut aut) (nxtIter nxt j u₀) := by
    rw [← rep_lang aut (nxtIter nxt i u₀), h, rep_lang aut]
  have hli : Live (trimAut aut) (nxtIter nxt i u₀) :=
    orbit_live_all aut rank nxt hfire hk hper hlive hnofix i
  obtain ⟨α, a, hstepI⟩ := hfire (nxtIter nxt i u₀) hli
    (orbit_nofix_all hk hper hnofix i)
  have hlnext : Live (trimAut aut) (nxt (nxtIter nxt i u₀)) :=
    orbit_live_all aut rank nxt hfire hk hper hlive hnofix (i + 1)
  have hmin₂ : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) (nxt (nxtIter nxt i u₀)) →
      rank (nxtIter nxt i u₀) ≤ rank w := by
    intro w hw
    have hlvl := walked_cycle_level_all aut rank nxt hdec hnxt_rank
      hfire hk hper hlive hnofix hmin (i + 1)
    have hwrep : autLang (genW T) (trimAut aut) w
        = autLang (genW T) (trimAut aut)
          (bisimRep (trimAut aut) (nxtIter nxt (i + 1) u₀)) := by
      rw [rep_lang aut]
      exact hw
    have hle := minRank_le (trimAut aut) rank hwrep
    rw [hlvl] at hle
    rw [nxtIter_rank hnxt_rank u₀ i]
    omega
  have hrank : rank (nxtIter nxt j u₀) = rank (nxtIter nxt i u₀) := by
    rw [nxtIter_rank hnxt_rank u₀ i, nxtIter_rank hnxt_rank u₀ j]
  have hLsucc := walked_class_succ_eq aut rank nxt hdec hnxt_rank
    hL hrank hstepI (hnontriv i) hlnext hmin₂
  exact (rep_lang_congr aut hLsucc).symm

open Classical in
/-- Iterated walked successor well-definedness. -/
theorem walked_qsucc_iter (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    {i j : Nat}
    (h : bisimRep (trimAut aut) (nxtIter nxt i u₀)
      = bisimRep (trimAut aut) (nxtIter nxt j u₀)) :
    ∀ t, bisimRep (trimAut aut) (nxtIter nxt (i + t) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt (j + t) u₀) := by
  intro t
  induction t with
  | zero => exact h
  | succ t ih =>
      have := walked_qsucc_well_defined aut rank nxt hdec hnxt_rank
        hfire hk hper hlive hnofix hmin hnontriv ih
      rw [show i + (t + 1) = (i + t) + 1 from by omega,
          show j + (t + 1) = (j + t) + 1 from by omega]
      exact this

#print axioms walked_realizer_propagate
#print axioms walked_cycle_level_all
#print axioms walked_qsucc_iter

/-! ## Walked shifted tracking and injectivity

    The pure index arithmetic (`qorb_periodic`, `qPeriod_spec`, `findFrom`,
    the shift lemmas) is `nxt`-generic and reused verbatim from the
    classical layer; only the theorems routed through the class successor
    re-thread, with `hnontriv` in the bundle. -/

open Classical in
/-- Walked rank minimality along the shifted orbit. -/
theorem walked_shift_min (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (i : Nat) :
    ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) (nxtIter nxt i u₀) →
      rank (nxtIter nxt i u₀) ≤ rank w := by
  intro w hw
  have hlvl := walked_cycle_level_all aut rank nxt hdec hnxt_rank hfire
    hk hper hlive hnofix hmin i
  have hwrep : autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut)
        (bisimRep (trimAut aut) (nxtIter nxt i u₀)) := by
    rw [rep_lang aut]
    exact hw
  have hle := minRank_le (trimAut aut) rank hwrep
  rw [hlvl] at hle
  rw [nxtIter_rank hnxt_rank u₀ i]
  exact hle

open Classical in
/-- Walked shifted-orbit tracking. -/
theorem walked_orbit_lang_determined (aut : GAut S A T)
    (rank : S → Nat) (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    {i : Nat} {u' : S}
    (hu'L : autLang (genW T) (trimAut aut) u'
      = autLang (genW T) (trimAut aut) (nxtIter nxt i u₀))
    (hu'rank : rank u' = rank u₀) :
    ∀ j, autLang (genW T) (trimAut aut) (nxtIter nxt j u')
      = autLang (genW T) (trimAut aut) (nxtIter nxt (i + j) u₀) := by
  intro j
  induction j with
  | zero =>
      rw [Nat.add_zero]
      exact hu'L
  | succ j ih =>
      have hlij : Live (trimAut aut) (nxtIter nxt (i + j) u₀) :=
        orbit_live_all aut rank nxt hfire hk hper hlive hnofix (i + j)
      obtain ⟨α, a, hstepS⟩ := hfire (nxtIter nxt (i + j) u₀) hlij
        (orbit_nofix_all hk hper hnofix (i + j))
      have hlnext : Live (trimAut aut)
          (nxt (nxtIter nxt (i + j) u₀)) :=
        orbit_live_all aut rank nxt hfire hk hper hlive hnofix
          (i + j + 1)
      have hmin₂ : ∀ w, autLang (genW T) (trimAut aut) w
          = autLang (genW T) (trimAut aut)
            (nxt (nxtIter nxt (i + j) u₀)) →
          rank (nxtIter nxt (i + j) u₀) ≤ rank w := by
        intro w hw
        have hlvl := walked_cycle_level_all aut rank nxt hdec hnxt_rank
          hfire hk hper hlive hnofix hmin (i + j + 1)
        have hwrep : autLang (genW T) (trimAut aut) w
            = autLang (genW T) (trimAut aut)
              (bisimRep (trimAut aut) (nxtIter nxt (i + j + 1) u₀)) := by
          rw [rep_lang aut]
          exact hw
        have hle := minRank_le (trimAut aut) rank hwrep
        rw [hlvl] at hle
        rw [nxtIter_rank hnxt_rank u₀ (i + j)]
        omega
      have hrankeq : rank (nxtIter nxt j u')
          = rank (nxtIter nxt (i + j) u₀) := by
        rw [nxtIter_rank hnxt_rank u' j, hu'rank,
            nxtIter_rank hnxt_rank u₀ (i + j)]
      have hstep := walked_class_succ_eq aut rank nxt hdec hnxt_rank
        ih.symm hrankeq hstepS (hnontriv (i + j)) hlnext hmin₂
      rw [show i + (j + 1) = (i + j) + 1 from by omega]
      exact hstep

open Classical in
/-- Walked orbit injectivity below the first-return period. -/
theorem walked_qorb_injective (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    {i j : Nat} (hij : i < j) (hjp : j < qPeriod aut nxt u₀ k)
    (h : bisimRep (trimAut aut) (nxtIter nxt i u₀)
      = bisimRep (trimAut aut) (nxtIter nxt j u₀)) :
    False := by
  obtain ⟨hp1, hp2, hp3, hp4⟩ := qPeriod_spec aut nxt u₀ k hk hper
  have hshift := walked_qsucc_iter aut rank nxt hdec hnxt_rank hfire hk
    hper hlive hnofix hmin hnontriv h (k - i)
  have hk0 : bisimRep (trimAut aut) (nxtIter nxt k u₀)
      = bisimRep (trimAut aut) (nxtIter nxt (k + (j - i)) u₀) := by
    rw [show i + (k - i) = k from by omega] at hshift
    rw [show j + (k - i) = k + (j - i) from by omega] at hshift
    exact hshift
  have hbase : bisimRep (trimAut aut) u₀
      = bisimRep (trimAut aut) (nxtIter nxt (j - i) u₀) := by
    have e1 : bisimRep (trimAut aut) (nxtIter nxt k u₀)
        = bisimRep (trimAut aut) u₀ := by rw [hper]
    have e2 : bisimRep (trimAut aut) (nxtIter nxt (k + (j - i)) u₀)
        = bisimRep (trimAut aut) (nxtIter nxt (j - i) u₀) := by
      rw [show k + (j - i) = (j - i) + k from by omega]
      exact qorb_periodic aut nxt u₀ k hper (j - i)
    rw [← e1, hk0, e2]
  exact hp4 (j - i) (by omega) (by omega) hbase.symm

#print axioms walked_shift_min
#print axioms walked_orbit_lang_determined
#print axioms walked_qorb_injective

/-! ## The walked dichotomies

    Under the three-way discipline the quotient dichotomy keeps its
    SHAPE: self, descent, or the successor class.  The realizer's new
    self-landing case folds into the existing self-refutation — a
    self-landing at the firing atom makes the target's language the
    class's own, contradicting the non-self assumption of that branch. -/

open Classical in
/-- Walked cycle dichotomy for cleaned quotient arms. -/
theorem walked_quot_cycle_dichotomy (aut : GAut S A T)
    (rank : S → Nat) (nxt : S → S) (hdec : WalkedDec aut rank nxt) :
    ∀ c ∈ (bisimQuotAut (trimAut aut)).states,
    ∃ u, rank u ≤ minRank (trimAut aut) rank c ∧
      autLang (genW T) (trimAut aut) u
        = autLang (genW T) (trimAut aut) c ∧
      ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans c,
        e.2.2 = c ∨
        minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank c ∨
        e.2.2 = bisimRep (trimAut aut) (nxt u) := by
  have hdecT : ∀ s (α : T → Bool), ∀ e ∈ (trimAut aut).trans s,
      bval (genW T) e.1 α = true →
      e.2.2 = s ∨ e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
    intro s α e he hb
    obtain ⟨g₀, hg₀, himp⟩ := trimList_target_mem_fires aut
      (aut.trans s) .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀ ⟨α, himp α hb⟩
  intro c hc
  obtain ⟨u, hule, huL⟩ := minRank_spec (trimAut aut) rank c
  refine ⟨u, hule, huL, ?_⟩
  intro e he
  by_cases hself : e.2.2 = c
  · exact Or.inl hself
  · obtain ⟨α, -, hfm⟩ := cleanList_fires
      (bisimQuotAut (trimAut aut))
      ((bisimQuotAut (trimAut aut)).trans c) .zero e he
    have hstepC : autStep (genW T)
        (cleanAut (bisimQuotAut (trimAut aut))) c α
        = some (e.2.1, e.2.2) := hfm
    have hstepQ : autStep (genW T) (bisimQuotAut (trimAut aut)) c α
        = some (e.2.1, e.2.2) := by
      rw [← autStep_cleanAut (genW T)]
      exact hstepC
    have heQ : e ∈ (bisimQuotAut (trimAut aut)).trans c :=
      cleanList_sub _ .zero e he
    obtain ⟨v'', hv'', hrep⟩ : ∃ v'', v'' ∈ (trimAut aut).trans c ∧
        bisimRep (trimAut aut) v''.2.2 = e.2.2 := by
      obtain ⟨v'', hv'', heq⟩ := List.mem_map.mp heQ
      exact ⟨v'', hv'', congrArg (fun z => z.2.2) heq⟩
    have htfix : bisimRep (trimAut aut) e.2.2 = e.2.2 := by
      rw [← hrep]
      exact bisimRep_idem (trimAut aut) v''.2.2
    have hcfix : bisimRep (trimAut aut) c = c := by
      obtain ⟨w, -, hw⟩ := List.mem_map.mp hc
      rw [← hw]
      exact bisimRep_idem (trimAut aut) w
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
    obtain ⟨β₀, w₀, hw₀⟩ := htlive
    have hword : autRun (genW T) (trimAut aut) c α
        ((e.2.1, β₀) :: w₀) := (hDT β₀ w₀).mp hw₀
    have hwordU : autRun (genW T) (trimAut aut) u α
        ((e.2.1, β₀) :: w₀) :=
      (iff_of_eq (congrFun huL (α, (e.2.1, β₀) :: w₀))).mpr hword
    obtain ⟨v, hstepU, -⟩ : ∃ v,
        autStep (genW T) (trimAut aut) u α = some (e.2.1, v)
        ∧ autRun (genW T) (trimAut aut) v β₀ w₀ := hwordU
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
    obtain ⟨ea, hea, hbea, -, heat⟩ :=
      firstMatch_mem_fires (genW T) hstepU
    have heat' : ea.2.2 = v := heat
    rcases hdecT u α ea hea hbea with hSelf | hEq | hLt
    · exfalso
      have hvu : v = u := heat'.symm.trans hSelf
      have hLtc : autLang (genW T) (trimAut aut) e.2.2
          = autLang (genW T) (trimAut aut) c := by
        rw [← hvL, hvu, huL]
      exact hself (trim_repfixed_lang_eq aut hcfix htfix hLtc)
    · refine Or.inr (Or.inr ?_)
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
    · refine Or.inr (Or.inl ?_)
      have hvrank : rank v < rank u := by
        rw [heat'] at hLt
        exact hLt
      have h1 : minRank (trimAut aut) rank e.2.2 ≤ rank v :=
        minRank_le (trimAut aut) rank hvL
      omega

open Classical in
/-- Walked orbit dichotomy: the abstract successor is the concrete next
    orbit class. -/
theorem walked_orbit_dichotomy (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    (j : Nat)
    (hc : bisimRep (trimAut aut) (nxtIter nxt j u₀)
      ∈ (bisimQuotAut (trimAut aut)).states) :
    ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans
        (bisimRep (trimAut aut) (nxtIter nxt j u₀)),
      e.2.2 = bisimRep (trimAut aut) (nxtIter nxt j u₀)
      ∨ minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank
              (bisimRep (trimAut aut) (nxtIter nxt j u₀))
      ∨ e.2.2 = bisimRep (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
  obtain ⟨u, hule, huL, harms⟩ :=
    walked_quot_cycle_dichotomy aut rank nxt hdec _ hc
  have hsucc : bisimRep (trimAut aut) (nxt u)
      = bisimRep (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
    have hlvl := walked_cycle_level_all aut rank nxt hdec hnxt_rank
      hfire hk hper hlive hnofix hmin j
    have hrankJ : rank (nxtIter nxt j u₀) = rank u₀ :=
      nxtIter_rank hnxt_rank u₀ j
    have hL1 : autLang (genW T) (trimAut aut) (nxtIter nxt j u₀)
        = autLang (genW T) (trimAut aut) u :=
      (huL.trans (rep_lang aut _)).symm
    have hranku : rank u = rank (nxtIter nxt j u₀) := by
      rw [hlvl] at hule
      have h2 : rank (nxtIter nxt j u₀) ≤ rank u :=
        walked_shift_min aut rank nxt hdec hnxt_rank hfire hk hper
          hlive hnofix hmin j u hL1.symm
      omega
    obtain ⟨α, a, hstep⟩ := hfire (nxtIter nxt j u₀)
      (orbit_live_all aut rank nxt hfire hk hper hlive hnofix j)
      (orbit_nofix_all hk hper hnofix j)
    have hlnext : Live (trimAut aut) (nxt (nxtIter nxt j u₀)) :=
      orbit_live_all aut rank nxt hfire hk hper hlive hnofix (j + 1)
    have hmin₂ : ∀ w, autLang (genW T) (trimAut aut) w
        = autLang (genW T) (trimAut aut) (nxt (nxtIter nxt j u₀)) →
        rank (nxtIter nxt j u₀) ≤ rank w := by
      intro w hw
      have h3 := walked_shift_min aut rank nxt hdec hnxt_rank hfire hk
        hper hlive hnofix hmin (j + 1) w hw
      rw [nxtIter_rank hnxt_rank u₀ (j + 1)] at h3
      rw [hrankJ]
      exact h3
    have hLsucc := walked_class_succ_eq aut rank nxt hdec hnxt_rank
      hL1 hranku hstep (hnontriv j) hlnext hmin₂
    exact rep_lang_congr aut hLsucc
  intro e he
  rcases harms e he with h | h | h
  · exact Or.inl h
  · exact Or.inr (Or.inl h)
  · exact Or.inr (Or.inr (h.trans hsucc))

#print axioms walked_quot_cycle_dichotomy
#print axioms walked_orbit_dichotomy

/-! ## The walked cy-bundle

    Rank equality, arm pinning, and port descent under the three-way
    discipline; the halt-condition layer (`orbit_halt_empty`,
    `cy_halt_conditions_of_empty`, `hint_nil_of_pinned`) is
    discipline-free and reused verbatim. -/

open Classical in
theorem walked_orbit_rank_eq (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w) :
    ∀ j i : Nat,
      minRank (trimAut aut) rank
          (bisimRep (trimAut aut) (nxtIter nxt j u₀))
        = minRank (trimAut aut) rank
            (bisimRep (trimAut aut) (nxtIter nxt i u₀)) := by
  intro j i
  rw [walked_cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper
        hlive hnofix hmin j,
      walked_cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper
        hlive hnofix hmin i]

open Classical in
theorem walked_orbit_arms_pinned_nxtAt (aut : GAut S A T)
    (rank : S → Nat) (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    (j : Nat)
    (hc : bisimRep (trimAut aut) (nxtIter nxt j u₀)
      ∈ (bisimQuotAut (trimAut aut)).states)
    (hNoDesc : ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans
        (bisimRep (trimAut aut) (nxtIter nxt j u₀)),
      ¬ minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank
              (bisimRep (trimAut aut) (nxtIter nxt j u₀))) :
    ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans
        (bisimRep (trimAut aut) (nxtIter nxt j u₀)),
      e.2.2 = bisimRep (trimAut aut) (nxtIter nxt j u₀)
      ∨ e.2.2 = nxtAt (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
          (qPeriod aut nxt u₀ k) j := by
  intro e he
  rcases walked_orbit_dichotomy aut rank nxt hdec hnxt_rank hfire hk
    hper hlive hnofix hmin hnontriv j hc e he with h | h | h
  · exact Or.inl h
  · exact absurd h (hNoDesc e he)
  · refine Or.inr ?_
    unfold nxtAt
    rcases Classical.em (j + 1 = qPeriod aut nxt u₀ k) with hlen | hlen
    · rw [if_pos hlen]
      show e.2.2 = bisimRep (trimAut aut) (nxtIter nxt 0 u₀)
      rw [h, hlen]
      exact qm_wrap aut nxt u₀ k hk hper
    · rw [if_neg hlen]
      exact h

open Classical in
theorem walked_orbit_port_descent (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    (hlen2 : 2 ≤ qPeriod aut nxt u₀ k)
    (hc : bisimRep (trimAut aut) (nxtIter nxt 0 u₀)
      ∈ (bisimQuotAut (trimAut aut)).states) :
    ∀ e ∈ gOthers
        (nxtAt (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
          (qPeriod aut nxt u₀ k) 0)
        (restL (cleanAut (bisimQuotAut (trimAut aut)))
          (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀)) 0),
      minRank (trimAut aut) rank e.2.2
        < minRank (trimAut aut) rank
            (bisimRep (trimAut aut) (nxtIter nxt 0 u₀)) := by
  intro e he
  obtain ⟨heL1, hne1⟩ := gOthers_sub _ _ e he
  obtain ⟨heL2, hne2⟩ := gOthers_sub _ _ e heL1
  rcases walked_orbit_dichotomy aut rank nxt hdec hnxt_rank hfire hk
    hper hlive hnofix hmin hnontriv 0 hc e heL2 with h | h | h
  · exact absurd h hne2
  · exact h
  · exfalso
    apply hne1
    show e.2.2 = nxtAt (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
      (qPeriod aut nxt u₀ k) 0
    unfold nxtAt
    rw [if_neg (by omega : ¬ (0 + 1 = qPeriod aut nxt u₀ k))]
    exact h

#print axioms walked_orbit_rank_eq
#print axioms walked_orbit_arms_pinned_nxtAt
#print axioms walked_orbit_port_descent

/-! ## Walked positions, tracking, and the bundle package

    Class-level mod reduction, canonical positions, cross-witness orbit
    closure, and the complete per-orbit package — the `qpos`/`firstMem`
    definitions reuse verbatim; the proofs re-thread through the walked
    successor machinery. -/

open Classical in
theorem walked_qorb_period_all (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀)) :
    ∀ t, bisimRep (trimAut aut)
      (nxtIter nxt (t + qPeriod aut nxt u₀ k) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt t u₀) := by
  intro t
  have hA1 := (qPeriod_spec aut nxt u₀ k hk hper).1
  have h0 := walked_qsucc_iter aut rank nxt hdec hnxt_rank hfire hk
    hper hlive hnofix hmin hnontriv
    (i := qPeriod aut nxt u₀ k) (j := 0) hA1 t
  rw [Nat.zero_add] at h0
  rw [Nat.add_comm t (qPeriod aut nxt u₀ k)]
  exact h0

open Classical in
theorem walked_qorb_qmod (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀)) :
    ∀ j, bisimRep (trimAut aut) (nxtIter nxt j u₀)
      = bisimRep (trimAut aut)
          (nxtIter nxt (j % qPeriod aut nxt u₀ k) u₀) := by
  have hmul : ∀ q r, bisimRep (trimAut aut)
      (nxtIter nxt (r + qPeriod aut nxt u₀ k * q) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt r u₀) := by
    intro q
    induction q with
    | zero => intro r; rfl
    | succ q ih =>
        intro r
        rw [show qPeriod aut nxt u₀ k * (q + 1)
            = qPeriod aut nxt u₀ k * q + qPeriod aut nxt u₀ k from
              Nat.mul_succ _ _]
        rw [show r + (qPeriod aut nxt u₀ k * q + qPeriod aut nxt u₀ k)
            = (r + qPeriod aut nxt u₀ k * q) + qPeriod aut nxt u₀ k from
              by omega]
        rw [walked_qorb_period_all aut rank nxt hdec hnxt_rank hfire hk
          hper hlive hnofix hmin hnontriv
          (r + qPeriod aut nxt u₀ k * q)]
        exact ih r
  intro j
  have hdm := Nat.div_add_mod j (qPeriod aut nxt u₀ k)
  have h0 := hmul (j / qPeriod aut nxt u₀ k)
    (j % qPeriod aut nxt u₀ k)
  rw [show j % qPeriod aut nxt u₀ k
      + qPeriod aut nxt u₀ k * (j / qPeriod aut nxt u₀ k) = j from
        by omega] at h0
  exact h0

open Classical in
theorem walked_qpos_spec (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    {c : S} (h : InOrbit aut nxt u₀ c) :
    bisimRep (trimAut aut)
      (nxtIter nxt (qpos aut nxt u₀ k c) u₀) = c
    ∧ qpos aut nxt u₀ k c < qPeriod aut nxt u₀ k := by
  unfold qpos
  rw [dif_pos h]
  have hc := Classical.choose_spec h
  constructor
  · rw [← walked_qorb_qmod aut rank nxt hdec hnxt_rank hfire hk hper
      hlive hnofix hmin hnontriv (Classical.choose h)]
    exact hc.symm
  · exact Nat.mod_lt _ (by
      have := (qPeriod_spec aut nxt u₀ k hk hper).2.1
      omega)

open Classical in
theorem walked_qpos_qm (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    {j : Nat} (hj : j < qPeriod aut nxt u₀ k) :
    qpos aut nxt u₀ k (bisimRep (trimAut aut) (nxtIter nxt j u₀))
      = j := by
  have hio : InOrbit aut nxt u₀
      (bisimRep (trimAut aut) (nxtIter nxt j u₀)) := ⟨j, rfl⟩
  obtain ⟨heq, hlt⟩ := walked_qpos_spec aut rank nxt hdec hnxt_rank
    hfire hk hper hlive hnofix hmin hnontriv hio
  rcases Nat.lt_trichotomy
    (qpos aut nxt u₀ k (bisimRep (trimAut aut) (nxtIter nxt j u₀))) j
    with hlt' | heq' | hgt'
  · exact absurd heq
      (fun hcontra => walked_qorb_injective aut rank nxt hdec hnxt_rank
        hfire hk hper hlive hnofix hmin hnontriv hlt' hj hcontra)
  · exact heq'
  · exact absurd heq.symm
      (fun hcontra => walked_qorb_injective aut rank nxt hdec hnxt_rank
        hfire hk hper hlive hnofix hmin hnontriv hgt' hlt hcontra)

open Classical in
/-- Walked cross-witness tracking. -/
theorem walked_orbit_track_from (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u : S} {k : Nat} (hkU : 1 ≤ k) (hperU : nxtIter nxt k u = u)
    (hliveU : Live (trimAut aut) u)
    (hnofixU : ∀ j, j < k → nxt (nxtIter nxt j u) ≠ nxtIter nxt j u)
    (hminU : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u → rank u ≤ rank w)
    (hnontrivU : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u))
    {v : S} {k₁ : Nat} (hkV : 1 ≤ k₁) (hperV : nxtIter nxt k₁ v = v)
    (hliveV : Live (trimAut aut) v)
    (hnofixV : ∀ j, j < k₁ → nxt (nxtIter nxt j v) ≠ nxtIter nxt j v)
    (hminV : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) v → rank v ≤ rank w)
    {t s : Nat}
    (heq : bisimRep (trimAut aut) (nxtIter nxt s v)
      = bisimRep (trimAut aut) (nxtIter nxt t u)) :
    ∀ d, bisimRep (trimAut aut) (nxtIter nxt (s + d) v)
      = bisimRep (trimAut aut) (nxtIter nxt (t + d) u) := by
  intro d
  have hL : autLang (genW T) (trimAut aut) (nxtIter nxt s v)
      = autLang (genW T) (trimAut aut) (nxtIter nxt t u) := by
    rw [← rep_lang aut (nxtIter nxt s v), heq, rep_lang aut]
  have hrv : rank v = rank u := by
    have h1 := walked_cycle_level_all aut rank nxt hdec hnxt_rank hfire
      hkV hperV hliveV hnofixV hminV s
    have h2 := walked_cycle_level_all aut rank nxt hdec hnxt_rank hfire
      hkU hperU hliveU hnofixU hminU t
    rw [heq] at h1
    omega
  have hr : rank (nxtIter nxt s v) = rank u := by
    rw [nxtIter_rank hnxt_rank v s]
    exact hrv
  have h3 := walked_orbit_lang_determined aut rank nxt hdec hnxt_rank
    hfire hkU hperU hliveU hnofixU hminU hnontrivU
    (i := t) (u' := nxtIter nxt s v) hL hr d
  have h4 : autLang (genW T) (trimAut aut) (nxtIter nxt (s + d) v)
      = autLang (genW T) (trimAut aut) (nxtIter nxt (t + d) u) := by
    rw [← h3, ← nxtIter_add]
  exact rep_lang_congr aut h4

open Classical in
/-- Walked orbit closure of `InOrbit`. -/
theorem walked_inOrbit_track (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u : S} {k : Nat} (hkU : 1 ≤ k) (hperU : nxtIter nxt k u = u)
    (hliveU : Live (trimAut aut) u)
    (hnofixU : ∀ j, j < k → nxt (nxtIter nxt j u) ≠ nxtIter nxt j u)
    (hminU : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u → rank u ≤ rank w)
    (hnontrivU : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u))
    {w : S} {k₂ : Nat} (hkW : 1 ≤ k₂) (hperW : nxtIter nxt k₂ w = w)
    (hliveW : Live (trimAut aut) w)
    (hnofixW : ∀ j, j < k₂ → nxt (nxtIter nxt j w) ≠ nxtIter nxt j w)
    (hminW : ∀ x, autLang (genW T) (trimAut aut) x
      = autLang (genW T) (trimAut aut) w → rank w ≤ rank x)
    {t t' : Nat}
    (h : InOrbit aut nxt w (bisimRep (trimAut aut) (nxtIter nxt t u))) :
    InOrbit aut nxt w
      (bisimRep (trimAut aut) (nxtIter nxt t' u)) := by
  obtain ⟨s, hs⟩ := h
  have htrack := walked_orbit_track_from aut rank nxt hdec hnxt_rank
    hfire hkU hperU hliveU hnofixU hminU hnontrivU hkW hperW hliveW
    hnofixW hminW (t := t) (s := s) hs.symm
  refine ⟨s + ((k - t % k) + t'), ?_⟩
  rw [htrack ((k - t % k) + t')]
  have hik : t % k < k := Nat.mod_lt t (by omega)
  have hdm := Nat.div_add_mod t k
  rw [show t + ((k - t % k) + t') = k * (t / k) + (k + t') from
    by omega]
  rw [nxtIter_add, nxtIter_mul_period hperU, nxtIter_add, hperU]

#print axioms walked_qorb_qmod
#print axioms walked_qpos_qm
#print axioms walked_inOrbit_track

/-! ## The walked bundle package and THE WALKED GLUE

    The per-orbit package under the three-way discipline, then the master:
    a walked rank-modulo-cycle automaton with a covering orbit list has a
    solvable canonical quotient.  `orbCy` and the walked assembly reuse
    verbatim — the assembly always allowed member self-loops. -/

open Classical in
theorem walked_orbit_cy_bundle (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (hnontriv : ∀ j : Nat,
      autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀)
        ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j u₀))
    (hlen2 : 2 ≤ qPeriod aut nxt u₀ k)
    (hstates : ∀ j, bisimRep (trimAut aut) (nxtIter nxt j u₀)
      ∈ (bisimQuotAut (trimAut aut)).states)
    (hNoDescInt : ∀ j, 1 ≤ j → j < qPeriod aut nxt u₀ k →
      ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans
          (bisimRep (trimAut aut) (nxtIter nxt j u₀)),
        ¬ minRank (trimAut aut) rank e.2.2
            < minRank (trimAut aut) rank
                (bisimRep (trimAut aut) (nxtIter nxt j u₀)))
    (hnoeps : ∀ j, 1 ≤ j → j < qPeriod aut nxt u₀ k →
      ∀ α : T → Bool,
        ¬ autRun (genW T) (trimAut aut) (nxtIter nxt j u₀) α []) :
    (∀ j, j < qPeriod aut nxt u₀ k →
      minRank (trimAut aut) rank
          (bisimRep (trimAut aut) (nxtIter nxt j u₀))
        = minRank (trimAut aut) rank
            (bisimRep (trimAut aut) (nxtIter nxt 0 u₀)))
    ∧ (∀ e ∈ gOthers
        (nxtAt (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
          (qPeriod aut nxt u₀ k) 0)
        (restL (cleanAut (bisimQuotAut (trimAut aut)))
          (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀)) 0),
        minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank
              (bisimRep (trimAut aut) (nxtIter nxt 0 u₀)))
    ∧ (∀ j, 1 ≤ j → j < qPeriod aut nxt u₀ k →
        gOthers
          (nxtAt (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
            (qPeriod aut nxt u₀ k) j)
          (restL (cleanAut (bisimQuotAut (trimAut aut)))
            (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀)) j)
          = [])
    ∧ (∀ j, 1 ≤ j → j < qPeriod aut nxt u₀ k →
        GuardImplies
          ((cleanAut (bisimQuotAut (trimAut aut))).hlt
            (bisimRep (trimAut aut) (nxtIter nxt j u₀)))
          ((cleanAut (bisimQuotAut (trimAut aut))).hlt
            (bisimRep (trimAut aut) (nxtIter nxt 0 u₀))))
    ∧ (∀ j, 1 ≤ j → j < qPeriod aut nxt u₀ k →
        ∀ e ∈ gOthers
          (nxtAt (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
            (qPeriod aut nxt u₀ k) 0)
          (restL (cleanAut (bisimQuotAut (trimAut aut)))
            (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀)) 0),
          GuardEmpty (.and
            ((cleanAut (bisimQuotAut (trimAut aut))).hlt
              (bisimRep (trimAut aut) (nxtIter nxt j u₀))) e.1))
    ∧ (∀ j, 1 ≤ j → j < qPeriod aut nxt u₀ k →
        GuardImplies
          ((cleanAut (bisimQuotAut (trimAut aut))).hlt
            (bisimRep (trimAut aut) (nxtIter nxt j u₀)))
          (.not (.or
            (selfG (cleanAut (bisimQuotAut (trimAut aut)))
              (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀)) 0)
            (nextG (cleanAut (bisimQuotAut (trimAut aut)))
              (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
              (qPeriod aut nxt u₀ k) 0)))) := by
  have hEmpty : ∀ j, 1 ≤ j → j < qPeriod aut nxt u₀ k →
      GuardEmpty ((cleanAut (bisimQuotAut (trimAut aut))).hlt
        (bisimRep (trimAut aut) (nxtIter nxt j u₀))) := by
    intro j hj hjlt
    exact orbit_halt_empty aut nxt j (hnoeps j hj hjlt)
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro j _
    exact walked_orbit_rank_eq aut rank nxt hdec hnxt_rank hfire hk
      hper hlive hnofix hmin j 0
  · exact walked_orbit_port_descent aut rank nxt hdec hnxt_rank hfire
      hk hper hlive hnofix hmin hnontriv hlen2 (hstates 0)
  · intro j hj hjlt
    exact hint_nil_of_pinned (cleanAut (bisimQuotAut (trimAut aut)))
      (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
      (qPeriod aut nxt u₀ k) j
      (walked_orbit_arms_pinned_nxtAt aut rank nxt hdec hnxt_rank hfire
        hk hper hlive hnofix hmin hnontriv j (hstates j)
        (hNoDescInt j hj hjlt))
  · intro j hj hjlt
    exact (cy_halt_conditions_of_empty
      (cleanAut (bisimQuotAut (trimAut aut)))
      (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
      (qPeriod aut nxt u₀ k) j (hEmpty j hj hjlt)).1
  · intro j hj hjlt
    exact (cy_halt_conditions_of_empty
      (cleanAut (bisimQuotAut (trimAut aut)))
      (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
      (qPeriod aut nxt u₀ k) j (hEmpty j hj hjlt)).2.1
  · intro j hj hjlt
    exact (cy_halt_conditions_of_empty
      (cleanAut (bisimQuotAut (trimAut aut)))
      (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
      (qPeriod aut nxt u₀ k) j (hEmpty j hj hjlt)).2.2

open Classical in
private theorem orbCy_none' (aut : GAut S A T) (nxt : S → S)
    (os : List (S × Nat)) {c : S}
    (h : firstMem (fun p => InOrbit aut nxt p.1 c) os = none) :
    orbCy aut nxt os c = none := by
  unfold orbCy
  rw [h]

open Classical in
private theorem orbCy_some' (aut : GAut S A T) (nxt : S → S)
    (os : List (S × Nat)) {c : S} {p : S × Nat}
    (h : firstMem (fun p => InOrbit aut nxt p.1 c) os = some p) :
    orbCy aut nxt os c = some (qPeriod aut nxt p.1 p.2,
      fun t => bisimRep (trimAut aut) (nxtIter nxt t p.1),
      qpos aut nxt p.1 p.2 c) := by
  unfold orbCy
  rw [h]

open Classical in
/-- **THE WALKED GLUE**: a walked rank-modulo-cycle automaton with a
    covering orbit list has a solvable canonical quotient. -/
theorem walked_rankNxt_quot_solvesBA (aut : GAut S A T)
    (rank : S → Nat) (nxt : S → S) (hdec : WalkedDec aut rank nxt)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    (os : List (S × Nat))
    (hos : ∀ p ∈ os,
      1 ≤ p.2 ∧ nxtIter nxt p.2 p.1 = p.1 ∧ Live (trimAut aut) p.1
      ∧ (∀ j, j < p.2 →
          nxt (nxtIter nxt j p.1) ≠ nxtIter nxt j p.1)
      ∧ (∀ w, autLang (genW T) (trimAut aut) w
          = autLang (genW T) (trimAut aut) p.1 → rank p.1 ≤ rank w)
      ∧ (∀ j : Nat,
          autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) p.1)
            ≠ autLang (genW T) (trimAut aut) (nxtIter nxt j p.1))
      ∧ 2 ≤ qPeriod aut nxt p.1 p.2
      ∧ (∀ j, bisimRep (trimAut aut) (nxtIter nxt j p.1)
          ∈ (bisimQuotAut (trimAut aut)).states)
      ∧ (∀ j, 1 ≤ j → j < qPeriod aut nxt p.1 p.2 →
          ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans
              (bisimRep (trimAut aut) (nxtIter nxt j p.1)),
            ¬ minRank (trimAut aut) rank e.2.2
                < minRank (trimAut aut) rank
                    (bisimRep (trimAut aut) (nxtIter nxt j p.1)))
      ∧ (∀ j, 1 ≤ j → j < qPeriod aut nxt p.1 p.2 →
          ∀ α : T → Bool,
            ¬ autRun (genW T) (trimAut aut) (nxtIter nxt j p.1) α []))
    (hcover : ∀ c ∈ (cleanAut (bisimQuotAut (trimAut aut))).states,
      (∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans c,
        e.2.2 = c ∨ minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank c)
      ∨ ∃ p ∈ os, InOrbit aut nxt p.1 c) :
    ∃ qsol : S → Exp A T,
      SolvesBA (bisimQuotAut (trimAut aut)) qsol := by
  have hcy : ∀ s len m i, orbCy aut nxt os s = some (len, m, i) →
      i < len ∧ 2 ≤ len ∧ m i = s ∧
      (∀ j, j < len → orbCy aut nxt os (m j) = some (len, m, j)) ∧
      (∀ j, j < len →
        minRank (trimAut aut) rank (m j)
          = minRank (trimAut aut) rank (m 0)) ∧
      (∀ e ∈ gOthers (nxtAt m len 0)
          (restL (cleanAut (bisimQuotAut (trimAut aut))) m 0),
        minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank (m 0)) ∧
      (∀ j, 1 ≤ j → j < len →
        gOthers (nxtAt m len j)
          (restL (cleanAut (bisimQuotAut (trimAut aut))) m j) = []) ∧
      (∀ j, 1 ≤ j → j < len →
        GuardImplies
          ((cleanAut (bisimQuotAut (trimAut aut))).hlt (m j))
          ((cleanAut (bisimQuotAut (trimAut aut))).hlt (m 0))) ∧
      (∀ j, 1 ≤ j → j < len →
        ∀ e ∈ gOthers (nxtAt m len 0)
          (restL (cleanAut (bisimQuotAut (trimAut aut))) m 0),
          GuardEmpty (.and
            ((cleanAut (bisimQuotAut (trimAut aut))).hlt (m j)) e.1)) ∧
      (∀ j, 1 ≤ j → j < len →
        GuardImplies
          ((cleanAut (bisimQuotAut (trimAut aut))).hlt (m j))
          (.not (.or
            (selfG (cleanAut (bisimQuotAut (trimAut aut))) m 0)
            (nextG (cleanAut (bisimQuotAut (trimAut aut))) m len
              0)))) := by
    intro s len m i hcys
    cases hfm : firstMem (fun p => InOrbit aut nxt p.1 s) os with
    | none =>
        rw [orbCy_none' aut nxt os hfm] at hcys
        exact nomatch hcys
    | some p =>
        rw [orbCy_some' aut nxt os hfm] at hcys
        have hinj := Option.some.inj hcys
        rw [Prod.mk.injEq, Prod.mk.injEq] at hinj
        obtain ⟨hlenE, hmE, hiE⟩ := hinj
        subst hlenE
        subst hmE
        subst hiE
        obtain ⟨hpmem, hio⟩ := firstMem_mem hfm
        obtain ⟨hk, hper, hlive, hnofix, hmin, hnontriv, hlen2,
          hstates, hnodesc, hnoeps⟩ := hos p hpmem
        obtain ⟨hc3, hposlt⟩ := walked_qpos_spec aut rank nxt hdec
          hnxt_rank hfire hk hper hlive hnofix hmin hnontriv hio
        obtain ⟨hB1, hB2, hB3, hB4, hB5, hB6⟩ := walked_orbit_cy_bundle
          aut rank nxt hdec hnxt_rank hfire hk hper hlive hnofix hmin
          hnontriv hlen2 hstates hnodesc hnoeps
        refine ⟨hposlt, hlen2, hc3, ?_, hB1, hB2, hB3, hB4, hB5, hB6⟩
        intro j hj
        have hcongr : firstMem (fun p' => InOrbit aut nxt p'.1
            (bisimRep (trimAut aut) (nxtIter nxt j p.1))) os
            = firstMem (fun p' => InOrbit aut nxt p'.1 s) os := by
          apply firstMem_congr_mem
          intro p' hp'
          obtain ⟨hk', hper', hlive', hnofix', hmin', -, -, -, -, -⟩ :=
            hos p' hp'
          constructor
          · intro hin
            have h2 := walked_inOrbit_track aut rank nxt hdec
              hnxt_rank hfire hk hper hlive hnofix hmin hnontriv
              hk' hper' hlive' hnofix' hmin'
              (t := j) (t' := qpos aut nxt p.1 p.2 s) hin
            rw [hc3] at h2
            exact h2
          · intro hin
            have hin' : InOrbit aut nxt p'.1 (bisimRep (trimAut aut)
                (nxtIter nxt (qpos aut nxt p.1 p.2 s) p.1)) := by
              rw [hc3]
              exact hin
            exact walked_inOrbit_track aut rank nxt hdec hnxt_rank
              hfire hk hper hlive hnofix hmin hnontriv
              hk' hper' hlive' hnofix' hmin'
              (t := qpos aut nxt p.1 p.2 s) (t' := j) hin'
        rw [orbCy_some' aut nxt os (hcongr.trans hfm)]
        rw [walked_qpos_qm aut rank nxt hdec hnxt_rank hfire hk hper
          hlive hnofix hmin hnontriv hj]
  have hbase : ∀ s ∈ (cleanAut (bisimQuotAut (trimAut aut))).states,
      orbCy aut nxt os s = none →
      ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans s,
        e.2.2 = s ∨ minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank s := by
    intro s hs hnone e he
    rcases hcover s hs with hbase' | ⟨p, hp, hio⟩
    · exact hbase' e he
    · obtain ⟨y, hy⟩ := firstMem_isSome
        (P := fun p => InOrbit aut nxt p.1 s) hp hio
      rw [orbCy_some' aut nxt os hy] at hnone
      exact nomatch hnone
  obtain ⟨qsol, hroles⟩ := walked_assembly_roles
    (cleanAut (bisimQuotAut (trimAut aut)))
    (fun c => minRank (trimAut aut) rank c)
    (orbCy aut nxt os) hcy hbase
  exact ⟨qsol, solvesBA_unclean _ (decomp_solves _ _ hroles)⟩

#print axioms walked_orbit_cy_bundle
#print axioms walked_rankNxt_quot_solvesBA

end GkatWalkedOrbit
