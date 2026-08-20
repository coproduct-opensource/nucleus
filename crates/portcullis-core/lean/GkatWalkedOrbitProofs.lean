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

end GkatWalkedOrbit
