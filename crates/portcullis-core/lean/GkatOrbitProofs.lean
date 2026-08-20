import GkatChainLoopProofs

/-! # The orbit core — quotient cycles from source cycles

    The bridge between the cycle dichotomy and the walked-exit assembly.
    The quotient orbit of a cycle class `c₀` is defined DIRECTLY from one
    source orbit: `m j := ⟦nxt^[j] u₀⟧` for the canonical minimal realizer
    `u₀` of `L(c₀)`.  Then:

    * closure is immediate — `⟦nxt^[k] u₀⟧ = ⟦u₀⟧ = c₀` by source periodicity
      and rep-fixedness;
    * language tracking (`orbit_track`) is one induction: each source cycle
      state fires to its successor (the firing hypothesis), so the class
      languages follow the source derivatives around the cycle;
    * levels are constant along the orbit (`rank (nxt s) = rank s` plus
      minimality). -/

namespace GkatOrbit

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop GkatChainLoop

variable {S A T : Type}

open Classical in
/-- The canonical minimal realizer of a state's generic trim language. -/
noncomputable def uc (aut : GAut S A T) (rank : S → Nat) (c : S) : S :=
  Classical.choose (minRank_spec (trimAut aut) rank c)

open Classical in
theorem uc_rank_le (aut : GAut S A T) (rank : S → Nat) (c : S) :
    rank (uc aut rank c) ≤ minRank (trimAut aut) rank c :=
  (Classical.choose_spec (minRank_spec (trimAut aut) rank c)).1

open Classical in
theorem uc_lang (aut : GAut S A T) (rank : S → Nat) (c : S) :
    autLang (genW T) (trimAut aut) (uc aut rank c)
      = autLang (genW T) (trimAut aut) c :=
  (Classical.choose_spec (minRank_spec (trimAut aut) rank c)).2

open Classical in
/-- The canonical realizer sits exactly at the minimal rank. -/
theorem uc_rank (aut : GAut S A T) (rank : S → Nat) (c : S) :
    rank (uc aut rank c) = minRank (trimAut aut) rank c :=
  Nat.le_antisymm (uc_rank_le aut rank c)
    (minRank_le (trimAut aut) rank (uc_lang aut rank c))

/-- Trim liveness coincides with source liveness. -/
theorem live_trim_iff (aut : GAut S A T) (s : S) :
    Live (trimAut aut) s ↔ Live aut s := by
  constructor
  · intro ⟨α, l, hr⟩
    exact ⟨α, l, (autRun_trimAut (genW T) aut l s α).mp hr⟩
  · exact live_trimAut

open Classical in
/-- **THE ORBIT STEP**: if a source state `u` realizes `L(c)` and fires to
    `v`, then `v`'s language is the corresponding derivative of `L(c)`, and
    the class of `v` shares `v`'s language. -/
theorem orbit_step (aut : GAut S A T) {c u v : S} {α : T → Bool} {a : A}
    (huL : autLang (genW T) (trimAut aut) u
      = autLang (genW T) (trimAut aut) c)
    (hstepU : autStep (genW T) (trimAut aut) u α = some (a, v)) :
    autLang (genW T) (trimAut aut) (bisimRep (trimAut aut) v)
      = autLang (genW T) (trimAut aut) v ∧
    (∀ (β : T → Bool) (w : List (A × (T → Bool))),
      autRun (genW T) (trimAut aut) v β w ↔
        autRun (genW T) (trimAut aut) c α ((a, β) :: w)) := by
  constructor
  · exact (autLang_eq_of_gautBisim (genBisimilar_bisim (trimAut aut))
      (bisimRep_bisim (trimAut aut) v)).symm
  · intro β w
    have hDU := step_derivative hstepU β w
    have hcu : autRun (genW T) (trimAut aut) u α ((a, β) :: w)
        ↔ autRun (genW T) (trimAut aut) c α ((a, β) :: w) :=
      iff_of_eq (congrFun huL (α, (a, β) :: w))
    exact hDU.trans hcu

open Classical in
/-- Iterated successor. -/
def nxtIter (nxt : S → S) : Nat → S → S
  | 0, s => s
  | k + 1, s => nxt (nxtIter nxt k s)

/-- **ORBIT LANGUAGE TRACKING**: under the firing hypothesis, the class
    languages follow one source orbit around the cycle — each iterate is
    trim-live and realizes the corresponding class language. -/
theorem orbit_track (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s)) :
    ∀ (u₀ : S), Live (trimAut aut) u₀ →
    ∀ k, (∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀) →
      Live (trimAut aut) (nxtIter nxt k u₀) := by
  intro u₀ hlive k
  induction k with
  | zero => intro _; exact hlive
  | succ k ih =>
      intro hne
      have hlk : Live (trimAut aut) (nxtIter nxt k u₀) :=
        ih (fun j hj => hne j (by omega))
      obtain ⟨α, a, hstep⟩ := hfire (nxtIter nxt k u₀) hlk
        (hne k (by omega))
      -- the step target is live: trim steps land live
      have hlnext : Live aut (nxtIter nxt (k + 1) u₀) := by
        rw [autStep_trimAut] at hstep
        obtain ⟨-, hl⟩ := bind_live_some hstep
        exact hl
      exact (live_trim_iff aut _).mpr hlnext

#print axioms orbit_track

/-- Ranks are constant along the successor orbit. -/
theorem nxtIter_rank {rank : S → Nat} {nxt : S → S}
    (hnxt_rank : ∀ s, rank (nxt s) = rank s) (u₀ : S) :
    ∀ j, rank (nxtIter nxt j u₀) = rank u₀ := by
  intro j
  induction j with
  | zero => rfl
  | succ j ih =>
      show rank (nxt (nxtIter nxt j u₀)) = rank u₀
      rw [hnxt_rank]
      exact ih

open Classical in
/-- Representatives carry their state's language. -/
theorem rep_lang (aut : GAut S A T) (x : S) :
    autLang (genW T) (trimAut aut) (bisimRep (trimAut aut) x)
      = autLang (genW T) (trimAut aut) x :=
  (autLang_eq_of_gautBisim (genBisimilar_bisim (trimAut aut))
    (bisimRep_bisim (trimAut aut) x)).symm

open Classical in
/-- **REALIZER PROPAGATION**: a realizer of an orbit language walks forward
    around the cycle without rank increase — at each cycle atom its firing
    target realizes the next orbit language at the same or lower rank. -/
theorem realizer_propagate (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
      e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
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
      obtain ⟨ea, hea, hbea, -, heat⟩ := firstMatch_mem_fires (genW T) hstepW
      have heat' : ea.2.2 = v := heat
      have hvrank : rank v ≤ rank w := by
        rcases hdecT w α ea hea hbea with hEq | hLt
        · rw [← heat', hEq, hnxt_rank]
          exact Nat.le_refl _
        · rw [heat'] at hLt
          omega
      obtain ⟨w', hw'L, hw'r⟩ := ih (j + 1) (by omega) v hvL
      refine ⟨w', ?_, Nat.le_trans hw'r hvrank⟩
      rw [show j + (steps + 1) = (j + 1) + steps from by omega]
      exact hw'L

open Classical in
/-- **CYCLE LEVEL MINIMALITY**: on a periodic source orbit whose basepoint is
    a minimal realizer of its own language, every orbit class sits at exactly
    the basepoint's rank. -/
theorem cycle_level_min (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
      minRank (trimAut aut) rank (bisimRep (trimAut aut) (nxtIter nxt j u₀))
        = rank u₀ := by
  intro j hj
  refine Nat.le_antisymm ?_ ?_
  · -- ≤ : the orbit point itself realizes, at the basepoint rank
    have h1 : autLang (genW T) (trimAut aut) (nxtIter nxt j u₀)
        = autLang (genW T) (trimAut aut)
          (bisimRep (trimAut aut) (nxtIter nxt j u₀)) :=
      (rep_lang aut (nxtIter nxt j u₀)).symm
    have h2 := minRank_le (trimAut aut) rank h1
    rw [nxtIter_rank hnxt_rank u₀ j] at h2
    exact h2
  · -- ≥ : any better realizer would propagate around to beat the basepoint
    obtain ⟨w, hwle, hwL⟩ := minRank_spec (trimAut aut) rank
      (bisimRep (trimAut aut) (nxtIter nxt j u₀))
    have hwL' : autLang (genW T) (trimAut aut) w
        = autLang (genW T) (trimAut aut) (nxtIter nxt j u₀) := by
      rw [hwL]
      exact rep_lang aut (nxtIter nxt j u₀)
    obtain ⟨w', hw'L, hw'r⟩ := realizer_propagate aut rank nxt hdec hnxt_rank
      hfire u₀ hlive k hnofix (k - j) j (by omega) w hwL'
    have hw'u : autLang (genW T) (trimAut aut) w'
        = autLang (genW T) (trimAut aut) u₀ := by
      rw [show j + (k - j) = k from by omega, hper] at hw'L
      exact hw'L
    have := hmin w' hw'u
    omega

#print axioms cycle_level_min

/-! ## Orbit combinatorics: the quotient orbit behaves like a function orbit -/

theorem nxtIter_add (nxt : S → S) (a b : Nat) (s : S) :
    nxtIter nxt (a + b) s = nxtIter nxt b (nxtIter nxt a s) := by
  induction b with
  | zero => rfl
  | succ b ih =>
      show nxtIter nxt (a + b + 1) s = nxt (nxtIter nxt b (nxtIter nxt a s))
      rw [← ih]
      rfl

open Classical in
/-- The quotient orbit inherits the source period. -/
theorem qorb_periodic (aut : GAut S A T) (nxt : S → S) (u₀ : S) (k : Nat)
    (hper : nxtIter nxt k u₀ = u₀) (j : Nat) :
    bisimRep (trimAut aut) (nxtIter nxt (j + k) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt j u₀) := by
  rw [show j + k = k + j from by omega, nxtIter_add, hper]

open Classical in
/-- **MIN-LEVEL FIRING**: a firing whose target's rank is not below the
    source's must land exactly on the `nxt`-successor. -/
theorem min_fire (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    {s v : S} {α : T → Bool} {a : A}
    (hstep : autStep (genW T) (trimAut aut) s α = some (a, v))
    (hvmin : rank s ≤ rank v) :
    v = nxt s := by
  have hdecT : ∀ s (α : T → Bool), ∀ e ∈ (trimAut aut).trans s,
      bval (genW T) e.1 α = true →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
    intro s α e he hb
    obtain ⟨g₀, hg₀, himp⟩ := trimList_target_mem_fires aut (aut.trans s)
      .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀ ⟨α, himp α hb⟩
  obtain ⟨ea, hea, hbea, -, heat⟩ := firstMatch_mem_fires (genW T) hstep
  have heat' : ea.2.2 = v := heat
  rcases hdecT s α ea hea hbea with hEq | hLt
  · exact heat'.symm.trans hEq
  · rw [heat'] at hLt
    omega

open Classical in
/-- **CLASS-SUCCESSOR WELL-DEFINEDNESS**: two same-rank source states with
    equal languages that both fire at a common live-derivative atom have
    `nxt`-successors with equal languages — so the quotient successor is a
    function of the class. -/
theorem class_succ_eq (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    {s₁ s₂ : S} {α : T → Bool} {a : A}
    (hL : autLang (genW T) (trimAut aut) s₁
      = autLang (genW T) (trimAut aut) s₂)
    (hrank : rank s₂ = rank s₁)
    (hstep₁ : autStep (genW T) (trimAut aut) s₁ α = some (a, nxt s₁))
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
  have hv : v = nxt s₂ := by
    refine min_fire aut rank nxt hdec hstep₂ ?_
    have := hmin₂ v hvL
    omega
  rw [← hv]
  exact hvL

#print axioms class_succ_eq

/-! ## Orbit wrap arithmetic and language congruences -/

theorem nxtIter_wrap {nxt : S → S} {u₀ : S} {k : Nat}
    (hper : nxtIter nxt k u₀ = u₀) :
    ∀ n, nxtIter nxt (k + n) u₀ = nxtIter nxt n u₀ := by
  intro n
  rw [nxtIter_add, hper]

theorem nxtIter_mul_period {nxt : S → S} {u₀ : S} {k : Nat}
    (hper : nxtIter nxt k u₀ = u₀) :
    ∀ q, nxtIter nxt (k * q) u₀ = u₀ := by
  intro q
  induction q with
  | zero => rfl
  | succ q ih =>
      rw [Nat.mul_succ, nxtIter_add, ih, hper]

theorem nxtIter_mod {nxt : S → S} {u₀ : S} {k : Nat} (hk : 1 ≤ k)
    (hper : nxtIter nxt k u₀ = u₀) :
    ∀ n, nxtIter nxt n u₀ = nxtIter nxt (n % k) u₀ := by
  intro n
  conv =>
    lhs
    rw [show n = k * (n / k) + n % k from (Nat.div_add_mod n k).symm]
  rw [nxtIter_add, nxtIter_mul_period hper]

open Classical in
/-- Orbit liveness, unbounded index. -/
theorem orbit_live_all (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀) :
    ∀ j, Live (trimAut aut) (nxtIter nxt j u₀) := by
  intro j
  rw [nxtIter_mod hk hper]
  exact orbit_track aut rank nxt hfire u₀ hlive (j % k)
    (fun i hi => hnofix i (by
      have := Nat.mod_lt j (show 0 < k by omega)
      omega))

open Classical in
/-- Orbit non-fixedness, unbounded index. -/
theorem orbit_nofix_all {nxt : S → S} {u₀ : S} {k : Nat} (hk : 1 ≤ k)
    (hper : nxtIter nxt k u₀ = u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀) :
    ∀ j, nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀ := by
  intro j
  rw [nxtIter_mod hk hper]
  exact hnofix (j % k) (Nat.mod_lt j (show 0 < k by omega))

open Classical in
/-- Minimal realizer ranks are language-determined. -/
theorem minRank_lang_congr (aut : GAut S A T) (rank : S → Nat) {c₁ c₂ : S}
    (h : autLang (genW T) (trimAut aut) c₁
      = autLang (genW T) (trimAut aut) c₂) :
    minRank (trimAut aut) rank c₁ = minRank (trimAut aut) rank c₂ := by
  refine Nat.le_antisymm ?_ ?_
  · obtain ⟨u, hule, huL⟩ := minRank_spec (trimAut aut) rank c₂
    have := minRank_le (trimAut aut) rank (huL.trans h.symm)
    omega
  · obtain ⟨u, hule, huL⟩ := minRank_spec (trimAut aut) rank c₁
    have := minRank_le (trimAut aut) rank (huL.trans h)
    omega

open Classical in
/-- Representatives are language-determined (the trim is LiveSteps, so
    language equality is bisimilarity). -/
theorem rep_lang_congr (aut : GAut S A T) {x y : S}
    (h : autLang (genW T) (trimAut aut) x
      = autLang (genW T) (trimAut aut) y) :
    bisimRep (trimAut aut) x = bisimRep (trimAut aut) y := by
  refine bisimRep_coherent (trimAut aut) ?_
  refine genBisimilar_of_uniformStateEquiv (liveSteps_trimAut aut) ?_
  exact uniformStateEquiv_of_gen h

open Classical in
/-- Orbit levels, unbounded index. -/
theorem cycle_level_all (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
  exact cycle_level_min aut rank nxt hdec hnxt_rank hfire u₀ k hper hlive
    hnofix hmin (j % k) (by
      have := Nat.mod_lt j (show 0 < k by omega)
      omega)

open Classical in
/-- **SHIFTED-ORBIT TRACKING**: any same-rank realizer of an orbit language
    generates the SAME orbit of languages, shifted — the key to canonical
    basepoints. -/
theorem orbit_lang_determined (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
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
      have hlnext : Live (trimAut aut) (nxt (nxtIter nxt (i + j) u₀)) :=
        orbit_live_all aut rank nxt hfire hk hper hlive hnofix (i + j + 1)
      have hmin₂ : ∀ w, autLang (genW T) (trimAut aut) w
          = autLang (genW T) (trimAut aut) (nxt (nxtIter nxt (i + j) u₀)) →
          rank (nxtIter nxt (i + j) u₀) ≤ rank w := by
        intro w hw
        have hlvl := cycle_level_all aut rank nxt hdec hnxt_rank hfire hk
          hper hlive hnofix hmin (i + j + 1)
        have hwrep : autLang (genW T) (trimAut aut) w
            = autLang (genW T) (trimAut aut)
              (bisimRep (trimAut aut) (nxtIter nxt (i + j + 1) u₀)) := by
          rw [rep_lang aut]
          exact hw
        have hle := minRank_le (trimAut aut) rank hwrep
        rw [hlvl] at hle
        rw [nxtIter_rank hnxt_rank u₀ (i + j)]
        omega
      have hrankeq : rank (nxtIter nxt j u') = rank (nxtIter nxt (i + j) u₀) := by
        rw [nxtIter_rank hnxt_rank u' j, hu'rank,
            nxtIter_rank hnxt_rank u₀ (i + j)]
      have hstep := class_succ_eq aut rank nxt hdec hnxt_rank
        ih.symm hrankeq hstepS hlnext hmin₂
      rw [show i + (j + 1) = (i + j) + 1 from by omega]
      exact hstep

#print axioms orbit_lang_determined

/-! ## Quotient-cycle enumeration: well-defined successors, first-return
    periods, and injectivity -/

open Classical in
/-- **QUOTIENT SUCCESSOR WELL-DEFINEDNESS**: equal orbit classes have equal
    successor classes. -/
theorem qsucc_well_defined (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    {i j : Nat}
    (h : bisimRep (trimAut aut) (nxtIter nxt i u₀)
      = bisimRep (trimAut aut) (nxtIter nxt j u₀)) :
    bisimRep (trimAut aut) (nxtIter nxt (i + 1) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
  -- equal classes have equal languages
  have hL : autLang (genW T) (trimAut aut) (nxtIter nxt i u₀)
      = autLang (genW T) (trimAut aut) (nxtIter nxt j u₀) := by
    rw [← rep_lang aut (nxtIter nxt i u₀), h, rep_lang aut]
  -- fire the i-side; transfer to the j-side by class_succ_eq
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
    have hlvl := cycle_level_all aut rank nxt hdec hnxt_rank hfire hk
      hper hlive hnofix hmin (i + 1)
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
  have hLsucc := class_succ_eq aut rank nxt hdec hnxt_rank
    hL hrank hstepI hlnext hmin₂
  exact (rep_lang_congr aut hLsucc).symm

open Classical in
/-- Iterated successor well-definedness. -/
theorem qsucc_iter (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    {i j : Nat}
    (h : bisimRep (trimAut aut) (nxtIter nxt i u₀)
      = bisimRep (trimAut aut) (nxtIter nxt j u₀)) :
    ∀ t, bisimRep (trimAut aut) (nxtIter nxt (i + t) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt (j + t) u₀) := by
  intro t
  induction t with
  | zero => exact h
  | succ t ih =>
      have := qsucc_well_defined aut rank nxt hdec hnxt_rank hfire hk hper
        hlive hnofix hmin ih
      rw [show i + (t + 1) = (i + t) + 1 from by omega,
          show j + (t + 1) = (j + t) + 1 from by omega]
      exact this

open Classical in
/-- Upward search: the least index in `[i, i+fuel]` satisfying `P`, else the
    end of the range. -/
noncomputable def findFrom (P : Nat → Prop) : Nat → Nat → Nat
  | i, 0 => i
  | i, fuel + 1 => if P i then i else findFrom P (i + 1) fuel

open Classical in
private theorem findFrom_succ (P : Nat → Prop) (i fuel : Nat) :
    findFrom P i (fuel + 1) = if P i then i else findFrom P (i + 1) fuel := rfl

open Classical in
theorem findFrom_spec (P : Nat → Prop) :
    ∀ fuel i, P (i + fuel) →
      (P (findFrom P i fuel)
        ∧ i ≤ findFrom P i fuel ∧ findFrom P i fuel ≤ i + fuel
        ∧ ∀ t, i ≤ t → t < findFrom P i fuel → ¬ P t) := by
  intro fuel
  induction fuel with
  | zero =>
      intro i hP
      have h0 : findFrom P i 0 = i := rfl
      rw [Nat.add_zero] at hP
      rw [h0]
      exact ⟨hP, Nat.le_refl _, by omega, fun t h1 h2 => by omega⟩
  | succ fuel ih =>
      intro i hP
      rw [findFrom_succ]
      by_cases hPi : P i
      · rw [if_pos hPi]
        exact ⟨hPi, Nat.le_refl _, by omega, fun t h1 h2 => by omega⟩
      · rw [if_neg hPi]
        have hP' : P ((i + 1) + fuel) := by
          rw [show (i + 1) + fuel = i + (fuel + 1) from by omega]
          exact hP
        obtain ⟨hf1, hf2, hf3, hf4⟩ := ih (i + 1) hP'
        refine ⟨hf1, by omega, by omega, ?_⟩
        intro t h1 h2
        by_cases ht : t = i
        · rw [ht]; exact hPi
        · exact hf4 t (by omega) h2

open Classical in
/-- The first-return period of the quotient orbit: least `p ≥ 1` with
    `⟦nxtIter p u₀⟧ = ⟦u₀⟧`. -/
noncomputable def qPeriod (aut : GAut S A T) (nxt : S → S) (u₀ : S)
    (k : Nat) : Nat :=
  findFrom (fun p => bisimRep (trimAut aut) (nxtIter nxt p u₀)
    = bisimRep (trimAut aut) u₀) 1 (k - 1)

open Classical in
theorem qPeriod_spec (aut : GAut S A T) (nxt : S → S) (u₀ : S) (k : Nat)
    (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀) :
    (bisimRep (trimAut aut) (nxtIter nxt (qPeriod aut nxt u₀ k) u₀)
      = bisimRep (trimAut aut) u₀)
    ∧ 1 ≤ qPeriod aut nxt u₀ k ∧ qPeriod aut nxt u₀ k ≤ k
    ∧ ∀ t, 1 ≤ t → t < qPeriod aut nxt u₀ k →
        bisimRep (trimAut aut) (nxtIter nxt t u₀)
          ≠ bisimRep (trimAut aut) u₀ := by
  unfold qPeriod
  have hPk : bisimRep (trimAut aut) (nxtIter nxt (1 + (k - 1)) u₀)
      = bisimRep (trimAut aut) u₀ := by
    rw [show 1 + (k - 1) = k from by omega, hper]
  obtain ⟨h1, h2, h3, h4⟩ := findFrom_spec
    (fun p => bisimRep (trimAut aut) (nxtIter nxt p u₀)
      = bisimRep (trimAut aut) u₀) (k - 1) 1 hPk
  exact ⟨h1, h2, by omega, fun t ht1 ht2 => h4 t ht1 ht2⟩

open Classical in
/-- **ORBIT INJECTIVITY**: below the first-return period, orbit classes are
    pairwise distinct. -/
theorem qorb_injective (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    {i j : Nat} (hij : i < j) (hjp : j < qPeriod aut nxt u₀ k)
    (h : bisimRep (trimAut aut) (nxtIter nxt i u₀)
      = bisimRep (trimAut aut) (nxtIter nxt j u₀)) :
    False := by
  obtain ⟨hp1, hp2, hp3, hp4⟩ := qPeriod_spec aut nxt u₀ k hk hper
  -- shift the coincidence to the basepoint: qorb 0 = qorb (j - i)
  have hshift := qsucc_iter aut rank nxt hdec hnxt_rank hfire hk hper hlive
    hnofix hmin h (k - i)
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

#print axioms qorb_injective

/-! ## Orbit rotation and canonical basepoints

    The hypothesis bundle transports to any shifted basepoint `nxtIter i u₀`,
    orbit membership is basepoint-independent, and the first-in-list basepoint
    is therefore the SAME canonical class from every member of the orbit. -/

theorem shift_per {nxt : S → S} {u₀ : S} {k : Nat}
    (hper : nxtIter nxt k u₀ = u₀) (i : Nat) :
    nxtIter nxt k (nxtIter nxt i u₀) = nxtIter nxt i u₀ := by
  rw [← nxtIter_add, show i + k = k + i from by omega, nxtIter_add, hper]

theorem shift_nofix {nxt : S → S} {u₀ : S} {k : Nat} (hk : 1 ≤ k)
    (hper : nxtIter nxt k u₀ = u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (i : Nat) :
    ∀ j, j < k → nxt (nxtIter nxt j (nxtIter nxt i u₀))
      ≠ nxtIter nxt j (nxtIter nxt i u₀) := by
  intro j _
  rw [← nxtIter_add]
  exact orbit_nofix_all hk hper hnofix (i + j)

open Classical in
/-- Rank minimality transports along the orbit: every shifted basepoint is a
    minimal-rank realizer of its own language. -/
theorem shift_min (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
  have hlvl := cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper
    hlive hnofix hmin i
  have hwrep : autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut)
        (bisimRep (trimAut aut) (nxtIter nxt i u₀)) := by
    rw [rep_lang aut]
    exact hw
  have hle := minRank_le (trimAut aut) rank hwrep
  rw [hlvl] at hle
  rw [nxtIter_rank hnxt_rank u₀ i]
  exact hle

/-- Orbit membership: `c` is one of the quotient classes generated by `u₀`. -/
def InOrbit (aut : GAut S A T) (nxt : S → S) (u₀ : S) (c : S) : Prop :=
  ∃ j, c = bisimRep (trimAut aut) (nxtIter nxt j u₀)

/-- **ORBIT ROTATION**: membership in the orbit is basepoint-independent —
    the orbit of any shifted basepoint is the SAME set of classes. -/
theorem inOrbit_shift {aut : GAut S A T} {nxt : S → S} {u₀ : S} {k : Nat}
    (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀) (i : Nat) :
    ∀ c, InOrbit aut nxt (nxtIter nxt i u₀) c ↔ InOrbit aut nxt u₀ c := by
  intro c
  constructor
  · rintro ⟨j, hj⟩
    exact ⟨i + j, by rw [hj, nxtIter_add]⟩
  · rintro ⟨j, hj⟩
    obtain ⟨q, r, hi, hr⟩ : ∃ q r, i = k * q + r ∧ r < k :=
      ⟨i / k, i % k, by have := Nat.div_add_mod i k; omega,
        Nat.mod_lt i (by omega)⟩
    refine ⟨(k - r) + j % k, ?_⟩
    rw [hj]
    have h1 : nxtIter nxt ((k - r) + j % k) (nxtIter nxt i u₀)
        = nxtIter nxt (i + ((k - r) + j % k)) u₀ :=
      (nxtIter_add nxt i ((k - r) + j % k) u₀).symm
    have h2 : i + ((k - r) + j % k) = k * q + (k + j % k) := by omega
    rw [h1, h2, nxtIter_add, nxtIter_mul_period hper, nxtIter_add, hper,
        ← nxtIter_mod hk hper]

open Classical in
/-- The first element of a list satisfying `P`, if any. -/
noncomputable def firstMem (P : S → Prop) : List S → Option S
  | [] => none
  | x :: xs => if P x then some x else firstMem P xs

open Classical in
private theorem firstMem_cons (P : S → Prop) (x : S) (xs : List S) :
    firstMem P (x :: xs) = if P x then some x else firstMem P xs := rfl

open Classical in
/-- `firstMem` respects pointwise equivalence of predicates. -/
theorem firstMem_congr {P Q : S → Prop} (h : ∀ x, P x ↔ Q x) :
    ∀ l : List S, firstMem P l = firstMem Q l := by
  intro l
  induction l with
  | nil => rfl
  | cons x xs ih =>
      rw [firstMem_cons, firstMem_cons, ih]
      rcases Classical.em (P x) with hp | hp
      · rw [if_pos hp, if_pos ((h x).mp hp)]
      · rw [if_neg hp, if_neg (fun hq => hp ((h x).mpr hq))]

open Classical in
theorem firstMem_mem {P : S → Prop} : ∀ {l : List S} {x : S},
    firstMem P l = some x → x ∈ l ∧ P x := by
  intro l
  induction l with
  | nil => intro x hx; exact nomatch hx
  | cons y ys ih =>
      intro x hx
      rw [firstMem_cons] at hx
      rcases Classical.em (P y) with hp | hp
      · rw [if_pos hp] at hx
        cases hx
        exact ⟨List.mem_cons_self .., hp⟩
      · rw [if_neg hp] at hx
        obtain ⟨hmem, hPx⟩ := ih hx
        exact ⟨List.mem_cons_of_mem y hmem, hPx⟩

open Classical in
theorem firstMem_isSome {P : S → Prop} : ∀ {l : List S} {x : S},
    x ∈ l → P x → ∃ y, firstMem P l = some y := by
  intro l
  induction l with
  | nil => intro x hx; exact absurd hx (List.not_mem_nil)
  | cons y ys ih =>
      intro x hx hPx
      rw [firstMem_cons]
      rcases Classical.em (P y) with hp | hp
      · exact ⟨y, if_pos hp⟩
      · rw [if_neg hp]
        rcases List.mem_cons.mp hx with heq | hmem
        · exact absurd (heq ▸ hPx) hp
        · exact ih hmem hPx

open Classical in
/-- The canonical basepoint of an orbit: the first state in `states` that
    belongs to the orbit of `u₀`. -/
noncomputable def basepoint (aut : GAut S A T) (nxt : S → S)
    (states : List S) (u₀ : S) : Option S :=
  firstMem (InOrbit aut nxt u₀) states

open Classical in
/-- **BASEPOINT INVARIANCE**: every member of the orbit selects the SAME
    canonical basepoint. -/
theorem basepoint_shift (aut : GAut S A T) {nxt : S → S} {u₀ : S} {k : Nat}
    (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀) (i : Nat)
    (states : List S) :
    basepoint aut nxt states (nxtIter nxt i u₀)
      = basepoint aut nxt states u₀ :=
  firstMem_congr (inOrbit_shift hk hper i) states

open Classical in
/-- The basepoint exists whenever the orbit meets the list, and it is itself
    an orbit member drawn from the list. -/
theorem basepoint_isSome (aut : GAut S A T) (nxt : S → S)
    (states : List S) (u₀ : S)
    (hmem : bisimRep (trimAut aut) u₀ ∈ states) :
    ∃ c, basepoint aut nxt states u₀ = some c
      ∧ c ∈ states ∧ InOrbit aut nxt u₀ c := by
  obtain ⟨c, hc⟩ := firstMem_isSome (P := InOrbit aut nxt u₀) hmem ⟨0, rfl⟩
  obtain ⟨hcmem, hcorb⟩ := firstMem_mem hc
  exact ⟨c, hc, hcmem, hcorb⟩

#print axioms basepoint_shift
#print axioms basepoint_isSome

/-! ## The orbit dichotomy: pinning quotient arms to the concrete cycle

    `quot_cycle_dichotomy` classifies cleaned quotient arms against an
    ABSTRACT successor `⟦nxt u⟧` for a choice-picked minimal realizer `u`.
    On orbit classes the abstract successor IS the concrete next orbit class,
    so descent-free classes have every arm pinned to self-or-next — which is
    exactly the walked-exit side condition `hint_nil`. -/

open Classical in
/-- **THE ORBIT DICHOTOMY**: every cleaned arm of the canonical quotient at
    the orbit class `⟦nxtIter j u₀⟧` is a self-arm, strictly descends in
    minimal-realizer rank, or targets the NEXT orbit class
    `⟦nxtIter (j+1) u₀⟧`. -/
theorem orbit_dichotomy (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
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
    quot_cycle_dichotomy aut rank nxt hdec _ hc
  have hsucc : bisimRep (trimAut aut) (nxt u)
      = bisimRep (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
    have hlvl := cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper
      hlive hnofix hmin j
    have hrankJ : rank (nxtIter nxt j u₀) = rank u₀ :=
      nxtIter_rank hnxt_rank u₀ j
    have hL1 : autLang (genW T) (trimAut aut) (nxtIter nxt j u₀)
        = autLang (genW T) (trimAut aut) u :=
      (huL.trans (rep_lang aut _)).symm
    have hranku : rank u = rank (nxtIter nxt j u₀) := by
      rw [hlvl] at hule
      have h2 : rank (nxtIter nxt j u₀) ≤ rank u :=
        shift_min aut rank nxt hdec hnxt_rank hfire hk hper hlive hnofix
          hmin j u hL1.symm
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
      have h3 := shift_min aut rank nxt hdec hnxt_rank hfire hk hper hlive
        hnofix hmin (j + 1) w hw
      rw [nxtIter_rank hnxt_rank u₀ (j + 1)] at h3
      rw [hrankJ]
      exact h3
    have hLsucc := class_succ_eq aut rank nxt hdec hnxt_rank hL1 hranku
      hstep hlnext hmin₂
    exact rep_lang_congr aut hLsucc
  intro e he
  rcases harms e he with h | h | h
  · exact Or.inl h
  · exact Or.inr (Or.inl h)
  · exact Or.inr (Or.inr (h.trans hsucc))

open Classical in
/-- **DESCENT-FREE PINNING**: an orbit class with no descending arms has
    every cleaned arm pinned to self or the next orbit class. -/
theorem orbit_arms_pinned (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
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
      ∨ e.2.2 = bisimRep (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
  intro e he
  rcases orbit_dichotomy aut rank nxt hdec hnxt_rank hfire hk hper hlive
    hnofix hmin j hc e he with h | h | h
  · exact Or.inl h
  · exact absurd h (hNoDesc e he)
  · exact Or.inr h

open Classical in
/-- The orbit's cycle map wraps at the first-return period. -/
theorem qm_wrap (aut : GAut S A T) (nxt : S → S) (u₀ : S) (k : Nat)
    (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀) :
    bisimRep (trimAut aut) (nxtIter nxt (qPeriod aut nxt u₀ k) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt 0 u₀) :=
  (qPeriod_spec aut nxt u₀ k hk hper).1

open Classical in
/-- Arms pinned to self-or-next through the `nxtAt` wrap of the cycle map
    `m j := ⟦nxtIter j u₀⟧` at length `qPeriod`. -/
theorem orbit_arms_pinned_nxtAt (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
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
  rcases orbit_arms_pinned aut rank nxt hdec hnxt_rank hfire hk hper hlive
    hnofix hmin j hc hNoDesc e he with h | h
  · exact Or.inl h
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
/-- **PINNED ARMS GIVE `hint_nil`**: when every arm at `m j` targets self or
    `nxtAt m len j`, the walked-exit interior side condition holds. -/
theorem hint_nil_of_pinned (Q : GAut S A T) (m : Nat → S) (len j : Nat)
    (hpin : ∀ e ∈ Q.trans (m j), e.2.2 = m j ∨ e.2.2 = nxtAt m len j) :
    gOthers (nxtAt m len j) (restL Q m j) = [] := by
  apply gOthers_nil_of_all
  intro e he
  obtain ⟨heL, hne⟩ := gOthers_sub (m j) (Q.trans (m j)) e he
  rcases hpin e heL with h | h
  · exact absurd h hne
  · exact h

#print axioms orbit_dichotomy
#print axioms orbit_arms_pinned_nxtAt
#print axioms hint_nil_of_pinned

/-! ## Halt-guard side conditions from empty-word-freeness

    Interior states of a chain loop never accept the empty word — the
    guardedness of the loop body, semantically.  Since `trimAut`,
    `bisimQuotAut`, and `cleanAut` all preserve `hlt` verbatim, an
    empty-word-free orbit member forces its quotient class's halt guard to
    be SEMANTICALLY EMPTY, and all three remaining walked-exit side
    conditions (`himpc`, `hdisj`, `hexcl`) follow for free. -/

theorem guardImplies_of_empty {b : BExp T} (h : GuardEmpty b) (c : BExp T) :
    GuardImplies b c := by
  intro X W x hb
  rw [h X W x] at hb
  exact nomatch hb

theorem guardEmpty_and_left {b : BExp T} (h : GuardEmpty b) (c : BExp T) :
    GuardEmpty (.and b c) := by
  intro X W x
  show (bval W b x && bval W c x) = false
  rw [h X W x]
  rfl

open Classical in
/-- **EMPTY-WORD-FREE ⟹ EMPTY HALT GUARD**: an orbit member that accepts no
    empty word gives its quotient class a semantically empty halt guard —
    at EVERY valuation, by `bval` naturality through the generic atom. -/
theorem orbit_halt_empty (aut : GAut S A T) (nxt : S → S) {u₀ : S} (j : Nat)
    (hnoeps : ∀ α : T → Bool,
      ¬ autRun (genW T) (trimAut aut) (nxtIter nxt j u₀) α []) :
    GuardEmpty ((cleanAut (bisimQuotAut (trimAut aut))).hlt
      (bisimRep (trimAut aut) (nxtIter nxt j u₀))) := by
  intro X W x
  rw [bval_gen W x]
  cases hb : bval (genW T)
      ((cleanAut (bisimQuotAut (trimAut aut))).hlt
        (bisimRep (trimAut aut) (nxtIter nxt j u₀)))
      (fun t => W t x) with
  | false => rfl
  | true =>
      have hrun : autRun (genW T) (trimAut aut)
          (bisimRep (trimAut aut) (nxtIter nxt j u₀))
          (fun t => W t x) [] := hb
      have htrans := (iff_of_eq (congrFun
        (rep_lang aut (nxtIter nxt j u₀)) ((fun t => W t x), []))).mp hrun
      exact absurd htrans (hnoeps _)

open Classical in
/-- **THE HALT-GUARD SIDE CONDITIONS**: a cycle position with a semantically
    empty halt guard satisfies all three walked-exit halt conditions
    (`himpc`, `hdisj`, `hexcl`) against ANY port. -/
theorem cy_halt_conditions_of_empty (Q : GAut S A T) (m : Nat → S)
    (len j : Nat) (h : GuardEmpty (Q.hlt (m j))) :
    GuardImplies (Q.hlt (m j)) (Q.hlt (m 0))
    ∧ (∀ e ∈ gOthers (nxtAt m len 0) (restL Q m 0),
        GuardEmpty (.and (Q.hlt (m j)) e.1))
    ∧ GuardImplies (Q.hlt (m j))
        (.not (.or (selfG Q m 0) (nextG Q m len 0))) :=
  ⟨guardImplies_of_empty h _,
    fun e _ => guardEmpty_and_left h e.1,
    guardImplies_of_empty h _⟩

#print axioms orbit_halt_empty
#print axioms cy_halt_conditions_of_empty

/-! ## THE ORBIT CY-BUNDLE

    Everything `walked_assembly_roles`' cycle hypothesis demands — rank
    equality along the cycle, port descent, interior pinning, and the three
    halt conditions — derived for the canonical orbit cycle
    `m j := ⟦nxtIter j u₀⟧` at length `qPeriod`.  Only the global
    cy-coherence (position assignment) remains for the final glue. -/

open Classical in
/-- Rank equality along the orbit cycle: every class sits at level
    `rank u₀`. -/
theorem orbit_rank_eq (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
      minRank (trimAut aut) rank (bisimRep (trimAut aut) (nxtIter nxt j u₀))
        = minRank (trimAut aut) rank
            (bisimRep (trimAut aut) (nxtIter nxt i u₀)) := by
  intro j i
  rw [cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper hlive hnofix
        hmin j,
      cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper hlive hnofix
        hmin i]

open Classical in
/-- **PORT DESCENT**: the port's non-self, non-next arms all strictly
    descend in minimal-realizer rank. -/
theorem orbit_port_descent (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
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
  rcases orbit_dichotomy aut rank nxt hdec hnxt_rank hfire hk hper hlive
    hnofix hmin 0 hc e heL2 with h | h | h
  · exact absurd h hne2
  · exact h
  · exfalso
    apply hne1
    show e.2.2 = nxtAt (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
      (qPeriod aut nxt u₀ k) 0
    unfold nxtAt
    rw [if_neg (by omega : ¬ (0 + 1 = qPeriod aut nxt u₀ k))]
    exact h

open Classical in
/-- **THE ORBIT CY-BUNDLE**: the complete per-orbit hypothesis package of
    `walked_assembly_roles` — rank equality, port descent, interior pinning
    (`hint_nil`), and the three halt conditions — for the canonical cycle
    map `m j := ⟦nxtIter j u₀⟧` at length `qPeriod`.  The fragment supplies
    only interior descent-freeness and interior empty-word-freeness. -/
theorem orbit_cy_bundle (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
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
      minRank (trimAut aut) rank (bisimRep (trimAut aut) (nxtIter nxt j u₀))
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
            (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀)) j) = [])
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
    exact orbit_rank_eq aut rank nxt hdec hnxt_rank hfire hk hper hlive
      hnofix hmin j 0
  · exact orbit_port_descent aut rank nxt hdec hnxt_rank hfire hk hper
      hlive hnofix hmin hlen2 (hstates 0)
  · intro j hj hjlt
    exact hint_nil_of_pinned (cleanAut (bisimQuotAut (trimAut aut)))
      (fun i => bisimRep (trimAut aut) (nxtIter nxt i u₀))
      (qPeriod aut nxt u₀ k) j
      (orbit_arms_pinned_nxtAt aut rank nxt hdec hnxt_rank hfire hk hper
        hlive hnofix hmin j (hstates j) (hNoDescInt j hj hjlt))
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

#print axioms orbit_cy_bundle

/-! ## Rotation and witness invariance: the quotient cycle is canonical

    The global `cy` assignment must give every orbit member the SAME cycle
    data.  Different members supply different witnesses `(u₀, k)` — rotated
    on the same source orbit, or on an entirely different bisimilar source
    orbit.  Here: the first-return period is invariant under rotation
    (`qPeriod_shift`) and under change of witness (`qPeriod_congr`), and the
    enumerations agree pointwise (`orbit_m_eq`). -/

open Classical in
/-- **ROTATION INVARIANCE OF THE PERIOD**: every shifted basepoint sees the
    same first-return period. -/
theorem qPeriod_shift (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    qPeriod aut nxt (nxtIter nxt i u₀) k = qPeriod aut nxt u₀ k := by
  rw [nxtIter_mod hk hper i]
  have hik : i % k < k := Nat.mod_lt i (by omega)
  generalize hgen : i % k = i' at hik ⊢
  obtain ⟨hA1, hA2, hA3, hA4⟩ := qPeriod_spec aut nxt u₀ k hk hper
  obtain ⟨hS1, hS2, hS3, hS4⟩ := qPeriod_spec aut nxt (nxtIter nxt i' u₀) k
    hk (shift_per hper i')
  -- the base return transports to the shifted orbit
  have hretS : bisimRep (trimAut aut)
      (nxtIter nxt (qPeriod aut nxt u₀ k) (nxtIter nxt i' u₀))
      = bisimRep (trimAut aut) (nxtIter nxt i' u₀) := by
    have h0 := qsucc_iter aut rank nxt hdec hnxt_rank hfire hk hper hlive
      hnofix hmin (i := qPeriod aut nxt u₀ k) (j := 0) hA1 i'
    rw [Nat.add_comm (qPeriod aut nxt u₀ k) i', Nat.zero_add i'] at h0
    rw [nxtIter_add] at h0
    exact h0
  -- the shifted return transports back to the base orbit
  have hretB : bisimRep (trimAut aut)
      (nxtIter nxt (qPeriod aut nxt (nxtIter nxt i' u₀) k) u₀)
      = bisimRep (trimAut aut) u₀ := by
    have hS1' : bisimRep (trimAut aut)
        (nxtIter nxt (i' + qPeriod aut nxt (nxtIter nxt i' u₀) k) u₀)
        = bisimRep (trimAut aut) (nxtIter nxt i' u₀) := by
      rw [nxtIter_add]
      exact hS1
    have h1 := qsucc_iter aut rank nxt hdec hnxt_rank hfire hk hper hlive
      hnofix hmin
      (i := i' + qPeriod aut nxt (nxtIter nxt i' u₀) k) (j := i')
      hS1' (k - i')
    rw [show i' + qPeriod aut nxt (nxtIter nxt i' u₀) k + (k - i')
          = qPeriod aut nxt (nxtIter nxt i' u₀) k + k from by omega,
        show i' + (k - i') = k from by omega] at h1
    rw [qorb_periodic aut nxt u₀ k hper] at h1
    rw [hper] at h1
    exact h1
  refine Nat.le_antisymm ?_ ?_
  · rcases Nat.lt_or_ge (qPeriod aut nxt u₀ k)
      (qPeriod aut nxt (nxtIter nxt i' u₀) k) with hlt | hge
    · exact absurd hretS (hS4 _ hA2 hlt)
    · exact hge
  · rcases Nat.lt_or_ge (qPeriod aut nxt (nxtIter nxt i' u₀) k)
      (qPeriod aut nxt u₀ k) with hlt | hge
    · exact absurd hretB (hA4 _ hS2 hlt)
    · exact hge

open Classical in
/-- **WITNESS INVARIANCE OF THE ENUMERATION**: any same-rank realizer of an
    orbit language enumerates the SAME classes, shifted. -/
theorem orbit_m_eq (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    {i : Nat} {u₁ : S}
    (hL : autLang (genW T) (trimAut aut) u₁
      = autLang (genW T) (trimAut aut) (nxtIter nxt i u₀))
    (hr : rank u₁ = rank u₀) :
    ∀ j, bisimRep (trimAut aut) (nxtIter nxt j u₁)
      = bisimRep (trimAut aut) (nxtIter nxt (i + j) u₀) := by
  intro j
  exact rep_lang_congr aut (orbit_lang_determined aut rank nxt hdec
    hnxt_rank hfire hk hper hlive hnofix hmin hL hr j)

open Classical in
/-- **WITNESS INVARIANCE OF THE PERIOD**: any periodic same-rank realizer of
    an orbit language has the SAME first-return period — regardless of its
    own source period `k₁`. -/
theorem qPeriod_congr (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    {u₁ : S} {k₁ : Nat} (hk₁ : 1 ≤ k₁) (hper₁ : nxtIter nxt k₁ u₁ = u₁)
    {i : Nat}
    (hL : autLang (genW T) (trimAut aut) u₁
      = autLang (genW T) (trimAut aut) (nxtIter nxt i u₀))
    (hr : rank u₁ = rank u₀) :
    qPeriod aut nxt u₁ k₁ = qPeriod aut nxt u₀ k := by
  have hpt : ∀ t, bisimRep (trimAut aut) (nxtIter nxt t u₁)
      = bisimRep (trimAut aut) (nxtIter nxt t (nxtIter nxt i u₀)) := by
    intro t
    rw [← nxtIter_add]
    exact orbit_m_eq aut rank nxt hdec hnxt_rank hfire hk hper hlive
      hnofix hmin hL hr t
  have hept : bisimRep (trimAut aut) u₁
      = bisimRep (trimAut aut) (nxtIter nxt i u₀) := hpt 0
  obtain ⟨hB1, hB2, hB3, hB4⟩ := qPeriod_spec aut nxt u₁ k₁ hk₁ hper₁
  obtain ⟨hS1, hS2, hS3, hS4⟩ := qPeriod_spec aut nxt (nxtIter nxt i u₀) k
    hk (shift_per hper i)
  have hretS : bisimRep (trimAut aut)
      (nxtIter nxt (qPeriod aut nxt (nxtIter nxt i u₀) k) u₁)
      = bisimRep (trimAut aut) u₁ :=
    (hpt _).trans (hS1.trans hept.symm)
  have hretB : bisimRep (trimAut aut)
      (nxtIter nxt (qPeriod aut nxt u₁ k₁) (nxtIter nxt i u₀))
      = bisimRep (trimAut aut) (nxtIter nxt i u₀) :=
    (hpt _).symm.trans (hB1.trans hept)
  have hmain : qPeriod aut nxt u₁ k₁
      = qPeriod aut nxt (nxtIter nxt i u₀) k := by
    refine Nat.le_antisymm ?_ ?_
    · rcases Nat.lt_or_ge (qPeriod aut nxt (nxtIter nxt i u₀) k)
        (qPeriod aut nxt u₁ k₁) with hlt | hge
      · exact absurd hretS (hB4 _ hS2 hlt)
      · exact hge
    · rcases Nat.lt_or_ge (qPeriod aut nxt u₁ k₁)
        (qPeriod aut nxt (nxtIter nxt i u₀) k) with hlt | hge
      · exact absurd hretB (hS4 _ hB2 hlt)
      · exact hge
  exact hmain.trans (qPeriod_shift aut rank nxt hdec hnxt_rank hfire hk
    hper hlive hnofix hmin i)

#print axioms qPeriod_shift
#print axioms qPeriod_congr

/-! ## The cy-assembly support layer

    Class-level mod reduction, cross-witness orbit tracking, orbit-closure of
    `InOrbit`, list-relative `firstMem` congruence, and the canonical
    position function — everything the global `cy` assignment consumes. -/

open Classical in
/-- The class sequence is `qPeriod`-periodic. -/
theorem qorb_period_all (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w) :
    ∀ t, bisimRep (trimAut aut)
      (nxtIter nxt (t + qPeriod aut nxt u₀ k) u₀)
      = bisimRep (trimAut aut) (nxtIter nxt t u₀) := by
  intro t
  have hA1 := (qPeriod_spec aut nxt u₀ k hk hper).1
  have h0 := qsucc_iter aut rank nxt hdec hnxt_rank hfire hk hper hlive
    hnofix hmin (i := qPeriod aut nxt u₀ k) (j := 0) hA1 t
  rw [Nat.zero_add] at h0
  rw [Nat.add_comm t (qPeriod aut nxt u₀ k)]
  exact h0

open Classical in
/-- **CLASS-LEVEL MOD REDUCTION**: every orbit index reduces modulo the
    first-return period. -/
theorem qorb_qmod (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w) :
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
        rw [qorb_period_all aut rank nxt hdec hnxt_rank hfire hk hper hlive
          hnofix hmin (r + qPeriod aut nxt u₀ k * q)]
        exact ih r
  intro j
  have hdm := Nat.div_add_mod j (qPeriod aut nxt u₀ k)
  have h0 := hmul (j / qPeriod aut nxt u₀ k) (j % qPeriod aut nxt u₀ k)
  rw [show j % qPeriod aut nxt u₀ k
      + qPeriod aut nxt u₀ k * (j / qPeriod aut nxt u₀ k) = j from
        by omega] at h0
  exact h0

open Classical in
/-- **CROSS-WITNESS TRACKING**: orbits of different witnesses that meet in
    one class track together forever. -/
theorem orbit_track_from (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u : S} {k : Nat} (hkU : 1 ≤ k) (hperU : nxtIter nxt k u = u)
    (hliveU : Live (trimAut aut) u)
    (hnofixU : ∀ j, j < k → nxt (nxtIter nxt j u) ≠ nxtIter nxt j u)
    (hminU : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u → rank u ≤ rank w)
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
    have h1 := cycle_level_all aut rank nxt hdec hnxt_rank hfire hkV hperV
      hliveV hnofixV hminV s
    have h2 := cycle_level_all aut rank nxt hdec hnxt_rank hfire hkU hperU
      hliveU hnofixU hminU t
    rw [heq] at h1
    omega
  have hr : rank (nxtIter nxt s v) = rank u := by
    rw [nxtIter_rank hnxt_rank v s]
    exact hrv
  have h3 := orbit_m_eq aut rank nxt hdec hnxt_rank hfire hkU hperU hliveU
    hnofixU hminU (i := t) (u₁ := nxtIter nxt s v) hL hr d
  rw [← nxtIter_add] at h3
  exact h3

open Classical in
/-- **ORBIT-CLOSURE OF `InOrbit`**: a witness containing one class of an
    orbit contains them all. -/
theorem inOrbit_track (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u : S} {k : Nat} (hkU : 1 ≤ k) (hperU : nxtIter nxt k u = u)
    (hliveU : Live (trimAut aut) u)
    (hnofixU : ∀ j, j < k → nxt (nxtIter nxt j u) ≠ nxtIter nxt j u)
    (hminU : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u → rank u ≤ rank w)
    {w : S} {k₂ : Nat} (hkW : 1 ≤ k₂) (hperW : nxtIter nxt k₂ w = w)
    (hliveW : Live (trimAut aut) w)
    (hnofixW : ∀ j, j < k₂ → nxt (nxtIter nxt j w) ≠ nxtIter nxt j w)
    (hminW : ∀ x, autLang (genW T) (trimAut aut) x
      = autLang (genW T) (trimAut aut) w → rank w ≤ rank x)
    {t t' : Nat}
    (h : InOrbit aut nxt w (bisimRep (trimAut aut) (nxtIter nxt t u))) :
    InOrbit aut nxt w (bisimRep (trimAut aut) (nxtIter nxt t' u)) := by
  obtain ⟨s, hs⟩ := h
  have htrack := orbit_track_from aut rank nxt hdec hnxt_rank hfire hkU
    hperU hliveU hnofixU hminU hkW hperW hliveW hnofixW hminW
    (t := t) (s := s) hs.symm
  refine ⟨s + ((k - t % k) + t'), ?_⟩
  rw [htrack ((k - t % k) + t')]
  have hik : t % k < k := Nat.mod_lt t (by omega)
  have hdm := Nat.div_add_mod t k
  rw [show t + ((k - t % k) + t') = k * (t / k) + (k + t') from by omega]
  rw [nxtIter_add, nxtIter_mul_period hperU, nxtIter_add, hperU]

open Classical in
/-- `firstMem` congruence relative to the list. -/
theorem firstMem_congr_mem {P Q : S → Prop} :
    ∀ l : List S, (∀ x ∈ l, (P x ↔ Q x)) → firstMem P l = firstMem Q l := by
  intro l
  induction l with
  | nil => intro _; rfl
  | cons x xs ih =>
      intro h
      rw [firstMem_cons, firstMem_cons,
          ih (fun y hy => h y (List.mem_cons_of_mem x hy))]
      rcases Classical.em (P x) with hp | hp
      · rw [if_pos hp, if_pos ((h x (List.mem_cons_self ..)).mp hp)]
      · rw [if_neg hp, if_neg
          (fun hq => hp ((h x (List.mem_cons_self ..)).mpr hq))]

open Classical in
/-- The canonical position of a class on the orbit of `u₀`: its unique
    index below the first-return period. -/
noncomputable def qpos (aut : GAut S A T) (nxt : S → S) (u₀ : S) (k : Nat)
    (c : S) : Nat :=
  if h : InOrbit aut nxt u₀ c then
    Classical.choose h % qPeriod aut nxt u₀ k
  else 0

open Classical in
theorem qpos_spec (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    {c : S} (h : InOrbit aut nxt u₀ c) :
    bisimRep (trimAut aut)
      (nxtIter nxt (qpos aut nxt u₀ k c) u₀) = c
    ∧ qpos aut nxt u₀ k c < qPeriod aut nxt u₀ k := by
  unfold qpos
  rw [dif_pos h]
  have hc := Classical.choose_spec h
  constructor
  · rw [← qorb_qmod aut rank nxt hdec hnxt_rank hfire hk hper hlive hnofix
      hmin (Classical.choose h)]
    exact hc.symm
  · exact Nat.mod_lt _ (by
      have := (qPeriod_spec aut nxt u₀ k hk hper).2.1
      omega)

open Classical in
/-- **POSITION COHERENCE**: the canonical position of the `j`-th orbit
    class is `j` itself, for `j` below the period. -/
theorem qpos_qm (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    {j : Nat} (hj : j < qPeriod aut nxt u₀ k) :
    qpos aut nxt u₀ k (bisimRep (trimAut aut) (nxtIter nxt j u₀)) = j := by
  have hio : InOrbit aut nxt u₀
      (bisimRep (trimAut aut) (nxtIter nxt j u₀)) := ⟨j, rfl⟩
  obtain ⟨heq, hlt⟩ := qpos_spec aut rank nxt hdec hnxt_rank hfire hk hper
    hlive hnofix hmin hio
  rcases Nat.lt_trichotomy
    (qpos aut nxt u₀ k (bisimRep (trimAut aut) (nxtIter nxt j u₀))) j with
    hlt' | heq' | hgt'
  · exact absurd heq
      (fun hcontra => qorb_injective aut rank nxt hdec hnxt_rank hfire hk
        hper hlive hnofix hmin hlt' hj hcontra)
  · exact heq'
  · exact absurd heq.symm
      (fun hcontra => qorb_injective aut rank nxt hdec hnxt_rank hfire hk
        hper hlive hnofix hmin hgt' hlt hcontra)

#print axioms qorb_qmod
#print axioms inOrbit_track
#print axioms qpos_qm

/-! ## THE ORBIT GLUE: `rankNxt_quot_solvesBA`

    The canonical quotient of a rank-modulo-simple-cycle automaton is
    solvable, given a list of orbit representatives covering the non-base
    classes.  `orbCy` assigns cycle data by first-match search over the
    list; coherence holds because every class of one quotient cycle finds
    the SAME representative (`inOrbit_track` + `firstMem_congr_mem`) and
    positions are canonical (`qpos_qm`).  The walked assembly does the
    rest. -/

open Classical in
/-- The global cycle assignment: search the orbit list, store the period,
    the canonical enumeration, and the canonical position. -/
noncomputable def orbCy (aut : GAut S A T) (nxt : S → S)
    (os : List (S × Nat)) (c : S) : Option (Nat × (Nat → S) × Nat) :=
  match firstMem (fun p => InOrbit aut nxt p.1 c) os with
  | none => none
  | some p => some (qPeriod aut nxt p.1 p.2,
      fun t => bisimRep (trimAut aut) (nxtIter nxt t p.1),
      qpos aut nxt p.1 p.2 c)

open Classical in
private theorem orbCy_none (aut : GAut S A T) (nxt : S → S)
    (os : List (S × Nat)) {c : S}
    (h : firstMem (fun p => InOrbit aut nxt p.1 c) os = none) :
    orbCy aut nxt os c = none := by
  unfold orbCy
  rw [h]

open Classical in
private theorem orbCy_some (aut : GAut S A T) (nxt : S → S)
    (os : List (S × Nat)) {c : S} {p : S × Nat}
    (h : firstMem (fun p => InOrbit aut nxt p.1 c) os = some p) :
    orbCy aut nxt os c = some (qPeriod aut nxt p.1 p.2,
      fun t => bisimRep (trimAut aut) (nxtIter nxt t p.1),
      qpos aut nxt p.1 p.2 c) := by
  unfold orbCy
  rw [h]

open Classical in
/-- **THE ORBIT GLUE**: a rank-modulo-simple-cycle automaton with a
    covering orbit list has a solvable canonical quotient. -/
theorem rankNxt_quot_solvesBA (aut : GAut S A T) (rank : S → Nat)
    (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
            (nextG (cleanAut (bisimQuotAut (trimAut aut))) m len 0)))) := by
    intro s len m i hcys
    cases hfm : firstMem (fun p => InOrbit aut nxt p.1 s) os with
    | none =>
        rw [orbCy_none aut nxt os hfm] at hcys
        exact nomatch hcys
    | some p =>
        rw [orbCy_some aut nxt os hfm] at hcys
        have hinj := Option.some.inj hcys
        rw [Prod.mk.injEq, Prod.mk.injEq] at hinj
        obtain ⟨hlenE, hmE, hiE⟩ := hinj
        subst hlenE
        subst hmE
        subst hiE
        obtain ⟨hpmem, hio⟩ := firstMem_mem hfm
        obtain ⟨hk, hper, hlive, hnofix, hmin, hlen2, hstates, hnodesc,
          hnoeps⟩ := hos p hpmem
        obtain ⟨hc3, hposlt⟩ := qpos_spec aut rank nxt hdec hnxt_rank hfire
          hk hper hlive hnofix hmin hio
        obtain ⟨hB1, hB2, hB3, hB4, hB5, hB6⟩ := orbit_cy_bundle aut rank
          nxt hdec hnxt_rank hfire hk hper hlive hnofix hmin hlen2 hstates
          hnodesc hnoeps
        refine ⟨hposlt, hlen2, hc3, ?_, hB1, hB2, hB3, hB4, hB5, hB6⟩
        intro j hj
        have hcongr : firstMem (fun p' => InOrbit aut nxt p'.1
            (bisimRep (trimAut aut) (nxtIter nxt j p.1))) os
            = firstMem (fun p' => InOrbit aut nxt p'.1 s) os := by
          apply firstMem_congr_mem
          intro p' hp'
          obtain ⟨hk', hper', hlive', hnofix', hmin', -, -, -, -⟩ :=
            hos p' hp'
          constructor
          · intro hin
            have h2 := inOrbit_track aut rank nxt hdec hnxt_rank hfire
              hk hper hlive hnofix hmin hk' hper' hlive' hnofix' hmin'
              (t := j) (t' := qpos aut nxt p.1 p.2 s) hin
            rw [hc3] at h2
            exact h2
          · intro hin
            have hin' : InOrbit aut nxt p'.1 (bisimRep (trimAut aut)
                (nxtIter nxt (qpos aut nxt p.1 p.2 s) p.1)) := by
              rw [hc3]
              exact hin
            exact inOrbit_track aut rank nxt hdec hnxt_rank hfire
              hk hper hlive hnofix hmin hk' hper' hlive' hnofix' hmin'
              (t := qpos aut nxt p.1 p.2 s) (t' := j) hin'
        rw [orbCy_some aut nxt os (hcongr.trans hfm)]
        rw [qpos_qm aut rank nxt hdec hnxt_rank hfire hk hper hlive
          hnofix hmin hj]
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
      rw [orbCy_some aut nxt os hy] at hnone
      exact nomatch hnone
  obtain ⟨qsol, hroles⟩ := walked_assembly_roles
    (cleanAut (bisimQuotAut (trimAut aut)))
    (fun c => minRank (trimAut aut) rank c)
    (orbCy aut nxt os) hcy hbase
  exact ⟨qsol, solvesBA_unclean _ (decomp_solves _ _ hroles)⟩

#print axioms rankNxt_quot_solvesBA

/-! ## Interior descent-freeness from deterministic stepping

    An interior chain position steps UNIQUELY: at every atom, the one thing
    it can do is perform the next chain action and advance.  Semantically
    this pins every cleaned quotient arm's target to the successor class —
    which sits at the SAME cycle level — so no arm descends.  This converts
    `rankNxt_quot_solvesBA`'s `hnodesc` obligation into a constructive
    single-step fact about the source automaton. -/

open Classical in
/-- **DETERMINISTIC STEP ⟹ NO DESCENT**: an orbit member that steps
    uniquely to its successor at every atom gives its quotient class no
    descending arms. -/
theorem interior_no_desc (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s,
      (∃ α : T → Bool, bval (genW T) e.1 α = true) →
      e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    (hnxt_rank : ∀ s, rank (nxt s) = rank s)
    (hfire : ∀ s, Live (trimAut aut) s → nxt s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T) (trimAut aut) s α = some (a, nxt s))
    {u₀ : S} {k : Nat} (hk : 1 ≤ k) (hper : nxtIter nxt k u₀ = u₀)
    (hlive : Live (trimAut aut) u₀)
    (hnofix : ∀ j, j < k → nxt (nxtIter nxt j u₀) ≠ nxtIter nxt j u₀)
    (hmin : ∀ w, autLang (genW T) (trimAut aut) w
      = autLang (genW T) (trimAut aut) u₀ → rank u₀ ≤ rank w)
    (j : Nat)
    (hstep_uniq : ∀ α : T → Bool, ∃ a : A,
      autStep (genW T) (trimAut aut) (nxtIter nxt j u₀) α
        = some (a, nxtIter nxt (j + 1) u₀)) :
    ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans
        (bisimRep (trimAut aut) (nxtIter nxt j u₀)),
      ¬ minRank (trimAut aut) rank e.2.2
          < minRank (trimAut aut) rank
              (bisimRep (trimAut aut) (nxtIter nxt j u₀)) := by
  intro e he
  -- the arm fires at some generic atom
  obtain ⟨α, -, hfm⟩ := cleanList_fires
    (bisimQuotAut (trimAut aut))
    ((bisimQuotAut (trimAut aut)).trans
      (bisimRep (trimAut aut) (nxtIter nxt j u₀))) .zero e he
  have hstepQ : autStep (genW T) (bisimQuotAut (trimAut aut))
      (bisimRep (trimAut aut) (nxtIter nxt j u₀)) α
      = some (e.2.1, e.2.2) := by
    rw [← autStep_cleanAut (genW T)]
    exact hfm
  -- the quotient step is a language derivative (in trim terms)
  have hDT : ∀ (β : T → Bool) (w : List (A × (T → Bool))),
      autRun (genW T) (trimAut aut) e.2.2 β w ↔
        autRun (genW T) (trimAut aut)
          (bisimRep (trimAut aut) (nxtIter nxt j u₀)) α
          ((e.2.1, β) :: w) := by
    intro β w
    have h1 := step_derivative hstepQ β w
    have h2 : autRun (genW T) (bisimQuotAut (trimAut aut)) e.2.2 β w
        ↔ autRun (genW T) (trimAut aut) e.2.2 β w :=
      iff_of_eq (congrFun (quot_lang_eq aut e.2.2) (β, w))
    have h3 : autRun (genW T) (bisimQuotAut (trimAut aut))
          (bisimRep (trimAut aut) (nxtIter nxt j u₀)) α
          ((e.2.1, β) :: w)
        ↔ autRun (genW T) (trimAut aut)
          (bisimRep (trimAut aut) (nxtIter nxt j u₀)) α
          ((e.2.1, β) :: w) :=
      iff_of_eq (congrFun
        (quot_lang_eq aut (bisimRep (trimAut aut) (nxtIter nxt j u₀)))
        (α, (e.2.1, β) :: w))
    exact (h2.symm.trans h1).trans h3
  -- the target is live: it accepts some word
  have heQ : e ∈ (bisimQuotAut (trimAut aut)).trans
      (bisimRep (trimAut aut) (nxtIter nxt j u₀)) :=
    cleanList_sub _ .zero e he
  obtain ⟨v'', hv'', hrep⟩ : ∃ v'',
      v'' ∈ (trimAut aut).trans
        (bisimRep (trimAut aut) (nxtIter nxt j u₀)) ∧
      bisimRep (trimAut aut) v''.2.2 = e.2.2 := by
    obtain ⟨v'', hv'', heq⟩ := List.mem_map.mp heQ
    exact ⟨v'', hv'', congrArg (fun z => z.2.2) heq⟩
  have htlive : ∃ (β : T → Bool) (w : List (A × (T → Bool))),
      autRun (genW T) (trimAut aut) e.2.2 β w := by
    have hlv : Live aut v''.2.2 :=
      trimList_target_live aut
        (aut.trans (bisimRep (trimAut aut) (nxtIter nxt j u₀))) .zero
        v'' hv''
    have hlvT : Live (trimAut aut) v''.2.2 := live_trimAut hlv
    obtain ⟨β, w, hw⟩ := hlvT
    have hle : autLang (genW T) (trimAut aut) v''.2.2
        = autLang (genW T) (trimAut aut) e.2.2 := by
      rw [← hrep]
      exact autLang_eq_of_gautBisim (genBisimilar_bisim (trimAut aut))
        (bisimRep_bisim (trimAut aut) v''.2.2)
    exact ⟨β, w, (iff_of_eq (congrFun hle (β, w))).mp hw⟩
  -- the class's word at α starts with the UNIQUE source letter
  obtain ⟨a, hstepS⟩ := hstep_uniq α
  obtain ⟨β₀, w₀, hw₀⟩ := htlive
  have hwordC : autRun (genW T) (trimAut aut)
      (bisimRep (trimAut aut) (nxtIter nxt j u₀)) α
      ((e.2.1, β₀) :: w₀) := (hDT β₀ w₀).mp hw₀
  have hwordS : autRun (genW T) (trimAut aut) (nxtIter nxt j u₀) α
      ((e.2.1, β₀) :: w₀) :=
    (iff_of_eq (congrFun (rep_lang aut (nxtIter nxt j u₀))
      (α, (e.2.1, β₀) :: w₀))).mp hwordC
  obtain ⟨s', hs', -⟩ : ∃ s',
      autStep (genW T) (trimAut aut) (nxtIter nxt j u₀) α
        = some (e.2.1, s')
      ∧ autRun (genW T) (trimAut aut) s' β₀ w₀ := hwordS
  have hletter : e.2.1 = a := by
    have h0 := hs'.symm.trans hstepS
    have h1 := Option.some.inj h0
    rw [Prod.mk.injEq] at h1
    exact h1.1
  -- the target's language IS the successor's language
  have htL : autLang (genW T) (trimAut aut) e.2.2
      = autLang (genW T) (trimAut aut) (nxtIter nxt (j + 1) u₀) := by
    funext gs
    obtain ⟨β, w⟩ := gs
    apply propext
    have hDS := step_derivative hstepS β w
    have hDc := hDT β w
    have hcs : autRun (genW T) (trimAut aut)
        (bisimRep (trimAut aut) (nxtIter nxt j u₀)) α
        ((e.2.1, β) :: w)
        ↔ autRun (genW T) (trimAut aut) (nxtIter nxt j u₀) α
          ((e.2.1, β) :: w) :=
      iff_of_eq (congrFun (rep_lang aut (nxtIter nxt j u₀))
        (α, (e.2.1, β) :: w))
    rw [hletter] at hDc hcs
    exact hDc.trans (hcs.trans hDS.symm)
  -- both levels are rank u₀
  intro hcontra
  have h1 : minRank (trimAut aut) rank e.2.2
      = minRank (trimAut aut) rank
        (bisimRep (trimAut aut) (nxtIter nxt (j + 1) u₀)) := by
    apply minRank_lang_congr
    rw [htL, rep_lang aut]
  have h2 := cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper
    hlive hnofix hmin (j + 1)
  have h3 := cycle_level_all aut rank nxt hdec hnxt_rank hfire hk hper
    hlive hnofix hmin j
  rw [h1, h2, h3] at hcontra
  exact Nat.lt_irrefl _ hcontra

#print axioms interior_no_desc

end GkatOrbit






