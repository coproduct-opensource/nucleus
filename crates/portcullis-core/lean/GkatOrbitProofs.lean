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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
  have hdecT : ∀ s, ∀ e ∈ (trimAut aut).trans s,
      e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
    intro s e he
    obtain ⟨g₀, hg₀⟩ := trimList_target_mem aut (aut.trans s) .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀
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
      obtain ⟨ea, hea, -, heat⟩ := firstMatch_mem (genW T) hstepW
      have heat' : ea.2.2 = v := heat
      have hvrank : rank v ≤ rank w := by
        rcases hdecT w ea hea with hEq | hLt
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
    {s v : S} {α : T → Bool} {a : A}
    (hstep : autStep (genW T) (trimAut aut) s α = some (a, v))
    (hvmin : rank s ≤ rank v) :
    v = nxt s := by
  have hdecT : ∀ s, ∀ e ∈ (trimAut aut).trans s,
      e.2.2 = nxt s ∨ rank e.2.2 < rank s := by
    intro s e he
    obtain ⟨g₀, hg₀⟩ := trimList_target_mem aut (aut.trans s) .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀
  obtain ⟨ea, hea, -, heat⟩ := firstMatch_mem (genW T) hstep
  have heat' : ea.2.2 = v := heat
  rcases hdecT s ea hea with hEq | hLt
  · exact heat'.symm.trans hEq
  · rw [heat'] at hLt
    omega

open Classical in
/-- **CLASS-SUCCESSOR WELL-DEFINEDNESS**: two same-rank source states with
    equal languages that both fire at a common live-derivative atom have
    `nxt`-successors with equal languages — so the quotient successor is a
    function of the class. -/
theorem class_succ_eq (aut : GAut S A T) (rank : S → Nat) (nxt : S → S)
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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
    (hdec : ∀ s, ∀ e ∈ aut.trans s, e.2.2 = nxt s ∨ rank e.2.2 < rank s)
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

end GkatOrbit
