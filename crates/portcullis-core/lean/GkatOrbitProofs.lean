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

end GkatOrbit
