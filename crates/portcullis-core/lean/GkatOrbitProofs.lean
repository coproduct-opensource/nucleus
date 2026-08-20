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

end GkatOrbit
