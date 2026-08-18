import GkatSumQuotientProofs

/-!
# The nesting coequation is closed under quotients — the covariety's other half

`Nested_sumGAut` (in `GkatSumQuotientProofs`) proves the nesting coequation closed under
coproducts, and `nested_of_quotient_nested` pulls it back along a quotient.  The literature's
characterisation says more: the class is a COVARIETY, closed under homomorphic images.  That is
the direction the sum route actually consumes — the start-merged quotient of `Me + Mf` was
measured nested on all 274,461 systems across two sizes, and this file replaces that measurement
with a theorem.

The proof is the pigeonhole argument.  A mutual-reachability cycle between `q1` and `q2` in the
quotient lifts, step by step, through the bisimulation graph (`autStep_eq`): from any source
state over `q1` one reaches a state over `q2` and then a state over `q1` again.  Iterating
builds an infinite chain of states over `q1`; the automaton is finite and targets-listed, so two
chain entries coincide, closing a GENUINE cycle in the source that visits both fibers.  Halt
guards transport along the quotient (`hlt_ba`), so the complementary-halt pattern that would
violate nestedness in the quotient reproduces in the source, contradicting `Nested src`.

Well-nestedness famously FAILS this closure — there is a well-nested automaton with a
non-well-nested quotient, which is why the literature moves to the coequation.  `Nested` here is
the coequation's finite kernel (no mutually-reachable pair with complementary halt guards), and
for it the closure goes through.
-/

namespace GkatNestedClosure

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open Classical

variable {A T S Q Atom : Type}

/-! ## Pigeonhole, hand-rolled

    Core Lean only: a function from `Nat` into a finite list repeats.  Classical, via the
    `open Classical` decidability instance; no Mathlib. -/

/-- Strictly monotone reindexing that skips index `i0`. -/
def skipIdx (i0 k : Nat) : Nat := if k < i0 then k else k + 1

theorem skipIdx_ne (i0 k : Nat) : skipIdx i0 k ≠ i0 := by
  unfold skipIdx
  by_cases h : k < i0
  · rw [if_pos h]; exact Nat.ne_of_lt h
  · rw [if_neg h]
    intro he
    exact absurd (he ▸ Nat.lt_succ_of_le (Nat.le_of_not_lt h)) (Nat.lt_irrefl _)

theorem skipIdx_mono {i0 k l : Nat} (h : k < l) : skipIdx i0 k < skipIdx i0 l := by
  unfold skipIdx
  by_cases hk : k < i0 <;> by_cases hl : l < i0
  · rw [if_pos hk, if_pos hl]; exact h
  · rw [if_pos hk, if_neg hl]; exact Nat.lt_succ_of_lt h
  · exact absurd (Nat.lt_trans h hl) hk
  · rw [if_neg hk, if_neg hl]; exact Nat.succ_lt_succ h

theorem skipIdx_lt {i0 k m : Nat} (h : k < m) : skipIdx i0 k < m + 1 := by
  unfold skipIdx
  by_cases hk : k < i0
  · rw [if_pos hk]; exact Nat.lt_succ_of_lt h
  · rw [if_neg hk]; exact Nat.succ_lt_succ h

/-- **A `Nat`-indexed family drawn from a finite list repeats.** -/
theorem exists_repeat {α : Type} :
    ∀ (l : List α) (f : Nat → α), (∀ i, i < l.length + 1 → f i ∈ l) →
      ∃ i j, i < j ∧ f i = f j := by
  intro l
  induction l with
  | nil =>
      intro f h
      exact absurd (h 0 (Nat.zero_lt_succ 0)) (List.not_mem_nil)
  | cons a tl ih =>
      intro f h
      by_cases hpair : ∃ i j, i < j ∧ j < tl.length + 2 ∧ f i = a ∧ f j = a
      · obtain ⟨i, j, hij, -, hfi, hfj⟩ := hpair
        exact ⟨i, j, hij, hfi.trans hfj.symm⟩
      · by_cases hone : ∃ i, i < tl.length + 2 ∧ f i = a
        · obtain ⟨i0, hi0, hfi0⟩ := hone
          have hg : ∀ k, k < tl.length + 1 → f (skipIdx i0 k) ∈ tl := by
            intro k hk
            have hslt : skipIdx i0 k < tl.length + 2 := skipIdx_lt hk
            have hb : skipIdx i0 k < (a :: tl).length + 1 := by
              simpa [List.length_cons] using hslt
            rcases List.mem_cons.mp (h _ hb) with heq | htl
            · exact ((hpair (by
                rcases Nat.lt_or_ge (skipIdx i0 k) i0 with hlt | hge
                · exact ⟨skipIdx i0 k, i0, hlt, hi0, heq, hfi0⟩
                · exact ⟨i0, skipIdx i0 k,
                    Nat.lt_of_le_of_ne hge (fun he => skipIdx_ne i0 k he.symm),
                    hslt, hfi0, heq⟩))).elim
            · exact htl
          obtain ⟨i, j, hij, hfij⟩ := ih (fun k => f (skipIdx i0 k)) hg
          exact ⟨skipIdx i0 i, skipIdx i0 j, skipIdx_mono hij, hfij⟩
        · have hg : ∀ k, k < tl.length + 1 → f k ∈ tl := by
            intro k hk
            have hb : k < (a :: tl).length + 1 := by
              simp only [List.length_cons]
              exact Nat.lt_succ_of_lt hk
            rcases List.mem_cons.mp (h k hb) with heq | htl
            · exact absurd ⟨k, Nat.lt_succ_of_lt hk, heq⟩ hone
            · exact htl
          exact ih f hg

/-! ## Lifting steps and paths backwards through a quotient -/

/-- A quotient step lifts: whatever the image does, the source can match. -/
theorem autStep1_lift {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot) (V : T → Atom → Bool)
    {s : S} {t : Q} (h : AutStep1 V quot (π.mapState s) t) :
    ∃ u, π.mapState u = t ∧ AutStep1 V src s u := by
  obtain ⟨a, q, hq⟩ := h
  have heq := π.autStep_eq V s a
  rw [hq] at heq
  cases hs : autStep V src s a with
  | none => rw [hs] at heq; exact absurd heq (by simp)
  | some y =>
      rw [hs] at heq
      simp only [Option.map_some] at heq
      injection heq with h1
      injection h1 with hq1 ht1
      exact ⟨y.2, ht1, a, y.1, by rw [hs]⟩

/-- Quotient reachability lifts, by induction along the path. -/
theorem autReaches_lift {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot) (V : T → Atom → Bool)
    {s : S} {t : Q} (h : AutReaches V quot (π.mapState s) t) :
    ∃ u, π.mapState u = t ∧ AutReaches V src s u := by
  generalize hstart : π.mapState s = p at h
  induction h with
  | refl => exact ⟨s, hstart, AutReaches.refl s⟩
  | tail hr hstep ih =>
      obtain ⟨u, hu, hru⟩ := ih
      rw [← hu] at hstep
      obtain ⟨w, hw, hsw⟩ := autStep1_lift π V hstep
      exact ⟨w, hw, AutReaches.tail hru hsw⟩

/-- One-or-more-step quotient reachability lifts. -/
theorem autReaches1_lift {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot) (V : T → Atom → Bool)
    {s : S} {t : Q} (h : AutReaches1 V quot (π.mapState s) t) :
    ∃ u, π.mapState u = t ∧ AutReaches1 V src s u := by
  obtain ⟨x, hstep, hreach⟩ := h
  obtain ⟨u, hu, hsu⟩ := autStep1_lift π V hstep
  rw [← hu] at hreach
  obtain ⟨w, hw, huw⟩ := autReaches_lift π V hreach
  exact ⟨w, hw, u, hsu, huw⟩

/-! ## Reachability stays inside a targets-listed state list -/

theorem autStep1_mem {aut : GAut S A T} {V : T → Atom → Bool}
    (ht : GAutTargetsListed aut) {s u : S}
    (hs : s ∈ aut.states) (h : AutStep1 V aut s u) : u ∈ aut.states := by
  obtain ⟨a, q, hq⟩ := h
  obtain ⟨g, hmem, -⟩ := firstMatch_some_mem V a (aut.trans s) hq
  exact ht s hs (g, q, u) hmem

theorem autReaches_mem {aut : GAut S A T} {V : T → Atom → Bool}
    (ht : GAutTargetsListed aut) {s u : S}
    (hs : s ∈ aut.states) (h : AutReaches V aut s u) : u ∈ aut.states := by
  induction h with
  | refl => exact hs
  | tail _ hstep ih => exact autStep1_mem ht ih hstep

theorem autReaches1_mem {aut : GAut S A T} {V : T → Atom → Bool}
    (ht : GAutTargetsListed aut) {s u : S}
    (hs : s ∈ aut.states) (h : AutReaches1 V aut s u) : u ∈ aut.states := by
  obtain ⟨x, hstep, hreach⟩ := h
  exact autReaches_mem ht (autStep1_mem ht hs hstep) hreach

/-- `AutReaches1` composes. -/
theorem autReaches1_trans {aut : GAut S A T} {V : T → Atom → Bool} {a b c : S}
    (h1 : AutReaches1 V aut a b) (h2 : AutReaches1 V aut b c) :
    AutReaches1 V aut a c := by
  obtain ⟨x, hstep, hreach⟩ := h1
  obtain ⟨y, hstep2, hreach2⟩ := h2
  exact ⟨x, hstep, AutReaches.trans hreach (AutReaches.head hstep2 hreach2)⟩

/-! ## The closure theorem -/

/-- **The nesting coequation is closed under uniform behavioural quotients.**

    With `Nested_sumGAut` (coproducts) and `nested_of_quotient_nested` (the pullback), this
    completes the closure properties the sum route consumes: the start-merged quotient of a sum
    of nested automata is nested, as a theorem rather than a 274,461-sample measurement. -/
theorem Nested_quotient {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot)
    (ht : GAutTargetsListed src) (V : T → Atom → Bool)
    (hn : Nested V src) : Nested V quot := by
  intro q1 q2 hq1 h12 h21 hcomp
  obtain ⟨s1, hs1mem, hs1⟩ := π.onto_states q1 hq1
  -- one full loop, lifted: from any source state over q1, a state over q2 and back over q1
  have step : ∀ s : S, π.mapState s = q1 →
      ∃ p : S × S, π.mapState p.1 = q2 ∧ π.mapState p.2 = q1 ∧
        AutReaches1 V src s p.1 ∧ AutReaches1 V src p.1 p.2 := by
    intro s hs
    have h12' : AutReaches1 V quot (π.mapState s) q2 := by rw [hs]; exact h12
    obtain ⟨m, hm, hsm⟩ := autReaches1_lift π V h12'
    have h21' : AutReaches1 V quot (π.mapState m) q1 := by rw [hm]; exact h21
    obtain ⟨u, hu, hmu⟩ := autReaches1_lift π V h21' 
    exact ⟨(m, u), hm, hu, hsm, hmu⟩
  -- the chain, built by classical choice
  let F : S → S × S := fun s =>
    if h : π.mapState s = q1 then Classical.choose (step s h) else (s, s)
  let f : Nat → S := fun n => Nat.rec s1 (fun _ prev => (F prev).2) n
  let mid : Nat → S := fun n => (F (f n)).1
  have key : ∀ n, π.mapState (f n) = q1 →
      π.mapState (mid n) = q2 ∧ π.mapState (f (n + 1)) = q1 ∧
        AutReaches1 V src (f n) (mid n) ∧ AutReaches1 V src (mid n) (f (n + 1)) := by
    intro n hqn
    have hF : F (f n) = Classical.choose (step (f n) hqn) := dif_pos hqn
    have spec := Classical.choose_spec (step (f n) hqn)
    have hmid : mid n = (Classical.choose (step (f n) hqn)).1 := by
      show (F (f n)).1 = _
      rw [hF]
    have hnext : f (n + 1) = (Classical.choose (step (f n) hqn)).2 := by
      show (F (f n)).2 = _
      rw [hF]
    exact ⟨hmid ▸ spec.1, hnext ▸ spec.2.1, hmid ▸ spec.2.2.1,
      hmid ▸ hnext ▸ spec.2.2.2⟩
  have hq1n : ∀ n, π.mapState (f n) = q1 := by
    intro n
    induction n with
    | zero => exact hs1
    | succ m ihm => exact (key m ihm).2.1
  have hprop := fun n => key n (hq1n n)
  have hfmem : ∀ n, f n ∈ src.states := by
    intro n
    induction n with
    | zero => exact hs1mem
    | succ m ihm =>
        exact autReaches1_mem ht (autReaches1_mem ht ihm (hprop m).2.2.1) (hprop m).2.2.2
  obtain ⟨i, j, hij, hfij⟩ := exists_repeat src.states f (fun i _ => hfmem i)
  have hchain : ∀ n m, n < m → AutReaches1 V src (f n) (f m) := by
    intro n m
    induction m with
    | zero => intro h; exact absurd h (Nat.not_lt_zero n)
    | succ m ihm =>
        intro h
        have hstep1 : AutReaches1 V src (f m) (f (m + 1)) :=
          autReaches1_trans (hprop m).2.2.1 (hprop m).2.2.2
        rcases Nat.lt_or_eq_of_le (Nat.le_of_lt_succ h) with h' | h'
        · exact autReaches1_trans (ihm h') hstep1
        · subst h'; exact hstep1
  have hAB : AutReaches1 V src (f i) (mid i) := (hprop i).2.2.1
  have hBA : AutReaches1 V src (mid i) (f i) := by
    rcases Nat.lt_or_eq_of_le (Nat.succ_le_of_lt hij) with h' | h'
    · have hj : AutReaches1 V src (mid i) (f j) :=
        autReaches1_trans (hprop i).2.2.2 (hchain (i + 1) j h')
      exact hfij.symm ▸ hj
    · have h'' : i + 1 = j := h'
      have heq : f i = f (i + 1) := by rw [h'']; exact hfij
      exact heq.symm ▸ (hprop i).2.2.2
  refine hn (f i) (mid i) (hfmem i) hAB hBA (fun a => ?_)
  have h1 := π.hlt_ba (f i) Atom V a
  have h2 := π.hlt_ba (mid i) Atom V a
  rw [hq1n i] at h1
  rw [(hprop i).1] at h2
  rw [h1, h2]
  exact hcomp a

#print axioms exists_repeat
#print axioms autReaches1_lift
#print axioms Nested_quotient

/-! ## Plumbing: targets-listed for sums, and the packaged chain

    `certifiedThompson_targetsListed` (in `GkatDeadBranchProofs`) supplies the Thompson leaf;
    the sum inherits it componentwise; and with `Nested_sumGAut` plus `Nested_quotient` above,
    the whole sum route's nestedness reduces to ONE open leaf: `Nested V (Thompson e)`. -/

theorem GAutTargetsListed_sumGAut {S₁ S₂ : Type}
    {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T}
    (h₁ : GAutTargetsListed a₁) (h₂ : GAutTargetsListed a₂) :
    GAutTargetsListed (sumGAut a₁ a₂) := by
  intro state hstate transition htransition
  cases state with
  | inl s =>
      have hs : s ∈ a₁.states := mem_sumGAut_inl hstate
      simp only [sumGAut, List.mem_map] at htransition
      obtain ⟨orig, horig, rfl⟩ := htransition
      show Sum.inl orig.2.2 ∈ (sumGAut a₁ a₂).states
      simp only [sumGAut, List.mem_append, List.mem_map]
      exact Or.inl ⟨orig.2.2, h₁ s hs orig horig, rfl⟩
  | inr s =>
      have hs : s ∈ a₂.states := mem_sumGAut_inr hstate
      simp only [sumGAut, List.mem_map] at htransition
      obtain ⟨orig, horig, rfl⟩ := htransition
      show Sum.inr orig.2.2 ∈ (sumGAut a₁ a₂).states
      simp only [sumGAut, List.mem_append, List.mem_map]
      exact Or.inr ⟨orig.2.2, h₂ s hs orig horig, rfl⟩

/-- **The sum route's nestedness, packaged.**  Every uniform behavioural quotient of the sum of
    two Thompson automata is nested, PROVIDED the Thompson automata themselves are — the one
    leaf still open.  Everything else is theorem: coproduct closure, quotient closure, and
    targets-listed for the Thompson construction and the sum. -/
theorem Nested_thompson_sum_quotient {Q : Type} {V : T → Atom → Bool}
    {e f : Exp A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient
      (sumGAut (GkatThompson.certifiedThompson A T e).aut.toGAut
               (GkatThompson.certifiedThompson A T f).aut.toGAut) quot)
    (hne : Nested V (GkatThompson.certifiedThompson A T e).aut.toGAut)
    (hnf : Nested V (GkatThompson.certifiedThompson A T f).aut.toGAut) :
    Nested V quot :=
  Nested_quotient π
    (GAutTargetsListed_sumGAut
      (GkatDeadBranch.certifiedThompson_targetsListed e)
      (GkatDeadBranch.certifiedThompson_targetsListed f))
    V (Nested_sumGAut hne hnf)

#print axioms GAutTargetsListed_sumGAut
#print axioms Nested_thompson_sum_quotient

end GkatNestedClosure
