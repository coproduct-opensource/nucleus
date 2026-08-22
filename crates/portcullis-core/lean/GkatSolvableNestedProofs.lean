import GkatThompsonNestedProofs

/-!
# Semantically solvable automata satisfy the nesting coequation

The harness's central soundness control rests on one cited fact: a NON-nested automaton has no
solution, so every sound procedure must reject it.  This file turns the citation into a
theorem, in its contrapositive form:

    Nested_of_semSolves : WF V aut → SemSolves V aut sol → Nested V aut

If every state's language is the denotation of an expression, then no two mutually-reachable
states carry complementary halt guards.

The argument walks the offending cycle THROUGH THE DERIVATIVES of the solution.  A language
equality `⟦d⟧ = L(s)` transfers along any automaton step whose target has nonempty language —
the fundamental theorem of derivatives (`den_cons`) produces the matching syntactic derivative,
and determinism on both sides makes the transfer exact (`step_track`).  Every state on a
complementary cycle has nonempty language (one of the two halt guards holds at every atom, and
the cycle reaches both).  So the infinite alternating walk `s1 → s2 → s1 → …` lifts to an
infinite walk through `derivs (sol s1)`, which is finite: the pigeonhole (`exists_repeat`,
shared with the quotient-closure proof) closes a GENUINE derivative cycle whose `E`-guards are
complementary — and that contradicts `Nested_derivAut`, the already-proved nestedness of
derivative automata.

Everything below `Nested_derivAut` is thus one machinery: cycles that violate nesting cannot
survive inside anything whose states denote expressions, whether the states ARE expressions
(derivatives) or merely name them (a solved automaton).
-/

namespace GkatSolvableNested

open GkatSyntax GkatGS GkatKleene GkatThompson GkatNestedClosure GkatDeriv
open Classical

variable {A T S Atom : Type}

/-- A nonempty language pulls back along reachability. -/
theorem lang_nonempty_of_reaches {aut : GAut S A T} {V : T → Atom → Bool} {s t : S}
    (h : AutReaches V aut s t) (hne : ∃ a w, autRun V aut t a w) :
    ∃ a w, autRun V aut s a w := by
  induction h with
  | refl => exact hne
  | tail hr hstep ih =>
      obtain ⟨a', w', hrun⟩ := hne
      obtain ⟨a, q0, hq⟩ := hstep
      exact ih ⟨a, (q0, a') :: w', _, hq, hrun⟩

/-- When `⟦d⟧` is a state's language, `E d` agrees with the state's halt guard. -/
theorem bval_E_eq_hlt {aut : GAut S A T} {V : T → Atom → Bool} {s : S} {d : Exp A T}
    (h : den V d = autLang V aut s) (a : Atom) :
    bval V (E d) a = bval V (aut.hlt s) a := by
  have h1 : den V d (a, []) ↔ autLang V aut s (a, []) := by rw [h]
  have h2 : den V d (a, []) ↔ bval V (E d) a = true := GkatDeriv.den_nil V d a
  cases hE : bval V (E d) a with
  | true =>
      have hb : autLang V aut s (a, []) := h1.mp (h2.mpr hE)
      exact (hb : bval V (aut.hlt s) a = true).symm
  | false =>
      cases hb : bval V (aut.hlt s) a with
      | false => rfl
      | true =>
          have hE' : bval V (E d) a = true := h2.mp (h1.mpr hb)
          rw [hE] at hE'
          exact absurd hE' (by simp)

/-- **The tracking step.**  A language match transfers along an automaton step whose target
    has nonempty language, producing the matching syntactic derivative.  Determinism of both
    `autStep` and `next` makes the transferred match exact. -/
theorem step_track {aut : GAut S A T} {V : T → Atom → Bool} {s t : S} {d : Exp A T}
    {a : Atom} {q : A}
    (hd : den V d = autLang V aut s)
    (hstep : autStep V aut s a = some (q, t))
    (hne : ∃ a' w', autRun V aut t a' w') :
    ∃ d', next V d a = some (q, d') ∧ den V d' = autLang V aut t := by
  obtain ⟨a', w', hrun⟩ := hne
  have hmem : den V d (a, (q, a') :: w') := by
    rw [hd]
    exact ⟨t, hstep, hrun⟩
  obtain ⟨d', hnext, -⟩ := (GkatDeriv.den_cons V d a q a' w').mp hmem
  refine ⟨d', hnext, funext (fun gs => propext ?_)⟩
  obtain ⟨a'', w''⟩ := gs
  constructor
  · intro hw
    have hin : den V d (a, (q, a'') :: w'') :=
      (GkatDeriv.den_cons V d a q a'' w'').mpr ⟨d', hnext, hw⟩
    rw [hd] at hin
    obtain ⟨t', ht', hrun'⟩ := hin
    rw [hstep] at ht'
    injection ht' with h1
    injection h1 with _ h2
    rw [h2]
    exact hrun'
  · intro hw
    have hin : autLang V aut s (a, (q, a'') :: w'') := ⟨t, hstep, hw⟩
    rw [← hd] at hin
    obtain ⟨d'', hnext'', hw''⟩ := (GkatDeriv.den_cons V d a q a'' w'').mp hin
    rw [hnext] at hnext''
    injection hnext'' with h1
    injection h1 with _ h2
    rw [h2]
    exact hw''

/-- Tracking extends along reachability, provided the endpoint's language is nonempty. -/
theorem track_reaches {aut : GAut S A T} {V : T → Atom → Bool} {s t : S}
    (h : AutReaches V aut s t) :
    ∀ d : Exp A T, den V d = autLang V aut s →
      (∃ a w, autRun V aut t a w) →
      ∃ d', GkatDeriv.Reaches V d d' ∧ den V d' = autLang V aut t := by
  induction h with
  | refl => intro d hd _; exact ⟨d, GkatDeriv.Reaches.refl d, hd⟩
  | tail hr hstep ih =>
      intro d hd hne
      obtain ⟨a, q0, hq⟩ := hstep
      have hnem : ∃ a w, autRun V aut _ a w :=
        lang_nonempty_of_reaches (AutReaches.tail (AutReaches.refl _) ⟨a, q0, hq⟩) hne
      obtain ⟨dm, hdm_reach, hdm⟩ := ih d hd hnem
      obtain ⟨d', hnext, hd'⟩ := step_track hdm hq hne
      exact ⟨d', GkatDeriv.Reaches.tail hdm_reach ⟨a, q0, hnext⟩, hd'⟩

/-- Tracking along one-or-more-step reachability. -/
theorem track_reach1 {aut : GAut S A T} {V : T → Atom → Bool} {s t : S}
    (h : AutReaches1 V aut s t)
    (d : Exp A T) (hd : den V d = autLang V aut s)
    (hne : ∃ a w, autRun V aut t a w) :
    ∃ d', GkatDeriv.Reaches1 V d d' ∧ den V d' = autLang V aut t := by
  obtain ⟨m, hstep, hreach⟩ := h
  obtain ⟨a, q0, hq⟩ := hstep
  have hnem : ∃ a w, autRun V aut m a w := lang_nonempty_of_reaches hreach hne
  obtain ⟨dm, hnext, hdm⟩ := step_track hd hq hnem
  obtain ⟨d', hdr, hd'⟩ := track_reaches hreach dm hdm hne
  exact ⟨d', ⟨dm, ⟨a, q0, hnext⟩, hdr⟩, hd'⟩

/-- `Reaches1` on expressions composes. -/
theorem dReaches1_trans {V : T → Atom → Bool} {a b c : Exp A T}
    (h1 : GkatDeriv.Reaches1 V a b) (h2 : GkatDeriv.Reaches1 V b c) :
    GkatDeriv.Reaches1 V a c := by
  obtain ⟨x, hs, hr⟩ := h1
  obtain ⟨y, hs2, hr2⟩ := h2
  exact ⟨x, hs, GkatDeriv.Reaches.trans V hr (GkatDeriv.Reaches.head V hs2 hr2)⟩

/-- **Semantic solvability implies the nesting coequation.** -/
theorem Nested_of_semSolves {aut : GAut S A T} {V : T → Atom → Bool}
    {sol : S → Exp A T} (hwf : WF V aut) (hsol : SemSolves V aut sol) :
    Nested V aut := by
  intro s1 s2 hmem h12 h21 hcomp
  have hreach12 : AutReaches V aut s1 s2 := by
    obtain ⟨m, hst, hre⟩ := h12
    exact AutReaches.head hst hre
  have hreach21 : AutReaches V aut s2 s1 := by
    obtain ⟨m, hst, hre⟩ := h21
    exact AutReaches.head hst hre
  obtain ⟨m0, hstep0, -⟩ := id h12
  obtain ⟨a0, q0, hq0⟩ := hstep0
  have hne : (∃ a w, autRun V aut s1 a w) ∧ (∃ a w, autRun V aut s2 a w) := by
    cases hb : bval V (aut.hlt s1) a0 with
    | true =>
        have h1 : ∃ a w, autRun V aut s1 a w := ⟨a0, [], hb⟩
        exact ⟨h1, lang_nonempty_of_reaches hreach21 h1⟩
    | false =>
        have hb2 : bval V (aut.hlt s2) a0 = true := by rw [hcomp a0, hb]; rfl
        have h2 : ∃ a w, autRun V aut s2 a w := ⟨a0, [], hb2⟩
        exact ⟨lang_nonempty_of_reaches hreach12 h2, h2⟩
  have hL1 : den V (sol s1) = autLang V aut s1 := (sem_solves_autLang hwf hsol s1 hmem).symm
  have step : ∀ d : Exp A T, den V d = autLang V aut s1 →
      ∃ p : Exp A T × Exp A T,
        den V p.1 = autLang V aut s2 ∧ den V p.2 = autLang V aut s1 ∧
        GkatDeriv.Reaches1 V d p.1 ∧ GkatDeriv.Reaches1 V p.1 p.2 := by
    intro d hd
    obtain ⟨dm, hr1, hdm⟩ := track_reach1 h12 d hd hne.2
    obtain ⟨d', hr2, hd'⟩ := track_reach1 h21 dm hdm hne.1
    exact ⟨(dm, d'), hdm, hd', hr1, hr2⟩
  let F : Exp A T → Exp A T × Exp A T := fun d =>
    if h : den V d = autLang V aut s1 then Classical.choose (step d h) else (d, d)
  let f : Nat → Exp A T := fun n => Nat.rec (sol s1) (fun _ prev => (F prev).2) n
  let mid : Nat → Exp A T := fun n => (F (f n)).1
  have key : ∀ n, den V (f n) = autLang V aut s1 →
      den V (mid n) = autLang V aut s2 ∧ den V (f (n + 1)) = autLang V aut s1 ∧
        GkatDeriv.Reaches1 V (f n) (mid n) ∧ GkatDeriv.Reaches1 V (mid n) (f (n + 1)) := by
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
  have hq1n : ∀ n, den V (f n) = autLang V aut s1 := by
    intro n
    induction n with
    | zero => exact hL1
    | succ m ihm => exact (key m ihm).2.1
  have hprop := fun n => key n (hq1n n)
  have hmemd : ∀ n, f n ∈ GkatDeriv.derivs (sol s1) := by
    intro n
    induction n with
    | zero => exact GkatDeriv.mem_self (sol s1)
    | succ k ihk =>
        obtain ⟨x1, hs1', hr1'⟩ := (hprop k).2.2.1
        obtain ⟨x2, hs2', hr2'⟩ := (hprop k).2.2.2
        exact GkatDeriv.reaches_mem_derivs V
          (GkatDeriv.reaches_mem_derivs V ihk (GkatDeriv.Reaches.head V hs1' hr1'))
          (GkatDeriv.Reaches.head V hs2' hr2')
  obtain ⟨i, j, hij, hfij⟩ :=
    exists_repeat (GkatDeriv.derivs (sol s1)) f (fun i _ => hmemd i)
  have hchain : ∀ n m', n < m' → GkatDeriv.Reaches1 V (f n) (f m') := by
    intro n m'
    induction m' with
    | zero => intro h; exact absurd h (Nat.not_lt_zero n)
    | succ m' ihm =>
        intro h
        have hstep1 : GkatDeriv.Reaches1 V (f m') (f (m' + 1)) :=
          dReaches1_trans (hprop m').2.2.1 (hprop m').2.2.2
        rcases Nat.lt_or_eq_of_le (Nat.le_of_lt_succ h) with h' | h'
        · exact dReaches1_trans (ihm h') hstep1
        · subst h'; exact hstep1
  have hAB : GkatDeriv.Reaches1 V (f i) (mid i) := (hprop i).2.2.1
  have hBA : GkatDeriv.Reaches1 V (mid i) (f i) := by
    rcases Nat.lt_or_eq_of_le (Nat.succ_le_of_lt hij) with h' | h'
    · have hj : GkatDeriv.Reaches1 V (mid i) (f j) :=
        dReaches1_trans (hprop i).2.2.2 (hchain (i + 1) j h')
      exact hfij.symm ▸ hj
    · have h'' : i + 1 = j := h'
      have heq : f i = f (i + 1) := by rw [h'']; exact hfij
      exact heq.symm ▸ (hprop i).2.2.2
  refine Nested_derivAut V (sol s1) (f i) (mid i) (hmemd i)
    ((autReaches1_iff_reaches1 V (sol s1) (f i) (mid i)).mpr hAB)
    ((autReaches1_iff_reaches1 V (sol s1) (mid i) (f i)).mpr hBA)
    (fun a => ?_)
  show bval V (E (mid i)) a = ! bval V (E (f i)) a
  rw [bval_E_eq_hlt (hprop i).1 a, bval_E_eq_hlt (hq1n i) a]
  exact hcomp a

#print axioms Nested_of_semSolves

/-- **Provable solvability implies the nesting coequation.**  The `SolvesBA` corollary, via
    soundness of the axioms: this is the exact statement every sound-procedure control in the
    measurement harness relies on, in its contrapositive — a non-nested automaton has no
    provable solution. -/
theorem Nested_of_solvesBA {aut : GAut S A T} {V : T → Atom → Bool}
    {sol : S → Exp A T} (hwf : WF V aut) (hsol : SolvesBA aut sol) :
    Nested V aut :=
  Nested_of_semSolves hwf (solvesBA_semSolves (V := V) hsol)

#print axioms Nested_of_solvesBA

end GkatSolvableNested
