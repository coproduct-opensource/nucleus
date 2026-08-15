import GkatInexpressibilityProofs
import GkatBehaviorProofs

/-!
# The GKAT automaton carrier and the derivative automaton (Kleene synthesis, Phase 1)

Toward the completeness direction `W ⊆ {⟦e⟧}` of Prop 6.2 (Schmid–Kappé–Kozen–Silva,
ICALP 2021). The soundness half `{⟦e⟧} ⊆ W` is `GkatCoequation.den_mem_W`; the converse
is the **Kleene / completeness** direction. Two proven obstructions (`W_not_subset_den`,
`halt_not_bexp_not_den`) show it fails over a raw `GS → Prop` language and must be stated
over the **covariety of deterministic, `BExp`-guarded automata** — a **GKAT automaton**,
a coalgebra for `G X = (2 + A×X)^At`, deterministic and finitely `BExp`-presented.

This file (Phase 1) builds that carrier and proves the derivative automaton is one:

* **`GAut`** — a finite, `BExp`-guarded automaton: `states`, a halt guard `hlt`, a list of
  guarded transitions `trans` per state, and a `start`. Its language interpreter `autLang`
  runs a guarded string, taking at each atom the first matching guarded transition.
* **`transG`** — the guarded-transition list read off an expression's structure, and
  **`firstMatch_transG : firstMatch V a (transG e) = next V e a`**: the guarded list *is*
  the Brzozowski derivative. So the derivative automaton **`derivAut e`** is a `GAut` and
  **`autLang_derivAut : autLang V (derivAut e) e = den V e`** — its language is `⟦e⟧`.
* **`WF`** — well-formedness (halting excludes stepping; every target is a state).
  **`derivAut e` is `WF`** (`next_halt_exclusive` + `derivs_closed`).
* **`Nested`** — the automaton-level nesting coequation: no two mutually-reachable states
  have complementary halt-guards (the finite kernel of Lemma D.2 that excludes Fig 3).
  **`derivAut e` is `Nested`** (the automaton analogue of `den_mem_W`, from
  `no_mutreach_complementary`), and the **Fig 3 automaton is *not* `Nested`** — so the
  covariety genuinely excludes the machine-checked inexpressible witness.

All axioms `[propext, Quot.sound]` (or `+ Classical.choice`), `sorryAx`-free.
-/

namespace GkatKleene

open GkatSyntax GkatGS GkatDeriv GkatBehavior

variable {S A T Atom : Type}

/-- A finite, `BExp`-guarded GKAT automaton — the concrete coalgebra for
    `G X = (2 + A×X)^At`. `hlt s` is the halt guard (the `2` output at state `s`),
    `trans s` the list of guarded transitions `(guard, action, target)` (the `A×X`
    output), `start` the initial state. Finiteness lives in `states` and the guard
    lists; no `Fintype Atom` is needed. -/
structure GAut (S A T : Type) where
  states : List S
  hlt    : S → BExp T
  trans  : S → List (BExp T × A × S)
  start  : S

/-- The first guarded transition whose guard holds at atom `a` — the deterministic
    one-step move a state makes when reading `a`. -/
def firstMatch (V : T → Atom → Bool) (a : Atom) :
    List (BExp T × A × S) → Option (A × S)
  | []                => none
  | (g, q, s') :: rest => if bval V g a then some (q, s') else firstMatch V a rest

/-- The automaton's one-step transition at state `s`, atom `a`. -/
def autStep (V : T → Atom → Bool) (aut : GAut S A T) (s : S) (a : Atom) : Option (A × S) :=
  firstMatch V a (aut.trans s)

/-- Run a guarded string from state `s`: accept the empty string at a halt-guard atom,
    else step (matching the demanded action) and continue. -/
def autRun (V : T → Atom → Bool) (aut : GAut S A T) : S → Atom → List (A × Atom) → Prop
  | s, a, []            => bval V (aut.hlt s) a = true
  | s, a, (q, a') :: w  => ∃ s', autStep V aut s a = some (q, s') ∧ autRun V aut s' a' w

/-- The **language** of a `GAut` from state `s` — the guarded strings it accepts. The
    automaton analogue of `den`. -/
def autLang (V : T → Atom → Bool) (aut : GAut S A T) (s : S) (gs : GS A Atom) : Prop :=
  autRun V aut s gs.1 gs.2

-- ── `firstMatch` combinator lemmas (for the `transG` correctness induction) ───────

/-- `firstMatch` over an append: if the first list has no match, fall through. -/
theorem firstMatch_append_none (V : T → Atom → Bool) (a : Atom)
    (L1 L2 : List (BExp T × A × S)) (h : firstMatch V a L1 = none) :
    firstMatch V a (L1 ++ L2) = firstMatch V a L2 := by
  induction L1 with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      rw [List.cons_append]
      simp only [firstMatch] at h ⊢
      by_cases hg : bval V g a
      · rw [if_pos hg] at h; exact absurd h (by simp)
      · rw [if_neg hg] at h ⊢; exact ih h

/-- `firstMatch` over an append: a match in the first list is the overall match. -/
theorem firstMatch_append_some (V : T → Atom → Bool) (a : Atom)
    (L1 L2 : List (BExp T × A × S)) {x : A × S} (h : firstMatch V a L1 = some x) :
    firstMatch V a (L1 ++ L2) = some x := by
  induction L1 with
  | nil => simp [firstMatch] at h
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      rw [List.cons_append]
      simp only [firstMatch] at h ⊢
      by_cases hg : bval V g a
      · rw [if_pos hg] at h ⊢; exact h
      · rw [if_neg hg] at h ⊢; exact ih h

/-- `firstMatch` over a guard-conjoined list: the whole list is gated by `P`. -/
theorem firstMatch_map_guard (V : T → Atom → Bool) (a : Atom) (P : BExp T)
    (L : List (BExp T × A × S)) :
    firstMatch V a (L.map (fun t => (BExp.and P t.1, t.2))) =
      if bval V P a then firstMatch V a L else none := by
  induction L with
  | nil => simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval V (BExp.and P g) a = (bval V P a && bval V g a) := rfl
      rw [hand, ih]
      by_cases hP : bval V P a <;> simp [hP]

/-- `firstMatch` over a target-remapped list: matches are relabeled by `F`. -/
theorem firstMatch_map_target (V : T → Atom → Bool) (a : Atom) (F : S → S)
    (L : List (BExp T × A × S)) :
    firstMatch V a (L.map (fun t => (t.1, t.2.1, F t.2.2))) =
      (firstMatch V a L).map (fun x => (x.1, F x.2)) := by
  induction L with
  | nil => simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      simp only [List.map_cons, firstMatch]
      by_cases hg : bval V g a <;> simp [hg, ih]

/-- `firstMatch` over a list both guard-conjoined by `P` and target-remapped by `F`. -/
theorem firstMatch_map_guard_target (V : T → Atom → Bool) (a : Atom) (P : BExp T)
    (F : S → S) (L : List (BExp T × A × S)) :
    firstMatch V a (L.map (fun t => (BExp.and P t.1, t.2.1, F t.2.2))) =
      if bval V P a then (firstMatch V a L).map (fun x => (x.1, F x.2)) else none := by
  induction L with
  | nil => simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval V (BExp.and P g) a = (bval V P a && bval V g a) := rfl
      rw [hand, ih]
      by_cases hP : bval V P a <;> by_cases hg : bval V g a <;> simp [hP, hg]

-- ── `transG`: the guarded-transition list read off an expression ──────────────────

/-- The **no-step guard** of a transition list: the atoms at which *no* guarded
    transition fires (the conjunction of all negated guards). -/
def noStepG : List (BExp T × A × S) → BExp T
  | []                => .one
  | (g, _, _) :: rest => .and (.not g) (noStepG rest)

/-- `noStepG` characterizes exactly the atoms where `firstMatch` finds nothing. -/
theorem noStepG_iff (V : T → Atom → Bool) (a : Atom) (L : List (BExp T × A × S)) :
    bval V (noStepG L) a = true ↔ firstMatch V a L = none := by
  induction L with
  | nil => simp [noStepG, firstMatch, bval]
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      simp only [noStepG, firstMatch, bval]
      by_cases hg : bval V g a <;> simp [hg, ih]

/-- The **guarded-transition list of an expression**, read off the structure of `next`.
    Each constructor's transitions carry the syntactic `BExp` guard on which they fire:
    `act` steps always; `ite` splits on `b`/`¬b`; `wh` gates by `b` and tails the loop;
    `seq` keeps `e`'s steps, then falls through to `f` on the atoms where `e` neither steps
    (`noStepG (transG e)`) nor is forced to (it may halt, `E e`). -/
def transG : Exp A T → List (BExp T × A × Exp A T)
  | .act p     => [(.one, p, .test .one)]
  | .test _    => []
  | .seq e f   => (transG e).map (fun t => (t.1, t.2.1, Exp.seq t.2.2 f)) ++
                  (transG f).map (fun t => (BExp.and (BExp.and (noStepG (transG e)) (E e)) t.1, t.2))
  | .ite b e f => (transG e).map (fun t => (BExp.and b t.1, t.2)) ++
                  (transG f).map (fun t => (BExp.and (BExp.not b) t.1, t.2))
  | .wh b e    => (transG e).map (fun t => (BExp.and b t.1, t.2.1, Exp.seq t.2.2 (.wh b e)))

/-- **The guarded list is the Brzozowski derivative.** `firstMatch` over `transG e` at
    atom `a` returns exactly `next V e a` — so the syntactic guarded automaton and the
    coalgebraic derivative agree at every atom. Structural induction on `e`; the `seq`
    fall-through is handled by `noStepG`. -/
theorem firstMatch_transG (V : T → Atom → Bool) (e : Exp A T) (a : Atom) :
    firstMatch V a (transG e) = next V e a := by
  induction e generalizing a with
  | act p => simp [transG, firstMatch, next, bval]
  | test t => simp [transG, firstMatch, next]
  | ite b e f ihe ihf =>
      rw [transG]
      have hAe : firstMatch V a ((transG e).map (fun t => (BExp.and b t.1, t.2)))
               = if bval V b a then next V e a else none := by
        rw [firstMatch_map_guard, ihe]
      have hBf : firstMatch V a ((transG f).map (fun t => (BExp.and (BExp.not b) t.1, t.2)))
               = if bval V (BExp.not b) a then next V f a else none := by
        rw [firstMatch_map_guard, ihf]
      cases hA : firstMatch V a ((transG e).map (fun t => (BExp.and b t.1, t.2))) with
      | some x =>
          rw [firstMatch_append_some V a _ _ hA, hAe] at *
          by_cases hb : bval V b a
          · rw [if_pos hb] at hA; simp only [next]; rw [if_pos hb]; exact hA.symm
          · rw [if_neg hb] at hA; exact absurd hA (by simp)
      | none =>
          rw [firstMatch_append_none V a _ _ hA, hBf]
          rw [hAe] at hA
          by_cases hb : bval V b a
          · rw [if_pos hb] at hA
            simp only [next]; rw [if_pos hb, hA]; simp [bval, hb]
          · simp only [next]; rw [if_neg hb]; simp [bval, hb]
  | seq e f ihe ihf =>
      rw [transG]
      have hA : firstMatch V a ((transG e).map (fun t => (t.1, t.2.1, Exp.seq t.2.2 f)))
              = (firstMatch V a (transG e)).map (fun x => (x.1, Exp.seq x.2 f)) :=
        firstMatch_map_target V a (fun e' => Exp.seq e' f) (transG e)
      have hB : firstMatch V a ((transG f).map
                  (fun t => (BExp.and (BExp.and (noStepG (transG e)) (E e)) t.1, t.2)))
              = if bval V (BExp.and (noStepG (transG e)) (E e)) a
                  then firstMatch V a (transG f) else none :=
        firstMatch_map_guard V a (BExp.and (noStepG (transG e)) (E e)) (transG f)
      cases hfa : firstMatch V a ((transG e).map (fun t => (t.1, t.2.1, Exp.seq t.2.2 f))) with
      | some x =>
          rw [firstMatch_append_some V a _ _ hfa]
          rw [hA, ihe] at hfa
          cases hne : next V e a with
          | none => rw [hne] at hfa; simp at hfa
          | some y =>
              obtain ⟨p, e'⟩ := y
              rw [hne] at hfa; simp only [Option.map_some] at hfa
              simp only [next, hne]; exact hfa.symm
      | none =>
          rw [firstMatch_append_none V a _ _ hfa, hB, ihf]
          rw [hA, ihe] at hfa
          have hne : next V e a = none := by
            cases h : next V e a with
            | none => rfl
            | some y => rw [h] at hfa; simp at hfa
          have hns : bval V (noStepG (transG e)) a = true :=
            (noStepG_iff V a (transG e)).mpr (by rw [ihe]; exact hne)
          simp only [next, hne]
          rw [show bval V (BExp.and (noStepG (transG e)) (E e)) a = bval V (E e) a by
                simp [bval, hns]]
  | wh b e ihe =>
      rw [transG]
      have hW : firstMatch V a ((transG e).map
                  (fun t => (BExp.and b t.1, t.2.1, Exp.seq t.2.2 (Exp.wh b e))))
              = if bval V b a
                  then (firstMatch V a (transG e)).map (fun x => (x.1, Exp.seq x.2 (Exp.wh b e)))
                  else none :=
        firstMatch_map_guard_target V a b (fun e' => Exp.seq e' (Exp.wh b e)) (transG e)
      rw [hW, ihe]
      by_cases hb : bval V b a
      · rw [if_pos hb]; simp only [next]; rw [if_pos hb]
        cases next V e a with
        | none => rfl
        | some x => obtain ⟨p, e'⟩ := x; rfl
      · rw [if_neg hb]; simp only [next]; rw [if_neg hb]

-- ── The derivative automaton and its language ─────────────────────────────────────

/-- **The derivative automaton of `e`.** States are `e`'s finitely many derivatives; the
    halt guard is `E`, the guarded transitions are `transG`, and the start is `e`. This is
    the coalgebra `⟨E, next⟩` presented as a finite `BExp`-guarded `GAut`. -/
def derivAut (e : Exp A T) : GAut (Exp A T) A T where
  states := derivs e
  hlt    := E
  trans  := transG
  start  := e

/-- The derivative automaton steps exactly by `next`. -/
theorem autStep_derivAut (V : T → Atom → Bool) (e s : Exp A T) (a : Atom) :
    autStep V (derivAut e) s a = next V s a :=
  firstMatch_transG V s a

/-- **The derivative automaton's run agrees with `den` at every state.** By list induction,
    using `den_nil`/`den_cons` and `autStep_derivAut`. -/
theorem autRun_eq_den (V : T → Atom → Bool) (e s : Exp A T)
    (a : Atom) (w : List (A × Atom)) :
    autRun V (derivAut e) s a w ↔ den V s (a, w) := by
  induction w generalizing s a with
  | nil => exact (den_nil V s a).symm
  | cons hd w ihw =>
      obtain ⟨q, a'⟩ := hd
      simp only [autRun]
      rw [den_cons]
      constructor
      · rintro ⟨s', hst, hr⟩
        exact ⟨s', (autStep_derivAut V e s a) ▸ hst, (ihw s' a').mp hr⟩
      · rintro ⟨s', hst, hd⟩
        refine ⟨s', ?_, (ihw s' a').mpr hd⟩
        rw [autStep_derivAut]; exact hst

/-- **`autLang (derivAut e) e = ⟦e⟧`.** The derivative automaton's language is exactly the
    denotation of `e` — so `⟦e⟧` is realized by a finite `BExp`-guarded automaton. -/
theorem autLang_derivAut (V : T → Atom → Bool) (e : Exp A T) :
    autLang V (derivAut e) e = den V e := by
  funext gs
  obtain ⟨a, w⟩ := gs
  exact propext (autRun_eq_den V e e a w)

-- ── Well-formedness: determinism (halt excludes step) + closure ───────────────────

/-- **Well-formedness.** At each reachable state, halting excludes stepping (the `2`-output
    and the `A×X`-output are mutually exclusive — one-step determinism), and every
    transition target is again a state (closure). -/
def WF (V : T → Atom → Bool) (aut : GAut S A T) : Prop :=
  (∀ s ∈ aut.states, ∀ a, bval V (aut.hlt s) a = true → autStep V aut s a = none) ∧
  (∀ s ∈ aut.states, ∀ a q s', autStep V aut s a = some (q, s') → s' ∈ aut.states)

/-- **The derivative automaton is well-formed.** Halt-excludes-step is
    `next_halt_exclusive`; closure is `derivs_closed`. -/
theorem WF_derivAut (V : T → Atom → Bool) (e : Exp A T) : WF V (derivAut e) := by
  constructor
  · intro s hs a hhalt
    have hh : bval V (E s) a = true := hhalt
    rw [autStep_derivAut]
    cases hn : next V s a with
    | none => rfl
    | some x =>
        exfalso; rw [next_halt_exclusive V s a x hn] at hh; exact absurd hh (by simp)
  · intro s hs a q s' hst
    rw [autStep_derivAut] at hst
    exact derivs_closed e hs hst

-- ── Automaton reachability and the nesting coequation `Nested` ─────────────────────

/-- One-step reachability in a `GAut`: `s` steps to `s'` on some atom via some action. -/
def AutStep1 (V : T → Atom → Bool) (aut : GAut S A T) (s s' : S) : Prop :=
  ∃ (a : Atom) (q : A), autStep V aut s a = some (q, s')

/-- Reachability — the reflexive-transitive closure of `AutStep1`. -/
inductive AutReaches (V : T → Atom → Bool) (aut : GAut S A T) : S → S → Prop where
  | refl (s) : AutReaches V aut s s
  | tail {s s' s''} : AutReaches V aut s s' → AutStep1 V aut s' s'' → AutReaches V aut s s''

/-- `≥1`-step reachability (a genuine cycle when `AutReaches1 s s`). -/
def AutReaches1 (V : T → Atom → Bool) (aut : GAut S A T) (s s' : S) : Prop :=
  ∃ x, AutStep1 V aut s x ∧ AutReaches V aut x s'

/-- **The nesting coequation, at the automaton level.** No two mutually-reachable states
    have *complementary* halt-guards. This is the finite kernel of Lemma D.2 — the
    condition that excludes the Fig 3 `b/b̄`-alternating 2-cycle — lifted to an arbitrary
    `GAut`. The behavioral coequation `W` cuts out exactly the automata satisfying it. -/
def Nested (V : T → Atom → Bool) (aut : GAut S A T) : Prop :=
  ∀ s1 s2, s1 ∈ aut.states →
    AutReaches1 V aut s1 s2 → AutReaches1 V aut s2 s1 →
    ¬ (∀ a, bval V (aut.hlt s2) a = ! bval V (aut.hlt s1) a)

-- Bridges: on `derivAut e`, automaton reachability *is* derivative reachability.

theorem autStep1_iff_step (V : T → Atom → Bool) (e s s' : Exp A T) :
    AutStep1 V (derivAut e) s s' ↔ Step V s s' := by
  simp only [AutStep1, Step, autStep_derivAut]

theorem autReaches_iff_reaches (V : T → Atom → Bool) (e s s' : Exp A T) :
    AutReaches V (derivAut e) s s' ↔ Reaches V s s' := by
  constructor
  · intro h
    induction h with
    | refl => exact Reaches.refl _
    | tail _ hstep ih => exact Reaches.tail ih ((autStep1_iff_step V e _ _).mp hstep)
  · intro h
    induction h with
    | refl => exact AutReaches.refl _
    | tail _ hstep ih => exact AutReaches.tail ih ((autStep1_iff_step V e _ _).mpr hstep)

theorem autReaches1_iff_reaches1 (V : T → Atom → Bool) (e s s' : Exp A T) :
    AutReaches1 V (derivAut e) s s' ↔ Reaches1 V s s' := by
  simp only [AutReaches1, Reaches1]
  constructor
  · rintro ⟨x, h1, h2⟩
    exact ⟨x, (autStep1_iff_step V e s x).mp h1, (autReaches_iff_reaches V e x s').mp h2⟩
  · rintro ⟨x, h1, h2⟩
    exact ⟨x, (autStep1_iff_step V e s x).mpr h1, (autReaches_iff_reaches V e x s').mpr h2⟩

/-- **The derivative automaton is `Nested`** — the automaton analogue of `den_mem_W`. Every
    expression's automaton satisfies the nesting coequation: no `b/b̄`-alternating 2-cycle,
    because none exists in a GKAT behavior (`no_mutreach_complementary`). -/
theorem Nested_derivAut (V : T → Atom → Bool) (e : Exp A T) : Nested V (derivAut e) := by
  intro s1 s2 hs1 h12 h21 hcomp
  exact no_mutreach_complementary V hs1
    ((autReaches1_iff_reaches1 V e s1 s2).mp h12)
    ((autReaches1_iff_reaches1 V e s2 s1).mp h21)
    hcomp

-- ── Non-vacuity: the Figure 3 automaton is rejected by `Nested` ────────────────────

/-- **The Figure 3 automaton.** `v0` (`false`) halts on `¬b` and steps to `v1` on every
    `b`-atom via `p`; `v1` (`true`) halts on `b` and steps to `v0` on every `¬b`-atom via
    `q`. The `b/b̄`-alternating 2-cycle whose behavior no expression denotes
    (`fig3_inexpressible`). -/
def fig3Aut (b : BExp T) (p q : A) : GAut Bool A T where
  states := [false, true]
  hlt    := fun s => cond s b (BExp.not b)
  trans  := fun s => cond s [(BExp.not b, q, false)] [(b, p, true)]
  start  := false

/-- **`Nested` genuinely excludes the machine-checked inexpressible witness.** Whenever `b`
    and `¬b` are both satisfiable, the Figure 3 automaton violates the nesting coequation:
    its two states are mutually reachable and have complementary halt-guards. So the
    covariety cut out by `Nested` really does exclude Fig 3 — the non-vacuity guard that
    ties `Nested` back to `fig3_inexpressible`. -/
theorem fig3_not_nested (V : T → Atom → Bool) (b : BExp T) (p q : A) (ab anb : Atom)
    (hab : bval V b ab = true) (hanb : bval V b anb = false) :
    ¬ Nested V (fig3Aut b p q) := by
  intro hN
  have hmem : (false : Bool) ∈ (fig3Aut b p q).states := by simp [fig3Aut]
  have h12 : AutReaches1 V (fig3Aut b p q) false true :=
    ⟨true, ⟨ab, p, by simp [autStep, fig3Aut, firstMatch, hab]⟩, AutReaches.refl true⟩
  have h21 : AutReaches1 V (fig3Aut b p q) true false :=
    ⟨false, ⟨anb, q, by simp [autStep, fig3Aut, firstMatch, bval, hanb]⟩, AutReaches.refl false⟩
  have hcomp : ∀ a, bval V ((fig3Aut b p q).hlt true) a = ! bval V ((fig3Aut b p q).hlt false) a := by
    intro a; simp [fig3Aut, bval]
  exact hN false true hmem h12 h21 hcomp

#print axioms firstMatch_transG
#print axioms autLang_derivAut
#print axioms WF_derivAut
#print axioms Nested_derivAut
#print axioms fig3_not_nested

end GkatKleene
