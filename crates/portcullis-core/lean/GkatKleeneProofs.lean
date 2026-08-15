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

/-- Reachability is transitive. -/
theorem AutReaches.trans {V : T → Atom → Bool} {aut : GAut S A T} {s s' s'' : S}
    (h1 : AutReaches V aut s s') (h2 : AutReaches V aut s' s'') : AutReaches V aut s s'' := by
  induction h2 with
  | refl => exact h1
  | tail _ hstep ih => exact AutReaches.tail ih hstep

/-- Reachability is transitive on the left through a step. -/
theorem AutReaches.head {V : T → Atom → Bool} {aut : GAut S A T} {s s' s'' : S}
    (hstep : AutStep1 V aut s s') (h : AutReaches V aut s' s'') : AutReaches V aut s s'' :=
  AutReaches.trans (AutReaches.tail (AutReaches.refl s) hstep) h

-- ── SCC decomposition: mutual reachability and the condensation order ──────────────

/-- **Same strongly-connected component.** Two states are mutually reachable — they lie on a
    common cycle (or are equal). This is the equivalence relation whose classes are the SCCs;
    a nontrivial class (with `AutReaches1 s s`) is a loop, and the SCC quotient is the DAG the
    synthesis recurses over. -/
def AutMutReach (V : T → Atom → Bool) (aut : GAut S A T) (s s' : S) : Prop :=
  AutReaches V aut s s' ∧ AutReaches V aut s' s

theorem AutMutReach.refl {V : T → Atom → Bool} {aut : GAut S A T} (s : S) :
    AutMutReach V aut s s := ⟨AutReaches.refl s, AutReaches.refl s⟩

theorem AutMutReach.symm {V : T → Atom → Bool} {aut : GAut S A T} {s s' : S}
    (h : AutMutReach V aut s s') : AutMutReach V aut s' s := ⟨h.2, h.1⟩

theorem AutMutReach.trans {V : T → Atom → Bool} {aut : GAut S A T} {s s' s'' : S}
    (h1 : AutMutReach V aut s s') (h2 : AutMutReach V aut s' s'') : AutMutReach V aut s s'' :=
  ⟨AutReaches.trans h1.1 h2.1, AutReaches.trans h2.2 h1.2⟩

/-- **The strict SCC order.** `s'` is *downstream* of `s` — reachable from it but not back.
    This is the strict order on the condensation DAG; the synthesis eliminates SCCs from the
    bottom of this order, and its irreflexivity (a state is never strictly below itself) is
    what makes the elimination recursion well-founded. -/
def AutBelow (V : T → Atom → Bool) (aut : GAut S A T) (s' s : S) : Prop :=
  AutReaches V aut s s' ∧ ¬ AutReaches V aut s' s

/-- The SCC order is irreflexive: no state is strictly downstream of itself. -/
theorem AutBelow.irrefl {V : T → Atom → Bool} {aut : GAut S A T} (s : S) :
    ¬ AutBelow V aut s s := fun h => h.2 (AutReaches.refl s)

/-- The SCC order is transitive. -/
theorem AutBelow.trans {V : T → Atom → Bool} {aut : GAut S A T} {s s' s'' : S}
    (h1 : AutBelow V aut s' s) (h2 : AutBelow V aut s'' s') : AutBelow V aut s'' s :=
  ⟨AutReaches.trans h1.1 h2.1, fun hb => h2.2 (AutReaches.trans hb h1.1)⟩

/-- **`AutBelow` respects SCCs**: mutually-reachable states are downstream of exactly the
    same states — so the strict order descends to the condensation (SCC quotient). -/
theorem AutBelow.congr_left {V : T → Atom → Bool} {aut : GAut S A T} {s s' t : S}
    (h : AutMutReach V aut s s') (hb : AutBelow V aut t s) : AutBelow V aut t s' :=
  ⟨AutReaches.trans h.2 hb.1, fun hr => hb.2 (AutReaches.trans hr h.2)⟩

/-- **Monotone `filter` length** (Mathlib-free): a pointwise-weaker predicate keeps no more
    elements. -/
theorem filter_len_le {α : Type} (l : List α) (p q : α → Bool)
    (hmono : ∀ a ∈ l, p a = true → q a = true) :
    (l.filter p).length ≤ (l.filter q).length := by
  induction l with
  | nil => simp
  | cons a t ih =>
      have iht := ih (fun a' ha' h => hmono a' (List.mem_cons_of_mem a ha') h)
      by_cases hp : p a = true
      · have hq : q a = true := hmono a List.mem_cons_self hp
        simp [hp, hq]; omega
      · by_cases hq : q a = true
        · simp [hp, hq]; omega
        · simp only [List.filter_cons, hp, hq]; exact iht

/-- **Strict `filter` length** (Mathlib-free): if additionally some element of `l` is kept by
    `q` but not `p`, strictly fewer are kept by `p`. -/
theorem filter_len_lt {α : Type} (l : List α) (p q : α → Bool)
    (hmono : ∀ a ∈ l, p a = true → q a = true)
    (x : α) (hx : x ∈ l) (hqx : q x = true) (hpx : p x = false) :
    (l.filter p).length < (l.filter q).length := by
  induction l with
  | nil => exact absurd hx (List.not_mem_nil)
  | cons a t ih =>
      have hmono' : ∀ a' ∈ t, p a' = true → q a' = true :=
        fun a' ha' h => hmono a' (List.mem_cons_of_mem a ha') h
      by_cases hp : p a = true
      · have hq : q a = true := hmono a List.mem_cons_self hp
        have hxt : x ∈ t := by
          rcases List.mem_cons.mp hx with rfl | h
          · rw [hpx] at hp; exact absurd hp (by simp)
          · exact h
        have := ih hmono' hxt
        simp [hp, hq]; omega
      · by_cases hq : q a = true
        · have := filter_len_le t p q hmono'
          simp [hp, hq]; omega
        · have hxt : x ∈ t := by
            rcases List.mem_cons.mp hx with rfl | h
            · rw [hqx] at hq; exact absurd hq (by simp)
            · exact h
          have := ih hmono' hxt
          simp only [List.filter_cons, hp, hq]; exact this

/-- **The termination measure.** The number of states reachable from `s`. Same across an SCC
    (mutually reachable ⇒ same reachable set), and strictly larger than anything strictly
    downstream — so it is the SCC-topological rank the elimination recursion descends. -/
noncomputable def reachCount (V : T → Atom → Bool) (aut : GAut S A T) (s : S) : Nat :=
  (aut.states.filter (fun t => @decide (AutReaches V aut s t) (Classical.propDecidable _))).length

/-- **The measure strictly decreases downstream.** If `s'` is strictly below `s`, fewer states
    are reachable from `s'` — `s` reaches everything `s'` does, plus itself. -/
theorem reachCount_lt_of_below (V : T → Atom → Bool) (aut : GAut S A T) {s s' : S}
    (hs : s ∈ aut.states) (hb : AutBelow V aut s' s) :
    reachCount V aut s' < reachCount V aut s := by
  unfold reachCount
  refine filter_len_lt aut.states _ _ ?_ s hs ?_ ?_
  · intro t _ ht
    simp only [decide_eq_true_eq] at ht ⊢
    exact AutReaches.trans hb.1 ht
  · simp only [decide_eq_true_eq]; exact AutReaches.refl s
  · simp only [decide_eq_false_iff_not]; exact hb.2

/-- **The measure is constant on an SCC.** Mutually-reachable states reach exactly the same
    states, so `reachCount` is well-defined on the condensation — a genuine SCC-rank. -/
theorem reachCount_eq_of_mutReach (V : T → Atom → Bool) (aut : GAut S A T) {s s' : S}
    (h : AutMutReach V aut s s') : reachCount V aut s = reachCount V aut s' := by
  unfold reachCount
  apply Nat.le_antisymm
  · apply filter_len_le; intro t _ ht
    simp only [decide_eq_true_eq] at ht ⊢; exact AutReaches.trans h.2 ht
  · apply filter_len_le; intro t _ ht
    simp only [decide_eq_true_eq] at ht ⊢; exact AutReaches.trans h.1 ht

/-- **Every edge is rank-non-increasing.** A step never raises `reachCount` — its target
    reaches no more than its source. So an edge either stays within an SCC (equal rank) or
    descends to a lower one; there are no back-edges up the condensation. The structural fact
    the elimination order rests on. -/
theorem reachCount_step_le (V : T → Atom → Bool) (aut : GAut S A T) {s s' : S}
    (hstep : AutStep1 V aut s s') : reachCount V aut s' ≤ reachCount V aut s := by
  unfold reachCount
  apply filter_len_le; intro t _ ht
  simp only [decide_eq_true_eq] at ht ⊢
  exact AutReaches.trans (AutReaches.head hstep (AutReaches.refl s')) ht

/-- **Equal `filter` length forces the reverse inclusion** (Mathlib-free): if `p ⊆ q` on `l`
    yet keeps as many, then everything `q` keeps `p` keeps too. -/
theorem filter_mem_of_len_eq {α : Type} (l : List α) (p q : α → Bool)
    (hmono : ∀ a ∈ l, p a = true → q a = true)
    (hlen : (l.filter p).length = (l.filter q).length)
    (x : α) (hx : x ∈ l) (hqx : q x = true) : p x = true := by
  cases hpx : p x with
  | true => rfl
  | false =>
      have hlt := filter_len_lt l p q hmono x hx hqx hpx
      omega

/-- **An edge that does not drop rank stays in the SCC.** If `s` steps to `s'` and they have
    the same `reachCount`, they are mutually reachable — everything `s` reaches, `s'` reaches
    too (equal counts + the forward inclusion), so `s'` reaches `s` back. The converse of
    `reachCount_step_le`'s strictness: rank is constant *only* within an SCC. -/
theorem mutReach_of_step_reachCount_eq (V : T → Atom → Bool) (aut : GAut S A T) {s s' : S}
    (hs : s ∈ aut.states) (hstep : AutStep1 V aut s s')
    (heq : reachCount V aut s = reachCount V aut s') :
    AutMutReach V aut s s' := by
  refine ⟨AutReaches.head hstep (AutReaches.refl s'), ?_⟩
  have hmono : ∀ t ∈ aut.states,
      (fun t => @decide (AutReaches V aut s' t) (Classical.propDecidable _)) t = true →
      (fun t => @decide (AutReaches V aut s t) (Classical.propDecidable _)) t = true := by
    intro t _ ht
    simp only [decide_eq_true_eq] at ht ⊢
    exact AutReaches.trans (AutReaches.head hstep (AutReaches.refl s')) ht
  have hlen : (aut.states.filter
        (fun t => @decide (AutReaches V aut s' t) (Classical.propDecidable _))).length
      = (aut.states.filter
        (fun t => @decide (AutReaches V aut s t) (Classical.propDecidable _))).length :=
    heq.symm
  have hps := filter_mem_of_len_eq aut.states _ _ hmono hlen s hs
    (by simp only [decide_eq_true_eq]; exact AutReaches.refl s)
  simp only [decide_eq_true_eq] at hps
  exact hps

/-- **Cross-SCC edges strictly drop the rank.** If `s` steps to a state `s'` *not* mutually
    reachable with it (a genuine descent in the condensation, not an in-SCC cycle), then
    `reachCount s' < reachCount s`. This is what certifies that the exits of a collapsed SCC
    go to strictly-smaller rank — the `WNAutE` well-formedness the construction needs. -/
theorem reachCount_lt_of_step_not_mutReach (V : T → Atom → Bool) (aut : GAut S A T) {s s' : S}
    (hs : s ∈ aut.states) (hstep : AutStep1 V aut s s')
    (hnm : ¬ AutMutReach V aut s s') :
    reachCount V aut s' < reachCount V aut s := by
  have hle := reachCount_step_le V aut hstep
  rcases Nat.lt_or_ge (reachCount V aut s') (reachCount V aut s) with h | h
  · exact h
  · exact absurd (mutReach_of_step_reachCount_eq V aut hs hstep (Nat.le_antisymm h hle)) hnm

/-- **The condensation is well-founded** — a DAG. The strict SCC order `AutBelow`, on the
    automaton's states, embeds into `Nat.lt` via `reachCount` (`reachCount_lt_of_below`), so it
    is well-founded. This is the termination guarantee for the SCC elimination recursion: one
    cannot descend the condensation forever. -/
theorem autBelow_wf (V : T → Atom → Bool) (aut : GAut S A T) :
    WellFounded (fun s' s : {x // x ∈ aut.states} => AutBelow V aut s'.1 s.1) :=
  Subrelation.wf
    (fun {s' s} h => reachCount_lt_of_below V aut s.2 h)
    (invImage (fun s : {x // x ∈ aut.states} => reachCount V aut s.1) Nat.lt_wfRel).wf

/-- **`firstMatch` returns a firing member.** If the guarded list steps `(q,s')` at `a`, then
    `(g,q,s')` is genuinely in the list with `g` firing at `a` — the transition is real, not an
    artifact of ordering. The bridge for reading a `GAut`'s edges off `firstMatch`. -/
theorem firstMatch_some_mem (V : T → Atom → Bool) (a : Atom) (L : List (BExp T × A × S))
    {q : A} {s' : S} (h : firstMatch V a L = some (q, s')) :
    ∃ g, (g, q, s') ∈ L ∧ bval V g a = true := by
  induction L with
  | nil => simp [firstMatch] at h
  | cons hd tl ih =>
      obtain ⟨g, q0, s0⟩ := hd
      simp only [firstMatch] at h
      by_cases hg : bval V g a
      · rw [if_pos hg, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨g, List.mem_cons_self, hg⟩
      · rw [if_neg hg] at h
        obtain ⟨g', hmem, hg'⟩ := ih h
        exact ⟨g', List.mem_cons_of_mem _ hmem, hg'⟩

/-- **Guards fire disjointly at `a`**: at most one transition of the list is active. The
    determinism condition that makes `firstMatch` order-independent. -/
def GuardsDisjoint (V : T → Atom → Bool) (a : Atom) (L : List (BExp T × A × S)) : Prop :=
  ∀ t1 ∈ L, ∀ t2 ∈ L, bval V t1.1 a = true → bval V t2.1 a = true → t1 = t2

/-- **`firstMatch` is position-independent under determinism.** If a guarded transition fires
    at `a` and the guards are disjoint there, `firstMatch` returns *that* transition wherever it
    sits — so a self-edge may be read (and extracted to a Salomaa loop) regardless of order. -/
theorem firstMatch_eq_of_mem_det (V : T → Atom → Bool) (a : Atom) (L : List (BExp T × A × S))
    (hdisj : GuardsDisjoint V a L) {g : BExp T} {q : A} {s' : S}
    (hmem : (g, q, s') ∈ L) (hg : bval V g a = true) :
    firstMatch V a L = some (q, s') := by
  induction L with
  | nil => simp at hmem
  | cons hd tl ih =>
      obtain ⟨g0, q0, s0⟩ := hd
      simp only [firstMatch]
      by_cases h0 : bval V g0 a
      · rw [if_pos h0]
        have heq := hdisj (g0, q0, s0) List.mem_cons_self (g, q, s') hmem h0 hg
        rw [Prod.mk.injEq, Prod.mk.injEq] at heq
        rw [heq.2.1, heq.2.2]
      · rw [if_neg h0]
        rcases List.mem_cons.mp hmem with heq | htl
        · have hgg : g = g0 := congrArg (·.1) heq
          exact absurd (hgg ▸ hg) h0
        · exact ih (fun t1 h1 t2 h2 => hdisj t1 (List.mem_cons_of_mem _ h1) t2
            (List.mem_cons_of_mem _ h2)) htl

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

-- ── The coinduction principle across the carrier: `GAut` state ↔ expression ────────

/-- **A bisimulation between a `GAut` and the derivative coalgebra of expressions.** `R s e`
    relates an automaton state `s` to an expression `e` when they halt on the same atoms and
    their transitions match step-for-step (same action, related residual/target). The
    automaton analogue of `GkatBisim.Bisim`, connecting the two carriers `S` and `Exp A T`. -/
def GBisim (V : T → Atom → Bool) (aut : GAut S A T) (R : S → Exp A T → Prop) : Prop :=
  ∀ s e, R s e →
    (∀ a, bval V (aut.hlt s) a = bval V (E e) a) ∧
    (∀ a q s', autStep V aut s a = some (q, s') → ∃ e', next V e a = some (q, e') ∧ R s' e') ∧
    (∀ a q e', next V e a = some (q, e') → ∃ s', autStep V aut s a = some (q, s') ∧ R s' e')

/-- **The transfer principle.** A `GBisim` is contained in language equality: if `R s e`
    then the automaton's language from `s` is exactly `⟦e⟧`. This is the tool by which a
    *solved* automaton (one exhibited bisimilar to an expression) becomes an expression —
    the mechanism at the heart of GKAT completeness. Length induction on the guarded string,
    via `autRun`/`den_nil`/`den_cons` (the `GAut` analogue of `bisim_sound`). -/
theorem autLang_eq_of_gbisim {V : T → Atom → Bool} {aut : GAut S A T}
    {R : S → Exp A T → Prop} (hR : GBisim V aut R) {s : S} {e : Exp A T} (hse : R s e) :
    autLang V aut s = den V e := by
  have H : ∀ (l : List (A × Atom)) (s : S) (e : Exp A T) (a : Atom),
      R s e → (autRun V aut s a l ↔ den V e (a, l)) := by
    intro l
    induction l with
    | nil =>
        intro s e a hse
        simp only [autRun, den_nil, (hR s e hse).1 a]
    | cons hd tl ih =>
        intro s e a hse; obtain ⟨q, a'⟩ := hd
        obtain ⟨_, hfwd, hbwd⟩ := hR s e hse
        simp only [autRun]; rw [den_cons]
        constructor
        · rintro ⟨s', hst, hr⟩
          obtain ⟨e', hne, hrel⟩ := hfwd a q s' hst
          exact ⟨e', hne, (ih s' e' a' hrel).mp hr⟩
        · rintro ⟨e', hne, hde'⟩
          obtain ⟨s', hst, hrel⟩ := hbwd a q e' hne
          exact ⟨s', hst, (ih s' e' a' hrel).mpr hde'⟩
  funext gs; obtain ⟨a, w⟩ := gs
  exact propext (H w s e a hse)

/-- **Sanity / non-vacuity of the transfer.** The derivative automaton is `GBisim` to the
    identity relation on expressions — recovering `autLang_derivAut` through the transfer. -/
theorem gbisim_derivAut (V : T → Atom → Bool) (e : Exp A T) :
    GBisim V (derivAut e) (fun s x => s = x) := by
  intro s x hsx; subst hsx
  refine ⟨fun _ => rfl, ?_, ?_⟩
  · intro a q s' h; rw [autStep_derivAut] at h; exact ⟨s', h, rfl⟩
  · intro a q e' h; exact ⟨e', by rw [autStep_derivAut]; exact h, rfl⟩

/-- **A bisimulation between two `GAut`s** (possibly over different carriers): related states
    halt on the same atoms and their transitions match step-for-step. -/
def GAutBisim {S1 S2 : Type} (V : T → Atom → Bool) (aut1 : GAut S1 A T) (aut2 : GAut S2 A T)
    (R : S1 → S2 → Prop) : Prop :=
  ∀ s1 s2, R s1 s2 →
    (∀ a, bval V (aut1.hlt s1) a = bval V (aut2.hlt s2) a) ∧
    (∀ a q s1', autStep V aut1 s1 a = some (q, s1') →
       ∃ s2', autStep V aut2 s2 a = some (q, s2') ∧ R s1' s2') ∧
    (∀ a q s2', autStep V aut2 s2 a = some (q, s2') →
       ∃ s1', autStep V aut1 s1 a = some (q, s1') ∧ R s1' s2')

/-- **Bisimilar automata recognize the same language** (the paper's Lemma 5.2, at the
    concrete `GAut` level): if `R s1 s2` for a `GAutBisim R`, then `autLang aut1 s1 =
    autLang aut2 s2`. Length induction on the guarded string. The tool for reasoning about
    language-preserving automaton transformations (state elimination, the Thompson
    presentation of a covariety behavior) — and it subsumes the expression transfer
    (`autLang_eq_of_gbisim`) by taking `aut2 = derivAut e`. -/
theorem autLang_eq_of_gautBisim {S1 S2 : Type} {V : T → Atom → Bool}
    {aut1 : GAut S1 A T} {aut2 : GAut S2 A T} {R : S1 → S2 → Prop}
    (hR : GAutBisim V aut1 aut2 R) {s1 : S1} {s2 : S2} (h : R s1 s2) :
    autLang V aut1 s1 = autLang V aut2 s2 := by
  have H : ∀ (l : List (A × Atom)) (s1 : S1) (s2 : S2) (a : Atom),
      R s1 s2 → (autRun V aut1 s1 a l ↔ autRun V aut2 s2 a l) := by
    intro l
    induction l with
    | nil =>
        intro s1 s2 a hr
        simp only [autRun, (hR s1 s2 hr).1 a]
    | cons hd tl ih =>
        intro s1 s2 a hr; obtain ⟨q, a'⟩ := hd
        obtain ⟨_, hfwd, hbwd⟩ := hR s1 s2 hr
        simp only [autRun]
        constructor
        · rintro ⟨s1', hst, hrun⟩
          obtain ⟨s2', hst2, hrel⟩ := hfwd a q s1' hst
          exact ⟨s2', hst2, (ih s1' s2' a' hrel).mp hrun⟩
        · rintro ⟨s2', hst, hrun⟩
          obtain ⟨s1', hst1, hrel⟩ := hbwd a q s2' hst
          exact ⟨s1', hst1, (ih s1' s2' a' hrel).mpr hrun⟩
  funext gs; obtain ⟨a, w⟩ := gs
  exact propext (H w s1 s2 a h)

-- ── The Salomaa equation system of a `GAut` (Def 4.3) and its solutions ────────────

/-- Denotation of an action-prefixed expression: `⟦q·X⟧` accepts `(a, w)` iff `w` begins
    with a `q`-step and `X` accepts the rest. -/
theorem den_seq_act (V : T → Atom → Bool) (q : A) (X : Exp A T) (a : Atom)
    (w : List (A × Atom)) :
    den V (Exp.seq (Exp.act q) X) (a, w) ↔ ∃ a' w', w = (q, a') :: w' ∧ den V X (a', w') := by
  simp only [den_seq, den_act]
  constructor
  · rintro ⟨l1, l2, hl, ⟨x, y, hxy⟩, hX⟩
    rw [Prod.mk.injEq] at hxy
    obtain ⟨_, hl1⟩ := hxy
    subst hl1
    exact ⟨y, l2, by simp [hl], by simpa [lastAtom] using hX⟩
  · rintro ⟨a', w', hw, hX⟩
    exact ⟨[(q, a')], w', by simp [hw], ⟨a, a', rfl⟩, by simpa [lastAtom] using hX⟩

/-- **State `s`'s Salomaa equation, as an expression** (Def 4.3). The guarded transitions
    are read in order as a deterministic guarded choice `q · x_{s'} +_g …`, ending in the
    halt test `hlt s · 1`; `sol` supplies the expression standing for each successor. This
    matches the automaton's first-match run semantics (`firstMatch`/`autStep`). -/
def eqRHS (aut : GAut S A T) (sol : S → Exp A T) (s : S) : Exp A T :=
  (aut.trans s).foldr
    (fun t acc => Exp.ite t.1 (Exp.seq (Exp.act t.2.1) (sol t.2.2)) acc)
    (Exp.test (aut.hlt s))

/-- **`sol` solves the automaton's equation system**: at every state, its assigned
    expression is provably equivalent to that state's equation RHS. An expression solving
    the *start* state's equation is the synthesized program. -/
def Solves (aut : GAut S A T) (sol : S → Exp A T) : Prop :=
  ∀ s ∈ aut.states, Equiv (sol s) (eqRHS aut sol s)

/-- **The Uniqueness Axiom (UA), `Equiv`-level.** Any two solutions of the automaton's
    system agree (provably) on every state. This is the hypothesis GKAT completeness is
    proven *relative to* (the paper's UA, `w3` generalized from one equation to systems);
    deriving it is the finite-axiomatization problem open since 2019, so it enters here as
    an explicit assumption, never as an axiom. -/
def UA (aut : GAut S A T) : Prop :=
  ∀ sol1 sol2, Solves aut sol1 → Solves aut sol2 →
    ∀ s ∈ aut.states, Equiv (sol1 s) (sol2 s)

/-- The one-state self-loop automaton `x ─(b|q)→ x`, halting on `h`. The smallest genuine
    loop; its equation is the single-state Salomaa equation. -/
def loopAut (b : BExp T) (q : A) (h : BExp T) : GAut Unit A T where
  states := [()]
  hlt    := fun _ => h
  trans  := fun _ => [(b, q, ())]
  start  := ()

/-- **The base case of elimination, wired through the equation-system vocabulary.** The
    self-loop system is solved by `q^(b) · h` — exactly `salomaa_solution_exists`. Validates
    that `eqRHS` encodes Def 4.3 faithfully (the guarded self-loop equation
    `x ≡ q·x +_b h`) and gives the base case the general well-nested elimination bottoms out
    in. -/
theorem loopAut_solves (b : BExp T) (q : A) (h : BExp T) :
    Solves (loopAut b q h) (fun _ => Exp.seq (Exp.wh b (Exp.act q)) (Exp.test h)) := by
  intro s _
  simp only [eqRHS, loopAut, List.foldr_cons, List.foldr_nil]
  exact salomaa_solution_exists b (Exp.act q) (Exp.test h)

/-- **Denotation of the guarded-choice equation RHS = first-match semantics.** `⟦eqRHS⟧`
    reads the guarded transitions in order exactly as `firstMatch`/`autStep` does: the first
    matching guard hands off to `q · sol s'`, and if none matches, to the halt test. List
    induction on the transitions. -/
theorem den_foldr_ite (V : T → Atom → Bool) (sol : S → Exp A T) (base : Exp A T)
    (L : List (BExp T × A × S)) (a : Atom) (w : List (A × Atom)) :
    den V (L.foldr (fun t acc => Exp.ite t.1 (Exp.seq (Exp.act t.2.1) (sol t.2.2)) acc) base)
        (a, w) ↔
      (match firstMatch V a L with
       | some (q, s') => den V (Exp.seq (Exp.act q) (sol s')) (a, w)
       | none         => den V base (a, w)) := by
  induction L with
  | nil => simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      simp only [List.foldr_cons, den_ite, firstMatch]
      by_cases hg : bval V g a
      · rw [if_pos hg]
        constructor
        · rintro (⟨_, h⟩ | ⟨hc, _⟩)
          · exact h
          · rw [hg] at hc; exact absurd hc (by simp)
        · intro h; exact Or.inl ⟨hg, h⟩
      · have hgf : bval V g a = false := by simpa using hg
        rw [if_neg hg]
        constructor
        · rintro (⟨hc, _⟩ | ⟨_, h⟩)
          · rw [hgf] at hc; exact absurd hc (by simp)
          · exact ih.mp h
        · intro h; exact Or.inr ⟨hgf, ih.mpr h⟩

/-- **`sol` semantically solves the system**: at every state its assigned expression *denotes*
    the equation RHS. Weaker than `Solves` (which asks for provable `Equiv`) — and crucially
    it is **not blocked** by the missing `ite`-guard axioms, since `den (ite 1 X Y) = den X`
    holds outright. This is the form the existence construction can actually establish. -/
def SemSolves (V : T → Atom → Bool) (aut : GAut S A T) (sol : S → Exp A T) : Prop :=
  ∀ s ∈ aut.states, den V (sol s) = den V (eqRHS aut sol s)

/-- **Semantic soundness of solving — the Kleene synthesis, semantic half.** If `sol`
    *semantically* solves a *well-formed* automaton's system, then at every state the
    automaton's language is exactly the denotation of the solution: `autLang aut s = ⟦sol s⟧`.
    Needs **no UA** — UA is for *uniqueness*; correctness-as-a-language is this theorem. The
    remaining half of the Kleene theorem is *existence* of a solution (the state-elimination
    construction for well-nested automata) — the Phase-2 crux. Length induction on the guarded
    string: at each step `den (sol s) = den (eqRHS)` (`SemSolves`), and `den (eqRHS)` reads the
    guards exactly as `autStep` (`den_foldr_ite`); well-formedness supplies halt/step exclusion
    and successor closure. -/
theorem sem_solves_autLang {V : T → Atom → Bool} {aut : GAut S A T} {sol : S → Exp A T}
    (hwf : WF V aut) (hsol : SemSolves V aut sol) :
    ∀ s ∈ aut.states, autLang V aut s = den V (sol s) := by
  have key : ∀ (w : List (A × Atom)) (s : S) (a : Atom), s ∈ aut.states →
      (autRun V aut s a w ↔ den V (sol s) (a, w)) := by
    intro w
    induction w with
    | nil =>
        intro s a hs
        rw [congrFun (hsol s hs) (a, [])]
        simp only [autRun, eqRHS]
        rw [den_foldr_ite]
        have haS : autStep V aut s a = firstMatch V a (aut.trans s) := rfl
        cases hfm : firstMatch V a (aut.trans s) with
        | none => simp
        | some x =>
            obtain ⟨q, s'⟩ := x
            show bval V (aut.hlt s) a = true ↔ den V (Exp.seq (Exp.act q) (sol s')) (a, [])
            rw [den_seq_act]
            have hne : bval V (aut.hlt s) a ≠ true := by
              intro h; have := hwf.1 s hs a h; rw [haS, hfm] at this; exact absurd this (by simp)
            exact iff_of_false hne (by simp)
    | cons hd tl ih =>
        intro s a hs; obtain ⟨q'', a''⟩ := hd
        rw [congrFun (hsol s hs) (a, (q'', a'') :: tl)]
        simp only [autRun, eqRHS]
        rw [den_foldr_ite]
        have haS : autStep V aut s a = firstMatch V a (aut.trans s) := rfl
        cases hfm : firstMatch V a (aut.trans s) with
        | none =>
            simp only [den_test]
            constructor
            · rintro ⟨s', h, _⟩; rw [haS, hfm] at h; exact absurd h (by simp)
            · rintro ⟨_, h⟩; exact absurd h (by simp)
        | some x =>
            obtain ⟨q, s'⟩ := x
            show (∃ s', autStep V aut s a = some (q'', s') ∧ autRun V aut s' a'' tl) ↔
                den V (Exp.seq (Exp.act q) (sol s')) (a, (q'', a'') :: tl)
            rw [den_seq_act]
            have hstep : autStep V aut s a = some (q, s') := by rw [haS, hfm]
            have hs' : s' ∈ aut.states := hwf.2 s hs a q s' hstep
            constructor
            · rintro ⟨s0, h0, hrun⟩
              rw [hstep, Option.some.injEq, Prod.mk.injEq] at h0
              obtain ⟨hq, hss⟩ := h0
              refine ⟨a'', tl, by rw [hq], ?_⟩
              rw [hss]; exact (ih s0 a'' (by rw [← hss]; exact hs')).mp hrun
            · rintro ⟨a', w', heq, hden⟩
              rw [List.cons.injEq, Prod.mk.injEq] at heq
              obtain ⟨⟨hq, ha⟩, hw⟩ := heq
              refine ⟨s', ?_, ?_⟩
              · rw [hstep, hq]
              · apply (ih s' a'' hs').mpr; rw [ha, hw]; exact hden
  intro s hs; funext gs; obtain ⟨a, w⟩ := gs
  simp only [autLang]; exact propext (key w s a hs)

/-- A provable (`Equiv`) solution is a fortiori a semantic one (`sound`). -/
theorem solves_semSolves {V : T → Atom → Bool} {aut : GAut S A T} {sol : S → Exp A T}
    (hsol : Solves aut sol) : SemSolves V aut sol := by
  intro s hs; funext gs; exact propext (GkatGS.sound V (hsol s hs) gs)

/-- **Semantic soundness for a provable solution** — the `Solves` corollary of
    `sem_solves_autLang`, via `solves_semSolves`. -/
theorem solves_autLang {V : T → Atom → Bool} {aut : GAut S A T} {sol : S → Exp A T}
    (hwf : WF V aut) (hsol : Solves aut sol) :
    ∀ s ∈ aut.states, autLang V aut s = den V (sol s) :=
  sem_solves_autLang hwf (solves_semSolves hsol)

/-- **The semantic fundamental theorem of derivatives.** Every expression *semantically*
    solves its own derivative system with `sol = id` (each derivative stands for itself):
    `⟦s⟧ = ⟦eqRHS (derivAut e) id s⟧` — an expression equals the guarded choice of its
    Brzozowski derivatives. This is exactly the identity the *syntactic* `Solves (derivAut e)
    id` cannot prove (it would need `ite 1 X Y ≡ X` for the `one`-guarded `act`-transitions),
    yet it holds semantically because `next`/`den` compute the guards. So the semantic route
    succeeds precisely where the syntactic one is axiom-blocked — the enabling fact for the
    existence construction. -/
theorem semSolves_derivAut (V : T → Atom → Bool) (e : Exp A T) :
    SemSolves V (derivAut e) (fun s => s) := by
  intro s _
  funext gs; obtain ⟨a, w⟩ := gs
  show den V s (a, w) = den V (eqRHS (derivAut e) (fun x => x) s) (a, w)
  rw [eqRHS, den_foldr_ite V (fun x => x) (Exp.test ((derivAut e).hlt s)) ((derivAut e).trans s) a w]
  have hnext : firstMatch V a ((derivAut e).trans s) = next V s a := firstMatch_transG V s a
  rw [hnext]
  cases hn : next V s a with
  | none =>
      cases w with
      | nil => simp [den_nil, E, derivAut]
      | cons hd tl => obtain ⟨q, a'⟩ := hd; rw [den_cons, hn]; simp [den_test]
  | some x =>
      obtain ⟨q0, s'⟩ := x
      show den V s (a, w) = den V (Exp.seq (Exp.act q0) s') (a, w)
      cases w with
      | nil =>
          rw [den_nil, next_halt_exclusive V s a (q0, s') hn, den_seq_act]; simp
      | cons hd tl =>
          obtain ⟨q, a'⟩ := hd
          rw [den_cons, hn, den_seq_act]
          apply propext
          constructor
          · rintro ⟨e', h, hd'⟩
            rw [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨hq, he⟩ := h
            exact ⟨a', tl, by rw [hq], by rw [he]; exact hd'⟩
          · rintro ⟨a'', w'', heq, hd'⟩
            rw [List.cons.injEq, Prod.mk.injEq] at heq
            obtain ⟨⟨hq, ha⟩, hw⟩ := heq
            exact ⟨s', by rw [hq], by rw [ha, hw]; exact hd'⟩

-- ── Existence for acyclic automata: the guarded-choice solution ───────────────────

/-- **The guarded-choice solution of an acyclic automaton.** `rank` witnesses acyclicity
    (every transition target is strictly smaller), so `buildSol s := s`'s equation RHS with
    each successor solved recursively — is a *finite* expression. There is no loop to
    finitize, so no `wh` and no fixpoint reasoning is needed. -/
def buildSol (aut : GAut S A T) (rank : S → Nat)
    (hac : ∀ s : S, ∀ t ∈ aut.trans s, rank t.2.2 < rank s) : S → Exp A T := fun s =>
  (aut.trans s).foldr
    (fun t acc => Exp.ite t.1 (Exp.seq (Exp.act t.2.1) (buildSol aut rank hac t.2.2)) acc)
    (Exp.test (aut.hlt s))
  termination_by s => rank s
  decreasing_by exact hac _ t (by assumption)

/-- **The guarded-choice solution solves the system — by construction.** `buildSol s` *is*
    its own equation RHS (`eqRHS` with the successors filled in by `buildSol`), so it solves
    the system with `Equiv` by reflexivity — no `ite`-guard axiom needed, since nothing is
    collapsed. -/
theorem buildSol_solves (aut : GAut S A T) (rank : S → Nat)
    (hac : ∀ s : S, ∀ t ∈ aut.trans s, rank t.2.2 < rank s) :
    Solves aut (buildSol aut rank hac) := by
  intro s _
  have heq : buildSol aut rank hac s = eqRHS aut (buildSol aut rank hac) s := by
    rw [buildSol]; rfl
  rw [heq]; exact Equiv.refl _

/-- **Existence for acyclic automata (Kleene, the loop-free half).** Every well-formed
    automaton with a rank witnessing acyclicity is expressible: `autLang aut s = ⟦buildSol s⟧`
    at every state — an expression synthesized with no `wh`, no fixpoint, no UA. The loop-free
    fragment of `W ⊆ {⟦e⟧}` is now machine-checked; cycles (needing `wh`) are the remainder. -/
theorem acyclic_expressible (V : T → Atom → Bool) (aut : GAut S A T) (rank : S → Nat)
    (hac : ∀ s : S, ∀ t ∈ aut.trans s, rank t.2.2 < rank s) (hwf : WF V aut) :
    ∀ s ∈ aut.states, autLang V aut s = den V (buildSol aut rank hac s) :=
  solves_autLang hwf (buildSol_solves aut rank hac)

/-- **Construction body, step 1: an acyclic flat automaton is expressible with the rank
    *computed*.** No rank is assumed — `reachCount` (the SCC-topological rank) is used, and its
    strict descent across every (live) edge is *derived* from acyclicity: a live edge whose
    target reached back would make a cycle, so by `reachCount_lt_of_step_not_mutReach` it drops
    the rank, discharging `buildSol`'s `hac`. This is where the SCC graph-algorithm layer first
    produces a synthesis from a raw transition graph. (`hall`: the state type is exactly the
    automaton's states; `hlive`: no dead edges — every listed transition genuinely fires.) -/
theorem acyclic_flat_expressible (V : T → Atom → Bool) (aut : GAut S A T) (hwf : WF V aut)
    (hall : ∀ s : S, s ∈ aut.states)
    (hlive : ∀ s : S, ∀ t ∈ aut.trans s, AutStep1 V aut s t.2.2)
    (hacyclic : ∀ s : S, ¬ AutReaches1 V aut s s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, autLang V aut s = den V (sol s) := by
  have hac : ∀ s : S, ∀ t ∈ aut.trans s, reachCount V aut t.2.2 < reachCount V aut s := by
    intro s t ht
    have hstep : AutStep1 V aut s t.2.2 := hlive s t ht
    have hnm : ¬ AutMutReach V aut s t.2.2 := by
      rintro ⟨_, hr2⟩; exact hacyclic s ⟨t.2.2, hstep, hr2⟩
    exact reachCount_lt_of_step_not_mutReach V aut (hall s) hstep hnm
  exact ⟨buildSol aut (reachCount V aut) hac, acyclic_expressible V aut (reachCount V aut) hac hwf⟩

-- ── Cyclic case: self-loop elimination via `wh` ───────────────────────────────────

/-- **Self-loop elimination — the cyclic inductive step.** A state whose equation is a
    self-loop with continuation, `g ≡ q·g +_b f`, is solved by `q^(b)·f`: the `wh` finitizes
    the back-edge that a plain guarded-choice recursion (`buildSol`) would unfold forever.
    This is exactly `salomaa_solution_exists` (a unique guarded fixpoint, Salomaa-style), and
    it is the step the full well-nested construction applies at each loop, with `buildSol` as
    the acyclic glue between loops. -/
theorem selfLoop_solves (b : BExp T) (q : A) (f : Exp A T) :
    Equiv (Exp.seq (Exp.wh b (Exp.act q)) f)
          (Exp.ite b (Exp.seq (Exp.act q) (Exp.seq (Exp.wh b (Exp.act q)) f)) f) :=
  salomaa_solution_exists b (Exp.act q) f

/-- A two-state loop-with-exit: `loop` iterates on `b` via `p`, and on `¬b` steps to `acc`
    via `r`; `acc` accepts. A genuine cycle whose exit continues into (acyclic) structure —
    the smallest "uniform continuation of a loop". -/
inductive Q2 where
  | loop
  | acc
  deriving DecidableEq, Repr

def loopExitAut (b : BExp T) (p r : A) : GAut Q2 A T where
  states := [Q2.loop, Q2.acc]
  hlt    := fun s => match s with | .loop => BExp.zero | .acc => BExp.one
  trans  := fun s => match s with
    | .loop => [(b, p, Q2.loop), (BExp.not b, r, Q2.acc)]
    | .acc  => []
  start  := Q2.loop

/-- The synthesized solution: `loop ↦ p^(b)·(if ¬b then r else 0)`, `acc ↦ 1`. -/
def loopExitSol (b : BExp T) (p r : A) : Q2 → Exp A T := fun s => match s with
  | .loop => Exp.seq (Exp.wh b (Exp.act p))
      (Exp.ite (BExp.not b) (Exp.seq (Exp.act r) (Exp.test BExp.one)) (Exp.test BExp.zero))
  | .acc  => Exp.test BExp.one

theorem loopExitAut_solves (b : BExp T) (p r : A) :
    Solves (loopExitAut b p r) (loopExitSol b p r) := by
  intro s _
  cases s with
  | loop =>
      show Equiv (loopExitSol b p r .loop) (eqRHS (loopExitAut b p r) (loopExitSol b p r) .loop)
      simp only [loopExitSol, eqRHS, loopExitAut, List.foldr_cons, List.foldr_nil]
      exact selfLoop_solves b p _
  | acc =>
      show Equiv (loopExitSol b p r .acc) (eqRHS (loopExitAut b p r) (loopExitSol b p r) .acc)
      simp only [loopExitSol, eqRHS, loopExitAut, List.foldr_nil]
      exact Equiv.refl _

theorem loopExitAut_wf (V : T → Atom → Bool) (b : BExp T) (p r : A) :
    WF V (loopExitAut b p r) := by
  constructor
  · intro s _ a hhalt
    cases s with
    | loop => simp only [loopExitAut] at hhalt; simp [bval] at hhalt
    | acc  => simp [autStep, loopExitAut, firstMatch]
  · intro s _ a q s' hst
    cases s with
    | loop =>
        simp only [autStep, loopExitAut, firstMatch] at hst
        by_cases hb : bval V b a
        · rw [if_pos hb, Option.some.injEq, Prod.mk.injEq] at hst
          simp [loopExitAut, hst.2]
        · rw [if_neg hb] at hst
          by_cases hnb : bval V (BExp.not b) a
          · rw [if_pos hnb, Option.some.injEq, Prod.mk.injEq] at hst; simp [loopExitAut, hst.2]
          · rw [if_neg hnb] at hst; exact absurd hst (by simp)
    | acc => simp [autStep, loopExitAut, firstMatch] at hst

/-- **First machine-checked synthesis of a looping automaton with a continuation.** The
    loop-with-exit automaton is well-formed and solved, so `solves_autLang` yields
    `autLang (loopExitAut …) loop = ⟦p^(b)·(¬b → r)⟧` — a genuine cycle synthesized into a
    `wh`-expression whose behavior it provably has. The cyclic pipeline works end-to-end. -/
theorem loopExitAut_expressible (V : T → Atom → Bool) (b : BExp T) (p r : A) :
    autLang V (loopExitAut b p r) Q2.loop = den V (loopExitSol b p r Q2.loop) :=
  solves_autLang (loopExitAut_wf V b p r) (loopExitAut_solves b p r) Q2.loop (by simp [loopExitAut])

-- ── The assembly: nested single-action loops + acyclic glue ───────────────────────

/-- **A hierarchically-ranked automaton with (optional) self-loops.** Each state carries an
    optional self-loop `loop s = some (b, q)` (iterate on `b` via `q`) and a list of `exits`
    to *strictly-smaller* states (`hexit`). Cycles are exactly the self-loops; everything else
    descends in rank — so loops may nest (an exit into a smaller loop head) and be glued by
    acyclic structure, all under one well-founded recursion. This is the well-nested class for
    single-action loop bodies. -/
structure WNAut (S A T : Type) where
  states : List S
  rank   : S → Nat
  hlt    : S → BExp T
  loop   : S → Option (BExp T × A)
  exits  : S → List (BExp T × A × S)
  hexit  : ∀ s : S, ∀ t ∈ exits s, rank t.2.2 < rank s
  start  : S

/-- The induced `GAut`: the self-loop (if any) is the first transition, then the exits. -/
def wnGAut (w : WNAut S A T) : GAut S A T where
  states := w.states
  hlt    := w.hlt
  trans  := fun s => (match w.loop s with | some (b, q) => [(b, q, s)] | none => []) ++ w.exits s
  start  := w.start

/-- **The synthesized solution.** Solve the exits into a guarded-choice continuation `f`
    (recursion only over the strictly-smaller exits), then wrap the self-loop around it with
    `wh`: `loop s = some (b,q)` gives `q^(b)·f`, `none` gives `f`. Well-founded on `rank`. -/
def wnSol (w : WNAut S A T) : S → Exp A T := fun s =>
  match w.loop s with
  | some (b, q) => Exp.seq (Exp.wh b (Exp.act q))
      ((w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq (Exp.act t.2.1) (wnSol w t.2.2)) acc)
        (Exp.test (w.hlt s)))
  | none => (w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq (Exp.act t.2.1) (wnSol w t.2.2)) acc)
      (Exp.test (w.hlt s))
  termination_by s => w.rank s
  decreasing_by all_goals exact w.hexit _ _ (by assumption)

/-- **The solution solves the system.** At a loop state the equation is the Salomaa self-loop
    `g ≡ q·g +_b f` — discharged by `selfLoop_solves` — and at a loop-free state it *is* its
    own guarded choice (`refl`). -/
theorem wnSol_solves (w : WNAut S A T) : Solves (wnGAut w) (wnSol w) := by
  intro s _
  cases hl : w.loop s with
  | none =>
      have e : wnSol w s = eqRHS (wnGAut w) (wnSol w) s := by
        rw [wnSol]; simp only [hl, eqRHS, wnGAut, List.nil_append]
      rw [e]; exact Equiv.refl _
  | some bq =>
      obtain ⟨b, q⟩ := bq
      have e1 : wnSol w s = Exp.seq (Exp.wh b (Exp.act q))
          ((w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq (Exp.act t.2.1) (wnSol w t.2.2)) acc)
            (Exp.test (w.hlt s))) := by
        rw [wnSol]; simp only [hl]
      have e2 : eqRHS (wnGAut w) (wnSol w) s = Exp.ite b (Exp.seq (Exp.act q) (wnSol w s))
          ((w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq (Exp.act t.2.1) (wnSol w t.2.2)) acc)
            (Exp.test (w.hlt s))) := by
        simp only [eqRHS, wnGAut, hl, List.singleton_append, List.foldr_cons]
      rw [e2, e1]
      exact selfLoop_solves b q _

/-- **The assembly, as far as single-action loop bodies reach.** Every well-formed `WNAut`
    is expressible: `autLang (wnGAut w) s = ⟦wnSol w s⟧` at every state — nested loops glued by
    acyclic structure, synthesized into a `wh`/`·`/`+_b` expression, via `solves_autLang`.
    This closes `W ⊆ {⟦e⟧}` for the hierarchically-ranked single-action-loop class; the
    remaining gap to full completeness is multi-state loop *bodies* (cycles longer than a
    self-loop), where the loop body is itself a sub-automaton to be synthesized first. -/
theorem wn_expressible (V : T → Atom → Bool) (w : WNAut S A T) (hwf : WF V (wnGAut w)) :
    ∀ s ∈ (wnGAut w).states, autLang V (wnGAut w) s = den V (wnSol w s) :=
  solves_autLang hwf (wnSol_solves w)

/-- **Construction body, step 2: singleton-SCC flat automata, rank computed.** A flat GAut
    presented as (optional) self-loop + exits — the singleton-SCC shape, where the only cycles
    are self-loops — is expressible, with the rank *computed* by `reachCount`. The `WNAut`
    well-formedness `hexit` (exits strictly smaller) is **derived** from a semantic condition:
    each exit is a live edge whose target is *not* mutually reachable (`hcross`), hence drops
    the rank by `reachCount_lt_of_step_not_mutReach`. So the caller supplies a reachability
    fact instead of a hand-built rank; the SCC machinery produces the loop nesting. -/
theorem flat_selfloop_expressible (V : T → Atom → Bool) (states : List S) (hlt : S → BExp T)
    (loop : S → Option (BExp T × A)) (exits : S → List (BExp T × A × S)) (start : S)
    (A0 : GAut S A T)
    (hA0 : A0 = ⟨states, hlt,
      fun s => (match loop s with | some (b, q) => [(b, q, s)] | none => []) ++ exits s, start⟩)
    (hwf : WF V A0) (hall : ∀ s : S, s ∈ states)
    (hlive : ∀ s : S, ∀ t ∈ exits s, AutStep1 V A0 s t.2.2)
    (hcross : ∀ s : S, ∀ t ∈ exits s, ¬ AutMutReach V A0 s t.2.2) :
    ∃ sol : S → Exp A T, ∀ s ∈ states, autLang V A0 s = den V (sol s) := by
  have hexit : ∀ s : S, ∀ t ∈ exits s, reachCount V A0 t.2.2 < reachCount V A0 s := by
    intro s t ht
    have hsA0 : s ∈ A0.states := by rw [hA0]; exact hall s
    exact reachCount_lt_of_step_not_mutReach V A0 hsA0 (hlive s t ht) (hcross s t ht)
  let w : WNAut S A T :=
    { states := states, rank := reachCount V A0, hlt := hlt, loop := loop, exits := exits,
      hexit := hexit, start := start }
  have hwn : wnGAut w = A0 := by rw [hA0]; rfl
  refine ⟨wnSol w, fun s hs => ?_⟩
  have key := wn_expressible V w (by rw [hwn]; exact hwf) s (by
    show s ∈ (wnGAut w).states; rw [hwn, hA0]; exact hs)
  rw [hwn] at key; exact key

-- ── State elimination, step 1: the expression-labeled generalized automaton ────────

/-- **An expression-labeled generalized automaton** (the target of state elimination). Each
    state carries an optional self-loop whose body is an arbitrary *expression* `loopB s =
    some (b, e)`, and a list of *expression-labeled* `exits` to strictly-smaller states. When
    a flat single-action automaton has a state eliminated, its through-paths become such
    expression labels; iterating elimination drives any well-nested automaton into this shape,
    where the loop body may be any synthesized sub-expression (not just one action). -/
structure WNAutE (S A T : Type) where
  rank   : S → Nat
  hlt    : S → BExp T
  loopB  : S → Option (BExp T × Exp A T)
  exits  : S → List (BExp T × Exp A T × S)
  hexit  : ∀ s : S, ∀ t ∈ exits s, rank t.2.2 < rank s

/-- The generalized equation of state `s`: expression-labeled guarded choice over the exits,
    with the self-loop (if any) as the outer Salomaa fixpoint `e·g +_b (exits)`. -/
def eqRHSE (w : WNAutE S A T) (sol : S → Exp A T) (s : S) : Exp A T :=
  match w.loopB s with
  | some (b, e) => Exp.ite b (Exp.seq e (sol s))
      ((w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq t.2.1 (sol t.2.2)) acc)
        (Exp.test (w.hlt s)))
  | none => (w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq t.2.1 (sol t.2.2)) acc)
      (Exp.test (w.hlt s))

/-- **The synthesized solution** — recursion only over the strictly-smaller exits; the
    self-loop's arbitrary body `e` is wrapped by `wh`, never recursed. -/
def wnSolE (w : WNAutE S A T) : S → Exp A T := fun s =>
  match w.loopB s with
  | some (b, e) => Exp.seq (Exp.wh b e)
      ((w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq t.2.1 (wnSolE w t.2.2)) acc)
        (Exp.test (w.hlt s)))
  | none => (w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq t.2.1 (wnSolE w t.2.2)) acc)
      (Exp.test (w.hlt s))
  termination_by s => w.rank s
  decreasing_by all_goals exact w.hexit _ _ (by assumption)

/-- **The generalized system is solved** — for an *arbitrary* loop body `e`. Loop states are
    the Salomaa fixpoint `e·g +_b f` (`salomaa_solution_exists`, any `e`); loop-free states
    are their own generalized guarded choice (`refl`). This is the synthesis end of state
    elimination: once a flat automaton is driven into `WNAutE` form, `wnSolE` is the program. -/
theorem wnSolE_solves (w : WNAutE S A T) (s : S) :
    Equiv (wnSolE w s) (eqRHSE w (wnSolE w) s) := by
  cases hl : w.loopB s with
  | none =>
      have e : wnSolE w s = eqRHSE w (wnSolE w) s := by
        rw [wnSolE]; simp only [hl, eqRHSE]
      rw [e]; exact Equiv.refl _
  | some be =>
      obtain ⟨b, e⟩ := be
      have e1 : wnSolE w s = Exp.seq (Exp.wh b e)
          ((w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq t.2.1 (wnSolE w t.2.2)) acc)
            (Exp.test (w.hlt s))) := by
        rw [wnSolE]; simp only [hl]
      have e2 : eqRHSE w (wnSolE w) s = Exp.ite b (Exp.seq e (wnSolE w s))
          ((w.exits s).foldr (fun t acc => Exp.ite t.1 (Exp.seq t.2.1 (wnSolE w t.2.2)) acc)
            (Exp.test (w.hlt s))) := by
        simp only [eqRHSE, hl]
      rw [e2, e1]
      exact salomaa_solution_exists b e _

-- ── General multi-state loop body: an arbitrary-length linear cycle ────────────────

/-- The loop body of an action chain `[q₁,…,qₖ]` as one expression: `q₁·(q₂·…·(qₖ·1))`. -/
def bodyChain : List A → Exp A T
  | []      => Exp.test BExp.one
  | q :: qs => Exp.seq (Exp.act q) (bodyChain qs)

/-- Prepend an action chain to an expression: `[q₁,…,qₖ] X ↦ q₁·(q₂·…·(qₖ·X))` — the body
    executed, then continuing with `X`. This is how the equation of a linear cycle reads. -/
def seqActs : List A → Exp A T → Exp A T
  | [],      X => X
  | q :: qs, X => Exp.seq (Exp.act q) (seqActs qs X)

/-- Running the body chain then `X` is the same as prepending the chain to `X` — the state
    elimination that collapses a linear cycle into one composed body, by `S1`/`S4`. -/
theorem seq_bodyChain (qs : List A) (X : Exp A T) :
    Equiv (Exp.seq (bodyChain qs) X) (seqActs qs X) := by
  induction qs generalizing X with
  | nil => exact Equiv.s4 X
  | cons q qs ih =>
      exact Equiv.trans (Equiv.s1 (Exp.act q) (bodyChain qs) X)
        (Equiv.seq_c (Equiv.refl _) (ih X))

/-- **General linear-loop elimination.** A loop whose body is an arbitrary-length action
    chain — the multi-state cycle equation `g ≡ q₁·q₂·…·qₖ·g +_b f` — is solved by
    `(q₁·…·qₖ)^(b)·f`. `salomaa_solution_exists` handles the (composed) body, and
    `seq_bodyChain` performs the state elimination that turns the `k`-state cycle into that
    single composed body. This is `selfLoop_solves` (k = 1) and `loop2Aut` (k = 2) unified
    to any length — the engine that synthesizes a linear SCC once its states are collapsed. -/
theorem loopChain_solves (b : BExp T) (qs : List A) (f : Exp A T) :
    Equiv (Exp.seq (Exp.wh b (bodyChain qs)) f)
          (Exp.ite b (seqActs qs (Exp.seq (Exp.wh b (bodyChain qs)) f)) f) :=
  Equiv.trans (salomaa_solution_exists b (bodyChain qs) f)
    (Equiv.ite_c (seq_bodyChain qs _) (Equiv.refl f))

-- ── Multi-state loop body: `while b do (p; q)` as a two-state cycle ────────────────

/-- The two states of `while b do (p; q)`: `h` (head, branches on `b`), `k` (does `q`,
    returns to `h`). The cycle `h ⇄ k` is a loop whose *body spans two states* — longer than
    a self-loop. -/
inductive Q2c where
  | h
  | k
  deriving DecidableEq, Repr

def loop2Aut (b : BExp T) (p q : A) : GAut Q2c A T where
  states := [Q2c.h, Q2c.k]
  hlt    := fun s => match s with | .h => BExp.not b | .k => BExp.zero
  trans  := fun s => match s with
    | .h => [(b, p, Q2c.k)]           -- on `b`: do `p`, go to `k`
    | .k => [(BExp.one, q, Q2c.h)]    -- unconditionally: do `q`, return to `h`
  start  := Q2c.h

/-- The synthesized head expression: `(p·q)^(b)·¬b` — the loop body `p·q` is the composition
    of the two states' actions, recovered by state elimination (`S1` associativity). -/
def loop2Sol0 (b : BExp T) (p q : A) : Exp A T :=
  Exp.seq (Exp.wh b (Exp.seq (Exp.act p) (Exp.act q))) (Exp.test (BExp.not b))

def loop2Sol (b : BExp T) (p q : A) : Q2c → Exp A T := fun s => match s with
  | .h => loop2Sol0 b p q
  | .k => Exp.seq (Exp.act q) (loop2Sol0 b p q)

theorem loop2Aut_wf (V : T → Atom → Bool) (b : BExp T) (p q : A) :
    WF V (loop2Aut b p q) := by
  constructor
  · intro s _ a hhalt
    cases s with
    | h => have hbf : bval V b a = false := by
             have : bval V (BExp.not b) a = true := hhalt; simpa [bval] using this
           simp [autStep, loop2Aut, firstMatch, hbf]
    | k => simp only [loop2Aut] at hhalt; simp [bval] at hhalt
  · intro s _ a q' s' hst
    cases s with
    | h => simp only [autStep, loop2Aut, firstMatch] at hst
           by_cases hb : bval V b a
           · rw [if_pos hb, Option.some.injEq, Prod.mk.injEq] at hst; simp [loop2Aut, hst.2]
           · rw [if_neg hb] at hst; exact absurd hst (by simp)
    | k => simp only [autStep, loop2Aut, firstMatch, bval, if_true, Option.some.injEq,
             Prod.mk.injEq] at hst
           simp [loop2Aut, hst.2]

/-- **The two-state loop is solved — *semantically*.** The head equation is the Salomaa
    fixpoint for the *composed* body `p·q` (`salomaa_solution_exists` + `S1` to re-associate
    `(p·q)·g` into `p·(q·g)`); the body state `k` steps unconditionally, so its equation
    carries an `ite 1` that only the semantic solve (`den (ite 1 X Y) = den X`) discharges. -/
theorem loop2Aut_semsolves (V : T → Atom → Bool) (b : BExp T) (p q : A) :
    SemSolves V (loop2Aut b p q) (loop2Sol b p q) := by
  intro s _
  cases s with
  | h =>
      have hEq : Equiv (loop2Sol b p q Q2c.h) (eqRHS (loop2Aut b p q) (loop2Sol b p q) Q2c.h) := by
        simp only [eqRHS, loop2Aut, loop2Sol, loop2Sol0, List.foldr_cons, List.foldr_nil]
        exact Equiv.trans
          (salomaa_solution_exists b (Exp.seq (Exp.act p) (Exp.act q)) (Exp.test (BExp.not b)))
          (Equiv.ite_c (Equiv.s1 (Exp.act p) (Exp.act q) _) (Equiv.refl _))
      funext gs; exact propext (GkatGS.sound V hEq gs)
  | k =>
      funext gs
      show den V (loop2Sol b p q Q2c.k) gs = den V (eqRHS (loop2Aut b p q) (loop2Sol b p q) Q2c.k) gs
      simp [loop2Sol, eqRHS, loop2Aut, den_ite, bval]

/-- **First synthesis of a loop whose body spans multiple states.** `autLang (loop2Aut …) h =
    ⟦(p·q)^(b)·¬b⟧` — a `while b do (p; q)` cycle recovered as an expression, its two-action
    body composed by state elimination. The multi-state loop body is handled; the general
    case (arbitrary well-nested bodies) iterates this composition. -/
theorem loop2Aut_expressible (V : T → Atom → Bool) (b : BExp T) (p q : A) :
    autLang V (loop2Aut b p q) Q2c.h = den V (loop2Sol b p q Q2c.h) :=
  sem_solves_autLang (loop2Aut_wf V b p q) (loop2Aut_semsolves V b p q) Q2c.h (by simp [loop2Aut])

-- ── Worked end-to-end synthesis: the `while` automaton (non-vacuity of the pipeline) ─

/-- The genuine `while` automaton has halt guard `¬b` (a loop exits exactly off its guard),
    which makes it well-formed: at a halt atom (`¬b`) the self-loop guard `b` is false, so it
    cannot step. -/
theorem WF_loopAut (V : T → Atom → Bool) (b : BExp T) (q : A) :
    WF V (loopAut b q (BExp.not b)) := by
  constructor
  · intro s _ a hhalt
    have hbf : bval V b a = false := by
      have : bval V (BExp.not b) a = true := hhalt
      simpa [bval] using this
    simp [autStep, loopAut, firstMatch, hbf]
  · intro s _ a q' s' _
    cases s'; simp [loopAut]

/-- **End-to-end synthesis, validated.** The `while` automaton `x ─(b|q)→ x` (halting on
    `¬b`) is well-formed and solved by `q^(b)·¬b`; running the whole Phase-2 pipeline
    (`solves_autLang` on `WF_loopAut` + `loopAut_solves`) yields its language *as a
    denotation*: `autLang (loopAut …) () = ⟦q^(b)·¬b⟧`. Non-vacuity of the entire chain —
    a genuine automaton is synthesized into an expression whose behavior it provably has. -/
theorem loopAut_expressible (V : T → Atom → Bool) (b : BExp T) (q : A) :
    autLang V (loopAut b q (BExp.not b)) () =
      den V (Exp.seq (Exp.wh b (Exp.act q)) (Exp.test (BExp.not b))) := by
  simpa using
    solves_autLang (WF_loopAut V b q) (loopAut_solves b q (BExp.not b)) () (by simp [loopAut])

#print axioms firstMatch_transG
#print axioms autLang_derivAut
#print axioms WF_derivAut
#print axioms Nested_derivAut
#print axioms fig3_not_nested
#print axioms autLang_eq_of_gbisim
#print axioms gbisim_derivAut
#print axioms autLang_eq_of_gautBisim
#print axioms den_seq_act
#print axioms den_foldr_ite
#print axioms loopAut_solves
#print axioms sem_solves_autLang
#print axioms solves_autLang
#print axioms semSolves_derivAut
#print axioms buildSol_solves
#print axioms acyclic_expressible
#print axioms acyclic_flat_expressible
#print axioms selfLoop_solves
#print axioms loopExitAut_solves
#print axioms loopExitAut_expressible
#print axioms wnSol_solves
#print axioms wn_expressible
#print axioms flat_selfloop_expressible
#print axioms loop2Aut_semsolves
#print axioms AutReaches.trans
#print axioms AutMutReach.trans
#print axioms AutBelow.trans
#print axioms AutBelow.congr_left
#print axioms reachCount_lt_of_below
#print axioms reachCount_eq_of_mutReach
#print axioms reachCount_step_le
#print axioms mutReach_of_step_reachCount_eq
#print axioms reachCount_lt_of_step_not_mutReach
#print axioms autBelow_wf
#print axioms firstMatch_some_mem
#print axioms firstMatch_eq_of_mem_det
#print axioms wnSolE_solves
#print axioms seq_bodyChain
#print axioms loopChain_solves
#print axioms loop2Aut_expressible
#print axioms WF_loopAut
#print axioms loopAut_expressible

end GkatKleene
