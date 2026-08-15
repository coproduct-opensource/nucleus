import GkatDerivativeFiniteProofs

/-!
# The runnable decision procedure: membership factors through the derivative run

The coalgebraic spine (`next`, `den_cons`, `derivs_closed`, `bisim_upto_iff`) proves
GKAT equivalence *decidable in principle*. This file assembles the runnable core: it
turns "does `⟦e⟧` accept `(a,w)`?" into *deterministically following the derivative
run of `w`*, and bounds emptiness by that run.

  * `derivAfter e a w` — follow the unique derivative run of the guarded string `w`
    from `e` at atom `a`, returning the `(expression, atom)` reached, or `none` if `e`
    is dead on `w`.
  * `den_run` — `⟦e⟧` accepts `(a,w)` iff the run reaches a state that halts:
    `den e (a,w) ↔ ∃ e' b, derivAfter e a w = some (e',b) ∧ E e' b`.
  * `nonempty_of_deriv_halts` / `deriv_halts_of_nonempty` — the language is non-empty
    iff some state reachable by a run halts.

Every state the run visits is a derivative (`derivs_closed`), so the run lives in the
finite set `derivs e`. Bounding emptiness/equivalence by that finiteness (the
pumping step) is the remaining engineering; this file is the executable membership
core it builds on. Requires `DecidableEq` on actions to follow the run.

Axioms `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatDeriv

open GkatSyntax GkatGS

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- Follow the derivative run of a guarded string. At each step the (deterministic)
    action `e` performs must match the string's action, else the run dies (`none`). -/
def derivAfter [DecidableEq A] : Exp A T → Atom → List (A × Atom) → Option (Exp A T × Atom)
  | e, a, []            => some (e, a)
  | e, a, (q, a') :: w  =>
      match next V e a with
      | some (q', e') => if q' = q then derivAfter e' a' w else none
      | none          => none

/-- **Membership = the run reaches a halting state.** `⟦e⟧` accepts `(a,w)` iff
    following `w` from `e` lands on a `(e',b)` whose `e'` can halt at `b`. -/
theorem den_run [DecidableEq A] (e : Exp A T) (a : Atom) (w : List (A × Atom)) :
    den V e (a, w) ↔ ∃ e' b, derivAfter V e a w = some (e', b) ∧ bval V (E e') b = true := by
  induction w generalizing e a with
  | nil =>
      simp only [derivAfter]
      constructor
      · intro h; exact ⟨e, a, rfl, (den_nil V e a).mp h⟩
      · rintro ⟨e', b, heq, hE⟩
        rw [Option.some.injEq, Prod.mk.injEq] at heq; obtain ⟨rfl, rfl⟩ := heq
        exact (den_nil V e a).mpr hE
  | cons hd tl ih =>
      obtain ⟨q, a'⟩ := hd
      rw [den_cons]
      cases hne : next V e a with
      | none => simp [derivAfter, hne]
      | some pe =>
          obtain ⟨q', e0⟩ := pe
          by_cases hq : q' = q
          · subst hq
            constructor
            · rintro ⟨e1, he1, hd1⟩
              rw [Option.some.injEq, Prod.mk.injEq] at he1; obtain ⟨_, rfl⟩ := he1
              obtain ⟨e', b, heq, hE⟩ := (ih e0 a').mp hd1
              exact ⟨e', b, by simp only [derivAfter, hne, if_pos rfl]; exact heq, hE⟩
            · rintro ⟨e', b, heq, hE⟩
              simp only [derivAfter, hne, if_pos rfl] at heq
              exact ⟨e0, rfl, (ih e0 a').mpr ⟨e', b, heq, hE⟩⟩
          · constructor
            · rintro ⟨e1, he1, _⟩
              rw [Option.some.injEq, Prod.mk.injEq] at he1; exact absurd he1.1 hq
            · rintro ⟨e', b, heq, _⟩
              simp only [derivAfter, hne, if_neg hq] at heq; exact absurd heq (by simp)

/-- Every state a run visits is a derivative of the start (so runs stay in the finite
    `derivs e`). -/
theorem derivAfter_mem_derivs [DecidableEq A] (e : Exp A T) (a : Atom) (w : List (A × Atom))
    {e' : Exp A T} {b : Atom} (h : derivAfter V e a w = some (e', b)) : e' ∈ derivs e := by
  induction w generalizing e a with
  | nil =>
      simp only [derivAfter, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, _⟩ := h; exact mem_self e
  | cons hd tl ih =>
      obtain ⟨q, a'⟩ := hd
      simp only [derivAfter] at h
      cases hne : next V e a with
      | none => rw [hne] at h; simp at h
      | some pe =>
          obtain ⟨q', e0⟩ := pe; rw [hne] at h
          by_cases hq : q' = q
          · subst hq; simp only [if_pos rfl] at h
            exact derivs_trans e (deriv_mem e hne) e' (ih e0 a' h)
          · simp only [if_neg hq] at h; simp at h

/-- The language is non-empty iff a run reaches a halting state. -/
theorem nonempty_iff_run_halts [DecidableEq A] (e : Exp A T) :
    (∃ gs : GS A Atom, den V e gs) ↔
      ∃ (a : Atom) (w : List (A × Atom)) (e' : Exp A T) (b : Atom),
        derivAfter V e a w = some (e', b) ∧ bval V (E e') b = true := by
  constructor
  · rintro ⟨⟨a, w⟩, hd⟩; obtain ⟨e', b, heq, hE⟩ := (den_run V e a w).mp hd; exact ⟨a, w, e', b, heq, hE⟩
  · rintro ⟨a, w, e', b, heq, hE⟩; exact ⟨(a, w), (den_run V e a w).mpr ⟨e', b, heq, hE⟩⟩

#print axioms den_run
#print axioms derivAfter_mem_derivs

end GkatDeriv
