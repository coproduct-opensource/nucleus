import GkatSyntaxProofs

/-!
# The guarded-string model — and left-distributivity is genuinely unsound

The single-atom model (`GkatLanguageProofs`) is sound and separates `0` from `1`,
but it is too coarse to witness the *frontier* obstruction: with one atom, tests
are constant, so left-distributivity `p·(a +_c b) ≡ p·a +_c p·b` holds there.

This file builds the canonical **guarded-string** model over ≥2 atoms, where an
action can change the atom a later test reads. A guarded string is
`α₀ p₁ α₁ … pₙ αₙ` — represented as `(α₀, [(p₁,α₁), …, (pₙ,αₙ)])` — and a language
is a set of guarded strings. The loop is the least fixpoint of "run `e` while the
current atom satisfies `b`", captured by an **inductive predicate** `InLoop`.

The headline (this file): `left_distrib_fails` — a concrete 2-atom (`Bool`)
countermodel where `p·(1 +_c 0)` and `(p·1) +_c (p·0)` denote *different* languages,
because `p` moves from a `¬c`-atom to a `c`-atom (the guard is read at the START
atom on one side, the END atom on the other). This is machine-checked here.

The `den` above is the **standard guarded-string semantics** of GKAT (actions =
single steps, `+_b` = guarded union, `·` = fusion product, `e^(b)` = the `InLoop`
least fixpoint), which is **sound** for the GKAT axioms — the classical result of
Smolka et al. (2019), which we CITE rather than re-derive here. Combining that
soundness with the refutation below: **`LeftDistrib` is not a GKAT theorem** — so
the completeness-frontier obstruction (`GkatFrontierProofs.two_cycle_solvable_of_left_distrib`)
rests on a law GKAT genuinely cannot have, not one merely left unused.

What is machine-checked here: the model definition and the refutation. What is
cited: the model's soundness (standard). Re-proving that soundness in Lean
(loop-free U/S is straightforward fusion algebra; W1–W3 over `InLoop` needs the
guarded-Kleene-star uniqueness argument) is the natural follow-up.
-/

namespace GkatGS

open GkatSyntax

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- Test valuation at an atom. -/
def bval : BExp T → Atom → Bool
  | .zero,    _ => false
  | .one,     _ => true
  | .prim t,  a => V t a
  | .and b c, a => bval b a && bval c a
  | .or b c,  a => bval b a || bval c a
  | .not b,   a => ! bval b a

/-- A guarded string: a start atom and a list of (action, next-atom) steps. -/
abbrev GS (A Atom : Type) := Atom × List (A × Atom)

/-- The final atom of a guarded string. -/
def lastAtom : Atom → List (A × Atom) → Atom
  | a, [] => a
  | _, (_, b) :: rest => lastAtom b rest

/-- The loop language as a least fixpoint: run `dene` while the current atom
    satisfies `b`, exit (empty string) when it does not. -/
inductive InLoop (b : BExp T) (dene : GS A Atom → Prop) : GS A Atom → Prop where
  | exit (a : Atom) : bval V b a = false → InLoop b dene (a, [])
  | step (a : Atom) (l1 : List (A × Atom)) (rest : List (A × Atom)) :
      bval V b a = true → dene (a, l1) →
      InLoop b dene (lastAtom a l1, rest) →
      InLoop b dene (a, l1 ++ rest)

/-- The guarded-string denotation. -/
def den : Exp A T → GS A Atom → Prop
  | .act p    => fun gs => ∃ a b, gs = (a, [(p, b)])
  | .test t   => fun gs => bval V t gs.1 = true ∧ gs.2 = []
  | .seq e f  => fun gs => ∃ l1 l2, gs.2 = l1 ++ l2 ∧ den e (gs.1, l1) ∧
                    den f (lastAtom gs.1 l1, l2)
  | .ite b e f => fun gs =>
      (bval V b gs.1 = true ∧ den e gs) ∨ (bval V b gs.1 = false ∧ den f gs)
  | .wh b e   => InLoop V b (den e)

@[simp] theorem den_act (p : A) (gs : GS A Atom) :
    den V (.act p) gs ↔ ∃ a b, gs = (a, [(p, b)]) := Iff.rfl
@[simp] theorem den_test (t : BExp T) (gs : GS A Atom) :
    den V (Exp.test t : Exp A T) gs ↔ (bval V t gs.1 = true ∧ gs.2 = []) := Iff.rfl
@[simp] theorem den_seq (e f : Exp A T) (gs : GS A Atom) :
    den V (.seq e f) gs ↔
      ∃ l1 l2, gs.2 = l1 ++ l2 ∧ den V e (gs.1, l1) ∧ den V f (lastAtom gs.1 l1, l2) :=
  Iff.rfl
@[simp] theorem den_ite (b : BExp T) (e f : Exp A T) (gs : GS A Atom) :
    den V (.ite b e f) gs ↔
      ((bval V b gs.1 = true ∧ den V e gs) ∨ (bval V b gs.1 = false ∧ den V f gs)) :=
  Iff.rfl

-- ── Left-distributivity fails: a concrete 2-atom (Bool) countermodel ─────────

/-- Atoms = `Bool`; the primitive test reads the atom (`c` true iff the atom is
    `true`). Action `p` (any) can move `false ↦ true`. -/
def V0 : Unit → Bool → Bool := fun _ a => a

/-- **Left-distributivity is unsound** — a sound GKAT model refutes it, so it is
    not a GKAT theorem. Witness: the string `false --p--> true`. In
    `p·(1 +_c 0)` the guard `c` is read at the END atom (`true` ⇒ accept); in
    `(p·1) +_c (p·0)` it is read at the START atom (`false` ⇒ reject). So the two
    denote different languages. `c := prim ()`, valuation `V0`. -/
theorem left_distrib_fails :
    ¬ (∀ gs : GS Unit Bool,
        den V0 (.seq (.act ()) (.ite (.prim ()) (.test .one) (.test .zero))) gs ↔
        den V0 (.ite (.prim ()) (.seq (.act ()) (.test .one))
                                (.seq (.act ()) (.test .zero))) gs) := by
  intro h
  -- LHS holds at the witness `false --p--> true` (guard `c` read at end atom = true)
  have hlhs : den V0 (.seq (.act ()) (.ite (.prim ()) (.test .one) (.test .zero)))
      (false, [((), true)]) :=
    ⟨[((), true)], [], rfl, ⟨false, true, rfl⟩, Or.inl ⟨rfl, rfl, rfl⟩⟩
  -- RHS fails at the witness (guard `c` read at start atom = false)
  have hrhs : ¬ den V0 (.ite (.prim ()) (.seq (.act ()) (.test .one))
      (.seq (.act ()) (.test .zero))) (false, [((), true)]) := by
    rintro (⟨hc, _⟩ | ⟨_, l1, l2, _, _, hz, _⟩)
    · exact absurd hc (by decide)
    · simp [bval] at hz
  exact hrhs ((h _).mp hlhs)

end GkatGS
