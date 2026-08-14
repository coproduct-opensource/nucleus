import GkatSyntaxProofs

/-!
# The GKAT completeness frontier — general-n existence, machine-checked

GKAT completeness reduces (Pham 2026) to: every Thompson-generated automaton's
Salomaa equation system has a *provable* solution. The UNARY case is solvable —
it is exactly `GkatSyntax.salomaa_solution_exists` (the loop `e^(b)·f` solves
`g ≡ e·g +_b f`). Classic Kleene-algebra completeness reduces an n-state system to
the unary case by **left-distributivity of sequencing over branching**
(`p·(a +_c b) ≡ p·a +_c p·b`) — Gaussian elimination. But that law is **unsound
under GKAT's bisimulation semantics**: an action `p` can change the atom, so the
test `c` cannot be factored past it. This is why general-n existence is OPEN
(Smolka et al. 2019; the class of *well-nested* automata that DO come from
expressions is solved by the Kleene theorem, but bisimulation yields general
systems).

This file pins that frontier precisely and machine-checks it for n = 2:

- `LeftDistrib` — the (unsound, non-GKAT) left-distribution law.
- `TwoCycleSolvable` — the 2-state cyclic system has a provable GKAT solution.
- `two_cycle_solvable_of_left_distrib` — **given `LeftDistrib`, the 2-cycle is
  solvable**, and the proof uses `LeftDistrib` and nothing else (no guardedness):
  eliminate the second state, then solve one loop. So **n = 2 existence reduces
  EXACTLY to the one unsound law** — the frontier, made a checked statement.

What this is NOT: a proof of general-n existence (open), nor that `LeftDistrib`
fails (that needs a ≥2-atom guarded-string model — the classical fact, cited). It
localizes the obstruction in machine-checked form.
-/

namespace GkatFrontier

open GkatSyntax

variable {A T : Type}

/-- **The left-distribution law** — sequencing distributes over guarded union on
    the left. KA completeness uses it to reduce systems to the unary case; it is
    UNSOUND for GKAT (an action can change the atom the guard reads), so it is not
    a GKAT theorem. This is the exact crux of the open existence problem. -/
def LeftDistrib (A T : Type) : Prop :=
  ∀ (p : A) (c : BExp T) (a b : Exp A T),
    Equiv (.seq (.act p) (.ite c a b)) (.ite c (.seq (.act p) a) (.seq (.act p) b))

/-- A 2-state cyclic Salomaa system is solvable: expressions `g₁, g₂` provably
    satisfy the guarded equations `x₁ ≡ p·x₂ +_b f₁`, `x₂ ≡ q·x₁ +_c f₂`. -/
def TwoCycleSolvable (p q : A) (b c : BExp T) (f1 f2 : Exp A T) : Prop :=
  ∃ g1 g2 : Exp A T,
    Equiv g1 (.ite b (.seq (.act p) g2) f1) ∧
    Equiv g2 (.ite c (.seq (.act q) g1) f2)

/-- **The frontier, machine-checked (n = 2).** Given the unsound `LeftDistrib`,
    the 2-cycle is solvable. Construction: let the round-trip be `pq = p·q`,
    `d = c ∧ b`, `REST = if b then p·f₂ else f₁`; take `g₁ = (pq)^(d)·REST`,
    `g₂ = q·g₁ +_c f₂`. Then `g₂`'s equation is reflexivity, and `g₁`'s follows
    from `salomaa_solution_exists` (the unary loop) after rewriting the eliminated
    state with `LeftDistrib`, `S1`, `U3`. Crucially the proof needs NO guardedness
    — it uses `LeftDistrib` and nothing else — so n=2 existence reduces exactly to
    that one unsound law. -/
theorem two_cycle_solvable_of_left_distrib (hld : LeftDistrib A T)
    (p q : A) (b c : BExp T) (f1 f2 : Exp A T) :
    TwoCycleSolvable p q b c f1 f2 := by
  let pq : Exp A T := .seq (.act p) (.act q)
  let REST : Exp A T := .ite b (.seq (.act p) f2) f1
  let d : BExp T := .and c b
  let g1 : Exp A T := .seq (.wh d pq) REST
  let g2 : Exp A T := .ite c (.seq (.act q) g1) f2
  refine ⟨g1, g2, ?_, Equiv.refl _⟩
  -- Step A: g₁ ≡ if d then pq·g₁ else REST   (the unary loop solves its equation)
  have stepA : Equiv g1 (.ite d (.seq pq g1) REST) :=
    salomaa_solution_exists d pq REST
  -- Step B: (if b then p·g₂ else f₁) ≡ if d then pq·g₁ else REST
  have hstep : Equiv (.seq (.act p) (.ite c (.seq (.act q) g1) f2))
      (.ite c (.seq pq g1) (.seq (.act p) f2)) :=
    Equiv.trans (hld p c (.seq (.act q) g1) f2)
      (Equiv.ite_c (Equiv.s1 (.act p) (.act q) g1).symm (Equiv.refl _))
  have stepB : Equiv (.ite b (.seq (.act p) (.ite c (.seq (.act q) g1) f2)) f1)
      (.ite d (.seq pq g1) REST) :=
    Equiv.trans (Equiv.ite_c hstep (Equiv.refl _))
      (Equiv.u3 c b (.seq pq g1) (.seq (.act p) f2) f1)
  show Equiv g1 (.ite b (.seq (.act p) g2) f1)
  exact Equiv.trans stepA stepB.symm

end GkatFrontier
