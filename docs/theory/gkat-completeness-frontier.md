# The GKAT completeness frontier: general-n existence

This note states precisely where GKAT completeness stands, why the remaining piece
(existence of solutions to general n-state systems) is hard, and what our
formalization contributes. It complements `docs/theory/gkat-fixed-point.md`.

## The completeness argument, and Pham's reduction

GKAT equivalence is decided by: each expression → a **G-automaton** → a **Salomaa
system of equations**; two bisimilar expressions solve the *same* system; the
**Uniqueness Axiom (UA)** makes them provably equal. Completeness of the finite
axiom system has been open since Smolka et al. (2019).

A Salomaa system for an automaton `(X, β)` assigns each state `x` an equation
`τ(x) = +_α ( ⨁_d β(x)_α(d) · sys(d) )` — a guarded sum, over atoms `α`, of the
transitions out of `x`. It is **Salomaa** (productive) when each prefix
coefficient `g` satisfies `E(g)_α = 0` ("cannot terminate immediately"), so loops
make progress. **Pham (2026)** proved **uniqueness** of solutions to
Thompson-generated systems and reduced completeness to the remaining half:
**existence** of a provable solution.

## What is solved, and the exact gap

- **Kleene theorem (solved).** Smolka et al. identified the class of **well-nested**
  G-automata: every GKAT expression yields a well-nested automaton, and every
  well-nested automaton is expressible by a GKAT term. So for well-nested systems,
  a solution exists.
- **The gap.** Bisimulation of two expressions yields a **general** n-state system
  (a product/pairing automaton), which need **not** be well-nested. Whether such a
  system has a *provable* GKAT solution is open.

### Why it is hard — the one unsound law

Classical Kleene-algebra completeness reduces an arbitrary n-state system to the
**unary** case by **left-distributivity of sequencing over branching**:

> `p · (a +_c b) ≡ (p·a) +_c (p·b)`

This is Gaussian elimination: distribute, collect, solve one variable at a time.
**In GKAT this law is unsound** under bisimulation semantics — an action `p` can
change the current atom, so the test `c` (read *after* `p`) cannot be factored to
*before* `p`. GKAT deliberately lacks it (it also lacks unrestricted `+`). So:

- the **unary** case is solvable — it is exactly the loop, `e^(b)·f` solves
  `g ≡ e·g +_b f` (our `GkatSyntax.salomaa_solution_exists`);
- but the **n → unary reduction** is blocked, because it needs left-distributivity.

Pham's UA handles the unary equation; the missing piece is a *non-distributive*
way to solve n-state systems (or an extended syntax with `goto`, as the weighted-
GKAT work notes). That is the open frontier.

## What we contribute (machine-checked)

`crates/portcullis-core/lean/GkatFrontierProofs.lean` pins the frontier for the
smallest non-trivial case, **n = 2**:

- `LeftDistrib` — the (unsound, non-GKAT) left-distribution law, as a `Prop`.
- `TwoCycleSolvable` — the 2-state cyclic system `x₁ ≡ p·x₂ +_b f₁`,
  `x₂ ≡ q·x₁ +_c f₂` has a provable GKAT solution.
- `two_cycle_solvable_of_left_distrib` — **given `LeftDistrib`, the 2-cycle is
  solvable**, by eliminating the second state and solving one loop
  (`salomaa_solution_exists`). The proof depends on **no axioms** and uses
  `LeftDistrib` and nothing else — *not even guardedness*. So **n = 2 existence
  reduces exactly to the one unsound law.**

This is not a proof of general-n existence (open), nor a proof that `LeftDistrib`
fails — that needs a ≥2-atom guarded-string model, the classical fact we cite. It
localizes the obstruction: existence is blocked precisely at, and only at, the law
GKAT cannot soundly have. A real attack must either (a) find a non-distributive
elimination that solves n-state systems using only sound GKAT reasoning, or
(b) extend the syntax past well-structured control flow.

## Sources
- [GKAT (POPL'20), arXiv:1907.05920](https://arxiv.org/abs/1907.05920) — syntax,
  axioms, the Kleene theorem, well-nested automata.
- [Coequations, Coinduction, and Completeness (ICALP'21), arXiv:2102.08286](https://arxiv.org/abs/2102.08286)
  — systems of equations, uniqueness, the guardedness side condition.
- [A Complete Inference System for Skip-free GKAT (FoSSaCS'23), arXiv:2301.11301](https://arxiv.org/abs/2301.11301).
- [Weighted GKAT: Completeness and Complexity (ICALP'25), arXiv:2504.20385](https://arxiv.org/abs/2504.20385)
  — the Salomaa-system solving construction and the left-distributivity obstruction.
- [Toward a Completeness Theorem for GKAT, Pham 2026](https://digitalcommons.bucknell.edu/honors_theses/754/)
  — the single loop axiom, uniqueness for Thompson systems, reduction to existence.
