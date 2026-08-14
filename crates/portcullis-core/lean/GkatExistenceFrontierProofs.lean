import GkatSyntaxProofs

/-!
# Where the LeftDistrib obstruction bites: n=2 existence WITHOUT left-distribution

`GkatFrontierProofs.two_cycle_solvable_of_left_distrib` showed the existence half of
the n=2 (mutual-recursion) case of GKAT completeness reduces to `LeftDistrib`
`p·(a +_c b) ≡ p·a +_c p·b`, and `GkatGuardedStringProofs.left_distrib_not_gkat_theorem`
showed `LeftDistrib` is not a GKAT theorem — so the textbook Gaussian-elimination
route to solving the two-state system is genuinely blocked.

But that route uses `LeftDistrib` to expand `e₀·(e₁·g₀ +_{b₁} f₁)` — pushing the
prefix `e₀` past the *inner branch* `+_{b₁}`. That branch only exists if **state 1
itself branches**. This file maps the boundary: when state 1 is a **pure
continuation** — its equation is `g₁ ≡ e₁·g₀`, no guarded exit — the elimination
goes through by **associativity (S1) alone**, and the system collapses to a single
loop that `W3` solves. No `LeftDistrib`.

`two_state_existence_pure_return` (below) proves it, syntactically, from the GKAT
axioms: `g₀ ≡ (e₀·e₁)^(b₀)·f₀`, using only congruence, `S1`, and `W3`. Its dual
`two_state_existence_pure_head` handles a non-branching state 0.

**Consequence / boundary.** The `LeftDistrib` obstruction to n=2 existence is
confined to **genuinely two-exit** mutual recursion — where BOTH states have a
guarded exit (the non-well-nested "early return from a nested loop" pattern). The
moment either state is deterministic, existence holds constructively without
`LeftDistrib`. This does not solve the open case (both states branching); it sharply
delimits it. The two theorems depend on **no axioms at all** — they are pure
derivations inside the GKAT equational system (congruence + S1 + W3), `sorryAx`-free.
-/

namespace GkatExistFrontier

open GkatSyntax

variable {A T : Type}

/-- **n=2 existence, pure-return case (no LeftDistrib).** For the two-state system

        g₀ ≡ e₀·g₁ +_{b₀} f₀        g₁ ≡ e₁·g₀   (state 1 does NOT branch),

    `g₀` is provably the single loop `(e₀·e₁)^(b₀)·f₀`, given productivity of the
    composite body `e₀·e₁`. The elimination `e₀·g₁ ≡ e₀·(e₁·g₀) ≡ (e₀·e₁)·g₀` uses
    only congruence + `S1` (associativity), NOT `LeftDistrib`; then `W3` closes it. -/
theorem two_state_existence_pure_return
    {b0 : BExp T} {e0 e1 f0 g0 g1 : Exp A T}
    (hguard : Equiv (Exp.test (E (Exp.seq e0 e1)) : Exp A T) (.test .zero))
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.seq e1 g0)) :
    Equiv g0 (.seq (.wh b0 (.seq e0 e1)) f0) := by
  -- g0 ≡ ite b0 (e0·g1) f0 ≡ ite b0 (e0·(e1·g0)) f0 ≡ ite b0 ((e0·e1)·g0) f0
  have step : Equiv g0 (.ite b0 (.seq (.seq e0 e1) g0) f0) :=
    Equiv.trans h0
      (Equiv.ite_c
        (Equiv.trans (Equiv.seq_c (Equiv.refl e0) h1)
          (Equiv.symm (Equiv.s1 e0 e1 g0)))
        (Equiv.refl f0))
  -- single-state fixpoint (W3): g0 ≡ (e0·e1)^(b0) · f0
  exact salomaa_solution_unique hguard step

/-- **n=2 existence, pure-head case (no LeftDistrib).** Dual: if state 0 does not
    branch (`g₀ ≡ e₀·g₁`) and state 1 branches (`g₁ ≡ e₁·g₀ +_{b₁} f₁`), then `g₁` is
    the single loop `(e₁·e₀)^(b₁)·f₁`. Same S1-only elimination. -/
theorem two_state_existence_pure_head
    {b1 : BExp T} {e0 e1 f1 g0 g1 : Exp A T}
    (hguard : Equiv (Exp.test (E (Exp.seq e1 e0)) : Exp A T) (.test .zero))
    (h0 : Equiv g0 (.seq e0 g1))
    (h1 : Equiv g1 (.ite b1 (.seq e1 g0) f1)) :
    Equiv g1 (.seq (.wh b1 (.seq e1 e0)) f1) := by
  have step : Equiv g1 (.ite b1 (.seq (.seq e1 e0) g1) f1) :=
    Equiv.trans h1
      (Equiv.ite_c
        (Equiv.trans (Equiv.seq_c (Equiv.refl e1) h0)
          (Equiv.symm (Equiv.s1 e1 e0 g1)))
        (Equiv.refl f1))
  exact salomaa_solution_unique hguard step

/-- Non-vacuity: the pure-return elimination relates syntactically DISTINCT terms
    (the solution `g₀` is not literally its own loop form), so the theorems above are
    genuine derivations, not reflexivity. -/
example :
    (Exp.seq (Exp.act ()) (Exp.act ()) : Exp Unit Unit) ≠
      Exp.seq (Exp.wh (BExp.prim ()) (Exp.seq (Exp.act ()) (Exp.act ()))) (Exp.act ()) := by
  decide

#print axioms two_state_existence_pure_return
#print axioms two_state_existence_pure_head

end GkatExistFrontier
