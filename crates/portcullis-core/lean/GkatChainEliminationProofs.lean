import GkatSyntaxProofs

/-!
# The n-ary decomposition: chain-elimination reduces a guarded cycle to `UA₁`

`GkatUAIndependenceProofs` decomposed the crossed *two*-state instance of the Uniqueness
Axiom as `UA₂ = UA₁ + a guard-pullback witness`. This file lifts that to the **full
scheme**: an `n`-state guarded cycle

    g₀ ≡ e₀·g₁ +_{b₀} f₀ ,  g₁ ≡ e₁·g₂ +_{b₁} f₁ ,  … ,  g_{n-1} ≡ e_{n-1}·g₀ +_{b_{n-1}} f_{n-1}

is reduced to a single `W3` (`UA₁`) loop by **iterating one kernel rule**, given a
guard-pullback witness at each crossing.

* `chain_elim` — the KERNEL: eliminate one intermediate state `g₁`, folding its equation
  into `g₀`'s so that `g₀` is expressed directly in terms of the *next* state `g₂`:

      g₀ ≡ (c₁∧b₀)?((e₀·e₁)·g₂):(b₀?(e₀·f₁):f₀).

  The witness `∀ x y, e₀·(b₁?x:y) ≡ c₁?(e₀·x):(e₀·y)` (i.e. `c₁ = wp(e₀,b₁)`) discharges
  the one step that would otherwise be `LeftDistrib`; the rest is congruence, `S1`, `U3`.
  This is exactly the reshaping of `crossed_closed_form_of_pullback`, now parametric in
  the continuation, hence composable.

* `three_cycle_solvable_of_pullbacks` — the kernel applied twice, then `W3`, solves a
  **3-state cycle**. The pattern `chain_elim^(n-1) ∘ W3` gives the general `n`: each
  witness folds one state, the composite body `e₀·e₁·…` and guard `c…∧b₀` accumulate, and
  a single productive loop remains. So `UAₙ = UA₁ + (n−1) guard-pullback witnesses`.

The pullback condition is stated inline (`∀ x y, …`) so this file is self-contained on
`GkatSyntaxProofs`. All theorems are pure derivations — `sorryAx`-free, NO axioms.
-/

namespace GkatChainElim

open GkatSyntax

variable {A T : Type}

/-- **The chain-elimination kernel.** Given `g₀ ≡ e₀·g₁ +_{b₀} f₀` and
    `g₁ ≡ e₁·g₂ +_{b₁} f₁`, plus a guard-pullback witness `c₁` for `(e₀,b₁)`, eliminate
    `g₁`: `g₀` is expressed directly over the *next* state `g₂` with the composite body
    `e₀·e₁`. Iterating this around a cycle collapses it to a single self-loop. -/
theorem chain_elim {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g0 g1 g2 : Exp A T}
    (hpb : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.ite b1 (.seq e1 g2) f1)) :
    Equiv g0 (.ite (.and c1 b0) (.seq (.seq e0 e1) g2) (.ite b0 (.seq e0 f1) f0)) :=
  Equiv.trans h0
  (Equiv.trans (Equiv.ite_c (Equiv.seq_c (Equiv.refl e0) h1) (Equiv.refl f0))
  (Equiv.trans (Equiv.ite_c (hpb (.seq e1 g2) f1) (Equiv.refl f0))
  (Equiv.trans
    (Equiv.ite_c (Equiv.ite_c (Equiv.symm (Equiv.s1 e0 e1 g2)) (Equiv.refl (.seq e0 f1)))
      (Equiv.refl f0))
    (Equiv.u3 c1 b0 (.seq (.seq e0 e1) g2) (.seq e0 f1) f0))))

/-- **Three-state cycle solved via two witnesses + `W3`.** The `n=3` instance of the
    n-ary decomposition: two applications of `chain_elim` fold `g₁` then `g₂` into a single
    productive self-loop on `g₀`, closed by `W3`. The witnesses are `c₁ = wp(e₀,b₁)` and
    `c₂ = wp(e₀·e₁, b₂)` (the second on the *composite* body — exactly what iterating the
    kernel produces). Generalizes `crossed_closed_form_of_pullback` (the n=2 case). -/
theorem three_cycle_solvable_of_pullbacks
    {b0 b1 b2 c1 c2 : BExp T} {e0 e1 e2 f0 f1 f2 g0 g1 g2 : Exp A T}
    (hguard : Equiv (Exp.test (E (.seq (.seq e0 e1) e2)) : Exp A T) (.test .zero))
    (hpb1 : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (hpb2 : ∀ x y : Exp A T,
      Equiv (.seq (.seq e0 e1) (.ite b2 x y))
            (.ite c2 (.seq (.seq e0 e1) x) (.seq (.seq e0 e1) y)))
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.ite b1 (.seq e1 g2) f1))
    (h2 : Equiv g2 (.ite b2 (.seq e2 g0) f2)) :
    Equiv g0
      (.seq (.wh (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2))
        (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0))) :=
  -- fold g₁ (g₀ now over g₂), then fold g₂ (g₀ now a self-loop), then W3
  salomaa_solution_unique hguard (chain_elim hpb2 (chain_elim hpb1 h0 h1) h2)

/-- **The reverse kernel (for EXISTENCE).** If `h` satisfies the *reduced* equation over
    the next state `g₂`, then `h` satisfies the *original* two-state form with the
    intermediate state reconstructed as `g₁ := b₁?(e₁·g₂):f₁`. This is `chain_elim`'s
    reshaping run backwards; iterating it rebuilds every intermediate state of the cycle,
    so the witness-built closed form provably SOLVES the system. -/
theorem chain_intro {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g2 h : Exp A T}
    (hpb : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (hred : Equiv h (.ite (.and c1 b0) (.seq (.seq e0 e1) g2) (.ite b0 (.seq e0 f1) f0))) :
    Equiv h (.ite b0 (.seq e0 (.ite b1 (.seq e1 g2) f1)) f0) :=
  Equiv.trans hred (Equiv.symm
    (Equiv.trans (Equiv.ite_c (hpb (.seq e1 g2) f1) (Equiv.refl f0))
    (Equiv.trans
      (Equiv.ite_c (Equiv.ite_c (Equiv.symm (Equiv.s1 e0 e1 g2)) (Equiv.refl (.seq e0 f1)))
        (Equiv.refl f0))
      (Equiv.u3 c1 b0 (.seq (.seq e0 e1) g2) (.seq e0 f1) f0))))

/-- **EXISTENCE for the 3-cycle (no productivity needed).** The witness-built closed form
    `CF` actually solves the 3-state cycle: reconstructing `g₂ := b₂?(e₂·CF):f₂` and
    `g₁ := b₁?(e₁·g₂):f₁`, `CF ≡ b₀?(e₀·g₁):f₀`. Two `chain_intro`s on top of the canonical
    loop solution (`salomaa_solution_exists`, which needs no side-condition) — the existence
    direction the completeness programme actually needs (Pham reduced completeness to
    existence). The `chain_intro^(n-1) ∘ salomaa_solution_exists` pattern gives general `n`. -/
theorem three_cycle_solves_of_pullbacks
    {b0 b1 b2 c1 c2 : BExp T} {e0 e1 e2 f0 f1 f2 : Exp A T}
    (hpb1 : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (hpb2 : ∀ x y : Exp A T,
      Equiv (.seq (.seq e0 e1) (.ite b2 x y))
            (.ite c2 (.seq (.seq e0 e1) x) (.seq (.seq e0 e1) y))) :
    let CF : Exp A T := .seq (.wh (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2))
              (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0))
    Equiv CF (.ite b0 (.seq e0 (.ite b1 (.seq e1 (.ite b2 (.seq e2 CF) f2)) f1)) f0) :=
  chain_intro hpb1 (chain_intro hpb2
    (salomaa_solution_exists (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2)
      (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0))))

#print axioms chain_elim
#print axioms chain_intro
#print axioms three_cycle_solvable_of_pullbacks
#print axioms three_cycle_solves_of_pullbacks

end GkatChainElim
