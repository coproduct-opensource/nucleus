import GkatTotalizationProofs

/-!
# W0 — the single loop axiom, derived

Pham's thesis (*Toward Completeness Theorem for Guarded Kleene Algebra with Tests*, Bucknell,
2026) proposes replacing Smolka et al.'s three loop axioms W1, W2, W3 by a single axiom

    (W0)    g ≡ E(e)‾ · e · g +_b f   ⟺   g ≡ e^(b) · f

and shows W1, W2 and W3 are all derivable from it.  The guard `E(e)‾` is what makes the naive
version sound: without it, `g := 1`, `e := 1`, `f := 1` satisfies `1 ≡ 1 · 1 +_b 1` and would
force `1 ≡ 1^(b) · 1`, which is false — a loop whose body can terminate immediately under the
same atom that opens the loop diverges rather than terminating.

This file establishes the converse direction, which the thesis does not need but which
settles the relationship between the two axiom sets: **W0 is derivable from W1–W3**, so the
two systems are interderivable and the reduction to a single axiom costs no strength.

This bears on the SECOND of the two open questions the literature poses about the finite
system.  They are stated together: "can the uniqueness axiom be eliminated?" and "can we
eliminate the guardedness side condition?"  The side condition is `w3`'s `E(e) ≡ 0`, and it
cannot simply be dropped — the unguarded rule is UNSOUND, as the `g := 1, e := 1, f := 1`
witness below shows.  What W0 does is INTERNALISE it: the restriction moves from a side
condition into the equation, and `w0` proves that internalised form is derivable from W1–W3.
So the side condition costs no strength and can be traded for a guard inside the axiom, which
is a positive partial answer to the second question rather than to the first.

That matters here for a specific reason.  Every completeness result in this development is
stated over W1–W3, and W0 is *prima facie* stronger: the `w3` constructor carries the side
condition `E(e) ≡ 0` ("`e` is strictly productive"), whereas W0 carries no side condition at
all — it builds the restriction into the equation instead.  If W0 were genuinely stronger,
results proved from it would assume more than results proved here.  They do not.

The derivation turns on one lemma that is already available: `test_restrict`, which says
`b ≤ E(e) → b? · e ≡ b?`.  Instantiated at `b := E(e)` it gives `E(e)? · e ≡ E(e)?`, hence

    e  ≡  e  +_{E(e)‾}  1

— under the atoms where `e` halts immediately, `e` *is* `1`, provably.  W2 then converts that
into the restricted-body form, and `w3` supplies uniqueness because the restricted body
`E(e)‾? · e` is strictly productive by construction.
-/

namespace GkatW0

open GkatSyntax GkatGS GkatFaithful GkatTotalization

variable {A T : Type}

/-- The restricted loop body `E(e)‾? · e` that W0 uses in place of `e`. -/
def guardedBody (e : Exp A T) : Exp A T :=
  .seq (.test (.not (E e))) e

/-! ## The restricted body is strictly productive

    This is the whole reason W0 needs no side condition: `E(E(e)‾? · e) = E(e)‾ ∧ E(e) = 0`
    holds by Boolean algebra, so `w3` always applies to the restricted body. -/

/-- `E` of the restricted body is `0` — the `w3` side condition, discharged by BA alone. -/
theorem E_guardedBody (e : Exp A T) :
    EquivBA (.test (E (guardedBody e)) : Exp A T) (.test .zero) := by
  refine EquivBA.baTest ?_
  intro X W x
  show (!bval W (E e) x && bval W (E e) x) = false
  cases bval W (E e) x <;> rfl

/-! ## Under `E(e)`, the program `e` is provably `1` -/

/-- **`e ≡ 1 +_{E(e)} e`.**  On the atoms where `e` may halt without acting it *does* halt
    without acting, and that is provable rather than merely true in the model: `u4` moves the
    guard onto the branch, `test_restrict` collapses `E(e)? · e` to `E(e)?`, and `s6` plus BA
    identify `E(e)? ` with `E(e)? · 1`. -/
theorem split_on_E (e : Exp A T) :
    EquivBA e (.ite (E e) (.test .one) e) := by
  -- e ≡ e +_{E(e)} e
  have h1 : EquivBA e (.ite (E e) e e) := EquivBA.symm (EquivBA.base (Equiv.u1 (E e) e))
  -- push the guard onto the then-branch
  have h2 : EquivBA (.ite (E e) e e : Exp A T)
      (.ite (E e) (.seq (.test (E e)) e) e) :=
    EquivBA.base (Equiv.u4 (E e) e e)
  -- E(e)? · e ≡ E(e)?
  have h3 : EquivBA (.seq (.test (E e)) e : Exp A T) (.test (E e)) :=
    test_restrict e (E e) (fun _ _ _ h => h)
  -- and E(e)? ≡ E(e)? · 1, so the then-branch is 1 under its own guard
  have h4 : EquivBA (.test (E e) : Exp A T) (.seq (.test (E e)) (.test .one)) :=
    EquivBA.symm (EquivBA.trans (EquivBA.s6 (E e) .one)
      (EquivBA.baTest (fun X W x => by
        show (bval W (E e) x && true) = bval W (E e) x
        cases bval W (E e) x <;> rfl)))
  have h5 : EquivBA (.ite (E e) (.seq (.test (E e)) (.test .one)) e : Exp A T)
      (.ite (E e) (.test .one) e) :=
    EquivBA.symm (EquivBA.base (Equiv.u4 (E e) (.test .one) e))
  exact EquivBA.trans h1 (EquivBA.trans h2
    (EquivBA.trans (EquivBA.ite_c (EquivBA.trans h3 h4) (EquivBA.base (Equiv.refl e))) h5))

/-- The same fact in W2's shape: `e ≡ e +_{E(e)‾} 1`. -/
theorem split_on_E' (e : Exp A T) :
    EquivBA e (.ite (.not (E e)) e (.test .one)) :=
  EquivBA.trans (split_on_E e) (EquivBA.base (Equiv.u2 (E e) (.test .one) e))

/-! ## Restricting the body does not change the loop -/

/-- **`e^(b) ≡ (E(e)‾? · e)^(b)`.**  Immediate from `split_on_E'` under `wh_c`, followed by
    W2 — which is exactly the tightening law, used in the direction that installs the guard. -/
theorem wh_guardedBody (b : BExp T) (e : Exp A T) :
    EquivBA (.wh b e : Exp A T) (.wh b (guardedBody e)) :=
  EquivBA.trans (EquivBA.wh_c (split_on_E' e))
    (EquivBA.base (Equiv.w2 b (.not (E e)) e))

/-! ## W0, both directions -/

/-- **W0, uniqueness direction.**  Any solution of the *restricted* Salomaa equation is
    `e^(b) · f` — with no productivity side condition, because the restricted body supplies
    it.  This is the half of W0 that looks stronger than `w3`, and it is not. -/
theorem w0_unique {b : BExp T} {e f g : Exp A T}
    (hsol : EquivBA g (.ite b (.seq (guardedBody e) g) f)) :
    EquivBA g (.seq (.wh b e) f) :=
  EquivBA.trans (EquivBA.w3_ba (E_guardedBody e) hsol)
    (EquivBA.seq_c (EquivBA.symm (wh_guardedBody b e)) (EquivBA.base (Equiv.refl f)))

/-- **W0, existence direction.**  `e^(b) · f` does solve the restricted equation.

    Note that `e ≡ E(e)‾? · e` is *false* — off the guard the left side is `e` and the right
    side is `0` — so the body cannot simply be rewritten in place.  The move is to rewrite the
    *loop* first, by `wh_guardedBody`, and then apply ordinary W1-existence to the restricted
    body, which is where the restriction is legitimate. -/
theorem w0_exists (b : BExp T) (e f : Exp A T) :
    EquivBA (.seq (.wh b e) f : Exp A T)
      (.ite b (.seq (guardedBody e) (.seq (.wh b e) f)) f) := by
  -- e^(b) · f ≡ G^(b) · f, where G is the restricted body
  have hloop : EquivBA (.seq (.wh b e) f : Exp A T) (.seq (.wh b (guardedBody e)) f) :=
    EquivBA.seq_c (wh_guardedBody b e) (EquivBA.base (Equiv.refl f))
  -- G^(b) · f ≡ G · (G^(b) · f) +_b f, by W1-existence at the restricted body
  have hstep : EquivBA (.seq (.wh b (guardedBody e)) f : Exp A T)
      (.ite b (.seq (guardedBody e) (.seq (.wh b (guardedBody e)) f)) f) :=
    EquivBA.base (salomaa_solution_exists b (guardedBody e) f)
  -- and back: the inner occurrence returns to e^(b) · f
  have hback : EquivBA (.seq (.wh b (guardedBody e)) f : Exp A T) (.seq (.wh b e) f) :=
    EquivBA.symm hloop
  exact EquivBA.trans hloop (EquivBA.trans hstep
    (EquivBA.ite_c (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hback) (EquivBA.base (Equiv.refl f))))

/-- **W0 is derivable from W1–W3.**  Both directions of the biconditional, packaged.

    With the thesis's converse — W1, W2 and W3 all derivable from W0 — the two axiom systems
    are interderivable.  So the completeness statements in this development, which are proved
    over W1–W3, assume exactly what a development over W0 would assume. -/
theorem w0 (b : BExp T) (e f : Exp A T) (g : Exp A T) :
    (EquivBA g (.ite b (.seq (guardedBody e) g) f) → EquivBA g (.seq (.wh b e) f)) ∧
      EquivBA (.seq (.wh b e) f : Exp A T)
        (.ite b (.seq (guardedBody e) (.seq (.wh b e) f)) f) :=
  ⟨fun h => w0_unique h, w0_exists b e f⟩

#print axioms E_guardedBody
#print axioms split_on_E
#print axioms wh_guardedBody
#print axioms w0_unique
#print axioms w0_exists
#print axioms w0

end GkatW0
