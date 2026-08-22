import GkatExistenceFrontierProofs
import GkatFaithfulnessProofs
import GkatGuardedAlgebraProofs
import GkatDecidedUAProofs

/-!
# Narrowing the n=2 existence frontier

`GkatExistFrontier` established the sharp boundary for two-state existence: the textbook
Gaussian-elimination route needs `LeftDistrib`, which is *not* a GKAT theorem, but the
elimination goes through by associativity and `W3` alone whenever one state is a **pure
continuation** — no guarded exit.  So the obstruction is confined to genuinely two-exit
mutual recursion.

This file narrows that remaining case further.  A state whose exit guard is *degenerate* is
not genuinely two-exit, even though it is written with a branch:

* a **tautologous** guard collapses the state to a pure continuation, and the frontier's
  own theorem then applies;
* an **unsatisfiable** guard removes the recursion altogether, and the system solves
  directly with no fixpoint rule at all.

A third case is narrower still and comes from the other side of the blocked step.  The
elimination is blocked because a prefix cannot be pushed past an inner guarded choice, but
that push *is* a theorem when the prefix is an assertion (`test_seq_ite`).  So a system one
of whose bodies is a test eliminates after all.

A fourth slice comes from the guard-pullback machinery.  `crossed_closed_form_of_pullbackBA`
already derives a closed form from a pullback witness — that is *existence*, not merely
uniqueness — and a witness exists whenever the crossing is **decided**.  The repository
states the uniqueness consequence; since existence is the whole remainder, the existence
consequence is stated here.

What is left open at two states is therefore mutual recursion in which both guards are
properly satisfiable **and** refutable, neither body is a test, **and** the crossing is
undecided — the prefix neither always establishes the other state's guard nor never does.
Nothing degenerate anywhere, on any of the three axes.

All five theorems depend on **no axioms at all** — like the frontier's own, they are pure
derivations inside the GKAT equational system.
-/

namespace GkatExistenceNarrow

open GkatSyntax GkatGS GkatFaithful GkatExistFrontier GkatGuardedAlgebra
open GkatDecidedUA GkatDecidedPullback

variable {A T : Type}

/-! ## Degenerate guards collapse a branch -/

/-- A tautologous guard collapses a conditional to its then-branch. -/
theorem ite_of_taut {b : BExp T} (x y : Exp A T)
    (htaut : ∀ (X : Type) (W : T → X → Bool) (z : X), bval W b z = true) :
    EquivBA (.ite b x y) x :=
  EquivBA.trans
    (EquivBA.ite_guard (b := b) (c := BExp.one) (e := x) (f := y)
      (fun X W z => by rw [htaut X W z]; rfl))
    (ite_one x y)

/-- An unsatisfiable guard collapses a conditional to its else-branch. -/
theorem ite_of_unsat {b : BExp T} (x y : Exp A T)
    (hunsat : ∀ (X : Type) (W : T → X → Bool) (z : X), bval W b z = false) :
    EquivBA (.ite b x y) y :=
  EquivBA.trans
    (EquivBA.ite_guard (b := b) (c := BExp.zero) (e := x) (f := y)
      (fun X W z => by rw [hunsat X W z]; rfl))
    (EquivBA.base (ite_zero x y))

/-! ## The two narrowed cases -/

/-- **Tautologous exit ⇒ existence.**  If state 1's branch guard is a tautology, state 1 is
    a pure continuation in disguise, and the single loop `(e₀·e₁)^(b₀)·f₀` solves the
    system — by associativity and `W3`, with no `LeftDistrib`. -/
theorem two_state_existence_taut_exit
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 : Exp A T}
    (hguard : EquivBA (Exp.test (E (Exp.seq e0 e1)) : Exp A T) (.test .zero))
    (htaut : ∀ (X : Type) (W : T → X → Bool) (z : X), bval W b1 z = true)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1)) :
    EquivBA g0 (.seq (.wh b0 (.seq e0 e1)) f0) := by
  have h1' : EquivBA g1 (.seq e1 g0) :=
    EquivBA.trans h1 (ite_of_taut (.seq e1 g0) f1 htaut)
  have step : EquivBA g0 (.ite b0 (.seq (.seq e0 e1) g0) f0) :=
    EquivBA.trans h0
      (EquivBA.ite_c
        (EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl e0)) h1')
          (EquivBA.symm (EquivBA.base (Equiv.s1 e0 e1 g0))))
        (EquivBA.base (Equiv.refl f0)))
  exact EquivBA.w3_ba hguard step

/-- **Unsatisfiable exit ⇒ existence, without any fixpoint rule.**  If state 1's branch
    guard is unsatisfiable, the recursion never returns to state 0: the system is not
    mutually recursive at all and `g₀` is solved outright. -/
theorem two_state_existence_unsat_exit
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 : Exp A T}
    (hunsat : ∀ (X : Type) (W : T → X → Bool) (z : X), bval W b1 z = false)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1)) :
    EquivBA g0 (.ite b0 (.seq e0 f1) f0) :=
  EquivBA.trans h0
    (EquivBA.ite_c
      (EquivBA.seq_c (EquivBA.base (Equiv.refl e0))
        (EquivBA.trans h1 (ite_of_unsat (.seq e1 g0) f1 hunsat)))
      (EquivBA.base (Equiv.refl f0)))

/-- The dual of `two_state_existence_taut_exit`, collapsing state 0 instead. -/
theorem two_state_existence_taut_head
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 : Exp A T}
    (hguard : EquivBA (Exp.test (E (Exp.seq e1 e0)) : Exp A T) (.test .zero))
    (htaut : ∀ (X : Type) (W : T → X → Bool) (z : X), bval W b0 z = true)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1)) :
    EquivBA g1 (.seq (.wh b1 (.seq e1 e0)) f1) := by
  have h0' : EquivBA g0 (.seq e0 g1) :=
    EquivBA.trans h0 (ite_of_taut (.seq e0 g1) f0 htaut)
  have step : EquivBA g1 (.ite b1 (.seq (.seq e1 e0) g1) f1) :=
    EquivBA.trans h1
      (EquivBA.ite_c
        (EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl e1)) h0')
          (EquivBA.symm (EquivBA.base (Equiv.s1 e1 e0 g1))))
        (EquivBA.base (Equiv.refl f1)))
  exact EquivBA.w3_ba hguard step

#print axioms ite_of_taut
#print axioms ite_of_unsat
#print axioms two_state_existence_taut_exit
#print axioms two_state_existence_unsat_exit
#print axioms two_state_existence_taut_head

/-! ## A test prefix distributes, so the blocked step is not blocked there

    The elimination is blocked because a prefix cannot be pushed past an inner guarded
    choice — `LeftDistrib` is not a GKAT theorem.  But it *is* a theorem when the prefix is
    an assertion: `test_seq_ite` pushes a test through a conditional, paying only a
    conjunction on the guard.  So a two-state system whose first body is a test eliminates
    after all, and the whole system collapses to a single loop. -/

/-- **Test-prefix ⇒ existence.**  If the step from state 0 to state 1 is an assertion, the
    blocked distribution step becomes `test_seq_ite`, `U3` re-associates the nested choice,
    and `W3` closes the resulting single-state loop:

        g₀ ≡ (e₁)^((c ∧ b₁) ∧ b₀) · (b₀ ? (c · f₁) : f₀)

    No `LeftDistrib`, and the loop body is the *other* state's body. -/
theorem two_state_existence_test_head
    {b0 b1 c : BExp T} {e1 f0 f1 g0 g1 : Exp A T}
    (hguard : EquivBA (Exp.test (E e1) : Exp A T) (.test .zero))
    (h0 : EquivBA g0 (.ite b0 (.seq (.test c) g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1)) :
    EquivBA g0
      (.seq (.wh (.and (.and c b1) b0) e1)
        (.ite b0 (.seq (.test c) f1) f0)) := by
  have hpush : EquivBA (.seq (.test c) g1)
      (.ite (.and c b1) (.seq e1 g0) (.seq (.test c) f1)) :=
    EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl (.test c))) h1)
      (test_seq_ite c b1 (.seq e1 g0) f1)
  have hnest : EquivBA g0
      (.ite b0 (.ite (.and c b1) (.seq e1 g0) (.seq (.test c) f1)) f0) :=
    EquivBA.trans h0 (EquivBA.ite_c hpush (EquivBA.base (Equiv.refl f0)))
  have step : EquivBA g0
      (.ite (.and (.and c b1) b0) (.seq e1 g0)
        (.ite b0 (.seq (.test c) f1) f0)) :=
    EquivBA.trans hnest
      (EquivBA.base (Equiv.u3 (.and c b1) b0 (.seq e1 g0) (.seq (.test c) f1) f0))
  exact EquivBA.w3_ba hguard step

/-- The dual: an assertion stepping from state 1 back to state 0. -/
theorem two_state_existence_test_return
    {b0 b1 c : BExp T} {e0 f0 f1 g0 g1 : Exp A T}
    (hguard : EquivBA (Exp.test (E e0) : Exp A T) (.test .zero))
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq (.test c) g0) f1)) :
    EquivBA g1
      (.seq (.wh (.and (.and c b0) b1) e0)
        (.ite b1 (.seq (.test c) f0) f1)) := by
  have hpush : EquivBA (.seq (.test c) g0)
      (.ite (.and c b0) (.seq e0 g1) (.seq (.test c) f0)) :=
    EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl (.test c))) h0)
      (test_seq_ite c b0 (.seq e0 g1) f0)
  have hnest : EquivBA g1
      (.ite b1 (.ite (.and c b0) (.seq e0 g1) (.seq (.test c) f0)) f1) :=
    EquivBA.trans h1 (EquivBA.ite_c hpush (EquivBA.base (Equiv.refl f1)))
  have step : EquivBA g1
      (.ite (.and (.and c b0) b1) (.seq e0 g1)
        (.ite b1 (.seq (.test c) f0) f1)) :=
    EquivBA.trans hnest
      (EquivBA.base (Equiv.u3 (.and c b0) b1 (.seq e0 g1) (.seq (.test c) f0) f1))
  exact EquivBA.w3_ba hguard step

#print axioms two_state_existence_test_head
#print axioms two_state_existence_test_return

/-! ## Existence at decided crossings

    `crossed_closed_form_of_pullbackBA` already derives a *closed form* for the two-state
    system from a guard-pullback witness — that is existence, not merely uniqueness.  And
    `GkatDecidedUA` supplies the witness whenever the crossing is **decided**: the prefix
    either always establishes the guard, or never does.

    The repository states the *uniqueness* consequence of that (`ua2_eliminated_of_decided_*`).
    Since existence is the whole of what remains open, the existence consequence is worth
    stating too. -/

/-- **Existence at a `must` crossing.**  If the prefix `e₀` always establishes `b₁`, the
    pullback witness is `1` and the two-state system has the closed form outright. -/
theorem two_state_existence_of_must
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 : Exp A T}
    (hguard : EquivBA (.test (E (.seq e0 e1)) : Exp A T) (.test .zero))
    (hmust : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (mustTest e0 b1) x = true)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1)) :
    EquivBA g0
      (.seq (.wh (.and .one b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0)) :=
  crossed_closed_form_of_pullbackBA hguard (pullbackBA_one_of_must e0 b1 hmust) h0 h1

/-- **Existence at a `cannot` crossing.**  If the prefix can never establish `b₁`, the
    witness is `0` and the loop guard is unsatisfiable — the system solves with no
    iteration. -/
theorem two_state_existence_of_cannot
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 : Exp A T}
    (hguard : EquivBA (.test (E (.seq e0 e1)) : Exp A T) (.test .zero))
    (hcannot : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (cannotTest e0 b1) x = true)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1)) :
    EquivBA g0
      (.seq (.wh (.and .zero b0) (.seq e0 e1)) (.ite b0 (.seq e0 f1) f0)) :=
  crossed_closed_form_of_pullbackBA hguard (pullbackBA_zero_of_cannot e0 b1 hcannot) h0 h1

#print axioms two_state_existence_of_must
#print axioms two_state_existence_of_cannot

end GkatExistenceNarrow
