import GkatRefinesProofs
import GkatGuardedAlgebraProofs

/-!
# The residue, discharged — pair #3 proved without the uniqueness axiom

The measurement programme in `experiments/gkat-crystallization/span-search` reduces the
instance space (`NA = 2`, `K = 5`, 9245 language-equivalent pairs) to **eight** pairs that
neither the published skip-free completeness result nor any sound witness in the harness
discharges.  Recovered from the closure's provenance and written in GKAT syntax, pair #3 is

    e = ( p ; ( ((0 +_b p) ; p^(¬b))            +_{¬b} p ) )^(¬b)
    f = ( p ; ( ((0 +_b p) ; (b +_b p))^(¬b)    +_{¬b} p ) )^(¬b)

— identical but for one subterm: `A ; B^(g)` on the left against `(A ; C)^(g)` on the right.
That is a loop-restructuring identity of exactly the kind the uniqueness axiom supplies, and
it is not obvious that W1–W3 reach it.  They do.  This file proves it.

## The derivation

Write `nb` for `¬b`, `A = 0 +_b p`, `C = b +_b p`, `D = p +_{nb} 1`.  Then

  1. `C ≡ D`                       — under `b` the tests `b` and `1` agree (U4, S6, BA), then U2.
  2. `A ; C ≡ nb? · (p ; D)`       — U2 turns `A` into `p +_{nb} 0`, U5 pushes `D` through the
                                      choice, S2 kills the failing arm, and a guarded choice
                                      with a failing else arm *is* an assertion.
  3. `(A;C)^(nb) ≡ p^(nb)`         — `wh_restrict_body` strips the assertion from the loop body,
                                      leaving `(p ; D)^(nb)`.  And `p ; D` is literally
                                      `expK nb p 1`, so `Refines.cyc` — the degree-2 cyclic
                                      cover, already proved as `cyclicCoverExp` — collapses it.
  4. the two `ite` arms agree      — under `nb`, `A ≡ p` and W1 unrolls `p^(nb)` to `p · p^(nb)`,
                                      so both sides reduce to `nb? · (p · p^(nb))`.

Step 3 is the one that matters.  The two programs differ by *where the iteration boundary
falls*, and the cyclic-cover refinement is precisely a change of iteration granularity.  The
harness never found this because its soundness test admits only two witness shapes —
an elimination order, or a Thompson automaton somewhere in the congruence lattice — and a
`Refines`-chain is neither, even though `equivBA_of_refines` has been in the corpus all along.

## Scope

This discharges **one** of the eight, for arbitrary `b` and arbitrary productive `p`.  It is
not a completeness proof and does not bear on the other seven, whose shapes differ.  What it
does show is that the residue is not uniformly obstructed: at least one member of it falls to
the finite axioms, by a route the measurement was blind to.
-/

namespace GkatResidue

open GkatSyntax GkatGS GkatFaithful GkatGuardedAlgebra GkatCyclicK GkatRefines

variable {A T : Type}

/-! ## Three lemmas the derivation needs -/

/-- **Under its own guard, the test `b` is the test `1`.**  `U4` asserts the guard on the then
    arm, `S6` merges the two tests, and Boolean algebra identifies `b ∧ b` with `b ∧ 1`. -/
theorem ite_then_test (b : BExp T) (X : Exp A T) :
    EquivBA (.ite b (.test b) X) (.ite b (.test .one) X) :=
  EquivBA.trans (EquivBA.base (Equiv.u4 b (.test b) X))
    (EquivBA.trans
      (EquivBA.ite_c
        (EquivBA.trans (EquivBA.s6 b b)
          (EquivBA.trans
            (EquivBA.baTest (fun _ W x => by
              show (bval W b x && bval W b x) = (bval W b x && true)
              cases bval W b x <;> rfl))
            (EquivBA.symm (EquivBA.s6 b .one))))
        (EquivBA.base (Equiv.refl X)))
      (EquivBA.symm (EquivBA.base (Equiv.u4 b (.test .one) X))))

/-- **A loop may assert its own guard at the top of the body.**

    `e^(b) ≡ (b? · e)^(b)` whenever `e` is productive.  This is not W2 — W2 exchanges a
    guarded *choice* in the body for an assertion, and says nothing about the loop guard
    itself.  The proof runs through `w3`: W1 unrolls the restricted loop, `S1` re-associates
    so the assertion sits in front of the whole continuation, and `U4` then *removes* it,
    because a `ite b _ _` may always assert `b` on its then arm.  What is left is the Salomaa
    equation for `e^(b)`, and `w3` — applicable because `e` is productive — identifies its
    solution.

    Productivity is genuinely needed, not an artefact: for `e := 1` and `b := 1` the left side
    is `1^(1)`, which diverges, and the right side is `(1? · 1)^(1)`, which also diverges — but
    the *equation* `w3` would solve has other solutions, and without the side condition the
    rule is unsound (see `GkatW0Proofs`). -/
theorem wh_restrict_body {b : BExp T} {e : Exp A T}
    (hE : EquivBA (.test (E e) : Exp A T) (.test .zero)) :
    EquivBA (.wh b e : Exp A T) (.wh b (.seq (.test b) e)) := by
  have hsol : EquivBA (.wh b (.seq (.test b) e) : Exp A T)
      (.ite b (.seq e (.wh b (.seq (.test b) e))) (.test .one)) :=
    EquivBA.trans (EquivBA.base (Equiv.w1 b (.seq (.test b) e)))
      (EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.s1 _ _ _)) (EquivBA.base (Equiv.refl _)))
        (EquivBA.symm (EquivBA.base (Equiv.u4 b _ _))))
  exact EquivBA.symm (EquivBA.trans (EquivBA.w3_ba hE hsol) (seq_one _))

/-- **An assertion selects the else arm of the choice it contradicts.**  The mirror of
    `test_seq_ite_of_implies`, obtained by flipping the choice with `U2`. -/
theorem test_seq_ite_else (b : BExp T) (e f : Exp A T) :
    EquivBA (.seq (.test (.not b)) (.ite b e f)) (.seq (.test (.not b)) f) :=
  EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.u2 b e f)))
    (test_seq_ite_of_implies (b := .not b) (z := .not b) f e (fun _ _ _ h => h))

/-! ## The pair -/

/-- `A = 0 +_b p` — fail under `b`, run `p` otherwise. -/
def resA (b : BExp T) (p : Exp A T) : Exp A T := .ite b (.test .zero) p

/-- `C = b +_b p` — assert `b` under `b`, run `p` otherwise. -/
def resC (b : BExp T) (p : Exp A T) : Exp A T := .ite b (.test b) p

/-- `D = p +_{¬b} 1`, the second factor of `expK ¬b p 1`. -/
def resD (b : BExp T) (p : Exp A T) : Exp A T := .ite (.not b) p (.test .one)

/-- `expK (¬b) p 1` is exactly `p ; D`, by unfolding alone. -/
theorem expK_one (b : BExp T) (p : Exp A T) :
    expK (.not b) p 1 = .seq p (resD b p) := rfl

/-- **Step 1.**  `C ≡ D`. -/
theorem resC_eq_resD (b : BExp T) (p : Exp A T) :
    EquivBA (resC b p) (resD b p) :=
  EquivBA.trans (ite_then_test b p) (EquivBA.base (Equiv.u2 b (.test .one) p))

/-- **Step 2.**  `A ; C ≡ ¬b? · (p ; D)`.  The body of `f`'s inner loop is the body of
    `expK ¬b p 1`, asserted under the loop guard. -/
theorem resA_seq_resC (b : BExp T) (p : Exp A T) :
    EquivBA (.seq (resA b p) (resC b p))
      (.seq (.test (.not b)) (.seq p (resD b p))) := by
  -- A ; C ≡ A ; D
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (resC_eq_resD b p)) ?_
  -- A ≡ p +_{¬b} 0, so A ; D ≡ (p;D) +_{¬b} (0;D)
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.u2 b (.test .zero) p))
      (EquivBA.base (Equiv.refl _))) ?_
  refine EquivBA.trans (ite_seq_right (.not b) p (.test .zero) (resD b p)) ?_
  -- 0 ; D ≡ 0, and a choice with a failing else arm is an assertion
  exact EquivBA.trans
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.s2 _)))
    (ite_zero_else (.not b) (.seq p (resD b p)))

/-- **Step 3, the crux.**  `(A ; C)^(¬b) ≡ p^(¬b)`.

    The two loops iterate the same action at different granularities — one `p` per turn on the
    right, `p` then a conditional second `p` on the left — and the cyclic cover is exactly the
    proof that granularity is immaterial. -/
theorem wh_resA_resC (b : BExp T) (p : Exp A T)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false) :
    EquivBA (.wh (.not b) (.seq (resA b p) (resC b p))) (.wh (.not b) p) := by
  have hE : EquivBA (.test (E (.seq p (resD b p))) : Exp A T) (.test .zero) :=
    EquivBA.baTest (fun X W x => by
      show (bval W (E p) x && _) = false
      rw [hEp X W x]; rfl)
  refine EquivBA.trans (EquivBA.wh_c (resA_seq_resC b p)) ?_
  refine EquivBA.trans (EquivBA.symm (wh_restrict_body hE)) ?_
  exact EquivBA.symm (equivBA_of_refines (Refines.cyc (.not b) p 1))

/-- **Step 4.**  Under `¬b`, `A · p^(¬b)` and `p^(¬b)` agree: the left side runs `p` and then
    the loop, and W1 says the right side does the same. -/
theorem branches_agree (b : BExp T) (p : Exp A T) :
    EquivBA (.ite (.not b) (.seq (resA b p) (.wh (.not b) p)) p)
      (.ite (.not b) (.wh (.not b) p) p) := by
  have hL : EquivBA (.seq (.test (.not b)) (.seq (resA b p) (.wh (.not b) p)))
      (.seq (.test (.not b)) (.seq p (.wh (.not b) p))) :=
    EquivBA.trans (EquivBA.symm (seq_assoc _ _ _))
      (EquivBA.trans
        (EquivBA.seq_c (test_seq_ite_else b (.test .zero) p) (EquivBA.base (Equiv.refl _)))
        (seq_assoc _ _ _))
  have hR : EquivBA (.seq (.test (.not b)) (.wh (.not b) p))
      (.seq (.test (.not b)) (.seq p (.wh (.not b) p))) :=
    EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.w1 (.not b) p)))
      (test_seq_ite_of_implies (b := .not b) (z := .not b) _ _ (fun _ _ _ h => h))
  exact EquivBA.trans (EquivBA.base (Equiv.u4 (.not b) _ p))
    (EquivBA.trans
      (EquivBA.ite_c (EquivBA.trans hL (EquivBA.symm hR)) (EquivBA.base (Equiv.refl p)))
      (EquivBA.symm (EquivBA.base (Equiv.u4 (.not b) _ p))))

/-- **Pair #3 of the residue, proved from the finite axioms.**

    No instance of the uniqueness axiom appears: the derivation uses U1–U5, S1–S6, W1, W2 and
    a single application of W3 (inside `wh_restrict_body`, discharged by productivity of `p`),
    plus the cyclic-cover refinement, which is itself built from covers rather than axioms.

    `p` ranges over every productive expression, so this is not a proof about one three-state
    automaton but about the whole family the automaton represents. -/
theorem residue_pair_three (b : BExp T) (p : Exp A T)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false) :
    EquivBA
      (.wh (.not b) (.seq p (.ite (.not b) (.seq (resA b p) (.wh (.not b) p)) p)))
      (.wh (.not b) (.seq p (.ite (.not b) (.wh (.not b) (.seq (resA b p) (resC b p))) p))) :=
  EquivBA.wh_c (EquivBA.seq_c (EquivBA.base (Equiv.refl p))
    (EquivBA.trans (branches_agree b p)
      (EquivBA.ite_c (EquivBA.symm (wh_resA_resC b p hEp)) (EquivBA.base (Equiv.refl p)))))

/-- The pair as the harness produced it, with `p` an action.  Productivity is then definitional,
    so the hypothesis discharges by `rfl`. -/
theorem residue_pair_three_act (b : BExp T) (a : A) :
    EquivBA
      (.wh (.not b) (.seq (.act a)
        (.ite (.not b) (.seq (resA b (.act a)) (.wh (.not b) (.act a))) (.act a))))
      (.wh (.not b) (.seq (.act a)
        (.ite (.not b) (.wh (.not b) (.seq (resA b (.act a)) (resC b (.act a)))) (.act a)))) :=
  residue_pair_three b (.act a) (fun _ _ _ => rfl)

#print axioms ite_then_test
#print axioms wh_restrict_body
#print axioms test_seq_ite_else
#print axioms wh_resA_resC
#print axioms branches_agree
#print axioms residue_pair_three
#print axioms residue_pair_three_act

end GkatResidue
