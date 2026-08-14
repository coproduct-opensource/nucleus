/-!
# GKAT syntax and the Salomaa equation — the syntactic attempt

A faithful Lean formalization of GKAT's syntax and equational axioms (Smolka,
Kappé, Kozen, Silva et al., *Guarded Kleene Algebra with Tests*, POPL 2020;
Figure 1), and the **base case of the completeness reduction**, proven inside the
axiom system.

GKAT completeness routes through: each expression → a G-automaton → a **Salomaa
equation system**; bisimilar expressions solve the same system; the **Uniqueness
Axiom** makes them provably equal. Pham (2026) proved uniqueness; **existence of a
provable solution is the open half.** For a SINGLE-state automaton the equation is
`g ≡ e·g +_b f`, and here BOTH halves are provable from the axioms:

  - `salomaa_solution_exists` — the canonical `e^(b)·f` SOLVES the equation
    (derived from W1, U5, S1, S4). This is existence for one state.
  - `salomaa_solution_unique` — any solution is `≡ e^(b)·f` (the W3 fixpoint rule).
  - `salomaa_solutions_agree` — hence any two solutions are provably equal.

## What this is and is NOT
This is the axiomatic scaffold and the **base case** of the syntactic reduction.
The OPEN problem is EXISTENCE for GENERAL n-state (Thompson) automata — solving a
whole *system* of guarded equations back into a GKAT term — which the single-
equation W3 does not give. That is the crux Pham reduced completeness to, and it is
NOT solved here.

Consistency of `≡` (that it is not the total relation, so the theorems below are
non-vacuous) is classical — the guarded-string language model of Smolka et al. —
and, in this tree, the endomap model of `GkatWhileStep.lean` interprets `e^(b)` as
`whileStep`, with W1 ↔ `whileStep_solves` and W3 ↔ `solution_unique`. Wiring that
denotational soundness bridge in Lean (to make consistency machine-checked here) is
the identified next step; this file states the axioms and derives the base case.
-/

namespace GkatSyntax

/-- Boolean tests: a free Boolean-algebra syntax over primitive tests `T`. -/
inductive BExp (T : Type) where
  | zero
  | one
  | prim (t : T)
  | and (b c : BExp T)
  | or (b c : BExp T)
  | not (b : BExp T)
  deriving DecidableEq, Repr

/-- GKAT expressions over actions `A` and tests `T`
    (POPL'20 grammar: `e ::= p | b | e·f | e +_b f | e^(b)`). -/
inductive Exp (A T : Type) where
  | act (p : A)
  | test (b : BExp T)
  | seq (e f : Exp A T)
  | ite (b : BExp T) (e f : Exp A T)   -- `e +_b f`  (if b then e else f)
  | wh (b : BExp T) (e : Exp A T)      -- `e^(b)`    (while b do e)
  deriving DecidableEq, Repr

variable {A T : Type}

/-- The empty-word test `E(e)` — whether `e` may terminate without acting. The W3
    guardedness side condition is `E(e) ≡ 0` ("`e` is strictly productive"). -/
def E : Exp A T → BExp T
  | .act _    => .zero
  | .test b   => b
  | .seq e f  => .and (E e) (E f)
  | .ite b e f => .or (.and b (E e)) (.and (.not b) (E f))
  | .wh b _   => .not b

/-- Provable equivalence `⊢ e ≡ f` — GKAT's equational theory (POPL'20 Figure 1):
    equivalence + congruence + the guarded-union (U1–U5), sequencing (S1–S5), and
    loop (W1–W3) axioms. -/
inductive Equiv : Exp A T → Exp A T → Prop where
  -- equivalence
  | refl (e : Exp A T) : Equiv e e
  | symm {e f} : Equiv e f → Equiv f e
  | trans {e f g} : Equiv e f → Equiv f g → Equiv e g
  -- congruence
  | seq_c {e e' f f'} : Equiv e e' → Equiv f f' → Equiv (.seq e f) (.seq e' f')
  | ite_c {b e e' f f'} : Equiv e e' → Equiv f f' → Equiv (.ite b e f) (.ite b e' f')
  | wh_c {b e e'} : Equiv e e' → Equiv (.wh b e) (.wh b e')
  -- U1–U5 (guarded union)
  | u1 (b) (e : Exp A T) : Equiv (.ite b e e) e
  | u2 (b) (e f : Exp A T) : Equiv (.ite b e f) (.ite (.not b) f e)
  | u3 (b c) (e f g : Exp A T) :
      Equiv (.ite c (.ite b e f) g) (.ite (.and b c) e (.ite c f g))
  | u4 (b) (e f : Exp A T) : Equiv (.ite b e f) (.ite b (.seq (.test b) e) f)
  | u5 (b) (e f g : Exp A T) :
      Equiv (.ite b (.seq e g) (.seq f g)) (.seq (.ite b e f) g)
  -- S1–S5 (sequencing)
  | s1 (e f g : Exp A T) : Equiv (.seq (.seq e f) g) (.seq e (.seq f g))
  | s2 (e : Exp A T) : Equiv (.seq (.test .zero) e) (.test .zero)
  | s3 (e : Exp A T) : Equiv (.seq e (.test .zero)) (.test .zero)
  | s4 (e : Exp A T) : Equiv (.seq (.test .one) e) e
  | s5 (e : Exp A T) : Equiv (.seq e (.test .one)) e
  -- W1–W3 (guarded loop)
  | w1 (b) (e : Exp A T) : Equiv (.wh b e) (.ite b (.seq e (.wh b e)) (.test .one))
  | w2 (b c) (e : Exp A T) :
      Equiv (.wh b (.ite c e (.test .one))) (.wh b (.seq (.test c) e))
  | w3 {b e f g} : Equiv (.test (E e)) (.test .zero) →
      Equiv g (.ite b (.seq e g) f) → Equiv g (.seq (.wh b e) f)

/-- **EXISTENCE (one state).** The canonical expression `e^(b)·f` solves the
    single-state Salomaa equation `g ≡ e·g +_b f`. Derived from W1 (unroll), U5
    (distribute `·` over `+_b`), S1 (assoc), S4 (`1·f ≡ f`). -/
theorem salomaa_solution_exists (b : BExp T) (e f : Exp A T) :
    Equiv (.seq (.wh b e) f) (.ite b (.seq e (.seq (.wh b e) f)) f) :=
  let sol : Exp A T := .seq (.wh b e) f
  have step1 : Equiv sol (.seq (.ite b (.seq e (.wh b e)) (.test .one)) f) :=
    Equiv.seq_c (Equiv.w1 b e) (Equiv.refl f)
  have step2 : Equiv (.seq (.ite b (.seq e (.wh b e)) (.test .one)) f)
      (.ite b (.seq (.seq e (.wh b e)) f) (.seq (.test .one) f)) :=
    Equiv.symm (Equiv.u5 b (.seq e (.wh b e)) (.test .one) f)
  have step3 : Equiv (.ite b (.seq (.seq e (.wh b e)) f) (.seq (.test .one) f))
      (.ite b (.seq e (.seq (.wh b e) f)) f) :=
    Equiv.ite_c (Equiv.s1 e (.wh b e) f) (Equiv.s4 f)
  Equiv.trans step1 (Equiv.trans step2 step3)

/-- **UNIQUENESS (one state).** Any solution of `g ≡ e·g +_b f` is `≡ e^(b)·f`,
    given the guardedness side condition `E(e) ≡ 0`. This is the W3 fixpoint rule —
    the single-equation Uniqueness Axiom. -/
theorem salomaa_solution_unique {b : BExp T} {e f g : Exp A T}
    (hguard : Equiv (Exp.test (E e) : Exp A T) (.test .zero))
    (hsol : Equiv g (.ite b (.seq e g) f)) :
    Equiv g (.seq (.wh b e) f) :=
  Equiv.w3 hguard hsol

/-- **The reduction.** Two solutions of the same guarded single-state equation are
    provably equal — existence + uniqueness combined, the base case of GKAT
    completeness done syntactically. -/
theorem salomaa_solutions_agree {b : BExp T} {e f g₁ g₂ : Exp A T}
    (hguard : Equiv (Exp.test (E e) : Exp A T) (.test .zero))
    (h₁ : Equiv g₁ (.ite b (.seq e g₁) f))
    (h₂ : Equiv g₂ (.ite b (.seq e g₂) f)) :
    Equiv g₁ g₂ :=
  Equiv.trans (salomaa_solution_unique hguard h₁)
    (Equiv.symm (salomaa_solution_unique hguard h₂))

/-- Non-triviality: the existence theorem relates syntactically DISTINCT
    expressions (a `seq`/`ite` head mismatch), so it is a real equivalence, not an
    instance of reflexivity. (Consistency of `≡` itself — that it is not total — is
    the classical model result, discussed in the header.) -/
example :
    (Exp.seq (Exp.wh (BExp.prim ()) (Exp.act ())) (Exp.act ()) : Exp Unit Unit) ≠
      (Exp.ite (BExp.prim ()) (Exp.seq (Exp.act ())
        (Exp.seq (Exp.wh (BExp.prim ()) (Exp.act ())) (Exp.act ()))) (Exp.act ()) : Exp Unit Unit) := by
  decide

#print axioms salomaa_solution_exists
#print axioms salomaa_solution_unique
#print axioms salomaa_solutions_agree

end GkatSyntax
