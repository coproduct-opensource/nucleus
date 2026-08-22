import GkatThompsonUniquenessProofs

/-!
# Derived guarded-algebra laws for the null-language elimination

This file collects the purely *equational* consequences of the finite GKAT axioms
(U1–U5, S1–S5, plus Boolean-guard congruence and `s6`) that the null-language argument
needs.  Nothing here uses the guarded-string model, `W3`, or any uniqueness principle:
every theorem is a finite derivation.

The point of isolating them is that the two hard theorems downstream —
`Q` (null-language completeness) and `POST` (postcondition elimination) — then read as
pure control-flow arguments, with each algebraic step named.

Axioms: `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatGuardedAlgebra

open GkatSyntax GkatGS GkatFaithful

variable {A T : Type}

/-! ## Boolean-guard helpers -/

/-- `b ∧ c` and `c ∧ b` are the same guard. -/
theorem band_comm_guard (b c : BExp T) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b c) x = bval W (.and c b) x := by
  intro X W x
  simp only [bval]
  cases bval W b x <;> cases bval W c x <;> rfl

/-- A guard implying `z` absorbs `z`. -/
theorem band_of_implies {b z : BExp T} (himp : GuardImplies b z) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b z) x = bval W b x := by
  intro X W x
  simp only [bval]
  cases hb : bval W b x with
  | false => rfl
  | true => rw [himp X W x hb]; rfl

/-- Double negation on guards. -/
theorem bnot_not_guard (b : BExp T) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.not (.not b)) x = bval W b x := by
  intro X W x
  simp only [bval]
  cases bval W b x <;> rfl

/-- `¬b ∧ b` is unsatisfiable. -/
theorem bnot_and_self (b : BExp T) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (.not b) b) x = bval W (.zero : BExp T) x := by
  intro X W x
  simp only [bval]
  cases bval W b x <;> rfl

/-! ## Assertion and guarded choice -/

/-- `b·e` is the guarded choice between `e` and failure.  (Restated from
    `GkatFaithful.test_seq_as_ite` so the null-language file reads uniformly.) -/
theorem seq_test_eq_ite (b : BExp T) (e : Exp A T) :
    EquivBA (.seq (.test b) e) (.ite b e (.test .zero)) :=
  test_seq_as_ite b e

/-- A guarded choice whose else arm fails is an assertion. -/
theorem ite_zero_else (b : BExp T) (e : Exp A T) :
    EquivBA (.ite b e (.test .zero) : Exp A T) (.seq (.test b) e) :=
  EquivBA.symm (test_seq_as_ite b e)

/-- A guarded choice whose *then* arm fails is the complementary assertion.  This is the
    step that lets a killed branch move its guard into the continuation, where
    associativity can reach it. -/
theorem ite_zero_then (b : BExp T) (f : Exp A T) :
    EquivBA (.ite b (.test .zero) f : Exp A T) (.seq (.test (.not b)) f) :=
  EquivBA.trans (EquivBA.base (Equiv.u2 b (.test .zero) f))
    (ite_zero_else (.not b) f)

/-- Inside the else arm of `b`, the continuation may be asserted under `¬b`. -/
theorem ite_restrict_else (b : BExp T) (e f : Exp A T) :
    EquivBA (.ite b e f) (.ite b e (.seq (.test (.not b)) f)) :=
  EquivBA.trans (EquivBA.base (Equiv.u2 b e f))
    (EquivBA.trans (EquivBA.base (Equiv.u4 (.not b) f e))
      (EquivBA.trans
        (EquivBA.base (Equiv.u2 (.not b) (.seq (.test (.not b)) f) e))
        (EquivBA.ite_guard (bnot_not_guard b))))

/-- Consecutive assertions merge. -/
theorem test_seq_merge (b c : BExp T) (e : Exp A T) :
    EquivBA (.seq (.test b) (.seq (.test c) e)) (.seq (.test (.and b c)) e) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.s1 _ _ _)))
    (EquivBA.seq_c (EquivBA.s6 b c) (EquivBA.base (Equiv.refl e)))

/-- An assertion contradicting its continuation's assertion fails. -/
theorem test_seq_contradiction (b : BExp T) (e : Exp A T) :
    EquivBA (.seq (.test (.not b)) (.seq (.test b) e)) (.test .zero) :=
  EquivBA.trans (test_seq_merge (.not b) b e)
    (EquivBA.trans
      (EquivBA.seq_c (EquivBA.baTest (bnot_and_self b))
        (EquivBA.base (Equiv.refl e)))
      (EquivBA.base (Equiv.s2 e)))

/-- **Assertion distributes into a guarded choice.**  The valid, test-only fragment of
    left distribution: the guard of the choice is conjoined with the assertion, and the
    assertion survives into the else arm. -/
theorem test_seq_ite (b c : BExp T) (e f : Exp A T) :
    EquivBA (.seq (.test b) (.ite c e f))
      (.ite (.and b c) e (.seq (.test b) f)) :=
  EquivBA.trans (test_seq_as_ite b (.ite c e f))
    (EquivBA.trans (EquivBA.base (Equiv.u3 c b e f (.test .zero)))
      (EquivBA.trans (EquivBA.ite_guard (band_comm_guard c b))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl e)) (ite_zero_else b f))))

/-- **Postcondition elimination for assertions.**  If the assertion already implies the
    branch guard, the choice collapses to its then arm.  This is the base case of the
    general postcondition-elimination law. -/
theorem test_seq_ite_of_implies {b z : BExp T} (e f : Exp A T)
    (himp : GuardImplies b z) :
    EquivBA (.seq (.test b) (.ite z e f)) (.seq (.test b) e) :=
  EquivBA.trans (test_seq_ite b z e f)
    (EquivBA.trans (EquivBA.ite_guard (band_of_implies himp))
      (EquivBA.trans (ite_restrict_else b e (.seq (.test b) f))
        (EquivBA.trans
          (EquivBA.ite_c (EquivBA.base (Equiv.refl e))
            (test_seq_contradiction b f))
          (ite_zero_else b e))))

/-! ## Inserting and killing a Boolean case split -/

/-- **Case-split insertion.**  Any continuation may be split on an arbitrary test, with
    the then arm asserted.  `U1` supplies the duplicated branch and `U4` the assertion;
    no distributivity is involved. -/
theorem insert_test (d : BExp T) (e : Exp A T) :
    EquivBA e (.ite d (.seq (.test d) e) e) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u1 d e)))
    (EquivBA.base (Equiv.u4 d e e))

/-- **The kill law.**  If the continuation is dead on `d` and the prefix never ends
    outside `d`, the composite is dead.  This is the one place where a *right-hand*
    Boolean fact (`u·¬d = 0`) is turned into a rewrite of `u`'s continuation: the
    inserted split leaves `0` in the then arm, `ite_zero_then` moves `¬d` out of the
    choice, and associativity delivers it to `u`. -/
theorem seq_kill {u e : Exp A T} {d : BExp T}
    (hthen : EquivBA (.seq (.test d) e) (.test .zero))
    (hprefix : EquivBA (.seq u (.test (.not d))) (.test .zero)) :
    EquivBA (.seq u e) (.test .zero) :=
  EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl u)) (insert_test d e))
    (EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl u))
        (EquivBA.trans
          (EquivBA.ite_c hthen (EquivBA.base (Equiv.refl e)))
          (ite_zero_then d e)))
      (EquivBA.trans
        (EquivBA.symm (EquivBA.base (Equiv.s1 u (.test (.not d)) e)))
        (EquivBA.trans (EquivBA.seq_c hprefix (EquivBA.base (Equiv.refl e)))
          (EquivBA.base (Equiv.s2 e)))))

/-- Zero absorbs on the right. -/
theorem seq_zero_right (e : Exp A T) :
    EquivBA (.seq e (.test .zero)) (.test .zero) :=
  EquivBA.base (Equiv.s3 e)

/-- Zero absorbs on the left. -/
theorem seq_zero_left (e : Exp A T) :
    EquivBA (.seq (.test .zero) e) (.test .zero) :=
  EquivBA.base (Equiv.s2 e)

/-- An unsatisfiable assertion kills any continuation. -/
theorem test_unsat_seq {b : BExp T} (e : Exp A T)
    (hunsat : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = false) :
    EquivBA (.seq (.test b) e) (.test .zero) :=
  EquivBA.trans
    (EquivBA.seq_c (EquivBA.baTest (b := b) (c := .zero)
        (fun X W x => hunsat X W x))
      (EquivBA.base (Equiv.refl e)))
    (seq_zero_left e)

/-- A tautologous guard selects the then arm. -/
theorem ite_taut {z : BExp T} (e f : Exp A T)
    (htaut : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W z x = true) :
    EquivBA (.ite z e f) e :=
  EquivBA.trans
    (EquivBA.ite_guard (b := z) (c := .one) (e := e) (f := f)
      (fun X W x => htaut X W x))
    (ite_one e f)

/-! ## Sequencing through a guarded choice -/

/-- `U5`, oriented for pushing a continuation into both arms. -/
theorem ite_seq_right (b : BExp T) (e f g : Exp A T) :
    EquivBA (.seq (.ite b e f) g) (.ite b (.seq e g) (.seq f g)) :=
  EquivBA.symm (EquivBA.base (Equiv.u5 b e f g))

/-- Associativity, oriented left-to-right. -/
theorem seq_assoc (e f g : Exp A T) :
    EquivBA (.seq (.seq e f) g) (.seq e (.seq f g)) :=
  EquivBA.base (Equiv.s1 e f g)

/-- Associativity, oriented right-to-left. -/
theorem seq_assoc' (e f g : Exp A T) :
    EquivBA (.seq e (.seq f g)) (.seq (.seq e f) g) :=
  EquivBA.symm (EquivBA.base (Equiv.s1 e f g))

/-- Rewriting the assertion of an asserted expression by a Boolean identity. -/
theorem test_seq_guard_congr {b c : BExp T} (e : Exp A T)
    (heq : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W b x = bval W c x) :
    EquivBA (.seq (.test b) e) (.seq (.test c) e) :=
  EquivBA.seq_c (EquivBA.baTest heq) (EquivBA.base (Equiv.refl e))

/-- `1` is a unit on the left. -/
theorem one_seq (e : Exp A T) : EquivBA (.seq (.test .one) e) e :=
  EquivBA.base (Equiv.s4 e)

/-- `1` is a unit on the right. -/
theorem seq_one (e : Exp A T) : EquivBA (.seq e (.test .one)) e :=
  EquivBA.base (Equiv.s5 e)

#print axioms seq_test_eq_ite
#print axioms ite_zero_then
#print axioms ite_restrict_else
#print axioms test_seq_ite
#print axioms test_seq_ite_of_implies
#print axioms insert_test
#print axioms seq_kill
#print axioms ite_taut

end GkatGuardedAlgebra
