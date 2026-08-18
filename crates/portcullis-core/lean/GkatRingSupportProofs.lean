import GkatResidueProofs
import GkatSumQuotientProofs

/-! # Ring/parking support

    The k=6 residue (80 pairs, halt-in-cycle 100%, two-halt 0%) is covered by a witness
    type outside the elimination/Thompson families: RING solutions.  A cycle whose every
    halt lies on one shared guard `c` picks a header state that halts on `c`; the header
    becomes a `wh ¬c body` whose body walks the ring once, and each interior halt is
    PARKED — written as the actionless factor `ite c (c?) q` — so the atom that triggered
    it survives to the header's own exit test.  Exits whose continuation terminates with
    halt guard `c` are INLINED into the body wholesale and fall out through the same
    header test.

    This file holds the five reusable proof pieces those solutions need.  Everything is
    finite-axiom: W1 (via `salomaa_solution_exists`), U1/U2/U5, S1/S2/S5, `s6`/`baTest`/
    `ite_guard` — no UA. -/

namespace GkatRingSupport

open GkatSyntax GkatGS GkatFaithful GkatGuardedAlgebra GkatResidue

variable {A T : Type}

theorem himp_self (b : BExp T) : GuardImplies b b := fun _ _ _ h => h

theorem himp_dneg (b : BExp T) : GuardImplies (.not (.not b)) b := by
  intro X W x h
  have h' : (!(!(bval W b x))) = true := h
  cases hb : bval W b x with
  | false => rw [hb] at h'; exact Bool.noConfusion h'
  | true => rfl

theorem himp_intro_dneg (b : BExp T) : GuardImplies b (.not (.not b)) := by
  intro X W x h
  show (!(!(bval W b x))) = true
  rw [h]; rfl

/-- Double negation at the `bval` level, for `EquivBA.ite_guard`. -/
theorem dneg_bval (b : BExp T) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.not (.not b)) x = bval W b x := by
  intro X W x
  show (!(!(bval W b x))) = bval W b x
  cases bval W b x <;> rfl

/-- A test absorbs its own repetition. -/
theorem test_test (c : BExp T) :
    EquivBA (.seq (.test c) (.test c) : Exp A T) (.test c) :=
  EquivBA.trans (EquivBA.s6 c c)
    (EquivBA.baTest (fun X W x => by
      show (bval W c x && bval W c x) = bval W c x
      cases bval W c x <;> rfl))

/-- Under `c`, a loop whose guard is off exits at once. -/
theorem test_wh_absorb (c g : BExp T) (B : Exp A T)
    (himp : GuardImplies c (.not g)) :
    EquivBA (.seq (.test c) (.wh g B)) (.test c) := by
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
    (EquivBA.base (Equiv.w1 g B))) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
    (EquivBA.base (Equiv.u2 g _ _))) ?_
  refine EquivBA.trans (test_seq_ite_of_implies _ _ himp) ?_
  exact EquivBA.base (Equiv.s5 _)

/-- **The parking absorption.**  Under the exit guard `c`, a ring header
    `(wh g body) ; c?` is just `c?`: the loop exits at once and the trailing test is
    absorbed. -/
theorem test_header_absorb (c g : BExp T) (B : Exp A T)
    (himp : GuardImplies c (.not g)) :
    EquivBA (.seq (.test c) (.seq (.wh g B) (.test c))) (.test c) :=
  EquivBA.trans (seq_assoc' (.test c) (.wh g B) (.test c))
    (EquivBA.trans (EquivBA.seq_c (test_wh_absorb c g B himp)
      (EquivBA.base (Equiv.refl _))) (test_test c))

/-- Congruence in the else arm, under the negated guard: `U2` both ways around
    `ite_congr_under_guard`. -/
theorem ite_congr_under_else {g : BExp T} {Z X Y : Exp A T}
    (h : EquivBA (.seq (.test (.not g)) X) (.seq (.test (.not g)) Y)) :
    EquivBA (.ite g Z X) (.ite g Z Y) :=
  EquivBA.trans (EquivBA.base (Equiv.u2 g Z X))
    (EquivBA.trans (ite_congr_under_guard h)
      (EquivBA.symm (EquivBA.base (Equiv.u2 g Z Y))))

/-- A dead `0?` arm may be introduced under the else guard: `Y ≡ ite z Y 0?` once
    `¬b` implies `z`. -/
theorem else_expand (b z : BExp T) {X Y : Exp A T}
    (himp : GuardImplies (.not b) z) :
    EquivBA (.ite b X Y) (.ite b X (.ite z Y (.test .zero))) :=
  ite_congr_under_else
    (EquivBA.symm (test_seq_ite_of_implies Y (.test .zero) himp))

/-- A state whose both atoms step to the same target satisfies its two-armed equation. -/
theorem both_arms (b c : BExp T) (X : Exp A T)
    (himp : GuardImplies (.not b) c) :
    EquivBA X (.ite b X (.ite c X (.test .zero))) :=
  EquivBA.symm
    (EquivBA.trans
      (EquivBA.symm (else_expand b c himp))
      (EquivBA.base (Equiv.u1 b X)))

/-- **The parked state's equation.**  A halt on `c` deferred through the actionless
    factor `ite c (c?) q` satisfies the state's own equation, provided the header
    absorbs `c?` (which `test_header_absorb` supplies). -/
theorem park_solves (c : BExp T) (q solH : Exp A T)
    (habs : EquivBA (.seq (.test c) solH) (.test c)) :
    EquivBA (.seq (.ite c (.test c) q) solH)
      (.ite (.not c) (.seq q solH) (.test c)) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 c (.test c) q solH)))
    (EquivBA.trans (EquivBA.ite_c habs (EquivBA.base (Equiv.refl _)))
      (EquivBA.base (Equiv.u2 c (.test c) (.seq q solH))))

#print axioms park_solves
#print axioms test_header_absorb
#print axioms both_arms

end GkatRingSupport
