import GkatCertSupportProofs
import GkatResidueProofs
import GkatDeadExitElimProofs
import GkatSumQuotientProofs

/-! # GkatCertR5: emitted instance certificate (machine-generated; see emit_cert.py) -/

namespace GkatCertR5

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport
open GkatGuardedAlgebra GkatResidue

abbrev Tst := Unit
abbrev Act := Unit
def bT : BExp Tst := .prim ()
def pA : Exp Act Tst := .act ()
def eP : Exp Act Tst := (Exp.seq (Exp.ite bT (Exp.seq (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA) (Exp.ite bT (Exp.test bT) pA)) (Exp.test (BExp.not bT))) (Exp.wh (BExp.not bT) (Exp.seq (Exp.wh (BExp.not bT) pA) (Exp.seq (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA) (Exp.ite bT (Exp.test bT) pA)))))
def fP : Exp Act Tst := (Exp.seq (Exp.seq (Exp.wh (BExp.not bT) pA) (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA)) (Exp.wh (BExp.not bT) (Exp.seq pA (Exp.ite (BExp.not bT) (Exp.seq (Exp.wh (BExp.not bT) pA) (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA)) (Exp.test bT)))))

abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut
abbrev SUM := sumGAut eAut fAut

/-! ## The ring solutions

    The quotient is a 3-ring `s0 -t-> s1 -¬t-> s2 -¬t-> s0` with a `¬t` self-loop at `s0`
    and halts on `t` at `s1` and `s2` — the halt-in-cycle shape of the whole k=6 residue
    (two-halt 0%, halt-in-cycle 100%).  No level/chain decomposition applies (the ring is
    a single SCC that is not a 2-SCC), and no lattice quotient of the sum is Thompson or
    per-atom eliminable — this pair is FAILURE #5 of the k=6 sweep.  But the ring IS
    derivably solvable: all in-cycle halts share the guard `t`, so `s1`'s halt can be
    PARKED — written as the actionless factor `ite t (t?) p` — and re-read by the header
    loop's own guard, which exits exactly on `t`.  The three `SolvesBA` obligations use
    only W1 (via `salomaa_solution_exists` / `level_satisfies`), U2, U5, S1, S5/S6, and
    guard reasoning — no UA. -/

/-- The park factor: at `t`, skip (`s1`'s halt, deferred to the header); else the ring
    action to `s2`. -/
def PK : Exp Act Tst := .ite bT (.test bT) pA

/-- `s0`'s self-loop. -/
def SL : Exp Act Tst := .wh (.not bT) pA

/-- One trip around the ring, header at `s2`: action to `s0`, `s0`'s self-loops, action
    to `s1`, park. -/
def B2 : Exp Act Tst := .seq pA (.seq SL (.seq pA PK))

def L2 : LevelG Act Tst := ([((BExp.not bT), B2)], [], (Exp.test bT))
def sol2 : Exp Act Tst := levelSol L2
def sol1 : Exp Act Tst := .seq PK sol2
def sol0 : Exp Act Tst := .seq SL (.seq pA sol1)

/-- `t` turns the header loop's guard `¬t ∨ 0` off. -/
private theorem himp_exit : GuardImplies bT (.not (.or (.not bT) .zero)) := by
  intro X W x h
  show (!(!bval W bT x || bval W (.zero : BExp Tst) x)) = true
  rw [h]
  rfl

/-- Double negation: `¬¬t` implies `t`. -/
private theorem himp_dneg : GuardImplies (.not (.not bT)) bT := by
  intro X W x h
  have h' : (!(!(bval W bT x))) = true := h
  cases hb : bval W bT x with
  | false => rw [hb] at h'; exact Bool.noConfusion h'
  | true => rfl

/-- After `t?`, the header loop exits at once and its `t?` continuation is absorbed. -/
private theorem testT_sol2 : EquivBA (.seq (.test bT) sol2) (.test bT) := by
  have hexit : EquivBA
      (.seq (.test bT) (.wh (.or (.not bT) BExp.zero) (bodyFold L2.1)) : Exp Act Tst)
      (.test bT) := by
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.base (Equiv.w1 _ _))) ?_
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.base (Equiv.u2 _ _ _))) ?_
    refine EquivBA.trans (test_seq_ite_of_implies _ _ himp_exit) ?_
    exact EquivBA.base (Equiv.s5 _)
  refine EquivBA.trans (seq_assoc' (.test bT)
    (.wh (.or (.not bT) BExp.zero) (bodyFold L2.1)) (.test bT)) ?_
  refine EquivBA.trans (EquivBA.seq_c hexit (EquivBA.base (Equiv.refl _))) ?_
  refine EquivBA.trans (EquivBA.s6 bT bT) ?_
  exact EquivBA.baTest (fun Y W x => by
    show (bval W bT x && bval W bT x) = bval W bT x
    cases hb : bval W bT x <;> rfl)

/-- Congruence in the else arm, under the negated guard: `U2` both ways around
    `ite_congr_under_guard`. -/
private theorem ite_congr_under_else {g : BExp Tst} {X Y Z : Exp Act Tst}
    (h : EquivBA (.seq (.test (.not g)) X) (.seq (.test (.not g)) Y)) :
    EquivBA (.ite g Z X) (.ite g Z Y) :=
  EquivBA.trans (EquivBA.base (Equiv.u2 g Z X))
    (EquivBA.trans (ite_congr_under_guard h)
      (EquivBA.symm (EquivBA.base (Equiv.u2 g Z Y))))

/-- `s0`'s equation: unroll the self-loop (`salomaa_solution_exists`), then under `¬¬t`
    the fold's dead `0?` arm may be dropped. -/
theorem ring_E0 : EquivBA sol0
    (.ite (.not bT) (.seq pA sol0) (.ite bT (.seq pA sol1) (.test BExp.zero))) :=
  EquivBA.trans
    (EquivBA.base (salomaa_solution_exists (.not bT) pA (.seq pA sol1)))
    (ite_congr_under_else
      (EquivBA.symm (test_seq_ite_of_implies (.seq pA sol1) (.test BExp.zero) himp_dneg)))

/-- `s1`'s equation: distribute the park factor (`U5`), absorb `t? ; sol2`, flip. -/
theorem ring_E1 : EquivBA sol1 (.ite (.not bT) (.seq pA sol2) (.test bT)) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 bT (.test bT) pA sol2)))
    (EquivBA.trans (EquivBA.ite_c testT_sol2 (EquivBA.base (Equiv.refl _)))
      (EquivBA.base (Equiv.u2 bT (.test bT) (.seq pA sol2))))

/-- `s2`'s equation: `level_satisfies` unrolls the header loop; three associativity
    steps rebuild `p ; sol0` from the trip body. -/
theorem ring_E2 : EquivBA sol2 (.ite (.not bT) (.seq pA sol0) (.test bT)) :=
  EquivBA.trans (level_satisfies L2)
    (EquivBA.ite_c
      (EquivBA.trans (EquivBA.base (Equiv.s1 pA (.seq SL (.seq pA PK)) sol2))
        (EquivBA.seq_c (EquivBA.base (Equiv.refl pA))
          (EquivBA.trans (EquivBA.base (Equiv.s1 SL (.seq pA PK) sol2))
            (EquivBA.seq_c (EquivBA.base (Equiv.refl SL))
              (EquivBA.base (Equiv.s1 pA PK sol2))))))
      (EquivBA.base (Equiv.refl _)))

def QAut : GAut Nat Act Tst where
  states := [0, 1, 2]
  hlt
    | 0 => BExp.zero
    | 1 => bT
    | 2 => bT
    | _ => BExp.zero
  trans
    | 0 => [((BExp.not bT), (), 0), (bT, (), 1)]
    | 1 => [((BExp.not bT), (), 2)]
    | 2 => [((BExp.not bT), (), 0)]
    | _ => []
  start := 0

def qmap : Sum (Option (certifiedThompson Act Tst eP).State)
             (Option (certifiedThompson Act Tst fP).State) → Nat
  | .inl none => 0
  | .inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))) => 1
  | .inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))) => 2
  | .inl (some (Sum.inr (Sum.inl ()))) => 0
  | .inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))) => 1
  | .inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ()))))) => 2
  | .inr none => 0
  | .inr (some (Sum.inl (Sum.inl ()))) => 0
  | .inr (some (Sum.inl (Sum.inr (Sum.inr ())))) => 1
  | .inr (some (Sum.inr (Sum.inl ()))) => 2
  | .inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))) => 0
  | .inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))) => 1
  | _ => 0

variable {X : Type} (W : Tst → X → Bool) (x : X)

theorem qstep_0_false (h : W () x = false) :
    autStep W QAut 0 x = some ((), 0) := by
  rw [autStep_unit, h]; rfl
theorem qstep_0_true (h : W () x = true) :
    autStep W QAut 0 x = some ((), 1) := by
  rw [autStep_unit, h]; rfl
theorem qstep_1_false (h : W () x = false) :
    autStep W QAut 1 x = some ((), 2) := by
  rw [autStep_unit, h]; rfl
theorem qstep_1_true (h : W () x = true) :
    autStep W QAut 1 x = none := by
  rw [autStep_unit, h]; rfl
theorem qstep_2_false (h : W () x = false) :
    autStep W QAut 2 x = some ((), 0) := by
  rw [autStep_unit, h]; rfl
theorem qstep_2_true (h : W () x = true) :
    autStep W QAut 2 x = none := by
  rw [autStep_unit, h]; rfl

theorem qmap_bisim : GAutBisim W SUM QAut (fun s q => qmap s = q) := by
  rintro s1 s2 rfl
  match s1 with
  | Sum.inl none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl none)) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl none) ()
                = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl none) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))))) a = bval W (QAut.hlt 2) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inl (some (Sum.inr (Sum.inl ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inr (Sum.inl ()))))) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) ()
                = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) ()
                = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ()))))))) a = bval W (QAut.hlt 2) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inr none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr none)) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr none) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr none) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inl ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inl ()))))) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inr (some (Sum.inr (Sum.inl ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inr (Sum.inl ()))))) a = bval W (QAut.hlt 2) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inr (Sum.inl ())))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inr (Sum.inl ())))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))))) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ())))))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨0, qstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ())))))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = some ((), 0) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ()))))))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ()))))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)

def qquot : UniformBehavioralGAutQuotient SUM QAut where
  mapState := qmap
  maps_states := by
    intro s _
    match s with
    | Sum.inl none => exact (List.Mem.head _)
    | Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inl (some (Sum.inr (Sum.inl ()))) => exact (List.Mem.head _)
    | Sum.inl (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inl (some (Sum.inr (Sum.inr (Sum.inr (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inr none => exact (List.Mem.head _)
    | Sum.inr (some (Sum.inl (Sum.inl ()))) => exact (List.Mem.head _)
    | Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inr (some (Sum.inr (Sum.inl ()))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))) => exact (List.Mem.head _)
    | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))) => exact (List.Mem.tail _ (List.Mem.head _))
  onto_states := by
    intro q hq
    match q, hq with
    | 0, _ => exact ⟨(Sum.inl none), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _)))), rfl⟩
    | 1, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))))))), rfl⟩
    | 2, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))))))), rfl⟩
  bisim_graph := fun _ W => qmap_bisim W

def qsol : Nat → Exp Act Tst
  | 0 => sol0
  | 1 => sol1
  | 2 => sol2
  | _ => Exp.test BExp.zero

theorem qsol_solves : SolvesBA QAut qsol := by
  intro s hs
  match s, hs with
  | 0, _ => exact ring_E0
  | 1, _ => exact ring_E1
  | 2, _ => exact ring_E2

theorem cert : EquivBA eP fP :=
  certifiedThompson_uniform_solved_quotient qquot qsol qsol_solves rfl

#print axioms cert

end GkatCertR5

