import GkatCertSupportProofs
import GkatRingSupportProofs
import GkatDeadExitElimProofs
import GkatSumQuotientProofs

/-! # GkatK6R50: emitted instance certificate (machine-generated; see emit_cert.py) -/

namespace GkatK6R50

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport
open GkatGuardedAlgebra GkatRingSupport

abbrev Tst := Unit
abbrev Act := Unit
def bT : BExp Tst := .prim ()
def pA : Exp Act Tst := .act ()
def eP : Exp Act Tst := (Exp.ite bT (Exp.wh bT (Exp.seq (Exp.seq (Exp.seq pA pA) (Exp.wh (BExp.not bT) pA)) (Exp.seq (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA) (Exp.ite (BExp.not bT) (Exp.test (BExp.not bT)) pA)))) (Exp.test BExp.zero))
def fP : Exp Act Tst := (Exp.ite bT (Exp.wh bT (Exp.seq (Exp.seq (Exp.seq (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA) (Exp.ite (BExp.not bT) (Exp.test (BExp.not bT)) pA)) (Exp.wh (BExp.not bT) pA)) (Exp.seq (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA) (Exp.ite (BExp.not bT) (Exp.test (BExp.not bT)) pA)))) (Exp.test BExp.zero))

abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut
abbrev SUM := sumGAut eAut fAut

/-! ## Ring solutions (machine-generated; see emit_ring.py).
    SCC [1, 2, 3, 4] header=4 exit=(BExp.not bT); the walk plan and every proof
    recipe follow GkatRingSupportProofs and the GkatCertR1-R6 instances. -/

def BODY : Exp Act Tst := (.seq pA (.seq pA (.seq (.wh (BExp.not bT) pA) (.seq pA (.ite (BExp.not bT) (.test (BExp.not bT)) pA)))))
def sol4 : Exp Act Tst := (.seq (.wh bT BODY) (.test (BExp.not bT)))
def sol3 : Exp Act Tst := (.seq (.ite (BExp.not bT) (.test (BExp.not bT)) pA) sol4)
def sol2 : Exp Act Tst := (.seq (.wh (BExp.not bT) pA) (.seq pA sol3))
def sol1 : Exp Act Tst := (.seq pA sol2)
def sol0 : Exp Act Tst := (.ite bT (.seq pA sol1) (.test BExp.zero))

private theorem habs4 : EquivBA (.seq (.test (BExp.not bT)) sol4) (.test (BExp.not bT)) :=
  test_header_absorb (BExp.not bT) bT BODY (himp_self (BExp.not bT))

theorem ringE4 : EquivBA sol4 (.ite bT (.seq pA sol1) (.test (BExp.not bT))) :=
  EquivBA.trans (EquivBA.base (salomaa_solution_exists bT BODY (.test (BExp.not bT))))
    (EquivBA.ite_c (EquivBA.trans (EquivBA.base (Equiv.s1 pA (.seq pA (.seq (.wh (BExp.not bT) pA) (.seq pA (.ite (BExp.not bT) (.test (BExp.not bT)) pA)))) sol4))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.trans (EquivBA.base (Equiv.s1 pA (.seq (.wh (BExp.not bT) pA) (.seq pA (.ite (BExp.not bT) (.test (BExp.not bT)) pA))) sol4))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.trans (EquivBA.base (Equiv.s1 (.wh (BExp.not bT) pA) (.seq pA (.ite (BExp.not bT) (.test (BExp.not bT)) pA)) sol4))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.s1 pA (.ite (BExp.not bT) (.test (BExp.not bT)) pA) sol4)))))))) (EquivBA.base (Equiv.refl _)))

theorem ringE3 : EquivBA sol3 (.ite bT (.seq pA sol4) (.test (BExp.not bT))) :=
  (EquivBA.trans (park_solves (BExp.not bT) pA sol4 habs4)
    (EquivBA.ite_guard (dneg_bval bT)))

theorem ringE2 : EquivBA sol2 (.ite (BExp.not bT) (.seq pA sol2) (.ite bT (.seq pA sol3) (.test BExp.zero))) :=
  EquivBA.trans (EquivBA.base (salomaa_solution_exists (BExp.not bT) pA (.seq pA sol3)))
    (else_expand (BExp.not bT) bT (himp_dneg bT))

theorem ringE1 : EquivBA sol1 (.ite (BExp.not bT) (.seq pA sol2) (.ite bT (.seq pA sol2) (.test BExp.zero))) :=
  both_arms (BExp.not bT) bT (.seq pA sol2) (himp_dneg bT)


def QAut : GAut Nat Act Tst where
  states := [0, 1, 2, 3, 4]
  hlt
    | 0 => BExp.zero
    | 1 => BExp.zero
    | 2 => BExp.zero
    | 3 => (BExp.not bT)
    | 4 => (BExp.not bT)
    | _ => BExp.zero
  trans
    | 0 => [(bT, (), 1)]
    | 1 => [((BExp.not bT), (), 2), (bT, (), 2)]
    | 2 => [((BExp.not bT), (), 2), (bT, (), 3)]
    | 3 => [(bT, (), 4)]
    | 4 => [(bT, (), 1)]
    | _ => []
  start := 0

def qmap : Sum (Option (certifiedThompson Act Tst eP).State)
             (Option (certifiedThompson Act Tst fP).State) → Nat
  | .inl none => 0
  | .inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ()))))) => 1
  | .inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))) => 2
  | .inl (some (Sum.inl (Sum.inl (Sum.inr ())))) => 2
  | .inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => 3
  | .inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))) => 4
  | .inr none => 0
  | .inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))) => 1
  | .inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))) => 2
  | .inr (some (Sum.inl (Sum.inl (Sum.inr ())))) => 2
  | .inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => 3
  | .inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))) => 4
  | _ => 0

variable {X : Type} (W : Tst → X → Bool) (x : X)

theorem qstep_0_false (h : W () x = false) :
    autStep W QAut 0 x = none := by
  rw [autStep_unit, h]; rfl
theorem qstep_0_true (h : W () x = true) :
    autStep W QAut 0 x = some ((), 1) := by
  rw [autStep_unit, h]; rfl
theorem qstep_1_false (h : W () x = false) :
    autStep W QAut 1 x = some ((), 2) := by
  rw [autStep_unit, h]; rfl
theorem qstep_1_true (h : W () x = true) :
    autStep W QAut 1 x = some ((), 2) := by
  rw [autStep_unit, h]; rfl
theorem qstep_2_false (h : W () x = false) :
    autStep W QAut 2 x = some ((), 2) := by
  rw [autStep_unit, h]; rfl
theorem qstep_2_true (h : W () x = true) :
    autStep W QAut 2 x = some ((), 3) := by
  rw [autStep_unit, h]; rfl
theorem qstep_3_false (h : W () x = false) :
    autStep W QAut 3 x = none := by
  rw [autStep_unit, h]; rfl
theorem qstep_3_true (h : W () x = true) :
    autStep W QAut 3 x = some ((), 4) := by
  rw [autStep_unit, h]; rfl
theorem qstep_4_false (h : W () x = false) :
    autStep W QAut 4 x = none := by
  rw [autStep_unit, h]; rfl
theorem qstep_4_true (h : W () x = true) :
    autStep W QAut 4 x = some ((), 1) := by
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
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl none) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ()))))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))) a = bval W (QAut.hlt 2) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_2_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ())))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ())))))) a = bval W (QAut.hlt 2) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ()))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ()))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_2_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) a = bval W (QAut.hlt 3) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨4, qstep_3_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 3 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 3 ()
                = some ((), 4) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))))) a = bval W (QAut.hlt 4) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_4_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 4 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 4 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
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
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr none) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))))) a = bval W (QAut.hlt 2) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ()))))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_2_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))))) a = bval W (QAut.hlt 2) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_2_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) a = bval W (QAut.hlt 3) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨4, qstep_3_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 3 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 3 ()
                = some ((), 4) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))))) a = bval W (QAut.hlt 4) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_4_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 4 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 4 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl

def qquot : UniformBehavioralGAutQuotient SUM QAut where
  mapState := qmap
  maps_states := by
    intro s _
    match s with
    | Sum.inl none => exact (List.Mem.head _)
    | Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ()))))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inl (some (Sum.inl (Sum.inl (Sum.inr ())))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))
    | Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))))
    | Sum.inr none => exact (List.Mem.head _)
    | Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inr (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr (Sum.inr ())))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))
    | Sum.inr (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))))
  onto_states := by
    intro q hq
    match q, hq with
    | 0, _ => exact ⟨(Sum.inl none), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _)))), rfl⟩
    | 1, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inl ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inl (Sum.inl (Sum.inl ())))))))))), rfl⟩
    | 2, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inl (Sum.inl (Sum.inr ())))))))))), rfl⟩
    | 3, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))))))), rfl⟩
    | 4, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inr (Sum.inr (Sum.inr ())))))))))), rfl⟩
  bisim_graph := fun _ W => qmap_bisim W

def qsol : Nat → Exp Act Tst
  | 0 => sol0
  | 1 => sol1
  | 2 => sol2
  | 3 => sol3
  | 4 => sol4
  | _ => Exp.test BExp.zero

theorem qsol_solves : SolvesBA QAut qsol := by
  intro s hs
  match s, hs with
  | 0, _ => exact EquivBA.base (Equiv.refl _)
  | 1, _ => exact ringE1
  | 2, _ => exact ringE2
  | 3, _ => exact ringE3
  | 4, _ => exact ringE4

theorem cert : EquivBA eP fP :=
  certifiedThompson_uniform_solved_quotient qquot qsol qsol_solves rfl

#print axioms cert

end GkatK6R50

