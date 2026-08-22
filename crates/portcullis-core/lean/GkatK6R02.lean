import GkatCertSupportProofs
import GkatRingSupportProofs
import GkatDeadExitElimProofs
import GkatSumQuotientProofs

/-! # GkatK6R02: emitted instance certificate (machine-generated; see emit_cert.py) -/

namespace GkatK6R02

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport
open GkatGuardedAlgebra GkatRingSupport

abbrev Tst := Unit
abbrev Act := Unit
def bT : BExp Tst := .prim ()
def pA : Exp Act Tst := .act ()
def eP : Exp Act Tst := (Exp.ite bT (Exp.wh bT (Exp.seq pA (Exp.ite bT (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA) (Exp.seq pA (Exp.test (BExp.not bT)))))) (Exp.seq pA (Exp.test (BExp.not bT))))
def fP : Exp Act Tst := (Exp.seq (Exp.seq (Exp.ite (BExp.not bT) (Exp.test (BExp.not bT)) pA) (Exp.ite (BExp.not bT) (Exp.seq pA (Exp.test (BExp.not bT))) (Exp.test bT))) (Exp.wh bT (Exp.seq pA (Exp.ite bT (Exp.seq pA (Exp.ite (BExp.not bT) (Exp.seq pA (Exp.test (BExp.not bT))) (Exp.test bT))) (Exp.test (BExp.not bT))))))

abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut
abbrev SUM := sumGAut eAut fAut

/-! ## Ring solutions (machine-generated; see emit_ring.py).
    SCC [1, 2] header=2 exit=(BExp.not bT); the walk plan and every proof
    recipe follow GkatRingSupportProofs and the GkatCertR1-R6 instances. -/

def sol3 : Exp Act Tst := (.test (BExp.not bT))
def BODY : Exp Act Tst := (.seq pA (.ite (BExp.not bT) (.seq pA sol3) pA))
def sol2 : Exp Act Tst := (.seq (.wh bT BODY) (.test (BExp.not bT)))
def sol1 : Exp Act Tst := (.seq (.ite (BExp.not bT) (.seq pA sol3) pA) sol2)
def sol0 : Exp Act Tst := (.ite (BExp.not bT) (.seq pA sol3) (.ite bT (.seq pA sol1) (.test BExp.zero)))

private theorem habs2 : EquivBA (.seq (.test (BExp.not bT)) sol2) (.test (BExp.not bT)) :=
  test_header_absorb (BExp.not bT) bT BODY (himp_self (BExp.not bT))

private theorem abs3 : EquivBA (.seq sol3 sol2) sol3 :=
  habs2

theorem ringE2 : EquivBA sol2 (.ite bT (.seq pA sol1) (.test (BExp.not bT))) :=
  EquivBA.trans (EquivBA.base (salomaa_solution_exists bT BODY (.test (BExp.not bT))))
    (EquivBA.ite_c (EquivBA.base (Equiv.s1 pA (.ite (BExp.not bT) (.seq pA sol3) pA) sol2)) (EquivBA.base (Equiv.refl _)))

theorem ringE1 : EquivBA sol1 (.ite (BExp.not bT) (.seq pA sol3) (.ite bT (.seq pA sol2) (.test BExp.zero))) :=
  (EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 (BExp.not bT) (.seq pA sol3) pA sol2)))
    (EquivBA.trans (EquivBA.ite_c (EquivBA.trans (EquivBA.base (Equiv.s1 pA sol3 sol2))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) abs3)) (EquivBA.base (Equiv.refl _)))
    (else_expand (BExp.not bT) bT (himp_dneg bT))))


def QAut : GAut Nat Act Tst where
  states := [0, 1, 2, 3]
  hlt
    | 0 => BExp.zero
    | 1 => BExp.zero
    | 2 => (BExp.not bT)
    | 3 => (BExp.not bT)
    | _ => BExp.zero
  trans
    | 0 => [((BExp.not bT), (), 3), (bT, (), 1)]
    | 1 => [((BExp.not bT), (), 3), (bT, (), 2)]
    | 2 => [(bT, (), 1)]
    | 3 => []
    | _ => []
  start := 0

def qmap : Sum (Option (certifiedThompson Act Tst eP).State)
             (Option (certifiedThompson Act Tst fP).State) → Nat
  | .inl none => 0
  | .inl (some (Sum.inl (Sum.inl ()))) => 1
  | .inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => 2
  | .inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ()))))) => 3
  | .inl (some (Sum.inr (Sum.inl ()))) => 3
  | .inr none => 0
  | .inr (some (Sum.inl (Sum.inl (Sum.inr ())))) => 1
  | .inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))) => 3
  | .inr (some (Sum.inr (Sum.inl ()))) => 2
  | .inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))) => 1
  | .inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))) => 3
  | _ => 0

variable {X : Type} (W : Tst → X → Bool) (x : X)

theorem qstep_0_false (h : W () x = false) :
    autStep W QAut 0 x = some ((), 3) := by
  rw [autStep_unit, h]; rfl
theorem qstep_0_true (h : W () x = true) :
    autStep W QAut 0 x = some ((), 1) := by
  rw [autStep_unit, h]; rfl
theorem qstep_1_false (h : W () x = false) :
    autStep W QAut 1 x = some ((), 3) := by
  rw [autStep_unit, h]; rfl
theorem qstep_1_true (h : W () x = true) :
    autStep W QAut 1 x = some ((), 2) := by
  rw [autStep_unit, h]; rfl
theorem qstep_2_false (h : W () x = false) :
    autStep W QAut 2 x = none := by
  rw [autStep_unit, h]; rfl
theorem qstep_2_true (h : W () x = true) :
    autStep W QAut 2 x = some ((), 1) := by
  rw [autStep_unit, h]; rfl
theorem qstep_3_false (h : W () x = false) :
    autStep W QAut 3 x = none := by
  rw [autStep_unit, h]; rfl
theorem qstep_3_true (h : W () x = true) :
    autStep W QAut 3 x = none := by
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
            exact ⟨3, qstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl none) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = some ((), 3) := by rfl
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
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inl ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inl ()))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) a = bval W (QAut.hlt 2) a
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
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_2_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ()))))))) a = bval W (QAut.hlt 3) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
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
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inl (some (Sum.inr (Sum.inl ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inr (Sum.inl ()))))) a = bval W (QAut.hlt 3) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
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
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr none) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_0_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 0 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 0 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ()))))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))) a = bval W (QAut.hlt 3) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
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
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inr (Sum.inl ())))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨1, qstep_2_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 2 ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 2 ()
                = some ((), 1) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ())))))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨3, qstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ())))))) ()
                = some ((), (Sum.inr (some (Sum.inr (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨2, qstep_1_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) QAut 1 ()
                = some ((), 3) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ())))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) QAut 1 ()
                = some ((), 2) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))))) a = bval W (QAut.hlt 3) a
        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ())))))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ())))))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
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
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)

def qquot : UniformBehavioralGAutQuotient SUM QAut where
  mapState := qmap
  maps_states := by
    intro s _
    match s with
    | Sum.inl none => exact (List.Mem.head _)
    | Sum.inl (some (Sum.inl (Sum.inl ()))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))
    | Sum.inl (some (Sum.inr (Sum.inl ()))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))
    | Sum.inr none => exact (List.Mem.head _)
    | Sum.inr (some (Sum.inl (Sum.inl (Sum.inr ())))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))
    | Sum.inr (some (Sum.inr (Sum.inl ()))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inl ()))))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inr (some (Sum.inr (Sum.inr (Sum.inl (Sum.inr (Sum.inl (Sum.inl ()))))))) => exact (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))
  onto_states := by
    intro q hq
    match q, hq with
    | 0, _ => exact ⟨(Sum.inl none), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _)))), rfl⟩
    | 1, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inl ())))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inl ())))))))), rfl⟩
    | 2, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))))))), rfl⟩
    | 3, _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inr (Sum.inl ())))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inr (Sum.inr (Sum.inl ())))))))))), rfl⟩
  bisim_graph := fun _ W => qmap_bisim W

def qsol : Nat → Exp Act Tst
  | 0 => sol0
  | 1 => sol1
  | 2 => sol2
  | 3 => sol3
  | _ => Exp.test BExp.zero

theorem qsol_solves : SolvesBA QAut qsol := by
  intro s hs
  match s, hs with
  | 0, _ => exact EquivBA.base (Equiv.refl _)
  | 1, _ => exact ringE1
  | 2, _ => exact ringE2
  | 3, _ => exact EquivBA.base (Equiv.refl _)

theorem cert : EquivBA eP fP :=
  certifiedThompson_uniform_solved_quotient qquot qsol qsol_solves rfl

#print axioms cert

end GkatK6R02

