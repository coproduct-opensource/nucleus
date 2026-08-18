import GkatCertSupportProofs
import GkatDeadExitElimProofs
import GkatSumQuotientProofs

/-! # GkatCertT2: emitted Thompson-witness certificate (machine-generated; see emit_cert.py -t) -/

namespace GkatCertT2

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport

abbrev Tst := Unit
abbrev Act := Unit
def bT : BExp Tst := .prim ()
def pA : Exp Act Tst := .act ()
def eP : Exp Act Tst := (Exp.ite (BExp.not bT) (Exp.wh (BExp.not bT) (Exp.seq pA (Exp.ite (BExp.not bT) (Exp.seq (Exp.ite bT (Exp.test BExp.zero) pA) (Exp.wh (BExp.not bT) pA)) pA))) (Exp.test BExp.zero))
def fP : Exp Act Tst := (Exp.ite (BExp.not bT) (Exp.wh (BExp.not bT) (Exp.seq pA (Exp.ite (BExp.not bT) (Exp.wh (BExp.not bT) (Exp.seq (Exp.ite bT (Exp.test BExp.zero) pA) (Exp.ite bT (Exp.test bT) pA))) pA))) (Exp.test BExp.zero))
def gP : Exp Act Tst := (Exp.seq (Exp.seq pA (Exp.test (BExp.not bT))) (Exp.wh (BExp.not bT) (Exp.seq pA (Exp.ite bT (Exp.ite (BExp.not bT) (Exp.test BExp.zero) pA) (Exp.wh (BExp.not bT) pA)))))

abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut
abbrev SUM := sumGAut eAut fAut
abbrev gC := certifiedThompson Act Tst gP
def START : gC.State := (Sum.inl (Sum.inl ()))
def TAut : GAut gC.State Act Tst := coreGAut gC START

def tmap : Sum (Option (certifiedThompson Act Tst eP).State)
             (Option (certifiedThompson Act Tst fP).State) → gC.State
  | .inl none => (Sum.inl (Sum.inl ()))
  | .inl (some (Sum.inl (Sum.inl ()))) => (Sum.inr (Sum.inl ()))
  | .inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))) => (Sum.inr (Sum.inr (Sum.inr ())))
  | .inl (some (Sum.inl (Sum.inr (Sum.inr ())))) => (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))
  | .inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => (Sum.inr (Sum.inr (Sum.inr ())))
  | .inr none => (Sum.inl (Sum.inl ()))
  | .inr (some (Sum.inl (Sum.inl ()))) => (Sum.inr (Sum.inl ()))
  | .inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))) => (Sum.inr (Sum.inr (Sum.inr ())))
  | .inr (some (Sum.inl (Sum.inr (Sum.inr ())))) => (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))
  | .inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))) => (Sum.inr (Sum.inr (Sum.inr ())))
  | _ => START

variable {X : Type} (W : Tst → X → Bool) (x : X)

theorem tstep_0_false (h : W () x = false) :
    autStep W TAut ((Sum.inl (Sum.inl ())) : gC.State) x = some ((), ((Sum.inr (Sum.inl ())) : gC.State)) := by
  rw [autStep_unit, h]; rfl
theorem tstep_0_true (h : W () x = true) :
    autStep W TAut ((Sum.inl (Sum.inl ())) : gC.State) x = none := by
  rw [autStep_unit, h]; rfl
theorem tstep_1_false (h : W () x = false) :
    autStep W TAut ((Sum.inr (Sum.inl ())) : gC.State) x = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by
  rw [autStep_unit, h]; rfl
theorem tstep_1_true (h : W () x = true) :
    autStep W TAut ((Sum.inr (Sum.inl ())) : gC.State) x = some ((), ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State)) := by
  rw [autStep_unit, h]; rfl
theorem tstep_2_false (h : W () x = false) :
    autStep W TAut ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State) x = some ((), ((Sum.inr (Sum.inl ())) : gC.State)) := by
  rw [autStep_unit, h]; rfl
theorem tstep_2_true (h : W () x = true) :
    autStep W TAut ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State) x = none := by
  rw [autStep_unit, h]; rfl
theorem tstep_3_false (h : W () x = false) :
    autStep W TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) x = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by
  rw [autStep_unit, h]; rfl
theorem tstep_3_true (h : W () x = true) :
    autStep W TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) x = none := by
  rw [autStep_unit, h]; rfl

theorem tmap_bisim : GAutBisim W SUM TAut (fun s q => tmap s = q) := by
  rintro s1 s2 rfl
  match s1 with
  | Sum.inl none =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl none)) a = bval W (TAut.hlt (Sum.inl (Sum.inl ()))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl none) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inl ())), tstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl none) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inl (Sum.inl ())) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inl ())) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inl (Sum.inl ())) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inl (some (Sum.inl (Sum.inl ()))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inl ()))))) a = bval W (TAut.hlt (Sum.inr (Sum.inl ()))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inr ()))), tstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))), tstep_1_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inl ())) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inl ())) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))))) a = bval W (TAut.hlt (Sum.inr (Sum.inr (Sum.inr ())))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inr ()))), tstep_3_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inl (some (Sum.inl (Sum.inr (Sum.inr ())))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr ())))))) a = bval W (TAut.hlt (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inl ())), tstep_2_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inl ())) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) a = bval W (TAut.hlt (Sum.inr (Sum.inr (Sum.inr ())))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = some ((), (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inr ()))), tstep_3_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inr none =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr none)) a = bval W (TAut.hlt (Sum.inl (Sum.inl ()))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
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
            exact ⟨(Sum.inr (Sum.inl ())), tstep_0_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr none) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inl (Sum.inl ())) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inl ())) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inl (Sum.inl ())) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inr (some (Sum.inl (Sum.inl ()))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inl ()))))) a = bval W (TAut.hlt (Sum.inr (Sum.inl ()))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inr ()))), tstep_1_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))), tstep_1_true W a hb, rfl⟩
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inl ())) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inl ())) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))))) a = bval W (TAut.hlt (Sum.inr (Sum.inr (Sum.inr ())))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inr ()))), tstep_3_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) a = bval W (TAut.hlt (Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inl ()))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inl ())), tstep_2_false W a hb, rfl⟩
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
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inl ())) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inr (Sum.inl (Sum.inr ())))) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))) =>
      first | simp only [tmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr (Sum.inr ())))))))) a = bval W (TAut.hlt (Sum.inr (Sum.inr (Sum.inr ())))) a
        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]
        cases hb : W () a <;> rfl
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr (Sum.inr ()))))))) ()
                = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ())))))))) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            exact ⟨(Sum.inr (Sum.inr (Sum.inr ()))), tstep_3_false W a hb, rfl⟩
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr (Sum.inr ()))))))) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)
      · rw [autStep_unit] at hst
        cases hb : W () a with
        | false =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => false) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = some ((), ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State)) := by rfl
            rw [hred] at hst
            have hs := congrArg Prod.snd (Option.some.inj hst)
            subst hs
            refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))), ?_, rfl⟩
            rw [autStep_unit, hb]
            rfl
        | true =>
            rw [hb] at hst
            have hred : autStep (fun _ (_ : Unit) => true) TAut ((Sum.inr (Sum.inr (Sum.inr ()))) : gC.State) ()
                = none := by rfl
            rw [hred] at hst
            exact absurd hst (by simp)

def tquot : UniformBehavioralGAutQuotient SUM TAut where
  mapState := tmap
  maps_states := fun s _ => GkatTotalization.thompson_states_complete gP (tmap s)
  onto_states := by
    intro q hq
    match q, hq with
    | Sum.inl (Sum.inl ()), _ => exact ⟨(Sum.inl none), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _)))), rfl⟩
    | Sum.inr (Sum.inl ()), _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inl ())))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inl ())))))))), rfl⟩
    | Sum.inr (Sum.inr (Sum.inl (Sum.inr ()))), _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inr ()))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inr (Sum.inr ()))))))))), rfl⟩
    | Sum.inr (Sum.inr (Sum.inr ())), _ => exact ⟨(Sum.inl (some (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inl (Sum.inr (Sum.inl (Sum.inl (Sum.inr ()))))))))))), rfl⟩
  bisim_graph := fun _ W => tmap_bisim W

theorem cert : EquivBA eP fP :=
  certifiedThompson_uniform_solved_quotient tquot gC.standard (coreGAut_solves gC START) rfl

#print axioms cert

end GkatCertT2

