import GkatCertSupportBoolProofs
import GkatRingSupportProofs
import GkatDeadExitElimProofs

/-! # GkatMixPilot: the mixed-halt frontier candidate, certified (emitted from Rust;
    see emit_mix_pilot in span-search).  Subset parking over Tst = Bool: the interior
    halt guard is a proper subset of the header's exit guard.  First certificate at
    two primitive tests. -/

namespace GkatMixPilot

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim
open GkatCertSupportBool GkatGuardedAlgebra GkatRingSupport GkatResidue

abbrev Tst := Bool
abbrev Act := Unit
def bT1 : BExp Tst := .prim true
def bT2 : BExp Tst := .prim false
def pA : Exp Act Tst := .act ()
def eP : Exp Act Tst := (Exp.ite (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2)) (Exp.test (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.or (BExp.and bT1 (BExp.not bT2)) (BExp.and bT1 bT2)))) (Exp.wh (BExp.or (BExp.and bT1 (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2)) (Exp.ite (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2)) pA (Exp.wh (BExp.or (BExp.and bT1 (BExp.not bT2)) (BExp.and bT1 bT2)) (Exp.ite (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2)) pA pA)))))
def fP : Exp Act Tst := (Exp.wh (BExp.or (BExp.and bT1 (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2)) (Exp.ite (BExp.and bT1 (BExp.not bT2)) (Exp.seq pA (Exp.wh (BExp.and bT1 bT2) (Exp.seq (Exp.ite (BExp.and (BExp.not bT1) (BExp.not bT2)) (Exp.test (BExp.and bT1 (BExp.not bT2))) pA) (Exp.wh (BExp.or (BExp.and bT1 (BExp.not bT2)) (BExp.and bT1 bT2)) pA)))) pA))

abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut
abbrev SUM := sumGAut eAut fAut

/-! ## Subset-parking solutions -/

def SLs : Exp Act Tst := .wh (.or (BExp.and bT1 (BExp.not bT2)) (BExp.and bT1 bT2)) pA
def PKs : Exp Act Tst := .ite (BExp.and (BExp.not bT1) bT2) pA (.test (BExp.and (BExp.not bT1) (BExp.not bT2)))
def BODY : Exp Act Tst := .ite (BExp.and (BExp.not bT1) bT2) pA (.seq pA (.seq SLs PKs))
def solH : Exp Act Tst := .seq (.wh (.or (BExp.and bT1 (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2)) BODY) (.test (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2)))
def solS : Exp Act Tst := .seq SLs (.seq PKs solH)

/-! ## Guard facts (four-valuation case analysis) -/

private theorem himp_step : GuardImplies (BExp.and bT1 (BExp.not bT2)) (.not (BExp.and (BExp.not bT1) bT2)) := by
  intro X W x h
  revert h
  cases hb1 : W true x <;> cases hb2 : W false x <;> simp [bval, bT1, bT2, hb1, hb2]
private theorem himp_selfg : GuardImplies (BExp.and (BExp.not bT1) bT2) (BExp.and (BExp.not bT1) bT2) :=
  fun _ _ _ h => h
private theorem himp_park : GuardImplies (BExp.and (BExp.not bT1) (BExp.not bT2)) (.not (.or (BExp.and bT1 (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2))) := by
  intro X W x h
  revert h
  cases hb1 : W true x <;> cases hb2 : W false x <;> simp [bval, bT1, bT2, hb1, hb2]

private theorem hsub : ∀ (X : Type) (W : Tst → X → Bool) (x : X),
    (bval W (BExp.and (BExp.not bT1) (BExp.not bT2)) x && bval W (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2)) x) = bval W (BExp.and (BExp.not bT1) (BExp.not bT2)) x := by
  intro X W x
  cases hb1 : W true x <;> cases hb2 : W false x <;> simp [bval, bT1, bT2, hb1, hb2]

private theorem habs_sub : EquivBA (.seq (.test (BExp.and (BExp.not bT1) (BExp.not bT2))) solH) (.test (BExp.and (BExp.not bT1) (BExp.not bT2))) :=
  test_header_absorb_sub (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2)) (.or (BExp.and bT1 (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2)) BODY himp_park hsub

/-! ## The two SolvesBA obligations -/

theorem ring_EH : EquivBA solH
    (.ite (BExp.and bT1 (BExp.not bT2)) (.seq pA solS) (.ite (BExp.and (BExp.not bT1) bT2) (.seq pA solH) (.test (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2))))) := by
  refine EquivBA.trans (EquivBA.base (salomaa_solution_exists (.or (BExp.and bT1 (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2)) BODY (.test (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2))))) ?_
  refine EquivBA.trans (ite_or_split (BExp.and bT1 (BExp.not bT2)) (BExp.and (BExp.not bT1) bT2) (.seq BODY solH) (.test (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2)))) ?_
  have h_step : EquivBA (.seq (.test (BExp.and bT1 (BExp.not bT2))) (.seq BODY solH))
      (.seq (.test (BExp.and bT1 (BExp.not bT2))) (.seq pA solS)) := by
    have hstep : EquivBA (.seq (.test (BExp.and bT1 (BExp.not bT2))) BODY)
        (.seq (.test (BExp.and bT1 (BExp.not bT2))) (.seq pA (.seq SLs PKs))) := by
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.base (Equiv.u2 (BExp.and (BExp.not bT1) bT2) pA (.seq pA (.seq SLs PKs))))) ?_
      exact test_seq_ite_of_implies _ _ himp_step
    refine EquivBA.trans (seq_under_guard solH hstep) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.s1 pA (.seq SLs PKs) solH)) ?_
    exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.base (Equiv.s1 SLs PKs solH))
  have h_self : EquivBA (.seq (.test (BExp.and (BExp.not bT1) bT2)) (.seq BODY solH))
      (.seq (.test (BExp.and (BExp.not bT1) bT2)) (.seq pA solH)) := by
    have hstep : EquivBA (.seq (.test (BExp.and (BExp.not bT1) bT2)) BODY) (.seq (.test (BExp.and (BExp.not bT1) bT2)) pA) :=
      test_seq_ite_of_implies _ _ himp_selfg
    exact seq_under_guard solH hstep
  exact EquivBA.trans (ite_congr_under_guard h_step)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ite_congr_under_guard h_self))

theorem ring_ES : EquivBA solS
    (.ite (BExp.and bT1 (BExp.not bT2)) (.seq pA solS) (.ite (BExp.and bT1 bT2) (.seq pA solS)
      (.ite (BExp.and (BExp.not bT1) bT2) (.seq pA solH) (.test (BExp.and (BExp.not bT1) (BExp.not bT2)))))) := by
  refine EquivBA.trans (EquivBA.base (salomaa_solution_exists (.or (BExp.and bT1 (BExp.not bT2)) (BExp.and bT1 bT2)) pA
    (.seq PKs solH))) ?_
  refine EquivBA.trans (ite_or_split (BExp.and bT1 (BExp.not bT2)) (BExp.and bT1 bT2) (.seq pA solS) (.seq PKs solH)) ?_
  refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
  refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
  refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 (BExp.and (BExp.not bT1) bT2) pA (.test (BExp.and (BExp.not bT1) (BExp.not bT2))) solH))) ?_
  exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) habs_sub

/-! ## Quotient, map, bisimulation -/

def QAut : GAut Nat Act Tst where
  states := [0, 1]
  hlt
    | 0 => (BExp.or (BExp.and (BExp.not bT1) (BExp.not bT2)) (BExp.and bT1 bT2))
    | 1 => (BExp.and (BExp.not bT1) (BExp.not bT2))
    | _ => BExp.zero
  trans
    | 0 => [((BExp.and bT1 (BExp.not bT2)), (), 1), ((BExp.and (BExp.not bT1) bT2), (), 0)]
    | 1 => [((BExp.and bT1 (BExp.not bT2)), (), 1), ((BExp.and bT1 bT2), (), 1), ((BExp.and (BExp.not bT1) bT2), (), 0)]
    | _ => []
  start := 0

def qmap : Sum (Option (certifiedThompson Act Tst eP).State)
             (Option (certifiedThompson Act Tst fP).State) → Nat
  | .inl none => 0
  | .inl (some (Sum.inr (Sum.inr (Sum.inr ())))) => 1
  | .inl (some (Sum.inr (Sum.inl ()))) => 0
  | .inl (some (Sum.inr (Sum.inr (Sum.inl ())))) => 1
  | .inr none => 0
  | .inr (some (Sum.inl (Sum.inl ()))) => 1
  | .inr (some (Sum.inr ())) => 0
  | .inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => 1
  | .inr (some (Sum.inl (Sum.inr (Sum.inr ())))) => 1
  | _ => 0

variable {X : Type} (W : Tst → X → Bool) (x : X)

theorem qstep_0_00 (h1 : W true x = false) (h2 : W false x = false) :
    autStep W QAut 0 x = none := by
  rw [autStep_bool, h1, h2]; rfl
theorem qstep_0_01 (h1 : W true x = false) (h2 : W false x = true) :
    autStep W QAut 0 x = some ((), 0) := by
  rw [autStep_bool, h1, h2]; rfl
theorem qstep_0_10 (h1 : W true x = true) (h2 : W false x = false) :
    autStep W QAut 0 x = some ((), 1) := by
  rw [autStep_bool, h1, h2]; rfl
theorem qstep_0_11 (h1 : W true x = true) (h2 : W false x = true) :
    autStep W QAut 0 x = none := by
  rw [autStep_bool, h1, h2]; rfl
theorem qstep_1_00 (h1 : W true x = false) (h2 : W false x = false) :
    autStep W QAut 1 x = none := by
  rw [autStep_bool, h1, h2]; rfl
theorem qstep_1_01 (h1 : W true x = false) (h2 : W false x = true) :
    autStep W QAut 1 x = some ((), 0) := by
  rw [autStep_bool, h1, h2]; rfl
theorem qstep_1_10 (h1 : W true x = true) (h2 : W false x = false) :
    autStep W QAut 1 x = some ((), 1) := by
  rw [autStep_bool, h1, h2]; rfl
theorem qstep_1_11 (h1 : W true x = true) (h2 : W false x = true) :
    autStep W QAut 1 x = some ((), 1) := by
  rw [autStep_bool, h1, h2]; rfl

theorem qmap_bisim : GAutBisim W SUM QAut (fun s q => qmap s = q) := by
  rintro s1 s2 rfl
  match s1 with
  | Sum.inl none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl none)) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inl none) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inl none) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_0_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inl none) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_0_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inl none) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 0 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 0 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
  | Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ())))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ())))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_1_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_11 W a hb1 hb2, rfl⟩
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 1 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 1 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
  | Sum.inl (some (Sum.inr (Sum.inl ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inr (Sum.inl ()))))) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_0_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_0_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inl (some (Sum.inr (Sum.inl ())))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 0 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 0 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
  | Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ())))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ())))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ()))))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ()))))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inl ()))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_1_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ()))))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ()))))) ()
                  = some ((), (Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_11 W a hb1 hb2, rfl⟩
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 1 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 1 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inl ())))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
  | Sum.inr none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr none)) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inr none) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inr none) ()
                  = some ((), (Sum.inr (some (Sum.inr ())))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_0_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inr none) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inl ()))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_0_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inr none) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 0 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inr ()))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 0 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
  | Sum.inr (some (Sum.inl (Sum.inl ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inl ()))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) ()
                  = some ((), (Sum.inr (some (Sum.inr ())))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_1_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inl ()))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inr (some (Sum.inl (Sum.inl ())))) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_11 W a hb1 hb2, rfl⟩
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 1 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 1 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inr ()))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
  | Sum.inr (some (Sum.inr ())) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inr ())))) a = bval W (QAut.hlt 0) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inr (some (Sum.inr ()))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inr (some (Sum.inr ()))) ()
                  = some ((), (Sum.inr (some (Sum.inr ())))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_0_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inr (some (Sum.inr ()))) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inl ()))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_0_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inr (some (Sum.inr ()))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 0 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inr ()))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 0 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inl ())))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 0 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                  = some ((), (Sum.inr (some (Sum.inr ())))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_1_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ())))))) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_11 W a hb1 hb2, rfl⟩
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 1 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 1 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inr ()))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
  | Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (SUM.hlt (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) a = bval W (QAut.hlt 1) a
        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]
        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))) () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                  = some ((), (Sum.inr (some (Sum.inr ())))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨0, qstep_1_01 W a hb1 hb2, rfl⟩
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_10 W a hb1 hb2, rfl⟩
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) SUM (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))) ()
                  = some ((), (Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))))) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              exact ⟨1, qstep_1_11 W a hb1 hb2, rfl⟩
      · rw [autStep_bool] at hst
        cases hb1 : W true a with
        | false =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false false) QAut 1 () = none := by rfl
              rw [hred] at hst
              exact absurd hst (by simp)
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b false true) QAut 1 ()
                  = some ((), 0) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inr ()))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
        | true =>
          rw [hb1] at hst
          cases hb2 : W false a with
          | false =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true false) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl
          | true =>
              rw [hb2] at hst
              have hred : autStep (fun b (_ : Unit) => cond b true true) QAut 1 ()
                  = some ((), 1) := by rfl
              rw [hred] at hst
              have hs := congrArg Prod.snd (Option.some.inj hst)
              subst hs
              refine ⟨(Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ()))))), ?_, rfl⟩
              rw [autStep_bool, hb1, hb2]
              rfl

def qquot : UniformBehavioralGAutQuotient SUM QAut where
  mapState := qmap
  maps_states := by
    intro s _
    match s with
    | Sum.inl none => exact (List.Mem.head _)
    | Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ())))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inl (some (Sum.inr (Sum.inl ()))) => exact (List.Mem.head _)
    | Sum.inl (some (Sum.inr (Sum.inr (Sum.inl ())))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inr none => exact (List.Mem.head _)
    | Sum.inr (some (Sum.inl (Sum.inl ()))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inr (some (Sum.inr ())) => exact (List.Mem.head _)
    | Sum.inr (some (Sum.inl (Sum.inr (Sum.inl (Sum.inr ()))))) => exact (List.Mem.tail _ (List.Mem.head _))
    | Sum.inr (some (Sum.inl (Sum.inr (Sum.inr ())))) => exact (List.Mem.tail _ (List.Mem.head _))
  onto_states := by
    intro q hq
    match q, hq with
    | 0, _ => exact ⟨(Sum.inl none), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _)))), rfl⟩
    | 1, _ => exact ⟨(Sum.inl (some (Sum.inr (Sum.inr (Sum.inr ()))))), (List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP (Sum.inr (Sum.inr (Sum.inr ()))))))))), rfl⟩
  bisim_graph := fun _ W => qmap_bisim W

def qsol : Nat → Exp Act Tst
  | 0 => solH
  | 1 => solS
  | _ => Exp.test BExp.zero

theorem qsol_solves : SolvesBA QAut qsol := by
  intro st hst
  match st, hst with
  | 0, _ => exact ring_EH
  | 1, _ => exact ring_ES

theorem cert : EquivBA eP fP :=
  certifiedThompson_uniform_solved_quotient qquot qsol qsol_solves rfl

#print axioms cert

end GkatMixPilot
