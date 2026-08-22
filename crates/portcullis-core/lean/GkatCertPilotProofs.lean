import GkatDeadExitElimProofs
import GkatSumQuotientProofs

/-!
# The certificate pipeline's first instance: CERT #3, kernel-checked

The Rust harness's certificate extractor (`PAD_EMIT`) dumped, for the pairk=2 crux pair

    e = (b? +_b p) ; p^(b)        f = p ; p^(b)

the start-merged quotient of `Thompson(e) + Thompson(f)`: two classes — the merged initial
states, and everything else — with the second class self-looping on `b` and halting on `¬b`,
solve order trivial.  This file is the Lean template around that data: the quotient automaton
as a literal, the class map, the bisimulation, and the solution assembled from `levelSol` with
its `SolvesBA` obligation discharged by `level_satisfies`.  The output is

    cert_pilot : EquivBA eP fP

— a machine-checked instance equivalence produced from an extracted certificate, the pipeline's
hello-world.  Everything here is mechanical given the certificate, which is the point: the
emitter's job is to write files shaped exactly like this one.
-/

namespace GkatCertPilot

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim

abbrev Tst := Unit
abbrev Act := Unit

def bT : BExp Tst := .prim ()
def pA : Exp Act Tst := .act ()

/-- `e = (b? +_b p) ; p^(b)`. -/
def eP : Exp Act Tst := .seq (.ite bT (.test bT) pA) (.wh bT pA)

/-- `f = p ; p^(b)`. -/
def fP : Exp Act Tst := .seq pA (.wh bT pA)

abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut
abbrev SUM := sumGAut eAut fAut

/-- The extracted quotient: class `false` = the merged initial states, class `true` =
    everything else, self-looping on `b`, halting on `¬b`. -/
def QAut : GAut Bool Act Tst where
  states := [false, true]
  hlt
    | false => .zero
    | true => .not bT
  trans
    | false => [(.one, (), true)]
    | true => [(bT, (), true)]
  start := false

def qmap : Sum (Option (certifiedThompson Act Tst eP).State)
             (Option (certifiedThompson Act Tst fP).State) → Bool
  | .inl none => false
  | .inr none => false
  | _ => true

variable {X : Type} (W : Tst → X → Bool) (x : X)

private theorem bT_val : bval W bT x = W () x := rfl

/-! ## The six sum states, computed -/

private theorem pA_core_hlt : bval W ((certifiedThompson Act Tst pA).aut.core.hlt ()) x = true := rfl
private theorem pA_initHlt : bval W (certifiedThompson Act Tst pA).aut.initHlt x = false := rfl
private theorem test_bT_initHlt :
    bval W (certifiedThompson Act Tst (Exp.test bT)).aut.initHlt x = W () x := rfl
private theorem loop_initHlt :
    bval W (certifiedThompson Act Tst (Exp.wh bT pA)).aut.initHlt x = !(W () x) := rfl

private theorem C_cp_core_hlt :
    bval W ((certifiedThompson Act Tst (Exp.ite bT (Exp.test bT) pA)).aut.core.hlt
      (Sum.inr ())) x = true := rfl

/-- The guarded choice `b? +_b p` halts initially exactly on `b`. -/
private theorem C_initHlt :
    bval W (certifiedThompson Act Tst (Exp.ite bT (Exp.test bT) pA)).aut.initHlt x
      = W () x := by
  show (_ || _) = _
  simp [bval, bT_val, test_bT_initHlt, pA_initHlt]

/-! ## The six sum states, computed -/

theorem e_none_hlt : bval W (eAut.hlt none) x = false := by
  cases h : W () x <;> · show (_ && _) = false; simp [bval, bT_val, C_initHlt, loop_initHlt, h]

theorem e_cp_hlt : bval W (eAut.hlt (some (Sum.inl (Sum.inr ())))) x = !(W () x) := by
  show (_ && _) = _
  simp [bval, bT_val, C_cp_core_hlt, loop_initHlt]

theorem e_loop_hlt : bval W (eAut.hlt (some (Sum.inr ()))) x = !(W () x) := by
  show (_ && _) = _
  simp [bval, bT_val, pA_core_hlt]

theorem f_none_hlt : bval W (fAut.hlt none) x = false := by
  cases h : W () x <;> · show (_ && _) = false; simp [bval, bT_val, pA_initHlt, loop_initHlt, h]

theorem f_p1_hlt : bval W (fAut.hlt (some (Sum.inl ()))) x = !(W () x) := by
  show (_ && _) = _
  simp [bval, bT_val, pA_core_hlt, loop_initHlt]

theorem f_loop_hlt : bval W (fAut.hlt (some (Sum.inr ()))) x = !(W () x) := by
  show (_ && _) = _
  simp [bval, bT_val, pA_core_hlt]

theorem e_none_step (h : W () x = true) :
    autStep W eAut none x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else (if bval W _ x then _ else _)) = _
  simp [bval, bT_val, C_initHlt, h]
  rfl

theorem e_none_step_ff (h : W () x = false) :
    autStep W eAut none x = some ((), some (Sum.inl (Sum.inr ()))) := by
  show (if bval W _ x then _ else (if bval W _ x then _ else _)) = _
  simp [bval, bT_val, C_initHlt, h]
  rfl

theorem e_cp_step (h : W () x = true) :
    autStep W eAut (some (Sum.inl (Sum.inr ()))) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

theorem e_cp_step_ff (h : W () x = false) :
    autStep W eAut (some (Sum.inl (Sum.inr ()))) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

theorem e_loop_step (h : W () x = true) :
    autStep W eAut (some (Sum.inr ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

theorem e_loop_step_ff (h : W () x = false) :
    autStep W eAut (some (Sum.inr ())) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

theorem f_none_step : autStep W fAut none x = some ((), some (Sum.inl ())) := rfl

theorem f_p1_step (h : W () x = true) :
    autStep W fAut (some (Sum.inl ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

theorem f_p1_step_ff (h : W () x = false) :
    autStep W fAut (some (Sum.inl ())) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

theorem f_loop_step (h : W () x = true) :
    autStep W fAut (some (Sum.inr ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

theorem f_loop_step_ff (h : W () x = false) :
    autStep W fAut (some (Sum.inr ())) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, pA_core_hlt, h]
  rfl

/-! ## The quotient automaton, computed -/

theorem q_hlt_false : bval W (QAut.hlt false) x = false := rfl
theorem q_hlt_true : bval W (QAut.hlt true) x = !(W () x) := rfl
theorem q_step_false : autStep W QAut false x = some ((), true) := rfl

theorem q_step_true (h : W () x = true) : autStep W QAut true x = some ((), true) := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, h]

theorem q_step_true_ff (h : W () x = false) : autStep W QAut true x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, h]
  rfl

theorem sum_step_inl (s : Option (certifiedThompson Act Tst eP).State) :
    autStep W SUM (Sum.inl s) x = (autStep W eAut s x).map (fun o => (o.1, Sum.inl o.2)) := by
  show firstMatch W x ((eAut.trans s).map _) = _
  rw [firstMatch_map_target_to]; rfl

theorem sum_step_inr (s : Option (certifiedThompson Act Tst fP).State) :
    autStep W SUM (Sum.inr s) x = (autStep W fAut s x).map (fun o => (o.1, Sum.inr o.2)) := by
  show firstMatch W x ((fAut.trans s).map _) = _
  rw [firstMatch_map_target_to]; rfl

/-! ## The class map is a bisimulation -/

private theorem inl_tgt {S₁ S₂ : Type} {o : Act × S₁} {q : Act} {s' : Sum S₁ S₂}
    (h : (Option.map (fun z => (z.1, Sum.inl z.2)) (some o) : Option (Act × Sum S₁ S₂))
        = some (q, s')) : Sum.inl o.2 = s' :=
  congrArg Prod.snd (Option.some.inj h)

private theorem inr_tgt {S₁ S₂ : Type} {o : Act × S₂} {q : Act} {s' : Sum S₁ S₂}
    (h : (Option.map (fun z => (z.1, Sum.inr z.2)) (some o) : Option (Act × Sum S₁ S₂))
        = some (q, s')) : Sum.inr o.2 = s' :=
  congrArg Prod.snd (Option.some.inj h)

private theorem q_tgt {q : Act} {s2' : Bool} (h : some ((), true) = some (q, s2')) :
    (true : Bool) = s2' := congrArg Prod.snd (Option.some.inj h)

theorem qmap_bisim : GAutBisim W SUM QAut (fun s q => qmap s = q) := by
  rintro s1 s2 rfl
  match s1 with
  | .inl (some (Sum.inl (Sum.inl v))) => exact nomatch v
  | .inl none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (eAut.hlt none) a = bval W (QAut.hlt false) a
        rw [e_none_hlt, q_hlt_false]
      · rw [sum_step_inl] at hst
        cases hb : W () a with
        | true =>
            rw [e_none_step W a hb] at hst
            have hs := inl_tgt hst
            subst hs
            exact ⟨true, q_step_false W a, rfl⟩
        | false =>
            rw [e_none_step_ff W a hb] at hst
            have hs := inl_tgt hst
            subst hs
            exact ⟨true, q_step_false W a, rfl⟩
      · rw [q_step_false] at hst
        have hs := q_tgt hst
        subst hs
        cases hb : W () a with
        | true =>
            refine ⟨Sum.inl (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inl, e_none_step W a hb]; rfl
        | false =>
            refine ⟨Sum.inl (some (Sum.inl (Sum.inr ()))), ?_, rfl⟩
            rw [sum_step_inl, e_none_step_ff W a hb]; rfl
  | .inr none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (fAut.hlt none) a = bval W (QAut.hlt false) a
        rw [f_none_hlt, q_hlt_false]
      · rw [sum_step_inr, f_none_step] at hst
        have hs := inr_tgt hst
        subst hs
        exact ⟨true, q_step_false W a, rfl⟩
      · rw [q_step_false] at hst
        have hs := q_tgt hst
        subst hs
        refine ⟨Sum.inr (some (Sum.inl ())), ?_, rfl⟩
        rw [sum_step_inr, f_none_step]; rfl
  | .inl (some (Sum.inl (Sum.inr ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (eAut.hlt (some (Sum.inl (Sum.inr ())))) a = bval W (QAut.hlt true) a
        rw [e_cp_hlt, q_hlt_true]
      · rw [sum_step_inl] at hst
        cases hb : W () a with
        | false => rw [e_cp_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [e_cp_step W a hb] at hst
            have hs := inl_tgt hst
            subst hs
            exact ⟨true, q_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [q_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [q_step_true W a hb] at hst
            have hs := q_tgt hst
            subst hs
            refine ⟨Sum.inl (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inl, e_cp_step W a hb]; rfl
  | .inl (some (Sum.inr ())) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (eAut.hlt (some (Sum.inr ()))) a = bval W (QAut.hlt true) a
        rw [e_loop_hlt, q_hlt_true]
      · rw [sum_step_inl] at hst
        cases hb : W () a with
        | false => rw [e_loop_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [e_loop_step W a hb] at hst
            have hs := inl_tgt hst
            subst hs
            exact ⟨true, q_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [q_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [q_step_true W a hb] at hst
            have hs := q_tgt hst
            subst hs
            refine ⟨Sum.inl (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inl, e_loop_step W a hb]; rfl
  | .inr (some (Sum.inl ())) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (fAut.hlt (some (Sum.inl ()))) a = bval W (QAut.hlt true) a
        rw [f_p1_hlt, q_hlt_true]
      · rw [sum_step_inr] at hst
        cases hb : W () a with
        | false => rw [f_p1_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [f_p1_step W a hb] at hst
            have hs := inr_tgt hst
            subst hs
            exact ⟨true, q_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [q_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [q_step_true W a hb] at hst
            have hs := q_tgt hst
            subst hs
            refine ⟨Sum.inr (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inr, f_p1_step W a hb]; rfl
  | .inr (some (Sum.inr ())) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (fAut.hlt (some (Sum.inr ()))) a = bval W (QAut.hlt true) a
        rw [f_loop_hlt, q_hlt_true]
      · rw [sum_step_inr] at hst
        cases hb : W () a with
        | false => rw [f_loop_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [f_loop_step W a hb] at hst
            have hs := inr_tgt hst
            subst hs
            exact ⟨true, q_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [q_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [q_step_true W a hb] at hst
            have hs := q_tgt hst
            subst hs
            refine ⟨Sum.inr (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inr, f_loop_step W a hb]; rfl

/-! ## The quotient structure, the solution, and the payoff -/

def qquot : UniformBehavioralGAutQuotient SUM QAut where
  mapState := qmap
  maps_states := by
    intro s _
    cases hq : qmap s with
    | false => exact List.Mem.head _
    | true => exact List.Mem.tail _ (List.Mem.head _)
  onto_states := by
    intro q hq
    cases q with
    | false =>
        refine ⟨Sum.inl none, ?_, rfl⟩
        exact List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _)))
    | true =>
        refine ⟨Sum.inl (some (Sum.inr ())), ?_, rfl⟩
        refine List.mem_append.mpr (Or.inl (List.mem_map_of_mem ?_))
        exact List.Mem.tail _ (List.mem_map_of_mem
          (GkatTotalization.thompson_states_complete eP (Sum.inr ())))
  bisim_graph := fun _ W => qmap_bisim W

/-- The certificate's single level: one self-loop on `b`, no forward branches, halt `¬b`. -/
def L1 : LevelG Act Tst := ([(bT, pA)], [], .test (.not bT))

def qsol : Bool → Exp Act Tst
  | true => levelSol L1
  | false => .seq pA (levelSol L1)

theorem qsol_solves : SolvesBA QAut qsol := by
  intro s hs
  cases s with
  | false => exact EquivBA.symm (GkatFaithful.ite_one _ _)
  | true => exact level_satisfies L1

/-- **The pipeline's first machine-checked instance**: `(b? +_b p) ; p^(b) ≡ p ; p^(b)`,
    derived from the extracted certificate. -/
theorem cert_pilot : EquivBA eP fP :=
  certifiedThompson_uniform_solved_quotient qquot qsol qsol_solves rfl

#print axioms cert_pilot

end GkatCertPilot
