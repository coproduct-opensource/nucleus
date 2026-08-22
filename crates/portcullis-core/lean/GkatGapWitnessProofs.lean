import GkatSumQuotientProofs

/-!
# The gap, closed: a solvable quotient where no syntax-generated one exists

`GkatCollapseRefutation.not_commonSyntacticCollapse` refutes the cospan route on the pair

    e = p ; while b do p        f = (if b then 1 else p) ; while b do p

by showing determinism pins the quotient of `Me + Mf` to two states and no THOMPSON automaton
has that shape.  `GkatSumQuotient.gapAut_solvable` shows the two-state shape is nonetheless
solvable.  What was missing was the identification: that the pinned quotient really is that
shape.  This supplies it, so the two halves join into a theorem rather than an argument.

The consequence is that `SumQuotientSolvable` HOLDS on the pair that refutes
`CommonSyntacticCollapse` — the swapped conjunct is strictly weaker, and strictly weaker
exactly where it needs to be.
-/

namespace GkatGapWitness

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCollapseRefutation
open GkatSumQuotient

abbrev eAut := (certifiedThompson Act Tst eProg).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fProg).aut.toGAut

variable {X : Type} (W : Tst → X → Bool) (x : X)

/-! ## The two automata, computed at a general valuation

    Every state of `Me` reduces, and so do `Mf`'s interior states.  `Mf`'s START does not yet:
    `fProg = (if b then 1 else p) ; while b do p` puts an `ite` on the left of a `seq`, so its
    initial transition list is an APPEND of two mapped lists, and `firstMatch` does not reduce
    through the append by `simp`/`rfl` here.  Those three obligations — `f_none_hlt`,
    `f_none_step` at `b`, and at `¬b` — are what remain before the witness closes. -/

private theorem pA_hlt : bval W ((certifiedThompson Act Tst pA).aut.core.hlt ()) x = true := rfl
private theorem bT_val : bval W bT x = W () x := rfl

theorem e_none_hlt : bval W (eAut.hlt none) x = false := rfl
theorem e_mid_hlt : bval W (eAut.hlt (some (Sum.inl ()))) x = !(W () x) := rfl
theorem e_loop_hlt : bval W (eAut.hlt (some (Sum.inr ()))) x = !(W () x) := rfl
theorem f_mid_hlt : bval W (fAut.hlt (some (Sum.inl (Sum.inr ())))) x = !(W () x) := rfl
theorem f_loop_hlt : bval W (fAut.hlt (some (Sum.inr ()))) x = !(W () x) := rfl

theorem e_none_step : autStep W eAut none x = some ((), some (Sum.inl ())) := rfl

theorem e_mid_step (h : W () x = true) :
    autStep W eAut (some (Sum.inl ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

theorem e_loop_step (h : W () x = true) :
    autStep W eAut (some (Sum.inr ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

theorem f_mid_step (h : W () x = true) :
    autStep W fAut (some (Sum.inl (Sum.inr ()))) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

theorem f_loop_step (h : W () x = true) :
    autStep W fAut (some (Sum.inr ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

/-! ## `Mf`'s start

    `fProg = (if b then 1 else p) ; while b do p` puts an `ite` on the left of a `seq`, so the
    initial transition list is an append of two mapped lists.  Forcing it through with a nested
    `if` exposes both branches at once. -/

private theorem test_one_initHlt :
    bval W (certifiedThompson Act Tst (Exp.test BExp.one)).aut.initHlt x = true := rfl

/-- The loop's initial halt guard is `¬b`. -/
private theorem loopP_initHlt :
    bval W (certifiedThompson Act Tst loopP).aut.initHlt x = !(W () x) := rfl

private theorem pA_initHlt :
    bval W (certifiedThompson Act Tst pA).aut.initHlt x = false := rfl

/-- The `ite`'s own initial halt guard is `(b ∧ 1) ∨ (¬b ∧ 0)`, i.e. `b`: the `then` branch is
    a test that halts at once, the `else` branch an action that does not. -/
private theorem ite_initHlt :
    bval W (certifiedThompson Act Tst (Exp.ite bT (Exp.test BExp.one) pA)).aut.initHlt x
      = W () x := by
  show (_ || _) = _
  simp [bval, bT_val, test_one_initHlt, pA_initHlt]

theorem f_none_step (h : W () x = true) :
    autStep W fAut none x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else (if bval W _ x then _ else _)) = _
  simp [bval, bT_val, ite_initHlt, h]
  rfl

theorem f_none_step_ff (h : W () x = false) :
    autStep W fAut none x = some ((), some (Sum.inl (Sum.inr ()))) := by
  show (if bval W _ x then _ else (if bval W _ x then _ else _)) = _
  simp [bval, bT_val, ite_initHlt, h]
  rfl

theorem f_none_hlt : bval W (fAut.hlt none) x = false := by
  cases h : W () x <;> · show (_ && _) = false; simp [bval, bT_val, ite_initHlt, loopP_initHlt, h]

theorem e_mid_step_ff (h : W () x = false) :
    autStep W eAut (some (Sum.inl ())) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, pA_hlt, bT_val, h]
  rfl

theorem e_loop_step_ff (h : W () x = false) :
    autStep W eAut (some (Sum.inr ())) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, pA_hlt, bT_val, h]
  rfl

theorem f_mid_step_ff (h : W () x = false) :
    autStep W fAut (some (Sum.inl (Sum.inr ()))) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, pA_hlt, bT_val, h]
  rfl

theorem f_loop_step_ff (h : W () x = false) :
    autStep W fAut (some (Sum.inr ())) x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, pA_hlt, bT_val, h]
  rfl

/-! ## The quotient onto `gapAut`

    `gAutHom_bisim` is unavailable: the guards here are BA-equivalent, not syntactically equal,
    so there is no strict `GAutHom` and `bisim_graph` is discharged from the computations. -/

abbrev SUM := sumGAut eAut fAut
abbrev GAP := gapAut bT ()

theorem sum_step_inl (s : Option (certifiedThompson Act Tst eProg).State) :
    autStep W SUM (Sum.inl s) x = (autStep W eAut s x).map (fun o => (o.1, Sum.inl o.2)) := by
  show firstMatch W x ((eAut.trans s).map _) = _
  rw [firstMatch_map_target_to]; rfl

theorem sum_step_inr (s : Option (certifiedThompson Act Tst fProg).State) :
    autStep W SUM (Sum.inr s) x = (autStep W fAut s x).map (fun o => (o.1, Sum.inr o.2)) := by
  show firstMatch W x ((fAut.trans s).map _) = _
  rw [firstMatch_map_target_to]; rfl

theorem gap_hlt_false : bval W (GAP.hlt false) x = false := rfl
theorem gap_hlt_true : bval W (GAP.hlt true) x = !(W () x) := rfl
theorem gap_step_false : autStep W GAP false x = some ((), true) := rfl

theorem gap_step_true (h : W () x = true) : autStep W GAP true x = some ((), true) := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, h]

theorem gap_step_true_ff (h : W () x = false) : autStep W GAP true x = none := by
  show (if bval W _ x then _ else _) = _
  simp [bval, bT_val, h]
  rfl

/-- The pinned collapse: both starts to `q₀`, every action state to `q₁`. -/
def qmap : Sum (Option (certifiedThompson Act Tst eProg).State)
               (Option (certifiedThompson Act Tst fProg).State) → Bool
  | .inl none => false
  | .inr none => false
  | _ => true

private theorem inl_tgt {S₁ S₂ : Type} {o : Act × S₁} {q : Act} {s' : Sum S₁ S₂}
    (h : (Option.map (fun z => (z.1, Sum.inl z.2)) (some o) : Option (Act × Sum S₁ S₂))
        = some (q, s')) : Sum.inl o.2 = s' :=
  congrArg Prod.snd (Option.some.inj h)

private theorem inr_tgt {S₁ S₂ : Type} {o : Act × S₂} {q : Act} {s' : Sum S₁ S₂}
    (h : (Option.map (fun z => (z.1, Sum.inr z.2)) (some o) : Option (Act × Sum S₁ S₂))
        = some (q, s')) : Sum.inr o.2 = s' :=
  congrArg Prod.snd (Option.some.inj h)

private theorem gap_tgt {q : Act} {s2' : Bool} (h : some ((), true) = some (q, s2')) :
    (true : Bool) = s2' := congrArg Prod.snd (Option.some.inj h)

/-- **The pinned collapse is a bisimulation.**  Discharged case by case from the computations
    above.  `Act = Unit`, so the action component of every step is forced by eta. -/
theorem qmap_bisim : GAutBisim W SUM GAP (fun s q => qmap s = q) := by
  rintro s1 s2 rfl
  match s1 with
  | .inl none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (eAut.hlt none) a = bval W (GAP.hlt false) a
        rw [e_none_hlt, gap_hlt_false]
      · rw [sum_step_inl, e_none_step] at hst
        have hs := inl_tgt hst
        subst hs
        exact ⟨true, gap_step_false W a, rfl⟩
      · rw [gap_step_false] at hst
        have hs := gap_tgt hst
        subst hs
        refine ⟨Sum.inl (some (Sum.inl ())), ?_, rfl⟩
        rw [sum_step_inl, e_none_step]; rfl
  | .inl (some (Sum.inl ())) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (eAut.hlt (some (Sum.inl ()))) a = bval W (GAP.hlt true) a
        rw [e_mid_hlt, gap_hlt_true]
      · rw [sum_step_inl] at hst
        cases hb : W () a with
        | false => rw [e_mid_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [e_mid_step W a hb] at hst
            have hs := inl_tgt hst
            subst hs
            exact ⟨true, gap_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [gap_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [gap_step_true W a hb] at hst
            have hs := gap_tgt hst
            subst hs
            refine ⟨Sum.inl (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inl, e_mid_step W a hb]; rfl
  | .inl (some (Sum.inr ())) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (eAut.hlt (some (Sum.inr ()))) a = bval W (GAP.hlt true) a
        rw [e_loop_hlt, gap_hlt_true]
      · rw [sum_step_inl] at hst
        cases hb : W () a with
        | false => rw [e_loop_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [e_loop_step W a hb] at hst
            have hs := inl_tgt hst
            subst hs
            exact ⟨true, gap_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [gap_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [gap_step_true W a hb] at hst
            have hs := gap_tgt hst
            subst hs
            refine ⟨Sum.inl (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inl, e_loop_step W a hb]; rfl
  | .inr none =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (fAut.hlt none) a = bval W (GAP.hlt false) a
        rw [f_none_hlt, gap_hlt_false]
      · rw [sum_step_inr] at hst
        cases hb : W () a with
        | false =>
            rw [f_none_step_ff W a hb] at hst
            have hs := inr_tgt hst
            subst hs
            exact ⟨true, gap_step_false W a, rfl⟩
        | true =>
            rw [f_none_step W a hb] at hst
            have hs := inr_tgt hst
            subst hs
            exact ⟨true, gap_step_false W a, rfl⟩
      · rw [gap_step_false] at hst
        have hs := gap_tgt hst
        subst hs
        cases hb : W () a with
        | false =>
            refine ⟨Sum.inr (some (Sum.inl (Sum.inr ()))), ?_, rfl⟩
            rw [sum_step_inr, f_none_step_ff W a hb]; rfl
        | true =>
            refine ⟨Sum.inr (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inr, f_none_step W a hb]; rfl
  | .inr (some (Sum.inl (Sum.inr ()))) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (fAut.hlt (some (Sum.inl (Sum.inr ())))) a = bval W (GAP.hlt true) a
        rw [f_mid_hlt, gap_hlt_true]
      · rw [sum_step_inr] at hst
        cases hb : W () a with
        | false => rw [f_mid_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [f_mid_step W a hb] at hst
            have hs := inr_tgt hst
            subst hs
            exact ⟨true, gap_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [gap_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [gap_step_true W a hb] at hst
            have hs := gap_tgt hst
            subst hs
            refine ⟨Sum.inr (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inr, f_mid_step W a hb]; rfl
  | .inr (some (Sum.inr ())) =>
      first | simp only [qmap] | skip
      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩
      · show bval W (fAut.hlt (some (Sum.inr ()))) a = bval W (GAP.hlt true) a
        rw [f_loop_hlt, gap_hlt_true]
      · rw [sum_step_inr] at hst
        cases hb : W () a with
        | false => rw [f_loop_step_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [f_loop_step W a hb] at hst
            have hs := inr_tgt hst
            subst hs
            exact ⟨true, gap_step_true W a hb, rfl⟩
      · cases hb : W () a with
        | false => rw [gap_step_true_ff W a hb] at hst; exact absurd hst (by simp)
        | true =>
            rw [gap_step_true W a hb] at hst
            have hs := gap_tgt hst
            subst hs
            refine ⟨Sum.inr (some (Sum.inr ())), ?_, rfl⟩
            rw [sum_step_inr, f_loop_step W a hb]; rfl

/-- The collapse, as a behavioural quotient. -/
def qquot : UniformBehavioralGAutQuotient SUM GAP where
  mapState := qmap
  maps_states := by
    intro s _
    cases h : qmap s <;> simp [gapAut]
  onto_states := by
    intro q _
    cases q with
    | false =>
        exact ⟨Sum.inl none,
          List.mem_append.mpr (Or.inl (List.mem_map_of_mem List.mem_cons_self)), rfl⟩
    | true =>
        refine ⟨Sum.inl (some (Sum.inl ())), ?_, rfl⟩
        refine List.mem_append.mpr (Or.inl (List.mem_map_of_mem ?_))
        refine List.mem_cons_of_mem _ (List.mem_map_of_mem ?_)
        exact List.mem_append.mpr (Or.inl (List.mem_map_of_mem List.mem_cons_self))
  bisim_graph := fun _ W => qmap_bisim W

/-- **`SumQuotientSolvable` holds on the pair that refutes `CommonSyntacticCollapse`.**

    `not_commonSyntacticCollapse` shows this pair admits no SYNTAX-GENERATED common target.
    Here the quotient exists and is solved outright by `gapAut_solvable`.  So the swapped
    conjunct is strictly weaker than the cospan, and weaker exactly where it must be: the
    cospan dies on the demand that the target be Thompson-generated, which this never makes. -/
theorem sumQuotientSolvable_at_refuting_pair :
    ∃ (Q : Type) (quot : GAut Q Act Tst)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson Act Tst eProg).aut.toGAut
                     (certifiedThompson Act Tst fProg).aut.toGAut) quot)
      (qsol : Q → Exp Act Tst),
      SolvesBA quot qsol ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none) :=
  ⟨Bool, GAP, qquot, gapSol bT (), gapAut_solvable bT (), rfl⟩

#print axioms qmap_bisim
#print axioms sumQuotientSolvable_at_refuting_pair

end GkatGapWitness

