/-
  The links gauntlet's verdicts, as the harness computes them, ARE the model's
  (`GauntletVerdict.lean`).

  `extracted.gauntlet.*` is Aeneas's translation of
  `crates/nucleus-ifc-kernel/src/extracted/gauntlet.rs` (the same scoped run as
  the link, TLS and decision slices, installed in `generated-link/`). The
  harness (`nucleus-cli`, `host_evidence_live::links`) calls these functions for
  every judged item, so the model's theorems (`a_short_run_never_passes`,
  `an_empty_race_never_passes`, `canary_pass_iff`, `standing_outlives_sender`,
  …) are about the verdicts the gauntlet reports.

  `Report::failed` is `items.iter().any(|i| fails(i.verdict))`: the fold is the
  standard library's `Iterator::any`, outside the slice; `fails` is bound here.
-/

import PortcullisCoreLink.Types
import PortcullisCoreLink.Funs
import GauntletVerdict

open Aeneas Aeneas.Std Result

namespace GauntletVerdictExtracted

open nucleus_ifc_kernel

def toExt : GauntletVerdict.Verdict → extracted.gauntlet.Verdict
  | .pass => .Pass
  | .fail => .Fail
  | .inconclusive => .Inconclusive
  | .recorded => .Recorded

theorem judge_is_model (bad enough : Bool) :
    extracted.gauntlet.judge bad enough = ok (toExt (GauntletVerdict.judge bad enough)) := by
  unfold extracted.gauntlet.judge GauntletVerdict.judge
  cases bad <;> cases enough <;> rfl

theorem fails_is_model (v : GauntletVerdict.Verdict) :
    extracted.gauntlet.fails (toExt v) = ok (GauntletVerdict.fails v) := by
  cases v <;> rfl

private theorem gt0 (a : Std.U64) : decide (a > 0#u64) = decide (a.val > 0) := by
  simp [GT.gt, UScalar.lt_equiv]

private theorem ge (a b : Std.U64) : decide (a ≥ b) = decide (a.val ≥ b.val) := by
  simp [GE.ge, UScalar.le_equiv]

private theorem eq0 (a : Std.U64) : decide (a = 0#u64) = (a.val == 0) := by
  by_cases h : a.val = 0
  · have : a = 0#u64 := by scalar_tac
    simp [this]
  · have : a ≠ 0#u64 := by intro e; apply h; rw [e]; rfl
    simp [this, h]

theorem differential_is_model (m e : Std.U64) :
    extracted.gauntlet.differential m e =
      ok (toExt (GauntletVerdict.differential m.val e.val)) := by
  unfold extracted.gauntlet.differential GauntletVerdict.differential
  rw [← judge_is_model, gt0, ← eq0]

theorem per_request_is_model (saw : Bool) (r s ok' f mi le u : Std.U64) :
    extracted.gauntlet.per_request saw r s ok' f mi le u =
      ok (toExt (GauntletVerdict.perRequest saw r.val s.val ok'.val f.val mi.val le.val u.val)) := by
  unfold extracted.gauntlet.per_request GauntletVerdict.perRequest
  rw [← judge_is_model]
  simp only [GT.gt, GE.ge, UScalar.lt_equiv, UScalar.le_equiv]
  cases saw <;> split_ifs <;> simp_all <;> rw [decide_eq_false (by omega)]

theorem adversary_is_model (anyBad : Bool) (n : Std.U64) :
    extracted.gauntlet.adversary anyBad n = ok (toExt (GauntletVerdict.adversary anyBad n.val)) := by
  unfold extracted.gauntlet.adversary GauntletVerdict.adversary
  rw [← judge_is_model, gt0]

theorem isolation_is_model (identical : Bool) :
    extracted.gauntlet.isolation identical = ok (toExt (GauntletVerdict.isolation identical)) := by
  unfold extracted.gauntlet.isolation GauntletVerdict.isolation
  cases identical <;> rfl

theorem cancel_then_exit_is_model (a b c : Bool) :
    extracted.gauntlet.cancel_then_exit a b c =
      ok (toExt (GauntletVerdict.cancelThenExit a b c)) := by
  unfold extracted.gauntlet.cancel_then_exit GauntletVerdict.cancelThenExit
  cases a <;> cases b <;> cases c <;> rfl

theorem race_is_model (l u p : Std.U64) :
    extracted.gauntlet.race l u p = ok (toExt (GauntletVerdict.race l.val u.val p.val)) := by
  unfold extracted.gauntlet.race GauntletVerdict.race
  by_cases h0 : l.val = 0
  · have : l = 0#u64 := by scalar_tac
    simp [this, toExt]
  · have hl : l ≠ 0#u64 := by intro e; apply h0; rw [e]; rfl
    simp only [hl, h0, if_false]
    rw [← judge_is_model]
    by_cases hu : u ≤ l
    · have huv : u.val ≤ l.val := by scalar_tac
      obtain ⟨i, hi, hiv, -⟩ := WP.spec_imp_exists (UScalar.sub_spec huv)
      simp only [hu, if_true, hi, bind_tc_ok]
      by_cases hp : i = p
      · have hpv : l.val - u.val = p.val := by rw [← hiv, hp]
        by_cases h1 : p.val ≤ 1
        · have : p ≤ 1#u64 := by scalar_tac
          simp [hp, huv, hpv, h1, this]
        · have : ¬ p ≤ 1#u64 := by intro e; apply h1; scalar_tac
          simp [hp, huv, hpv, h1, this]
      · have hpv : l.val - u.val ≠ p.val := by
          intro e; apply hp; scalar_tac
        have hb : (l.val - u.val == p.val) = false := by simp [hpv]
        simp [hp, hb]
    · have huv : ¬ u.val ≤ l.val := by
        intro e; apply hu; scalar_tac
      simp [hu, huv]

theorem canary_is_model (n : Std.U64) (listening : Bool) :
    extracted.gauntlet.canary n listening = ok (toExt (GauntletVerdict.canary n.val listening)) := by
  unfold extracted.gauntlet.canary GauntletVerdict.canary
  rw [← judge_is_model, gt0]

theorem receipts_is_model (b v : Std.U64) :
    extracted.gauntlet.receipts b v = ok (toExt (GauntletVerdict.receipts b.val v.val)) := by
  unfold extracted.gauntlet.receipts GauntletVerdict.receipts
  rw [← judge_is_model, gt0, gt0]

theorem sender_wait_is_model (n : Std.U64) :
    ∃ w, extracted.gauntlet.sender_wait n = ok w ∧ w.val = GauntletVerdict.senderWait n.val := by
  unfold extracted.gauntlet.sender_wait GauntletVerdict.senderWait
  obtain ⟨q, hq, hqv⟩ := UScalar.div_spec n (y := 10#u64) (by simp)
  simp only [hq, bind_tc_ok]
  by_cases h : q > 900#u64
  · refine ⟨q, by simp [h], ?_⟩
    have : q.val > 900 := by scalar_tac
    simp at hqv; omega
  · refine ⟨900#u64, by simp [h], ?_⟩
    have : ¬ q.val > 900 := by intro e; apply h; scalar_tac
    simp at hqv; simp; omega

/-- At any scale that fits a `u64`, the standing pods' lifetime is the model's,
    so `standing_outlives_sender` holds of the lifetime the harness uses. -/
theorem standing_lifetime_is_model (ops n : Std.U64)
    (hfit : GauntletVerdict.standingLifetime ops.val n.val ≤ U64.max) :
    ∃ t, extracted.gauntlet.standing_lifetime ops n = ok (some t) ∧
      t.val = GauntletVerdict.standingLifetime ops.val n.val := by
  obtain ⟨w, hw, hwv⟩ := sender_wait_is_model n
  unfold GauntletVerdict.standingLifetime at hfit ⊢
  rw [← hwv] at hfit ⊢
  have h1 := U64.checked_add_bv_spec 11400#u64 ops
  have h11400 : (11400#u64).val = 11400 := by simp
  unfold extracted.gauntlet.standing_lifetime
  cases hc : U64.checked_add 11400#u64 ops with
  | none =>
    rw [hc] at h1
    simp [U64.max] at h1 hfit
    omega
  | some a =>
    rw [hc] at h1
    obtain ⟨-, ha, -⟩ := h1
    have h2 := U64.checked_add_bv_spec a w
    cases hc2 : U64.checked_add a w with
    | none =>
      rw [hc2] at h2
      simp [U64.max] at h2 hfit
      omega
    | some t =>
      rw [hc2] at h2
      obtain ⟨-, ht, -⟩ := h2
      refine ⟨t, by simp [lift, hw, hc2], ?_⟩
      rw [h11400] at ha
      omega

end GauntletVerdictExtracted

#print axioms GauntletVerdictExtracted.judge_is_model
#print axioms GauntletVerdictExtracted.fails_is_model
#print axioms GauntletVerdictExtracted.differential_is_model
#print axioms GauntletVerdictExtracted.per_request_is_model
#print axioms GauntletVerdictExtracted.adversary_is_model
#print axioms GauntletVerdictExtracted.isolation_is_model
#print axioms GauntletVerdictExtracted.cancel_then_exit_is_model
#print axioms GauntletVerdictExtracted.race_is_model
#print axioms GauntletVerdictExtracted.canary_is_model
#print axioms GauntletVerdictExtracted.receipts_is_model
#print axioms GauntletVerdictExtracted.sender_wait_is_model
#print axioms GauntletVerdictExtracted.standing_lifetime_is_model
