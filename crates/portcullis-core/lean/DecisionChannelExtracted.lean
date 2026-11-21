/-
  The decision channel's two decisions, as the proxy runs them, ARE the model's
  (`DecisionChannel.lean`).

  `extracted.decision.disposition` and `extracted.decision.on_deadline` are
  Aeneas's translation of `crates/nucleus-ifc-kernel/src/extracted/decision.rs`
  (the same scoped run as the link and TLS slices, installed in
  `generated-link/`). This file proves both total, that `disposition` is the
  model's `disposition` exactly, and that `on_deadline`, fed a whole frame and
  the owed count after the timeout, poisons exactly when the model's `tick`
  does. So `answer_admits_only_its_request`, `late_answer_never_admits`,
  `channel_recovers_after_timeout` and `unissued_answer_poisons` are about the
  shipped decisions.

  The code has one input the model abstracts: `frame_written`. A deadline that
  fires before the request's frame is fully written leaves the node holding a
  partial frame, which is a broken channel; the model treats a frame as
  delivered atomically, and the bridge below is stated for `frame_written =
  true`.
-/

import PortcullisCoreLink.Types
import PortcullisCoreLink.Funs
import DecisionChannel

open Aeneas Aeneas.Std Result

namespace DecisionChannelExtracted

open nucleus_ifc_kernel

def toExt : DecisionChannel.Disposition → extracted.decision.Disposition
  | .apply => .Apply
  | .dropLate => .DropLate
  | .poison => .Poison

/-- `disposition` is the model's, for every input. -/
theorem disposition_is_model (isCurrent isOwed : Bool) :
    extracted.decision.disposition isCurrent isOwed =
      ok (toExt (DecisionChannel.disposition isCurrent isOwed)) := by
  unfold extracted.decision.disposition
  cases isCurrent <;> cases isOwed <;> rfl

/-- `on_deadline`, exactly: poison on a partial frame or past the cap. -/
theorem on_deadline_spec (written : Bool) (owed cap : Std.U32) :
    extracted.decision.on_deadline written owed cap =
      ok (if written ∧ ¬ owed.val > cap.val then .RefuseAndOwe else .RefuseAndPoison) := by
  unfold extracted.decision.on_deadline
  cases written
  · simp
  · by_cases h : owed.val > cap.val
    · have : owed > cap := by simpa [GT.gt, UScalar.lt_equiv] using h
      simp [this, h]
    · have : ¬ owed > cap := by simpa [GT.gt, UScalar.lt_equiv] using h
      simp [this, h]

/-- With a whole frame, `on_deadline` poisons exactly when the model's `tick`
    poisons an overdue request on an unpoisoned channel. -/
theorem on_deadline_is_tick (σ : DecisionChannel.State) (c dl : Nat)
    (hc : σ.current = some (c, dl)) (hlate : σ.now + 1 > dl) (hp : σ.poisoned = false)
    (owed cap : Std.U32) (howed : owed.val = (c :: σ.owed).length)
    (hcap : cap.val = DecisionChannel.cap) :
    extracted.decision.on_deadline true owed cap =
      ok (if (DecisionChannel.step σ .tick).poisoned then .RefuseAndPoison else .RefuseAndOwe) := by
  rw [on_deadline_spec]
  simp only [DecisionChannel.step, hc, hlate, if_true]
  by_cases hk : (c :: σ.owed).length > DecisionChannel.cap
  · have : owed.val > cap.val := by rw [howed, hcap]; exact hk
    rw [if_pos hk]
    simp [this]
  · have : ¬ owed.val > cap.val := by rw [howed, hcap]; exact hk
    rw [if_neg hk]
    simp [this, hp]

end DecisionChannelExtracted

#print axioms DecisionChannelExtracted.disposition_is_model
#print axioms DecisionChannelExtracted.on_deadline_spec
#print axioms DecisionChannelExtracted.on_deadline_is_tick
