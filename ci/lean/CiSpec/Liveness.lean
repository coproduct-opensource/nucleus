/-
  CiSpec / Liveness — the case `Sched` cannot represent.

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Nat` + `List` + `Bool` +
  `omega` + structural induction. Lean 4 v4.30.0, `autoImplicit = false`.

  # The gap this file closes

  `Capacity.Sched q ds l l'` has two constructors and BOTH place a job. There
  is no case for a run submitted and never picked up. So
  `T7_no_timeout_ejection` reads: given a schedule that placed everything, and
  given the capacity inequality, every runner finishes by `T`. When nothing is
  placed its hypothesis is simply unavailable and the theorem quantifies over
  nothing.

  That is not a wrong theorem. It is a silent one, and the silence is the
  shape `docs/adr/0007` calls family A: "could not look" is never "looked and
  it was fine". A sum type lost a case, and the lost case is the one that
  happened.

  On 2026-09-21 six required checks on this repository reported
  `Undecided after 18000s` with between zero and four of five gates verified.
  The reading "the pool is oversubscribed" followed from the capacity model,
  and an idle-queue experiment refuted it: with no merge group building, the
  per-pull-request gates still advanced not at all. The model had no vocabulary
  for that, because `Sched` cannot say it.

  # What is modelled

  * `Service` is what the builder did with ONE gate run: `decided` with a
    finish time and a held bit, or `starved` — submitted, never placed.
  * A deadline turns a late `decided` into `undecided` too, which is what the
    controller's own text reports. Both roads to "no verdict" are the same
    verdict and neither is `failed`.
  * `WorkConserving` is the hypothesis `Sched` was hiding in its shape. Named,
    it becomes something a monitor can be pointed at.

  # What is NOT modelled (stated, not hidden)

  * WHY a run is starved. A scheduler that refuses work, a lane that never
    polls, and a request that never arrived are one case here. Distinguishing
    them needs a model of the producer, which is not in this repository.
  * Fairness. Nothing here says a starved run is eventually served; that is a
    temporal property and this is a one-shot model. `starved_at_every_deadline`
    is the strongest honest statement: no deadline decides it.
  * Recovery cost. That a timeout discards the gates already held is
    `Scope.lean`'s subject, not this one.
-/

import CiSpec.Verdict

namespace CiSpec

/-- What the builder did with one submitted gate run. `starved` is the case
    `Capacity.Sched` has no constructor for. -/
inductive Service where
  /-- Placed, finished at `finishMs`, and held or not. -/
  | decided (finishMs : Nat) (held : Bool)
  /-- Submitted and never placed. It has no finish time, which is exactly why
      a bound on finish times cannot constrain it. -/
  | starved
  deriving DecidableEq, Repr

namespace Service

/-- The verdict a service yields against a deadline. A run cut off by the
    deadline is `undecided`, not `failed` — it produced no decision — which
    is what `Undecided after 18000s` says. -/
def verdict (deadlineMs : Nat) : Service → Verdict
  | decided f h => if f ≤ deadlineMs then (if h then .held else .failed) else .undecided
  | starved => .undecided

/-- **No deadline decides a starved run.** This is the sentence `Sched` cannot
    express and the reason a capacity argument cannot reach today's failure:
    the bound constrains finish times, and starvation has none. -/
theorem starved_at_every_deadline (d : Nat) : verdict d starved = Verdict.undecided := rfl

/-- A run cut off by the deadline is undecided rather than failed. -/
theorem overrun_is_undecided {f d : Nat} {h : Bool} (hlate : d < f) :
    verdict d (decided f h) = Verdict.undecided := by
  unfold verdict
  have : ¬ (f ≤ d) := by omega
  simp [this]

/-- And a run that finished inside the deadline reports what it decided, so
    the deadline is not swallowing real verdicts. Non-vacuity for the two
    theorems above. -/
theorem in_time_reports_its_decision {f d : Nat} {h : Bool} (hfit : f ≤ d) :
    verdict d (decided f h) = (if h then Verdict.held else Verdict.failed) := by
  simp [verdict, hfit]

end Service

/-- The finish times of the runs that were actually placed. A starved run
    contributes nothing, which is how it stays invisible to a capacity
    argument. -/
def placedDurations : List Service → List Nat
  | [] => []
  | Service.decided f _ :: ss => f :: placedDurations ss
  | Service.starved :: ss => placedDurations ss

/-- **Starvation is invisible to the duration list.** Anything proved about
    `placedDurations` — every theorem in `Capacity` — holds identically with a
    starved run present and absent. That is the precise sense in which
    `T7_no_timeout_ejection` says nothing about it. -/
theorem starvation_is_invisible (ss : List Service) :
    placedDurations (Service.starved :: ss) = placedDurations ss := rfl

/-- The hypothesis `Sched` was hiding in its shape: every submitted run gets
    placed. Named here so a violation is something to detect rather than a
    constructor nobody wrote. -/
def WorkConserving (ss : List Service) : Prop := Service.starved ∉ ss

/-- The required context over one run's gates. -/
def requiredOf (deadlineMs : Nat) (ss : List Service) : Verdict :=
  rollupV (ss.map (Service.verdict deadlineMs))

theorem requiredOf_nil (d : Nat) : requiredOf d [] = Verdict.held := rfl

/-- **One starved gate undecides the whole context.** Four gates held and one
    never serviced is not "80% of a verdict"; it is no verdict, and the four
    are discarded with it. This is #2973 on 2026-09-21, which reached four of
    five and then died on the deadline. -/
theorem one_starvation_undecides {d : Nat} {ss : List Service}
    (h : Service.starved ∈ ss) : requiredOf d ss = Verdict.undecided := by
  apply rollupV_undecided_of_mem
  have : Service.verdict d Service.starved ∈ ss.map (Service.verdict d) :=
    List.mem_map_of_mem h
  simpa [Service.starved_at_every_deadline] using this

/-- **The bound is worth something once placement is a hypothesis.** With no
    starved run and every finish inside the deadline, the required context
    carries a decision. So the capacity theorems become load-bearing exactly
    under `WorkConserving`, and nowhere else — which is the hypothesis `Sched`
    was holding in its shape instead of in its statement. -/
theorem decided_when_work_conserving_and_in_time {d : Nat} {ss : List Service}
    (hwc : WorkConserving ss)
    (hfit : ∀ f h, Service.decided f h ∈ ss → f ≤ d) :
    requiredOf d ss ≠ Verdict.undecided := by
  intro hcontra
  -- The rollup is undecided only if some gate's verdict was.
  have hmem : Verdict.undecided ∈ ss.map (Service.verdict d) :=
    (rollupV_undecided_iff_mem _).mp hcontra
  -- So some service produced no verdict. Neither remaining case can.
  match List.mem_map.mp hmem with
  | ⟨s, hs, hv⟩ =>
    cases s with
    | starved => exact hwc hs
    | decided f hb =>
      have hf : f ≤ d := hfit f hb hs
      rw [Service.in_time_reports_its_decision hf] at hv
      cases hb <;> simp at hv

end CiSpec
