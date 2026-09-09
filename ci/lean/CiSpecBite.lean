/-
  CiSpecBite — the guarded/unguarded differential.

  Each theorem here takes a `CiSpec` theorem, DROPS one hypothesis, and proves
  the failure that hypothesis excludes is reachable — on the concrete shape
  found in this repository on 2026-09-05. A theorem whose hypothesis nobody
  has watched matter is a guess (`delegation_calc`'s tamarin-bite doctrine);
  these are the machine-checked "it mattered".

  This file adds NO SEMANTICS. It imports `CiSpec` and declares only closed
  constants (the concrete paths, patterns and producers of the defects) and
  theorems over `CiSpec`'s definitions — no `structure`, `inductive`,
  `class`, `instance`, `abbrev`, and no function-typed `def` — so the bite
  is about the same model and cannot drift into a different one.
  `scripts/check-ci-spec-bite.sh` asserts that rule textually.

  **STATUS: PROVED (0 `sorry`).** Mathlib-free.
-/

import CiSpec

namespace CiSpecBite

open CiSpec

-- ── The 2026-09-05 twin drift, concretely ────────────────────────────────

/-- The real twin's `paths:` — `crates/nucleus-ifc-kernel/**`. -/
def realPaths : List Pattern := [["crates", "nucleus-ifc-kernel"]]

/-- What the noop twin ignored — `crates/nucleus-ifc-kernel/src/extracted/**`,
    a strict subset. -/
def noopIgnore : List Pattern := [["crates", "nucleus-ifc-kernel", "src", "extracted"]]

/-- The change that fired both: `crates/nucleus-ifc-kernel/src/lib.rs`. -/
def libRs : Path := ["crates", "nucleus-ifc-kernel", "src", "lib.rs"]

/-- **Bite of T2 / I1.** Drop `paths-ignore == paths`: the drifted pair fires
    BOTH twins on a one-file, homogeneous change. Two check runs with the
    same name, one of them vacuously green. -/
theorem ifc_scoped_drift_fired_both :
    firesPaths realPaths [libRs] = true ∧ firesIgnore noopIgnore [libRs] = true :=
  drift_fires_both realPaths noopIgnore libRs (by decide) (by decide)

/-- And with the lists set-equal (PR #2642's repair), the same change fires
    the real twin and NOT the noop: exactly one report. -/
theorem ifc_scoped_repaired_fires_one :
    firesPaths realPaths [libRs] = true ∧ firesIgnore realPaths [libRs] = false := by
  decide

/-- The other direction of drift: had the noop ignored MORE than the real
    twin filtered, a change under the extra pattern would fire NEITHER and
    the PR would block forever on a context nothing reports. -/
theorem over_ignore_fires_neither :
    firesPaths noopIgnore [libRs] = false ∧ firesIgnore realPaths [libRs] = false := by
  decide

-- ── The detector vacuity, concretely ─────────────────────────────────────

/-- `Tests` as it stood: real, merge_group-triggered, but `needs:` a detector
    that was not a required context — skippable in the queue. -/
def testsSkippable : Producer :=
  { ctx := "Tests", isNoop := false, onMergeGroup := true, skippableInQueue := true }

/-- **Bite of T1 / I3.** With the only producer skippable, I3 is false ... -/
theorem i3_fails_on_skippable_tests : I3 [testsSkippable] ["Tests"] = false := by
  decide

/-- ... and the rollup passes `Tests` with no verdict at all: the merge goes
    through untested. -/
theorem tests_merges_untested : rollup (fun _ => none) ["Tests"] = true :=
  vacuous_merge_without_I3 "Tests"

/-- The repair: the detector becomes a required context, `Tests` is no longer
    skippable, I3 holds. -/
def testsRepaired : Producer :=
  { ctx := "Tests", isNoop := false, onMergeGroup := true, skippableInQueue := false }

theorem i3_holds_after_repair : I3 [testsRepaired] ["Tests"] = true := by
  decide

-- ── T5's hypothesis matters ───────────────────────────────────────────────

/-- **Bite of T5.** Drop `p ∉ queue`: cancelling a run of the HEAD entry's
    group ejects it — the queue changes. So "cancel every competing run" is
    only safe for runs of PRs no longer in the queue, which is exactly how
    the merge-only directive words it. -/
theorem cancelling_the_head_ejects_it :
    (step (run State.init [.enqueue 1, .pass 1]) (.cancel 1)).queue = [] ∧
    (step (run State.init [.enqueue 1, .pass 1]) (.cancel 1)).loc 1 = .ejected := by
  decide

end CiSpecBite

namespace CiSpecBite

open CiSpec

-- ── The 2026-09-04 stall, in minutes ─────────────────────────────────────

/-- One merge group's required jobs, in build-pool minutes, from the OTel
    readout of 2026-09-05 (Mutation Testing, the clippy ceiling, llvm-cov,
    cargo hack, Tests, the Lean builds, the small gates). Rounded. -/
def groupJobs : List Nat := [45, 30, 28, 25, 23, 20, 15, 15, 10, 10, 5, 5]

/-- **Bite of T7 (the budget).** With four build runners and the queue's
    60-minute check timeout of 2026-09-04, T7's hypothesis is FALSE — the
    group's work plus three times its longest job exceeds four hours of
    budget — greedy scheduling consumes the ENTIRE 60 minutes with the pool
    to itself (so any queue wait at all ejects), and with 50 minutes of
    pull-request runs already on each runner it overruns outright. The
    ejections were not bad luck; the budget did not fit the work. -/
theorem budget_60_did_not_fit :
    ¬ (groupJobs.sum + 3 * 45 ≤ 4 * 60) ∧
    60 ≤ makespan (greedy 4 groupJobs) ∧
    60 < makespan (greedyFrom [50, 50, 50, 50] groupJobs) := by
  decide

/-- The repair (ruleset 22351600, ci/merge-queue.toml): a 360-minute budget.
    T7's hypothesis holds, and greedy finishes with room to spare. -/
theorem budget_360_fits :
    groupJobs.sum + 3 * 45 ≤ 4 * 360 ∧ makespan (greedy 4 groupJobs) ≤ 360 := by
  decide

/-- **Bite of T12 (the pool this queue actually has).** Forty-seven machines with
    two groups building at once give each group twenty-three of its own. The
    group of 2026-09-04 fits that share inside the 360-minute budget with room to
    spare — 1221 against 8280.

    It also fits the OLD 60-minute budget at this share (1221 against 1380), and
    that is worth saying: the 2026-09-04 ejections were a four-runner problem,
    not a budget-shape problem. `budget_60_did_not_fit` above is the bite for
    the pool that actually existed then; at 23 machines a share the same work
    would have been fine. The repair was capacity as much as it was the timeout.

    Why two and not four: T12 says the share is `p / c`, and only the HEAD group
    can merge. Raising `c` shrinks the head's share, so speculation pays only
    when the pool has capacity above ONE group's demand. Measured on 2026-09-09
    it does not — a single group saturates the pool — and four-way speculation
    produced one merge in four hours with nothing red. The arithmetic that the
    shares fit is true for any `c`; which `c` is fastest is not a theorem, it is
    a measurement, and this is where the measurement is recorded. -/
theorem two_groups_of_twenty_three_fit_360 :
    (47 / 2) * 2 ≤ 47 ∧ groupJobs.sum + 22 * 45 ≤ 23 * 360 := by
  decide

/-- **Bite of T7 (competing runs).** Pull-request runs already occupying
    the pool are non-zero initial loads: with 50 minutes on each runner the
    same group finishes 50 minutes later. "Cancel every competing run" is
    what returns the initial loads to zero. -/
theorem competing_runs_delay_the_group :
    makespan (greedy 4 groupJobs) + 50 ≤ makespan (greedyFrom [50, 50, 50, 50] groupJobs) := by
  decide

/-- **Bite of T9 (the machine budget).** The pool as it actually ran on
    2026-09-09: 27 machines of the organization's 99 against a cap of 100, with
    a pass wanting six launches in flight. It does not fit, which is why every
    start answered 422 and the pool deadlocked warm with 44 jobs queued. The
    repair — reclaiming 26 machines from suspended apps, so 46 sit elsewhere —
    fits at 38 pooled machines and ten launches in flight, with room to spare. -/
theorem machine_budget_100_did_not_fit :
    (Slots.mk 100 72 27 6).fits = false ∧
    (Slots.mk 100 46 38 10).fits = true := by
  decide

/-- **Bite of T10 (the deadlock is not merely "full").** At the cap the pass
    fails for a pool that is not even large: the same 100-machine budget with
    99 machines held elsewhere refuses a pool of one with a single launch. The
    shortfall, not the pool's size, is what has to be given back. -/
theorem at_the_cap_even_one_launch_is_refused :
    (Slots.mk 100 99 1 1).fits = false ∧
    (Slots.mk 100 96 1 1).fits = true := by
  decide

end CiSpecBite
