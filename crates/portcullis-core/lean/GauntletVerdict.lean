/-
  The links gauntlet's verdicts (ADR 0017, "The gauntlet at full scale"): what
  each item's pass, fail and inconclusive mean, before the harness decides them.

  Found on the x86 runs (2026-11-19/20), three times: an item read "pass" when
  it had not observed what it claims. (b) passed with 137 of 200 linked
  requests ending 503, because a 503 fell into no bucket; (b) passed again with
  19,162 of 50,000 requests sent, because the sender was waited on for a fixed
  900 s; and (e2) passed with no link ever made, because 0 links and 0 unlinks
  leave a "consistent" table. Each time the harness's rule was the defect, not
  the node. So the rules are decisions like any other: they get a meaning here,
  the harness computes them through the extracted slice
  (`nucleus_ifc_kernel::extracted::gauntlet`), and `GauntletVerdictExtracted`
  proves the slice computes this.

  One shape decides every judged item: anything bad observed is a failure;
  otherwise the item passes only if it observed enough to say so; otherwise it
  is inconclusive. Items differ only in what "bad" and "enough" are. A
  `recorded` item is a measurement the gauntlet reports and does not judge.

  Mathlib-free, like `LinkTable.lean` and `DecisionChannel.lean`.
-/

namespace GauntletVerdict

inductive Verdict where
  | pass
  | fail
  | inconclusive
  | recorded
  deriving DecidableEq, Repr

/-- The one shape: bad fails; otherwise enough passes; otherwise inconclusive. -/
def judge (bad enough : Bool) : Verdict :=
  if bad then .fail else if enough then .pass else .inconclusive

/-- Whether a verdict fails the run. Inconclusive and recorded items do not:
    they are visible in the report, not hidden as failures or as passes. -/
def fails : Verdict → Bool
  | .fail => true
  | _ => false

/-- A run fails exactly when one of its items does. -/
def reportFails (vs : List Verdict) : Bool := vs.any fails

/-- (a): any step where the node answered other than the model is bad; a run
    cut short by an error observed too little. -/
def differential (mismatches errors : Nat) : Verdict :=
  judge (mismatches > 0) (errors == 0)

/-- (b): a linked request that failed, a linked request answered but missing, a
    refused request that leaked, or a delivery with no decision is bad. Enough
    is: something was seen, a linked request was delivered, and every kind was
    sent as many times as asked. -/
def perRequest (saw : Bool) (requested sentFewest linkedOk linkedFailed linkedMissing
    refusedLeaked undecided : Nat) : Verdict :=
  judge (linkedFailed > 0 || linkedMissing > 0 || refusedLeaked > 0 || undecided > 0)
    (saw && linkedOk > 0 && sentFewest ≥ requested)

/-- (c): an attempt that reached or was answered is bad; no attempts is too little. -/
def adversary (anyBad : Bool) (attempts : Nat) : Verdict :=
  judge anyBad (attempts > 0)

/-- (d): the two kinds of 404 must be identical; there is nothing to be
    inconclusive about once the probes ran. -/
def isolation (identical : Bool) : Verdict :=
  judge (!identical) true

/-- (e1): link 200, cancel 409, and a drop-on-exit receipt seen. -/
def cancelThenExit (linkOk cancelRefused dropped : Bool) : Verdict :=
  judge (!(linkOk && cancelRefused && dropped)) true

/-- (e2): the raced row ends consistent with the node's answers (links made less
    unlinks made is the row's presence, 0 or 1). A race in which no link was
    made raced nothing: inconclusive, before consistency is asked. -/
def race (linksDone unlinksDone present : Nat) : Verdict :=
  if linksDone = 0 then .inconclusive
  else judge (!(unlinksDone ≤ linksDone && linksDone - unlinksDone == present && present ≤ 1)) true

/-- (f): an unlinked pod that received anything is bad; silence counts only if
    the canary was seen listening. -/
def canary (received : Nat) (listening : Bool) : Verdict :=
  judge (received > 0) listening

/-- (g): a receipt that does not verify (or parse) is bad; none verified is too little. -/
def receipts (bad verified : Nat) : Verdict :=
  judge (bad > 0) (verified > 0)

/-- Seconds the sender of `n` requests per kind is waited for: about ten per
    second are allowed (twenty were measured), and never less than 900 s. -/
def senderWait (n : Nat) : Nat := max (n / 10) 900

/-- Seconds the standing pods (pool, destination, canary) live: three hours for
    the other items, a second per differential op, the sender's wait, and 600 s. -/
def standingLifetime (ops requests : Nat) : Nat :=
  3 * 3600 + ops + senderWait requests + 600

/-! ### What the verdicts mean -/

/-- A pass is exactly: nothing bad, and enough observed. -/
theorem judge_pass_iff (bad enough : Bool) :
    judge bad enough = .pass ↔ bad = false ∧ enough = true := by
  cases bad <;> cases enough <;> simp [judge]

/-- Anything bad is a failure, whatever else was observed. -/
theorem judge_bad_fails (enough : Bool) : judge true enough = .fail := by
  simp [judge]

/-- No judged item is ever `recorded`: recording is a separate, explicit choice. -/
theorem judge_never_recorded (bad enough : Bool) : judge bad enough ≠ .recorded := by
  cases bad <;> cases enough <;> simp [judge]

/-- The 503 finding: one linked request that failed fails (b). -/
theorem a_failed_linked_request_fails (saw : Bool) (r s ok missing leaked und f : Nat)
    (hf : f > 0) : perRequest saw r s ok f missing leaked und = .fail := by
  have : (decide (f > 0) || decide (missing > 0) || decide (leaked > 0) || decide (und > 0)) = true := by
    simp [hf]
  simp [perRequest, judge, this]

/-- The short-wait finding: a run that sent fewer than asked never passes (b). -/
theorem a_short_run_never_passes (saw : Bool) (r s ok f missing leaked und : Nat)
    (hs : s < r) : perRequest saw r s ok f missing leaked und ≠ .pass := by
  intro h
  have := (judge_pass_iff _ _).mp h
  have h2 := this.2
  simp at h2
  exact absurd hs (Nat.not_lt.mpr h2.2)

/-- The empty-race finding: no link made is never a pass (e2). -/
theorem an_empty_race_never_passes (u p : Nat) : race 0 u p ≠ .pass := by
  simp [race]

/-- A race whose answers and row agree passes (e2): the rule is not vacuous. -/
theorem a_consistent_race_passes (l u : Nat) (hl : l > 0) (hu : u ≤ l) (hp : l - u ≤ 1) :
    race l u (l - u) = .pass := by
  have h0 : l ≠ 0 := Nat.pos_iff_ne_zero.mp hl
  simp [race, judge, h0, hu, hp]

/-- A canary passes only when it was seen listening and received nothing (f). -/
theorem canary_pass_iff (received : Nat) (listening : Bool) :
    canary received listening = .pass ↔ received = 0 ∧ listening = true := by
  rw [canary, judge_pass_iff]
  simp [Nat.pos_iff_ne_zero]

/-- A report fails exactly when one item fails; inconclusive and recorded items
    never fail it, and never make it pass in their place. -/
theorem reportFails_iff (vs : List Verdict) :
    reportFails vs = true ↔ Verdict.fail ∈ vs := by
  simp only [reportFails, List.any_eq_true]
  constructor
  · rintro ⟨v, hv, hf⟩
    cases v <;> simp [fails] at hf
    exact hv
  · intro h
    exact ⟨.fail, h, rfl⟩

/-- The expired-pods finding: the standing pods outlive the sender's wait by at
    least three hours, whatever the scale. -/
theorem standing_outlives_sender (ops n : Nat) :
    standingLifetime ops n ≥ senderWait n + 3 * 3600 := by
  unfold standingLifetime
  omega

/-- At the goal's scale (10,000 ops, 50,000 requests) the pods live longer than
    the 5,600 s the full-scale run took plus three hours of margin. -/
theorem full_scale_fits : standingLifetime 10000 50000 > 5600 + 3 * 3600 := by
  decide

/-! ### Worked examples, decided -/

-- The x86 run-2 numbers: 63 delivered, 137 failed.
example : perRequest true 200 200 63 137 0 0 0 = .fail := by decide
-- The first full-scale run: 19,162 of 50,000 sent, nothing failed.
example : perRequest true 50000 19162 19162 0 0 0 0 = .inconclusive := by decide
-- The second: all 50,000 sent and delivered.
example : perRequest true 50000 50000 50000 0 0 0 0 = .pass := by decide
-- (e2) at 08f8c57fc: 64 tasks, no link made.
example : race 0 0 0 = .inconclusive := by decide
-- (e2) at b32cf4c91: 2 links, 2 unlinks, no row.
example : race 2 2 0 = .pass := by decide
-- A row left with no link to account for it.
example : race 2 2 1 = .fail := by decide
-- A silent canary whose logs were never found.
example : canary 0 false = .inconclusive := by decide

end GauntletVerdict

#print axioms GauntletVerdict.judge_pass_iff
#print axioms GauntletVerdict.a_failed_linked_request_fails
#print axioms GauntletVerdict.a_short_run_never_passes
#print axioms GauntletVerdict.an_empty_race_never_passes
#print axioms GauntletVerdict.a_consistent_race_passes
#print axioms GauntletVerdict.canary_pass_iff
#print axioms GauntletVerdict.reportFails_iff
#print axioms GauntletVerdict.standing_outlives_sender
#print axioms GauntletVerdict.full_scale_fits
