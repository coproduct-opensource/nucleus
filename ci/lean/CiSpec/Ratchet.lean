/-
  CiSpec / Ratchet — a floor pinned AT the measurement is a second copy of it.

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Nat` + `omega` + `decide`.
  Lean 4 v4.30.0, `autoImplicit = false`.

  # Why this file exists

  `.scorecard-ratchet.toml` stores a floor per defect family and the gate
  refuses slack: "a floor with slack under it has already stopped gating"
  (ADR 0007 I-1). Taken literally that makes the check an EQUALITY between a
  stored number and a measured one, and an equality between a stored fact and
  a computed one is the shape ADR 0007 calls G — if a fact is written twice,
  one copy is wrong sooner or later.

  It went wrong twice on 2026-09-21, in the same hour, in the direction nobody
  designs for: **a branch failed the gate for improving the number.**
  `nucleus-blast-radius` declares all seven panic lints by inheriting the
  workspace set, so it RAISED the totality ratio on arrival. Two branches that
  each merged it then had to edit the same line — 3176 to 3255, and 3255 to
  3333 — and those edits collide.

  # What is modelled

  * `pinnedAtMeasure` is the rule as it stands: the floor must equal the
    measurement.
  * `boundedBelow` is a floor as a bound.
  * `derivedFloor` is the repair: hold a branch to the BASE's measurement, so
    the branch stores nothing and there is no second copy to conflict over. A
    deliberate lowering is then the only thing anyone writes down, which is
    what the file says it wants reviewers to see.

  # The three properties, and why all three are needed

  `boundedBelow` alone is not the answer — a bound with slack is the thing the
  gate refuses, and rightly: slack is how a ratchet quietly stops ratcheting.
  The repair has to keep the ratchet while admitting improvement, so:

  * `derived_floor_catches_a_regression` — it still refuses a fall (the
    property `pinnedAtMeasure` has and a loose bound loses);
  * `derived_floor_admits_an_improvement` — it does not refuse a rise (the
    property `pinnedAtMeasure` lacks);
  * `derived_floor_is_confluent` — two branches that each pass still pass
    after a merge, so parallel work does not collide.

  # What is NOT modelled (stated, not hidden)

  * The merge itself. `derived_floor_is_confluent` assumes the merged
    measurement is at least one of the branches'; whether a ratio over a crate
    set is monotone under merge is a fact about the census, not about arithmetic.
  * Text conflicts. That two branches editing one line collide is a property of
    files, not of numbers. What is proved is the weaker and checkable thing:
    with the floor derived, neither branch has a line to edit.
  * Who may lower a floor. That is an owner decision the file already records
    in prose, and no theorem should pretend otherwise.
-/

import CiSpec.Verdict

namespace CiSpec

/-- The rule as it stands: the stored floor must EQUAL the measurement, because
    slack means the floor has stopped gating. -/
def pinnedAtMeasure (floor measure : Nat) : Bool := floor == measure

/-- A floor as a bound: the measurement may not fall below it. -/
def boundedBelow (floor measure : Nat) : Bool := floor ≤ measure

/-- The repair: a branch is held to the base's measurement, and stores nothing
    of its own. -/
def derivedFloor (baseMeasure : Nat) : Nat := baseMeasure

/-- A branch passes when its measurement did not fall below the base's. -/
def passesDerived (baseMeasure branchMeasure : Nat) : Bool :=
  boundedBelow (derivedFloor baseMeasure) branchMeasure

/-- **The defect, in the abstract.** An improvement fails the pinned rule.
    Any measurement above the stored floor is refused, which is the opposite
    of what a ratchet is for. -/
theorem pinned_refuses_every_improvement {floor measure : Nat}
    (h : floor < measure) : pinnedAtMeasure floor measure = false := by
  simp [pinnedAtMeasure]
  omega

/-- And it refuses a regression too, so the rule is not WRONG — it is
    two-sided where it should be one-sided. Non-vacuity for the theorem
    above: `pinnedAtMeasure` is not the constant `false`. -/
theorem pinned_refuses_a_regression {floor measure : Nat}
    (h : measure < floor) : pinnedAtMeasure floor measure = false := by
  simp [pinnedAtMeasure]
  omega

theorem pinned_admits_only_equality (floor measure : Nat) :
    pinnedAtMeasure floor measure = true ↔ floor = measure := by
  simp [pinnedAtMeasure]

/-- **The ratchet survives the repair.** A measurement that falls below the
    base is still refused, which is the property a loose bound would lose. -/
theorem derived_floor_catches_a_regression {base branch : Nat}
    (h : branch < base) : passesDerived base branch = false := by
  simp [passesDerived, boundedBelow, derivedFloor]
  omega

/-- **And an improvement is admitted.** This is the case that failed twice on
    2026-09-21. -/
theorem derived_floor_admits_an_improvement {base branch : Nat}
    (h : base ≤ branch) : passesDerived base branch = true := by
  simp [passesDerived, boundedBelow, derivedFloor, h]

/-- **Confluence.** Two branches that each pass against the base still pass
    after a merge whose measurement is at least one of theirs. So parallel work
    on independent crates cannot produce a merge that fails for a reason
    neither side had — and, because the floor is derived, neither branch wrote
    a number down for the other to collide with. -/
theorem derived_floor_is_confluent {base a b m : Nat}
    (ha : passesDerived base a = true) (hb : passesDerived base b = true)
    (hm : a ≤ m ∨ b ≤ m) : passesDerived base m = true := by
  simp [passesDerived, boundedBelow, derivedFloor] at ha hb ⊢
  cases hm with
  | inl h => omega
  | inr h => omega

/-- **The pinned rule is not confluent.** Two branches each pinned at their own
    measurement, and a merge measuring more than both: the merge fails against
    either stored floor. Concretely the two numbers from 2026-09-21 — a branch
    at 3255, another at 3255, and the merge measuring 3333. -/
theorem pinned_is_not_confluent :
    pinnedAtMeasure 3255 3255 = true ∧
    pinnedAtMeasure 3255 3333 = false := by
  constructor <;> rfl

end CiSpec
