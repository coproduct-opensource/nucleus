/-
  CiSpec / Verdict — the third value, kept.

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Bool` + `List` + structural
  induction. Lean 4 v4.30.0, `autoImplicit = false`.

  # Why this file exists

  `Pipeline.rollup` models GitHub's rule with `(verdict c).getD true`: a
  required context with no verdict counts as PASSED. That is the documented
  behaviour and it is the vacuity every I3 defect exploits. The gatehouse
  controller does the opposite and defaults an undecided gate to FAILED.

  Both are collapses of a three-valued thing into `Bool`, and both throw away
  WHICH of the two reasons applied. On 2026-09-21 that cost a diagnosis: six
  required checks reported failure, the reading "the lane is oversubscribed"
  followed, and it was wrong. The controller's own text said `Undecided after
  18000s` — it knew the difference. Nothing downstream could represent it.

  So: an explicit `Verdict` with `undecided` as a case, TWO orders over it,
  and a rollup that carries the weakest reason to the top rather than a bit.

  # The two orders, and why not one

  * `infoLe` is the INFORMATION order: `undecided` sits below both decided
    values, because it is the absence of a decision rather than a third
    decision. It is a partial order and `held`/`failed` are incomparable.
  * `permits` is the PERMISSION map: only `held` lets a merge proceed.

  `permits_is_monotone` is fail-closed stated as a theorem rather than as a
  default: learning more can only turn a deny into an allow, never an allow
  into a deny. That is the shape `docs/adr/0007` calls B (defaults that grant)
  read forwards, and it is the same asymmetry the PCA model records as
  "decide commutes, enforce is lax".

  # What is NOT modelled (stated, not hidden)

  * Belnap's fourth value (`both`, a contradictory verdict from two producers
    of the same name). `Pipeline`'s straddling-twin residual is where that
    would land; two same-named check runs are a real shape here and this file
    does not reach it.
  * Time. `undecided` here is a value, not "undecided YET" — the deadline
    that turns waiting into undecided is `Liveness.Service.verdict`.
-/

import CiSpec.Pipeline

namespace CiSpec

/-- A required context's state. `undecided` is not a third decision: it is the
    absence of one, and the case both existing rollups erase. -/
inductive Verdict where
  /-- The gate ran and held. -/
  | held
  /-- The gate ran and did not hold. -/
  | failed
  /-- No verdict: never serviced, or cut off by a deadline. -/
  | undecided
  deriving DecidableEq, Repr

namespace Verdict

/-- The information order: `undecided ⊑ held` and `undecided ⊑ failed`, and
    the two decided values are incomparable. -/
def infoLe : Verdict → Verdict → Bool
  | undecided, _ => true
  | held, held => true
  | failed, failed => true
  | _, _ => false

/-- Fail-closed permission: only a gate that ran and held permits a merge. -/
def permits : Verdict → Bool
  | held => true
  | failed => false
  | undecided => false

theorem infoLe_refl (v : Verdict) : infoLe v v = true := by
  cases v <;> rfl

theorem infoLe_trans {u v w : Verdict}
    (h₁ : infoLe u v = true) (h₂ : infoLe v w = true) : infoLe u w = true := by
  cases u <;> cases v <;> cases w <;> simp_all [infoLe]

/-- `undecided` is the bottom of the information order. -/
theorem undecided_is_least (v : Verdict) : infoLe undecided v = true := rfl

/-- **Fail-closed, as monotonicity.** Along the information order `permits`
    can only go up: learning what a gate decided may turn a deny into an
    allow, and never the reverse. A default that granted would break this. -/
theorem permits_is_monotone {v w : Verdict}
    (h : infoLe v w = true) (hp : permits v = true) : permits w = true := by
  cases v <;> cases w <;> simp_all [infoLe, permits]

/-- The distinction the `Bool` collapses erase. Trivial to state and it is the
    whole point: these are different answers to different questions. -/
theorem undecided_is_not_failed : undecided ≠ failed := by decide

/-- And neither of them permits, which is why collapsing them looks harmless
    right up to the moment someone has to act on the reason. -/
theorem neither_permits : permits undecided = false ∧ permits failed = false := by
  constructor <;> rfl

/-- The weakest of two verdicts in the information order, with `undecided`
    absorbing: a rollup that has seen no verdict has no verdict. -/
def meet : Verdict → Verdict → Verdict
  | undecided, _ => undecided
  | _, undecided => undecided
  | failed, _ => failed
  | held, failed => failed
  | held, held => held

theorem meet_undecided_left (v : Verdict) : meet undecided v = undecided := rfl

theorem meet_undecided_right (v : Verdict) : meet v undecided = undecided := by
  cases v <;> rfl

end Verdict

/-- The rolled-up required verdict: fold the gates' verdicts under `meet`,
    starting from `held`. Unlike `Pipeline.rollup` this returns a `Verdict`,
    so the REASON survives to the top. -/
def rollupV (vs : List Verdict) : Verdict := vs.foldl Verdict.meet Verdict.held

theorem rollupV_nil : rollupV [] = Verdict.held := rfl

/-- Once the fold has lost its verdict it stays lost. -/
theorem foldl_meet_undecided (vs : List Verdict) :
    vs.foldl Verdict.meet Verdict.undecided = Verdict.undecided := by
  induction vs with
  | nil => rfl
  | cons v vs ih => simpa [Verdict.meet_undecided_left] using ih

/-- **The reason reaches the top.** One undecided gate anywhere among the
    required set makes the required context undecided — not failed. This is
    the sentence that was unavailable on 2026-09-21. -/
theorem rollupV_undecided_of_mem {vs : List Verdict}
    (h : Verdict.undecided ∈ vs) : rollupV vs = Verdict.undecided := by
  unfold rollupV
  induction vs with
  | nil => cases h
  | cons v vs ih =>
    cases h with
    | head => simpa [Verdict.meet] using foldl_meet_undecided vs
    | tail _ hmem =>
      cases v with
      | held => simpa [Verdict.meet] using ih hmem
      | failed =>
        have : ∀ (l : List Verdict),
            l.foldl Verdict.meet Verdict.failed = Verdict.undecided ∨
            l.foldl Verdict.meet Verdict.failed = Verdict.failed := by
          intro l
          induction l with
          | nil => exact Or.inr rfl
          | cons w ws ihw =>
            cases w with
            | held => simpa [Verdict.meet] using ihw
            | failed => simpa [Verdict.meet] using ihw
            | undecided =>
              exact Or.inl (by simpa [Verdict.meet] using foldl_meet_undecided ws)
        -- `failed` cannot absorb an `undecided` that is still to come.
        have habs : vs.foldl Verdict.meet Verdict.failed = Verdict.undecided := by
          clear ih this
          induction vs with
          | nil => cases hmem
          | cons w ws ihw =>
            cases hmem with
            | head => simpa [Verdict.meet] using foldl_meet_undecided ws
            | tail _ h2 =>
              cases w with
              | held => simpa [Verdict.meet] using ihw h2
              | failed => simpa [Verdict.meet] using ihw h2
              | undecided => simpa [Verdict.meet] using foldl_meet_undecided ws
        simpa [Verdict.meet] using habs
      | undecided => simpa [Verdict.meet] using foldl_meet_undecided vs

/-- The fold never invents an `undecided`: from a decided accumulator over a
    list with no undecided member, the result is decided. -/
theorem foldl_meet_ne_undecided (acc : Verdict) (vs : List Verdict)
    (hacc : acc ≠ Verdict.undecided) (hmem : Verdict.undecided ∉ vs) :
    vs.foldl Verdict.meet acc ≠ Verdict.undecided := by
  induction vs generalizing acc with
  | nil => simpa using hacc
  | cons v vs ih =>
    have hv : v ≠ Verdict.undecided := fun he => hmem (he ▸ List.mem_cons_self)
    have hvs : Verdict.undecided ∉ vs := fun hm => hmem (List.mem_cons_of_mem v hm)
    apply ih _ _ hvs
    cases acc <;> cases v <;> simp_all [Verdict.meet]

/-- **The rollup is undecided exactly when a gate was.** With the converse of
    `rollupV_undecided_of_mem`, "no verdict at the top" is equivalent to "some
    required gate produced none" — so the top-level answer names a real cause
    and can never be undecided for a reason nobody can point at. -/
theorem rollupV_undecided_iff_mem (vs : List Verdict) :
    rollupV vs = Verdict.undecided ↔ Verdict.undecided ∈ vs := by
  constructor
  · intro h
    -- Core-Lean decidability rather than `by_contra`: this corpus is
    -- Mathlib-free, and membership in a `DecidableEq` list is decidable.
    exact Decidable.byCases (p := Verdict.undecided ∈ vs) id
      (fun hno => absurd h (foldl_meet_ne_undecided Verdict.held vs (by decide) hno))
  · intro h
    exact rollupV_undecided_of_mem h

/-- **Fail-closed at the rollup.** If the rolled-up context permits, every
    required gate ran and held. Nothing passes by silence. -/
theorem rollupV_permits_all_held {vs : List Verdict}
    (h : (rollupV vs).permits = true) : ∀ v, v ∈ vs → v = Verdict.held := by
  intro v hv
  cases v with
  | held => rfl
  | undecided =>
    rw [rollupV_undecided_of_mem hv] at h
    exact absurd h (by simp [Verdict.permits])
  | failed =>
    -- A `failed` member drives the fold to `failed` or `undecided`; neither permits.
    exfalso
    have hf : rollupV vs = Verdict.failed ∨ rollupV vs = Verdict.undecided := by
      unfold rollupV
      clear h
      induction vs with
      | nil => cases hv
      | cons w ws ihw =>
        cases hv with
        | head =>
          have : ∀ (l : List Verdict),
              l.foldl Verdict.meet Verdict.failed = Verdict.failed ∨
              l.foldl Verdict.meet Verdict.failed = Verdict.undecided := by
            intro l
            induction l with
            | nil => exact Or.inl rfl
            | cons x xs ihx =>
              cases x with
              | held => simpa [Verdict.meet] using ihx
              | failed => simpa [Verdict.meet] using ihx
              | undecided =>
                exact Or.inr (by simpa [Verdict.meet] using foldl_meet_undecided xs)
          simpa [Verdict.meet] using this ws
        | tail _ h2 =>
          cases w with
          | held => simpa [Verdict.meet] using ihw h2
          | failed =>
            have : ∀ (l : List Verdict),
                l.foldl Verdict.meet Verdict.failed = Verdict.failed ∨
                l.foldl Verdict.meet Verdict.failed = Verdict.undecided := by
              intro l
              induction l with
              | nil => exact Or.inl rfl
              | cons x xs ihx =>
                cases x with
                | held => simpa [Verdict.meet] using ihx
                | failed => simpa [Verdict.meet] using ihx
                | undecided =>
                  exact Or.inr (by simpa [Verdict.meet] using foldl_meet_undecided xs)
            simpa [Verdict.meet] using this ws
          | undecided =>
            exact Or.inr (by simpa [Verdict.meet] using foldl_meet_undecided ws)
    cases hf with
    | inl he => rw [he] at h; exact absurd h (by simp [Verdict.permits])
    | inr he => rw [he] at h; exact absurd h (by simp [Verdict.permits])

end CiSpec
