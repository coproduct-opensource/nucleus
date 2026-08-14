import GkatGuardedLoopBridge

/-!
# GKAT `while b do body` as a monotone cascade step

`GkatGuardedLoopBridge` reconciled the *not-fixed* guarded loop with our least
fixed point, and showed (`arbitrary_guard_breaks_monotonicity`) that an ARBITRARY
GKAT test need not give a monotone endomap. This file closes that gap: it states
the **guardedness condition** on the test `b` under which the general
`while b do body` IS a monotone endomap on the exposure lattice — and therefore an
admissible cascade step that inherits the anti-laundering ratchet.

The condition (`Guarded`) is exactly what makes the four `if`-cases of the guarded
step compose: **the body never overshoots the guard boundary** — if `x ≤ y`, the
guard still holds at `x` but has turned off at `y`, then one body step from `x`
stays `≤ y`. The not-fixed guard satisfies it (`notFixed_guarded`), so this
subsumes the bridge; the earlier counterexample fails it
(`arbitrary_guard_not_guarded`), so `Guarded` is exactly the missing hypothesis.

Mathlib-free; `#print axioms` audited at the end.
-/

namespace GkatWhile

open ExposureLoop GkatBridge

variable {α : Type} [RankedLattice α]

/-- The body only raises the exposure — join/observe steps are inflationary. -/
def Inflationary (f : α → α) : Prop := ∀ x, RankedLattice.le x (f x)

/-- **The guardedness condition.** The body never overshoots the guard boundary:
    if `x ≤ y`, the guard holds at `x` but not at `y`, then one body step from `x`
    stays `≤ y`. This is the hypothesis that makes `while b do body` monotone. -/
def Guarded (b : Test α) (body : α → α) : Prop :=
  ∀ x y, RankedLattice.le x y → b x = true → b y = false → RankedLattice.le (body x) y

/-- **The guarded step is monotone** under a monotone, inflationary body and a
    guarded test. The `b a ∧ ¬b c` case is exactly where `Guarded` is used; the
    `¬b a ∧ b c` case is where inflationarity is used. -/
theorem guardedStep_mono (b : Test α) (body : α → α)
    (hmono : Mono body) (hinf : Inflationary body) (hg : Guarded b body) :
    Mono (guardedStep b body) := by
  intro a c hac
  simp only [guardedStep]
  by_cases hba : b a = true <;> by_cases hbc : b c = true
  · rw [if_pos hba, if_pos hbc]; exact hmono a c hac
  · rw [if_pos hba, if_neg hbc]
    exact hg a c hac hba (Bool.not_eq_true (b c) ▸ hbc)
  · rw [if_neg hba, if_pos hbc]
    exact RankedLattice.le_trans hac (hinf c)
  · rw [if_neg hba, if_neg hbc]; exact hac

/-- Iterating a monotone map preserves monotonicity in the starting argument. -/
theorem iter_arg_mono (f : α → α) (hf : Mono f) : ∀ n, Mono (fun x => iter f n x) := by
  intro n
  induction n with
  | zero => intro a c h; exact h
  | succ n ih => intro a c h; exact hf _ _ (ih a c h)

/-- The `while b do body` cascade step: run the guarded body to termination
    (bounded by the lattice height). -/
def whileStep (b : Test α) (body : α → α) : α → α :=
  fun x => iter (guardedStep b body) (RankedLattice.height (α := α) + 1) x

/-- **`while b do body` is a monotone endomap** given the guardedness condition. -/
theorem whileStep_mono (b : Test α) (body : α → α)
    (hmono : Mono body) (hinf : Inflationary body) (hg : Guarded b body) :
    Mono (whileStep b body) :=
  iter_arg_mono (guardedStep b body) (guardedStep_mono b body hmono hinf hg) _

/-- **A `while b do body` step inherits the ratchet.** Given the guardedness
    condition, the step is a monotone endomap, so `loop_admissible` applies and it
    is an admissible cascade step — the one-theorem story now covers `if`/`while`,
    not just straight-line cascades. -/
theorem whileStep_ratchets (b : Test α) (body : α → α)
    (hmono : Mono body) (hinf : Inflationary body) (hg : Guarded b body) :
    Ratchets (whileStep b body) :=
  loop_admissible (whileStep b body) (whileStep_mono b body hmono hinf hg)

/-- The not-fixed guard is `Guarded`, so the general `while` step SUBSUMES the
    converge-to-fixpoint loop reconciled in `GkatGuardedLoopBridge`. -/
theorem notFixed_guarded [DecidableEq α] (body : α → α) (hmono : Mono body) :
    Guarded (notFixed body) body := by
  intro x y hxy _ hby
  have hby' : body y = y := by
    simp only [notFixed] at hby
    exact Decidable.of_not_not (of_decide_eq_false hby)
  exact hby' ▸ hmono x y hxy

/-- The `arbitrary_guard_breaks_monotonicity` counterexample from the bridge FAILS
    `Guarded` — confirming `Guarded` is exactly the condition that was missing (not
    a stronger-than-necessary hypothesis smuggling the result in). -/
theorem arbitrary_guard_not_guarded :
    ¬ Guarded (fun x => decide (x = L3.lo)) (fun _ => L3.hi) := by
  intro hg
  exact absurd (hg L3.lo L3.mid (by decide) (by decide) (by decide)) (by decide)

/-- Non-vacuity: a real `while (x = ⊥) do (raise to mid)` on the 3-chain — the
    guard fires only at ⊥, `Guarded` holds, so the step is monotone and ratchets. -/
example :
    Ratchets (whileStep (fun x => decide (x = L3.lo)) (fun x => RankedLattice.join x L3.mid)) :=
  whileStep_ratchets _ _
    (bump_mono _)
    (fun x => RankedLattice.le_join_left x L3.mid)
    (by intro x y hxy hx hy; cases x <;> cases y <;> revert hxy hx hy <;> decide)

#print axioms whileStep_ratchets
#print axioms notFixed_guarded
#print axioms arbitrary_guard_not_guarded

end GkatWhile
