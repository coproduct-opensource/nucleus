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

-- ════════════════════════════════════════════════════════════════════════════
-- The Salomaa equation of the `while` loop has a UNIQUE solution (semantically)
--
-- GKAT completeness reduces two bisimilar expressions to solutions of one Salomaa
-- equation system, then invokes the Uniqueness Axiom. Pham (2026) proved
-- uniqueness of those solutions; EXISTENCE is the open syntactic half. In our
-- finite exposure-lattice model BOTH hold constructively — this section proves it
-- for the `while` loop's one-state equation `g x = if b x then g (body x) else x`:
--   • existence  — `whileStep b body` solves it (`whileStep_solves`);
--   • uniqueness — any solution equals it (`solution_unique`).
-- Existence needs only inflationarity (the loop makes progress up the lattice);
-- uniqueness needs `Progress` (the guard never sits on a fixed point of the body —
-- the semantic analogue of GKAT's guardedness side condition, which is exactly
-- what forces uniqueness). This is the semantic instance of the completeness
-- ingredient whose SYNTACTIC existence half is open.
-- ════════════════════════════════════════════════════════════════════════════

/-- The guard never rests on a fixed point of the body — the loop always makes
    progress while it runs. Semantic analogue of GKAT's guardedness. -/
def Progress (b : Test α) (body : α → α) : Prop := ∀ x, b x = true → body x ≠ x

/-- `g` solves the `while b do body` Salomaa equation. -/
def Solves (b : Test α) (body : α → α) (g : α → α) : Prop :=
  ∀ x, g x = if b x then g (body x) else x

omit [RankedLattice α] in
/-- Shifting one iteration to the argument: `f^{n+1}(x) = f^n(f x)`. -/
theorem iter_shift (f : α → α) : ∀ n x, iter f (n + 1) x = iter f n (f x) := by
  intro n
  induction n with
  | zero => intro x; rfl
  | succ n ih => intro x; show f (iter f (n + 1) x) = f (iter f n (f x)); rw [ih x]

/-- The guarded step is inflationary when the body is. -/
theorem guardedStep_inflationary (b : Test α) (body : α → α) (hinf : Inflationary body) :
    ∀ x, RankedLattice.le x (guardedStep b body x) := by
  intro x
  simp only [guardedStep]
  by_cases hb : b x = true
  · rw [if_pos hb]; exact hinf x
  · rw [if_neg hb]; exact RankedLattice.le_refl x

/-- An inflationary map's rank climbs by at least the step count while it keeps
    moving — the termination measure for reaching a fixed point. -/
theorem rank_ge_of_moving (g : α → α) (hg : ∀ x, RankedLattice.le x (g x)) (x : α) :
    ∀ n, (∀ k, k < n → g (iter g k x) ≠ iter g k x) → n ≤ RankedLattice.rank (iter g n x) := by
  intro n
  induction n with
  | zero => intro _; exact Nat.zero_le _
  | succ n ih =>
      intro hmov
      have ihn := ih (fun k hk => hmov k (Nat.lt_succ_of_lt hk))
      have hne := hmov n (Nat.lt_succ_self n)
      have hlt : RankedLattice.rank (iter g n x) < RankedLattice.rank (iter g (n + 1) x) :=
        RankedLattice.rank_strict (hg (iter g n x)) (fun h => hne h.symm)
      exact Nat.lt_of_le_of_lt ihn hlt

/-- An inflationary map reaches a fixed point within `height + 1` steps. -/
theorem exists_fixed_index (g : α → α) (hg : ∀ x, RankedLattice.le x (g x)) (x : α) :
    ∃ k, k ≤ RankedLattice.height (α := α) ∧ g (iter g k x) = iter g k x := by
  refine Classical.byContradiction (fun hne => ?_)
  have hmov : ∀ k, k < RankedLattice.height (α := α) + 1 → g (iter g k x) ≠ iter g k x := by
    intro k hk hEq; exact hne ⟨k, Nat.lt_succ_iff.mp hk, hEq⟩
  have hge := rank_ge_of_moving g hg x (RankedLattice.height (α := α) + 1) hmov
  have hle := RankedLattice.rank_le_height (iter g (RankedLattice.height (α := α) + 1) x)
  exact absurd (Nat.le_trans hge hle) (Nat.not_succ_le_self _)

omit [RankedLattice α] in
theorem iter_const_from (g : α → α) (x : α) (k : Nat)
    (hfix : g (iter g k x) = iter g k x) : ∀ j, iter g (k + j) x = iter g k x := by
  intro j
  induction j with
  | zero => rfl
  | succ j ih => show g (iter g (k + j) x) = iter g k x; rw [ih]; exact hfix

/-- `height + 1` iterations of an inflationary map land on a fixed point. -/
theorem iter_reaches_fixed (g : α → α) (hg : ∀ x, RankedLattice.le x (g x)) (x : α) :
    g (iter g (RankedLattice.height (α := α) + 1) x)
      = iter g (RankedLattice.height (α := α) + 1) x := by
  obtain ⟨k, hkH, hfix⟩ := exists_fixed_index g hg x
  have hconst := iter_const_from g x k hfix
  have hkH1 : k ≤ RankedLattice.height (α := α) + 1 := Nat.le_trans hkH (Nat.le_succ _)
  have e1 : iter g (RankedLattice.height (α := α) + 1) x = iter g k x := by
    obtain ⟨d, hd⟩ := Nat.le.dest hkH1; rw [← hd]; exact hconst d
  have e2 : iter g (RankedLattice.height (α := α) + 2) x = iter g k x := by
    have hkH2 : k ≤ RankedLattice.height (α := α) + 2 := Nat.le_trans hkH1 (Nat.le_succ _)
    obtain ⟨d, hd⟩ := Nat.le.dest hkH2; rw [← hd]; exact hconst d
  calc g (iter g (RankedLattice.height (α := α) + 1) x)
        = iter g (RankedLattice.height (α := α) + 2) x := rfl
      _ = iter g k x := e2
      _ = iter g (RankedLattice.height (α := α) + 1) x := e1.symm

/-- **EXISTENCE.** `whileStep b body` solves the `while` Salomaa equation — it needs
    only that the body is inflationary (the loop climbs the lattice). -/
theorem whileStep_solves (b : Test α) (body : α → α) (hinf : Inflationary body) :
    Solves b body (whileStep b body) := by
  intro x
  have hgsinf := guardedStep_inflationary b body hinf
  have hWfix : guardedStep b body (whileStep b body x) = whileStep b body x :=
    iter_reaches_fixed (guardedStep b body) hgsinf x
  by_cases hb : b x = true
  · rw [if_pos hb]
    -- whileStep x = iter gs (H+1) x = iter gs H (gs x) = iter gs H (body x);
    -- whileStep (body x) = iter gs (H+1) (body x) = gs (iter gs H (body x)) = gs (whileStep x)
    have hgsx : guardedStep b body x = body x := by simp only [guardedStep]; rw [if_pos hb]
    show whileStep b body x = whileStep b body (body x)
    have lhs : whileStep b body x
        = iter (guardedStep b body) (RankedLattice.height (α := α)) (body x) := by
      show iter (guardedStep b body) (RankedLattice.height (α := α) + 1) x = _
      rw [iter_shift, hgsx]
    have rhs : whileStep b body (body x)
        = guardedStep b body (iter (guardedStep b body) (RankedLattice.height (α := α)) (body x)) := by
      show iter (guardedStep b body) (RankedLattice.height (α := α) + 1) (body x) = _
      rfl
    rw [lhs, rhs, ← lhs, hWfix]
  · rw [if_neg hb]
    have hgsx : guardedStep b body x = x := by simp only [guardedStep]; rw [if_neg hb]
    show whileStep b body x = x
    have : guardedStep b body (iter (guardedStep b body) 0 x) = iter (guardedStep b body) 0 x := hgsx
    have hconst := iter_const_from (guardedStep b body) x 0 this
    show iter (guardedStep b body) (RankedLattice.height (α := α) + 1) x = x
    have := hconst (RankedLattice.height (α := α) + 1)
    simpa using this

/-- **UNIQUENESS.** Any two solutions of the `while` Salomaa equation agree —
    given `Progress` (the guard never sits on a body fixed point). Proof: fuel
    induction on `height + 1 − rank x`; each looping step raises the rank, so the
    measure strictly decreases. This is Pham's uniqueness theorem, in the model. -/
theorem solution_unique (b : Test α) (body : α → α)
    (hinf : Inflationary body) (hprog : Progress b body)
    (g₁ g₂ : α → α) (h₁ : Solves b body g₁) (h₂ : Solves b body g₂) :
    ∀ x, g₁ x = g₂ x := by
  suffices key : ∀ n x,
      RankedLattice.height (α := α) + 1 - RankedLattice.rank x ≤ n → g₁ x = g₂ x by
    intro x; exact key (RankedLattice.height (α := α) + 1) x (Nat.sub_le _ _)
  intro n
  induction n with
  | zero =>
      intro x hx
      exact absurd hx (by have := RankedLattice.rank_le_height x; omega)
  | succ n ih =>
      intro x hx
      by_cases hb : b x = true
      · have e1 : g₁ x = g₁ (body x) := by rw [h₁ x, if_pos hb]
        have e2 : g₂ x = g₂ (body x) := by rw [h₂ x, if_pos hb]
        have hlt : RankedLattice.rank x < RankedLattice.rank (body x) :=
          RankedLattice.rank_strict (hinf x) (fun h => (hprog x hb) h.symm)
        have hmeas : RankedLattice.height (α := α) + 1 - RankedLattice.rank (body x) ≤ n := by
          have := RankedLattice.rank_le_height (body x); omega
        rw [e1, e2]; exact ih (body x) hmeas
      · rw [h₁ x, h₂ x, if_neg hb, if_neg hb]

/-- **The while-equation has a unique solution, and it is `whileStep`.** The
    semantic instance of the GKAT completeness ingredient: Pham's uniqueness
    (`solution_unique`) plus the syntactically-open existence (`whileStep_solves`),
    both constructive here because the lattice is finite and the loop is guarded. -/
theorem whileStep_is_unique_solution (b : Test α) (body : α → α)
    (hinf : Inflationary body) (hprog : Progress b body)
    (g : α → α) (hg : Solves b body g) :
    ∀ x, g x = whileStep b body x :=
  solution_unique b body hinf hprog g (whileStep b body) hg (whileStep_solves b body hinf)

#print axioms whileStep_ratchets
#print axioms notFixed_guarded
#print axioms arbitrary_guard_not_guarded
#print axioms whileStep_solves
#print axioms solution_unique

end GkatWhile
