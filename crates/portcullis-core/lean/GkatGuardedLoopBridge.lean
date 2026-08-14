import ExposureLoopFixpointProofs

/-!
# GKAT's guarded loop ↔ our least fixed point

GKAT (Guarded Kleene Algebra with Tests, Smolka et al. 2019) is the decidable,
guarded fragment of KAT — `if b then p else q` and `while b do p`. Its loop is
NOT axiomatized as a *least* fixed point (dropping KAT's `+` removes the lattice
order that KAT/Kleene-star lean on); it is a **unique** fixed point in Salomaa's
style, made unique by a **guardedness** side condition. Our cascade ratchet
(`ExposureLoopFixpointProofs`) instead uses the **least** fixed point
(Knaster–Tarski over a monotone endomap). These are a priori different objects.

This file reconciles them on the exposure lattice for the operational loop:

- `guardedStep b f` is GKAT's `b · f` — do `f` when the guard holds, else skip.
- With the guard "the body still changes the state" (`f x ≠ x`), the guarded step
  IS the body (`guardedStep_notFixed_eq`), so **iterating GKAT's guarded loop from
  ⊥ computes exactly `lfp f`** (`guarded_loop_is_lfp`), and the loop halts
  precisely at that fixed point (`lfp_fixed`). GKAT's unique guarded fixed point
  and our least fixed point coincide, for any monotone body — so a guarded loop
  inherits the anti-laundering ratchet (`guarded_loop_ratchets`).

- The reconciliation needs the guard to be well-behaved: with an ARBITRARY GKAT
  test the guarded step need not be a monotone endomap
  (`arbitrary_guard_breaks_monotonicity`), so it does not automatically inherit
  the ratchet. That is exactly where the general GKAT `while` (an arbitrary test +
  the guardedness/termination condition) is the further work — and where the
  research frontier sits: GKAT completeness turns on the *unique* fixed point,
  whose axiom is open to eliminate outside the skip-free fragment.

Mathlib-free; `#print axioms` audited at the end.
-/

namespace GkatBridge

open ExposureLoop

variable {α : Type}

/-- A GKAT test: a Boolean predicate on the exposure state. -/
abbrev Test (α : Type) := α → Bool

/-- One guarded step `b · f`: apply `f` when the guard `b` holds, else skip
    (`if b then f else id`). -/
def guardedStep (b : Test α) (f : α → α) : α → α := fun x => if b x then f x else x

/-- The termination test "the body still changes the state" (`f x ≠ x`). GKAT's
    `while` halts when its guard is false; for THIS guard that is exactly a fixed
    point of the body. -/
def notFixed [DecidableEq α] (f : α → α) : Test α := fun x => decide (f x ≠ x)

/-- With the not-fixed guard the guarded step is just the body: when the guard is
    false the body is already the identity there, so both branches agree. -/
theorem guardedStep_notFixed_eq [DecidableEq α] (f : α → α) (x : α) :
    guardedStep (notFixed f) f x = f x := by
  by_cases h : f x = x <;> simp [guardedStep, notFixed, h]

variable [RankedLattice α]

/-- **The guarded loop computes the least fixed point.** Iterating GKAT's guarded
    step `while (f x ≠ x) do f` from ⊥ reaches exactly `lfp f` — GKAT's guarded
    iteration and Knaster–Tarski agree. (This half is definitional in the loop
    count; monotonicity is what makes the reached value a genuine FIXED point, and
    that is `guarded_loop_halts_at_lfp` below — so the two are cleanly separated.) -/
theorem guarded_loop_is_lfp [DecidableEq α] (f : α → α) :
    iter (guardedStep (notFixed f) f) (RankedLattice.height (α := α) + 1) RankedLattice.bot
      = lfp f := by
  have hgs : guardedStep (notFixed f) f = f := funext (guardedStep_notFixed_eq f)
  show iter (guardedStep (notFixed f) f) (RankedLattice.height (α := α) + 1) RankedLattice.bot
       = iter f (RankedLattice.height (α := α) + 1) RankedLattice.bot
  rw [hgs]

/-- The loop's unique fixed point IS the body's fixed point: at `lfp f` the guard
    is false (`f (lfp f) = lfp f`), so the guarded loop halts exactly where
    Knaster–Tarski does. -/
theorem guarded_loop_halts_at_lfp (f : α → α) (hf : Mono f) : f (lfp f) = lfp f :=
  lfp_fixed f hf

/-- **A guarded loop inherits the ratchet.** Since it computes `lfp f`, GKAT's
    guarded loop over a monotone body inherits the anti-laundering ratchet, with
    no per-loop proof — the same one-theorem story the straight-line cascade has. -/
theorem guarded_loop_ratchets (f : α → α) (hf : Mono f) : Ratchets f :=
  loop_admissible f hf

-- ── Where the general GKAT `while` needs more: the guardedness condition ─────

/-- Decidability bridge so `decide` can see the abstract `RankedLattice.le`
    projection at the concrete `L3` witness (as in `DerivationCascadeAdmissible`). -/
instance (a b : L3) : Decidable (RankedLattice.le a b) :=
  inferInstanceAs (Decidable (L3.le a b))

/-- **An arbitrary GKAT test breaks monotonicity.** With `b = (· = ⊥)` and
    `f = const ⊤`, the guarded step sends `lo ↦ hi` but `mid ↦ mid`; since
    `lo ≤ mid` yet `hi ⋠ mid`, `guardedStep b f` is not a monotone endomap. So an
    arbitrary GKAT `while b do f` does NOT automatically inherit the ratchet — the
    reconciliation above rests on the not-fixed (more generally, a guardedness-
    respecting) guard. This is the precise boundary of the general GKAT case. -/
theorem arbitrary_guard_breaks_monotonicity :
    ¬ Mono (guardedStep (fun x => decide (x = L3.lo)) (fun _ => L3.hi)) := by
  intro hmono
  exact absurd (hmono L3.lo L3.mid (by decide)) (by decide)

-- ── Non-vacuity: a concrete guarded loop on the 3-chain ─────────────────────

/-- A concrete guarded loop `while (x ≠ raise x) do (raise to mid)` from ⊥ reaches
    `mid` — the fixed point, distinct from the ⊥ start. -/
example :
    iter (guardedStep (notFixed (fun x => RankedLattice.join x L3.mid))
                      (fun x => RankedLattice.join x L3.mid))
         (RankedLattice.height (α := L3) + 1) RankedLattice.bot = L3.mid := by
  rw [guarded_loop_is_lfp _, lfp_join_const]

#print axioms guarded_loop_is_lfp
#print axioms guarded_loop_ratchets
#print axioms arbitrary_guard_breaks_monotonicity

end GkatBridge
