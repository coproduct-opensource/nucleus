/-
  Nucleus / ReputationCapital  (the reputation↔capital flywheel — soundness)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: pure `Nat` arithmetic discharged by
  `omega` + `split` on the one branch. Mirrors the proof style of
  `Nucleus.Auctions.SettlementDecision` and builds directly on
  `Nucleus.WitnessOlog.ForkCost` (the single-stake fork-cost inequality).

  # What this file specifies

  The economic flywheel: **proven history substitutes for posted capital.** A
  bonder's deterrent against a one-shot defection is not just its posted `bond`,
  but `bond + rep`, where `rep` is the *reputation value at risk* — the future
  business it would forfeit if a defection were caught (and it IS caught: recompute
  is the fraud proof). So the more verifiable clean history an agent has, the less
  collateral it must lock to remain honest — and that compounds.

  This file proves the flywheel is **sound and bounded**, not merely optimistic:

  1. `requiredBond_deters`        — posting `requiredBond gain rep` deters a gain.
  2. `requiredBond_le_gain`       — reputation never *increases* the capital required.
  3. `sybil_no_discount`          — a fresh identity (`rep = 0`) must post the FULL
                                    bond; splitting into new identities buys nothing.
  4. `requiredBond_antitone`      — more reputation ⇒ no more bond (the substitution).
  5. `requiredBond_strict_saving` — positive reputation STRICTLY lowers the bond.
  6. `under_collateralized_not_deterred` — below `gain - rep` the agent is NOT
                                    deterred (tightness: you cannot under-collateralize
                                    and stay sound).
  7. `deters_implies_unprofitable`— bridge to the `ForkCost` payoff view: a deterred
                                    defection has net payoff ≤ 0 over the COMBINED
                                    stake `bond + rep` — the same inequality as
                                    `ForkCost.staying_dominates`, with reputation
                                    counted into the forfeiture.

  # Honest scope boundary (read this)

  These theorems prove the *capital arithmetic* of the flywheel: how far reputation
  can substitute for a posted bond while preserving one-shot deterrence. They DO
  NOT prove that `rep` is *real* — that the claimed reputation value is backed by
  actual verifiable clean history. That backing is the recompute + pinning layer
  (`nucleus-witness-olog`): a counterparty must independently re-derive the agent's
  history and the bond-reduction. The model also assumes a defection, if it occurs,
  is DETECTED (recompute) and that detection forfeits `rep` (counterparties stop
  dealing). Detection is mechanised; "detection destroys rep" is the standard
  reputation assumption, named here, not proven.

  Parity: mirrored value-identically by `nucleus-econ-kernels`'s sibling crate
  `nucleus-witness-olog::bond::{required_bond, deters}` (u64 µ-amounts), pinned by
  unit tests there.
-/

namespace Nucleus.ReputationCapital

/-- A bonder is **deterred** from a one-shot defection worth `gain` when the total
    it forfeits on detection — posted `bond` collateral PLUS reputation value at
    risk `rep` — is at least the gain. -/
def deters (bond rep gain : Nat) : Prop := gain ≤ bond + rep

/-- The **minimum bond** that still deters, given reputation `rep`: zero once
    reputation alone covers the gain, otherwise the shortfall `gain - rep`. -/
def requiredBond (gain rep : Nat) : Nat :=
  if gain ≤ rep then 0 else gain - rep

/-- **(1)** Posting `requiredBond gain rep` deters a defection of `gain`. -/
theorem requiredBond_deters (gain rep : Nat) :
    deters (requiredBond gain rep) rep gain := by
  unfold deters requiredBond
  split <;> omega

/-- **(2)** Reputation never *increases* the capital required:
    `requiredBond ≤ gain` always (rep = 0 is the worst case). -/
theorem requiredBond_le_gain (gain rep : Nat) : requiredBond gain rep ≤ gain := by
  unfold requiredBond
  split <;> omega

/-- **(3) Sybil gets no discount.** A fresh identity with no reputation must post
    the full bond — so splitting into new identities to dodge collateral buys
    nothing. (This is the one-shot mitigation of the unavoidable Sybil exposure:
    discounts accrue only to a *persistent* identity that accumulated real history.) -/
theorem sybil_no_discount (gain : Nat) : requiredBond gain 0 = gain := by
  unfold requiredBond
  split <;> omega

/-- **(4) Capital substitution (the flywheel).** More reputation requires no more
    bond: `requiredBond` is antitone in `rep`. -/
theorem requiredBond_antitone (gain : Nat) {r1 r2 : Nat} (h : r1 ≤ r2) :
    requiredBond gain r2 ≤ requiredBond gain r1 := by
  unfold requiredBond
  split <;> split <;> omega

/-- **(5) Strict capital saving.** Positive reputation (up to the gain) *strictly*
    lowers the required bond below the no-reputation case — the compounding edge. -/
theorem requiredBond_strict_saving (gain rep : Nat) (hpos : 0 < rep) (hle : rep ≤ gain) :
    requiredBond gain rep < requiredBond gain 0 := by
  rw [sybil_no_discount]
  unfold requiredBond
  split <;> omega

/-- **(6) Tightness / no under-collateralisation.** If `bond + rep < gain` the
    agent is NOT deterred — capital cannot be reduced past `gain - rep` and remain
    sound. The substitution has a proven floor. -/
theorem under_collateralized_not_deterred (bond rep gain : Nat) (h : bond + rep < gain) :
    ¬ deters bond rep gain := by
  unfold deters
  omega

/-- **(7) Bridge to the fork-cost payoff.** A deterred defection has net payoff
    `gain - (bond + rep) ≤ 0` over the COMBINED stake — i.e. reputation enters the
    exact same deterrence inequality as the bond in
    `Nucleus.WitnessOlog.ForkCost.staying_dominates`. -/
theorem deters_implies_unprofitable (bond rep gain : Nat) (hd : deters bond rep gain) :
    (gain : Int) - ((bond : Int) + (rep : Int)) ≤ 0 := by
  unfold deters at hd
  omega

end Nucleus.ReputationCapital
