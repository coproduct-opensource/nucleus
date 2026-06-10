/-
  Nucleus / Cooperation / Bonded Deterrence  (the one-shot honesty result)

  **STATUS: PROVED (0 `sorry`).** No `Mathlib` dependency; pure `Nat` kernel
  discharged by `omega`/`decide` and structural case analysis. Mirrors the proof
  style of `Nucleus.WitnessOlog.ForkCost` (`forkPayoff g b = g - b`, `omega`) and
  `Nucleus.ReputationCapital` (`requiredBond`/`deters`, `Nat`, parity-bridged).

  ════════════════════════════════════════════════════════════════════════════
  HONEST-LIMITS BLOCK — read before citing this file.  (Overclaim is rife here;
  the skeptic WILL check. Every clause below is load-bearing.)
  ════════════════════════════════════════════════════════════════════════════

  * This is an INSPECTION / DETERRENCE-game + COMMITMENT-DEVICE result. It is
    NOT a folk-theorem result and does NOT "strengthen", "collapse", or "extend"
    the folk theorem. Folk theorems are about REPETITION + PATIENCE: even with
    perfect monitoring they still require the discount factor δ → 1. The one-shot
    collapse proved here comes from the BOND (a posted, forfeitable stake), NOT
    from the monitoring. A single-shot game with no bond is NOT cooperative no
    matter how perfect the monitoring.

  * It holds ONLY for VERIFIABLE actions (declared-inputs → recomputed-outputs;
    "detected with probability 1" models RECOMPUTE as perfect verifiable
    monitoring of those actions — see the Rice/Löb clause), and ONLY IF the bond
    `B` exceeds the TRUE worst-case one-shot deviation gain — INCLUDING off-model
    bribes, side-payments, and externalities that the recompute cannot see. That
    true worst-case gain is an EMPIRICAL quantity. The theorem is therefore
    CONDITIONAL on correct bond sizing; it does NOT say "cooperation is now
    unconditional." If `B` is mis-sized below the true gain, deviation pays
    (`deviate_pays_when_underbonded` proves exactly this tightness).

  * SYBIL-CONDITIONED (T4). The dominance guarantee assumes ONE-IDENTITY-ONE-BOND
    (`k = 1`). If `k > 1` identities can be minted per posted bond, the per-bond
    deterrence margin DILUTES: an attacker amortising one bond across `k`
    identities effectively needs `B > k * gain`, not `B > gain`. T4 makes this a
    TYPED precondition, never silent. No slashing rule can be Sybil-proof
    (arXiv:2509.18338, Prop. 6) — this file states the dependence, it does not
    defeat it.

  * It does NOT dissolve, weaken, or evade MYERSON-SATTERTHWAITE,
    GIBBARD-SATTERTHWAITE, or GREEN-LAFFONT budget-balance. Those impossibilities
    are about private VALUES / PREFERENCES (mechanism design under incomplete
    information), NOT about monitoring or commitment. Bonded deterrence is
    orthogonal to them and claims nothing about them.

  * RICE / LÖB wall respected. The model is a FINITE integer payoff game over
    DECLARED INPUTS → RECOMPUTED OUTPUTS. "Detected with probability 1" is the
    decidability of recompute on declared data, NOT a decision procedure for
    semantic properties of arbitrary agent code (which Rice forbids), and NOT any
    form of an agent reasoning about its own verifier (which Löb forbids). The
    theorem says nothing about un-recomputable / semantic behaviour.

  ════════════════════════════════════════════════════════════════════════════

  # What is proved

  A SINGLE-SHOT deterrence game. An agent chooses `Honest` or `Deviate`.
  Deviating yields a one-shot `gain : Nat`, but — because recompute detects every
  deviation with probability 1 — the posted bond `B : Nat` is SLASHED. Honest
  play forfeits nothing. Normalising the common honest flow to 0:

      payoff Honest          = 0
      payoff (Deviate caught) = gain - B   (integer; may be negative)

  * **T1 — One-shot bonded-deterrence dominance.** `B > gain → Honest strictly
    dominates Deviate`. No patience, repetition, or reputation needed; the bond
    alone does it, in one shot.
  * **T4 — Sybil-conditioned.** With `k` identities mintable per bond, the
    effective deviation gain is `k * gain` and dominance requires `B > k * gain`.
    At the typed precondition `k = 1` this is exactly T1; for `k > 1` the margin
    degrades, so the guarantee CANNOT be read as unconditional.

  Non-vacuity: a concrete honest-dominant instance (premise SATISFIABLE) AND a
  concrete underbonded instance where Deviate is NOT dominated (premise
  REFUTABLE) — so the theorem has teeth.

  # Parity to the Rust kernel (`nucleus-witness-olog::bond`)

  T1's deterrence condition is the value-identical mirror of the REAL slashing
  schedule `deters(bond, rep, gain) = gain ≤ bond + rep` (`bond.rs`), specialised
  to the pure-bond case `rep = 0`: `deters(B, 0, gain) ↔ gain ≤ B`. The bond is
  the `slashed_micro` forfeited by `slash`/`forfeiture_on_fork`. A parity test
  (`bonded_deterrence_t1_parity` in `bond.rs`) binds `B > gain ⇒ Honest dominant`
  to that real schedule (`deters(B,0,gain)` admits the bond exactly when it
  covers the gain). This file additionally relates to, but is NOT subsumed by,
  `Nucleus.WitnessOlog.ForkCost` (which frames the same arithmetic as fork-cost,
  not as an explicit two-action deterrence game with the Sybil `k` parameter).
-/

namespace Nucleus.Cooperation.BondedDeterrence

/-- The agent's single-shot choice in the inspection/deterrence game. -/
inductive Action where
  | Honest
  | Deviate
deriving DecidableEq, Repr

/-- The net payoff of an action, as an `Int` (deviation may net a LOSS once the
    bond is slashed, so the codomain must admit negatives).

    * `Honest`  forfeits nothing and the common honest flow is normalised to 0.
    * `Deviate` captures the one-shot `gain`, but recompute detects it with
      probability 1, so the posted bond `B` is slashed: net `gain - B`.

    `gain` and `B` are `Nat` (µUSD amounts); the subtraction is taken in `Int`
    so an over-bonded deviation correctly nets negative. -/
def payoff (gain B : Nat) : Action → Int
  | Action.Honest  => 0
  | Action.Deviate => (gain : Int) - (B : Int)

-- ───────────────────────────────────────────────────────────────────────────
-- T1 — One-shot bonded-deterrence dominance.
-- ───────────────────────────────────────────────────────────────────────────

/-- **T1 (One-Shot Bonded-Deterrence Dominance).** If the posted, forfeitable
    bond `B` strictly exceeds the one-shot deviation `gain`, then HONEST play
    STRICTLY dominates deviation in a SINGLE shot:

        `payoff gain B Honest  >  payoff gain B Deviate`.

    No patience, no repetition, no reputation, no δ → 1. The strict dominance is
    purchased entirely by the BOND under perfect (probability-1) detection —
    that is the commitment-device collapse, NOT a folk-theorem effect.

    (See the HONEST-LIMITS block: `B` must exceed the TRUE worst-case gain incl.
    off-model bribes; this is conditional on correct bond sizing.) -/
theorem honest_strictly_dominates (gain B : Nat) (h : B > gain) :
    payoff gain B Action.Honest > payoff gain B Action.Deviate := by
  simp only [payoff]
  omega

/-- T1, general form: under `B > gain`, honest beats EVERY non-honest action
    (here, the only alternative is `Deviate`, by case analysis over `Action`).
    This is the "strictly dominant strategy" statement: for all `a ≠ Honest`,
    `payoff Honest > payoff a`. -/
theorem honest_dominates_all (gain B : Nat) (h : B > gain) :
    ∀ a : Action, a ≠ Action.Honest →
      payoff gain B Action.Honest > payoff gain B a := by
  intro a ha
  cases a with
  | Honest => exact absurd rfl ha
  | Deviate => exact honest_strictly_dominates gain B h

/-- **Tightness of T1.** If the bond does NOT cover the gain (`B ≤ gain`), then
    deviation is NOT strictly dominated — it weakly pays (`payoff Deviate ≥
    payoff Honest`). So `B > gain` is exactly the right deterrence threshold, not
    a conservative one: under-bonding breaks the guarantee. -/
theorem deviate_pays_when_underbonded (gain B : Nat) (h : B ≤ gain) :
    payoff gain B Action.Deviate ≥ payoff gain B Action.Honest := by
  simp only [payoff]
  omega

-- ───────────────────────────────────────────────────────────────────────────
-- T4 — Sybil-conditioned dominance (the anti-overclaim artifact).
-- ───────────────────────────────────────────────────────────────────────────

/-- The EFFECTIVE deviation payoff when `k` identities can be minted per posted
    bond. An attacker who amortises ONE bond `B` across `k` identities collects
    `gain` on each (`k * gain` total) while only `B` is at stake to slash:

        `sybilPayoff k gain B = k * gain - B`.

    At `k = 1` this is exactly `payoff gain B Deviate`. The honest baseline
    remains 0. -/
def sybilPayoff (k gain B : Nat) : Int := (k : Int) * (gain : Int) - (B : Int)

/-- `sybilPayoff 1 = payoff … Deviate` — the typed precondition `k = 1`
    (one-identity-one-bond) recovers the T1 game exactly. -/
theorem sybilPayoff_one (gain B : Nat) :
    sybilPayoff 1 gain B = payoff gain B Action.Deviate := by
  simp only [sybilPayoff, payoff]
  omega

/-- **T4 (Sybil-Conditioned Bonded-Deterrence).** With `k` identities mintable
    per bond, HONEST dominates the (Sybil-amortised) deviation iff the bond
    exceeds the DILUTED gain `k * gain`:

        `B > k * gain → 0 > sybilPayoff k gain B`.

    This statement CANNOT be read as unconditional: the deterrence threshold
    scales with `k`. At the typed precondition `k = 1` it is exactly T1
    (`B > gain`); for `k > 1` the required bond grows, i.e. the per-identity
    deterrence margin DEGRADES by a factor of `k`. No slashing rule defeats this
    (arXiv:2509.18338 Prop. 6); T4 only makes the dependence explicit. -/
theorem sybil_honest_dominates (k gain B : Nat) (h : B > k * gain) :
    (0 : Int) > sybilPayoff k gain B := by
  simp only [sybilPayoff]
  -- Reduce the Int product of casts to the cast of the Nat product (core lemma),
  -- so the remaining goal is linear over `Int` and discharged by `omega`.
  rw [← Int.natCast_mul]
  omega

/-- **T4 degradation (the dilution, made explicit).** Fix a gain `gain ≥ 1` and
    the MINIMAL T1-deterring bond `B = gain + 1` (which under T1's `k = 1` makes
    Honest strictly dominant). If `k ≥ 2` identities are mintable per bond, that
    same bond NO LONGER STRICTLY DETERS — the Sybil-amortised deviation is at
    least break-even:

        `2 ≤ k → 1 ≤ gain → sybilPayoff k gain (gain + 1) ≥ 0`.

    I.e. the T1-correct bond is NOT a T4-correct bond: the strict dominance of
    T1 is destroyed (deviation goes from strictly losing to ≥ break-even). The
    boundary `k = 2, gain = 1` is exactly break-even (`2·1 − 2 = 0`); strictly
    above it deviation strictly pays — see `sybil_dilutes_t1_bond_strict` and the
    concrete `t4_sybil_breaks_t1_bond_concrete` (k = 3). This is why T1's
    guarantee is Sybil-conditioned. -/
theorem sybil_dilutes_t1_bond (k gain : Nat) (hk : 2 ≤ k) (hg : 1 ≤ gain) :
    sybilPayoff k gain (gain + 1) ≥ 0 := by
  simp only [sybilPayoff]
  -- `gain + 1 ≤ 2 * gain ≤ k * gain` (Nat); cast it and the goal is linear.
  have hkg : gain + 1 ≤ k * gain :=
    Nat.le_trans (by omega) (Nat.mul_le_mul_right gain hk)
  have hcast : ((gain + 1 : Nat) : Int) ≤ ((k * gain : Nat) : Int) :=
    Int.ofNat_le.mpr hkg
  rw [Int.natCast_mul] at hcast
  omega

/-- Strict form: once strictly above the break-even boundary (`gain ≥ 2` with
    `k ≥ 2`, or any `k ≥ 3`), the T1-minimal bond is strictly beaten — deviation
    STRICTLY PAYS despite the bond. Here proved for `k ≥ 2, gain ≥ 2`. -/
theorem sybil_dilutes_t1_bond_strict (k gain : Nat) (hk : 2 ≤ k) (hg : 2 ≤ gain) :
    sybilPayoff k gain (gain + 1) > 0 := by
  simp only [sybilPayoff]
  have hkg : gain + 2 ≤ k * gain :=
    Nat.le_trans (by omega) (Nat.mul_le_mul_right gain hk)
  have hcast : ((gain + 2 : Nat) : Int) ≤ ((k * gain : Nat) : Int) :=
    Int.ofNat_le.mpr hkg
  rw [Int.natCast_mul] at hcast
  omega

-- ───────────────────────────────────────────────────────────────────────────
-- NON-VACUITY — the premise `B > gain` is BOTH satisfiable AND refutable.
-- (Concrete `decide` witnesses, same shape as CredibleClearing's existentials.)
-- ───────────────────────────────────────────────────────────────────────────

/-- **Premise SATISFIABLE (the theorem fires).** A concrete honest-dominant
    instance: gain = 0.4M µUSD, bond = 1.0M µUSD. The premise `B > gain` holds,
    and Honest strictly out-pays Deviate (`0 > 0.4M - 1.0M = -0.6M`). So T1 is
    not vacuously true. -/
example : (1_000_000 : Nat) > 400_000 := by decide

theorem t1_fires_concrete :
    payoff 400_000 1_000_000 Action.Honest
      > payoff 400_000 1_000_000 Action.Deviate :=
  honest_strictly_dominates 400_000 1_000_000 (by decide)

/-- **Premise REFUTABLE (Deviate NOT dominated).** A concrete UNDERBONDED
    instance: gain = 1.0M µUSD, bond = 0.4M µUSD. Here `B ≤ gain`, the premise
    FAILS, and Deviate strictly out-pays Honest (`1.0M - 0.4M = +0.6M > 0`). So
    the hypothesis `B > gain` is doing real work — without it the conclusion is
    false. This is the existential counterexample giving the theorem teeth. -/
theorem t1_premise_refutable_concrete :
    payoff 1_000_000 400_000 Action.Deviate
      > payoff 1_000_000 400_000 Action.Honest := by
  unfold payoff
  decide

/-- The premise really is FALSE on that instance (it is not vacuously excluded
    elsewhere): `0.4M > 1.0M` is `False`. -/
example : ¬ ((400_000 : Nat) > 1_000_000) := by decide

/-- **T4 non-vacuity — the Sybil dilution bites on a concrete instance.** Same
    bond (1.0M) that deters a SINGLE identity at gain 0.4M (since 1.0M > 0.4M)
    FAILS once `k = 3` identities are minted: effective gain 3 × 0.4M = 1.2M >
    1.0M, so deviation nets `1.2M - 1.0M = +0.2M > 0`. The single-identity-
    correct bond is Sybil-incorrect — exactly the warning T4 encodes. -/
theorem t4_sybil_breaks_t1_bond_concrete :
    sybilPayoff 3 400_000 1_000_000 > 0 := by
  unfold sybilPayoff
  decide

-- ───────────────────────────────────────────────────────────────────────────
-- Auditor verification. `lake build` surfaces these; each must report axioms
-- WITHIN [propext, Quot.sound, Classical.choice] — sorry-free.
-- ───────────────────────────────────────────────────────────────────────────

/-- info: 'Nucleus.Cooperation.BondedDeterrence.honest_strictly_dominates' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms honest_strictly_dominates

/-- info: 'Nucleus.Cooperation.BondedDeterrence.honest_dominates_all' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms honest_dominates_all

/-- info: 'Nucleus.Cooperation.BondedDeterrence.deviate_pays_when_underbonded' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms deviate_pays_when_underbonded

/-- info: 'Nucleus.Cooperation.BondedDeterrence.sybil_honest_dominates' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms sybil_honest_dominates

/-- info: 'Nucleus.Cooperation.BondedDeterrence.sybil_dilutes_t1_bond' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms sybil_dilutes_t1_bond

/-- info: 'Nucleus.Cooperation.BondedDeterrence.sybil_dilutes_t1_bond_strict' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms sybil_dilutes_t1_bond_strict

end Nucleus.Cooperation.BondedDeterrence
