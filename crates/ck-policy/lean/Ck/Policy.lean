/-
  Ck / Policy  (Constitutional Kernel monotonicity-gate soundness proofs)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: `Nat` + `List` + `Bool` + `omega`
  / `decide` + structural induction. No native-decide. Lean 4 v4.30.0-rc2,
  `autoImplicit = false`. Same discipline as `Nucleus.Rubric` in
  `crates/nucleus-rubric/lean`.

  This file is the Lean *statement and proof* of the soundness properties the Rust
  crate `ck-policy` (`crates/ck-policy/src/lib.rs`, `check_monotonicity`) is
  parity-pinned to. The verdict predicate of the model is asserted to AGREE with
  the production `check_monotonicity().passed` over randomized manifest pairs in
  `crates/ck-policy/tests/policy_lean_parity.rs`.

  This discharges **T1** (monotonicity-gate soundness) of the guaranteed-safe-
  recursion theorem programme, and surfaces the **T4** (anti-self-weakening) crux
  as a sorry-free constructive counterexample (`meta_gap`) plus its fix
  (`strengthened_gate_closes_it`).

  # EXTRACTION-GAP CAVEAT

  These theorems are proved about the Lean MODEL. The parity proptest binds the
  model verdict to the SHIPPED Rust only PROBABILISTICALLY (random sampling,
  finite cases) plus a fixed adversarial vector; it is NOT a formal extraction. A
  formal Aeneas-style extraction of `check_monotonicity` would be required to
  close the model↔Rust gap DEDUCTIVELY. Until then, treat the theorems as
  statements about the model, parity-checked — not extracted — into Rust.

  # The model

  We model the *projections* that `check_monotonicity` actually reads:

    * capability / io / proof-requirement sets as `List String`, ordered by
      `Subset a b := ∀ x ∈ a, x ∈ b` (decidable);
    * budget bounds as a record of `Nat` with `BudgetWithin` = pointwise `≤`;
    * the three `amendment_rules` monotone flags as `Bool`.

  `capEscalates` / `ioEscalates` model `escalations_over(...).is_empty() == false`
  (an element of the CHILD not in the PARENT), `proofReqDrops` models
  `dropped_requirements(...).is_empty() == false` (an element of the PARENT not in
  the CHILD), and `budgetWithin` models `BudgetBounds::is_within` (pointwise `≤`).

  `passed p c` models `check_monotonicity(parent=p, child=c).passed`: each of
  cap / io / proofreq is gated on the PARENT's flag (`p.rules.*`); budget is
  ALWAYS checked; `passed` is the conjunction of the four "clean" verdicts — the
  exact image of `diff.is_clean()` (`violated_invariants.is_empty()`).
-/

namespace Ck.Policy

/- ───────────────────────────────────────────────────────────────────────────
   The model: manifest projections (Mathlib-free)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- A discrete authority axis (capabilities / io surface / proof requirements all
    reduce to a `List String` carrier in the projections the gate reads). -/
abbrev Names := List String

/-- `Subset a b`: every element of `a` is in `b`. Decidable, Mathlib-free.
    `List.Mem`/`List.all` give the decidability instance for free. -/
def Subset (a b : Names) : Prop := ∀ x ∈ a, x ∈ b

instance (a b : Names) : Decidable (Subset a b) := by
  unfold Subset
  exact inferInstanceAs (Decidable (∀ x ∈ a, x ∈ b))

/-- `escalatesB child parent`: `true` iff some element of `child` is NOT in
    `parent`. The boolean image of `escalations_over(parent).is_empty() == false`
    — i.e. there exists an escalation. -/
def escalatesB (child parent : Names) : Bool :=
  child.any (fun x => !parent.contains x)

/-- `dropsB child parent`: `true` iff some element of `parent` is NOT in `child`.
    The boolean image of `dropped_requirements(parent).is_empty() == false` — i.e.
    a required proof obligation was dropped. -/
def dropsB (child parent : Names) : Bool :=
  parent.any (fun x => !child.contains x)

/-- Budget bounds as the pointwise-ordered record the gate compares. The eight
    `Nat` fields mirror `ck_types::manifest::BudgetBounds` (units irrelevant to
    the order; modeled as `Nat`). -/
structure Budget where
  maxTokens : Nat
  maxWallMs : Nat
  maxCpuMs : Nat
  maxMemoryBytes : Nat
  maxNetworkCalls : Nat
  maxFilesTouched : Nat
  maxDollarSpendMillicents : Nat
  maxPatchAttempts : Nat
deriving DecidableEq, Repr

/-- `budgetWithin c p`: every field of the child `c` is `≤` the parent `p`. The
    boolean image of `BudgetBounds::is_within`. ALWAYS checked by the gate. -/
def budgetWithin (c p : Budget) : Bool :=
  decide (c.maxTokens ≤ p.maxTokens) &&
  decide (c.maxWallMs ≤ p.maxWallMs) &&
  decide (c.maxCpuMs ≤ p.maxCpuMs) &&
  decide (c.maxMemoryBytes ≤ p.maxMemoryBytes) &&
  decide (c.maxNetworkCalls ≤ p.maxNetworkCalls) &&
  decide (c.maxFilesTouched ≤ p.maxFilesTouched) &&
  decide (c.maxDollarSpendMillicents ≤ p.maxDollarSpendMillicents) &&
  decide (c.maxPatchAttempts ≤ p.maxPatchAttempts)

/-- The three monotone flags from `ck_types::manifest::AmendmentRules`. The gate
    reads them off the PARENT manifest only. -/
structure Rules where
  cap : Bool
  io : Bool
  proofreq : Bool
deriving DecidableEq, Repr

/-- The slice of a `PolicyManifest` the monotonicity gate actually reads:
    the cap / io / proofreq projections, the budget, and the amendment rules. -/
structure Manifest where
  caps : Names
  ioSurface : Names
  proofReqs : Names
  budget : Budget
  rules : Rules
deriving Repr

/- ───────────────────────────────────────────────────────────────────────────
   The model: check_monotonicity faithfully (parent = p, child = c)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Capability axis violated? Gated on the PARENT flag (`escalations_over` is only
    consulted when `parent.amendment_rules.require_monotone_capabilities`). -/
def capViolated (p c : Manifest) : Bool :=
  if p.rules.cap then escalatesB c.caps p.caps else false

/-- I/O axis violated? Gated on the PARENT flag. -/
def ioViolated (p c : Manifest) : Bool :=
  if p.rules.io then escalatesB c.ioSurface p.ioSurface else false

/-- Budget axis violated? ALWAYS checked — there is no gating flag in the Rust. -/
def budgetViolated (p c : Manifest) : Bool :=
  !budgetWithin c.budget p.budget

/-- Proof-requirement axis violated? Gated on the PARENT flag. -/
def proofReqViolated (p c : Manifest) : Bool :=
  if p.rules.proofreq then dropsB c.proofReqs p.proofReqs else false

/-- `passed p c` models `check_monotonicity(parent=p, child=c).passed`. The verdict
    is `is_clean()` = no axis violated = the conjunction of the four "not
    violated" verdicts. -/
def passed (p c : Manifest) : Bool :=
  !capViolated p c && !ioViolated p c && !budgetViolated p c && !proofReqViolated p c

/- ───────────────────────────────────────────────────────────────────────────
   The Prop-level escalation facts (what soundness rules OUT)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- `capEscalates c p`: the child grants a capability the parent did not — i.e.
    `¬ Subset c.caps p.caps`. -/
def capEscalates (c p : Manifest) : Prop := ¬ Subset c.caps p.caps

/-- `ioEscalates c p`: the child widens the io surface beyond the parent. -/
def ioEscalates (c p : Manifest) : Prop := ¬ Subset c.ioSurface p.ioSurface

/-- `proofReqDrops c p`: the child dropped a proof requirement the parent had —
    i.e. `¬ Subset p.proofReqs c.proofReqs` (parent ⊄ child). -/
def proofReqDrops (c p : Manifest) : Prop := ¬ Subset p.proofReqs c.proofReqs

/-- `budgetWithinP c p`: Prop-level "child budget is within parent budget". -/
def budgetWithinP (c p : Manifest) : Prop := budgetWithin c.budget p.budget = true

/- ───────────────────────────────────────────────────────────────────────────
   Bridge lemmas: the boolean scans decode to the Prop-level facts
   ─────────────────────────────────────────────────────────────────────────── -/

/-- `escalatesB` is `false` ↔ `Subset` (no element of the child is outside the
    parent). The decisive bridge between the boolean gate and the order. -/
theorem escalatesB_false_iff_subset (child parent : Names) :
    escalatesB child parent = false ↔ Subset child parent := by
  unfold escalatesB Subset
  constructor
  · intro h x hx
    simp only [List.any_eq_false] at h
    have := h x hx
    simp only [Bool.not_eq_true', Bool.not_eq_false] at this
    exact List.contains_iff_mem.mp this
  · intro h
    simp only [List.any_eq_false]
    intro x hx
    simp only [Bool.not_eq_true', Bool.not_eq_false]
    exact List.contains_iff_mem.mpr (h x hx)

/-- `dropsB c.proofReqs p.proofReqs = false` ↔ `Subset p.proofReqs c.proofReqs`:
    no parent requirement is missing from the child. -/
theorem dropsB_false_iff_subset (child parent : Names) :
    dropsB child parent = false ↔ Subset parent child := by
  unfold dropsB
  exact escalatesB_false_iff_subset parent child

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM T1 — conditional monotonicity-gate soundness (PROVED, 0 sorry)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- **THEOREM T1 (PROVED).** Conditional soundness of the monotonicity gate.

    If `check_monotonicity(parent=p, child=c)` PASSES, then for each axis whose
    monotone flag is set on the PARENT, the corresponding escalation is ruled out;
    and the budget is within bounds UNCONDITIONALLY (no flag gates it).

    This is exactly as strong as the Rust permits — and the conditional shape
    (each guarantee predicated on `p.rules.*`) is itself the seed of the T4 gap:
    the parent's own flags decide what is enforced. -/
theorem T1_gate_sound (p c : Manifest) (h : passed p c = true) :
    (p.rules.cap = true → ¬ capEscalates c p) ∧
    (p.rules.io = true → ¬ ioEscalates c p) ∧
    (budgetWithinP c p) ∧
    (p.rules.proofreq = true → ¬ proofReqDrops c p) := by
  -- Decompose the conjunctive verdict into the four per-axis "clean" facts.
  unfold passed at h
  simp only [Bool.and_eq_true, Bool.not_eq_true'] at h
  obtain ⟨⟨⟨hcap, hio⟩, hbud⟩, hproof⟩ := h
  refine ⟨?_, ?_, ?_, ?_⟩
  · -- capability axis
    intro hflag
    unfold capViolated at hcap
    rw [hflag] at hcap
    simp only [if_true] at hcap
    unfold capEscalates
    exact not_not_intro ((escalatesB_false_iff_subset c.caps p.caps).mp hcap)
  · -- io axis
    intro hflag
    unfold ioViolated at hio
    rw [hflag] at hio
    simp only [if_true] at hio
    unfold ioEscalates
    exact not_not_intro ((escalatesB_false_iff_subset c.ioSurface p.ioSurface).mp hio)
  · -- budget axis — unconditional
    unfold budgetWithinP
    unfold budgetViolated at hbud
    simpa using hbud
  · -- proof-requirement axis
    intro hflag
    unfold proofReqViolated at hproof
    rw [hflag] at hproof
    simp only [if_true] at hproof
    unfold proofReqDrops
    exact not_not_intro ((dropsB_false_iff_subset c.proofReqs p.proofReqs).mp hproof)

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM meta_gap — the anti-coup HOLE (PROVED, constructive, 0 sorry)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- `weakensRules c p`: the child turns OFF some monotone flag the parent had ON —
    i.e. it weakens the amendment rules along at least one axis. This is exactly
    what `check_monotonicity` does NOT inspect. -/
def weakensRules (c p : Manifest) : Prop :=
  (p.rules.cap = true ∧ c.rules.cap = false) ∨
  (p.rules.io = true ∧ c.rules.io = false) ∨
  (p.rules.proofreq = true ∧ c.rules.proofreq = false)

/-- An empty budget (all zero): trivially within any budget, so the always-on
    budget check never fires for our witnesses. -/
def zeroBudget : Budget :=
  ⟨0, 0, 0, 0, 0, 0, 0, 0⟩

/-- All-monotone parent: every flag ON, empty projections, zero budget. -/
def fullParent : Manifest :=
  { caps := [], ioSurface := [], proofReqs := []
  , budget := zeroBudget
  , rules := { cap := true, io := true, proofreq := true } }

/-- The malicious child: IDENTICAL projections (so every escalation/drop scan is
    empty and the gate passes), but it silently turns OFF the capability monotone
    flag — disarming the NEXT amendment. -/
def disarmingChild : Manifest :=
  { caps := [], ioSurface := [], proofReqs := []
  , budget := zeroBudget
  , rules := { cap := false, io := true, proofreq := true } }

/-- **THEOREM meta_gap (PROVED).** The honest gap / T4 crux.

    There exist a parent `p` and child `c` such that `check_monotonicity` PASSES
    (`passed p c = true`) AND `c` weakens the amendment rules vs `p` — it disables
    a required-monotone flag. The plain gate admits an amendment that disarms its
    own future enforcement: a two-step coup (this step legal, the NEXT step then
    escalates freely under the relaxed flag). `check_monotonicity` never checks
    that the CHILD's amendment_rules are themselves non-weakening. -/
theorem meta_gap : ∃ p c, passed p c = true ∧ weakensRules c p := by
  refine ⟨fullParent, disarmingChild, ?_, ?_⟩
  · decide
  · -- the capability flag was ON in the parent, OFF in the child
    left
    exact ⟨rfl, rfl⟩

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM strengthened_gate_closes_it — the constructive FIX (PROVED, 0 sorry)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- `rulesNonWeakening c p`: the child's flags are pointwise `≥` the parent's —
    i.e. you can ENABLE a monotone flag but never DISABLE one. As a `Bool`:
    `parent_flag → child_flag` on each axis. -/
def rulesNonWeakening (c p : Manifest) : Bool :=
  (!p.rules.cap || c.rules.cap) &&
  (!p.rules.io || c.rules.io) &&
  (!p.rules.proofreq || c.rules.proofreq)

/-- `checkPlus p c`: the STRENGTHENED gate. It is the plain gate PLUS the missing
    obligation — the child's amendment rules must be non-weakening. This is the
    one-line fix the proof recommends for `check_monotonicity`. -/
def checkPlus (p c : Manifest) : Bool :=
  passed p c && rulesNonWeakening c p

/-- `checkPlus` refines `passed`: anything the strengthened gate admits, the plain
    gate also admits (the fix only ever REJECTS more). -/
theorem checkPlus_refines_passed (p c : Manifest) (h : checkPlus p c = true) :
    passed p c = true := by
  unfold checkPlus at h
  simp only [Bool.and_eq_true] at h
  exact h.1

/-- The strengthened gate forbids `weakensRules`: if `checkPlus p c` passes, the
    child does NOT weaken the rules. This is precisely the obligation the plain
    gate (`meta_gap`) omits. -/
theorem checkPlus_no_weakening (p c : Manifest) (h : checkPlus p c = true) :
    ¬ weakensRules c p := by
  unfold checkPlus rulesNonWeakening at h
  simp only [Bool.and_eq_true] at h
  obtain ⟨_, ⟨⟨hcap, hio⟩, hproof⟩⟩ := h
  intro hw
  rcases hw with ⟨hp, hc⟩ | ⟨hp, hc⟩ | ⟨hp, hc⟩
  · rw [hp, hc] at hcap; simp at hcap
  · rw [hp, hc] at hio; simp at hio
  · rw [hp, hc] at hproof; simp at hproof

/-- **THEOREM strengthened_gate_closes_it (PROVED).** The anti-coup invariant
    holds across a TWO-amendment chain `p → c → g` under the strengthened gate,
    exactly where the plain gate (`meta_gap`) fails.

    Hypotheses: both steps pass `checkPlus`. Conclusions: at the END of the chain
    (`g` as child of `p`),
      1. budget is still within `p`'s bound; and
      2. if `p` required capability monotonicity, then `g` does NOT escalate
         capabilities over `p` — the guarantee survives the intermediate step,
         because `checkPlus` forbade `c` from disarming the flag.

    Under the PLAIN gate this fails: `c` could set `c.rules.cap = false` (the
    `meta_gap` witness), after which `g` escalates freely and `passed c g` still
    holds. The strengthened gate carries the flag forward, restoring transitive
    soundness — the T4 anti-self-weakening property. -/
theorem strengthened_gate_closes_it
    (p c g : Manifest)
    (h1 : checkPlus p c = true) (h2 : checkPlus c g = true) :
    budgetWithinP g p ∧
    (p.rules.cap = true → ¬ capEscalates g p) := by
  -- Unpack the two strengthened verdicts into plain + non-weakening parts.
  have hp1 : passed p c = true := checkPlus_refines_passed p c h1
  have hp2 : passed c g = true := checkPlus_refines_passed c g h2
  have hnw1 : ¬ weakensRules c p := checkPlus_no_weakening p c h1
  -- Soundness of each step from T1.
  have t1 := T1_gate_sound p c hp1
  have t2 := T1_gate_sound c g hp2
  refine ⟨?_, ?_⟩
  · -- Budget: g ≤ c ≤ p, pointwise, transitively.
    have hgc : budgetWithin g.budget c.budget = true := t2.2.2.1
    have hcp : budgetWithin c.budget p.budget = true := t1.2.2.1
    unfold budgetWithinP
    unfold budgetWithin at hgc hcp ⊢
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hgc hcp ⊢
    -- Each of the eight coordinates: g ≤ c and c ≤ p ⇒ g ≤ p.
    obtain ⟨⟨⟨⟨⟨⟨⟨a1, a2⟩, a3⟩, a4⟩, a5⟩, a6⟩, a7⟩, a8⟩ := hgc
    obtain ⟨⟨⟨⟨⟨⟨⟨b1, b2⟩, b3⟩, b4⟩, b5⟩, b6⟩, b7⟩, b8⟩ := hcp
    exact ⟨⟨⟨⟨⟨⟨⟨Nat.le_trans a1 b1, Nat.le_trans a2 b2⟩, Nat.le_trans a3 b3⟩,
      Nat.le_trans a4 b4⟩, Nat.le_trans a5 b5⟩, Nat.le_trans a6 b6⟩,
      Nat.le_trans a7 b7⟩, Nat.le_trans a8 b8⟩
  · -- Capabilities: the parent flag carries forward to the middle step.
    intro hflag
    -- Step 1 passed with the flag ON ⇒ ¬¬ Subset, decoded via decidability.
    have hsub_cp : Subset c.caps p.caps := Decidable.of_not_not (t1.1 hflag)
    -- The flag was NOT disarmed: c.rules.cap must still be true (else `weakensRules`).
    have hcflag : c.rules.cap = true := by
      cases hh : c.rules.cap with
      | true => rfl
      | false => exact absurd (Or.inl ⟨hflag, hh⟩) hnw1
    -- So step 2 enforced capability monotonicity too ⇒ Subset g.caps c.caps.
    have hsub_gc : Subset g.caps c.caps := Decidable.of_not_not (t2.1 hcflag)
    -- Compose the subsets: g ⊆ c ⊆ p.
    unfold capEscalates
    intro hbad
    apply hbad
    intro x hx
    exact hsub_cp x (hsub_gc x hx)

end Ck.Policy
