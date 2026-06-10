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
  recursion theorem programme, and discharges the **T4** (anti-self-weakening)
  crux: the pre-fix hole as a sorry-free constructive counterexample
  (`weak_gate_admits_coup`), the shipped fix on the same witness
  (`new_gate_rejects_coup`), and transitive anti-coup soundness across a 2-step
  chain (`strengthened_gate_closes_it`).

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

  `passedWeak p c` models the PRE-FIX `check_monotonicity`: each of
  cap / io / proofreq is gated on the PARENT's flag (`p.rules.*`); budget is
  ALWAYS checked. This is the buggy gate that admitted the two-step coup
  (`weak_gate_admits_coup`).

  `passed p c` models the SHIPPED (post-fix) `check_monotonicity(parent=p,
  child=c).passed`: `passedWeak` AND the UNCONDITIONAL `rulesNonWeakening`
  conjunct (the child may not DISABLE any governance flag the parent set). This
  is the exact image of the fixed `diff.is_clean()` and equals the proven
  `checkPlus`. The `rulesNonWeakening` conjunct is NEVER gated on any flag —
  that unconditionality is the fix (`new_gate_rejects_coup`).
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

/-- `passedWeak p c` models the PRE-FIX `check_monotonicity`: the conjunction of
    the four "not violated" verdicts, each cap/io/proofreq axis gated on the
    PARENT flag, budget always checked. This is the BUGGY gate — it never
    inspects the child's amendment rules, so it admits the two-step coup
    (`weak_gate_admits_coup`). Kept as a documentary witness of the old logic. -/
def passedWeak (p c : Manifest) : Bool :=
  !capViolated p c && !ioViolated p c && !budgetViolated p c && !proofReqViolated p c

/-- `weakensRules c p`: the child turns OFF some monotone flag the parent had ON —
    i.e. it weakens the amendment rules along at least one axis. This is exactly
    what the PRE-FIX `check_monotonicity` does NOT inspect. -/
def weakensRules (c p : Manifest) : Prop :=
  (p.rules.cap = true ∧ c.rules.cap = false) ∨
  (p.rules.io = true ∧ c.rules.io = false) ∨
  (p.rules.proofreq = true ∧ c.rules.proofreq = false)

/-- `rulesNonWeakening c p`: the child's flags are pointwise `≥` the parent's —
    i.e. you can ENABLE a monotone flag but never DISABLE one. As a `Bool`:
    `parent_flag → child_flag` on each axis. This is the boolean image of
    `ck_types::manifest::AmendmentRules::weakened_flags_over(...).is_empty()`,
    and it is checked UNCONDITIONALLY (no flag guard) by the shipped gate. -/
def rulesNonWeakening (c p : Manifest) : Bool :=
  (!p.rules.cap || c.rules.cap) &&
  (!p.rules.io || c.rules.io) &&
  (!p.rules.proofreq || c.rules.proofreq)

/-- `passed p c` models the SHIPPED `check_monotonicity(parent=p, child=c).passed`.
    The verdict is `is_clean()` = no axis violated AND no amendment-rule
    weakening. It is `passedWeak` AND the UNCONDITIONAL `rulesNonWeakening`
    conjunct — equal to the proven `checkPlus`. The `rulesNonWeakening` conjunct
    has NO flag guard: that unconditionality is the anti-coup fix. -/
def passed (p c : Manifest) : Bool :=
  passedWeak p c && rulesNonWeakening c p

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

/-- **THEOREM T1 (PROVED).** Soundness of the SHIPPED monotonicity gate.

    If the shipped `check_monotonicity(parent=p, child=c)` PASSES (`passed p c`),
    then for each axis whose monotone flag is set on the PARENT, the corresponding
    escalation is ruled out; the budget is within bounds UNCONDITIONALLY; AND —
    this is the T4 fix — the child does NOT weaken the amendment rules
    (`¬ weakensRules c p`), also UNCONDITIONALLY (no flag gates it).

    The first three guarantees keep the conditional shape the parent flags impose;
    the new fourth guarantee is unconditional, which is what carries the flags
    forward across an amendment chain (`strengthened_gate_closes_it`) and closes
    the two-step coup (`new_gate_rejects_coup`). -/
theorem T1_gate_sound (p c : Manifest) (h : passed p c = true) :
    (p.rules.cap = true → ¬ capEscalates c p) ∧
    (p.rules.io = true → ¬ ioEscalates c p) ∧
    (budgetWithinP c p) ∧
    (p.rules.proofreq = true → ¬ proofReqDrops c p) ∧
    (¬ weakensRules c p) := by
  -- Split the shipped verdict into the weak (four-axis) part and the
  -- unconditional non-weakening part.
  unfold passed passedWeak rulesNonWeakening at h
  simp only [Bool.and_eq_true, Bool.not_eq_true'] at h
  obtain ⟨⟨⟨⟨hcap, hio⟩, hbud⟩, hproof⟩, ⟨⟨hrw_cap, hrw_io⟩, hrw_proof⟩⟩ := h
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
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
  · -- amendment-rules non-weakening — UNCONDITIONAL (no flag guard)
    intro hw
    rcases hw with ⟨hp, hc⟩ | ⟨hp, hc⟩ | ⟨hp, hc⟩
    · rw [hp, hc] at hrw_cap; simp at hrw_cap
    · rw [hp, hc] at hrw_io; simp at hrw_io
    · rw [hp, hc] at hrw_proof; simp at hrw_proof

/- ───────────────────────────────────────────────────────────────────────────
   THE COUP: the OLD gate admits it; the NEW gate rejects it (PROVED, 0 sorry)
   ─────────────────────────────────────────────────────────────────────────── -/

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
    empty), but it silently turns OFF the capability monotone flag — disarming
    the NEXT amendment. The pre-fix gate admitted this; the shipped gate does not. -/
def disarmingChild : Manifest :=
  { caps := [], ioSurface := [], proofReqs := []
  , budget := zeroBudget
  , rules := { cap := false, io := true, proofreq := true } }

/-- **THEOREM weak_gate_admits_coup (PROVED, documentary).** The PRE-FIX hole.

    There exist a parent `p` and child `c` such that the OLD gate `passedWeak`
    PASSES AND `c` weakens the amendment rules vs `p` — it disables a
    required-monotone flag. The pre-fix gate admitted an amendment that disarms
    its own future enforcement: a two-step coup (this step legal, the NEXT step
    then escalates freely under the relaxed flag). `passedWeak` never checks that
    the CHILD's amendment_rules are themselves non-weakening — this theorem is
    kept to document precisely the bug the fix closes. -/
theorem weak_gate_admits_coup : ∃ p c, passedWeak p c = true ∧ weakensRules c p := by
  refine ⟨fullParent, disarmingChild, ?_, ?_⟩
  · decide
  · -- the capability flag was ON in the parent, OFF in the child
    left
    exact ⟨rfl, rfl⟩

/-- **THEOREM new_gate_rejects_coup (PROVED).** The fix, on the SAME witness.

    On the exact disarming amendment that `weak_gate_admits_coup` slips past the
    pre-fix gate, the SHIPPED gate `passed` returns `false`. The unconditional
    `rulesNonWeakening` conjunct rejects the disarming step at move ONE, so the
    coup never reaches its second move. -/
theorem new_gate_rejects_coup : passed fullParent disarmingChild = false := by
  decide

/-- The shipped gate refines the pre-fix gate: anything `passed` admits,
    `passedWeak` also admits (the fix only ever REJECTS more — STRICTLY
    STRICTER, no new acceptances). -/
theorem passed_refines_passedWeak (p c : Manifest) (h : passed p c = true) :
    passedWeak p c = true := by
  unfold passed at h
  simp only [Bool.and_eq_true] at h
  exact h.1

/-- The shipped gate forbids `weakensRules` directly (corollary of T1's new
    conjunct): if `passed p c`, the child does NOT weaken the rules. -/
theorem passed_no_weakening (p c : Manifest) (h : passed p c = true) :
    ¬ weakensRules c p :=
  (T1_gate_sound p c h).2.2.2.2

/- ───────────────────────────────────────────────────────────────────────────
   THEOREM strengthened_gate_closes_it — transitive anti-coup (PROVED, 0 sorry)
   ─────────────────────────────────────────────────────────────────────────── -/

/-- **THEOREM strengthened_gate_closes_it (PROVED).** The anti-coup invariant
    holds across a TWO-amendment chain `p → c → g` under the SHIPPED gate,
    exactly where the pre-fix gate (`weak_gate_admits_coup`) fails.

    Hypotheses: both steps pass the shipped `passed`. Conclusions: at the END of
    the chain (`g` as child of `p`),
      1. budget is still within `p`'s bound; and
      2. if `p` required capability monotonicity, then `g` does NOT escalate
         capabilities over `p` — the guarantee survives the intermediate step,
         because `passed` (via its unconditional `rulesNonWeakening` conjunct)
         forbade `c` from disarming the flag.

    Under the PRE-FIX gate this fails: `c` could set `c.rules.cap = false` (the
    `weak_gate_admits_coup` witness), after which `g` escalates freely and
    `passedWeak c g` still holds. The shipped gate carries the flag forward,
    restoring transitive soundness — the T4 anti-self-weakening property. -/
theorem strengthened_gate_closes_it
    (p c g : Manifest)
    (h1 : passed p c = true) (h2 : passed c g = true) :
    budgetWithinP g p ∧
    (p.rules.cap = true → ¬ capEscalates g p) := by
  -- Soundness of each step from T1 (now including the non-weakening conjunct).
  have t1 := T1_gate_sound p c h1
  have t2 := T1_gate_sound c g h2
  have hnw1 : ¬ weakensRules c p := t1.2.2.2.2
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

/- ───────────────────────────────────────────────────────────────────────────
   #print axioms — axiom-hygiene audit (kernel-checked, no proof holes,
   no compiled-decision shortcuts)
   ─────────────────────────────────────────────────────────────────────────── -/

#print axioms T1_gate_sound
#print axioms weak_gate_admits_coup
#print axioms new_gate_rejects_coup
#print axioms passed_refines_passedWeak
#print axioms passed_no_weakening
#print axioms strengthened_gate_closes_it

end Ck.Policy
