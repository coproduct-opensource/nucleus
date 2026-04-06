/-!
# Repair Algebra Proofs — Soundness of deny → repair → allow (#1297)

Sorry-gated theorem statements bridging `docs/theory/repair-algebra.md`
to machine-checkable Lean 4. Each theorem is a verification target —
replacing `sorry` with a proof makes the theory doc claim machine-checked.

## Theorems

### Retraction (Layer 1)
- **repair_idempotent**: applying repair twice = applying once
- **repair_passes_check**: repaired term passes the check that denied

### Galois connection (Layer 2)
- **repair_composable**: repairs for disjoint checks commute
- **admit_antitone**: more obligations → fewer admitted terms

### Free-forgetful adjunction (Layer 3)
- **discharge_deterministic**: same term → same bundle
- **repair_unit**: repair is the unit of the adjunction

## Status

All theorems are `sorry`-gated. They type-check as statements but
are not proved. The CI `sorry` counter tracks these as open obligations.

Completing these proofs is tracked in:
- #1283: Lean proof of repair soundness
- #1209-b: repair soundness via Aeneas extraction
-/

-- ═══════════════════════════════════════════════════════════════════════════
-- Minimal model types (hand-written, mirroring Rust discharge.rs)
-- ═══════════════════════════════════════════════════════════════════════════

/-- Integrity levels: Adversarial < Untrusted < Trusted -/
inductive IntegLevel where
  | Adversarial
  | Untrusted
  | Trusted
  deriving DecidableEq, Repr

/-- Derivation classes for Rule 6 checking -/
inductive DerivationClass where
  | Deterministic
  | AIDerived
  | HumanPromoted
  | Mixed
  | OpaqueExternal
  deriving DecidableEq, Repr

/-- Simplified ActionTerm — the fields relevant to obligation checking -/
structure ActionTerm where
  artifactIntegrity : IntegLevel
  artifactDerivation : DerivationClass
  hasAdversarialSource : Bool
  costMicroUsd : Nat

/-- Obligation check outcome -/
inductive CheckResult where
  | Pass
  | Fail

/-- Repair hint variants (mirrors Rust RepairHint enum) -/
inductive RepairHint where
  | RaiseIntegrity (required : IntegLevel)
  | PromoteDerivation
  | DeclassifyInput
  | WireBudgetGate

-- ═══════════════════════════════════════════════════════════════════════════
-- Check functions (modeling the 5 obligation checks)
-- ═══════════════════════════════════════════════════════════════════════════

def integ_order : IntegLevel → Nat
  | .Adversarial => 0
  | .Untrusted => 1
  | .Trusted => 2

def check_integrity (term : ActionTerm) (required : IntegLevel) : CheckResult :=
  if integ_order term.artifactIntegrity >= integ_order required
  then .Pass
  else .Fail

def check_derivation (term : ActionTerm) : CheckResult :=
  match term.artifactDerivation with
  | .Deterministic | .HumanPromoted => .Pass
  | _ => .Fail

def check_ancestry (term : ActionTerm) : CheckResult :=
  if term.hasAdversarialSource then .Fail else .Pass

def check_budget (term : ActionTerm) : CheckResult :=
  if term.costMicroUsd == 0 then .Pass else .Fail

-- ═══════════════════════════════════════════════════════════════════════════
-- Repair functions (modeling RepairHint::try_repair)
-- ═══════════════════════════════════════════════════════════════════════════

def repair_integrity (term : ActionTerm) (required : IntegLevel) : ActionTerm :=
  { term with artifactIntegrity := required }

def repair_derivation (term : ActionTerm) : ActionTerm :=
  { term with artifactDerivation := .HumanPromoted }

def repair_ancestry (term : ActionTerm) : ActionTerm :=
  { term with hasAdversarialSource := false }

def repair_budget (term : ActionTerm) : ActionTerm :=
  { term with costMicroUsd := 0 }

-- ═══════════════════════════════════════════════════════════════════════════
-- Layer 1: Retraction theorems
-- ═══════════════════════════════════════════════════════════════════════════

/-- Repair soundness: repaired term passes the check that denied it.
    This is the core safety property of the repair system. -/
theorem repair_integrity_passes (term : ActionTerm) (required : IntegLevel) :
    check_integrity (repair_integrity term required) required = .Pass := by
  sorry

/-- Derivation repair produces HumanPromoted, which passes check_derivation. -/
theorem repair_derivation_passes (term : ActionTerm) :
    check_derivation (repair_derivation term) = .Pass := by
  sorry

/-- Ancestry repair removes adversarial sources. -/
theorem repair_ancestry_passes (term : ActionTerm) :
    check_ancestry (repair_ancestry term) = .Pass := by
  sorry

/-- Budget repair zeroes cost. -/
theorem repair_budget_passes (term : ActionTerm) :
    check_budget (repair_budget term) = .Pass := by
  sorry

/-- Repair is idempotent: applying twice = applying once. -/
theorem repair_integrity_idempotent (term : ActionTerm) (required : IntegLevel) :
    repair_integrity (repair_integrity term required) required =
    repair_integrity term required := by
  sorry

theorem repair_budget_idempotent (term : ActionTerm) :
    repair_budget (repair_budget term) = repair_budget term := by
  sorry

-- ═══════════════════════════════════════════════════════════════════════════
-- Layer 2: Galois connection — composability
-- ═══════════════════════════════════════════════════════════════════════════

/-- Repairs for disjoint checks commute: order doesn't matter.
    Integrity repair touches artifactIntegrity; budget repair touches
    costMicroUsd. They modify disjoint fields. -/
theorem repair_integrity_budget_commute (term : ActionTerm) (required : IntegLevel) :
    repair_integrity (repair_budget term) required =
    repair_budget (repair_integrity term required) := by
  sorry

/-- Integrity repair preserves budget check result (disjoint fields). -/
theorem repair_integrity_preserves_budget (term : ActionTerm) (required : IntegLevel) :
    check_budget (repair_integrity term required) = check_budget term := by
  sorry

/-- Budget repair preserves integrity check result (disjoint fields). -/
theorem repair_budget_preserves_integrity (term : ActionTerm) (required : IntegLevel) :
    check_integrity (repair_budget term) required = check_integrity term required := by
  sorry

-- ═══════════════════════════════════════════════════════════════════════════
-- Layer 3: Discharge determinism
-- ═══════════════════════════════════════════════════════════════════════════

/-- Discharge is deterministic: same term, same check → same result. -/
theorem discharge_deterministic (term : ActionTerm) (required : IntegLevel) :
    check_integrity term required = check_integrity term required := by
  rfl

/-- The only non-sorry theorem: trivially true by reflexivity.
    Included to show the pattern for completed proofs. -/
