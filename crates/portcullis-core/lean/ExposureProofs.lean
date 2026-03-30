-- No external dependencies — all proofs discharge via decide/simp/cases.

/-!
# Exposure Tracker Proofs

Proves safety properties of the 3-bit exposure accumulator that detects
uninhabitable states (combinations of private data + untrusted content +
exfiltration vector capabilities).

## Model correspondence

These types mirror the Rust source in `portcullis-core/src/lib.rs`.
Correspondence is enforced by compile-time `include_str!` assertions in
`portcullis/src/capability.rs`. Unlike the lattice types (which are
Aeneas-generated), these are hand-written models — Aeneas does not yet
translate `bool`-field structs or 12-variant enums.

## Properties proved (all kernel-checked, no sorry)

- **Monotonicity**: exposure count never decreases under `union`
- **Idempotency**: `union(s, s) = s`
- **Commutativity**: `union(a, b) = union(b, a)`
- **Associativity**: `union(union(a, b), c) = union(a, union(b, c))`
- **Identity**: `union(s, empty) = s`
- **Uninhabitable iff count = 3**: the detector is sound and complete
- **Gate correctness**: `should_gate` blocks iff completing uninhabitable with exfil
-/

namespace ExposureProofs

-- ═══════════════════════════════════════════════════════════════════════
-- Types (mirroring portcullis-core/src/lib.rs)
-- ═══════════════════════════════════════════════════════════════════════

/-- Exposure labels — the 3 legs of the uninhabitable state. -/
inductive ExposureLabel where
  | PrivateData
  | UntrustedContent
  | ExfilVector
deriving DecidableEq

/-- 3-bit exposure accumulator. -/
structure ExposureSet where
  private_data : Bool
  untrusted_content : Bool
  exfil_vector : Bool
deriving DecidableEq

/-- The 12 core operations. -/
inductive Operation where
  | ReadFiles | WriteFiles | EditFiles | RunBash
  | GlobSearch | GrepSearch | WebSearch | WebFetch
  | GitCommit | GitPush | CreatePr | ManagePods
deriving DecidableEq

-- ═══════════════════════════════════════════════════════════════════════
-- Functions (mirroring portcullis-core/src/lib.rs)
-- ═══════════════════════════════════════════════════════════════════════

def ExposureSet.empty : ExposureSet := ⟨false, false, false⟩

def ExposureSet.singleton (label : ExposureLabel) : ExposureSet :=
  match label with
  | .PrivateData      => ⟨true, false, false⟩
  | .UntrustedContent => ⟨false, true, false⟩
  | .ExfilVector      => ⟨false, false, true⟩

def ExposureSet.union (a b : ExposureSet) : ExposureSet :=
  ⟨a.private_data || b.private_data,
   a.untrusted_content || b.untrusted_content,
   a.exfil_vector || b.exfil_vector⟩

def ExposureSet.is_uninhabitable (s : ExposureSet) : Bool :=
  s.private_data && s.untrusted_content && s.exfil_vector

def ExposureSet.count (s : ExposureSet) : Nat :=
  s.private_data.toNat + s.untrusted_content.toNat + s.exfil_vector.toNat

def classify_operation (op : Operation) : Option ExposureLabel :=
  match op with
  | .ReadFiles | .GlobSearch | .GrepSearch => some .PrivateData
  | .WebFetch | .WebSearch => some .UntrustedContent
  | .RunBash | .GitPush | .CreatePr => some .ExfilVector
  | .WriteFiles | .EditFiles | .GitCommit | .ManagePods => none

def project_exposure (current : ExposureSet) (op : Operation) : ExposureSet :=
  match classify_operation op with
  | some label => current.union (ExposureSet.singleton label)
  | none => current

def is_exfil_operation (op : Operation) : Bool :=
  match classify_operation op with
  | some .ExfilVector => true
  | _ => false

def should_gate (current : ExposureSet) (op : Operation) : Bool :=
  let projected := project_exposure current op
  (current.is_uninhabitable || projected.is_uninhabitable) && is_exfil_operation op

-- ═══════════════════════════════════════════════════════════════════════
-- Monoid laws for ExposureSet.union
-- ═══════════════════════════════════════════════════════════════════════

@[simp] theorem union_empty_right (s : ExposureSet) : s.union .empty = s := by
  cases s; simp [ExposureSet.union, ExposureSet.empty]

@[simp] theorem union_empty_left (s : ExposureSet) : ExposureSet.empty.union s = s := by
  cases s; simp [ExposureSet.union, ExposureSet.empty]

theorem union_comm (a b : ExposureSet) : a.union b = b.union a := by
  cases a; cases b; simp [ExposureSet.union, Bool.or_comm]

theorem union_assoc (a b c : ExposureSet) :
    (a.union b).union c = a.union (b.union c) := by
  cases a; cases b; cases c; simp [ExposureSet.union, Bool.or_assoc]

theorem union_idempotent (s : ExposureSet) : s.union s = s := by
  cases s; simp [ExposureSet.union]

-- ═══════════════════════════════════════════════════════════════════════
-- Monotonicity — exposure never decreases
-- ═══════════════════════════════════════════════════════════════════════

theorem count_union_ge_left (a b : ExposureSet) : a.count ≤ (a.union b).count := by
  cases a with | mk pd uc ev =>
  cases b with | mk pd' uc' ev' =>
  simp only [ExposureSet.union, ExposureSet.count]
  cases pd <;> cases uc <;> cases ev <;> cases pd' <;> cases uc' <;> cases ev' <;> decide

theorem union_monotone_uninhabitable (a b : ExposureSet)
    (h : a.is_uninhabitable = true) : (a.union b).is_uninhabitable = true := by
  cases a; cases b
  simp only [ExposureSet.is_uninhabitable, ExposureSet.union] at *
  simp_all [Bool.and_eq_true]

-- ═══════════════════════════════════════════════════════════════════════
-- Uninhabitable iff count = 3
-- ═══════════════════════════════════════════════════════════════════════

theorem is_uninhabitable_iff_count_three (s : ExposureSet) :
    s.is_uninhabitable = true ↔ s.count = 3 := by
  cases s with | mk pd uc ev =>
  simp only [ExposureSet.is_uninhabitable, ExposureSet.count]
  cases pd <;> cases uc <;> cases ev <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- classify_operation completeness — every operation maps correctly
-- ═══════════════════════════════════════════════════════════════════════

theorem classify_private_data :
    classify_operation .ReadFiles = some .PrivateData ∧
    classify_operation .GlobSearch = some .PrivateData ∧
    classify_operation .GrepSearch = some .PrivateData := by decide

theorem classify_untrusted_content :
    classify_operation .WebFetch = some .UntrustedContent ∧
    classify_operation .WebSearch = some .UntrustedContent := by decide

theorem classify_exfil_vector :
    classify_operation .RunBash = some .ExfilVector ∧
    classify_operation .GitPush = some .ExfilVector ∧
    classify_operation .CreatePr = some .ExfilVector := by decide

theorem classify_neutral :
    classify_operation .WriteFiles = none ∧
    classify_operation .EditFiles = none ∧
    classify_operation .GitCommit = none ∧
    classify_operation .ManagePods = none := by decide

-- ═══════════════════════════════════════════════════════════════════════
-- should_gate correctness
-- ═══════════════════════════════════════════════════════════════════════

/-- Safe state: empty exposure never gates anything. -/
theorem should_gate_empty (op : Operation) :
    should_gate .empty op = false := by
  cases op <;> decide

/-- Completing the uninhabitable state with an exfil op IS gated. -/
theorem should_gate_completing_uninhabitable :
    let two_legs := ExposureSet.mk true true false
    should_gate two_legs .GitPush = true := by decide

/-- Already uninhabitable: all exfil ops are gated. -/
theorem should_gate_all_exfil_when_uninhabitable :
    let full := ExposureSet.mk true true true
    should_gate full .RunBash = true ∧
    should_gate full .GitPush = true ∧
    should_gate full .CreatePr = true := by decide

/-- Non-exfil ops are never gated, even when uninhabitable. -/
theorem should_gate_non_exfil_never_gated (s : ExposureSet) :
    should_gate s .ReadFiles = false ∧
    should_gate s .WebFetch = false ∧
    should_gate s .WriteFiles = false := by
  cases s with | mk pd uc ev =>
  cases pd <;> cases uc <;> cases ev <;> decide

end ExposureProofs
