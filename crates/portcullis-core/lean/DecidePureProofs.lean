/-!
# Lean 4 Proofs for decide_pure() — the Kernel Decision Logic

Proves correctness properties of the pure lattice-based decision function
that forms the core of `Kernel::decide()`. This is the security-critical
path: given a capability level, exposure state, and operation, determine
the verdict (Allow / DenyCapability / RequiresApproval / GateExfil).

## Model correspondence

Hand-written Lean model mirroring `portcullis-core/src/lib.rs:959`.
NOT Aeneas-generated — Aeneas cannot translate `==` on enums or the
`should_gate` function (which uses `bool` fields and `Option` returns).

## What's proved (all kernel-checked, no proof holes)

- **Never always denies**: regardless of exposure or operation
- **LowRisk always requires approval**: regardless of exposure or operation
- **Allow only on Always + no gate**: the ONLY path to Allow
- **Monotonicity**: tightening capability can only increase restriction
- **Verdict exhaustiveness**: every input produces exactly one verdict
- **Gate soundness**: GateExfil only fires when should_gate is true
-/

-- Re-use ExposureProofs types (ExposureSet, Operation, should_gate, etc.)
-- and PortcullisCoreBridge types (CapabilityLevel)

namespace DecidePureProofs

-- ═══════════════════════════════════════════════════════════════════════
-- Types (mirroring portcullis-core/src/lib.rs)
-- ═══════════════════════════════════════════════════════════════════════

inductive CapabilityLevel where | Never | LowRisk | Always
deriving DecidableEq, Repr

inductive PureVerdict where | Allow | DenyCapability | RequiresApproval | GateExfil
deriving DecidableEq, Repr

-- Redefine the exposure types inline (self-contained proof file)
structure ExposureSet where
  private_data : Bool
  untrusted_content : Bool
  exfil_vector : Bool
deriving DecidableEq

inductive Operation where
  | ReadFiles | WriteFiles | EditFiles | RunBash
  | GlobSearch | GrepSearch | WebSearch | WebFetch
  | GitCommit | GitPush | CreatePr | ManagePods
  | SpawnAgent
deriving DecidableEq

-- ═══════════════════════════════════════════════════════════════════════
-- Functions (mirroring portcullis-core/src/lib.rs)
-- ═══════════════════════════════════════════════════════════════════════

def ExposureSet.is_uninhabitable (s : ExposureSet) : Bool :=
  s.private_data && s.untrusted_content && s.exfil_vector

def classify_exfil (op : Operation) : Bool :=
  match op with
  | .RunBash | .GitPush | .CreatePr | .SpawnAgent => true
  | _ => false

def project_exposure (current : ExposureSet) (op : Operation) : ExposureSet :=
  match op with
  | .ReadFiles | .GlobSearch | .GrepSearch =>
    { current with private_data := true }
  | .WebFetch | .WebSearch =>
    { current with untrusted_content := true }
  | .RunBash | .GitPush | .CreatePr | .SpawnAgent =>
    { current with exfil_vector := true }
  | _ => current

def should_gate (current : ExposureSet) (op : Operation) : Bool :=
  let projected := project_exposure current op
  (current.is_uninhabitable || projected.is_uninhabitable) && classify_exfil op

/-- The pure decision function — mirrors Rust decide_pure(). -/
def decide_pure (level : CapabilityLevel) (exposure : ExposureSet) (op : Operation) : PureVerdict :=
  if level == .Never then .DenyCapability
  else if level == .LowRisk then .RequiresApproval
  else if should_gate exposure op then .GateExfil
  else .Allow

-- ═══════════════════════════════════════════════════════════════════════
-- Core safety theorems
-- ═══════════════════════════════════════════════════════════════════════

/-- Never ALWAYS produces DenyCapability, regardless of exposure or operation. -/
theorem never_always_denies (exposure : ExposureSet) (op : Operation) :
    decide_pure .Never exposure op = .DenyCapability := by
  simp [decide_pure]

/-- LowRisk ALWAYS produces RequiresApproval, regardless of exposure or operation. -/
theorem lowrisk_always_requires_approval (exposure : ExposureSet) (op : Operation) :
    decide_pure .LowRisk exposure op = .RequiresApproval := by
  simp [decide_pure]

/-- Allow is ONLY reachable when level is Always AND should_gate is false.
    This is the key safety property: there is exactly ONE path to Allow. -/
theorem allow_requires_always_and_no_gate (exposure : ExposureSet) (op : Operation) :
    decide_pure .Always exposure op = .Allow ↔ should_gate exposure op = false := by
  simp [decide_pure]

/-- GateExfil fires if and only if level is Always and should_gate is true. -/
theorem gate_exfil_iff (exposure : ExposureSet) (op : Operation) :
    decide_pure .Always exposure op = .GateExfil ↔ should_gate exposure op = true := by
  simp [decide_pure]

-- ═══════════════════════════════════════════════════════════════════════
-- Monotonicity — tightening capability only increases restriction
-- ═══════════════════════════════════════════════════════════════════════

/-- Ordering on verdicts: Allow is least restrictive, DenyCapability most. -/
def PureVerdict.restriction : PureVerdict → Nat
  | .Allow => 0
  | .GateExfil => 1
  | .RequiresApproval => 2
  | .DenyCapability => 3

/-- Tightening from Always to LowRisk can only increase restriction. -/
theorem always_to_lowrisk_monotone (exposure : ExposureSet) (op : Operation) :
    (decide_pure .Always exposure op).restriction ≤
    (decide_pure .LowRisk exposure op).restriction := by
  simp [decide_pure, PureVerdict.restriction]
  cases should_gate exposure op <;> decide

/-- Tightening from LowRisk to Never can only increase restriction. -/
theorem lowrisk_to_never_monotone (exposure : ExposureSet) (op : Operation) :
    (decide_pure .LowRisk exposure op).restriction ≤
    (decide_pure .Never exposure op).restriction := by
  simp [decide_pure, PureVerdict.restriction]

/-- Tightening from Always to Never can only increase restriction. -/
theorem always_to_never_monotone (exposure : ExposureSet) (op : Operation) :
    (decide_pure .Always exposure op).restriction ≤
    (decide_pure .Never exposure op).restriction := by
  simp [decide_pure, PureVerdict.restriction]
  cases should_gate exposure op <;> decide

/-- Full monotonicity: for any two levels where a ≤ b (tighter),
    the verdict for b is at least as restrictive as for a. -/
theorem decide_monotone (a b : CapabilityLevel) (exposure : ExposureSet) (op : Operation)
    (h : a = .Always ∨ (a = .LowRisk ∧ (b = .LowRisk ∨ b = .Never)) ∨ (a = .Never ∧ b = .Never)) :
    (decide_pure a exposure op).restriction ≤ (decide_pure b exposure op).restriction := by
  rcases h with rfl | ⟨rfl, rfl | rfl⟩ | ⟨rfl, rfl⟩
  · -- a = Always: need to show Always ≤ b for any b
    -- This requires knowing b. Since a=Always, any b works.
    -- But we need b. The hypothesis doesn't constrain b when a=Always.
    -- For a=Always, verdict is Allow or GateExfil (restriction 0 or 1).
    -- For any b, verdict restriction is 0-3. Always true.
    cases b <;> simp [decide_pure, PureVerdict.restriction] <;> cases should_gate exposure op <;> decide
  · -- a = LowRisk, b = LowRisk: trivially ≤
    exact Nat.le_refl _
  · -- a = LowRisk, b = Never: RequiresApproval (2) ≤ DenyCapability (3)
    simp [decide_pure, PureVerdict.restriction]
  · -- a = Never, b = Never: trivially ≤
    exact Nat.le_refl _

-- ═══════════════════════════════════════════════════════════════════════
-- Exhaustiveness — every input produces exactly one verdict
-- ═══════════════════════════════════════════════════════════════════════

/-- decide_pure always returns one of the four verdicts. -/
theorem decide_pure_exhaustive (level : CapabilityLevel) (exposure : ExposureSet) (op : Operation) :
    decide_pure level exposure op = .Allow ∨
    decide_pure level exposure op = .DenyCapability ∨
    decide_pure level exposure op = .RequiresApproval ∨
    decide_pure level exposure op = .GateExfil := by
  cases level <;> simp [decide_pure] <;> cases should_gate exposure op <;> simp

-- ═══════════════════════════════════════════════════════════════════════
-- Gate soundness — GateExfil only fires when uninhabitable + exfil
-- ═══════════════════════════════════════════════════════════════════════

/-- Empty exposure never triggers the gate, for any operation. -/
theorem empty_exposure_no_gate (level : CapabilityLevel) (op : Operation) :
    decide_pure level ⟨false, false, false⟩ op ≠ .GateExfil := by
  cases level <;> simp [decide_pure, should_gate, project_exposure,
    ExposureSet.is_uninhabitable, classify_exfil]
  cases op <;> decide

/-- Non-exfil operations never trigger the gate, regardless of exposure. -/
theorem non_exfil_no_gate (level : CapabilityLevel) (exposure : ExposureSet) :
    decide_pure level exposure .ReadFiles ≠ .GateExfil ∧
    decide_pure level exposure .WebFetch ≠ .GateExfil ∧
    decide_pure level exposure .WriteFiles ≠ .GateExfil := by
  cases level <;> simp [decide_pure, should_gate, project_exposure,
    ExposureSet.is_uninhabitable, classify_exfil]
  all_goals (cases exposure with | mk pd uc ev => cases pd <;> cases uc <;> cases ev <;> decide)

end DecidePureProofs
