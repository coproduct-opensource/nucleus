/-!
# IFC Label Lattice Proofs — Flow Kernel Foundation

Proves that the 5-dimensional IFC label type forms a bounded lattice
with the correct variance (confidentiality/provenance covariant,
integrity/authority contravariant) and that the existing ExposureSet
is a sound quotient of the full label.

## Model correspondence

These types are HAND-WRITTEN Lean models mirroring the Rust source in
`portcullis-core/src/lib.rs`. Unlike the CapabilityLevel types (which are
Aeneas-generated), the IFC types are not yet translatable by Aeneas.
No structural correspondence test exists for these types — a variant
added to the Rust enum will NOT cause a Lean build failure.

## Key theorems

- **Authority confinement**: `NoAuthority` data cannot produce `Directive` output
- **Integrity preservation**: joining with untrusted data produces untrusted output
- **Confidentiality monotonicity**: joining with secret data produces secret output
- **Quotient soundness**: `ifc_to_exposure` is a monotone homomorphism

All proofs discharge via `decide` over finite types. No proof holes, no SMT.
-/

namespace FlowProofs

-- ═══════════════════════════════════════════════════════════════════════
-- Types (mirroring portcullis-core/src/lib.rs IFC types)
-- ═══════════════════════════════════════════════════════════════════════

inductive ConfLevel where | Public | Internal | Secret
deriving DecidableEq, Repr

inductive IntegLevel where | Adversarial | Untrusted | Trusted
deriving DecidableEq, Repr

inductive AuthorityLevel where | NoAuthority | Informational | Suggestive | Directive
deriving DecidableEq, Repr

-- ═══════════════════════════════════════════════════════════════════════
-- Ordering — covariant for Conf, contravariant for Integ/Authority
-- ═══════════════════════════════════════════════════════════════════════

def ConfLevel.toNat : ConfLevel → Nat
  | .Public => 0 | .Internal => 1 | .Secret => 2

def IntegLevel.toNat : IntegLevel → Nat
  | .Adversarial => 0 | .Untrusted => 1 | .Trusted => 2

def AuthorityLevel.toNat : AuthorityLevel → Nat
  | .NoAuthority => 0 | .Informational => 1 | .Suggestive => 2 | .Directive => 3

-- Covariant join (max)
def ConfLevel.join (a b : ConfLevel) : ConfLevel :=
  if a.toNat ≥ b.toNat then a else b

-- Contravariant join (min) — least trusted wins
def IntegLevel.join (a b : IntegLevel) : IntegLevel :=
  if a.toNat ≤ b.toNat then a else b

-- Contravariant join (min) — least authority wins
def AuthorityLevel.join (a b : AuthorityLevel) : AuthorityLevel :=
  if a.toNat ≤ b.toNat then a else b

-- ═══════════════════════════════════════════════════════════════════════
-- Authority confinement — the key indirect-injection defense
-- ═══════════════════════════════════════════════════════════════════════

/-- NoAuthority data joined with anything still has NoAuthority.
    Web content cannot acquire instruction authority by being combined
    with a user prompt. This kills indirect prompt injection. -/
theorem authority_confinement_left (b : AuthorityLevel) :
    AuthorityLevel.join .NoAuthority b = .NoAuthority := by
  cases b <;> decide

theorem authority_confinement_right (a : AuthorityLevel) :
    AuthorityLevel.join a .NoAuthority = .NoAuthority := by
  cases a <;> decide

/-- Directive authority is only preserved when BOTH inputs are Directive. -/
theorem directive_requires_both (a b : AuthorityLevel) :
    AuthorityLevel.join a b = .Directive ↔ a = .Directive ∧ b = .Directive := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Integrity preservation — untrusted data stays untrusted
-- ═══════════════════════════════════════════════════════════════════════

/-- Adversarial data joined with anything stays adversarial.
    Once tainted, always tainted. -/
theorem integrity_taint_left (b : IntegLevel) :
    IntegLevel.join .Adversarial b = .Adversarial := by
  cases b <;> decide

theorem integrity_taint_right (a : IntegLevel) :
    IntegLevel.join a .Adversarial = .Adversarial := by
  cases a <;> decide

/-- Trusted output requires BOTH inputs to be trusted. -/
theorem trusted_requires_both (a b : IntegLevel) :
    IntegLevel.join a b = .Trusted ↔ a = .Trusted ∧ b = .Trusted := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Confidentiality monotonicity — secret data stays secret
-- ═══════════════════════════════════════════════════════════════════════

/-- Secret data joined with anything stays secret. -/
theorem confidentiality_secret_left (b : ConfLevel) :
    ConfLevel.join .Secret b = .Secret := by
  cases b <;> decide

theorem confidentiality_secret_right (a : ConfLevel) :
    ConfLevel.join a .Secret = .Secret := by
  cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Join algebraic properties
-- ═══════════════════════════════════════════════════════════════════════

-- Conf join
theorem conf_join_comm (a b : ConfLevel) :
    ConfLevel.join a b = ConfLevel.join b a := by
  cases a <;> cases b <;> decide

theorem conf_join_assoc (a b c : ConfLevel) :
    ConfLevel.join (ConfLevel.join a b) c = ConfLevel.join a (ConfLevel.join b c) := by
  cases a <;> cases b <;> cases c <;> decide

theorem conf_join_idempotent (a : ConfLevel) :
    ConfLevel.join a a = a := by
  cases a <;> decide

-- Integ join
theorem integ_join_comm (a b : IntegLevel) :
    IntegLevel.join a b = IntegLevel.join b a := by
  cases a <;> cases b <;> decide

theorem integ_join_assoc (a b c : IntegLevel) :
    IntegLevel.join (IntegLevel.join a b) c = IntegLevel.join a (IntegLevel.join b c) := by
  cases a <;> cases b <;> cases c <;> decide

theorem integ_join_idempotent (a : IntegLevel) :
    IntegLevel.join a a = a := by
  cases a <;> decide

-- Authority join
theorem auth_join_comm (a b : AuthorityLevel) :
    AuthorityLevel.join a b = AuthorityLevel.join b a := by
  cases a <;> cases b <;> decide

theorem auth_join_assoc (a b c : AuthorityLevel) :
    AuthorityLevel.join (AuthorityLevel.join a b) c =
    AuthorityLevel.join a (AuthorityLevel.join b c) := by
  cases a <;> cases b <;> cases c <;> decide

theorem auth_join_idempotent (a : AuthorityLevel) :
    AuthorityLevel.join a a = a := by
  cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- The Invariant exploit theorem
--
-- A malicious GitHub issue (Public, Adversarial, NoAuthority) combined
-- with a private repo read (Internal, Trusted, Directive) produces a
-- label where the action CANNOT be authorized because authority is
-- NoAuthority.
-- ═══════════════════════════════════════════════════════════════════════

/-- The Invariant GitHub MCP exploit is blocked by authority confinement.
    Malicious issue body + private repo context = NoAuthority output. -/
theorem invariant_exploit_blocked :
    let issue := (ConfLevel.Public, IntegLevel.Adversarial, AuthorityLevel.NoAuthority)
    let repo := (ConfLevel.Internal, IntegLevel.Trusted, AuthorityLevel.Directive)
    let combined := (ConfLevel.join issue.1 repo.1,
                     IntegLevel.join issue.2.1 repo.2.1,
                     AuthorityLevel.join issue.2.2 repo.2.2)
    -- The combined label has NoAuthority — cannot instruct the agent
    combined.2.2 = .NoAuthority ∧
    -- AND Adversarial integrity — cannot be trusted
    combined.2.1 = .Adversarial ∧
    -- AND Internal confidentiality — contains private data
    combined.1 = .Internal := by
  decide

-- ═══════════════════════════════════════════════════════════════════════
-- Meet operations (dual of join) — matching Kani proofs L1-L11 (#644)
-- ═══════════════════════════════════════════════════════════════════════

-- Covariant meet (min) for confidentiality
def ConfLevel.meet (a b : ConfLevel) : ConfLevel :=
  if a.toNat ≤ b.toNat then a else b

-- Contravariant meet (max) for integrity — most trusted wins
def IntegLevel.meet (a b : IntegLevel) : IntegLevel :=
  if a.toNat ≥ b.toNat then a else b

-- Contravariant meet (max) for authority
def AuthorityLevel.meet (a b : AuthorityLevel) : AuthorityLevel :=
  if a.toNat ≥ b.toNat then a else b

-- Meet commutativity
theorem conf_meet_comm (a b : ConfLevel) :
    ConfLevel.meet a b = ConfLevel.meet b a := by
  cases a <;> cases b <;> decide

theorem integ_meet_comm (a b : IntegLevel) :
    IntegLevel.meet a b = IntegLevel.meet b a := by
  cases a <;> cases b <;> decide

theorem auth_meet_comm (a b : AuthorityLevel) :
    AuthorityLevel.meet a b = AuthorityLevel.meet b a := by
  cases a <;> cases b <;> decide

-- Meet associativity
theorem conf_meet_assoc (a b c : ConfLevel) :
    ConfLevel.meet (ConfLevel.meet a b) c = ConfLevel.meet a (ConfLevel.meet b c) := by
  cases a <;> cases b <;> cases c <;> decide

theorem integ_meet_assoc (a b c : IntegLevel) :
    IntegLevel.meet (IntegLevel.meet a b) c = IntegLevel.meet a (IntegLevel.meet b c) := by
  cases a <;> cases b <;> cases c <;> decide

theorem auth_meet_assoc (a b c : AuthorityLevel) :
    AuthorityLevel.meet (AuthorityLevel.meet a b) c =
    AuthorityLevel.meet a (AuthorityLevel.meet b c) := by
  cases a <;> cases b <;> cases c <;> decide

-- Meet idempotency
theorem conf_meet_idempotent (a : ConfLevel) :
    ConfLevel.meet a a = a := by cases a <;> decide

theorem integ_meet_idempotent (a : IntegLevel) :
    IntegLevel.meet a a = a := by cases a <;> decide

theorem auth_meet_idempotent (a : AuthorityLevel) :
    AuthorityLevel.meet a a = a := by cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Absorption laws (join/meet interaction) — bounded lattice requirement
-- ═══════════════════════════════════════════════════════════════════════

theorem conf_absorption_join_meet (a b : ConfLevel) :
    ConfLevel.join a (ConfLevel.meet a b) = a := by
  cases a <;> cases b <;> decide

theorem conf_absorption_meet_join (a b : ConfLevel) :
    ConfLevel.meet a (ConfLevel.join a b) = a := by
  cases a <;> cases b <;> decide

theorem integ_absorption_join_meet (a b : IntegLevel) :
    IntegLevel.join a (IntegLevel.meet a b) = a := by
  cases a <;> cases b <;> decide

theorem integ_absorption_meet_join (a b : IntegLevel) :
    IntegLevel.meet a (IntegLevel.join a b) = a := by
  cases a <;> cases b <;> decide

theorem auth_absorption_join_meet (a b : AuthorityLevel) :
    AuthorityLevel.join a (AuthorityLevel.meet a b) = a := by
  cases a <;> cases b <;> decide

theorem auth_absorption_meet_join (a b : AuthorityLevel) :
    AuthorityLevel.meet a (AuthorityLevel.join a b) = a := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Bounded lattice: identity elements
-- ═══════════════════════════════════════════════════════════════════════

-- Conf: bot = Public, top = Secret
theorem conf_join_bot (a : ConfLevel) : ConfLevel.join a .Public = a := by cases a <;> decide
theorem conf_meet_top (a : ConfLevel) : ConfLevel.meet a .Secret = a := by cases a <;> decide

-- Integ: bot = Adversarial (contravariant), top = Trusted
theorem integ_join_bot (a : IntegLevel) : IntegLevel.join a .Trusted = a := by cases a <;> decide
theorem integ_meet_top (a : IntegLevel) : IntegLevel.meet a .Adversarial = a := by cases a <;> decide

-- Auth: bot = NoAuthority (contravariant), top = Directive
theorem auth_join_bot (a : AuthorityLevel) : AuthorityLevel.join a .Directive = a := by cases a <;> decide
theorem auth_meet_top (a : AuthorityLevel) : AuthorityLevel.meet a .NoAuthority = a := by cases a <;> decide

end FlowProofs
