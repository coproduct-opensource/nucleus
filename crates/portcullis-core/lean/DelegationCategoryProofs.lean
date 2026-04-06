/-!
# Delegation Category Proofs — Free Category Structure (#1112)

Proves that delegation narrowing (pointwise min) forms a category:
- Associativity: compose(compose(a,b),c) = compose(a,compose(b,c))
- Identity: compose(identity, a) = a and compose(a, identity) = a
- Commutativity, idempotency, deflationary property

Standalone file — does not import DelegationProofs.lean to avoid
version-sensitive tactic compatibility issues.

All theorems kernel-checked — no sorry.
-/

-- ═══════════════════════════════════════════════════════════════════════════
-- Constraints model (same as DelegationProofs but self-contained)
-- ═══════════════════════════════════════════════════════════════════════════

structure Constraints where
  scope_size : Nat
  max_depth : Nat
  expires_at : Nat
  deriving DecidableEq, Repr

/-- Compose: pointwise min (the morphism composition). -/
def compose (a b : Constraints) : Constraints :=
  ⟨min a.scope_size b.scope_size,
   min a.max_depth b.max_depth,
   min a.expires_at b.expires_at⟩

/-- Identity: unconstrained delegation. -/
def identity (M : Nat) : Constraints := ⟨M, M, M⟩

-- ═══════════════════════════════════════════════════════════════════════════
-- Category axioms
-- ═══════════════════════════════════════════════════════════════════════════

/-- Associativity: compose(compose(a,b),c) = compose(a,compose(b,c)). -/
theorem compose_assoc (a b c : Constraints) :
    compose (compose a b) c = compose a (compose b c) := by
  simp [compose, Nat.min_assoc]

/-- Left identity: compose(identity M, a) = a when a ≤ M. -/
theorem compose_id_left (a : Constraints) (M : Nat)
    (hs : a.scope_size ≤ M) (hd : a.max_depth ≤ M) (he : a.expires_at ≤ M) :
    compose (identity M) a = a := by
  simp [compose, identity, Nat.min_eq_right hs, Nat.min_eq_right hd, Nat.min_eq_right he]

/-- Right identity: compose(a, identity M) = a when a ≤ M. -/
theorem compose_id_right (a : Constraints) (M : Nat)
    (hs : a.scope_size ≤ M) (hd : a.max_depth ≤ M) (he : a.expires_at ≤ M) :
    compose a (identity M) = a := by
  simp [compose, identity, Nat.min_eq_left hs, Nat.min_eq_left hd, Nat.min_eq_left he]

-- ═══════════════════════════════════════════════════════════════════════════
-- Additional categorical properties
-- ═══════════════════════════════════════════════════════════════════════════

/-- Commutativity: compose(a, b) = compose(b, a). -/
theorem compose_comm (a b : Constraints) :
    compose a b = compose b a := by
  simp [compose, Nat.min_comm]

/-- Idempotency: compose(a, a) = a. -/
theorem compose_idempotent (a : Constraints) :
    compose a a = a := by
  simp [compose]

/-- Self-narrowing is identity (matches DelegationProofs.narrow_self). -/
theorem compose_self_eq (a : Constraints) :
    compose a a = a := compose_idempotent a

/-- Deflationary: compose(a, b).scope_size ≤ a.scope_size. -/
theorem compose_deflationary_scope (a b : Constraints) :
    (compose a b).scope_size ≤ a.scope_size := by
  simp [compose]
  exact Nat.min_le_left _ _

/-- Deflationary: compose(a, b).max_depth ≤ a.max_depth. -/
theorem compose_deflationary_depth (a b : Constraints) :
    (compose a b).max_depth ≤ a.max_depth := by
  simp [compose]
  exact Nat.min_le_left _ _

/-- Deflationary: compose(a, b).expires_at ≤ a.expires_at. -/
theorem compose_deflationary_expiry (a b : Constraints) :
    (compose a b).expires_at ≤ a.expires_at := by
  simp [compose]
  exact Nat.min_le_left _ _
