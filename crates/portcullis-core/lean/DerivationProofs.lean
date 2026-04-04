/-!
# DerivationClass Lattice Proofs — DPI Formal Invariants

Proves that the DerivationClass diamond lattice satisfies the Data
Provenance Integrity (DPI) invariants:

1. **No silent cleansing**: `join(AIDerived, x) != Deterministic` for all x
2. **Monotone join**: `taint_level(join(a, b)) >= max(taint_level(a), taint_level(b))`

## Model correspondence

These types are HAND-WRITTEN Lean models mirroring the Rust source in
`portcullis-core/src/lib.rs`. The diamond lattice:

```text
      OpaqueExternal  (top)
           |
         Mixed
        /     \
  AIDerived  HumanPromoted
        \     /
      Deterministic  (bottom)
```

## Key theorems

- **join_comm**: join is commutative
- **join_assoc**: join is associative
- **join_idempotent**: join is idempotent
- **no_silent_cleansing**: AIDerived.join(x) != Deterministic for all x
- **join_monotone**: join result >= both inputs in taint ordering

All proofs discharge via `decide` over finite types. Fully kernel-checked, no SMT.
-/

namespace DerivationProofs

-- ═══════════════════════════════════════════════════════════════════════
-- DerivationClass (mirroring portcullis-core/src/lib.rs)
-- ═══════════════════════════════════════════════════════════════════════

inductive DerivationClass where
  | Deterministic
  | AIDerived
  | Mixed
  | HumanPromoted
  | OpaqueExternal
deriving DecidableEq, Repr

-- ═══════════════════════════════════════════════════════════════════════
-- Join — least upper bound in the diamond lattice
-- ═══════════════════════════════════════════════════════════════════════

/-- Join (least upper bound) matching the Rust implementation exactly.
    Deterministic is bottom, OpaqueExternal is top, incomparable elements
    (AIDerived, HumanPromoted) join to Mixed. -/
def DerivationClass.join (a b : DerivationClass) : DerivationClass :=
  match a, b with
  -- Deterministic is bottom — identity for join
  | .Deterministic, x => x
  | x, .Deterministic => x
  -- OpaqueExternal is top — absorbs everything
  | .OpaqueExternal, _ => .OpaqueExternal
  | _, .OpaqueExternal => .OpaqueExternal
  -- Same class: idempotent
  | .AIDerived, .AIDerived => .AIDerived
  | .HumanPromoted, .HumanPromoted => .HumanPromoted
  | .Mixed, .Mixed => .Mixed
  -- Different non-bottom, non-top classes -> Mixed
  | _, _ => .Mixed

-- ═══════════════════════════════════════════════════════════════════════
-- Taint level — height in the Hasse diagram
-- ═══════════════════════════════════════════════════════════════════════

/-- Map each variant to its height in the Hasse diagram.
    Deterministic = 0, AIDerived = HumanPromoted = 1, Mixed = 2, OpaqueExternal = 3. -/
def DerivationClass.taintLevel : DerivationClass → Nat
  | .Deterministic => 0
  | .AIDerived => 1
  | .HumanPromoted => 1
  | .Mixed => 2
  | .OpaqueExternal => 3

-- ═══════════════════════════════════════════════════════════════════════
-- Lattice algebraic properties
-- ═══════════════════════════════════════════════════════════════════════

/-- Join is commutative: a join b = b join a. -/
theorem join_comm (a b : DerivationClass) :
    DerivationClass.join a b = DerivationClass.join b a := by
  cases a <;> cases b <;> decide

/-- Join is associative: (a join b) join c = a join (b join c). -/
theorem join_assoc (a b c : DerivationClass) :
    DerivationClass.join (DerivationClass.join a b) c =
    DerivationClass.join a (DerivationClass.join b c) := by
  cases a <;> cases b <;> cases c <;> decide

/-- Join is idempotent: a join a = a. -/
theorem join_idempotent (a : DerivationClass) :
    DerivationClass.join a a = a := by
  cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Bottom and top identity
-- ═══════════════════════════════════════════════════════════════════════

/-- Deterministic is the identity for join (bottom element). -/
theorem join_deterministic_left (a : DerivationClass) :
    DerivationClass.join .Deterministic a = a := by
  cases a <;> decide

theorem join_deterministic_right (a : DerivationClass) :
    DerivationClass.join a .Deterministic = a := by
  cases a <;> decide

/-- OpaqueExternal absorbs everything in join (top element). -/
theorem join_opaque_left (a : DerivationClass) :
    DerivationClass.join .OpaqueExternal a = .OpaqueExternal := by
  cases a <;> decide

theorem join_opaque_right (a : DerivationClass) :
    DerivationClass.join a .OpaqueExternal = .OpaqueExternal := by
  cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- DPI-1: No silent cleansing
-- ═══════════════════════════════════════════════════════════════════════

/-- **DPI Invariant #1 — No silent cleansing.**
    AIDerived joined with ANY DerivationClass never produces Deterministic.
    AI-generated data carries its taint irreversibly through all joins. -/
theorem no_silent_cleansing (x : DerivationClass) :
    DerivationClass.join .AIDerived x ≠ .Deterministic := by
  cases x <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- DPI-2: Monotone join — joins never reduce taint level
-- ═══════════════════════════════════════════════════════════════════════

/-- **DPI Invariant #2 — Join is monotone in taint level.**
    taint_level(join(a, b)) >= taint_level(a) for all a, b. -/
theorem join_monotone_left (a b : DerivationClass) :
    (DerivationClass.join a b).taintLevel ≥ a.taintLevel := by
  cases a <;> cases b <;> decide

/-- taint_level(join(a, b)) >= taint_level(b) for all a, b. -/
theorem join_monotone_right (a b : DerivationClass) :
    (DerivationClass.join a b).taintLevel ≥ b.taintLevel := by
  cases a <;> cases b <;> decide

/-- Combined: taint_level(join(a, b)) >= max(taint_level(a), taint_level(b)). -/
theorem join_monotone (a b : DerivationClass) :
    (DerivationClass.join a b).taintLevel ≥
    max a.taintLevel b.taintLevel := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Meet — greatest lower bound (dual of join)
-- ═══════════════════════════════════════════════════════════════════════

/-- Meet (greatest lower bound) matching the Rust implementation. -/
def DerivationClass.meet (a b : DerivationClass) : DerivationClass :=
  match a, b with
  -- OpaqueExternal is top — identity for meet
  | .OpaqueExternal, x => x
  | x, .OpaqueExternal => x
  -- Deterministic is bottom — absorber for meet
  | .Deterministic, _ => .Deterministic
  | _, .Deterministic => .Deterministic
  -- Same class: idempotent
  | .AIDerived, .AIDerived => .AIDerived
  | .HumanPromoted, .HumanPromoted => .HumanPromoted
  | .Mixed, .Mixed => .Mixed
  -- Mixed meets AIDerived or HumanPromoted = the lower element
  | .Mixed, x => x
  | x, .Mixed => x
  -- AIDerived meets HumanPromoted = Deterministic (their GLB)
  | .AIDerived, .HumanPromoted => .Deterministic
  | .HumanPromoted, .AIDerived => .Deterministic

/-- Meet is commutative. -/
theorem meet_comm (a b : DerivationClass) :
    DerivationClass.meet a b = DerivationClass.meet b a := by
  cases a <;> cases b <;> decide

/-- Meet is associative. -/
theorem meet_assoc (a b c : DerivationClass) :
    DerivationClass.meet (DerivationClass.meet a b) c =
    DerivationClass.meet a (DerivationClass.meet b c) := by
  cases a <;> cases b <;> cases c <;> decide

/-- Meet is idempotent. -/
theorem meet_idempotent (a : DerivationClass) :
    DerivationClass.meet a a = a := by
  cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Absorption laws — confirms join/meet form a lattice
-- ═══════════════════════════════════════════════════════════════════════

/-- Absorption: a join (a meet b) = a. -/
theorem absorption_join_meet (a b : DerivationClass) :
    DerivationClass.join a (DerivationClass.meet a b) = a := by
  cases a <;> cases b <;> decide

/-- Absorption: a meet (a join b) = a. -/
theorem absorption_meet_join (a b : DerivationClass) :
    DerivationClass.meet a (DerivationClass.join a b) = a := by
  cases a <;> cases b <;> decide

end DerivationProofs
