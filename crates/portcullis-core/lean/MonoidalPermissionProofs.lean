/-!
# Monoidal Structure on Permission Composition (#1113)

Proves that capability levels form a commutative monoid under `meet`
(conjunction) with `Always` as identity, and a commutative monoid under
`join` (disjunction) with `Never` as identity.

Together with distributivity, this establishes that `CapabilityLevel`
is a bounded distributive lattice — the algebraic foundation for
composing permissions via tensor products.

## Key theorems

- Meet monoid: (meet, Always) is a commutative monoid
- Join monoid: (join, Never) is a commutative monoid
- Distributivity: meet distributes over join and vice versa
- Absorption: meet(a, join(a, b)) = a

All theorems kernel-checked — no sorry.
-/

-- ═══════════════════════════════════════════════════════════════════════════
-- CapabilityLevel model
-- ═══════════════════════════════════════════════════════════════════════════

inductive CapLevel where
  | Never
  | LowRisk
  | Always
  deriving DecidableEq, Repr

open CapLevel

def toNat : CapLevel → Nat
  | Never => 0
  | LowRisk => 1
  | Always => 2

def meet (a b : CapLevel) : CapLevel :=
  match a, b with
  | Never, _ | _, Never => Never
  | LowRisk, LowRisk => LowRisk
  | LowRisk, Always | Always, LowRisk => LowRisk
  | Always, Always => Always

def join (a b : CapLevel) : CapLevel :=
  match a, b with
  | Always, _ | _, Always => Always
  | LowRisk, _ | _, LowRisk => LowRisk
  | Never, Never => Never

-- ═══════════════════════════════════════════════════════════════════════════
-- Meet monoid: (meet, Always)
-- ═══════════════════════════════════════════════════════════════════════════

theorem meet_comm (a b : CapLevel) : meet a b = meet b a := by
  cases a <;> cases b <;> simp [meet]

theorem meet_assoc (a b c : CapLevel) : meet (meet a b) c = meet a (meet b c) := by
  cases a <;> cases b <;> cases c <;> simp [meet]

theorem meet_identity_left (a : CapLevel) : meet Always a = a := by
  cases a <;> simp [meet]

theorem meet_identity_right (a : CapLevel) : meet a Always = a := by
  cases a <;> simp [meet]

theorem meet_idempotent (a : CapLevel) : meet a a = a := by
  cases a <;> simp [meet]

-- ═══════════════════════════════════════════════════════════════════════════
-- Join monoid: (join, Never)
-- ═══════════════════════════════════════════════════════════════════════════

theorem join_comm (a b : CapLevel) : join a b = join b a := by
  cases a <;> cases b <;> simp [join]

theorem join_assoc (a b c : CapLevel) : join (join a b) c = join a (join b c) := by
  cases a <;> cases b <;> cases c <;> simp [join]

theorem join_identity_left (a : CapLevel) : join Never a = a := by
  cases a <;> simp [join]

theorem join_identity_right (a : CapLevel) : join a Never = a := by
  cases a <;> simp [join]

theorem join_idempotent (a : CapLevel) : join a a = a := by
  cases a <;> simp [join]

-- ═══════════════════════════════════════════════════════════════════════════
-- Distributivity
-- ═══════════════════════════════════════════════════════════════════════════

theorem meet_distributes_over_join (a b c : CapLevel) :
    meet a (join b c) = join (meet a b) (meet a c) := by
  cases a <;> cases b <;> cases c <;> simp [meet, join]

theorem join_distributes_over_meet (a b c : CapLevel) :
    join a (meet b c) = meet (join a b) (join a c) := by
  cases a <;> cases b <;> cases c <;> simp [meet, join]

-- ═══════════════════════════════════════════════════════════════════════════
-- Absorption laws
-- ═══════════════════════════════════════════════════════════════════════════

theorem absorption_meet_join (a b : CapLevel) : meet a (join a b) = a := by
  cases a <;> cases b <;> simp [meet, join]

theorem absorption_join_meet (a b : CapLevel) : join a (meet a b) = a := by
  cases a <;> cases b <;> simp [meet, join]

-- ═══════════════════════════════════════════════════════════════════════════
-- Bounded lattice: Never is bottom, Always is top
-- ═══════════════════════════════════════════════════════════════════════════

theorem never_is_bottom (a : CapLevel) : meet Never a = Never := by
  cases a <;> simp [meet]

theorem always_is_top (a : CapLevel) : join Always a = Always := by
  cases a <;> simp [join]

theorem meet_never_annihilates (a : CapLevel) : meet a Never = Never := by
  cases a <;> simp [meet]

theorem join_always_annihilates (a : CapLevel) : join a Always = Always := by
  cases a <;> simp [join]
