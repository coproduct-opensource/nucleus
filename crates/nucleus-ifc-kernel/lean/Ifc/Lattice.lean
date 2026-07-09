/-
  Ifc / Lattice  (IFC label kernel — lattice-soundness proofs)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: finite inductive enums +
  exhaustive `cases` / `rfl` / `decide`. No Mathlib, no native-decide, no
  `sorry` / `admit` / `axiom`. Lean 4 v4.30.0-rc2, `autoImplicit = false`.
  Same discipline as `Ck.Policy` (`crates/ck-policy/lean`) and `Nucleus.Rubric`
  (`crates/nucleus-rubric/lean`).

  This file is the Lean *statement and proof* of lattice-soundness properties the
  Rust crate `nucleus-ifc-kernel` (`crates/nucleus-ifc-kernel/src/ifc_lattice.rs`)
  relies on. It models, verbatim, two of the six axes of the IFC product lattice:

    * `DerivationClass` — the determinism-aware integrity axis. This is the one
      NON-LINEAR axis (a diamond: `AIDerived` and `HumanPromoted` are incomparable,
      both above `Deterministic`, both below `Mixed`, all below `OpaqueExternal`).
      Its `join` is defined by the exact `match` table in `ifc_lattice.rs`.
    * `ConfLevel` — the covariant confidentiality chain (`Public < Internal <
      Secret`) whose join is `max` ("most secret wins", BLP).

  # What is proved

  For `DerivationClass.join` (a bounded join-semilattice):
    * `join_comm`      — commutative
    * `join_assoc`     — associative
    * `join_idem`      — idempotent
    * `join_bot`       — `Deterministic` is the identity (bottom): `⊥ ⊔ x = x`
    * `join_top`       — `OpaqueExternal` is absorbing (top): `x ⊔ ⊤ = ⊤`
    * `join_ub_left/right` / `leq_join_left/right` — join is an upper bound
    * `no_silent_cleansing` — the crate's OWN documented key invariant:
        `∀ x, join AIDerived x ≠ Deterministic`. AI-derived data can NEVER be
        laundered back to deterministic (the anti-cleansing property that the
        source doc-comment on `DerivationClass` calls out by name). This is a
        genuine security invariant of the join table, NOT a tautology.
    * `leq_refl` / `leq_trans` / `leq_antisymm` — `leq` (defined exactly as the
      Rust `a.join(b) == b`) is a partial order.

  For `ConfLevel.join`:
    * `conf_join_comm` / `conf_join_assoc` / `conf_join_idem`
    * `conf_join_public_bot` — `Public` is bottom (identity for join)
    * `conf_join_ub_left/right` — join is an upper bound (nothing declassifies:
      `a.conf ≤ (a ⊔ b).conf`, i.e. combining data never LOWERS confidentiality)
    * `conf_join_mono` — join is monotone in each argument

  # EXTRACTION-GAP CAVEAT

  These theorems are proved about the Lean MODEL of the join tables. The model is
  a hand-transcription of the `ifc_lattice.rs` `match` arms (checked by eye, and
  by the crate's own `proptest` suite on the Rust side); it is NOT an Aeneas
  extraction. A formal Charon→Aeneas extraction of `DerivationClass::join` /
  `ConfLevel` `Ord` would be required to close the model↔Rust gap deductively.
  Until then, treat these as statements about the faithfully-mirrored model.
-/

namespace Ifc.Lattice

/- ───────────────────────────────────────────────────────────────────────────
   DerivationClass — the determinism-aware integrity axis (the diamond)
   Mirrors `enum DerivationClass` and `impl DerivationClass` in ifc_lattice.rs.
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Determinism-aware integrity classification. Lattice (Hasse):

    ```text
          OpaqueExternal  (top)
               |
             Mixed
            /     \
      AIDerived  HumanPromoted
            \     /
          Deterministic  (bottom)
    ```
-/
inductive DerivationClass
  | Deterministic
  | AIDerived
  | Mixed
  | HumanPromoted
  | OpaqueExternal
  deriving DecidableEq, Repr

namespace DerivationClass

/-- Join (least upper bound). Transcribes the `match (self, other)` arms of
    `DerivationClass::join` in `ifc_lattice.rs`, top-to-bottom, verbatim:

      (Deterministic, x) | (x, Deterministic) => x
      (OpaqueExternal, _) | (_, OpaqueExternal) => OpaqueExternal
      (AIDerived, AIDerived) => AIDerived
      (HumanPromoted, HumanPromoted) => HumanPromoted
      (Mixed, Mixed) => Mixed
      _ => Mixed
-/
def join : DerivationClass → DerivationClass → DerivationClass
  | Deterministic, x => x
  | x, Deterministic => x
  | OpaqueExternal, _ => OpaqueExternal
  | _, OpaqueExternal => OpaqueExternal
  | AIDerived, AIDerived => AIDerived
  | HumanPromoted, HumanPromoted => HumanPromoted
  | Mixed, Mixed => Mixed
  | _, _ => Mixed

/-- Lattice partial order, defined EXACTLY as the Rust `leq`:
    `a.leq(b) := a.join(b) == b`. -/
def leq (a b : DerivationClass) : Prop := join a b = b

instance (a b : DerivationClass) : Decidable (leq a b) :=
  inferInstanceAs (Decidable (join a b = b))

/-- `join` is commutative. -/
theorem join_comm (a b : DerivationClass) : join a b = join b a := by
  cases a <;> cases b <;> decide

/-- `join` is idempotent. -/
theorem join_idem (a : DerivationClass) : join a a = a := by
  cases a <;> decide

/-- `join` is associative. -/
theorem join_assoc (a b c : DerivationClass) :
    join (join a b) c = join a (join b c) := by
  cases a <;> cases b <;> cases c <;> decide

/-- `Deterministic` is the bottom / identity for `join`. -/
theorem join_bot (x : DerivationClass) : join Deterministic x = x := by
  cases x <;> decide

/-- `OpaqueExternal` is the top / absorbing element for `join`. -/
theorem join_top (x : DerivationClass) : join x OpaqueExternal = OpaqueExternal := by
  cases x <;> decide

/-- `join a b` is an upper bound of `a` (in the `leq = join _ _ = _` order). -/
theorem leq_join_left (a b : DerivationClass) : leq a (join a b) := by
  cases a <;> cases b <;> decide

/-- `join a b` is an upper bound of `b`. -/
theorem leq_join_right (a b : DerivationClass) : leq b (join a b) := by
  cases a <;> cases b <;> decide

/-- **No silent cleansing** — the crate's own documented key invariant.

    `AIDerived.join(x)` is NEVER `Deterministic`, for any `x`: AI-derived data
    can never be laundered back to a reproducible/deterministic class. This is a
    genuine security property of the join table (an "up-only" trap on the
    AI-derived class), directly asserted in the `DerivationClass` doc-comment. -/
theorem no_silent_cleansing (x : DerivationClass) :
    join AIDerived x ≠ Deterministic := by
  cases x <;> decide

/-- `leq` is reflexive (from idempotence). -/
theorem leq_refl (a : DerivationClass) : leq a a := by
  cases a <;> decide

/-- `leq` is transitive. -/
theorem leq_trans {a b c : DerivationClass} (hab : leq a b) (hbc : leq b c) :
    leq a c := by
  cases a <;> cases b <;> cases c <;>
    first
      | decide
      | simp_all [leq, join]
      | (revert hab hbc; decide)

/-- `leq` is antisymmetric. -/
theorem leq_antisymm {a b : DerivationClass} (hab : leq a b) (hba : leq b a) :
    a = b := by
  cases a <;> cases b <;>
    first
      | decide
      | simp_all [leq, join]
      | (revert hab hba; decide)

end DerivationClass

/- ───────────────────────────────────────────────────────────────────────────
   ConfLevel — the covariant confidentiality chain (join = max, BLP)
   Mirrors `enum ConfLevel` (`Public = 0 < Internal = 1 < Secret = 2`) and the
   confidentiality arm of `IFCLabel::join` (`if a >= b { a } else { b }` = max).
   ─────────────────────────────────────────────────────────────────────────── -/

/-- Confidentiality level — covariant (join = max, "most secret wins"). -/
inductive ConfLevel
  | Public
  | Internal
  | Secret
  deriving DecidableEq, Repr

namespace ConfLevel

/-- Numeric rank, matching the `#[repr(u8)]` discriminants `0 < 1 < 2`. -/
def rank : ConfLevel → Nat
  | Public => 0
  | Internal => 1
  | Secret => 2

/-- `≤` on levels, via the numeric rank (the derived `Ord` in Rust). -/
def le (a b : ConfLevel) : Prop := rank a ≤ rank b

instance (a b : ConfLevel) : Decidable (le a b) :=
  inferInstanceAs (Decidable (rank a ≤ rank b))

/-- Join = max: the confidentiality arm of `IFCLabel::join`
    (`if self.conf >= other.conf { self.conf } else { other.conf }`). -/
def join (a b : ConfLevel) : ConfLevel :=
  if rank a ≥ rank b then a else b

theorem join_comm (a b : ConfLevel) : join a b = join b a := by
  cases a <;> cases b <;> decide

theorem join_idem (a : ConfLevel) : join a a = a := by
  cases a <;> decide

theorem join_assoc (a b c : ConfLevel) :
    join (join a b) c = join a (join b c) := by
  cases a <;> cases b <;> cases c <;> decide

/-- `Public` is bottom (identity for join). -/
theorem join_public_bot (a : ConfLevel) : join Public a = a := by
  cases a <;> decide

/-- Join never DECLASSIFIES: `a`'s confidentiality is `≤` the join's.
    Combining data can only raise confidentiality (BLP "no read up"). -/
theorem join_ub_left (a b : ConfLevel) : le a (join a b) := by
  cases a <;> cases b <;> decide

theorem join_ub_right (a b : ConfLevel) : le b (join a b) := by
  cases a <;> cases b <;> decide

/-- Join is monotone in its left argument. -/
theorem join_mono_left {a a' : ConfLevel} (b : ConfLevel) (h : le a a') :
    le (join a b) (join a' b) := by
  cases a <;> cases a' <;> cases b <;>
    first
      | decide
      | simp_all [le, rank]
      | (revert h; decide)

/-- Join is monotone in its right argument. -/
theorem join_mono_right (a : ConfLevel) {b b' : ConfLevel} (h : le b b') :
    le (join a b) (join a b') := by
  cases a <;> cases b <;> cases b' <;>
    first
      | decide
      | simp_all [le, rank]
      | (revert h; decide)

end ConfLevel

end Ifc.Lattice
