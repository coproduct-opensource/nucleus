import Mathlib.Order.Lattice
import Mathlib.Order.BoundedOrder.Basic

/-!
# IFC Semilattice Typeclass Instances — Aeneas-cat-1 through aeneas-cat-5

Establishes Mathlib `SemilatticeInf`, `SemilatticeSup`, and `Lattice` instances
for the IFC label types defined in `portcullis-core/src/lib.rs`:

- **`ConfLevel`** — covariant confidentiality (join = max, meet = min)
- **`IntegLevel`** — contravariant integrity (join = min, meet = max, Biba model)
- **`IFCLabel2`** — the (ConfLevel × IntegLevel) product lattice
- **`propagate_label`** — functoriality theorem (join-preserving map)

These are hand-written Lean models mirroring the Rust source. The naming
convention `IFCLabel2` is used here to avoid conflicts with `FlowProofs`
(which also defines these types locally); in production they would share
the same namespace via an Aeneas-generated translation.

## Issues addressed

- aeneas-cat-1 (#1123): Translate ConfLevel and IntegLevel to Lean
- aeneas-cat-2 (#1124): Prove SemilatticeInf/Sup instances for ConfLevel
- aeneas-cat-4 (#1126): Prove IFCLabel join is SemilatticeSup (product construction)
- aeneas-cat-5 (#1127): Prove propagate_label preserves joins (functoriality)

All proofs discharge via `decide` over finite types.
No sorry, no SMT — kernel-checked by the Lean 4 type-checker.
-/

namespace IFCSemilatticeProofs

-- ═══════════════════════════════════════════════════════════════════════
-- aeneas-cat-1: Type definitions (#1123)
-- Mirrors portcullis-core/src/lib.rs, lines ~1019-1045
-- ═══════════════════════════════════════════════════════════════════════

/-- Confidentiality level — covariant. Higher = more secret.
    Rust: `pub enum ConfLevel { Public = 0, Internal = 1, Secret = 2 }` -/
inductive ConfLevel where
  | Public   : ConfLevel
  | Internal : ConfLevel
  | Secret   : ConfLevel
deriving DecidableEq, Repr, Inhabited

/-- Integrity level — contravariant (Biba model). Higher = more trusted.
    Rust: `pub enum IntegLevel { Adversarial = 0, Untrusted = 1, Trusted = 2 }`
    In the join lattice, LOWER values win (least trusted dominates). -/
inductive IntegLevel where
  | Adversarial : IntegLevel
  | Untrusted   : IntegLevel
  | Trusted     : IntegLevel
deriving DecidableEq, Repr, Inhabited

-- Natural number encodings (matching Rust #[repr(u8)] discriminants)

def ConfLevel.toNat : ConfLevel → Nat
  | .Public   => 0
  | .Internal => 1
  | .Secret   => 2

def IntegLevel.toNat : IntegLevel → Nat
  | .Adversarial => 0
  | .Untrusted   => 1
  | .Trusted     => 2

theorem ConfLevel.toNat_injective : Function.Injective ConfLevel.toNat := by
  intro a b h; cases a <;> cases b <;> simp [toNat] at *

theorem IntegLevel.toNat_injective : Function.Injective IntegLevel.toNat := by
  intro a b h; cases a <;> cases b <;> simp [toNat] at *

-- ═══════════════════════════════════════════════════════════════════════
-- aeneas-cat-2: ConfLevel SemilatticeInf / SemilatticeSup (#1124)
-- ═══════════════════════════════════════════════════════════════════════

-- ── LE / LT for ConfLevel (covariant: Public < Internal < Secret) ─────

instance : LE ConfLevel where
  le a b := a.toNat ≤ b.toNat

instance : LT ConfLevel where
  lt a b := a.toNat < b.toNat

instance : DecidableRel (α := ConfLevel) (· ≤ ·) :=
  fun a b => inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

instance : DecidableRel (α := ConfLevel) (· < ·) :=
  fun a b => inferInstanceAs (Decidable (a.toNat < b.toNat))

-- ── Preorder / PartialOrder / LinearOrder for ConfLevel ───────────────

instance : Preorder ConfLevel where
  le_refl  a     := Nat.le_refl _
  le_trans _ _ _ := Nat.le_trans
  lt_iff_le_not_ge _ _ := Nat.lt_iff_le_and_not_ge

instance : PartialOrder ConfLevel where
  le_antisymm a b h1 h2 :=
    ConfLevel.toNat_injective (Nat.le_antisymm h1 h2)

instance : LinearOrder ConfLevel where
  le_total a b := Nat.le_or_ge a.toNat b.toNat
  toDecidableLE := inferInstance
  toDecidableLT := inferInstance
  toDecidableEq := inferInstance

-- ── Inf / Sup instances for ConfLevel ────────────────────────────────
-- mathlib v4.30: `SemilatticeInf`/`SemilatticeSup` carry their own `inf`/`sup`
-- field directly; `Min`/`Max` are *derived* from them via `SemilatticeInf.toMin`
-- / `SemilatticeSup.toMax`. So we supply `inf`/`sup` here and drop the manual
-- `Min`/`Max` instances.

/-- ConfLevel is a SemilatticeInf under covariant ordering (inf = min). -/
instance : SemilatticeInf ConfLevel where
  inf a b := if a.toNat ≤ b.toNat then a else b
  inf_le_left  a b := by cases a <;> cases b <;> decide
  inf_le_right a b := by cases a <;> cases b <;> decide
  le_inf a b c hab hac := by
    revert hab hac; cases a <;> cases b <;> cases c <;> decide

/-- ConfLevel is a SemilatticeSup under covariant ordering (sup = max). -/
instance : SemilatticeSup ConfLevel where
  sup a b := if a.toNat ≥ b.toNat then a else b
  le_sup_left  a b := by cases a <;> cases b <;> decide
  le_sup_right a b := by cases a <;> cases b <;> decide
  sup_le a b c hac hbc := by
    revert hac hbc; cases a <;> cases b <;> cases c <;> decide

/-- ConfLevel is a full Lattice (inherits inf/sup from the two semilattices). -/
instance : Lattice ConfLevel :=
  { (inferInstance : SemilatticeSup ConfLevel),
    (inferInstance : SemilatticeInf ConfLevel) with }

-- ── LE / LT for IntegLevel ────────────────────────────────────────────
-- NB: The NATURAL ordering on IntegLevel is Adversarial < Untrusted < Trusted.
-- The join in the IFC lattice is the MEET in this natural order (min wins).
-- We define the standard order here; the product lattice handles variance.

instance : LE IntegLevel where
  le a b := a.toNat ≤ b.toNat

instance : LT IntegLevel where
  lt a b := a.toNat < b.toNat

instance : DecidableRel (α := IntegLevel) (· ≤ ·) :=
  fun a b => inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

instance : DecidableRel (α := IntegLevel) (· < ·) :=
  fun a b => inferInstanceAs (Decidable (a.toNat < b.toNat))

instance : Preorder IntegLevel where
  le_refl  a     := Nat.le_refl _
  le_trans _ _ _ := Nat.le_trans
  lt_iff_le_not_ge _ _ := Nat.lt_iff_le_and_not_ge

instance : PartialOrder IntegLevel where
  le_antisymm a b h1 h2 :=
    IntegLevel.toNat_injective (Nat.le_antisymm h1 h2)

instance : LinearOrder IntegLevel where
  le_total a b := Nat.le_or_ge a.toNat b.toNat
  toDecidableLE := inferInstance
  toDecidableLT := inferInstance
  toDecidableEq := inferInstance

-- ── SemilatticeInf / SemilatticeSup for IntegLevel ────────────────────

instance : SemilatticeInf IntegLevel where
  inf a b := if a.toNat ≤ b.toNat then a else b
  inf_le_left  a b := by cases a <;> cases b <;> decide
  inf_le_right a b := by cases a <;> cases b <;> decide
  le_inf a b c hab hac := by
    revert hab hac; cases a <;> cases b <;> cases c <;> decide

instance : SemilatticeSup IntegLevel where
  sup a b := if a.toNat ≥ b.toNat then a else b
  le_sup_left  a b := by cases a <;> cases b <;> decide
  le_sup_right a b := by cases a <;> cases b <;> decide
  sup_le a b c hac hbc := by
    revert hac hbc; cases a <;> cases b <;> cases c <;> decide

instance : Lattice IntegLevel :=
  { (inferInstance : SemilatticeSup IntegLevel),
    (inferInstance : SemilatticeInf IntegLevel) with }

-- ═══════════════════════════════════════════════════════════════════════
-- Correctness lemmas — key security properties as typeclass theorems
-- ═══════════════════════════════════════════════════════════════════════

/-- Public is the minimum confidentiality level. -/
theorem conf_public_is_bot (a : ConfLevel) : .Public ≤ a := by
  cases a <;> decide

/-- Secret is the maximum confidentiality level. -/
theorem conf_secret_is_top (a : ConfLevel) : a ≤ .Secret := by
  cases a <;> decide

/-- Adversarial is the minimum integrity level. -/
theorem integ_adversarial_is_bot (a : IntegLevel) : .Adversarial ≤ a := by
  cases a <;> decide

/-- Trusted is the maximum integrity level. -/
theorem integ_trusted_is_top (a : IntegLevel) : a ≤ .Trusted := by
  cases a <;> decide

/-- Joining with Adversarial always yields Adversarial (taint propagation).
    This is the IFC join in the PRODUCT lattice sense — where integrity
    is contravariant, so IFC-join = standard meet (inf). -/
theorem integ_inf_adversarial_left (b : IntegLevel) : .Adversarial ⊓ b = .Adversarial := by
  cases b <;> decide

theorem integ_inf_adversarial_right (a : IntegLevel) : a ⊓ .Adversarial = .Adversarial := by
  cases a <;> decide

/-- Joining with Secret always yields Secret (confidentiality elevation).
    IFC-join = standard sup for ConfLevel. -/
theorem conf_sup_secret_left (b : ConfLevel) : .Secret ⊔ b = .Secret := by
  cases b <;> decide

theorem conf_sup_secret_right (a : ConfLevel) : a ⊔ .Secret = .Secret := by
  cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- aeneas-cat-4: IFCLabel2 product lattice (#1126)
-- IFCLabel2 = ConfLevel × IntegLevel (simplified 2-dimensional label)
-- The full label also includes provenance, freshness, authority, derivation.
-- ═══════════════════════════════════════════════════════════════════════

/-- Simplified 2-dimensional IFC label: (confidentiality, integrity).
    Models the core of `portcullis-core::IFCLabel`. -/
structure IFCLabel2 where
  confidentiality : ConfLevel
  integrity       : IntegLevel
deriving DecidableEq, Repr

/-- IFC join: confidentiality covariant (sup), integrity contravariant (inf). -/
def IFCLabel2.join (a b : IFCLabel2) : IFCLabel2 where
  confidentiality := a.confidentiality ⊔ b.confidentiality
  integrity       := a.integrity ⊓ b.integrity

/-- IFC meet: confidentiality covariant (inf), integrity contravariant (sup). -/
def IFCLabel2.meet (a b : IFCLabel2) : IFCLabel2 where
  confidentiality := a.confidentiality ⊓ b.confidentiality
  integrity       := a.integrity ⊔ b.integrity

/-- IFC information-flow ordering: confidentiality covariant, integrity
    CONTRAVARIANT (Biba). `a ≤ b` means information may flow `a → b`: `b` is at
    least as confidential and at most as trusted. Under this order, the IFC
    `join` (conf ⊔, integ ⊓) is the genuine lattice supremum — combining two
    sources yields the least upper bound (most secret, least trusted). -/
instance : LE IFCLabel2 where
  le a b := a.confidentiality ≤ b.confidentiality ∧ b.integrity ≤ a.integrity

instance : Preorder IFCLabel2 where
  le_refl  a     := ⟨le_refl _, le_refl _⟩
  le_trans a b c h1 h2 := ⟨le_trans h1.1 h2.1, le_trans h2.2 h1.2⟩

instance : PartialOrder IFCLabel2 where
  le_antisymm a b h1 h2 := by
    cases a; cases b
    obtain ⟨hc1, hi1⟩ := h1
    obtain ⟨hc2, hi2⟩ := h2
    exact congr_arg₂ IFCLabel2.mk (le_antisymm hc1 hc2) (le_antisymm hi2 hi1)

/-- IFCLabel2 join (sup) forms a SemilatticeSup.
    This is the core claim of aeneas-cat-4 (#1126). -/
instance : SemilatticeSup IFCLabel2 where
  sup := IFCLabel2.join
  -- join: conf = sup (covariant), integ = inf (contravariant taint)
  le_sup_left a b :=
    ⟨_root_.le_sup_left, _root_.inf_le_left⟩
  le_sup_right a b :=
    ⟨_root_.le_sup_right, _root_.inf_le_right⟩
  sup_le a b c hac hbc :=
    ⟨_root_.sup_le hac.1 hbc.1, _root_.le_inf hac.2 hbc.2⟩

/-- IFCLabel2 meet (inf) forms a SemilatticeInf. -/
instance : SemilatticeInf IFCLabel2 where
  inf := IFCLabel2.meet
  -- meet: conf = inf (covariant), integ = sup (contravariant)
  inf_le_left a b :=
    ⟨_root_.inf_le_left, _root_.le_sup_left⟩
  inf_le_right a b :=
    ⟨_root_.inf_le_right, _root_.le_sup_right⟩
  le_inf a b c hab hac :=
    ⟨_root_.le_inf hab.1 hac.1, _root_.sup_le hab.2 hac.2⟩

/-- IFCLabel2 is a full Lattice (inherits sup from `SemilatticeSup`, inf from
    `SemilatticeInf`; both share the same `PartialOrder`). -/
instance : Lattice IFCLabel2 :=
  { (inferInstance : SemilatticeSup IFCLabel2),
    (inferInstance : SemilatticeInf IFCLabel2) with }

/-- `⊔` on `IFCLabel2` unfolds to `IFCLabel2.join` (the derived `Max`/`sup`). -/
@[simp] theorem ifc_sup_eq_join (a b : IFCLabel2) : a ⊔ b = IFCLabel2.join a b := rfl

/-- `⊓` on `IFCLabel2` unfolds to `IFCLabel2.meet` (the derived `Min`/`inf`). -/
@[simp] theorem ifc_inf_eq_meet (a b : IFCLabel2) : a ⊓ b = IFCLabel2.meet a b := rfl

-- Sanity check: the product lattice has a bottom and top element.
-- Under the IFC order (integrity contravariant), ⊥ is the most-public,
-- most-trusted label and ⊤ is the most-secret, least-trusted (fully tainted).
instance : OrderBot IFCLabel2 where
  bot := { confidentiality := .Public, integrity := .Trusted }
  bot_le a :=
    ⟨conf_public_is_bot _, integ_trusted_is_top _⟩

instance : OrderTop IFCLabel2 where
  top := { confidentiality := .Secret, integrity := .Adversarial }
  le_top a :=
    ⟨conf_secret_is_top _, integ_adversarial_is_bot _⟩

-- ═══════════════════════════════════════════════════════════════════════
-- aeneas-cat-5: propagate_label preserves joins (functoriality) (#1127)
--
-- A "label propagation function" f : IFCLabel2 → IFCLabel2 is join-
-- preserving (a semilattice homomorphism) if:
--   f (a ⊔ b) = f a ⊔ f b
--
-- We prove this for two canonical propagation maps:
-- 1. `elevate_conf c` — raises confidentiality to at least c (monotone map)
-- 2. `taint_integ i` — lowers integrity to at most i (monotone map)
-- These correspond to the Rust `IFCLabel::join` used in FlowTracker.
-- ═══════════════════════════════════════════════════════════════════════

/-- Elevate confidentiality to at least `floor` — monotone map on IFCLabel2. -/
def elevate_conf (floor : ConfLevel) (l : IFCLabel2) : IFCLabel2 :=
  { l with confidentiality := l.confidentiality ⊔ floor }

/-- Taint integrity down to at most `ceil` — monotone map on IFCLabel2. -/
def taint_integ (ceil : IntegLevel) (l : IFCLabel2) : IFCLabel2 :=
  { l with integrity := l.integrity ⊓ ceil }

/-- `elevate_conf` preserves IFC join (is a SemilatticeSup homomorphism). -/
theorem elevate_conf_preserves_join (floor : ConfLevel) (a b : IFCLabel2) :
    elevate_conf floor (a ⊔ b) = elevate_conf floor a ⊔ elevate_conf floor b := by
  obtain ⟨ac, ai⟩ := a; obtain ⟨bc, bi⟩ := b
  simp only [elevate_conf, ifc_sup_eq_join, IFCLabel2.join, IFCLabel2.mk.injEq]
  refine ⟨?_, trivial⟩
  cases ac <;> cases bc <;> cases floor <;> decide

/-- `taint_integ` preserves IFC join (is a SemilatticeSup homomorphism).
    This formalizes: tainting data with adversarial content distributes
    over label joins. -/
theorem taint_integ_preserves_join (ceil : IntegLevel) (a b : IFCLabel2) :
    taint_integ ceil (a ⊔ b) = taint_integ ceil a ⊔ taint_integ ceil b := by
  obtain ⟨ac, ai⟩ := a; obtain ⟨bc, bi⟩ := b
  simp only [taint_integ, ifc_sup_eq_join, IFCLabel2.join, IFCLabel2.mk.injEq]
  refine ⟨trivial, ?_⟩
  cases ai <;> cases bi <;> cases ceil <;> decide

/-- IFCLabel2.join itself is a SemilatticeSup morphism in its first argument.
    That is, fixing b, the map `λ a => a ⊔ b` distributes over ⊔. -/
theorem ifc_join_left_distributes (b c d : IFCLabel2) :
    (b ⊔ c) ⊔ d = b ⊔ c ⊔ (b ⊔ d) := by
  obtain ⟨bc, bi⟩ := b; obtain ⟨cc, ci⟩ := c; obtain ⟨dc, di⟩ := d
  simp only [ifc_sup_eq_join, IFCLabel2.join, IFCLabel2.mk.injEq]
  refine ⟨?_, ?_⟩
  · cases bc <;> cases cc <;> cases dc <;> decide
  · cases bi <;> cases ci <;> cases di <;> decide

/-- The IFC label join is idempotent in the product lattice. -/
theorem ifc_join_idempotent (a : IFCLabel2) : a ⊔ a = a := by
  obtain ⟨ac, ai⟩ := a
  simp only [ifc_sup_eq_join, IFCLabel2.join, IFCLabel2.mk.injEq]
  exact ⟨sup_idem _, inf_idem _⟩

/-- The IFC label join is commutative in the product lattice. -/
theorem ifc_join_comm (a b : IFCLabel2) : a ⊔ b = b ⊔ a := by
  obtain ⟨ac, ai⟩ := a; obtain ⟨bc, bi⟩ := b
  simp only [ifc_sup_eq_join, IFCLabel2.join, IFCLabel2.mk.injEq]
  exact ⟨sup_comm _ _, inf_comm _ _⟩

/-- The IFC label join is associative in the product lattice. -/
theorem ifc_join_assoc (a b c : IFCLabel2) : (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c) := by
  obtain ⟨ac, ai⟩ := a; obtain ⟨bc, bi⟩ := b; obtain ⟨cc, ci⟩ := c
  simp only [ifc_sup_eq_join, IFCLabel2.join, IFCLabel2.mk.injEq]
  exact ⟨sup_assoc _ _ _, inf_assoc _ _ _⟩

-- ═══════════════════════════════════════════════════════════════════════
-- Security invariant — the Invariant exploit is blocked at the lattice level
-- ═══════════════════════════════════════════════════════════════════════

/-- Combining a malicious GitHub issue label (Public, Adversarial) with a
    private repo label (Secret, Trusted) yields (Secret, Adversarial) —
    the adversarial taint propagates even though the secret is present.
    This is the IFC model of the "Invariant MCP" indirect injection attack. -/
theorem invariant_exploit_propagates_taint :
    let issue : IFCLabel2 := { confidentiality := .Public,   integrity := .Adversarial }
    let repo  : IFCLabel2 := { confidentiality := .Secret,   integrity := .Trusted }
    let combined := issue ⊔ repo
    -- Adversarial taint propagates (even though repo is Trusted)
    combined.integrity = .Adversarial ∧
    -- Confidentiality elevates to Secret
    combined.confidentiality = .Secret := by
  simp only [ifc_sup_eq_join, IFCLabel2.join]
  decide

end IFCSemilatticeProofs
