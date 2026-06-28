/-!
# WASI 0.3.0 World Functor — `CapabilityLattice → WasiWorld`

The Lean side of `crates/portcullis-wasi/src/lib.rs`. We prove that compiling a
Nucleus capability lattice into a WebAssembly Component Model **import world** is
a *lattice homomorphism*: it preserves meet (most-restrictive-wins), join, and
both bounds.

WASI is capability-based access control — a component may do only what its world
(imported interfaces) grants, with no ambient authority. This file proves the
core of the bridge from Nucleus's graded capability lattice onto that model.

## What is proven

- **`φ : CapabilityLevel → WasiGrant`** (the per-interface core) is a lattice
  **isomorphism** of 3-chains: `phi_meet`, `phi_join`, `phi_bot`, `phi_top`,
  `phi_mono`, `phi_injective`.
- **`present : WasiGrant → Bool`** (import-presence) is a bounded-lattice
  homomorphism onto `Bool`: `present_meet`, `present_join`. Composed with `φ`,
  this is the headline law — **meet ↦ import intersection**
  (`import_presence_meet` / `import_presence_join`).
- **`filesystemGrant`** (the dimension-folding step, where several capability
  dimensions collapse onto `wasi:filesystem`) is **monotone**:
  `filesystemGrant_mono`.

Every theorem discharges by `decide` over finite types — kernel-checked, no
`sorry`, no SMT, Mathlib-free. These mirror, 1:1, the exhaustive property tests
in `portcullis-wasi`'s `tests` module.

## Source correspondence

| Lean                         | Rust (`portcullis-wasi`)            |
|------------------------------|-------------------------------------|
| `CapabilityLevel`            | `nucleus_ifc_kernel::CapabilityLevel`  |
| `WasiGrant`                  | `WasiGrant`                         |
| `φ`                          | `impl From<CapabilityLevel> …`      |
| `present`                    | `WasiGrant::present`                |
| `filesystemGrant`            | `filesystem_grant`                  |
-/

namespace WasiWorldFunctor

-- ═══════════════════════════════════════════════════════════════════════════
-- CapabilityLevel — mirror of nucleus_ifc_kernel::CapabilityLevel (3-chain)
-- ═══════════════════════════════════════════════════════════════════════════

/-- Capability level. `never < lowRisk < always`; `meet` = min, `join` = max.
    Rust: `pub enum CapabilityLevel { Never = 0, LowRisk = 1, Always = 2 }`. -/
inductive CapabilityLevel where
  | never
  | lowRisk
  | always
deriving DecidableEq, Repr

namespace CapabilityLevel

/-- Discriminant, matching the Rust `#[repr(u8)]` values. -/
def toNat : CapabilityLevel → Nat
  | never   => 0
  | lowRisk => 1
  | always  => 2

/-- Partial order `≤` as min-chain comparison. -/
def le (a b : CapabilityLevel) : Bool := a.toNat ≤ b.toNat

/-- Meet (GLB) = min. -/
def meet (a b : CapabilityLevel) : CapabilityLevel := if a.le b then a else b

/-- Join (LUB) = max. -/
def join (a b : CapabilityLevel) : CapabilityLevel := if a.le b then b else a

end CapabilityLevel

-- ═══════════════════════════════════════════════════════════════════════════
-- WasiGrant — mirror of portcullis_wasi::WasiGrant (3-chain)
-- ═══════════════════════════════════════════════════════════════════════════

/-- The grant level for one WASI interface. `absent < restricted < full`;
    `Absent` = "interface not imported into the world". -/
inductive WasiGrant where
  | absent
  | restricted
  | full
deriving DecidableEq, Repr

namespace WasiGrant

def toNat : WasiGrant → Nat
  | absent     => 0
  | restricted => 1
  | full       => 2

def le (a b : WasiGrant) : Bool := a.toNat ≤ b.toNat

def meet (a b : WasiGrant) : WasiGrant := if a.le b then a else b

def join (a b : WasiGrant) : WasiGrant := if a.le b then b else a

end WasiGrant

-- ═══════════════════════════════════════════════════════════════════════════
-- φ : CapabilityLevel → WasiGrant — the functor core (lattice iso)
-- ═══════════════════════════════════════════════════════════════════════════

/-- The per-interface functor core. Rust: `impl From<CapabilityLevel> for WasiGrant`. -/
def φ : CapabilityLevel → WasiGrant
  | .never   => .absent
  | .lowRisk => .restricted
  | .always  => .full

/-- φ preserves meet — most-restrictive-wins is preserved by compilation. -/
theorem phi_meet (a b : CapabilityLevel) :
    φ (a.meet b) = (φ a).meet (φ b) := by
  cases a <;> cases b <;> decide

/-- φ preserves join. -/
theorem phi_join (a b : CapabilityLevel) :
    φ (a.join b) = (φ a).join (φ b) := by
  cases a <;> cases b <;> decide

/-- φ preserves the bottom: `Never ↦ Absent`. -/
theorem phi_bot : φ .never = .absent := rfl

/-- φ preserves the top: `Always ↦ Full`. -/
theorem phi_top : φ .always = .full := rfl

/-- φ is monotone (order-preserving). -/
theorem phi_mono (a b : CapabilityLevel) :
    a.le b = true → (φ a).le (φ b) = true := by
  cases a <;> cases b <;> decide

/-- φ is injective — no two capability levels collapse to the same grant.
    Together with `phi_meet`/`phi_join` this makes φ a lattice isomorphism
    onto its image. -/
theorem phi_injective (a b : CapabilityLevel) :
    φ a = φ b → a = b := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════════
-- present : WasiGrant → Bool — import-presence projection
-- ═══════════════════════════════════════════════════════════════════════════

/-- Is the interface imported into the component world at all?
    Rust: `WasiGrant::present`. -/
def present : WasiGrant → Bool
  | .absent => false
  | _       => true

/-- `present` preserves meet — **meet ↦ import intersection**. -/
theorem present_meet (a b : WasiGrant) :
    present (a.meet b) = (present a && present b) := by
  cases a <;> cases b <;> decide

/-- `present` preserves join — **join ↦ import union**. -/
theorem present_join (a b : WasiGrant) :
    present (a.join b) = (present a || present b) := by
  cases a <;> cases b <;> decide

/-- The headline law, composed: the import-presence of a meet of capability
    levels is the conjunction of import-presences. Restricting an agent's
    permissions can only *remove* interfaces from its world, never add them. -/
theorem import_presence_meet (a b : CapabilityLevel) :
    present (φ (a.meet b)) = (present (φ a) && present (φ b)) := by
  cases a <;> cases b <;> decide

/-- Dual: join of capabilities unions the imported interfaces. -/
theorem import_presence_join (a b : CapabilityLevel) :
    present (φ (a.join b)) = (present (φ a) || present (φ b)) := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════════
-- filesystemGrant — the dimension-folding step is monotone
-- ═══════════════════════════════════════════════════════════════════════════

/-- Fold the filesystem dimensions onto one `wasi:filesystem` grant: `full` if
    any write-ish capability is present, else `restricted` (read-only preopen)
    if any read-ish capability is present, else `absent`.
    Rust: `filesystem_grant`. -/
def filesystemGrant (fsRead fsWrite : CapabilityLevel) : WasiGrant :=
  match fsWrite, fsRead with
  | .never, .never => .absent
  | .never, _      => .restricted
  | _,      _      => .full

/-- The fold is monotone in both arguments: a more permissive capability
    lattice yields a more permissive filesystem grant. (In `world_of`, `fsRead`
    and `fsWrite` are themselves joins of capability dimensions, which are
    monotone, so the whole reduction is monotone by composition.) -/
theorem filesystemGrant_mono (r r' w w' : CapabilityLevel) :
    r.le r' = true → w.le w' = true →
    (filesystemGrant r w).le (filesystemGrant r' w') = true := by
  cases r <;> cases r' <;> cases w <;> cases w' <;> decide

-- ═══════════════════════════════════════════════════════════════════════════
-- Multi-source folding: join-homomorphism, but only lax for meet
-- ═══════════════════════════════════════════════════════════════════════════
--
-- `world_of` folds several capability dimensions onto one interface
-- (e.g. http_out ← web_fetch ⊔ create_pr ⊔ git_push). We model the essential
-- case with two sources: `fold2 x y = φ x ⊔ φ y`. This reveals the real
-- structure of `world_of`: a JOIN-homomorphism + monotone, but for MEET only
-- *lax* (`world_of (a ⊓ b) ≤ world_of a ⊓ world_of b`) — the security-safe
-- direction. The strict witness is the `git_push` vs `web_fetch` HTTP collision
-- from `portcullis-wasi`'s `world_of_meet_is_lax_and_safe` test.

/-- A two-source folded interface grant: the join of two φ-images. -/
def fold2 (x y : CapabilityLevel) : WasiGrant := (φ x).join (φ y)

/-- The fold is a **join-homomorphism**: `fold2 (x⊔x') (y⊔y') =
    fold2 x y ⊔ fold2 x' y'`. (Join-of-joins reassociates.) -/
theorem fold2_join_hom (x x' y y' : CapabilityLevel) :
    fold2 (x.join x') (y.join y') = (fold2 x y).join (fold2 x' y') := by
  cases x <;> cases x' <;> cases y <;> cases y' <;> decide

/-- The fold is **lax for meet**: `fold2 (x⊓x') (y⊓y') ≤ fold2 x y ⊓ fold2 x' y'`.
    Restricting capabilities can only shrink the folded grant — never grow it. -/
theorem fold2_meet_lax (x x' y y' : CapabilityLevel) :
    (fold2 (x.meet x') (y.meet y')).le ((fold2 x y).meet (fold2 x' y')) = true := by
  cases x <;> cases x' <;> cases y <;> cases y' <;> decide

/-- …and the inequality is **strict** in general: the HTTP collision. With
    `x = never, y = always` (imports via the 2nd source) and
    `x' = always, y' = never` (imports via the 1st source), the meet imports via
    neither (`absent`) yet the meet-of-folds keeps it (`full`). This is exactly
    why `world_of` is not a meet-homomorphism on multi-source interfaces. -/
theorem fold2_meet_strict :
    fold2 (CapabilityLevel.never.meet .always) (CapabilityLevel.always.meet .never)
      ≠ (fold2 .never .always).meet (fold2 .always .never) := by
  decide

end WasiWorldFunctor
