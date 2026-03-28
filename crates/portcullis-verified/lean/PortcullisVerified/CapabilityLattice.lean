/-!
# CapabilityLattice as a Heyting Algebra

This file proves that `CapabilityLattice` — the 12-dimensional product of
`CapabilityLevel` chains that is the **actual production enforcement object**
in `portcullis` — is a `HeytingAlgebra` in the sense of Mathlib's
`Order.Heyting.Basic`.

## Model

`CapabilityLattice` is represented as the Pi type `Fin 12 → CapabilityLevel`,
where each index corresponds to one of the 12 core permission fields in the Rust
`CapabilityLattice` struct:

| Index | Field         | Index | Field       |
|-------|---------------|-------|-------------|
|   0   | read_files    |   6   | web_search  |
|   1   | write_files   |   7   | web_fetch   |
|   2   | edit_files    |   8   | git_commit  |
|   3   | run_bash      |   9   | git_push    |
|   4   | glob_search   |  10   | create_pr   |
|   5   | grep_search   |  11   | manage_pods |

## Verification approach

`HeytingAlgebra CapabilityLevel` is already kernel-checked in `CapabilityLevel.lean`.
`CapabilityLattice = Fin 12 → CapabilityLevel` inherits `HeytingAlgebra` via
Mathlib's `Pi.instHeytingAlgebra` — the universal property of products in **HeytAlg**.
Every lattice law, Heyting adjunction, and pseudo-complement identity that holds for
`CapabilityLevel` is lifted pointwise to the 12-dimensional product by the Lean 4
kernel with no additional proof burden.

Operations are computed pointwise:
- `(a ⊓ b) i = a i ⊓ b i`   (meet = field-wise min)
- `(a ⊔ b) i = a i ⊔ b i`   (join = field-wise max)
- `(a ⇨ b) i = a i ⇨ b i`   (Heyting implication, field-wise)
- `(aᶜ) i    = (a i)ᶜ`       (pseudo-complement, field-wise)
- `⊥ i       = ⊥`             (bottom: all dimensions = Never)
- `⊤ i       = ⊤`             (top: all dimensions = Always)

## Extension dimensions

The Rust `CapabilityLattice` struct contains a 13th dimension —
`extensions: BTreeMap<ExtensionOperation, CapabilityLevel>` — modelled in this file
as the `ExtensionLattice K` Pi type (`K → CapabilityLevel`, defined after `end
CapabilityLattice`). The Heyting adjunction, pseudo-complement, and entailment
equivalence for extension dimensions are **formally kernel-checked** via the
`le_himp_iff_ext`, `inf_compl_eq_bot_ext`, and `le_iff_himp_eq_top_ext` theorems.

The Heyting implication over extensions is:

```
level_implies(a, b) := if a ≤ b then ⊤ (= Always) else b
```

This is identical to `CapabilityLevel.himp` applied to each extension slot.
The adjunction `(c ⊓ a) ≤ b ↔ c ≤ (a ⇨ b)` holds for extensions because
`CapabilityLevel` is a 3-element chain (a Heyting algebra) and `ExtensionLattice K`
is a product of such chains — `Pi.instHeytingAlgebra` lifts the scalar proof to
any key universe `K` without additional axioms.

## Sparse BTreeMap convention and `leq_himp`

The extension map uses a **sparse** BTreeMap representation. There are two distinct
absent-key conventions used in different contexts:

1. **Regular capability set** (enforced access control):
   - Absent key → `Never` (fail-closed security default)
   - Used by `leq()` for policy enforcement: `requested.leq(&allowed)`

2. **Implication result** (output of `implies()`):
   - Absent key → `Always` (mathematically correct: `level_implies(Never,Never) = Always`)
   - `implies()` stores only entries where the result is NOT `Always` (non-trivial restrictions)
   - Used by `leq_himp()` for adjunction checks: `c.leq_himp(&a.implies(&b))`

These two conventions are necessary because `a.implies(b)` cannot enumerate keys
that might appear in a future comparand `c`. The `leq_himp()` method in `HeytingAlgebra`
implements the correct absent-key default for implication results.

**Adjunction correctness**: The adjunction `(c ⊓ a) ≤ b ↔ c ≤ (a ⇨ b)` holds
in Rust for ALL keys (including sparse ones) when `leq_himp()` is used for the RHS:
- Keys in `a ∪ b`: computed pointwise by `implies()`, compared directly
- Keys only in `c` (absent from `a` and `b`): `(c ⊓ a)[K] = min(c[K], Never) = Never ≤ b[K] = Never` (LHS true); `c[K] ≤ Always` (RHS true via absent-key default)

This corresponds to the Pi-type model here: `Fin 12 → CapabilityLevel` has no sparse
keys — all 12 dimensions are always present. The `leq_himp()` method makes the BTreeMap
model agree with the Pi-type model for absent keys.

Extension correctness is verified at three layers:
1. **Lean kernel** (this file): `le_himp_iff_ext`, `inf_compl_eq_bot_ext`,
   `le_iff_himp_eq_top_ext` — formally kernel-checked for any `K`.
2. **Unit tests** in `heyting.rs` (`test_heyting_adjunction_extensions_regression`,
   `test_heyting_adjunction_extensions_exhaustive`,
   `test_heyting_adjunction_extensions_sparse_leq_himp`) — including the sparse-key
   case where `c` has extension key K absent from both `a` and `b`.
3. **Kani harnesses** R7/R8/R9 (and R7a) in `kani.rs` using a 2-slot mock that
   replicates the **production sparse convention**:
   - `ExtMock2::implies()` stores only NON-Always entries (absent slot = Always)
   - `ExtMock2::leq_himp()` uses `Always` as the absent-slot default
   - R7 uses `c.leq_himp(&a.implies(&b))` — exactly the production code path
   - R7a specifically constrains the sparse-key scenario (a=None, b=None, c=Some)
   (BTreeMap is excluded from Kani builds — `#[cfg(not(kani))]` — because heap
   allocations are intractable for bounded model checking)

## Correspondence with Kani harnesses

The Kani harnesses in `portcullis/src/kani.rs` mirror the key theorems proven here:

| Lean theorem              | Kani harness                            | Scope              |
|---------------------------|-----------------------------------------|--------------------|
| `le_himp_iff_lattice`     | `proof_r4_lattice_heyting_adjunction`   | 12-core-field      |
| `inf_compl_eq_bot_lattice`| `proof_r5_lattice_pseudo_complement`    | 12-core-field      |
| `le_iff_himp_eq_top_lattice`| `proof_r6_lattice_entailment`         | 12-core-field      |
| `le_himp_iff_ext`         | `proof_r7_ext_heyting_adjunction`       | Extension (mock)   |
| `inf_compl_eq_bot_ext`    | `proof_r8_ext_pseudo_complement`        | Extension (mock)   |
| `le_iff_himp_eq_top_ext`  | `proof_r9_ext_entailment`               | Extension (mock)   |
| `le_himp_iff_ext`         | `proof_r7a_sparse_key_adjunction`       | Sparse-key case    |

## Build

```bash
cd crates/portcullis-verified/lean
lake build PortcullisVerified
```
-/

import Mathlib.Order.Heyting.Basic
import PortcullisVerified.CapabilityLevel

/-- The production capability lattice as a Pi type over 12 permission dimensions.

    Each `Fin 12` index maps to one core permission field in the Rust `CapabilityLattice`
    struct. Representing the product as a Pi type makes Mathlib's `Pi.instHeytingAlgebra`
    immediately available, lifting the kernel-checked `HeytingAlgebra CapabilityLevel`
    proof to the full 12-dimensional struct without additional axioms. -/
abbrev CapabilityLattice := Fin 12 → CapabilityLevel

namespace CapabilityLattice

/-- `CapabilityLattice` is a `HeytingAlgebra`.

    This instance is supplied by Mathlib's `Pi.instHeytingAlgebra`, which lifts
    `HeytingAlgebra CapabilityLevel` (proven in `CapabilityLevel.lean`) pointwise
    to the product type `Fin 12 → CapabilityLevel`.

    Crucially, every axiom of `HeytingAlgebra` — the adjunction, the pseudo-complement
    law, and all bounded-lattice axioms — is verified by the Lean 4 kernel for the
    **compound struct** that actually gates tool permissions in production, not just
    for the scalar atom. -/
instance instHeytingAlgebra : HeytingAlgebra CapabilityLattice :=
  inferInstance

-- ---------------------------------------------------------------------------
-- R4: Heyting adjunction at the product level
-- ---------------------------------------------------------------------------

/-- **R4 — Adjunction** (product level): `a ≤ b ⇨ c ↔ a ⊓ b ≤ c`.

    Follows directly from the `HeytingAlgebra` typeclass method `le_himp_iff`,
    which the Pi instance resolves pointwise using `CapabilityLevel.le_himp_iff`.
    This is the defining property of the Heyting implication for the full
    12-dimensional `CapabilityLattice`. -/
theorem le_himp_iff_lattice (a b c : CapabilityLattice) :
    a ≤ b ⇨ c ↔ a ⊓ b ≤ c :=
  le_himp_iff a b c

-- ---------------------------------------------------------------------------
-- R5: Pseudo-complement at the product level
-- ---------------------------------------------------------------------------

/-- **R5 — Pseudo-complement** (product level): `a ⊓ aᶜ = ⊥`.

    The Pi instance gives `(aᶜ) i = (a i)ᶜ` and `⊥ i = ⊥`, so
    `(a ⊓ aᶜ) i = a i ⊓ (a i)ᶜ = ⊥` for every `i : Fin 12` by
    `CapabilityLevel.inf_compl_eq_bot`. The equality follows from
    `inf_compl_le_bot` (upper bound) and `bot_le` (lower bound). -/
theorem inf_compl_eq_bot_lattice (a : CapabilityLattice) :
    a ⊓ aᶜ = ⊥ :=
  le_antisymm inf_compl_le_bot bot_le

-- ---------------------------------------------------------------------------
-- R6: Entailment equivalence at the product level
-- ---------------------------------------------------------------------------

/-- **R6 — Entailment** (product level): `a ≤ b ↔ (a ⇨ b) = ⊤`.

    Follows from Mathlib's `himp_eq_top_iff` applied to the Pi `HeytingAlgebra`
    instance. For `CapabilityLattice`, this means: one permission set is ≤ another
    iff their Heyting implication equals the all-`Always` lattice. -/
theorem le_iff_himp_eq_top_lattice (a b : CapabilityLattice) :
    a ≤ b ↔ a ⇨ b = ⊤ :=
  himp_eq_top_iff.symm

-- ---------------------------------------------------------------------------
-- Sanity checks: spot-verify pointwise structure
-- ---------------------------------------------------------------------------

#check @instHeytingAlgebra  -- verifies the instance type-checks

/-- Meet in the product is pointwise. -/
example (a b : CapabilityLattice) (i : Fin 12) :
    (a ⊓ b) i = a i ⊓ b i :=
  Pi.inf_apply a b i

/-- Heyting implication in the product is pointwise. -/
example (a b : CapabilityLattice) (i : Fin 12) :
    (a ⇨ b) i = a i ⇨ b i :=
  Pi.himp_apply a b i

/-- Bottom of the product is pointwise Never. -/
example (i : Fin 12) : (⊥ : CapabilityLattice) i = CapabilityLevel.never :=
  rfl

/-- Top of the product is pointwise Always. -/
example (i : Fin 12) : (⊤ : CapabilityLattice) i = CapabilityLevel.always :=
  rfl

end CapabilityLattice

-- ===========================================================================
-- ExtensionLattice: K-indexed product of CapabilityLevel chains
-- ===========================================================================

/-- An open-ended capability lattice indexed by an arbitrary key type `K`.
    This models the `extensions: BTreeMap<ExtensionOperation, CapabilityLevel>`
    dimension of the Rust `CapabilityLattice` struct, where `K` plays the role
    of `ExtensionOperation`.  Like `CapabilityLattice`, the Pi type inherits
    `HeytingAlgebra` pointwise from `HeytingAlgebra CapabilityLevel` via
    `Pi.instHeytingAlgebra`. -/
abbrev ExtensionLattice (K : Type*) := K → CapabilityLevel

namespace ExtensionLattice

/-- `ExtensionLattice K` is a `HeytingAlgebra` for any key type `K`.

    Supplied by Mathlib's `Pi.instHeytingAlgebra`, which lifts
    `HeytingAlgebra CapabilityLevel` pointwise to `K → CapabilityLevel`.
    No cardinality constraint on `K` is required — the Pi construction
    works for any `Type*`. -/
instance instExtHeytingAlgebra (K : Type*) : HeytingAlgebra (ExtensionLattice K) :=
  inferInstance

-- ---------------------------------------------------------------------------
-- R7: Heyting adjunction for the extension lattice
-- ---------------------------------------------------------------------------

/-- **R7 — Adjunction** (extension level): `a ≤ b ⇨ c ↔ a ⊓ b ≤ c`.

    Identical proof term to `le_himp_iff_lattice`: `le_himp_iff` is stated with
    implicit arguments over any `GeneralizedHeytingAlgebra`, so Lean resolves it
    to `Pi.instGeneralizedHeytingAlgebra` for `K → CapabilityLevel`. -/
theorem le_himp_iff_ext {K : Type*} (a b c : ExtensionLattice K) :
    a ≤ b ⇨ c ↔ a ⊓ b ≤ c :=
  le_himp_iff

-- ---------------------------------------------------------------------------
-- R8: Pseudo-complement for the extension lattice
-- ---------------------------------------------------------------------------

/-- **R8 — Pseudo-complement** (extension level): `a ⊓ aᶜ = ⊥`.

    Uses `inf_compl_self` — the canonical Mathlib name for this equality in a
    `HeytingAlgebra`.  (`inf_compl_le_bot` is a field of `BooleanAlgebra`, not
    available here; `inf_compl_eq_bot` is an alias for `inf_compl_self`.) -/
theorem inf_compl_eq_bot_ext {K : Type*} (a : ExtensionLattice K) :
    a ⊓ aᶜ = ⊥ :=
  inf_compl_self a

-- ---------------------------------------------------------------------------
-- R9: Entailment equivalence for the extension lattice
-- ---------------------------------------------------------------------------

/-- **R9 — Entailment** (extension level): `a ≤ b ↔ (a ⇨ b) = ⊤`.

    Identical proof term to `le_iff_himp_eq_top_lattice`: `himp_eq_top_iff` is
    stated with implicit arguments over any `GeneralizedHeytingAlgebra`. -/
theorem le_iff_himp_eq_top_ext {K : Type*} (a b : ExtensionLattice K) :
    a ≤ b ↔ a ⇨ b = ⊤ :=
  himp_eq_top_iff.symm

end ExtensionLattice
