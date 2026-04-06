# Repair Algebra: Policy Denial as Program Rewriting

This document describes the categorical structure of the nucleus repair
system — the `RepairHint::try_repair()` mechanism that transforms denied
`ActionTerm`s into admissible ones.

## Overview

When `preflight_action(term)` returns `Denied { hint }`, the hint is not
diagnostic text — it is a **morphism** in the category of ActionTerms. Applying
it produces a new term that passes the specific obligation check that failed.

```
deny(term)                    → (reason, hint)
hint.try_repair(term)         → Some(repair)
preflight(repair.term())      → Allowed   (for the check that denied)
```

This is the first agent security framework where policy denial is a
**program transformation**, not a dead end.

---

## Layer 1: Retraction

For each obligation check C in {IntegrityGate, PathAllowed, DerivationClear,
NoAdversarialAncestry, BudgetNotExceeded}, partition the ActionTerm space:

```
Pass_C = { t ∈ ActionTerm | check_C(t) = pass }
Fail_C = { t ∈ ActionTerm | check_C(t) = fail }
```

The repair function for check C is:

```
repair_C : Fail_C → Pass_C
```

This is a **retraction** — a left inverse of the inclusion `Pass_C ↪ ActionTerm`.

**Idempotency**: `repair_C(repair_C(t)) = repair_C(t)`. A repaired term is
already in `Pass_C`, so applying repair again is identity. This is tested by
`full_deny_repair_retry_loop`: deny → repair → allow, and preflight on the
repaired term never re-triggers the same check.

**Implementation**: each `RepairHint` variant maps to exactly one check and
modifies only the fields that check examines:

| Hint | Check | Fields modified |
|---|---|---|
| `RaiseIntegrity` | IntegrityGate | `artifact_label.integrity` |
| `CorrectOperationSinkPair` | PathAllowed | None (terminal — no auto-fix) |
| `PromoteDerivation` | DerivationClear | `artifact_label.derivation` |
| `DeclassifyOrReplaceInput` | NoAdversarialAncestry | `source_labels` (filter) |
| `WireBudgetGate` | BudgetNotExceeded | `estimated_cost_micro_usd` |

---

## Layer 2: Galois Connection

The obligation set `S ⊆ Obligations` induces a **closure operator** on
ActionTerms:

```
Admit(S) = { t ∈ ActionTerm | ∀ C ∈ S, check_C(t) = pass }
```

Properties:

```
S₁ ⊆ S₂           ⟹  Admit(S₂) ⊆ Admit(S₁)         (antitone)
Admit(S₁ ∪ S₂)     =  Admit(S₁) ∩ Admit(S₂)          (intersection)
Admit(∅)            =  ActionTerm                       (vacuously true)
Admit(Obligations)  =  { t | preflight(t) = Allowed }  (fully constrained)
```

The repair system is the **left adjoint**:

```
Repair(S) : ActionTerm → Admit(S)
```

The **Galois connection** between the obligation lattice (ordered by ⊆) and
the ActionTerm powerset (ordered by ⊆):

```
Repair(S)(t) ∈ Admit(S)   ⟺   t is repairable for S
```

`Admit` is the upper (right) adjoint. `Repair` is the lower (left) adjoint.

### Composability theorem

Repairing for S₁ then S₂ equals repairing for S₁ ∪ S₂:

```
Repair(S₂)(Repair(S₁)(t)) = Repair(S₁ ∪ S₂)(t)
```

This holds because each `repair_C` modifies disjoint fields. The IntegrityGate
repair touches `artifact_label.integrity`; the BudgetNotExceeded repair touches
`estimated_cost_micro_usd`; the NoAdversarialAncestry repair touches
`source_labels`. Since the field sets are disjoint, the repairs commute and
compose.

**Practical implication**: if a term fails two checks, the agent can apply both
repairs in any order and get the same result. There is no "repair ordering"
problem.

### Optimality

The repair is **minimal** — it modifies the fewest fields needed to enter
`Admit(S)`. This follows from the construction: each repair_C modifies exactly
the field that C examines, and sets it to the minimum value that satisfies C.

For example, `RaiseIntegrity` sets `artifact_label.integrity = required` — the
minimum integrity that passes IntegrityGate, not `Trusted` unconditionally.

---

## Layer 3: Free-Forgetful Adjunction

Define two categories:

**Raw** — the category of "proposed actions"
- Objects: `ActionTerm` values
- Morphisms: field transformations (label changes, source filtering, cost adjustment)

**Checked** — the category of "authorized actions"
- Objects: `(ActionTerm, DischargedBundle)` pairs
- Morphisms: pairs of term transformations that preserve the bundle's validity

Two functors connect them:

```
F : Raw → Checked       F(t) = (t, preflight(t))     when preflight succeeds
U : Checked → Raw       U(t, b) = t                   forgetful (drops proof)
```

The repair system provides the **unit** of the adjunction F ⊣ U:

```
η_t : t → U(F(Repair(t)))
```

For any raw term t:
- If `preflight(t)` succeeds, η is identity (t is already in the image of F)
- If `preflight(t)` fails with hint h, then `η(t) = U(F(h.try_repair(t)))` —
  the repair lifts t into Checked, and the forgetful functor projects back

The **counit** is trivial:

```
ε_(t,b) : F(U(t, b)) → (t, b)
```

A checked term, forgotten and re-checked, produces the same bundle (preflight
is deterministic).

### The triangle identities

```
U ε ∘ η U = id_U        (forget, re-check, forget = just forget)
ε F ∘ F η = id_F        (repair, check, check-the-repair = just check)
```

Both hold because:
1. Preflight is deterministic on the same term
2. Repair produces terms that pass preflight (retraction property)

### The approval gate as a lifting condition

The `NeedsApproval` variant in `Repair` is where the adjunction "pauses."
The left adjoint has computed the target term in Checked, but the morphism
from Raw to Checked factors through a **human authorization gate**:

```
            repair
  Raw ──────────────► Checked
   │                     ▲
   │                     │ approval (natural transformation)
   ▼                     │
  NeedsApproval ─────────┘
```

The approval gate is a **natural transformation** α : G → F where G is the
"partially repaired" functor. Naturality means: approval commutes with further
term transformations. If you modify a term after repair but before approval,
the approval still applies — it's the *obligation* that's approved, not the
specific term.

This is why `Repair::NeedsApproval` carries a `gate: String` describing the
obligation, not the term: the approval is on the obligation class, not the
instance.

---

## Soundness Theorem (Informally)

For each `RepairHint` variant H and its corresponding check C:

```
∀ t ∈ ActionTerm,
  H.try_repair(t) = Some(Repair::Automatic(t'))  ⟹  check_C(t') = pass
  H.try_repair(t) = Some(Repair::NeedsApproval { term: t', .. })  ⟹  check_C(t') = pass
  H.try_repair(t) = None  ⟹  H = CorrectOperationSinkPair (structural, no auto-fix)
```

This is tested empirically by `repair_budget_is_automatic_and_zeroes_cost`,
`repair_adversarial_ancestry_strips_tainted_sources`, and the end-to-end
`full_deny_repair_retry_loop`. A Lean proof via Aeneas extraction is tracked
as future work (#1209).

---

## Relationship to Other Formal Structures

| Structure | Where in nucleus | Role |
|---|---|---|
| Belnap bilattice | `bilattice.rs` | Policy verdict algebra |
| Heyting algebra | `CapabilityLattice` | Permission composition |
| IFC semilattice | `IFCLabel::join` | Taint propagation |
| Galois connection | Repair system | Obligation↔admissibility duality |
| Free-forgetful adjunction | Discharge + repair | Raw→checked canonical path |
| Retraction | Per-check repair | Idempotent deny→fix cycle |

The repair algebra sits at the top of this hierarchy: it consumes the outputs
of all other structures (IFC labels, capability checks, derivation classes)
and provides the universal mechanism for converting policy denials into
policy-compliant actions.
