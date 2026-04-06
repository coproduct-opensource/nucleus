# IFC Semilattice: Information Flow as Lattice Join

The `IFCLabel` system is a **product semilattice** with mixed variance — some
dimensions are covariant (join = max) and others are contravariant (join = min).
This mixed structure is the formal encoding of Denning's lattice model adapted
for AI agent data flow.

## The Product Lattice

`IFCLabel` is a product of six ordered dimensions:

```
IFCLabel = ConfLevel × IntegLevel × AuthorityLevel × ProvenanceSet × Freshness × DerivationClass
```

Each dimension is a bounded lattice with its own ordering:

| Dimension | Order | Variance | Join semantics |
|---|---|---|---|
| `ConfLevel` | Public < Internal < Secret | Covariant | max (most restrictive wins) |
| `IntegLevel` | Adversarial < Untrusted < Trusted | **Contravariant** | min (least trusted wins) |
| `AuthorityLevel` | NoAuthority < Informational < Suggestive < Directive | **Contravariant** | min (least authority wins) |
| `ProvenanceSet` | Bitset inclusion | Covariant | union (all sources tracked) |
| `Freshness` | Newer/longer ≤ older/shorter | Covariant | oldest timestamp, shortest TTL |
| `DerivationClass` | Deterministic < AIDerived/HumanPromoted < Mixed < OpaqueExternal | Covariant | max (most tainted wins) |

## Why Mixed Variance?

The variance encodes the security intuition directly:

**Covariant dimensions** (join = max/union) track what the data *is*:
- Confidentiality: mixing Secret with Public produces Secret (the combo is at
  least as sensitive as the most sensitive input)
- Provenance: mixing USER data with WEB data produces {USER, WEB} (both
  sources are tracked)
- Derivation: mixing Deterministic with AIDerived produces AIDerived (the
  combo has AI-derived components)

**Contravariant dimensions** (join = min) track what the data *can do*:
- Integrity: mixing Trusted with Adversarial produces Adversarial (one drop
  of poison contaminates the whole)
- Authority: mixing Directive with NoAuthority produces NoAuthority (the combo
  cannot steer the agent if any component can't)

This is the **Biba integrity model** (contravariant integrity) combined with
the **Bell-LaPadula model** (covariant confidentiality) in a single product
lattice.

## The Join as a Functor

Label propagation through the flow graph is a **join-semilattice homomorphism**.
When data from nodes A and B combines to form node C:

```
label(C) = label(A) ⊔ label(B) ⊔ intrinsic(C)
```

Where `⊔` is the pointwise join defined above, and `intrinsic(C)` is the
base label for node C's kind (e.g., `ModelPlan` has `derivation: AIDerived`).

This is a functor from the **flow graph category** (nodes as objects, data
flow edges as morphisms) to the **label lattice** (labels as objects, ≤ as
morphisms):

```
F : FlowGraph → LabelLattice
F(n) = label(n)
F(n → m) = label(n) ≤ label(m)    (labels only increase along flow edges)
```

**Monotonicity**: if data flows from A to B, then `label(A) ≤ label(B)`.
This is the fundamental IFC invariant — labels never decrease along the
flow direction.

## Absorption Properties

The lattice has absorption elements — values that dominate the join:

**Integrity**: `Adversarial ⊓ x = Adversarial` for all x.
Once any adversarial data enters a computation, all outputs are adversarial.
*Proved in Lean*: `integ_inf_adversarial_left`, `integ_inf_adversarial_right`.

**Confidentiality**: `Secret ⊔ x = Secret` for all x.
Once secret data enters a computation, all outputs are secret.
*Proved in Lean*: `conf_sup_secret_left`, `conf_sup_secret_right`.

**Derivation**: `OpaqueExternal.join(x) = OpaqueExternal` for all x.
Once opaque external data enters, the derivation class saturates at the top.
*Proved in Lean*: `join_opaque_left`, `join_opaque_right`.

These absorption properties are the formal encoding of "contamination is
permanent" — the core security guarantee.

## The Session Ceiling as a Colimit

`FlowTracker::session_taint_ceiling` is the **colimit** of all derivation
classes observed in the session:

```
ceiling = ⊔ { label(n).derivation | n ∈ session_nodes }
```

Because join is monotone, this is a monotonically non-decreasing function
of the session's history. It is the "high-water mark" — once the session
has seen OpaqueExternal content, the ceiling stays there.

The confidentiality ceiling (`session_conf_ceiling`) is the analogous
colimit for confidentiality:

```
conf_ceiling = max { label(n).confidentiality | n ∈ session_nodes }
```

Together, these ceilings provide **session-level** IFC guarantees that
complement the per-node guarantees of the flow graph.

## Verification Status

| Property | Tool | Reference |
|---|---|---|
| Join commutativity | Lean 4 | `ifc_join_comm` |
| Join associativity | Lean 4 | `ifc_join_assoc` |
| Join idempotency | Lean 4 | `ifc_join_idempotent` |
| Adversarial absorption | Lean 4 | `integ_inf_adversarial_left/right` |
| Secret absorption | Lean 4 | `conf_sup_secret_left/right` |
| No silent cleansing | Lean 4 + Kani | `no_silent_cleansing`, `proof_derivation_no_silent_cleansing` |
| Join monotonicity | Lean 4 + Kani | `join_monotone_left`, `proof_derivation_join_monotone` |
| Distributivity | Lean 4 | `ifc_join_left_distributes` |
| Taint propagation (end-to-end) | Lean 4 | `invariant_exploit_propagates_taint` |
