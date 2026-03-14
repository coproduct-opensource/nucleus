# Nucleus v1.0 Stability Guarantees

This document defines what is frozen at v1.0 and what remains open for extension.
Breaking a frozen contract requires a major version bump (v2.0).

## Frozen Contracts

These interfaces are load-bearing walls. Changing them breaks downstream consumers
and invalidates Verus verification conditions.

| Contract | Frozen Element | Verified By |
|----------|---------------|-------------|
| **Operations** | 12 core `Operation` enum variants + exposure classifications | Verus VCs, conformance tests |
| **Exposure Labels** | 3 core `ExposureLabel` variants + uninhabitable state predicate | Verus VCs (E1-E3, M1-M8) |
| **CapabilityLevel** | `Never`, `LowRisk`, `Always` as named constants | Verus VCs, lattice law tests |
| ** Uninhabitable state Predicate** | `is_uninhabitable()` examines only core 3 labels | Verus VCs |
| **PodSpec** | `apiVersion: nucleus/v1`, field names, policy profile names | Integration tests |
| **MCP Tools** | `read`, `write`, `run`, `glob`, `grep`, `web_fetch` | Tool-proxy tests |
| **gRPC** | `nucleus.node.v1.NodeService` RPCs and message field numbers 1-8 | Proto compatibility |
| **HMAC Protocol** | Header names (`x-nucleus-signature`, etc.), SHA-256 algorithm | Auth tests |
| **Audit v1** | Entry fields (sequence through prev_hash), SHA-256 hash chain | Chain verification tests |
| **Receipt v1** | Field set (pod_id through spiffe_id), `v1_content_hash` algorithm | Receipt verification |

## Open Extension Points

These mechanisms allow growth without breaking v1.0 contracts or invalidating proofs.

| Extension Point | Mechanism | Default Behavior |
|----------------|-----------|-----------------|
| New operations | `CapabilityLattice.extensions: BTreeMap<ExtensionOperation, CapabilityLevel>` | Unknown ops default to `Never` (fail-closed) |
| New exposure labels | `ExposureSet.extensions: BTreeSet<ExtensionExposureLabel>` | Extension labels don't affect core uninhabitable state |
| New constraints | `ConstraintNucleus.additional: Vec<UninhabitableState>` | Only uninhabitable state in slot 0; additional combos add obligations |
| New capability levels | Future u16 values between existing constants (v1.1+) | Unknown string values deserialize to `Never` |
| New receipt fields | `ExecutionReceipt.extensions: BTreeMap<String, String>` + `version` bump | v1 verifiers check `v1_content_hash`, ignore extensions |
| New audit fields | `AuditEntry.extensions: BTreeMap<String, String>` + `schema_version` bump | v1 `content_hash()` only covers v1 fields |
| Multi-agent | `WorkspaceGuard` trait (interface only in v1.0) | Single-agent `GradedExposureGuard` is the v1 implementation |

## Why Proofs Survive Extensions

The extension points are designed so that existing Verus verification conditions
remain valid without re-verification:

1. **Product lattice**: `CapabilityLevel^12` extended to `CapabilityLevel^(12+E)` via
   `BTreeMap`. Lattice laws hold by the universal property of products in **Lat** —
   the product of lattices is a lattice, regardless of indexing set cardinality.

2. **Powerset embedding**: `ExposureSet` extension labels form a separate `BTreeSet`.
   The join-semilattice law (monotonicity under union) holds for any set, and the
   core uninhabitable state predicate only examines the frozen 3-bool core.

3. **Nucleus composition**: Each `UninhabitableState` is a deflationary endomorphism
   (only adds obligations). Composition of deflationary endomorphisms is deflationary.
   The uninhabitable state remains slot 0 and is always applied first.

## Proof Obligations for Extensions

When adding a new `UninhabitableState`, the implementor must demonstrate:

1. The combo's nucleus is deflationary (only adds obligations, never removes)
2. Property tests pass for the combo (template in `uninhabitable_state.rs` tests)
3. The combo composes correctly with existing constraints

No Verus re-verification is needed for extensions that follow these rules.

## Serde Compatibility

All extension fields use `#[serde(default)]` and `#[serde(skip_serializing_if = "...")]]`:

- Old YAML/JSON without extension fields deserializes correctly (defaults to empty)
- New YAML/JSON with extension fields is ignored by old consumers
- Unknown `CapabilityLevel` string values should be treated as `Never` (fail-closed)
- Unknown `Operation` string values in extensions are handled by `ExtensionOperation`

## Version Negotiation

- `ExecutionReceipt.version`: Schema version (1 for v1.0). Verifiers that don't
  understand version N fall back to verifying `v1_content_hash` over fields 1-8.
- `AuditEntry.schema_version`: Entry schema version (1 for v1.0). The hash chain
  algorithm for v1 fields is frozen. Extension fields are not included in v1 hashes.
