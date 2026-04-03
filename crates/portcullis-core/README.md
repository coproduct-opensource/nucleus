# portcullis-core

Core capability lattice types -- the Aeneas verification target.

This crate extracts the minimal, dependency-free types that form the permission lattice verified by Lean 4 HeytingAlgebra proofs. By default it has **zero dependencies**, enabling the [Aeneas](https://github.com/AeneasVerif/aeneas) Rust-to-Lean translator to produce pure functional Lean code.

## Why a Separate Crate?

The full `portcullis` crate imports serde, BTreeMap, chrono, uuid, etc. which Aeneas cannot model. This crate contains only what can be:

1. **Translated to Lean 4** via Aeneas (Rust MIR -> Lean)
2. **Proven correct** against Mathlib's HeytingAlgebra

The verified type IS the production type -- `portcullis` re-exports `CapabilityLevel` from this crate.

## Key Types

| Type | Purpose |
|------|---------|
| `CapabilityLevel` | 3-element total order: `Never < LowRisk < Always` |
| `CapabilityLattice` | Product of 13 capability dimensions |
| `IFCLabel` | Information flow control label (confidentiality, integrity, provenance, authority, derivation) |
| `ConfLevel`, `IntegLevel` | Confidentiality/integrity levels for IFC |
| `DerivationClass` | Deterministic vs AI-derived data classification |
| `SinkClass` | 13 typed sink categories (workspace, system, HTTP, git, etc.) |
| `FlowNode`, `NodeKind` | Causal flow graph nodes (20 variants including multimodal) |
| `WitnessBundle` | Data flow verification proof artifact |
| `FieldEnvelope` | Labeled container for per-field provenance |
| `ProvenanceSchema` | Declarative field derivation methodology |
| `DeclassificationToken` | Time-bounded, HMAC-signed controlled information release |

## Feature Flags

| Feature | Dependencies Added | Purpose |
|---------|-------------------|---------|
| `serde` | serde, toml | Serialization for production use |
| `artifact` | serde, serde_json, sha2 | Provenance output types |
| `envelope` | sha2 | Field envelopes and witness bundles |
| `attestation` | sha2 | Attestation hashing |
| `wasm-sandbox` | wasmtime, sha2 | WASM parser execution |
| `c2pa-manifest` | c2pa | C2PA content credential manifests |

## Verification Pipeline

```
portcullis-core (this crate)
    -> Charon (rustc nightly, MIR extraction)
    -> Aeneas (OCaml, LLBC -> Lean 4 translation)
    -> PortcullisCore.lean (generated Lean model)
    -> Mathlib HeytingAlgebra proof (kernel-checked)
```

See [`FORMAL_METHODS.md`](../../FORMAL_METHODS.md) for the full verification story.
