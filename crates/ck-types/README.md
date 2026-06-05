# ck-types

Constitutional Kernel — core types, manifests, digests, and the policy lattice.

[![docs.rs](https://img.shields.io/docsrs/ck-types)](https://docs.rs/ck-types)

The foundational data structures for **proof-carrying constitutional
self-amendment**: the schemas a system uses to describe what it is allowed to
do, to evidence a proposed change, and to record the terminal decision about
whether that change is admitted.

## Core types

| Type | Role |
|---|---|
| `PolicyManifest` | canonical schema for capabilities, I/O surface, budgets, and proof requirements (`CapabilitySet`, `IoSurface`, `BudgetBounds`, `ProofRequirements`, `AmendmentRules`) |
| `WitnessBundle` | canonical evidence schema for amendment admission (`AdmissionMode`, `SignatureVerifier`) |
| `PatchClass` | categorization of self-modification danger levels |
| `ArtifactDigest` | content-addressed artifact references |
| `AdmissionDecision` | terminal state of the amendment pipeline |

## Patch classes

`PatchClass` determines which proof obligations must be satisfied before a
self-modification is admitted, in increasing order of danger:

| Class | Covers |
|---|---|
| `Config` | config, thresholds, prompts, eval-suite additions |
| `Controller` | scheduler, routing, work-state transitions, budget-ledger logic |
| `Evaluator` | proposer, evaluator, search strategy, scoring logic |
| `Constitutional` | constitutional / kernel-adjacent changes — **requires human approval** |

## Scope

This crate is **types only** — serializable schemas (serde) plus content-address
digests (BLAKE3). The admission logic that consumes them lives in the sibling
`ck-policy` / `ck-kernel` crates; keeping the schemas dependency-light lets every
layer share one source of truth for the manifest and witness formats.

## License

MIT
