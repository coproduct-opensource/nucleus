# Nucleus Verified Claims Matrix

This document tracks the formal verification status of Nucleus's core safety claims.
Each claim progresses through a verification ladder, from unverified design intent
through machine-checked proof.

## Status Definitions

| Status | Meaning |
|--------|---------|
| **Unverified** | Claim is stated as a design goal but has no formal backing yet. |
| **Specified** | An executable spec (TLA+, Python model, or equivalent) captures the claim. |
| **Model-checked** | The spec has been model-checked (e.g., TLC, Alloy) against the claim. |
| **Machine-proved** | A machine-checked proof (Lean, Coq, Kani, or Verus) establishes the claim. |

## Claims Matrix

| Claim ID | Claim Description | Status | Proof Artifact | Code Path | Last Verified Commit |
|----------|-------------------|--------|----------------|-----------|----------------------|
| VC-001 | **Monotonicity** — authority can only tighten during execution. Once a session starts, no operation can widen the set of granted capabilities. | Machine-proved | `crates/portcullis/src/kani.rs` — `proof_normalize_monotone`, `proof_normalize_deflationary`; `crates/portcullis-verified/src/lib.rs` (Verus conformance) | `crates/portcullis/src/lattice.rs`, `crates/portcullis/src/capability.rs` | CI-verified |
| VC-001a | **Lattice distributivity** — capability meet distributes over join. | Machine-proved | `crates/portcullis/src/kani.rs` — `proof_capability_distributive` | `crates/portcullis/src/capability.rs` | CI-verified |
| VC-001b | **Normalization idempotence** — normalizing a permission twice yields the same result as once. | Machine-proved | `crates/portcullis/src/kani.rs` — `proof_normalize_idempotent` | `crates/portcullis/src/lattice.rs` | CI-verified |
| VC-002 | **Complete mediation** — no side effect bypasses the kernel. Every I/O operation (filesystem, network, process spawn) is intercepted and evaluated by the Nucleus kernel before execution. | Unverified | — | `crates/nucleus-tool-proxy/src/policy.rs`, `crates/portcullis/src/guard.rs` | — |
| VC-003 | **Sink safety** — exposed data cannot reach a sink without approval. Data originating from untrusted sources carries exposure_correctness` | `crates/portcullis/src/exposure_core.rs`, `crates/portcullis/src/guard.rs` | CI-verified |
| VC-003a | **Exposure monotonicity** — exposure never decreases under union. | Machine-proved | `crates/portcullis/src/kani.rs` — `proof_exposureset_union_monotone` | `crates/portcullis/src/exposure_core.rs` | CI-verified |
| VC-003b | **Exposure monoid laws** — ExposureSet union is associative, commutative, and idempotent with empty as identity. | Machine-proved | `crates/portcullis/src/kani.rs` — `proof_exposureset_monoid_identity`, `proof_exposureset_monoid_laws` | `crates/portcullis/src/exposure_core.rs` | CI-verified |
| VC-003c | **Operation exposure completeness** — all operations map to the correct exposure labels. | Machine-proved | `crates/portcullis/src/kani.rs` — `proof_operation_exposure_completeness` | `crates/portcullis/src/kani.rs` | CI-verified |
| VC-004 | **No ambient authority** — agent process has no direct capabilities. The agent process runs with zero ambient I/O permissions; all authority is granted via typed handles from the kernel. | Unverified | — | `crates/nucleus/src/sandbox.rs`, `crates/nucleus/src/pod.rs` | — |
| VC-005 | **Trace completeness** — all mediated actions produce audit records. Every decision made by the kernel (allow, deny, attenuate) is recorded in a tamper-evident trace log. | Unverified | — | `crates/portcullis/src/audit.rs` | — |

## How to update this matrix

1. **Adding a claim:** append a new row with a unique `VC-XXX` identifier and set status to `Unverified`.
2. **Advancing status:** update the status column and fill in the proof artifact path, code path, and commit hash. Link the proof artifact in the repository so reviewers can inspect it.
3. **CI integration:** once a claim reaches `Model-checked` or `Machine-proved`, add a CI gate that re-verifies the claim on every commit touching the relevant code path.

## Relationship to the North Star

These claims operationalize the **Flagship Safety Claim** from [`NORTH_STAR.md`](./NORTH_STAR.md):

> No external side effect occurs unless it is mediated by Nucleus and authorized by a policy that can only stay the same or tighten during execution.

Each verified claim covers one facet of that top-level guarantee:

- **VC-001** (Monotonicity) ensures authority cannot escalate.
- **VC-002** (Complete mediation) ensures nothing bypasses the kernel.
- **VC-003** (Sink safety) ensures exposed data is gated.
- **VC-004** (No ambient authority) ensures the agent starts with nothing.
- **VC-005** (Trace completeness) ensures auditability of every decision.
