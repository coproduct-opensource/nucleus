# ck-kernel

Constitutional Kernel — the admission engine and lineage store.

[![docs.rs](https://img.shields.io/docsrs/ck-kernel)](https://docs.rs/ck-kernel)

The kernel is the smallest component that can **reject self-serving amendments
even when the proposer is clever**. It is the trust root of constitutional
self-amendment: it does not know about prompts, LLM reasoning, or task semantics
— only about whether a candidate change is admissible.

## What `admit` checks

For each `CandidateAmendment`, the `Kernel` verifies, in order:

1. **Structure** — the candidate is well-formed and names a known parent.
2. **Monotonicity** — constitutional invariants are preserved (delegated to
   [`ck-policy`](../ck-policy)'s `check_monotonicity`).
3. **Evidence** — the `WitnessBundle` is complete and its signatures valid.
4. **Lineage** — on acceptance, the record is appended **atomically** to the
   `LineageStore`.

It returns an `AdmissionDecision` (`Accepted { … }` with lineage/witness
digests, or a rejection carrying a `RejectionReason`). `Constitutional`-class
patches go through `admit_constitutional`, which requires human approval.

## Signature policy — no silent "off"

```rust,ignore
use ck_kernel::{Kernel, SignaturePolicy};

// Production MUST use Enforced:
let mut kernel = Kernel::new(genesis_digest);
let decision = kernel.admit(candidate); // verifies Ed25519 witness signatures
```

`SignaturePolicy` has exactly two variants — `Enforced(verifier)` and
`SkipForTesting` — with no implicit default. `SkipForTesting` is named so that
any accidental production use is glaring in code review.

## Formal verification

The monotonicity-violation detectors are checked by **Kani** bounded model
checking (`src/kani.rs`), e.g. `proof_budget_escalation_detected`,
`proof_capability_escalation_detected_bitmask`,
`proof_io_confinement_detected_bitmask` — proving the kernel *detects* each class
of escalation rather than relying on tests alone.

## License

MIT
