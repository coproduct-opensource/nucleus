# Constitutional Kernel Spec v0.1

> Build the smallest kernel that can reject self-serving amendments even
> when the proposer is clever.

## Aim

Build a self-amending controller that may improve its own implementation
without unilaterally increasing its power, and that emits machine-checkable
evidence that constitutional invariants were preserved across each accepted
transition.

## Core Rule

**Competence may increase. Authority may not increase without explicit
higher-order authorization.**

## System Model

A versioned governed artifact:

```
A_i = (Code_i, Config_i, Policy_i, Budget_i, IO_i, Cap_i, ProofReq_i, EvalSuite_i)
```

A transition `A_i -> A_{i+1}` is accepted only if a witness bundle proves
the required obligations.

## Constitutional Contract (5 invariants)

### 1. Capability Non-Escalation

```
Cap(A_{i+1}) ⊆ Cap(A_i)   [ordinary path]
```

Capabilities: filesystem read/write roots, allowed tools, network domains,
secret classes, code execution authority, patch classes, max parallel tasks.

### 2. I/O Confinement

```
IO(A_{i+1}) ⊆ IO(A_i)   [ordinary path]
```

I/O surface: outbound domains, local file roots, env vars, secrets mount
classes, tool namespaces, IPC channels, repo write targets.

### 3. Resource Boundedness

```
BudgetUsage(run) ≤ BudgetBound(A_i)
```

Budget dimensions: max tokens, max wall-clock, max CPU-seconds, max memory,
max network calls, max files touched, max dollar spend, max patch attempts.

### 4. Governance Monotonicity (anti-coup rule)

```
ProofReq(A_{i+1}) ⊇ ProofReq(A_i)   [ordinary path]
```

Future amendment burden may stay the same or become stricter, never looser.

### 5. Bounded Termination / Progress

Every amendment attempt terminates with: Accepted | Rejected | Quarantined | Expired.

## Patch Classes

- **Class A** (config/eval): schema validation, build, replay, budget check, policy subset
- **Class B** (controller logic): + Kani proofs, progress check, golden trace replay
- **Class C** (proposer/evaluator/meta-search): + adversarial replay, spec-gaming regression
- **Class D** (constitutional/kernel): requires human threshold approval, external review

## Amendment State Machine

```
Draft -> Normalized -> Built -> SandboxedEval -> Verified -> Replayed
  -> Admitted | Rejected | Quarantined | Expired
```

## Admission Rule

```
Accept(P -> C) iff:
  1. ParentDigest is known and admitted
  2. Class(C) is well-formed
  3. Cap(C) ⊆ Cap(P)           [unless constitution path]
  4. IO(C) ⊆ IO(P)             [unless constitution path]
  5. BudgetBound(C) ≤ BudgetBound(P)  [unless constitution path]
  6. ProofReq(C) ⊇ ProofReq(P)        [ordinary path]
  7. All required witness artifacts present and valid
  8. All required verifiers return pass
  9. Replay suite passes within budget
  10. Lineage record appended atomically
```

## Minimal Viable Claim

> We built a self-amending controller whose accepted changes are constrained
> by a constitutional kernel enforcing capability non-escalation, I/O
> confinement, bounded resource laws, governance monotonicity, and replayable
> evidence-backed admission.

## Implementation Phases

- **Phase 1 (Hard Shell)**: policy manifest, monotonicity checker, witness bundle, lineage store, kernel admission, CI wiring
- **Phase 2 (Controller Proofs)**: Kani harnesses, retry/progress model, budget proofs, adversarial replay
- **Phase 3 (Meta-Amendment)**: patch classes B/C governed, evaluator/proposer amendments, constitution-change workflow

See full spec for witness bundle format, policy model, capability lattice,
Kani targets, replay suites, threat model, and human override model.
