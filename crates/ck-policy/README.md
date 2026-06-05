# ck-policy

Constitutional Kernel — the monotonicity checker at the core of amendment
admission.

[![docs.rs](https://img.shields.io/docsrs/ck-policy)](https://docs.rs/ck-policy)

A single **pure function**, `check_monotonicity(parent, child)`, decides whether
an ordinary amendment from one [`PolicyManifest`](../ck-types) to another
preserves constitutional order. No I/O, no side effects — it compares two
manifests and reports any violations as a `MonotonicityVerdict`.

## The four invariants

An ordinary amendment is admissible only if, for every invariant its parent
manifest requires, the child does not loosen it:

| # | Invariant | Rule |
|---|---|---|
| 1 | Capability non-escalation | `Cap(child) ⊆ Cap(parent)` |
| 2 | I/O confinement | `IO(child) ⊆ IO(parent)` |
| 3 | Resource boundedness | `Budget(child) ≤ Budget(parent)` |
| 4 | Governance monotonicity | `ProofReq(child) ⊇ ProofReq(parent)` |

Each check is gated by the parent's `amendment_rules` (e.g.
`require_monotone_capabilities`), so a manifest opts in to exactly the invariants
it wants enforced. The returned `MonotonicityVerdict` carries `passed` plus a
`PolicyDiffReport` enumerating any escalations found.

## Usage

```rust,ignore
use ck_policy::check_monotonicity;

let verdict = check_monotonicity(&parent_manifest, &child_manifest);
if !verdict.passed {
    // verdict.diff lists exactly which invariant(s) the child violated
    return Err(/* refuse the amendment */);
}
```

## Scope

Types-only dependency on [`ck-types`](../ck-types); the schemas live there, the
decision lives here. Because the checker is pure, it is trivially testable and is
the natural target for formal verification of the non-escalation property.

## License

MIT
