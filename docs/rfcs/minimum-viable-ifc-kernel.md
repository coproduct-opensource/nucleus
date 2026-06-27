# RFC: Minimum Viable IFC Kernel — carve the verified reference monitor out of portcullis-core

Status: Draft (rung 0 — boundary + ratchet)
Related: `multi-hop-noninterference-unwinding.md` (D1), `guaranteed-safe-recursion.md`, the Aeneas-extracted IFC slices (#1906), `nucleus-recompute` conformance harness (#1907 + follow-ons).

## Problem

`portcullis-core` is **38,517 LOC across 58 modules**. The formally-relevant
core — the part the IFC non-interference theorems are actually proven over and
the part a relying party must trust — is a small fraction of that. Today "the IFC
gate is verified" implicitly asks an auditor (or ARIA) to trust the whole 38.5k
LOC, because nothing draws the line between *the reference monitor* and *the
downstream machinery that should not be able to bypass it*.

A reference monitor (Anderson 1972) must be **(1) tamperproof, (2) always
invoked, (3) small enough to verify**. Property (3) is failing by default: the
verified decision logic is intermingled with ~33k LOC of transport, storage,
manifest parsing, enterprise glue, c2pa, zkvm, etc.

## Goal

Carve the closure-relevant subgraph into a small, auditable, Aeneas-extractable
kernel so the claim becomes:

> *These ~5k LOC are the verified IFC reference monitor. Everything else is
> downstream and depends on the kernel for its decisions — it can only
> **propose**, never **decide**.*

This is **not** a deletion — the other 33k LOC do real work. It is a dependency
inversion + a hard, ratcheted boundary, plus the eventual physical crate split.

## The boundary (measured)

Reachability analysis from the kernel entry points (`IFCLabel::flows_to`,
`FlowTracker::check_exfiltration_safety` / `check_action_safety`,
`intrinsic_label`, `extracted::ifc_{integrity,confidentiality}`) shows the IFC
core is a near-**leaf** subgraph:

| Kernel member | LOC | Intra-crate deps |
|---|---|---|
| lib.rs lattice block (`Operation`, `SinkClass`+`required_*`, `ConfLevel`, `IntegLevel`, `AuthorityLevel`, `ProvenanceSet`, `Freshness`, `DerivationClass`, `IFCLabel`+`join`/`flows_to`/`meet`, label ctors, `is_exfil_operation`) | ~600 (of lib.rs's 3970) | none (crate root primitives) |
| `flow.rs` (`NodeKind`, `intrinsic_label`, `FlowTracker` fold) | 1977 | `effect`, `storage_lane`, `is_exfil_operation` |
| `ifc_api.rs` (`FlowTracker` API, `SafetyCheck`, `check_exfiltration_safety`) | 1434 | `flow`; **`discharge` (1 fn param + 3 test helpers — the only entanglement)** |
| `extracted/ifc_integrity.rs`, `extracted/ifc_confidentiality.rs` (the proven slices) | ~600 | `IFCLabel`/`IntegLevel` only |
| `effect.rs` | 286 | none (leaf) |
| `storage_lane.rs` | 193 | none (leaf) |

**Total ≈ 5,000–5,500 LOC** — Cedar-scale (AWS Cedar's verified decision
function is ~1.7k model / 5.7k proof / 15.7k Rust). The binding constraint is not
LOC but keeping the proven core in the Aeneas subset (primitives; no
BTreeSet/String/dyn) — which is the same forcing function as "small enough to be
a reference monitor."

### The one residual entanglement

`ifc_api.rs::SessionCleanseToken::authorize(reason, _proof: &discharge::DischargedBundle)`
takes a `DischargedBundle` as a **type-level capability witness** (#1358: you
cannot forge a cleanse token without going through the policy pipeline). The
`_proof` is otherwise unused. This is discharge-pipeline *integration*, not core
IFC logic, so it belongs outside the kernel. It is `pub` API, so moving it is its
own rung (M2) to avoid breaking gateway/runner callers. Until then it is the
single allowlisted exception in the ratchet.

## Complete mediation

The kernel is useless as a reference monitor if downstream code can act without
consulting it. Mediation is a **deployment** property, not a proof:

- Every effecting path (egress, tool-call, git-push, …) must obtain its verdict
  from the kernel `decide`/`check_exfiltration_safety` — nothing reconstructs the
  decision itself.
- The `mediation_drift` exemplar metric and the `run.rs --disallowedTools` fix
  are instances of this discipline.
- Non-bypassability is enforced at the merge gate (the kernel is the only crate
  that may emit an IFC `Verdict`), not by a theorem.

## Honest seams (where "provably safe" silently becomes false)

1. **model↔binary** — Aeneas proves a model of MIR, not the binary. No verified
   rustc/codegen. Say "safe-Rust decision logic as modeled," never "verified
   binary." Residual TCB = {Charon, Aeneas, Lean kernel, rustc, LLVM}.
2. **the marshalling adapter = confused-deputy hole** — invariants are proven
   over structs; the bytes→struct parser is unverified and in the mediation path.
   Keep it tiny, fuzzed, explicitly in-TCB.
3. **non-vacuity** — a vacuous invariant proof is green and worthless. Each kernel
   invariant needs an anti-vacuity witness (cf. the D1 non-vacuity guard and the
   `adversarial_ancestry_is_blocked_both_sides` proptest).

## Rung ladder

- **M0 (this RFC) — boundary + ratchet.** Define the kernel member set; add a
  mechanical **boundary-ratchet test** that fails if any dedicated kernel file
  (`flow`, `ifc_api`, `effect`, `storage_lane`, `extracted/*`) gains a dependency
  on a non-kernel module (allowlist: `discharge`, to be removed in M2). Makes the
  boundary enforceable **today**, before any code moves.
- **M1 (done) — extracted the lib.rs lattice block** into `ifc_lattice.rs` (552
  LOC: `ConfLevel`/`IntegLevel`/`AuthorityLevel`/`ProvenanceSet`/`Freshness`/
  `DerivationClass`/`IFCLabel`+`join`/`flows_to`/`meet`/`leq`), re-exported at the
  crate root (`pub use ifc_lattice::*`) so every consumer path is unchanged, and
  added to the ratchet's `KERNEL_FILES`. No behavior change (754 lib tests pass,
  all-features build clean). `Operation`/`SinkClass` stay in lib.rs for now —
  they are shared with the capability machinery and more entangled.
- **M2 (done) — decoupled `discharge`** from `ifc_api` by **dependency inversion**:
  the kernel now defines a sealed `PolicyDischarged` capability contract and
  `SessionCleanseToken::authorize<P: PolicyDischarged>(reason, &P)` takes any
  witness; `discharge.rs` satisfies it (`impl PolicyDischarged for DischargedBundle`),
  so the dependency points downstream→kernel. Call-compatible (`&bundle` infers
  `P = DischargedBundle`); the seal (`cleanse_seal::Sealed`, `pub(crate)`) keeps the
  token unforgeable outside the crate (#1358). Kernel tests use a local witness;
  the real-bundle integration is covered from the discharge side. **Ratchet
  allowlist is now empty** — the IFC kernel names no downstream module. (755 lib
  tests pass.)
- **M3 — physical crate split:** new `nucleus-ifc-kernel` crate holding the member
  set; `portcullis-core` depends on it and re-exports for backward compat.
- **M4 — LOC + dep-count + Aeneas-extractability ratchet** on the new crate (CI
  fails if the kernel grows past a cap or pulls a non-subset dep).
- **M5 — complete-mediation gate:** only the kernel crate may construct an IFC
  `Verdict`; merge-gate enforces it.

## Non-goals

- Proving the *binary* (seam 1).
- Proving the agent/LLM safe — the kernel bounds what an untrusted proposer may
  *do*, not what it *intends* (in-spec sleeper carries a valid certificate).
- Touching the 33k LOC of legitimate downstream machinery beyond the dependency
  inversion.
