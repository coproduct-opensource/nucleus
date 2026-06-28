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

| Kernel member | LOC | Non-kernel deps |
|---|---|---|
| `ifc_lattice.rs` (extracted M1: `ConfLevel`, `IntegLevel`, `AuthorityLevel`, `ProvenanceSet`, `Freshness`, `DerivationClass`, `IFCLabel`+`join`/`flows_to`/`meet`/`leq`) | 552 | none |
| `ifc_ops.rs` (extracted M1b: `Operation`+`LatticeOperation`, `SinkClass`+`required_*`, `default_sink_class`, `is_exfil_operation`) | 491 | `AuthorityLevel`/`IntegLevel` (kernel) |
| `flow.rs` (`NodeKind`, `intrinsic_label`, `FlowTracker` fold) | 1977 | `Operation`/`is_exfil_operation` (kernel) |
| `ifc_api.rs` (`FlowTracker` API, `SafetyCheck`, `check_exfiltration_safety`) | 1434 | `crate::discharge::DischargedBundle` (cleanse proof, intended coupling) |
| `extracted/ifc_integrity.rs`, `extracted/ifc_confidentiality.rs`, `mod.rs` (the proven slices) | 389 | `SinkClass` (kernel); `IFCLabel`/`IntegLevel` (kernel) |
| `effect.rs` | 286 | `DerivationClass` (kernel) |
| `storage_lane.rs` | 193 | `DerivationClass` (kernel) |

**Total ≈ 5,000–5,500 LOC** — Cedar-scale (AWS Cedar's verified decision
function is ~1.7k model / 5.7k proof / 15.7k Rust). The binding constraint is not
LOC but keeping the proven core in the Aeneas subset (primitives; no
BTreeSet/String/dyn) — which is the same forcing function as "small enough to be
a reference monitor."

Honest note (post-audit, post-M1b): the kernel's only *non-kernel* dependency is
now the intended `discharge` coupling (below). Every other `crate::` reference a
kernel file makes resolves to a type/fn **defined in a kernel file** (the lattice
in `ifc_lattice`, the operation/sink vocabulary in `ifc_ops`) and re-exported at
the crate root — so the kernel no longer names anything in the unfenced `lib.rs`
root. The ratchet enforces this: it flags any non-kernel module, any
*un-enumerated* crate-root reference (e.g. `crate::CapabilityLattice`), and any
`use crate::*` wildcard. (`ROOT_RESIDUALS` is now empty; M1 left the residuals
behind, M1b moved them.)

### The `discharge` coupling (intended, not erosion)

`ifc_api.rs::SessionCleanseToken::authorize(reason, _proof: &discharge::DischargedBundle)`
takes a `DischargedBundle` as a **type-level capability witness** (#1358: you
cannot forge a cleanse token without going through the policy pipeline).

We initially tried to *invert* this away (kernel defines a sealed
`PolicyDischarged` trait, `discharge` satisfies it) so the kernel would name no
downstream module. A skeptical audit rejected that: a `pub(crate)` sealed trait is
implementable by **any** of the crate's 58 modules, so the inversion silently
*widened* who can mint a `SessionCleanseToken` (a privileged declassification)
from the single `discharge` module to the whole crate — and it would not survive
the M3 crate split (the seal would have to open to a downstream `discharge`
crate). `DischargedBundle`'s constructor is private to `discharge`, so the
concrete coupling is the *only* form that restricts minting to the policy
pipeline. We therefore keep the concrete `&DischargedBundle` and treat
`discharge` as an **intended** dependency of the cleanse escape-hatch (a
privileged override legitimately requiring the enforcement pipeline's proof),
enumerated in the ratchet's `MODULE_ALLOWLIST` rather than as removable erosion.
M3 (crate split) is what will let the boundary actually *enforce* this — when
`discharge` is a separate crate, only it and the kernel can produce the witness.

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

- **M0 (done) — boundary + ratchet.** Define the kernel member set; add a
  mechanical **boundary-ratchet test** that fails if any dedicated kernel file
  gains a dependency on non-kernel code — a non-kernel *module* (`crate::witness::…`),
  an un-enumerated crate-*root* item (`crate::CapabilityLattice`), or a
  `use crate::*` wildcard. Tracked exceptions: `MODULE_ALLOWLIST` (`discharge`,
  intended), `ROOT_RESIDUALS` (`Operation`/`SinkClass`/`is_exfil_operation`, still
  in lib.rs, M1b). Makes the boundary enforceable **today**, before the crate split.
- **M1 (done) — extracted the lib.rs lattice block** into `ifc_lattice.rs` (552
  LOC: `ConfLevel`/`IntegLevel`/`AuthorityLevel`/`ProvenanceSet`/`Freshness`/
  `DerivationClass`/`IFCLabel`+`join`/`flows_to`/`meet`/`leq`), re-exported at the
  crate root (`pub use ifc_lattice::*`) so every consumer path is unchanged, and
  added to the ratchet's `KERNEL_FILES`. No behavior change (754 lib tests pass,
  all-features build clean).
- **M2 (done — inversion tried then reverted) — examined the `discharge` coupling.**
  A sealed-`PolicyDischarged` inversion was implemented and then **reverted** after
  audit: a `pub(crate)` sealed trait widened `SessionCleanseToken` minting from one
  module to the whole crate and would not survive M3. Conclusion: the
  `&DischargedBundle` coupling is **intended** (the cleanse override requires the
  policy pipeline's proof, #1358), so it stays, enumerated in `MODULE_ALLOWLIST`.
  M3 is what will turn it into an enforced boundary.
- **M1b (done) — moved the root residuals** (`Operation`, `SinkClass`,
  `is_exfil_operation`) out of lib.rs into a new `ifc_ops.rs` kernel module,
  re-exported at the crate root (`pub use ifc_ops::*`) so consumer paths are
  unchanged. `is_exfil_operation` was reimplemented as a direct match on
  `Operation` (no longer routed through lib.rs's `classify_operation`/`ExposureLabel`
  exposure machinery), pinned to the old definition by the exhaustive
  `is_exfil_operation_matches_classifier` test. **`ROOT_RESIDUALS` is now empty —
  the kernel references no crate-root item defined outside a kernel file.** No
  behavior change (755 lib tests pass, all-features build clean).
- **M3 — physical crate split:** new `nucleus-ifc-kernel` crate holding the member
  set; `portcullis-core` depends on it and re-exports for backward compat. This is
  what makes `MODULE_ALLOWLIST = {discharge}` an *enforced* boundary (only the
  kernel + discharge crate can mint a cleanse witness).
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
