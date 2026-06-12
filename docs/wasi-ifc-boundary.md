# WASI as Nucleus's Capability Substrate — and IFC as the Layer Above It

*Design note. Status: prototype landed (`crates/portcullis-wasi`,
`crates/portcullis-core/lean/WasiWorldFunctor.lean`,
`crates/portcullis-core/lean/WasiIfcBoundary.lean`).*

## TL;DR

The agent-security field converged in 2025–2026 on exactly Nucleus's thesis:
**capabilities are necessary but not sufficient; you also need information-flow
control (IFC).** The flagship is Microsoft Research's FIDES. Two flanks are left
open by everyone shipping today, and they are precisely the two things Nucleus
already had the pieces for:

1. **The IFC is unverified.** FIDES, CaMeL, and dual-LLM are dynamic runtime
   monitors with no formal soundness proofs.
2. **The IFC is disconnected from the sandbox substrate.** WASI hosts for agents
   (Microsoft's Wassette) enforce capabilities only; the one piece of WASM-IFC
   work (TaintAssembly, 2018) is a V8-interpreter hack, not capability- or
   agent-aware.

This note records the landscape, the wedge, and the prototype that closes both
flanks: a **formally-verified functor** from Nucleus's capability lattice to a
WASI import world, and a **formally-verified IFC monitor** bound to that world's
import boundary, with an **audited declassification escape valve**.

## The problem: capabilities don't stop exfiltration

Capability-based sandboxing (WASI's model, and `world_of` below) answers *"may
this component touch the filesystem / network?"*. It says nothing about the
**lethal trifecta** — private data + untrusted content + an outbound channel —
which is exploitable *even when every capability is legitimately granted*: a
component that may read a secret and may make a network call can exfiltrate the
secret. Indirect prompt injection turns this from an accident into an attacker
primitive ([Willison 2025][trifecta]). The consensus is that guardrail
classifiers ("95% of attacks") are a failing grade and that the fix is
*architectural* — IFC, dual-LLM/quarantine, and sandboxing
([Cyera][cyera], [Airia][airia]).

## The landscape

| System | Capability sandbox | IFC (conf/integ labels) | Formal proof | Substrate |
|---|---|---|---|---|
| **FIDES** (MS Research, [arXiv:2505.23643][fides]) | — | ✅ lattice labels, propagation, declassification, "trusted action" + egress policies | ❌ dynamic monitor, "no formal completeness proofs" | orchestration layer |
| **CaMeL** / dual-LLM ([Willison][trifecta]) | — | ✅ (quarantine/data-flow) | ❌ | orchestration layer |
| **Wassette** (MS, Aug 2025, [TNS][tns]) | ✅ WASI components via MCP, deny-by-default | ❌ | ❌ | WASI host |
| **TaintAssembly** ([arXiv:1802.01050][taint], 2018) | — | ✅ taint in linear memory | ❌ | V8 interpreter fork |
| **Nucleus** (this work) | ✅ `world_of` functor | ✅ `IFCLabel` (conf × integ × authority × …) | ✅ **Lean 4, kernel-checked** | **WASI import boundary, microVM underneath** |

FIDES's model *is* Nucleus's model — a lattice of confidentiality + integrity
labels, label propagation, declassification, a trusted-action policy (untrusted
input can't drive a privileged action) and a confidentiality-egress policy. The
difference is that `portcullis-core` already proves its lattice and
non-interference in Lean, and Nucleus binds the enforcement to the sandbox
boundary rather than the orchestration layer.

## The two-flank wedge, made concrete

### Flank 1 — capabilities compile to a WASI world (verified)

`world_of : CapabilityLattice → WasiWorld` (`portcullis-wasi/src/lib.rs`) turns
a 13-dimension graded capability lattice into a WASI Component Model import
world. Its per-interface core `WasiGrant::from(CapabilityLevel)` is a **lattice
isomorphism** of 3-chains; the whole map is a **join-semilattice homomorphism +
monotone**, and *lax for meet* exactly where multiple capability dimensions fold
onto one WASI interface — the security-safe direction (restricting capabilities
can only remove interfaces). Proven in `WasiWorldFunctor.lean`
(`join_flowsTo_iff`-style `phi_meet`/`phi_join`/`phi_injective`, all `decide`-
closed). Three capability dimensions (`run_bash`, `web_search`,
`manage_pods`/`spawn_agent`) have *no WASI-standard target* and are flagged as
non-standard host imports — `run_bash` is the ambient authority WASI exists to
forbid, and stays in the Firecracker lane.

### Flank 2 — IFC enforced at the import boundary (verified)

`BoundaryMonitor` (`portcullis-wasi/src/ifc.rs`) is a floating-label monitor
built directly on `portcullis-core`'s `IFCLabel::join` (stamp) and `flows_to`
(check). At the wasmtime host (`src/host.rs`), the *same* import boundary that
enforces capabilities now also enforces information flow: **source** imports
(`fs_read`, `http_fetch`) stamp their data's label into `pc`; **sink** imports
(`fs_write`, `http_post`) check `pc` against a FIDES policy before acting —
`trusted_action` (integrity) and `public_egress` (confidentiality). A sink must
pass **both** gates. The lethal trifecta is blocked end-to-end on real executing
wasm (`lethal_trifecta_blocked_end_to_end`).

Soundness is proven in `WasiIfcBoundary.lean`: **`monitor_sound`** — if the
monitor admits a sink, every source the component read individually satisfies the
sink policy, so data from a disallowed source can never reach the sink. This is
the noninterference guarantee FIDES explicitly lacks.

### The escape valve — audited declassification

Floating labels suffer *label creep*: once `pc` is raised it stays raised, so a
component that reads a secret can never egress again. The principled exit is
**declassification**, not a bypass. `BoundaryMonitor::declassify` wires
`portcullis-core`'s `DeclassificationRule` (the `declassify` host import,
authorized out-of-band — FIDES's "quarantined summarizer" pattern). It is the
*sole* operation that may lower `pc`, it fires only when its precondition matches,
and **every attempt is recorded** for audit. Lean proves it can only lower
confidentiality and **cannot launder integrity**
(`declassify_only_lowers_conf`, `declassify_preserves_block_on_integrity`) —
declassifying a secret for egress does not make adversarial content able to drive
a trusted action.

## Honest limitations

- **Floating-label coarseness.** The guest is opaque between an `fs_read` and an
  `http_post`, so the monitor tracks at I/O granularity, not intra-guest
  dataflow (same granularity as FIDES; finer would need TaintAssembly-style
  instrumentation, the wrong layer). Label creep is the cost; declassification is
  the relief. `monitor_sound` shows the coarseness is conservative, never unsound.
- **Core-module, not full Component Model.** The prototype uses wasmtime's core
  `Linker`; the CM upgrade swaps `component::Linker` + WIT but keeps the gates
  identical.
- **WASM is not the whole sandbox.** Runtime escape vectors are real (JIT bugs;
  the Wasmer virtual-path CVE; monolithic linear memory as a single point of
  failure — [InstaTunnel][wasmbreach], [Zylos][zylos]). WASI runs *inside*
  Firecracker, not instead of it; the microVM is the defense-in-depth floor.
- **Labels must be assigned correctly.** IFC is only as good as the source
  labels. Nucleus's value is making propagation and enforcement *provably*
  correct given honest labels — not divining trust from content.

## Artifact map

| Concern | Rust | Lean (kernel-checked) |
|---|---|---|
| Capability → WASI world | `portcullis-wasi/src/lib.rs` (`world_of`) | `WasiWorldFunctor.lean` (`phi_meet`/`phi_join`, lax-meet) |
| Executable host (2 gates) | `portcullis-wasi/src/host.rs` | — (demonstration) |
| IFC floating-label monitor | `portcullis-wasi/src/ifc.rs` (`BoundaryMonitor`) | `WasiIfcBoundary.lean` (`monitor_sound`) |
| Declassification escape valve | `ifc.rs` (`declassify`) + `host.rs` | `WasiIfcBoundary.lean` (`declassify_*`) |

[trifecta]: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
[cyera]: https://www.cyera.com/blog/the-lethal-trifecta-why-ai-agents-require-architectural-boundaries
[airia]: https://airia.com/ai-security-in-2026-prompt-injection-the-lethal-trifecta-and-how-to-defend/
[fides]: https://arxiv.org/abs/2505.23643
[tns]: https://thenewstack.io/webassembly-sandboxing-ai-agents/
[taint]: https://arxiv.org/abs/1802.01050
[wasmbreach]: https://medium.com/@instatunnel/the-wasm-breach-escaping-backend-webassembly-sandboxes-05ad426051fc
[zylos]: https://zylos.ai/research/2026-04-04-ai-agent-sandboxing-security-isolation/
