# Sign the IFC effective-integrity label — pinned spec (Level-1 grounding)

The moonshot rung that turns the egress verdict from *recompute-able* into
*recompute-able **and tamper-evident***: move the chain's effective integrity
from an **unsigned `edge.attrs` entry** into the **signed `VerifierAttestation`**,
so the gate and `verify_ifc_flow` read signed data, and the verifier can
cross-check the gate's input against what was signed upstream.

Adversarially pinned before grinding (spec workflow `w6u535z3e`).

## 1. The gap is REAL (very high confidence)

- `canonical_edge_bytes` **excludes `edge.attrs`** (`nucleus-lineage/src/proof.rs:41-42`) — signs child/kind/parents/content-hash/ts/prev-hash/VA only.
- The runner stamps the label as an **unsigned attr**: `nucleus-runner/src/runner.rs:424` `.with_attr("ifc_effective_integrity", …)`, then signs `canonical_edge_bytes` (runner.rs:431) — signature does **not** cover it. The summary edge currently carries **no** VA at all.
- The egress gate **trusts that unsigned attr**: `nucleus-gateway/src/gateway.rs:282` reads `parent_edge.attrs["ifc_effective_integrity"]`.

**Attack today:** take a validly-signed summary edge with `attrs[ifc_effective_integrity]="adversarial"`, edit it to `"trusted"` — the edge signature still verifies, the gate reads `"trusted"`, egress is permitted. (Even the gateway test helper at gateway.rs:1029 *claims* it "stamps before signing" but uses `.with_attr` — the comment is false.)

## 2. What signing EARNS / what it does NOT (state verbatim)

**EARNS (Level-1):** moving the label into the signed `VerifierAttestation` makes
it **tamper-evident** (any post-signing edit invalidates the Ed25519 signature),
**runner-attested + non-repudiable** (the runner's key commits the runner to this
label), and reduces label trust to **trust in the runner's signer** — which the
gateway already verifies against. **No new trust assumption.**

**DOES NOT EARN (Level-2, sequenced separately):** signing does **not** ground the
label's **truth or completeness**. An under-declaring, buggy, or compromised
runner can sign a false-but-valid label (`"trusted"` over a flow that carried
adversarial data). The signature proves *the runner said it*, not *that it is
correct*. Grounding truth needs **mediated observation** (independent monitor
cross-checking the label against observed tool outcomes), quorum, or a formal
proof of label-derivation soundness. **Do not conflate signature-coverage with
correctness.** (Standard signed-provenance boundary: SLSA/sigstore — signed ≠
verified; DIFC — endorsed ≠ grounded.)

## 3. Spec — PINNED

### (A) Producer: stamp into the signed VA
- **NEW** field `ifc_effective_integrity: Option<String>` on `VerifierAttestation`
  (`nucleus-lineage/src/edge.rs`, alongside `ifc_gated_effective_integrity`) +
  `with_ifc_effective_integrity` builder + extend `is_empty()`.
  - **FLAG — do NOT reuse `ifc_gated_effective_integrity`.** That is the gateway's
    egress **co-commit** (gate *output*: "egress-gated AND allowed"). The new
    field is the runner's running-chain integrity (the gate *input*). The
    cross-check (C) compares the two — reusing one field collapses it.
- **`canonical_edge_bytes` emit (proof.rs):** **Some-gated** additive emit
  (`out.push(0); bytes; out.push(0)` only when `Some`), appended **after** the
  `ifc_gated_effective_integrity` block.
  - **FLAG — do NOT use `push_opt`** (always writes a NUL → shifts bytes of every
    existing VA-bearing economic edge → breaks their signatures). Follow the
    existing additive precedent.
- **Runner (platform, runner.rs:408-439):** replace the `.with_attr` at :424 with
  `.with_verifier_attestation(VerifierAttestation::new().with_ifc_effective_integrity(integ_name(label.integrity)))`
  before the `canonical_edge_bytes` sign. **Dual-emit** the attr too for one
  release (migration). Signer unchanged (runner's identity key).

### (B) Consumer migration: VA-first, attr-fallback for one release
- **Egress gate (gateway.rs:276-298):** read
  `parent_edge.verifier_attestation…ifc_effective_integrity`, **fall back** to the
  attr if VA-absent (legacy edges), then `unwrap_or("trusted")`. Drop the fallback
  after one release.
- **FLAG — gateway is a SECOND stamper:** the gateway writes
  `ifc_effective_confidentiality` (and integrity) as **attrs** on delegation edges
  (gateway.rs:455) and signs via `sign_chained`. Runner-only is **incomplete** —
  gateway-stamped parents stay unsigned unless the gateway stamp also moves to the
  VA it already signs. A *sound* gate needs both stampers migrated.
- **FLAG — confidentiality parity:** `ifc_effective_confidentiality` has the
  identical unsigned-attr gap (gateway.rs:250-254). Either fix in the same PR or
  explicitly document it remains Level-0 unsigned.
- **UI:** `nucleus-control/static/js/holy-grail.js` `panelIfc` — read VA-first.

### (C) Verifier cross-check (nucleus-recompute)
- Keep `verify_ifc_flow(Option<&str>)` (consistency-of-stamp). **Add** a wasm-pure
  `verify_ifc_flow_consistent(child_gated: Option<&str>, parent_effective: Option<&str>)`:
  on an egress-allowed hop (`child_gated == Some`), require
  `child_gated == parent_effective`; mismatch ⇒ reject (the gate evaluated a value
  different from what was signed upstream). `&LineageEdge` parent/child adapter
  stays behind the optional non-wasm feature. Honest scope unchanged: binds
  gate-input(runner-signed) to gate-output(gateway-signed); does **not** ground
  either value's truth.

## 4. Green predicate (mechanical)

1. **Tamper no longer downgrades the gate** (platform): edit `attrs` "adversarial"→"trusted" on an edge whose VA says "adversarial"; VA-first gate still **denies**.
2. **Forged signed label breaks the edge** (nucleus-lineage): mutate `va.ifc_effective_integrity` post-signing ⇒ signature verification **fails**.
3. **Cross-check rejects contradiction** (nucleus-recompute): child `ifc_gated_effective_integrity` ≠ parent `ifc_effective_integrity` ⇒ reject.
4. **Anti-vacuity (honest chain passes):** signed `"trusted"` parent → matching `"trusted"` gated child → gate allows, cross-check consistent. (Guards deny-everything.)
5. **Additive-compat golden** (nucleus-lineage): a pre-existing VA-bearing edge **without** the new field canonicalizes **byte-identically**; dual-emit edge (attr + VA) verifies and gate prefers VA.

## 5. Cross-repo ordering

- **nucleus (open) FIRST — loopable now:** VA field + builder + `is_empty` (edge.rs); Some-gated emit (proof.rs); additive golden; `verify_ifc_flow_consistent` + tests (nucleus-recompute). Green predicate items 2, 3, 5, recompute-half of 4.
- **THEN nucleus-platform — gated on the nucleus version/pin bump:** runner stamp→VA, gateway VA-first read, gateway delegation stamp→VA (+ conf parity), UI. Green items 1, 4 (gate behavior). Platform edits compile-fail until the pin bumps — do **not** start them this loop.

## 6. Not grindable / Level-2 (route around)

- **Label completeness** (runner misses a flow) — needs mediated observation.
- **Compromised / under-declaring runner** — signs a false-but-valid label.
- **Intent / truth of the flow** — not expressible by a signature (wall-1/Rice).
- Sequence a distinct Level-2 rung (independent monitor cross-checks the signed label against observed egress, or Lean soundness of label derivation) with its own honesty claim. Do not let it leak into this rung's language.
