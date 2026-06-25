# verify_ifc_flow — pinned spec

Make the gateway IFC egress-gate verdict **offline-recomputable** and bound into
the **signed** receipt — the honest differentiator vs CaMeL/FIDES (they enforce;
neither emits a third-party-recomputable, theorem-anchored, portable receipt).

Two parts: **(A) co-commit** the gate decision into a *signature-covered* slot,
and **(B) `verify_ifc_flow`** re-derives it offline. Adversarially pinned before
grinding (a prior loop wasted hours on a false-as-stated lemma; the last loop's
target was even mis-*located*).

## Pre-flight (Commit 0) — RESOLVED ✅

The predicate's home must be wasm-pure so `nucleus-recompute` (in the
`wasm-pure-crates` gate) can import it. **Verified:** `cargo build -p nucleus-ifc
--features decision --target wasm32-unknown-unknown` compiles cleanly (no
`ring`/wasm breakage — portcullis-core's crypto is feature-gated off the default
closure). ⇒ **predicate home = `nucleus-ifc` `decision` module.** The spec's
fallback (a new wasm-pure leaf) is unnecessary.

## The load-bearing fact (why the naive plan was a false target)

`canonical_edge_bytes` (`nucleus-lineage/src/proof.rs:41-42, 99-157`) signs
`child · kind · parents · content_hash · ts · prev_hash · VerifierAttestation` —
**NOT `edge.attrs`**. So stamping the co-commit on `edge.attrs` would be
*unsigned* (forgeable post-signature), defeating the trustless goal. The only
sound co-commit surface is the **`VerifierAttestation`**, which *is* inside
`canonical_edge_bytes`. (Corollary residual: the existing `ifc_effective_integrity`
the gate reads is an *unsigned* attr — see "wall 1" below.)

## Part A — co-commit (PINNED)

Add **one** field to `VerifierAttestation` (`nucleus-lineage/src/edge.rs`):

```rust
/// Present iff this hop was an IFC egress-gate point (tool had a non-empty
/// egress_allowlist) AND the gate allowed it. Value = the chain effective
/// integrity the gate evaluated. Presence encodes "was gated"; absence = not an
/// egress hop. A signed edge with Some("adversarial"|unrecognized) is
/// self-inconsistent (the gateway would have denied → no edge).
#[serde(default, skip_serializing_if = "Option::is_none")]
pub ifc_gated_effective_integrity: Option<String>,
```

One field, not two — **presence** encodes "egress-gated" (a separate bool is a
forgeable inconsistency surface). Update `VerifierAttestation::is_empty()` + a
builder.

**⚠ The additive-compat trap (THE lemma to get right):** the existing VA fields
in `canonical_edge_bytes` use `push_opt` which *always* emits a NUL. Every
gateway edge already carries a VA, so a naive always-emit 7th field changes the
signed bytes of **every existing VA-bearing edge** → breaks their signatures.
The new field MUST emit **zero bytes when `None`**:

```rust
// ADDITIVE: emits nothing unless this hop was an egress-gate point.
if let Some(integ) = va.ifc_gated_effective_integrity.as_deref() {
    out.push(0);
    out.extend_from_slice(integ.as_bytes());
    out.push(0);
}
```

Guard it with a **golden test**: a VA-bearing edge with no egress field produces
byte-identical canonical bytes to pre-change.

**Stamp site (gateway, platform — follow-on once the nucleus pin bumps):** in
`invoke_tool`, on the egress **allow** path, thread `Some(effective_integ)` into
`sign_chained` so the VA chokepoint stays the single stamping site; non-egress /
delegation paths pass `None`. CONFIRMED signature-covered (VA emitted by
`canonical_edge_bytes`, signed by `sign_chained`).

## Part B — verify_ifc_flow (PINNED)

Lives in `nucleus-recompute`. **wasm constraint:** the default build is
wasm-pure and `nucleus-lineage` is NOT (pulls dalek/base64/ct-merkle). So the
core takes **plain data**, never `&LineageEdge`, in the default build:

```rust
pub enum IfcFlowOutcome { NotGated, Allow, Inconsistent { effective_integrity: String } }

/// Re-derive the egress-gate verdict from the SIGNED VA field alone.
pub fn verify_ifc_flow(gated_effective_integrity: Option<&str>) -> IfcFlowOutcome {
    match gated_effective_integrity {
        None => IfcFlowOutcome::NotGated,
        Some(i) if !nucleus_ifc::decision::egress_blocked_by_integrity(i) => IfcFlowOutcome::Allow,
        Some(i) => IfcFlowOutcome::Inconsistent { effective_integrity: i.into() },
    }
}
```

A `&LineageEdge` adapter (reads `edge.verifier_attestation…ifc_gated_effective_integrity`)
goes behind an **optional feature** (mirror the `envelope` feature), keeping the
wasm-pure default closure unchanged.

`egress_blocked_by_integrity` must be **single-sourced** in `nucleus-ifc`
`decision` (pre-flight confirmed wasm-pure) and imported by both the gateway
(producer) and recompute (verifier) — that single definition *is* the trustless
guarantee.

**Honest property (TRUE-under-preconditions):** for every signed edge whose VA
carries `ifc_gated_effective_integrity = Some(x)`, `egress_blocked_by_integrity(x)
== false` — *every signed egress-gated hop is consistent with the allow-rule over
its own signed effective-integrity.* It verifies **consistency-with-the-signed-
stamp**, NOT the truth of the stamp (wall 1), and does **NOT** claim "a denial
happened" (denials leave no edge; absence ≠ evidence).

## Green predicate (mechanical)

- `nucleus-lineage`: **additive-compat golden** — a VA without the egress field is byte-identical pre/post.
- `nucleus-gateway` (follow-on): egress allow stamps `Some("trusted")`; flipping the VA field to `"adversarial"` makes `verify_edge_authentic` **fail** (proves it's in the signed surface).
- `nucleus-recompute`: `verify_ifc_flow(Some("trusted"))==Allow`, `Some("untrusted"))==Allow` (anti-vacuity — not deny-everything), `Some("adversarial"))` & `Some("garbage"))==Inconsistent` (fail-closed), `None==NotGated`.
- `cargo build --locked --target wasm32-unknown-unknown -p nucleus-recompute` — wasm-pure gate stays green.

## Not grindable (route around — document)

- **Wall 1 — stamp grounding:** that the stamped integrity equals the runner's *true* effective integrity. The value originates as an *unsigned* parent attr (runner.rs:424). Closing it = have the runner **sign** `ifc_effective_integrity` (move it into the signed surface) + cross-check. **Separate, sequenced rung** — do NOT fold in.
- **Denial-as-absence:** "a malicious egress *was* blocked" is not expressible (denied calls emit no edge).
- **Intent / should-this-tool-be-egress:** registry/governance, not recomputable.
- **Per-tool `requires_integrity=trusted`:** keep the predicate as-is this rung.

## Iteration plan (each green-gated)

0. ✅ Pre-flight (wasm-purity of predicate home) — DONE.
1. Pin this spec.
2. Single-source `egress_blocked_by_integrity` into `nucleus-ifc/decision` (no behavior change) + the `VerifierAttestation` field + the `Some`-gated `canonical_edge_bytes` emit + additive-compat golden. Green: `nucleus-ifc`, `nucleus-lineage`.
3. `verify_ifc_flow` plain-data core + `IfcFlowOutcome` + tests + optional edge adapter. Green: `nucleus-recompute` + wasm gate.
4. nucleus PR. (Gateway co-commit producer = cross-repo follow-on once the platform pin bumps.)
