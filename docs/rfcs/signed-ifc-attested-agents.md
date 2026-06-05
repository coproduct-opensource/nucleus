# RFC: Signed, IFC-Attested, Receipt-Bearing Agents

> Status: **Implementing (v1).** Layer 1 (the signed card profile) ships in
> `nucleus-agent-card` (PR #1735); the `just agent-sign` flow follows. Layers 2–3
> (receipt↔rule binding, runtime enforcement loading) are proposed. Composes
> existing crates: `nucleus-agent-card`, `nucleus-ifc`, `nucleus-verify-commerce`,
> `nucleus-envelope`, `nucleus-verifier-service`, the `nucleus-*-oidc` keyless path.

## Thesis

An agent should ship with a **signed card that declares the runtime
information-flow guarantee it enforces**, so a counterparty can *verify* that
guarantee — client-side, offline — instead of taking the host's word for it. The
field is racing toward signed **identity + provenance** (Sigstore A2A, Agent
Passport / Agent-VC) and **hardware-rooted** runtime attestation (EQTY, Windows
TPM). The white space is a portable, counterparty-checkable proof of a *semantic*
guarantee like IFC/non-interference. Nucleus already has every piece: a signed
agent card, the IFC gate (`serve_verified_ifc`, #1733), independently-verifiable
envelope receipts, OIDC keyless signing, and a transparency log.

## The attestation stack

**Layer 1 — declare (this RFC, shipped).** An optional
`RuntimeGuaranteeProfile` on `AgentCard` (`profile_version`, `tracked_sources`,
`enforcement_rules`, advisory `attestation_reference`). Because it is part of the
card's JCS-canonical bytes, the existing ES256 card signature covers it — the
declaration is authentic and tamper-evident (`tampering_runtime_guarantees_breaks_signature`).

**Layer 2 — bind receipts to the declared rules (proposed).** Each
`nucleus-envelope` receipt already folds its decision into a *signed* content
hash (the lesson from `nucleus-verify-commerce`: payload/attrs are **not** signed,
content hash is). Extend the receipt binding to include the *rule identity*
(`enforcement_rules[i].name` + a hash of the rule) so a verifier can confirm a
verdict came from evaluating **this card's declared rule**, not some unrelated
host policy.

**Layer 3 — load + enforce the declared profile (proposed).** At session start
the runtime loads the signed card's `tracked_sources` / `enforcement_rules` into
the `nucleus-ifc` `FlowDeclaration` path and fails closed. This is the only layer
that *prevents* (vs. detects) violations, and it is host-side.

## `just agent-sign` / `agent-ship` (next PR)

```text
just agent-sign     # OIDC-keyless-sign a card (incl. its runtime_guarantees), → SignedAgentCard
just agent-ship     # publish the signed card to /.well-known + the transparency log
```

Keyless signing reuses the existing path: a CI or workload OIDC token
(`nucleus-github-oidc` / `nucleus-fly-oidc`) → SPIFFE id → ES256 signature over
JCS(card). No new secret material.

## What a verified profile proves — and does not

| Proven | Not proven |
|---|---|
| **Authenticity** — the agent issued this exact card (ES256 over JCS) | **Policy correctness** — the declared rules are sound/sufficient (IFC is necessary, not sufficient) |
| **Integrity** — the profile wasn't altered post-signing | **Enforcement** — the host actually applies the rules (Layer 3) |
| **Rule provenance** (Layer 2) — a receipt's verdict came from a declared rule | **Good decisions** — IFC tracks data lineage, not hallucination/jailbreak |
| **Chain integrity** — the receipt sequence is complete + ordered | **Host honesty** — software signing ≠ hardware attestation; key theft possible |

**The core honesty line:** the client **verifies the attested declaration + the
receipts**; it does **not** enforce the seller's runtime. Enforcement is
host-side, model-level, and **coverage-limited** (an undeclared input is one the
lattice never sees; the gate is per-call, no cross-call taint ratchet). Lead with
*verifiable*, never *guaranteed-safe*.

## Microsoft ACS interop

Reference, don't reinvent. The `attestation_reference` field can carry a
Microsoft **Agent Control Specification** policy id; nucleus is then the
*verifiable enforcement + receipt* layer for an ACS-described policy. The mapping
is lossy and **one-way** (nucleus's finer-grained IFC labels → ACS's coarser
intervention points), and the reference is **advisory** — a verifier with no
out-of-band knowledge of the ACS policy cannot confirm it.

## Backward compatibility

`runtime_guarantees` is `Option<…>` with `skip_serializing_if`: omitted from JSON
when absent, so old cards (no field) and new cards both verify, and the existing
signature path is unchanged. (PR #1735.)

## Open questions

- Layer 2 receipt↔rule binding: exact canonical form of the rule hash.
- Revocation: receipts are immutable; clients detect a stale card only on
  re-verification — there is no server-side retroactive invalidation.
- A standard vocabulary for `enforcement_rules[].name` (so different agents'
  declarations are comparable), vs. free-form strings.

## Recommendation

Ship Layer 1 + `just agent-sign` now (verifiable declaration is useful on its
own and is the demo wedge). Sequence Layers 2–3 behind it. Keep the honesty
table attached to every external description of this feature.
