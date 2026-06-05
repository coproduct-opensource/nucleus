# RFC: Verified Agent Commerce — a drop-in trust + receipt layer for x402 / A2A

> Status: **Implemented (v1) — GTM exploratory.** The seller-side library now
> ships as [`crates/nucleus-verify-commerce`](../../crates/nucleus-verify-commerce)
> (real Agent-Card verification, signed `nucleus-envelope` receipts,
> `verify_receipt_bundle`, an x402 `X-PAYMENT` helper, and a runnable
> `quickstart` example). It composes existing crates (`nucleus-agent-card`,
> `nucleus-envelope`, `nucleus-verifier-service`, `nucleus-fly-oidc` /
> `nucleus-github-oidc`, `portcullis`); no new payment rail is built — x402 stays
> x402. The GTM motion (packaging, design partner) is the exploratory part.

## Thesis

The agent-payments rail is **solved and commoditized**. x402 (Linux Foundation,
100M+ agentic txns, ~$600M annualized) plus Google/Coinbase's **A2A x402
extension** and **AP2** already let an agent discover, authorize, and pay another
agent. Coinbase, Stripe, AWS (Bedrock AgentCore Payments), and Vercel
(`x402-mcp`) all ship free tooling to wire it up.

So **we do not build a bridge** — the bridge exists and is given away by the
incumbents. The open, loudly-documented problem one layer up is **trust**:

- a seller "cannot rely on its own telemetry to verify the buyer… forced to
  trust a software agent it did not build and cannot inspect";
- "merchant verification at scale is unsolved";
- fraud now looks like *clean, fast, successful* transactions, so sellers eat
  "hallucination disputes" and chargebacks.

Industry is converging on **verify-then-pay**. That is exactly what nucleus's
existing verifiable core provides. This RFC packages it as a 30-minute
drop-in for micro-SaaS sellers on x402/A2A.

## Scope

A seller-side library + QuickStart that, around an existing x402-paid endpoint,
adds two things the payment rail does **not**:

1. **Verify the caller before serving** — check the calling agent's signed
   identity (Agent Card / OIDC→SPIFFE) and policy bounds.
2. **Return a portable receipt after serving** — a provenance bundle proving
   *what was delivered for what payment*, independently verifiable and logged to
   a transparency log, so a buyer can verify-then-settle and a seller has a
   dispute-defense artifact.

Out of scope: the payment itself (x402 facilitator), custody, any new token,
buyer-side wallet UX.

## Flow

```text
  paying agent ──HTTP 402 / x402──▶  micro-SaaS endpoint
                                       │
                 ┌─────────────────────┴───────────────────────┐
                 │  nucleus verify-commerce middleware          │
                 │                                              │
                 │  (1) verify caller identity                  │
                 │      Agent Card (JWS) / OIDC→SPIFFE          │  ← nucleus-agent-card
                 │      + portcullis policy / spend bounds      │    nucleus-*-oidc, portcullis
                 │                                              │
                 │  (2) serve the paid work                     │
                 │                                              │
                 │  (3) emit a provenance receipt               │  ← nucleus-envelope
                 │      → transparency log + return to caller   │    nucleus-verifier-service
                 └──────────────────────────────────────────────┘
                                       │
            buyer independently verifies the receipt (verify-then-settle / dispute)
```

The receipt is the wedge: it is the artifact that survives the disappearance of
traditional fraud signals.

## Crate mapping (all already shipped)

| Capability | Crate |
|---|---|
| Verify-before-you-act agent identity | `nucleus-agent-card` |
| Federated workload identity → SPIFFE | `nucleus-fly-oidc`, `nucleus-github-oidc`, `nucleus-oidc-core` |
| Policy / capability / spend bounds | `portcullis`, `portcullis-effects`, `nucleus-permission-market` |
| Portable provenance receipt | `nucleus-envelope` |
| Transparency log + public verifier | `nucleus-verifier-service` |
| Browser/WASM independent verification | `@coproduct/verify` (verify pkg) |

The net-new work is **packaging + an adapter**, not new primitives: an x402/A2A
request adapter, a thin seller middleware, and a QuickStart.

## QuickStart shape (the GTM artifact)

> "Add verified agent commerce to your x402 API in 30 minutes."

1. `nucleus verify-commerce init` — generate a seller signing key + Agent Card.
2. Wrap the existing paid handler in the middleware (identity check in, receipt
   out). One import, one wrapper.
3. The caller receives a receipt; anyone can verify it with `@coproduct/verify`
   or the public verifier service.

Mirrors Coinbase's "30-minute" payment QuickStart, but for the trust layer the
payment QuickStart omits.

## Differentiation (be honest about the crowd)

Visa "Verifiable Intent", Mastercard, Signifyd, TessPay, Crossmint, and
Nevermined are all circling agentic-commerce trust. The **only** durable
differentiator is the one nobody else has: **formal verification + portable,
independently-verifiable provenance receipts** (sorry-free proofs, transparency
log) rather than a proprietary trust score. Lead with *verifiable*, not *trusted*.

## Open questions / honesty

- **Demand is the bottleneck, not the substrate.** A QuickStart lowers
  integration friction; it does not by itself create a forcing function. Target
  the one pain a seller will pay to avoid: liability for hallucination
  disputes / chargebacks. Make the receipt the dispute-defense artifact.
- **Keep the verify path OSS, free, near-zero-friction.** Sellers get payments
  free; they will only adopt a trust layer if it costs them almost nothing to
  add. Monetize the federation / registry / compliance control plane (the
  existing open-core split), not the verify call.
- **AP2 already has cryptographic *mandates* (authorization).** We do not
  duplicate authorization — we add *counterparty verification* and *delivery
  receipts*, which AP2/x402 leave to the participants.
- **Validate with one design partner before building the polished QuickStart.**
  A micro-SaaS seller already on (or adopting) x402 who has felt a dispute.

## Implementation note: what the receipt actually signs

The first cut (`crates/nucleus-verify-commerce`) surfaced a real subtlety worth
recording: `nucleus_lineage::canonical_edge_bytes` signs a lineage edge's
`child`, `kind`, `parents`, **`content_hash_hex`**, `ts`, and `prev_hash` — but
**not** the edge's free-form `attrs` nor the bundle's `payload`. So putting the
commerce binding only in the payload would be a *false* guarantee (the bundle
would still "verify" after the payload was tampered). The receipt issuer instead
folds the whole binding (resource + caller + payment + body hash) into the
delivery edge's **content hash**, which is signed; `verify_receipt_bundle`
re-derives the binding from the payload and checks it equals that signed hash.
Tampering any field is then detected (regression-tested). This is the kind of
guarantee that has to be checked, not assumed.

## Recommendation

Greenlight the QuickStart as a GTM experiment; drop the "bridge" framing. The
metric to watch is the same as the broader plan: one paid (or actively
integrating) design partner in 30 days. Reuse shipped crates; the net-new
surface is an adapter + middleware + docs.
