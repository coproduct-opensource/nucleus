# RFC: Social-good steering — verifiable externality accounting + commons routing

**Status:** active (North Star lens). **Ships:** `nucleus-econ-kernels::commons`
(routing) + `::settlement` (Bet B decision); RFC for the routing destination + the
non-extractive structure.

## The directive

Steer this commerce toward **social good — it should benefit people and the
planet** — and make that the lens for everything (now in the vision North Star).

## The thesis

**Verifiable externality accounting for the agent economy.** As agents do more
economic work, the externalities scale (compute → carbon, congestion, data
pollution). Today carbon/ESG accounting is *self-reported and unverifiable* — the
greenwashing problem. nucleus already prices these as first-class externality
dimensions (`ResourceDim`: `GridCarbonGramsCo2`, `PeerVerifierMillis`,
`CorpusBitsAdded`, the positive `KnowledgeSpillover`, …), Pigouvian-priced,
oracle-attested, on-chain anchored. The differentiator is **provable** externality
receipts — the anti-greenwashing primitive carbon/ESG markets lack.

## Monetization without betraying trustlessness

A trustless credible auction has **no rent chokepoint** — you can't tax the trade
(forkable). So:

- **Don't tax the trade.** The clearing is a public good.
- **Charge for proven work** — verification / witnessing / recompute-as-a-service,
  metered over x402 (a service station beside the road, not a toll booth).
- **Charge for the compliance / ESG control plane** — enterprises pay to *prove*
  their agent commerce is clean (verifiable externality receipts for regulatory /
  ESG reporting).
- **Route the externality pool to the commons, not to rent** (below). The org takes
  a *bounded, governance-capped* operations fee at most.

Verifiability is what makes the social-good claim **credible instead of
greenwashing**: the system's own receipts let anyone audit that the money went
where claimed. Trustlessness is the enabler, not the obstacle.

## What ships now: `commons` routing (the "watch the money fund the fix" primitive)

`nucleus_econ_kernels::commons::route_to_commons(pool_micro, &shares)` routes the
Pigouvian pool (`PigouvianClearing::rebate_pool_micro_usd`) across remediation
destinations with a **no-skim conservation guarantee**: the allocations sum to
**exactly** the pool (integer-division dust assigned, nothing lost or skimmed).
Pure + deterministic, so a settlement contract can run it on-chain and anyone can
recompute the split. Example default split (governance-set):

| destination | share |
|---|---|
| carbon-removal / drawdown | 60% |
| affected-party rebate | 25% |
| public-verifier commons | 15% |

And `::settlement` (Bet B decision, ported from `SettlementDecision.lean`):
`classify → reverse / partial / release`, with `seller_gross + refund == price`
(Lean `conservation`, parity-tested) — value is never created or destroyed in
settlement.

## Structure: the right vessel

A rent-maximizing company is the wrong vessel for a trust-fabric commons. Fit =
**steward-owned / public-benefit / foundation-core**: protocol = commons; the org
sustains on verification + compliance + a bounded fee; externality revenue
transparently → remediation. **The org's own verifiable receipts audit its own
treasury** — you can prove you're non-extractive.

## Honesty boundary (load-bearing)

- **The oracle problem is the open frontier.** A Pigouvian price is only "true" if
  the externality *measurement* (e.g. grams CO₂) is honest. The `commons` router
  faithfully routes the pool; it does **not** verify a destination actually performs
  the remediation. Both are oracle/attestation problems — mitigated by the zk/TEE
  upper-envelope proofs the externality layer cites, **not eliminated**.
- **Demand is still the bottleneck.** ESG/carbon markets are real but fraught;
  verifiability is the wedge, not a demand generator.
- **No testnet overclaiming.** The honest claim today: *the mechanism to price and
  route externalities verifiably exists and is proven* (parity-pinned to Lean);
  planetary impact is downstream of adoption.
- **Routing needs governance + legal structure** — who sets λ rates, who audits the
  oracle, what counts as remediation, who controls the commons addresses.

## Next

- Extend `@coproduct/verify` `recompute()` to the cleared price **including** the
  Pigouvian component, so a counterparty re-derives both the price *and* the
  externality charge.
- Wire `commons` + `settlement` into the Bet B settlement contract (the on-chain
  destination = a transparent commons address), per
  `docs/rfcs/credible-clearing-settlement.md`.
- Tackle the externality oracle (the honest hard part) — verifiable measurement,
  not just verifiable routing.
