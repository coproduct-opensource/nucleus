# Marketplace dashboard — roadmap

Three independently-verifiable properties of agent commerce. Each lands behind a
**trait seam**, so the real implementation drops in without reshaping the core.

| Pillar | Property | Seam | Status |
|--------|----------|------|--------|
| **Safe** | dangerous flows refused before money moves | `FlowDeclaration::decide` (IFC gate) | ✅ shipped |
| **Verifiable** | portable receipts anyone can re-check | `ReceiptIssuer` | ✅ shipped (hash-rebind); ⛳ signed-bundle on the real path |
| **Real** | actual on-chain settlement | [`Facilitator`](src/facilitator.rs) | ⛳ `FakeFacilitator` today; `X402Facilitator` next |
| **Efficient & truthful** | truthful price discovery + priced externalities | [`Clearing`](src/clearing.rs) | ⛳ `FixedPriceClearing` today; Pigouvian / VCG next |

Everything tagged ⛳ is a future *implementation of an existing trait* — the wire
contract (`MarketEvent`) and the orchestrator already carry it.

## 1. Real settlement — `Facilitator`

`X402Facilitator` (drives `x402-reqwest` against Base Sepolia with a
keystore-backed signer) lands in a **separate example workspace**, so the
alloy/x402 tree never enters this crate or main CI. The orchestrator is already
generic over `Facilitator`; settlements then carry
`BalanceSource::OnChainTestnet` (a reducer invariant forbids on-chain numbers
without a confirmed tx). The keystore signer (encrypted-at-rest, Keychain/KMS) is
sequenced here.

## 2. Verified clearing — `Clearing` (the VCG / externality pillar)

The [`Clearing`](src/clearing.rs) trait takes a **batch of bids** and returns one
outcome per bid (allocation + price + externality), so a real mechanism that
needs the whole bid profile drops in directly:

- **`PigouvianClearing`** — turns the IFC gate's binary allow/deny into a *priced
  gradient*: a call on the safe slope pays a surcharge that internalises the
  externality (risk / congestion) it imposes, derived from the bid's
  `externality_signal` (today: declared-input count; future: a defined,
  ideally-proven risk measure). `MarketEvent::Settlement` already carries
  `cleared_method` + `externality`.
- **`VcgClearing`** — clears a *contended* resource truthfully. VCG needs the
  full bid profile, hence the slice-based `clear(&[Bid])`. The current per-call
  loop passes a single-element slice (no contention); a future round-batching
  orchestrator passes the full profile. The clearing rule runs the **exact**
  sorry-free Lean-proven VCG function (mind the verified-spec / unverified-impl
  hazard — add a parity proptest binding the money-path to the theorem).
- The cleared price is folded into the **receipt** so price truthfulness is
  independently re-derivable: the "provably-honest clearing" artifact, the
  verified-clearing layer above x402 / AP2 / ERC-8004.

## 3. Identity & reputation — ERC-8004 anchoring

Register seller agents in the Identity Registry; write each receipt's hash to the
Validation Registry; derive a per-agent reputation surfaced in the feed. Base
Sepolia testnet; in the same separate-workspace pattern as real settlement.

## Honesty line (applies to every pillar)

Testnet only. The IFC verdict is model-level over *declared* inputs
(coverage-limited, per-call). Simulated money is source-badged and can never
appear as on-chain money. A verdict/price is only "verified" to the extent the
money-path runs the exact proven function — otherwise it is a claim, not a proof.
