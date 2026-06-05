# RFC: Initial Pigouvian structure — what we price, at what λ, and why

**Status:** active (Tier-1 shipped). **Ships:**
`nucleus-externality::ResourceDim::WaterLitresConsumed` (new dimension) +
`nucleus-econ-kernels::PigouvianRates::tier1_defaults()` (published λ vector) +
the two sourced constants `LAMBDA_CARBON_SCC_MICRO_USD_PER_GRAM` and
`LAMBDA_WATER_SHADOW_MICRO_USD_PER_LITRE`.

**Companion:** [`social-good-externality-routing.md`](./social-good-externality-routing.md)
(where the collected pool goes) and
[`credible-clearing-settlement.md`](./credible-clearing-settlement.md) (Bet B,
how settlement is verified). This RFC answers the upstream question those two
assume: **which externalities do we price, and at what rate?**

## The directive

Steer agent commerce toward **social good — benefiting people and the planet** —
and make the externality charge *credible, not greenwashing*. That requires the
rate vector to be (1) measurable, (2) sourced, (3) versioned, and (4) governed —
not a magic number.

## Design rules

1. **Only price what you can measure.** A Pigouvian charge on an externality you
   can't attest is just a tax with extra steps — and it breaks the truthfulness
   property, which holds *because* the discount is computed from an
   oracle-attested claim the bidder cannot misreport (see `vcg_pigou.rs` module
   docs and `PigouvianVcg.lean`). If we can't get a signed `units_micro`, λ stays
   0.
2. **λ is a published governance parameter, not a constant of nature.** Every
   non-zero rate ships with a cited source and a one-line override point. The
   marketplace's own receipts let anyone audit that the charged λ matches the
   published one — that auditability is what makes "social good" a verifiable
   claim instead of marketing.
3. **Never double-charge one physical externality.** If dimension A is the
   *measured input* an oracle multiplies to derive dimension B's social cost,
   only B carries λ. (Carbon and water are *derived from* GPU-seconds × grid
   intensity / WUE — so GPU-seconds itself ships at λ = 0.)
4. **Tax the negatives, subsidise the positives.** Negative externalities raise
   the Pigouvian charge; positive spillovers (`KnowledgeSpillover`) are a
   subsidy added back. The split is enforced by
   `ResourceDim::is_positive_externality()` and proved in
   `PigouvianVcgMultiDim.lean`.

## Unit discipline (so the λ values are auditable)

The kernel computes, in integer `u128` math (`effective_minus_pigou_micro`):

```text
contrib_µ$  =  λ · units_micro / 1_000_000
```

Each dimension's `units_micro` is "micro-X" (the physical quantity X × 1e6).
Substituting, the contribution **per whole unit X** is exactly `λ` µ$. So to
price a social cost of `C` dollars per whole-X, set:

```text
λ  =  C · 1_000_000   (µ$ per micro-X)
```

This is why the constants read the way they do — each is "social cost in µ$ per
one whole physical unit":

| Dimension              | `units_micro` is | λ (Tier-1) | = social cost per whole unit |
|------------------------|------------------|-----------:|------------------------------|
| `GridCarbonGramsCo2`   | micro-grams CO₂e | **190**    | $190 / tonne CO₂ (190 µ$/g)  |
| `WaterLitresConsumed`  | micro-litres     | **2 000**  | $2 / m³ (2 000 µ$/L)         |

Both are pinned by unit tests (`tier1_prices_carbon_at_scc`,
`tier1_prices_water_at_shadow_price`): 1 t CO₂ → exactly $190 charged, 1 m³ →
exactly $2.

## Tier-1 — what we price at launch (carbon + water)

### Carbon — `GridCarbonGramsCo2`, λ = $190 / tonne CO₂

The flagship. λ = the **Social Cost of Carbon (SCC)**.

- **Source:** U.S. EPA (2023) *Report on the Social Cost of Greenhouse Gases*,
  central estimate ≈ $190/t CO₂ at a 2% near-term Ramsey discount rate;
  corroborated by Rennert et al., *Nature* 610 (2022) ≈ $185/t.
- **Why mid-range:** the IWG (2021) interim figure was $51/t; recent literature
  spans $100–$300/t. $190 is a defensible, citable mid-point — and λ is a
  parameter precisely so it can be retuned by governance without a logic change.
- **Measurement:** GPU-seconds (TEE-attested compute oracle) × marginal grid
  carbon intensity (grid-intensity oracle), upper-bounded by a zk envelope proof
  (per Verifiable Carbon Accounting). The residual "the sensor can lie" gap is
  the subject of [Item 3 — the externality-oracle RFC](#) (forthcoming).

### Water — `WaterLitresConsumed`, λ = $2 / m³  *(new dimension)*

The gap this RFC closes. AI's water footprint (datacenter cooling + the water
embedded in the electricity it draws) is large, *local*, and almost never
priced. We add it as a first-class dimension.

- **Source:** scarcity-weighted marginal water values — World Bank *High and Dry*
  (2016) and AWARE characterisation factors (Boulay et al., *Int. J. LCA* 2018)
  place stressed-basin shadow prices around $1–$3/m³, well above the ~$0.1–0.5/m³
  utility *tariff* (which prices delivery, not scarcity). $2/m³ is a conservative
  mid-point.
- **Why separate from carbon:** carbon is *global* — a gram costs the same
  wherever emitted. Water is *local* — a litre from a stressed basin costs far
  more than one from a wet region. Folding water into the carbon λ would mis-price
  both. (A future tier can make λ_water region-indexed.)
- **Measurement:** same TEE-attested compute oracle as GPU-seconds, multiplied by
  a regional Water-Usage-Effectiveness (WUE) factor.

### GpuSeconds — λ = 0 **on purpose**

GPU-seconds is the *measured input* the carbon and water oracles consume to
derive their figures. Charging it directly would double-count the same physical
externality (rule 3). It stays declared-and-attested but unpriced.

## Tier-2 — congestion (scoped, not yet activated, λ = 0)

Priced once we can both measure and *source* the rate:

- **`PeerVerifierMillis`** — CPU/IO load this call imposes on the witness
  federation. A genuine congestion externality; the natural λ is the marginal
  cost of verifier capacity (metered over x402), which the witnessing market will
  reveal. Activate when that price signal exists.
- **`CorpusBitsAdded`** — storage/curation load on the shared verifier-training
  corpus. Small per-call; aggregate matters. λ from marginal storage + curation
  cost.

## Tier-3 — the positive spillover (subsidy, λ = 0 until funded)

- **`KnowledgeSpillover`** — reusable knowledge this call produces (a *benefit* to
  third parties). Modelled as a **negative-λ subsidy** (added back, not
  subtracted). It is the one dimension where the "tax" is a reward for doing
  social good. Activating it requires a funded subsidy pool — a governance + funding
  decision, deferred until the commons pool (see the routing RFC) is non-trivial.

## Deferred (not in any tier yet)

Real externalities we deliberately do **not** price, because we can't yet
*measure* them credibly per-call (rule 1) — listing them is the honest move, so
nobody mistakes silence for "zero":

- **Land use / siting**, **e-waste / embodied hardware** — lifecycle, not per-call.
- **`FxVolatilityDelta`**, **`AuctionDelay`** — mechanism-internal; priced via the
  auction itself, not a Pigouvian add-on, until shown otherwise.
- **Data-privacy harm**, **labor displacement** — real and important, but no
  defensible per-call attested metric exists. Pricing them on a guess would be the
  greenwashing we're trying to avoid.

## Honesty boundary

Everything above prices the **attested** consumption. The charge is exactly as
honest as the oracle that signs `units_micro`. Tier-1 ships with:

- ✅ a *verifiable* λ (published constant, unit-test-pinned, anyone can recompute
  via `@coproduct/verify`'s `recomputeVcgPigou`), and
- ⚠️ an *attested-not-proven* `units_micro` — the irreducible "the sensor can
  lie" residue, which the externality-oracle RFC (Item 3) addresses with
  TEE-attested telemetry + a grid-carbon oracle + a zk upper-envelope, and is
  explicit about what remains un-provable at the crypto layer.

We claim the first and never overclaim the second.

## What this RFC changes

- `nucleus-externality`: new `ResourceDim::WaterLitresConsumed` (tag `water_l`,
  appended last so prior multi-dim digests/signatures stay valid).
- `nucleus-econ-kernels::vcg_pigou`: `PigouvianRates::tier1_defaults()` +
  `LAMBDA_CARBON_SCC_MICRO_USD_PER_GRAM` (190) +
  `LAMBDA_WATER_SHADOW_MICRO_USD_PER_LITRE` (2 000), with the math pinned by tests.
- No change to the proven Pigouvian path: `PigouvianVcgMultiDim.lean` is generic
  over the tax/subsidy dimension lists, so adding a tax dimension and setting
  rates is covered by the existing truthfulness proof.
