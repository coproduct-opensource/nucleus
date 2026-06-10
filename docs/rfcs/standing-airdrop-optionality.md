# RFC: Standing airdrop optionality (Tier-1 non-transferable recomputable standing)

**Status:** intent-on-record + shipped primitive (Tier-1 only). **Not a spec for
any distribution; not a claim that anything will ever be distributed.**

This RFC records the *math* and the *legal posture* of a pure, deterministic,
recomputable function that projects an identity's already-recompute-verified
track record into a HYPOTHETICAL basis-point allocation. The function is built
(`crates/nucleus-creditworthiness/src/eligibility.rs`,
`eligibility_snapshot`). Nothing downstream of the math — no token, no
distribution, no sale — is built, and Tiers 2 and 3 below are explicitly
deferred behind an operator + securities-counsel decision.

Related: `regenerative-default-substrate.md`, `agent-efficiency-credit.md`,
`receipt-provenance-defection.md`, `reputation-weighted-clearing.md`.

---

## ⚠️ Notice — read this first

**This confers no right, claim, or promise. It is not a security. It is not for
sale.**

What this RFC describes is a *non-transferable standing* that **MAY** inform some
future form of recognition. **No promise is made** that any recognition,
distribution, value, or benefit of any kind will ever follow. The basis points
are **abstract math** — units of a recomputable projection over a public hash
chain — **not money, not a token, not a transferable balance, not an investment.**

The implementation deliberately exposes **no transfer, move, or mint API**. An
`Allocation` is a read-only `identity -> basis-points` map and nothing else.

---

## Why now

"Early verifiable contribution may be recognized later" is a sentence everyone in
this space says and nobody can make *credible* — it usually reduces to "trust the
operator's future generosity." The substrate already has the one ingredient that
makes it credible without a promise: a **recompute-verified, append-only credit
hash chain** (`nucleus-creditworthiness::ledger`). Every `CreditEvent` on it was
minted from a receipt that already recomputed, from DECLARED inputs, so its
economic magnitude cannot be inflated by the very lie the recompute catches.

So instead of *promising* future recognition, we ship the **math** of it: a pure
function anyone can rerun, in the browser, over the public chain, to see exactly
what standing each identity has rooted. The credibility comes from
recomputability, not from a promise — and recomputability is exactly what keeps
it Howey-clean.

## The incentive logic (greed pulls in, proof keeps honest)

The whole point is that the *only* way to increase your projected standing is to
do real, recompute-verified work:

- Eligibility derives **only** from recompute-gated `CreditEvent`s already on the
  append-only chain. There is **no new accrual path** — the snapshot reads the
  existing ledger, it does not let anyone mint standing a new way.
- The magnitude of each event was already recompute-verified from declared
  inputs, so it cannot be inflated by lying.
- A **Sybil-floor** (`min_distinct_receipts`) requires an identity to carry at
  least N *distinct* receipt hashes before it is eligible at all — one replayed
  receipt cannot farm standing, and spinning up empty identities buys nothing
  (empty / single-receipt → zero allocation).

Therefore greed is satisfiable **only** by honest, verified contribution. Greed
pulls agents in; proof keeps them honest. If eligibility could be farmed without
verified work, that would be the extraction vector — so by construction it cannot.

## The math (what the function actually does)

`eligibility_snapshot(identities: &[(&str, &[LedgerEntry])], params: &SnapshotParams) -> Allocation`

Per identity, over its contiguous `seq`-ordered chain:

1. **Sybil-floor.** Count DISTINCT `receipt_hash`es; drop the identity if it has
   fewer than `params.min_distinct_receipts` (clamped to ≥ 1, so an empty history
   never qualifies).
2. **Net verified standing.** Σ(credit `weight_micro`) − Σ(debit `weight_micro`),
   floored at 0 (a deeply-defected identity has zero standing, never negative).
3. **Per-dimension weighting.** Each event's weight is scaled by a governed,
   fixed-point per-dimension multiplier (`params.dimension_weight`, default ×1).
4. **Time-rooting / early-mover.** Each event is scaled by a factor that is
   **non-increasing in its position** in the chain (a governed integer half-life,
   `params.time_root_half_life`; `0` disables it). Earlier verified contribution —
   the time-scarce, backdated-unforgeable track record — therefore roots a larger
   share.
5. **Normalization.** Surviving identities' weights are apportioned to exact
   integer **basis points** (sum ≤ `10_000`) by largest-remainder (Hamilton)
   apportionment — the same deterministic integer discipline as the Shapley split
   elsewhere in the substrate.

Properties proven as tests (`eligibility::tests`): determinism, permutation-
invariance over identity order, monotonicity (adding a credit never lowers raw
weight), debit-reduces-eligibility, Sybil-floor exclusion of single-distinct-
receipt identities, normalization sums to ≤ 10 000 (= 10 000 iff anyone is
eligible), and all-debit / empty → 0. The function is **integer-only and
WASM-pure**: it compiles to `wasm32-unknown-unknown` exactly like `ledger.rs`, so
anyone can recompute the identical allocation client-side over the public chain.

## Honesty boundary (TCB)

This is a **recomputable projection over already-verified events, not a
guarantee.** The function does not itself verify receipts or chains — feed it
only chains whose entries were minted from receipts that already recomputed
(`mint`) and validated by `ledger::verify_chain`. The chain is **tamper-evident,
not a non-equivocating transparency log** (an operator who controls the store can
still equivocate; closing that gap — Merkle leaves + signed tree head + C2SP
witness cosignatures — is tracked in the `ledger` honesty boundary). The
time-rooting curve and per-dimension weights are **governed parameters, not
theorems**: they choose *which* recomputable projection is taken; given the same
chain and the same params the projection is reproducible byte-for-byte.

## Tiered token stance

This RFC ships **Tier 1 only.** Tiers 2 and 3 are recorded as intent/posture and
are explicitly **not built here.**

- **Tier 1 — non-transferable recomputable standing (THIS, now).** A pure
  recomputable projection over the verified chain into abstract basis points.
  Non-transferable, identity-bound, consumptive/reputational only. Confers no
  right, claim, or promise. Not a security, not for sale. **Built.**

- **Tier 2 — namespace-as-property (deferred).** Treating a claimed agent name /
  identity as property with history (the ENS/`.com` lane), so reputation has a
  durable home. Distinct posture; **not built here**; out of scope.

- **Tier 3 — transferable token / actual distribution (deferred; one-way door).**
  Any TRANSFERABLE token, any actual distribution of value, any on-chain mint,
  any sale. This is a **securities-counsel + operator one-way door** that is
  **explicitly out of scope** and **not built**. Exercising any optionality is
  gated and not implemented; this RFC builds only the optionality math.

## Bright lines (Howey) — never cross

- **No capital raise.** Nothing here raises money or accepts investment.
- **No sale of standing.** Standing is non-transferable and not for sale.
- **No marketing of price appreciation.** No "moon," "investment," "buy now,"
  "profit," "guaranteed," "will be worth," or any price-appreciation language
  anywhere — in code, docs, or comms.
- **No promise of distribution.** Standing **may** inform future recognition; no
  promise is made that it will.
- **No real funds / keys / mainnet / wallet** are touched. This is pure
  computation over existing public data only.

Framed strictly: *non-transferable standing that MAY inform future recognition;
no promise is made; not a security; not for sale.*

## What is deferred (one-way doors, out of scope here)

Any transferable token, any actual distribution of value, any on-chain mint, any
sale, and the Tier-2 namespace-as-property design. All gated behind an explicit
operator + securities-counsel decision. None are built by this RFC.
