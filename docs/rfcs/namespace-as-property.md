# RFC: Namespace-as-property (Tier-2 — a durable, tradeable home for recompute-verified reputation)

**Status:** intent-on-record / posture only. **Not a spec, not a built primitive,
not a claim that anything will ever be minted, sold, or transferred.**

This RFC records the *design posture* deferred as **Tier 2** by
`standing-airdrop-optionality.md`: treating an agent's claimed NAME / identity as
**property with history** — the ENS / `.com`-domain lane — so the time-rooted,
recompute-verified standing that Tier-1's `eligibility_snapshot` already computes
has a durable, scarce home. Nothing here is built. No registry, no mint, no sale,
no transfer API exists or is proposed for implementation by this RFC. This is
intent on the record so the legal posture is legible *before* any line of code or
any operator decision exists to drift it.

Related: `standing-airdrop-optionality.md` (Tier-1, the standing math this binds
to), `regenerative-default-substrate.md` (the north star + the
reputation-as-aristocracy watch item), `agent-efficiency-credit.md` (the
`EvalSubject` content-addressed identity that is the namespace hook),
`receipt-provenance-defection.md`, `reputation-weighted-clearing.md`.

---

## ⚠️ Notice — read this first

**This confers no right, claim, or promise. It is not a security. It is not for
sale. Nothing here is built.**

What this RFC describes is a *posture*: that IF a name/identity registry were ever
built, the legally cleaner lane is to treat a name as **consumptive property** (a
durable, scarce handle you use), **not** as an investment contract. A name is the
shell; the verified history is bound to the events, not to the price of the shell.
**No promise is made** that any registry, name, market, value, or benefit of any
kind will ever follow. Any actual mint, sale, or transferable profit instrument is
**Tier 3** — explicitly deferred behind an operator + securities-counsel decision
and **not** this RFC.

---

## Why now

Tier-1 ships a real primitive: `eligibility_snapshot` — a pure, recomputable
projection over the append-only credit chain into abstract, **non-transferable,
identity-bound** basis points. That non-transferability is exactly what keeps it
Howey-clean, and it is also its limitation: standing that cannot move has no
durable, portable *home*. "Early verifiable track record" is real and time-scarce
(Tier-1's time-rooting curve makes earlier verified work root a larger share), but
without a scarce handle to attach it to, an identity is just an ephemeral key.

The clean way to give reputation a home without minting a security is the lane the
web already proved: **names**. ENS names and `.com` domains are *property* — scarce,
claimable, tradeable handles with history — and they are not securities, because
their value is consumptive (you use the name) rather than a passive expectation of
profit from a common enterprise run by someone else. A name is a durable address
that an agent's recompute-verified history can accrue *to*.

This RFC records that posture now, while the design is wet, so the bright lines are
on the record before there is any registry, any market, or any incentive to blur
them.

## How this complements Tier-1 (the bind, stated precisely)

Tier-1 standing is **non-transferable and identity-bound** — and stays that way.
This RFC does not propose making standing transferable. Instead:

- **The NAME is the (potentially) transferable shell.** A name is a scarce,
  claimable handle — property with history, like a domain.
- **The HISTORY is soulbound to the verified events, not to the shell.** The
  recompute-verified `CreditEvent`s (and, per `agent-efficiency-credit.md`, the
  `EvalLedger` records) are append-only facts on a public chain. They are bound to
  the *identity that produced them and to the receipt hashes that recomputed* —
  not to who currently holds the name.
- **A name therefore gives reputation a portable, scarce HOME without making the
  reputation itself a tradeable balance.** The market (if one ever existed) would
  be for the *handle*, a consumptive good; the *track record* remains a
  recompute-verifiable public fact that anyone can independently re-derive.

The credibility still comes from recomputability, not from a promise: whoever
holds a name, anyone can recompute exactly what verified history is bound to the
identity(ies) that name points at. The name carries the history *by reference*; the
history is recompute-verified.

### The content-addressed hook already exists

`agent-efficiency-credit.md` already defines `EvalSubject` — a content-addressed
identity (`subject_hash` of `(prompt, model, params, tools)`, with recorded-not-
inherited `parent_hash` fork lineage) and explicitly calls it "the
namespace-as-property hook." A human-readable name in a registry would be a
*pointer* to such content-addressed identities; changing what produces the work is
a new subject (a fork), and a fork earns its own record. The namespace is the
human-legible shell over the content-addressed, recompute-anchored substrate.

## Bright lines (Howey) — carried verbatim from the Tier-1 RFC, and they hold here

- **No capital raise.** Nothing here raises money or accepts investment.
- **No sale of standing.** Standing is non-transferable and not for sale. (A name,
  if ever built, is consumptive property — distinct from standing, which stays
  identity-bound and non-transferable.)
- **No marketing of price appreciation.** No "moon," "investment," "buy now,"
  "profit," "guaranteed," "will be worth," or any price-appreciation language
  anywhere — in code, docs, or comms.
- **No promise of distribution.** A name **may** be a home for recognition; no
  promise is made that any registry, market, value, or benefit will ever exist.
- **No real funds / keys / mainnet / wallet** are touched. This RFC is posture
  only; nothing is built.

The Howey triggers to avoid **regardless of wrapper** are: **centralized control +
a capital raise + marketing of profit-from-our-efforts.** A name framed and
operated as *consumptive property* (you claim and use a handle) avoids all three;
a name marketed as a passive appreciating asset does not. The lane is legally
cleaner *only* if it is actually consumptive — the framing must match the operation,
or it is just a security in a domain costume.

Framed strictly: *a name is consumptive property (a handle you use), not an
investment contract; the verified history is a recompute-verifiable public fact
bound to the events, not a tradeable balance; no promise is made; not a security;
not for sale; nothing here is built.*

## What is deferred (one-way doors, out of scope here)

This RFC records the **namespace-as-property posture only.** Explicitly **not**
built and **not** decided here:

- **Any actual registry, mint, name issuance, or on-chain name.**
- **Any sale, auction, or transfer of names.**
- **Any transferable PROFIT token** or any instrument whose value is a passive
  expectation of appreciation — that is **Tier 3**, a one-way door behind an
  explicit **operator + securities-counsel** decision, and is out of scope of both
  this RFC and Tier-1.

Crossing from "non-transferable standing + recorded posture" into "an actual
transferable, sellable name market" is a deliberate one-way door. This RFC builds
none of it; it records only the *posture* that, if that door is ever opened, the
name is consumptive property and the history is soulbound to the verified events.

## Honest open questions (do not paper over)

These are open, not solved. Recording the posture does not resolve them; opening
the Tier-3 door without answers here would be reckless.

1. **Name-squatting / Sybil on names.** A scarce-handle namespace invites
   squatting and Sybil land-grabs. Tier-1's Sybil-floor protects *standing accrual*
   (empty identities earn zero), but it does not protect the *name space* itself.
   How are names claimed, priced, and reclaimed to deter squatting without
   recreating a pay-to-win incumbency? Unsolved.

2. **Binding reputation across rotation / transfer (the core question).** If a name
   is sold, does its history go with it? The intended answer is **no — the history
   is soulbound to the verified events and the identity that produced them; only
   the NAME (the shell) transfers.** But that has sharp edges: a buyer wants the
   name *because* of its associated track record, so a sold name's history must
   remain **auditable and clearly attributed to the original producer**, never
   silently re-credited to the new holder. How a name re-points to a new
   content-addressed identity after sale — and how a verifier sees "this name
   currently points at identity B, but its visible history was earned by identity
   A" — is unspecified and hard. Getting this wrong launders reputation.

3. **The tension between "tradeable" and "trustworthy."** A handle that can be sold
   is, by construction, a handle whose *current holder* may not be who earned its
   reputation. The whole value proposition collapses if a buyer inherits trust they
   did not earn. The posture (history soulbound, name transferable) is the proposed
   resolution, but it is a *claim*, not a proof: it depends entirely on every
   consumer recomputing the bound history rather than trusting the name at face
   value. A sold name's history **must remain auditable** — this is a hard
   requirement on any future design, and it is not yet shown to be achievable in a
   way buyers will actually respect.

4. **Registry neutrality / forkability.** Per the north-star self-binding
   commitment (`regenerative-default-substrate.md`), the verification must stay free
   and forkable — "the proof of non-capture is exit." A name registry is a natural
   point of *capture* (whoever runs the registry can gate, equivocate, or rent-seek
   on names). Can the registry itself be neutral, forkable, and recompute-checkable,
   the way the credit chain is? An equivocating or capturable registry reintroduces
   exactly the vendor-owned-trust dominator the substrate exists to remove.
   Unsolved.

5. **Reputation as inherited aristocracy (carried from the north star's watch
   list).** `regenerative-default-substrate.md` flags bond-substituting standing
   compounding into "unaccountable incumbency (the Matthew effect)" as an open watch
   item. A *tradeable* namespace can sharpen this: scarce early names plus
   compounding standing could ossify into rank that is bought, not earned. Standing
   must stay earned, decaying, and contestable; a name market must not become a way
   to *buy* rank. How the namespace design avoids hardening the aristocracy is open.

6. **Transparency-log gap (carried from Tier-1's honesty boundary).** Tier-1 notes
   the credit chain is tamper-evident, not yet a non-equivocating transparency log
   (the Merkle-leaves + signed-tree-head + C2SP-witness-cosignature work is
   tracked). A namespace binding history "by reference" inherits that gap: an
   operator who controls the store could equivocate on *which* history a name points
   at. Closing the transparency-log gap is a prerequisite to any trustworthy name
   binding, not an optional extra.

These are recorded as open precisely so the posture is honest: the namespace lane
is the *legally cleaner* and *more durable* home for verified reputation, but it is
not yet a safe one, and none of it is built.
