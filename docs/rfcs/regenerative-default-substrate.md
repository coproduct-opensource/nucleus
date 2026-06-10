# RFC: The regenerative-default agent substrate (north star)

**Status:** north star / intent-on-record. **Not a spec, not a claim of done.**
This RFC commits the *intent* — the defaults and the self-binding governance we
mean the substrate to have — while the rules of the agent economy are still wet.
It names what is already built, what is deliberately dormant, and what we bind
ourselves to. Related: `social-good-externality-routing.md`,
`credible-clearing-settlement.md`, `receipt-provenance-defection.md`,
`reputation-weighted-clearing.md`, `externality-oracle.md`.

## Why now

The settlement layer of the agent economy is being defined this cycle, and
defaults become invisible — nobody re-litigates TCP/IP. Whoever sets the default
defines, silently and for a long time, **what an agent is rewarded for.**

The path of least resistance — the *runaway externalizing force* — is not a
villain, it is physics: agents transact at **private** cost and dump the rest
(compute, energy, attention, labor displacement, the erosion of shared trust)
onto a commons that has no invoice. Winner-take-all; vendor-owned trust; truth
replaced by reach. This is the **default** unless the substrate makes a different
path cheaper.

This RFC is the different path, made the default.

## The thesis: a grammar in which the lie and the externality do not compile

Don't build a better marketplace. Build a **language for agent commerce in which
the only grammatical sentence is a true one whose true cost is part of its
syntax.** Externalizing isn't policed — it's *ungrammatical*. Four properties,
each tied to a primitive that already exists in this repo:

1. **Truth is the medium — recompute, not trust.** Value is earned by being
   verifiably right, not by capturing attention or trust. *Built:*
   `nucleus-recompute` (`verify_receipt` re-derives every cleared number from
   declared inputs), `nucleus-oracle` (held-out grading; the adversarial
   pressure-test shows a claim that doesn't recompute earns only what it actually
   achieved).
2. **The true cost is in the sentence — Pigouvian by construction.** The
   externality is priced at the point of transaction, not after.
   *Built (dormant):* `nucleus-externality` (signed externality envelopes +
   rate-setter) and `nucleus-creditworthiness::CreditDimension::Externality` — a
   **first-class but inert** dimension today.
3. **Surplus flows to the commons — by conservation, not goodwill.** Slashed
   collateral and externality dues route to the commons, never skimmed to an
   operator. *Built:* the `route_to_commons` / no-skim conservation path reused by
   the bonding layer.
4. **No dominator — anyone verifies.** No central trusted auctioneer; portable
   proof, not vendor-owned trust. *Built/designed:* `credible-clearing-settlement`
   (the OSS recompute *is* the fraud proof), the confused-deputy-guarded
   authenticated identity (`receipt-provenance-defection`).

The coalition mechanics (the dogfood rounds: `nucleus-oracle`'s
`dogfood_*_settlement` examples) make "find the others" mechanical — value
accrues to coalitions and is split by Shapley, with the irreplaceable producer
and the substitute verifiers each paid their structural worth.

## The danger: how this medicine becomes the poison

A north star worth the name names the ways it fails into the thing it opposes.

1. **The truth-toll.** A "monetize proof" layer can become the rent-seeking
   gatekeeper of truth — a trust oligopoly. **Guard:** because it is *recompute*,
   verification stays free and forkable forever. We sell convenience and
   coordination *above* the proof; we never sell the right to check. The day the
   checking can be gated, we have become the toll we replaced.
2. **The rate-setting cartel.** Pricing true cost is power; an
   externality-pricing monopoly is a new dominator in green clothing. **Guard:**
   externality rates and accounting must themselves be recompute-verifiable *and*
   contestable — governed as a commons (see Governance), not emitted by one
   oracle.
3. **Reputation as inherited aristocracy.** Bond-substituting standing
   (`reputation-weighted-clearing`) is a moat if it compounds into unaccountable
   incumbency (the Matthew effect). **Guard:** Sybil-cost is the floor; standing
   must stay *earned* (decaying, contestable), never unearned rank. This is an
   open watch item, not a solved one.
4. **Efficiency as accelerant (the deepest one).** A more efficient *extractive*
   economy is worse than an inefficient one; frictionless commerce accelerates
   whatever its defaults reward. **Guard:** the defaults bake in internalization +
   commons-routing, so efficiency gains flow to the commons by construction.
   Efficiency *without* internalization is the accelerant; efficiency *with* it is
   the cure. This is the whole reason the defaults must ship regenerative.

## Governance: Ostromian, not Leviathan and not enclosure

Elinor Ostrom showed a commons can be governed without either privatization or a
central authority. The externality/commons layer adopts her design principles as
constraints:

- **Polycentric & contestable rate-setting** — not a single oracle; nested,
  appealable, recompute-checkable.
- **Clear, verifiable boundaries** — who contributes, who benefits, measured by
  recompute, not assertion.
- **Proportional dues & graduated response** — true cost in, graduated slashing on
  defection (already the bond/anti-grief shape).
- **Transparent, auditable accounting** — the commons ledger is
  recompute-verifiable and dogfooded on ourselves.
- **The right to exit / fork** — the ultimate check on capture (see below).

## The self-binding commitment (tie yourself to the mast)

The rule-setter must make it structurally impossible to become the rent-extractor
— *before* hearing the sirens:

1. **Route our own take to a governed commons.** The substrate's own surplus
   flows to a steward / public-benefit vessel, with recompute-verifiable
   accounting we publish and dogfood — the same way we dogfooded the coalition
   settlement.
2. **Keep it forkable; the proof of non-capture is exit.** The core is open; the
   verification is free; anyone can leave and take the grammar with them. A
   commons defended by the right to walk away cannot be quietly enclosed.
3. **Defaults over decrees.** We earn the ethics by owning the *defaults*, not by
   policing users — and we relinquish the power to gate truth.

## The four concrete moves

1. **Flip the default from extractive to regenerative.** Light up the dormant
   `CreditDimension::Externality` (and the Pigouvian + commons-routing path) and
   ship it **ON by default** in the reference implementation, so the substrate is
   regenerative out of the box and you must go out of your way to build the
   extractive version. *(Today it is reserved/inert — the
   "config flip, not a schema migration" seam is deliberate.)*
2. **Publish the grammar as an open standard, not a product** — the way ACME /
   Let's Encrypt made "encrypted by default" the path of least resistance. Own the
   defaults; keep it forkable.
3. **Bind our own hands** — route the substrate's take to the governed commons,
   accounted recompute-verifiably, dogfooded on ourselves.
4. **Make it joinable — find the others** — co-govern from day one via the
   coalition mechanics; a commons defended by one actor is a fief.

## Why this *is* the mission (not a side quest)

An agent economy with no accountable, verifiable, externality-aware substrate is
itself a safety failure: unaccountable agents, no recourse, harms with no address
to send the bill to. Recompute-verifiable, attributable, true-cost-priced,
commons-routing agent actions are the **economic-layer instantiation of beneficial
AI** — constitutional infrastructure for agents. Proof-not-trust is
alignment-adjacent: verifiable claims about what an agent actually did.

## Honest scope

**Wired today (in code, with tests):** recompute, held-out oracle, the credit
ledger (append-only hash chain), the externality crate, the commons-routing
primitive (`route_to_commons`, no-skim conservation, pinned to `Commons.lean`'s
`routed_conserves`), credible-clearing design, coalition settlement (dogfooded).
The `CreditDimension::Externality` credit dimension is **active and load-bearing**
on the bond-substituting reputation: recompute-verified `Commons` receipts build
standing exactly as honest settlement does, and a recompute-Mismatch (dues
claimed but not routed) burns it (`nucleus-creditworthiness` `mint` + the
`externality_credit_builds_debit_burns` property test). A
**recompute-verifiable commons-ledger accounting view** now exists
(`nucleus-creditworthiness::commons_view`): a pure, read-only projection over
recompute-verified `Commons` receipts that re-derives, per destination + total,
the externality dues actually routed to the commons — anyone replaying the same
receipts recomputes the same totals ("watch the money fund the fix"). It re-runs
`route_to_commons` and counts only receipts that recompute, so a dumped
externality can never inflate the routed figure.

**Still dormant / operator-gated (NOT done — do not read this list as shipped):**
the *reference-default flip* of the deployed clearing config from extractive to
regenerative (a deliberate, reviewable operator call — the "config flip, not a
schema migration" seam); routing the substrate's own take to a governed commons
(real money / custody — HARD-STOP, counsel-gated); the Pigouvian *rate-setting*
process (what the dues *should* be — a governed, contestable process; rates stay
inputs/params, never a baked-in constant); the governed-commons steward / PBC
vessel; adoption as an open standard; the anti-aristocracy decay on standing; the
last-mile attestation that a destination actually *performed* the remediation
(an oracle problem). This RFC is **intent on the record**, so the commitment is
legible before the incentives drift — not a claim that the operator-gated items
are done.

## Decision (2026-06-07): Vision 2 — the regenerative agent-economy substrate

**Operator decision.** `nucleus` is **the verifiable, regenerative agent-*economy*
substrate** — not a domain-agnostic generic runtime that happens to host some
economics. Economic + regenerative vocabulary (Pigouvian externality pricing,
commons rebate, the economic lineage edge kinds, true-cost dues) is **first-class
and canonical-public**, alongside the already-public `nucleus-econ-kernels` /
`nucleus-externality` / `nucleus-creditworthiness`.

**Rationale — the strongest iterated game.** A substrate whose *dominant strategy
is regenerative + honest behavior* is the most defensible position there is: it is
the regenerative-dominance conjecture turned into product identity (see
`docs/rfcs/regenerative-dominance.md` when written). In the repeated game,
externalizing and lying are meant to be strictly dominated; making that the
substrate's *identity*, not a bolt-on, is what makes the equilibrium stick. Social
good is not a feature here — it is the load-bearing incentive.

**What this resolves (HD-2 → Option A).** The platform-vs-public fork of the
economic vocabulary is resolved by upstreaming it into the public canonical
crates: the economic `EdgeKind` variants (`Bid`, `Allocation`, `Settlement`,
`Externality`, `WelfareRebate`, `PigouvianRateUpdate`, `Dispute`, `MetricClaim`,
`ContractEvaluation`) + `VerifierAttestation` + the `sink-io` feature land in
public `nucleus-lineage`; `cube` + `rebate` land in public `nucleus-externality`
(which already carries `assurance`). The generic IFC/security primitives stay as
clean as they can, but we accept — deliberately — that `nucleus-lineage` becomes
the agent-*economy*'s lineage crate, because economics *is* the domain.

**What it unblocks.** Once the economic vocabulary is canonical-public, the
consolidation chain completes: `nucleus-lineage` + `nucleus-externality` reconcile
(merge-both → publish) → `nucleus-econ-kernels` adopts published → the platform
consumes published canonical → `ci/allowed-dups.txt` shrinks toward empty → the #3
vendoring/adapter layer deletes itself. See
`nucleus-platform/docs/CONSOLIDATION-PLAN.md` (HD-2 now decided).

**Accepted tradeoff (honest).** Choosing Vision 2 forecloses the "tiny generic
runtime reused for non-economic deployments" option: the core lineage crate now
carries economic edge kinds a purely-generic consumer would not need. We take
that cost knowingly — the bet is that the regenerative economy *is* the product,
and one canonical, recompute-verifiable substrate beats a pristine-but-forked one.
