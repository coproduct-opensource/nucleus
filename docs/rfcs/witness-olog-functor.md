# RFC: The witness→olog functor — proof-of-work that *accumulates* (Phase 2)

**Status:** scoping. **Depends on:** `ck-kernel` + `ck-types::WitnessBundle`
(admission + content-addressed evidence, shipped), the `merge-gate` witness
archive (ReDB, content-addressed, shipped), and the `olog` runtime + Lean core
(Spivak-style categorical KB, shipped). **Companion:**
`docs/CATEGORICAL-LANDSCAPE.md` (names this arrow as *intended*) and
[`credible-clearing-settlement.md`](./credible-clearing-settlement.md) (the
settlement spec→witness→kernel pattern this generalises).

## The gap this closes

Today every proof we produce is **per-transaction and ephemeral**. The
constitutional kernel admits an amendment, a settlement validator checks a
verdict, the marketplace recomputes a clearing — each is verified *in the
moment* and then the evidence is filed away. The `merge-gate` archives every
admitted `WitnessBundle` (content-addressed, lineage-linked), but those witnesses
are **never internalised into the categorical knowledge base**. The
`merge-gate → olog` arrow is named in `CATEGORICAL-LANDSCAPE.md` but the wire
does not exist (a grep for it returns zero).

So we can say *"we proved this one task."* We cannot yet say *"here is the
audited, categorical, queryable record of **everything** we have ever proven —
and proofs of composite work compose."* This RFC scopes that bridge.

## The one idea

Admission is already a structure: the kernel enforces a **dual-DAG lineage**
(every admitted node points at its admitted parent). The olog is already a
**category** (objects = types, morphisms = relationships, commuting diagrams =
laws). The bridge is a **functor**:

```text
Gov : 𝓦  ⟶  𝓞
```

- **𝓦 (the witness category)** — objects are admitted `WitnessBundle`s
  (identified by their content-addressed `digest()`); morphisms are the lineage
  edges the kernel already enforces (`parent_digest → candidate_digest`).
  Identity = a node's self-edge; composition = transitive admitted lineage.
- **𝓞 (the olog)** — the categorical KB. Objects are task/spec types; morphisms
  are validations and relationships.
- **Gov** maps each admitted witness to an **instance** (a fact / a Set-valued
  functor) in the olog: "task T, spec-hash H, was delivered by agent A and
  admitted with verdict V, evidenced by witness W."

The payoff is **functoriality**: because `Gov` preserves identity and
composition, *a pipeline of admitted tasks maps to a composed fact.* Proof-of-work
**composes** — chained proven steps become a proven pipeline, automatically,
rather than a pile of unrelated receipts. That is the difference between a
shoebox of receipts and a ledger.

## Why a functor (and not just a database insert)

A plain "log the witness to a table" loses the thing that matters: the **laws**.
Modelling admission as a functor into the olog buys three properties a table can't:

1. **Composition is preserved by construction.** `Gov(g ∘ f) = Gov(g) ∘ Gov(f)`
   — so "A produced X, then B consumed X to produce Y" yields a *single* proven
   morphism A→Y, with the intermediate guarantees intact. Proven pipelines are
   first-class.
2. **The KB's laws apply to accumulated proofs.** The olog's commuting diagrams
   become invariants every accumulated fact must satisfy — a re-derivation
   checker can reject a witness whose claimed instance violates the schema
   (catching a malformed or inconsistent proof at internalisation time).
3. **Functorial query / rollup for free.** The olog already supports the data-
   migration adjunction (Δ_F ⊣ Σ_F ⊣ Π_F). Once proofs are olog instances,
   "show me every task of class C proven under spec ≥ H in the last week, rolled
   up by agent" is a *functorial query*, not a bespoke report.

## What it preserves — and what it must NOT manufacture

**The functor preserves whatever the witness already proved — no more.** This is
the load-bearing honesty constraint:

- If a witness reached assurance rung-1 (signed only), the accumulated fact is
  rung-1. `Gov` carries the [assurance rung](./externality-oracle.md) through;
  it never *upgrades* trust by internalising.
- The olog's Lean core currently carries ~1,000 `sorry`s (tracked honestly via a
  sorry-ratchet). The KB *structure* is real and the re-derivation checker is
  real, but many categorical theorems are **obligations, not discharged proofs.**
  Every accumulated fact must therefore be **tiered** in its manifest
  (`PROVEN` / `MODELED` / `ANALOGY`), exactly as `CATEGORICAL-LANDSCAPE.md`
  prescribes — so the KB never *reads* as more-proven than it is.
- `Gov` accumulates proofs **faithfully**; it does not create them. A query
  against the KB returns "proven at rung R, tier T" — never a bare "proven."

## The signed accumulation manifest

Each internalised witness emits a **manifest** that binds the full provenance
chain so any third party can re-derive it:

```text
manifest := {
  agent_id,                 // who did the work
  task_spec_hash,           // which olog spec it claims to satisfy
  witness_digest,           // the content-addressed evidence (ck-types)
  admission_verdict,        // the kernel's decision
  assurance_rung, tier,     // how much to trust it (never upgraded)
  olog_instance_digest,     // the fact Gov produced
  commit_sha, axiom_footprint, ci_run_id,  // reproducibility anchors
}
```

Signed (Ed25519, reusing the `BundleSignature` machinery) and **transparency-
logged** (append-only). This is the concrete step toward the self-proving-system
north star: the system continuously proves its own work and signs the record,
with no human on the verifiable core.

## What's ready vs. net-new

| Piece | Status |
|---|---|
| Admitted witness bundles, content-addressed + lineage-linked | ✅ `ck-types::WitnessBundle`, `ck-kernel` |
| Witness archive (ReDB, content-addressed, indexed by sequence) | ✅ `merge-gate` |
| Olog runtime + categorical KB + re-derivation checker | ✅ `olog/`, `nucleus-olog-build` |
| Settlement spec→witness→kernel (the pattern, proven) | ✅ `SettlementDecision.lean` + parity |
| Assurance rung carried on a claim | ✅ `nucleus-externality` (O1, #1752) |
| **`Gov : 𝓦 → 𝓞` functor** (witness → olog instance) | ⛳ **net-new — the bridge** |
| **Accumulation manifest + transparency log** | ⛳ net-new |
| **Functoriality proof** (`Gov` preserves id + composition) | ⛳ net-new (Lean goal) |
| **`@coproduct/verify` KB query** ("is task X proven, at what rung?") | ⛳ net-new |

## Phasing

- **P2.1 — types + signature.** Define 𝓦 (objects = `WitnessBundle` digests,
  morphisms = lineage edges), the `Gov` functor signature, and the accumulation
  manifest type. No behaviour change; just the contract. (Mirror the discipline
  of the settlement port: types first, parity later.)
- **P2.2 — implement `Gov`.** Fold the existing `merge-gate` witness archive into
  olog instances. Each admitted bundle → a Set-valued functor over its
  task-spec category. Emit + sign the manifest.
- **P2.3 — re-derivation checker.** Validate each internalised instance satisfies
  the task-spec olog's commuting diagrams (reuse `nucleus-olog-build`'s checker).
  Reject inconsistent witnesses at internalisation.
- **P2.4 — surface it.** Extend `@coproduct/verify` with a KB query: "is task X
  proven, by whom, at what rung/tier?" — answerable from the transparency log
  with no server trust, the same way recompute is.

## The theorem to aim for (named, not yet done)

> **`Gov` is a functor:** `Gov(id_W) = id_{Gov W}` and
> `Gov(g ∘ f) = Gov(g) ∘ Gov(f)` for composable admitted lineage edges `f, g`.

Proving this (Lean, sorry-free, axiom-audited) is what turns "proofs compose" from
a slogan into a guarantee. Until it's discharged it ships as a `MODELED` claim,
flagged honestly. It is the categorical heart of Phase 2: with it, the audited
record of everything proven is not just a list — it's a **category of proven
work**, and you can compose within it.

## Honesty boundary

- Phase 2 makes proofs **accumulate and compose**; it does not make anything
  *more* proven than its witness already was. Trust in, trust out.
- The olog's `sorry` budget is real; the KB is structurally sound but
  theorem-incomplete. Tiering is mandatory, not optional.
- "Everything proven" means everything for which a witness was *admitted and
  internalised* — the KB's completeness is bounded by what actually flowed
  through the kernel, and the manifest says so. No silent gaps.
