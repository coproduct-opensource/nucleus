# RFC: The externality oracle — making `units_micro` trustworthy (Item 3)

**Status:** scoping (the open frontier). **Depends on:** `nucleus-externality`
(`SignedExternalityClaim` / `ExternalityProfile` / `oracle.rs`) +
`nucleus-econ-kernels::vcg_pigou` (the Pigouvian re-weighting that consumes the
claim). **Companion:**
[`initial-pigouvian-structure.md`](./initial-pigouvian-structure.md) (what λ we
charge) and [`social-good-externality-routing.md`](./social-good-externality-routing.md)
(where the pool goes).

## The one question this answers

The Pigouvian charge is `contrib = λ · units_micro / 1e6`. We publish, version,
and unit-test λ — that half is **verifiable**. This RFC is about the *other*
half: **`units_micro`** — the attested consumption (grams CO₂, litres of water,
verifier-millis). The whole social-good claim is exactly as honest as that
number. If an agent can under-report its carbon, the "internalised externality"
is theatre.

> **Plain statement of the problem:** *no cryptography can prove that a physical
> sensor told the truth.* A TEE can prove a measurement was taken inside an
> attested enclave running known code; it cannot prove the wire feeding the
> enclave wasn't lying. This is the **oracle problem**, and it is irreducible at
> the crypto layer. The honest goal is not to "solve" it but to **shrink the
> trusted surface to the smallest, most-accountable residue** and be explicit
> about what remains.

## What we are NOT claiming

- ❌ "Cryptographically proven carbon/water." We never say this.
- ❌ That a TEE quote means the underlying physical reading is true.
- ❌ That on-chain anchoring makes a self-reported number trustworthy.

What we DO claim is graded and bounded — see the trust-residue ladder below.

## The trust-residue ladder (each rung shrinks what you must trust)

Ordered from weakest to strongest. nucleus ships rung 1; rungs 2–4 are the build;
rung 5 is the irreducible residue we name honestly.

### Rung 0 — self-reported (the status quo we reject)
The agent says "I emitted X grams" and signs it. Trusted surface: **the agent
itself**. This is the greenwashing baseline; `SignedExternalityClaim` already does
better by requiring an *independent* oracle key.

### Rung 1 — independent oracle signature *(shipped)*
`SignedExternalityClaim` is signed by an oracle key distinct from the bidder, with
a `subject_identity` binding, an expiry (`not_after`), and a `resource` tag inside
the canonical bytes (so a dimension-swap breaks the signature). Trusted surface:
**the oracle operator**. Already enforced (`claim.rs`, `oracle.rs`); the
re-weighting refuses unsigned/expired/rogue-key claims.

### Rung 2 — TEE-attested telemetry *(feasible now)*
The oracle runs inside a hardware enclave (**Intel TDX**, **AMD SEV-SNP**, **AWS
Nitro Enclaves**, or **Phala**-style off-chain workers) and emits a **remote
attestation quote** binding (a) the enclave measurement (known code), (b) the
input source identifiers, and (c) the output `units_micro`. `oracle.rs` already
has the TEE-attestation seam (`tee_attestation_*` tests). Trusted surface drops
from "the operator" to **"the hardware vendor's attestation + the sensor wire into
the enclave."** The operator can no longer silently alter the number; they can
only feed a bad input — which rungs 3–4 attack.

> ⚠️ **TEE is not a hard floor — weight it accordingly.** Remote attestation is
> physically breakable: *TEE.fail* (Nov 2025) showed a **< $1,000 DDR5 bus
> interposer defeating attestation and extracting keys from Intel SGX/TDX and
> AMD SEV-SNP** (physical access + root). R2 *raises the cost* of silently
> altering a number; it does not make it impossible. Do not treat a TEE quote as
> equivalent to a proof — it is one (breakable) attestation, which is why R3/R4
> exist above it.

### Rung 3 — refereed dispute over corroborated sources *(feasible now)*
The naïve framing of this rung — "take **N independent sources** and trust the
majority" — is **provably weak**, and the 2024–2026 literature is blunt about why:
genuine verifier independence is hard to *guarantee* and easy to *fake* (the
Sybil≡collusion "mirror"; proof-of-personhood systems still drift to oligopoly;
the **Verifier's Dilemma** shows no pure-strategy equilibrium where a costly
verifier and a prover are *both* honest). **Counting "independent" feeds is not a
security argument.**

The sound primitive is a **refereed dispute** whose correctness rests on *a single
honest challenger*, not on the independence of a quorum:

- Corroborate the measurement from multiple feeds where available (carbon:
  GPU-seconds × grid-intensity from WattTime / ElectricityMaps-class providers,
  region- and time-matched; water: GPU/energy × a regional WUE factor) — but treat
  agreement as a *cheap-path heuristic*, not the guarantee.
- The guarantee comes from an **optimistic post + permissionless challenge**: a
  reporter posts the value with a **bond**; **anyone** may dispute within a window;
  a dispute is settled by a **refereed-delegation tournament** (the **PRT / Dave**
  family — Cartesi, peer-reviewed ACM DLT 2025) in which **one honest challenger
  prevails against an unbounded Sybil adversary**, with honest cost only
  *logarithmic* in adversary loss and correctness *independent* of bond
  calibration. This is the *same machinery* as Bet B's settlement challenge
  (`CredibleSettlement.sol`) — **reuse it**, and inherit the single-honest-party
  security model rather than a fragile "majority of independent feeds."

Trusted surface: **"≥1 honest party is watching, and the censorship window
holds"** — economic + structural, not an unverifiable independence assumption.

### Rung 4 — zk upper-envelope proof *(feasible, partial)*
For dimensions where we only need a *bound* (the Pigouvian charge is conservative
if we over-estimate the externality, so a **provable upper bound** is sound), emit
a **zk-SNARK** proving `units_micro ≤ f(public_inputs)` for a public model `f`
(per "Verifiable Carbon Accounting"-style constructions). `oracle.rs` already has
the **envelope-proof seam** (`envelope_proof_*` tests:
accepts-in-bound / rejects-overclaim / rejects-missing-public-inputs). This makes
*over*-claiming impossible to do undetectably; combined with rung 3 it brackets
the true value from both sides. Trusted surface: **the public model `f` + its
public inputs** — both auditable.

### Rung 5 — the irreducible residue *(named, not solved)*
After rungs 1–4, what remains trusted is the **physical-to-digital boundary**: the
power meter, the flow meter, the grid-intensity provider's own metering. **No
cryptography removes this.** The honest move is to (a) make it *small* (one
attested, bonded, multiply-sourced boundary instead of "trust the agent"), (b)
make it *accountable* (slashable bonds, public dispute history, named providers),
and (c) **disclose it on the receipt** — every externality claim carries which
rung it reached, so a consumer of the receipt knows exactly how much trust they
are extending.

## Design: the claim carries its own assurance level

Extend the receipt (not necessarily this RFC's first cut) so each
`SignedExternalityClaim` is accompanied by an **assurance descriptor**:

```text
assurance := { rung: 1..5,
               attestation: Option<TeeQuote>,
               sources: [SourceId],          // for rung-3 aggregation
               envelope: Option<ZkProof>,    // for rung-4 bound
               dispute: Option<OptimisticRef> } // bond/window/resolver
```

The verifier (`@coproduct/verify`) can then report not just "signed" but **"rung-4,
2 grid feeds agreed, upper-envelope proof checks"** — turning the honesty boundary
into a *machine-readable* field instead of a footnote. This is the
anti-greenwashing primitive: the receipt states its own trust level, and lying
about the rung is itself a signed, disputable claim.

## Why this is a wedge, not just diligence

Carbon/ESG accounting today is overwhelmingly **rung 0–1** (self-reported,
maybe third-party "verified" by an unaccountable auditor). A marketplace whose
receipts are **rung 2–4 and self-describing** is structurally more trustworthy
than the incumbent ESG-reporting stack — and the trust level is *checkable by
anyone*, not asserted. That is the compliance/ESG control-plane product
(`social-good-externality-routing.md`): enterprises pay to *prove* their agent
commerce is clean, at a stated, auditable assurance rung.

## Phasing

- **O1:** define the `assurance` descriptor + the rung enum; have
  `@coproduct/verify` surface the rung in `RecomputeReport`. (Schema + verifier;
  no new trust.)
- **O2:** wire the **TEE attestation** (rung 2) into `oracle.rs`'s existing seam
  for the compute oracle (GPU-seconds → the carbon/water inputs).
- **O3:** **multi-source carbon/water aggregation** (rung 3) + the
  **optimistic-oracle dispute** layer — reuse `CredibleSettlement`'s bond/challenge
  machinery rather than building a second one.
- **O4:** **zk upper-envelope** (rung 4) for carbon, building on the
  `envelope_proof_*` seam already in `oracle.rs`.
- **O5 (forever-open):** publish the rung-5 residue per provider; track and
  display dispute history. Never closes — it is *managed*, not solved.

## Honesty boundary (the whole point)

This RFC does not claim to make externality measurement trustless. It claims to
**shrink the trusted surface from "the agent" to "an attested, bonded,
multiply-sourced, upper-bounded measurement boundary," and to make the remaining
trust an explicit, machine-readable, disputable field on every receipt.** That is
a real, defensible improvement over self-reported ESG — and stated without
overclaim, which is the only kind of trust claim worth making.
