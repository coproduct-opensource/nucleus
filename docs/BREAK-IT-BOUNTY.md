# nucleus break-it bounty

> **STATUS: DRAFT — not live.** No funds are escrowed and no payout obligation
> exists until (a) the operator funds the escrow, (b) the operator signs off on
> these terms, and (c) legal review completes. Dollar amounts, escrow mechanism,
> judge, and disclosure process are marked **TBD** below and are the operator's
> to set. This document only *scopes* the bet.

## The bet

We machine-check a small number of **specific** security properties of nucleus
and we are willing to lose money if they don't hold over the **shipped** code.
Break a scoped challenge below and you are paid. We are deliberately betting only
on what we actually proved — **no more.** "Verified, not hoped" should cost us
money when we're wrong; we don't think we are, on exactly this scope.

## Read this first: scope is exact

In scope = the specific properties in the three challenges, **over the pinned
commits**, **within the stated boundaries**. Out of scope is enumerated at the
bottom and is not a loophole — it's the honest edge of what we claim. Do **not**
infer a broader claim than a challenge states. If a "break" relies on a
capability we explicitly say we do **not** provide, it is not a break.

Pinned commits (pin to the release tag `TBD` at funding time):

| Component | PR | Merge commit |
|---|---|---|
| Integrity noninterference (Lean, over extracted Rust) | #1660 | `97d58f09b431` |
| In-browser verifier + fixtures | #1661 | `654ee248fb21` |
| Agent-card (verify-before-act) | #1662 | `066e7ee4affa` |
| Witness mesh (C2SP tlog-witness) | #1664 | `4c936dd3afd6` |
| SPIFFE federation (JWT-SVID validation) | #1666 | `f722e690433d` |
| Trust registry (PR-rooted enrollment) | #1667 | `TBD (merge commit)` |

---

## Challenge 1 — Forge a federated identity

**Target:** `nucleus-trust-registry` (#1667) + `nucleus-oidc-core::spiffe_federation` (#1666).

**A break is any one of:**
1. Get a `trust-domain → JWK Set` binding **into the federation set without controlling the claimed GitHub org** — i.e. defeat the GitHub-Actions-OIDC proof-of-control: forge or replay an OIDC token that passes `verify_proof_of_control`, or bypass the numeric `repository_owner_id` pin.
2. Get the verifier to treat a binding as trusted whose leaf is **not present in a witness-cosigned STH** — i.e. defeat the transparency-log inclusion check (`verify_binding_in_log`) or fabricate a witness cosignature without the witness key.
3. Get `validate_jwt_svid` to **accept a JWT-SVID verified by a key that is not in the operator-pinned bundle** for that SVID's trust domain (i.e. make the validator select a key from the token, not the pinned bundle).

**Payout: TBD.**

**Honest caveats (not breaks):**
- OIDC proves **GitHub-org control, not trust-domain ownership.** Enrolling a trust domain whose GitHub org you legitimately control is the v1 design, not a break. (DNS-level trust-domain proof is a planned v2.)
- **Single-witness / single-maintainer MVP.** Compromising the one configured witness *private key* or the registry maintainer's credentials is a key-management assumption, not a protocol break — out of scope. Forging a valid cosignature or a merged binding **without** those secrets is in scope.

---

## Challenge 2 — Forge a verifiable bundle

**Target:** `nucleus-envelope::verify_bundle` + the witness cosignature path + `nucleus-verifier-wasm` (#1661), and the agent-card → TrustAnchor path (#1662).

**A break is:** produce a bundle that `verify_bundle` **accepts** against a pinned trust anchor, but whose lineage you **fabricated** — i.e. bytes that pass the hash-chain + Merkle-inclusion + witness-cosignature + trust-anchor checks **without** possession of the signing/cosigning private keys.

**Payout: TBD.**

**Honest caveats (not breaks):**
- You do not get the private keys; a break means forging **acceptance without them**.
- **Tamper-evidence ≠ good behavior.** We claim the *record* is authentic and tamper-evident — not that the agent behaved correctly. "The agent did something bad but the lineage faithfully records it" is the system working, not a break.

---

## Challenge 3 — Violate the integrity-noninterference theorem

**Target:** `crates/portcullis-core/lean/IntegrityNoninterferenceExtracted.lean` and the Charon+Aeneas-extracted defs `portcullis_core.extracted.ifc_integrity.*` (#1660).

**A break is any one of:**
1. A Lean term that closes a **false** instance of `integrity_sink_never_admitted` or `web_tainted_never_git_pushes` against the as-published defs (show the theorem is unsound/vacuous as stated), **or** introduce a `sorryAx` / opaque `*External` axiom into the proof's axiom set that the CI `#print axioms` gate would not catch.
2. Exhibit a **divergence between the extracted `ifc_integrity` functions and the production `IFCLabel` integrity axis** that the exhaustive parity tests miss — i.e. show the parity bridge is incomplete *on the integrity axis*.

**Payout: TBD (suggest the largest tier — this is the core claim).**

**Honest caveats (explicitly NOT in scope — these are the boundaries we publish, not weaknesses to exploit for a payout):**
- **Integrity axis only** — one of six `flows_to` conjuncts. Confidentiality, authority, provenance, freshness, derivation are **not** covered by this theorem.
- **Model / extracted-slice, not the running multi-axis gateway.** The bridge to production is a **finite-exhaustive parity** on the integrity axis, not a full-runtime refinement. We do not claim the *running* multi-axis runtime is verified.
- **Trusted base = Charon + Aeneas + the Lean kernel.** A soundness bug in Charon/Aeneas/Lean is a real and valuable finding — but it's *their* bug, not nucleus's, and pays out on a **separate track** (we'll still want to talk to you), not as a nucleus break.
- We do **not** claim: "verified runtime", "prompt injection impossible", full multi-axis noninterference, the lethal trifecta is impossible, or end-to-end verification. Demonstrating one of these "fails" is not a break because we never claimed it.

---

## What is NOT in scope (so the bet stays honest)

- Denial of service, resource exhaustion, infra/cloud misconfiguration, supply-chain or social-engineering attacks.
- Compromise of operator-held secrets (witness keys, maintainer credentials, signer keys) — those are stated assumptions, not protocol claims.
- Timing / microarchitectural / covert-channel / side-channel attacks (excluded by every credible verified system; the IFC model governs explicit flows only).
- Concurrency / interleaving attacks on the runtime (the proofs are sequential; whole-runtime concurrent noninterference is not claimed).
- Anything not machine-checked, or not reproducible against a **pinned** commit.
- The aspirational claims we explicitly do **not** make (listed per challenge above).

## Rules & non-custodial posture

- The escrow is **the operator's own funds** — a self-funded challenge, **not** a custody service. nucleus does not hold third-party funds.
- One payout per **distinct** break; the first reproducible submission wins a given clause.
- Submissions: **TBD process** (private disclosure channel + reproduction repo against the pinned commit).
- Judging: **TBD judge** publishes a written rationale for every accept/reject; disputes → **TBD process**.
- Amounts, escrow mechanism (suggest on-chain escrow in USDC for public verifiability, consistent with the project's settlement posture), and the disclosure/embargo window are **TBD**, set by the operator at funding.

## Why we're doing this

The whole thesis is *verifiable* trust. A bounty is the most honest possible
form of skin-in-the-game for that thesis: we publish exactly what we proved,
pin it to a commit, and put money on it — scoped to the claim, not the hype. If
we're wrong inside that scope, you should be paid; that's the point.
