# RFC: Receipt provenance + authenticated defection — the real money-safe-standing gate

**Status:** design / scoping. **Depends on:** `nucleus-recompute`, `nucleus-eval`,
`nucleus-oracle` (recompute-verified receipts), `nucleus-creditworthiness` (the
ledger), the Ed25519 detached-signature identity (`canonical_id = hex(vk)`).
This is the gate that must hold **before standing is allowed to touch real funds**.

## The question this answers

Standing only deserves to gate money if two things are true:

1. **Provenance** — a credit (or debit) is bound to a *real, recomputable
   outcome*, not to a self-report. "I delivered" must be re-derivable by anyone.
2. **Attribution** — a *defection* (non-delivery, or a caught lie) is
   cryptographically pinned to a real identity that cannot repudiate it or cheaply
   shed it via a fresh Sybil.

Without (1), standing is just an unverifiable scoreboard. Without (2), the
slashing/bond that makes standing *cost* anything has nothing to bite. Money
behind a standing that lacks either is unsafe. Today the system is deliberately
reputation-only / testnet precisely because this gate is not fully closed.

## Part 1 — Receipt provenance (bind credit to recompute)

A `CreditEvent` must reference a **receipt** whose provenance tier is known, and
only `RecomputeVerified` receipts may move money-gating standing:

| Receipt source | Provenance | May gate money? |
|---|---|---|
| `nucleus-recompute` clearing receipt (settlement/VCG/commons) | RecomputeVerified | yes |
| `nucleus-eval` deterministic check / `nucleus-oracle` exact held-out pass | RecomputeVerified | yes |
| `nucleus-oracle` MR-coverage, mutation-kill | Attested (statistical) | no — carried only |
| LLM-judge / self-reported | AttestationOnly | no — carried only |

This is the existing three-tier discipline (`nucleus-rubric` / `nucleus-oracle`)
applied to the **money** boundary: the load-bearing credit is exactly the part a
third party can re-derive byte-for-byte from declared inputs. The adversarial
pressure-test (`nucleus-oracle/docs/oracle-adversarial-pressure-test.md`) is the
empirical evidence this holds against real agents: a claim ("I solved it") that
doesn't recompute earns credit only for what it actually achieved.

**Concrete requirement:** a money-gating `CreditEvent` carries the
domain-separated receipt hash and the provenance tag; an accrual path that would
mint load-bearing credit from a non-RV receipt must refuse (mirrors
`grade_rubric_inputs` omitting the RV criterion on quarantine).

## Part 2 — Authenticated defection (make the consequence land)

A defection must be **detected** and **attributed**:

- **Detected by recompute, not by trust.** Non-delivery against a settled
  obligation, or a caught lie, surfaces as a recompute mismatch
  (`RecomputeOutcome::Mismatch`) or an oracle quarantine — a *deductive* signal,
  not a complaint.
- **Attributed to an authenticated identity.** The bid/obligation is signed
  (Ed25519 detached signature; `canonical_id = hex(vk)`), so the resulting debit
  lands on the exact key that committed. The confused-deputy guard (identity comes
  from the verified signature, never from request-body fields) is the load-bearing
  property here: no wire-level identity binding means no real authentication, no
  matter how strong the signature scheme looks on paper.
- **Sybil-resistant by construction, not by detection.** We do *not* try to detect
  Sybils. A fresh identity simply has zero standing, hence the maximum anti-grief
  bond (`reputation-weighted-clearing.md`). Shedding a bad identity means forfeiting
  accrued standing and re-collateralizing from scratch — the cost *is* the defense.

## The gate (when standing may touch real money)

Standing may gate real funds **only** when, for the accrual path in question, ALL
hold:

1. every money-gating `CreditEvent` derives from a `RecomputeVerified` receipt
   (Part 1), enforced in code (not by review);
2. obligations are signed and debits are attributed to the signing key (Part 2);
3. the anti-grief bond is posted/substituted and **slashable** on an authenticated
   defection;
4. the ledger is durable + transparency-logged (so neither credits nor debits can
   be quietly rewritten) — `nucleus-creditworthiness` hash-chained store.

Until all four hold for a given path, that path stays **reputation-only**.

## Honesty boundary / hard stop

This RFC describes the *gate*, not a green light. Real funds / signing keys /
mainnet remain a **hard stop** regardless of this gate being closed in code:
crossing it additionally requires external security audit and legal/regulatory
counsel (the custody posture — non-custodial vs. custodial — decides licensing).
Closing the gate
is **necessary, not sufficient**. Nothing here authorizes moving real money; it
specifies what would have to be true, and verifiable, first.
