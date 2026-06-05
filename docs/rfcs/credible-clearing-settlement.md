# RFC: Credible clearing & settlement — the auction with no trusted auctioneer (Bet B)

**Status:** scoping. **Depends on:** `nucleus-econ-kernels` (VCG/Pigou/sealed-bid,
now in OSS) + `@coproduct/verify` recompute.

## The question this answers

*Can we run a peer-to-peer auction with no intermediary?* Today nucleus makes the
auctioneer **untrusted-but-verifiable** (anyone recomputes the clearing). Bet B
removes the auctioneer's **role**: the verified outcome **self-executes** on-chain,
so no one has to be trusted to *act* on it.

## The key insight (already proven)

`CredibleClearing.lean::credible_reduces_to_set_and_recompute` (now published in
`crates/nucleus-econ-kernels/lean/Nucleus/Auctions/`) proves:

> **IF** the bid commitment set is complete **AND** the published clearing
> recomputes to the claimed result, **THEN** the outcome is honest.

This is what makes Bet B tractable: the settlement contract does **not** need to
run VCG on-chain. It needs to enforce two cheap things — *commitment-set
completeness* and *recompute-matches* — both of which nucleus already ships:
sealed-bid commitment-set roots (`sealed.rs`) and the public recompute
(`@coproduct/verify`).

## Architecture: optimistic credible clearing

A rollup-style mechanism where **the OSS recompute is the fraud proof**:

1. **Commit** — bidders post sealed commitments; the `CommitmentSetRoot` is
   anchored on-chain (open submission window → no coordinator can censor).
2. **Reveal** — bids open via timelock (`tlock.rs` / drand) — no coordinator
   needed to force or order reveals.
3. **Post** — anyone (a "sequencer", untrusted) posts the revealed bids + the
   claimed clearing result + a bond.
4. **Challenge window** — anyone runs `@coproduct/verify`'s recompute on the
   revealed bids; if `claimed ≠ recompute`, they submit a fraud proof → the
   poster is slashed and the correct (recomputed) result stands.
5. **Settle** — unchallenged ⇒ the contract executes `SettlementDecision`
   (`release | partial | reverse`, Lean-proven) and moves funds via x402 / the
   chain. No human, no company in the middle.

Because the clearing math is public + recomputable and the commitment set is
on-chain, **the poster cannot cheat and cannot censor** — the trusted auctioneer
is gone.

## What's ready vs. net-new

| Piece | Status |
|---|---|
| Truthful VCG + Pigou clearing | ✅ OSS (`econ-kernels`, parity-pinned) |
| Public recompute (the fraud-proof verifier) | ✅ `@coproduct/verify` (extend to clearing) |
| Credibility reduction theorem | ✅ `CredibleClearing.lean` |
| Settlement decision (release/partial/reverse) | ✅ Lean (`SettlementDecision.lean`); ⛳ port to OSS Rust + parity test |
| Sealed-bid commitment-set root | ✅ `sealed.rs` |
| Timelock reveal | ✅ `tlock.rs` (drand) |
| On-chain payment | ✅ x402 (EVM) / Aiken `settlement.ak` seam (Cardano) |
| **Optimistic settlement contract** (commit-root → reveal → post+bond → challenge → settle) | ✅ **shipped (B2)** — `examples/marketplace-live/contracts/src/CredibleSettlement.sol` |
| **Bond / challenge / slash** mechanism | ✅ shipped (B2) — slashed bond routed to commons (anti-grief) |
| On-chain settlement split runs the **exact proven function** | ✅ shipped — Solidity mirror of `settlement.rs`/`commons.rs`, parity-tested (`test/CredibleSettlement.t.sol`) |
| **On-chain bid commitment** (anti-censorship commit phase) | ⛳ net-new (B3) |
| **Clearing-price adjudication** (decide poster-vs-challenger, not just reverse) | ⛳ net-new (B3) — needs interactive proofs / on-chain commit |
| **Proof-of-Task-Execution** (did the seller *deliver*?) | ❌ unsolved — `deliveredBps` is an arbiter input |

## Phasing

- **B1 (ready):** port `SettlementDecision` to OSS Rust + a parity test (mirror the
  VCG parity pattern); extend `@coproduct/verify` recompute to the clearing price
  (now possible — the proven kernel is in OSS).
- **B2 (shipped):** an EVM **settlement contract**
  (`CredibleSettlement.sol`): commit root → timelock reveal → optimistic
  post+bond → challenge window → settle (release/partial/reverse). The
  settlement split + commons routing run the **exact** proven functions on-chain
  (a byte-for-byte Solidity mirror of `settlement.rs`/`commons.rs`, bound by a
  Foundry parity test against the same vectors as the Rust/Lean tests). A valid
  `challenge()` slashes the poster's bond **to the commons** and safely reverses
  (buyer refunded) — cheating is unprofitable without any on-chain VCG. Base
  Sepolia testnet; native-value escrow for v1. *Not yet:* deciding poster-vs-
  challenger correctness (always reverses on challenge) — that's B3.
- **B3:** on-chain bid commitment (open submission) + clearing-price
  adjudication (interactive fraud proof or on-chain commit so a challenge
  resolves to the *correct* result, not just a reversal) — this is what removes
  the *coordinator*, not just the *trust*.
- **B4 (research):** PoTE — proving the seller actually delivered. Until then, v1
  settles on **clearing-correct + payment**, not on delivery; disputes about
  delivery remain out of scope (pitch to compliance, not as full escrow).

## Honesty boundary

- **v1 removes the *trusted* auctioneer** (optimistic + public recompute fraud
  proof). A *coordinator* still posts results — but it can't cheat (recompute) and,
  once B3 lands, can't censor (on-chain commit). Fully coordinator-free is B3.
- **PoTE is unsolved.** "Did the work happen?" is not provable on-chain today; v1
  is honest that it settles payment/clearing, not delivery.
- **Real funds at scale** ⇒ testnet first; mainnet needs the custody posture
  (KMS / Safe) + external audit. The settlement signer is where custody (and
  licensing) is decided.
- A price/outcome is "verified" only insofar as the on-chain settlement runs the
  **exact** proven function — bind the contract logic to `SettlementDecision` via a
  parity/extraction test, or it's a claim, not a proof.
