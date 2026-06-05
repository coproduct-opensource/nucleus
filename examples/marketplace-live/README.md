# marketplace-live — REAL Base Sepolia settlement

The nucleus marketplace dashboard with **real on-chain settlement** on Base
Sepolia (testnet). Each confirmed settlement is a real `transferWithAuthorization`
tx, shown live in the dashboard with its on-chain hash.

> **Testnet only. Real (small) funds move.** Never point this at mainnet — the
> signer holds an extractable in-process key, acceptable for a faucet wallet only.
> Mainnet requires a non-extractable backend (AWS KMS / Ledger) + audit.
>
> Standalone workspace (own `[workspace]`) so the alloy/x402 tree stays out of
> the main nucleus build + CI. Build from this directory.

## How it differs from the simulated dashboard

| | `nucleus-marketplace-dashboard` (main) | `marketplace-live` (here) |
|---|---|---|
| Settlement | `FakeFacilitator` (simulated, `0xsimulated…`) | **`X402Facilitator`** — real x402 → Base Sepolia tx |
| Balances | `Simulated` badge | **`OnChainTestnet`** (real `balanceOf`) |
| Funds | none | small testnet USDC |
| Deploy | safe to host publicly | run locally / behind auth (holds a key) |

Same orchestrator, event model, IFC gate, and dashboard — only the `Facilitator`
trait impl changes. That's the seam.

## Run order

```bash
# 1) Create an encrypted keystore for a TESTNET wallet (never --private-key on argv):
cast wallet import nucleus-x402 --interactive      # prompts for the key + a password

# 2) Store the keystore password in the macOS Keychain (the -w flag prompts; not on argv):
security add-generic-password -s nucleus-x402 -a marketplace-keystore -w

# 3) Fund the wallet: Base Sepolia ETH is NOT needed (x402 is gasless via the
#    facilitator); get bUSDC from https://faucet.circle.com (select Base Sepolia)
#    for the address printed by `cast wallet address --account nucleus-x402`.

# 4) Run (REAL settlement). SELLER_ADDRESS = a receiving address (funds move there):
export SELLER_ADDRESS=0x<your base-sepolia receiving address>
just marketplace-live          # → http://127.0.0.1:4040 (dashboard + seller on one port)
```

Open the dashboard UI against it with `just marketplace-ui` (it proxies `/api` to
`:4040`); settlement rows show real tx hashes (link to
`https://sepolia.basescan.org/tx/<hash>`), and per-agent balances carry the
green **`testnet`** badge.

## ERC-8004 anchoring (optional)

Anchor each verified receipt on-chain so the in-bounds decision is checkable from
chain reads. **Identity** (`0x8004A818…BD9e`) and **Reputation** (`0x8004B663…8713`)
are canonical on Base Sepolia; the **Validation Registry** is not, so we deploy a
minimal selector-compatible one (`contracts/src/ValidationRegistry.sol`).

> These writes are **gasful** — the wallet needs **Base Sepolia ETH** (not just
> bUSDC). x402 settlement is gasless; ERC-8004 writes are not.

```bash
# 1) deploy the ValidationRegistry (one-time; prompts for the keystore password):
just marketplace-live-deploy-validation        # prints: Deployed to: 0x<addr>

# 2) run with anchoring on (registers each agent on Identity, anchors each
#    verified receipt on Validation):
SELLER_ADDRESS=0x<recv> just marketplace-live --validation-registry 0x<addr>
```

Per verified receipt the anchor task: computes `requestHash = keccak256(receipt)`,
calls `validationRequest(validator, agentId, requestURI, requestHash)`, then (as
the validator) `validationResponse(requestHash, 100, …, "clearing/in-bounds")`,
and emits a `ReceiptAnchored` event → the dashboard shows `anchored ⛓` with the
on-chain `agentId` + validation tx. Each real txn is then verifiable four ways:
**dashboard → Basescan settlement → portable receipt → ERC-8004 validation anchor.**

`response = 100` = "the gate allowed this flow and a receipt was issued" — a
model-level, declared-input in-bounds attestation, not an end-to-end proof.

## Credible settlement contract (Bet B / B2)

`contracts/src/CredibleSettlement.sol` is the **optimistic credible-clearing
settlement** contract — it removes the *trusted auctioneer* by letting the
verified settlement self-execute on-chain. Lifecycle: buyer `openRound` (escrows
the cleared price) → an untrusted poster `postClearing` (+bond, after the reveal
deadline) → a challenge window → `settle` (the arbiter supplies `deliveredBps`).

What makes the money path trustworthy: the settlement split (`classify` /
`sellerGross` / `refund`) and the commons routing (`routeToCommons`) are a
**byte-for-byte Solidity mirror** of `nucleus-econ-kernels::settlement` /
`::commons`, which are themselves parity-pinned to `SettlementDecision.lean`. The
load-bearing invariant `sellerGross + refund == price` holds by construction. A
valid `challenge()` slashes the poster's bond **to the commons** (anti-grief,
non-extractive) and safely reverses (buyer refunded) — so cheating is
unprofitable *without* running VCG on-chain.

Honesty boundary: the *cleared price* is posted optimistically (off-chain
recompute is the fraud proof; a challenge reverses, it does not yet adjudicate
poster-vs-challenger — that's B3). `deliveredBps` is an arbiter input — the
unsolved PoTE seam. See `docs/rfcs/credible-clearing-settlement.md`.

```bash
# forge-std is not vendored (/lib is gitignored); fetch it once:
cd contracts && forge install foundry-rs/forge-std --no-git   # or: git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
forge test --match-contract CredibleSettlementTest            # 17 tests: parity + lifecycle + fuzz
```

The `test_parity_*` cases mirror the SAME vectors as the Rust `settlement.rs` /
`commons.rs` tests — they are what bind the on-chain split to the Lean proof. If
the Solidity drifts from the proven function, they fail.

## Secure key handling

The signing key lives in a foundry-format encrypted keystore; the decryption
password is resolved, in order: **macOS Keychain** (`security` CLI) → **no-echo
prompt** (`rpassword`) → **file mount** (`NUCLEUS_X402_KEYSTORE_PASSWORD_FILE`) →
**env** (`NUCLEUS_X402_KEYSTORE_PASSWORD`, last resort). Neither the key nor the
password is ever accepted on the command line (argv leaks via `ps` / shell
history). Mainnet: swap `PrivateKeySigner` for `alloy-signer-aws` (KMS) or
`alloy-signer-ledger` — same x402 path, key never extractable.

## Safety rails

- `--testnet` is a required acknowledgement; the binary refuses to run without it.
- **Pre-flight balance floor**: refuses to start (and prints the faucet link) if
  the wallet is below 0.01 USDC; prints the wallet + real balance first.
- **`--max-settlements N`** (default 20): a hard global cap; the run stops so the
  faucet wallet can't be drained.
- **Single-flight signing** (`Semaphore(1)`) + slow pacing: one key never signs
  two authorizations at once; a settlement timeout is **terminal** (no re-settle).

## Tests (no funds)

```bash
just marketplace-live-check     # cargo build --bins && cargo test
```

Covers: keystore encrypt→decrypt→address round-trip (+ wrong-password rejection),
the password-resolver order, and `X-PAYMENT-RESPONSE` decode (confirmed / alias /
failed / missing). The funded end-to-end run is manual (testnet, real funds).
