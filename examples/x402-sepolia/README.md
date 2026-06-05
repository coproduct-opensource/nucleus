# x402 on Base Sepolia — 30-second bootstrap (testnet)

A minimal x402 **seller** and **buyer** on Base Sepolia (testnet), where the
paid route is also **IFC-gated + receipted** by
[`nucleus-verify-commerce`](../../crates/nucleus-verify-commerce) — so a *paid*
call is also contingent on an information-flow decision.

> **Testnet only.** Everything here targets Base Sepolia (`eip155:84532`) with
> faucet USDC. Never point it at mainnet or use a real-funds key. No keys are
> stored in this repo — they're read from env.
>
> Standalone crate (own `[workspace]`) so its `alloy` / x402-rs dependency tree
> stays out of the main nucleus workspace and CI. Build it from this directory.

## 30 seconds

```bash
just x402-info        # config + faucet links

# 1) get test funds (Base Sepolia ETH + USDC) from the faucets x402-info prints
# 2) run the seller (receives USDC; paid route is IFC-gated)
export SELLER_ADDRESS=0x<your base-sepolia address>
just x402-seller

# 3) in another shell, pay it (TESTNET key holding bUSDC)
export X402_PRIVATE_KEY=0x<testnet private key>
just x402-pay
```

`GET /paid` returns `402 Payment Required` until the buyer pays; the
`x402-reqwest` client auto-pays and retries. On success the handler runs the
nucleus model-level IFC decision over the call's declared data-flow and returns
the result with the (allow) verdict.

## Config (env)

**Seller** (`just x402-seller`): `SELLER_ADDRESS` (required), `FACILITATOR_URL`
(default `https://facilitator.x402.rs`), `PRICE_USDC` (default `0.01`), `BIND`
(default `0.0.0.0:4021`).

**Buyer** (`just x402-pay [url]`): `X402_PRIVATE_KEY` (required, **testnet**),
`TARGET_URL` (default `http://127.0.0.1:4021/paid`).

## What's nucleus vs. what's x402

- **x402-rs** (`x402-axum`, `x402-reqwest`) does the payment: 402 → sign → settle
  via the facilitator. Not ours; we just use it.
- **nucleus** adds the trust the rail omits: the paid route runs the lethal-
  trifecta IFC gate and can emit a signed in-bounds receipt. That's the part no
  payment stack provides.

The gate here enforces a **model-level** decision over **declared** inputs
(coverage-limited, per-call) — see the crate docs for the honesty boundary.
