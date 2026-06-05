# nucleus-marketplace-dashboard

A real-time **verified-agent-marketplace** dashboard: an axum SSE orchestrator
that runs N agent loops making paid calls through the nucleus IFC gate
([`nucleus-verify-commerce`](../nucleus-verify-commerce)), emitting
allow / deny / settlement / receipt events to a broadcast hub. A frontend
renders the live feed and verifies receipts in the browser.

The point it makes concrete: **a plain x402 paywall charges first and asks
questions never; nucleus refuses dangerous calls before money moves** — and you
can watch it happen, live, across a marketplace of agents.

## Architecture: a network-free, deterministic core + a thin SSE edge

```
 AgentLoop × N ─▶ Orchestrator.step_once ─▶ Hub.emit ─▶ broadcast ─▶ /api/events (SSE)
   │  flow.decide() (IFC gate)              │  seq + ts (Clock)        snapshot ─▶ /api/snapshot
   │  Facilitator.settle() (abstracted)     │  replay ring             receipt  ─▶ /api/receipt/{id}
   └─ deny ⇒ STOP (settle never called)     └─ MarketState.apply (pure reducer)
```

- **`event.rs`** — the `MarketEvent` wire contract (serde-tagged); shared verbatim
  with the wasm frontend (serde-only deps → compiles to wasm unchanged).
- **`reducer.rs`** — pure `MarketState::apply`; state is `fold(apply, default,
  events)`, so `/api/snapshot` and the live feed can never diverge.
- **`clock.rs` / `facilitator.rs`** — `Clock` + `Facilitator` traits, with
  `FixedClock` + `FakeFacilitator` so the **whole core tests with no network, no
  real clock, no alloy**.
- **`orchestrator.rs`** — runs the agent loops; mirrors
  `serve_verified_ifc`'s ordering (deny ⇒ settlement never attempted).
- **`hub.rs`** — tokio broadcast + monotonic seq + bounded replay ring
  (`Last-Event-ID` resume) + receipt store.
- **`http.rs`** (feature `server`) — the thin SSE edge; no business logic.

## Run the live (SIMULATED) demo

```bash
BIND=127.0.0.1:4040 cargo run -p nucleus-marketplace-dashboard --bin marketplace-orchestrator
# then:
curl -s http://127.0.0.1:4040/api/snapshot | jq
curl -N  http://127.0.0.1:4040/api/events
```

## Honesty

- **Testnet only.** The real settlement path targets Base Sepolia
  (`eip155:84532`) — never mainnet, never real funds.
- **Simulated money is labelled.** The default binary uses `FakeFacilitator`:
  every settlement is tagged `BalanceSource::Simulated` with a `0xsimulated…`
  reference. There is **no code path** that produces an `OnChainTestnet` number
  without a real confirmed tx — a reducer invariant test asserts this. The UI
  must surface the source as a visible badge.
- **The IFC verdict is model-level over _declared_ inputs** (coverage-limited,
  per-call; no cross-session taint ratchet) — see `nucleus-verify-commerce`'s
  `ifc` module. An `IfcAllow` is **not** an end-to-end exfiltration proof; the
  event carries `declared_inputs` so a viewer can judge coverage.
- **Real settlement lives elsewhere.** The `X402Facilitator` (driving
  `x402-reqwest` against Base Sepolia with a keystore-backed signer) lives in a
  **separate workspace** under `examples/`, exactly like `examples/x402-sepolia`,
  so the heavy alloy/x402 dependency tree never enters this crate or the main CI.

## Tests

```bash
cargo test -p nucleus-marketplace-dashboard            # core + SSE edge, no network
```

The load-bearing isolation tests (`tests/orchestrator_isolation.rs`) assert the
exact event sequence per iteration, that **a denied flow never reaches
settlement** (`settle_calls() == 0`), that a timeout yields no receipt and no
re-settle, and that the whole core is byte-for-byte reproducible.
