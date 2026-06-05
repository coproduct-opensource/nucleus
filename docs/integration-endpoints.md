# Integration Endpoints

The surfaces nucleus exposes for integration — agent discovery (A2A), verification,
keyless identity, transparency log, and MCP. **Status is honest**: some are live
today, some are offline/in-browser (no server needed), and some are deploy-ready
services you self-host.

| status | meaning |
|---|---|
| 🟢 **LIVE** | hosted and reachable right now |
| 🔵 **OFFLINE** | runs client-side / in CI — no endpoint to call |
| 🟡 **SELF-HOST** | the service is built + deploy-ready (`fly.toml`), but not currently on a public URL — `fly deploy` to expose it |

---

## Agent discovery (A2A)

A JWS-signed **Agent Card** describing the agent's identity, capabilities, and
verification keys (`nucleus-agent-card`).

- `GET /.well-known/agent-card.json` — 🟡 SELF-HOST (published by `nucleus-verifier-service`)

The card is signed; verify it against the issuer's `jwks.json` before trusting it.

## Verification

Re-check a signed provenance bundle / receipt (`nucleus-verifier-service`).

- `POST /v1/verify` — verify a bundle inline — 🟡 SELF-HOST
- `POST /v1/bundles/{hash}/verify` — verify by content hash — 🟡 SELF-HOST
- `GET /.well-known/jwks.json` — issuer verify key — 🟡 SELF-HOST

You usually don't need the server: the **offline verifier is live** and needs no endpoint.
- `npm i @coproduct_inc/verify` → `verifyReceipt(...)` — 🔵 OFFLINE (zero-trust, recomputes the verdict)
- In-browser WASM demo: `https://coproduct-opensource.github.io/nucleus/verify/` — 🟢 LIVE

## Transparency log & witness federation

Tamper-evident inclusion + a cosigning witness ring (`nucleus-verifier-service`).

- `GET /v1/log/size` · `GET /v1/log/sth` — 🟡 SELF-HOST
- `GET /v1/log/inclusion-proof` · `GET /v1/log/consistency-proof` — 🟡 SELF-HOST
- `GET /v1/witness/peers` · `POST /v1/witness/peer-sth` — 🟡 SELF-HOST

## Keyless identity (OIDC → SPIFFE)

Federated, keyless identity — exchange a workload OIDC token, publish a verify set
(`nucleus-oidc-provider`).

- `GET /.well-known/openid-configuration` — RFC 8414 discovery — 🟡 SELF-HOST
- `GET /jwks.json` — RFC 7517 verify set — 🟡 SELF-HOST
- `POST /oauth/token` — RFC 8693 token exchange — 🟡 SELF-HOST

## DID / WebFinger

Resolve a SPIFFE identity to a DID document + permission-fingerprint binding
(`nucleus-identity`).

- `GET /.well-known/webfinger?resource=spiffe://<trust-domain>/...` → links to
  `/.well-known/did.json` + `/.well-known/spiffe-did-binding.json` — 🟡 SELF-HOST

## MCP (agent-native)

Model Context Protocol endpoints so an LLM/agent can call nucleus directly.

- The Vault CTF MCP: `https://nucleus-ctf.fly.dev/mcp` — 🟢 LIVE
- Verifier MCP: `/mcp` on `nucleus-verifier-service` — 🟡 SELF-HOST
- `nucleus-mcp-server` (stdio MCP tool) — 🔵 OFFLINE

## The Vault (try it / point an agent at it) — 🟢 LIVE

A formally-verified permission lattice you (or an LLM) try to exfiltrate past.

- Play: `https://nucleus-ctf.fly.dev/` (also published at `/nucleus/vault/` on these docs)
- `GET /api/v1/levels` · `GET /api/v1/levels/{level}`
- `POST /api/v1/attack` · `POST /api/v1/challenge`
- `GET /openapi.json` · `GET /api` (docs)

---

## Honest deployment status (2026-06)

Live today: **The Vault** (`nucleus-ctf.fly.dev`), the **offline npm verifier**
(`@coproduct_inc/verify`), and the **in-browser `/verify` WASM demo**. The
`nucleus-verifier-service` and `nucleus-oidc-provider` are **built and
deploy-ready** (`fly.toml` in each crate) but are **not currently on a public
URL** — `fly deploy` to expose them, or wire your own host. The **agent card** is
served by the verifier-service, so it goes live when that service is deployed.

For self-hosting recipes see the existing guides in `docs/` (verifier integration,
external-RP integration, OpenClaw users).
