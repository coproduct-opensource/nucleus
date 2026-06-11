# A2A v1.0 server, nucleus-guarded (example)

An [A2A v1.0](https://a2a-protocol.org) agent server built on the
**official Rust SDK** (`a2a-lf`), demonstrating what nucleus adds to the
protocol's Signed Agent Cards:

1. **Discovery** — `/.well-known/agent-card.json` serves a *signed* v1.0
   card (detached JWS per §8.4) carrying nucleus claims in the registered
   extension `https://coproduct.one/a2a/ext/runtime-guarantees/v1`
   (see `docs/a2a-runtime-guarantees-extension.md`).
2. **Verify-before-you-act** — every task request must present the
   caller's signed card (`X-Agent-Card` header); it is verified against a
   key the operator resolved **out-of-band** before the SDK ever sees the
   request. No card, bad signature, or tampered field → 401.
3. **Receipts** — every non-streaming response carries
   `X-Nucleus-Receipt`: a base64url `nucleus-envelope` bundle whose signed
   content hash binds *caller × resource × sha256(response bytes)*. It
   verifies **offline** against the server's published JWKS
   (`verify_receipt_bundle` in Rust, `verify_receipt_js` in a browser).
   SSE streams are verified but not receipted (`skipped-streaming`) — a
   live stream has no final byte string to bind.

```bash
cd examples/a2a-server
cargo test          # e2e: discover → gate (401s) → serve → verify receipt
cargo run           # interactive server on :3000 with a demo caller card
```

The e2e suite also pins **shape interop**: a nucleus-signed card
round-trips through the official SDK's own `AgentCard` type and the
signature still verifies on the other side.

Demo-grade on purpose: keys are generated per run and the receipt signer
is the TEST-ONLY `insecure-local-issuer`. A production deployment injects
a real `EdgeSigner` (e.g. SPIFFE-Workload-API-backed), publishes its JWKS
out-of-band, and decides which caller keys to trust the same way. For the
IFC-gated variant (model-level flow decision folded into the receipt),
see `nucleus_verify_commerce::serve_verified_ifc`.

Standalone workspace — excluded from the root workspace so the SDK and
axum stay out of the main dependency graph.
