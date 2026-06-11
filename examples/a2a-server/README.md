# A2A v1.0 server, nucleus-guarded (example)

An [A2A v1.0](https://a2a-protocol.org) agent server built on the
**official Rust SDK** (`a2a-lf`), demonstrating what nucleus adds to the
protocol's Signed Agent Cards:

1. **Discovery** — `/.well-known/agent-card.json` serves a *signed* v1.0
   card (detached JWS per §8.4) carrying nucleus claims in the registered
   extension `https://coproduct.one/a2a/ext/runtime-guarantees/v1`
   (see `docs/a2a-runtime-guarantees-extension.md`).
2. **Declared auth (§7.3)** — the card's `securitySchemes` declares the
   gate's credential as an API-key-style scheme (`signedAgentCard`):
   header `X-Agent-Card`, value = the caller's *signed* A2A v1.0
   AgentCard JSON. A client needs nothing out-of-band beyond the trust
   key — the card itself says where the credential goes.
   `securityRequirements` requires the scheme on every request, and 401s
   carry a `WWW-Authenticate` hint pointing back at it (§7.4).
3. **Verify-before-you-act** — every task request's card is verified
   against a key the operator resolved **out-of-band** before the SDK
   ever sees the request. No card, bad signature, or tampered field → 401.
4. **Version negotiation (§3.6)** — requests must speak `A2A-Version:
   1.0` (header or query parameter; a numeric patch suffix is ignored per
   §3.6). Absent/empty means 0.3 (§3.6.2), which this interface does not
   serve → `VersionNotSupportedError`: JSON-RPC `-32009` envelope on
   `/jsonrpc`, HTTP 400 `google.rpc.Status` on `/rest` (§5.4, §9.5,
   §11.6).
5. **Receipts as a spec extension (§4.6.2)** — every response carries a
   signed `nucleus-envelope` bundle binding *caller × resource ×
   sha256(payload pre-image)*, riding in the response object's `metadata`
   under `https://coproduct.one/a2a/ext/receipt/v1` (declared in the
   card's `capabilities.extensions`, optional). Non-streaming responses
   *also* carry it base64url'd in the `X-Nucleus-Receipt` header for curl
   ergonomics. **SSE streams are receipted per event**: each event's
   receipt rides in that event's metadata and attests its position in the
   stream (`resource: "<path>#sse-<n>"`). Receipts verify **offline**
   against the server's published JWKS (`verify_receipt_bundle` in Rust,
   `verify_receipt_js` in a browser). The exact bytes a receipt binds —
   and what a receipt does *not* prove — are specified in
   `docs/a2a-receipt-extension.md`.

```bash
cd examples/a2a-server
cargo test          # unit + e2e: discover → gate (401s) → negotiate → serve → verify receipts
cargo run           # interactive server on :3000 with a demo caller card
```

## External conformance (A2A TCK)

`cargo run --bin tck-target` serves the **same SDK routers and executor
without the verification gate**, on port 9999. It exists so external
transport-conformance tooling (the [A2A TCK]) can exercise the protocol
bindings — the TCK speaks pure A2A and cannot attach the signed
`X-Agent-Card` header, so the gated server 401s it before any binding is
reached. It is **not a deployment mode**: the demo server always gates and
has no flag to disable its gate; the gate itself is covered by `tests/e2e.rs`.
CI runs the TCK against this target weekly and on changes here (advisory
`a2a-tck` workflow):

```bash
cargo run --bin tck-target &
git clone https://github.com/a2aproject/a2a-tck && cd a2a-tck
uv venv && uv pip install -e .
uv run ./run_tck.py --sut-host http://localhost:9999 \
  --level must --transport jsonrpc,http_json   # no gRPC: not served here
```

[A2A TCK]: https://github.com/a2aproject/a2a-tck

The e2e suite also pins **shape interop**: a nucleus-signed card
round-trips through the official SDK's own `AgentCard` type with exactly
one pinned deviation (the SDK re-serializes `securityRequirements` as the
flat OpenAPI map instead of the normative ProtoJSON shape) — the
signature still verifies once that field is restored.

Demo-grade on purpose: keys are generated per run and the receipt signer
is the TEST-ONLY `insecure-local-issuer`. A production deployment injects
a real `EdgeSigner` (e.g. SPIFFE-Workload-API-backed), publishes its JWKS
out-of-band, and decides which caller keys to trust the same way. For the
IFC-gated variant (model-level flow decision folded into the receipt),
see `nucleus_verify_commerce::serve_verified_ifc`.

Standalone workspace — excluded from the root workspace so the SDK and
axum stay out of the main dependency graph.
