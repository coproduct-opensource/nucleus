# @coproduct/verify

> The one-line, no-infra drop-in for verifying nucleus provenance receipts.

```sh
npm install @coproduct/verify
```

```ts
import { verify } from "@coproduct/verify";

const r = await verify(receipt, trustAnchor);   // auto-inits WASM; no setup
if (!r.ok) throw new Error(`receipt rejected: ${r.error.message}`);
console.log("verified locally:", r.report.head_edge_hash_hex);
```

That is the whole integration. No `init()`, no service to run, no crypto to
wire. `verify()` runs the audited nucleus envelope verifier (compiled to WASM)
**in your own Node or browser process** and returns a result you branch on.

### `recompute()` — re-derive the decision, don't just trust the signature

`verify()` proves a receipt was *signed*. `recompute()` proves the in-bounds
**IFC decision was correct** — by re-running the *exact same gate function the
producer ran* (`nucleus-ifc`, compiled to this WASM), in your process:

```ts
import { recompute, checkVerdict } from "@coproduct/verify";

// Re-derive the verdict for a call's declared data-flow inputs:
const r = await recompute(["user_prompt", "web_content"]);
// r.verdict.allow === false  (adversarial web content reaching an outbound action)

// Or one-line: does the receipt's claimed verdict actually hold?
const honest = await checkVerdict(receipt.declared_inputs, receipt.allow);
if (!honest) throw new Error("receipt's IFC verdict does not re-derive");
```

This is the structural difference from a payment receipt: it is a verdict a
counterparty **independently re-derives**, not a vendor's signature over the
vendor's own claim. Because it runs the *same code* as the gate, the recompute
can never drift from enforcement. Fails closed on an unknown input token.

**Scope (honest):** model-level over the **declared** inputs (coverage-limited,
per-call) — the same boundary as the gate itself.

### `verifyReceipt()` — the colimit receipt envelope

`verify()` covers the lineage **bundle**; `verifyReceipt()` covers the other
signed artifact — the **colimit receipt** (`nucleus-receipt`: a `Session` +
its `Projection[]`, Ed25519-signed over the BLAKE3 hash of the RFC 8785
canonical bytes). The WASM runs the *same* `Receipt::verify` every upstream
signer and verifier runs, so there is **one verifier code path for every
receipt kind**: a receipt signed by any nucleus binary verifies
byte-for-byte identically in your process.

```ts
import { verifyReceipt } from "@coproduct/verify";

const v = await verifyReceipt(receipt, issuerVerifyingKeyHex); // hex or Uint8Array
switch (v.outcome) {
  case "verified":            /* v.session_id, v.projection_kinds, v.root_hash_hex */ break;
  case "root_hash_mismatch":  /* content tampered AFTER signing */ break;
  case "signature_mismatch":  /* wrong issuer key or forged signature */ break;
}
```

A cryptographic rejection is a **value** you branch on — and it tells you
*which* property failed: `root_hash_mismatch` (the session or a projection was
altered after signing) vs `signature_mismatch` (intact content, wrong/forged
key). Only malformed *input* throws (bad JSON, wrong key length, a key that is
not a curve point). The verifying key is yours to pin — typically the issuer's
JWKS `x` field, decoded.

### What it checks

A receipt is a portable **bundle** of an agent's execution lineage. `verify()`
proves two things, locally, against a trust anchor **you pin**:

- **Tamper-evidence** — every edge is hash-chained and the chain is
  Merkle-anchored (RFC 9162). Reorder, splice, or flip one byte and it fails.
- **Authenticity** — every edge is Ed25519-signed, and the head is cosigned by
  the witness key(s) you trust. Signatures must verify against *your* JWKS, not
  anything embedded in the bundle.

### What it does NOT check (honest scope)

`verify()` is a cryptographic primitive, not a judgement about behaviour. A
green result means the lineage is **authentic and intact** — it does **not**
mean:

- the agent *behaved well* or made good decisions;
- any information-flow (IFC) policy held — that's the IFC gateway + the Lean
  noninterference theorem, a separate guarantee;
- any computation was *correct*.

Also: **the trust anchor is yours to supply and pin.** `verify()` does not fetch
keys, does not phone home, and trusts nothing but the anchor argument you hand
it. "Fetched and verified" is not "the agent did the right thing."

### Result shape (discriminated union)

A failed verification is a **value**, not a thrown exception — you can't forget
to handle it. Branch on `.ok`:

```ts
type VerifyResult =
  | { ok: true;  report: VerifyReport }
  | { ok: false; error: VerifyError };   // error.code: "INPUT" | "INIT" | "VERIFICATION"
```

`VERIFICATION` = the receipt was cryptographically/structurally rejected;
`INPUT` = the receipt/anchor couldn't be serialised; `INIT` = the WASM verifier
failed to load. `verify()` accepts either JSON strings or already-parsed
objects for both arguments. It auto-initialises the WASM exactly once per
process/page (concurrent calls share one init).

### Node + browser, same import

The package ships the wasm-pack `web` build. In the browser the WASM is fetched
from the co-located `.wasm`; in Node (>=18) the facade reads the same bytes off
disk and instantiates them directly — no network either way.

### Metering (DORMANT — documented, not wired)

A **successful** `verify()` is the natural per-verification metering point for a
future paid tier (e.g. pay-per-verify over [x402](https://www.x402.org/) /
L402): it is the unit of value the caller actually consumes. This seam is
**dormant** — `verify()` performs **no payment, keeps no counter, and makes no
network call**. Turning it on would wrap the `ok: true` branch with an
x402/L402 settlement step, a deliberate separate go-live decision (like the
gated npm publish workflow and the `DOCS_DEPLOY` seam). Nothing in this package
bills you today. See the comment at the top of `index.js`.

### Verify the verifier

```ts
import { verifierVersion, supportedSchemaVersion } from "@coproduct/verify";
await verifierVersion();        // semver of the WASM verifier
await supportedSchemaVersion(); // envelope-schema version this build accepts
```

### Smoke test (the wedge's core claim)

`npm test` runs a Node test that verifies a **real** fixture bundle and then
**rejects** a tampered copy (one flipped signature byte) — same fixtures the
in-browser demo uses, no fake data. Requires `./pkg` (run `npm run build:wasm`
first; CI builds it before publish).

---

## nucleus-verifier-wasm (the WASM core under the facade)

`@coproduct/verify` is a thin ergonomic facade over **nucleus-verifier-wasm**:
the WASM bindings for verifying [nucleus](https://github.com/coproduct-opensource/nucleus)
provenance bundles **in the browser or Node**, with no trust in any
hosted verifier service. The facade adds no crypto — only auto-init and the
typed result. Everything below documents that core.

This is the moat: anyone can verify a bundle without trusting our
storage, our endpoints, or our operators. The math runs in your
process; the trust anchor is something you obtain out of band.

## Why client-side verification

The default verifier service at `verifier.coproduct.io` is **convenience**,
not the trust root. If you only check bundles by POSTing them to a
service we run, you're trusting:

1. Our server isn't compromised
2. Our network isn't intercepted
3. Our reported result matches the math

Running the verification in your own process closes all three. The
SDK ships the same Rust verifier compiled to WASM — the byte-for-byte
implementation the open-source repo audits.

## Build

Requires Rust 1.95+ and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```sh
cd sdks/verifier-js
wasm-pack build --target web --release
# Output lands in ./pkg
```

Targets:

| `--target`  | Use when                                              |
|-------------|-------------------------------------------------------|
| `web`       | Direct `<script type="module">` or modern frontends   |
| `bundler`   | webpack, rollup, Vite, esbuild                         |
| `nodejs`    | Node.js CommonJS                                       |
| `no-modules`| Plain `<script>` tags (legacy)                         |

## Use

```ts
import init, {
  verifyBundle,
  sdkVersion,
  supportedEnvelopeSchemaVersion,
} from "./pkg/nucleus_verifier_wasm.js";

await init();   // load + instantiate the WASM module (once per page)

const bundle = await fetch("/your-bundle.json").then(r => r.text());
const trustAnchor = JSON.stringify({
  trust_jwks: {   // OOB JWKS — DO NOT use the bundle's embedded JWKS
    keys: [{
      kty: "OKP", crv: "Ed25519", kid: "...", x: "...",
    }],
  },
  // Optional knobs:
  // allow_empty: false,
  // trust_witness_pubkey_hex: "32-byte hex",
  // trusted_witnesses_hex: ["..."],
  // cosignature_threshold: 2,
  // require_payload_binding: true,
});

try {
  const report = verifyBundle(bundle, trustAnchor);
  console.log("OK:", report);
} catch (err) {
  console.error("verification failed:", err.message);
}
```

### Report shape

```ts
interface VerifyReport {
  ok: true;
  trust_mode: "out_of_band" | "self_check_only";
  trust_domain: string;
  edge_count: number;
  checkpoint_count: number;
  head_edge_hash_hex: string;     // 64-char SHA-256 hex
  schema_version: number;
  kids: string[];                  // Every kid covered by the JWKS
  merkle_verified: boolean;        // True iff v2 anchor checked
  cosignatures_verified: number;   // ≥ requested threshold when 200
  matched_witness_pubkeys_hex: string[];
  payload_binding_verified: boolean;
}
```

## Trust posture

The SDK is a pure-math primitive. It:

- **Verifies** every per-edge Ed25519 proof against the trust JWKS.
- **Walks** the chain hash and rejects splicing/reordering.
- **Validates** Merkle inclusion proofs against the witness pubkey
  (when supplied via `trust_witness_pubkey_hex`).
- **Enforces** cosignature thresholds across the trusted-witness set.
- **Checks** the v2.2 payload binding when present + required.

The SDK does NOT:

- Fetch JWKS over the network (call sites do that; SDK takes JSON).
- Cache results (call sites decide).
- Produce bundles (signing keys belong server-side, by design).

## Size

Release builds are ~380 KB gzipped to ~120 KB. This is the cost of
shipping a full verifier — Ed25519, SHA-256, RFC 9162 Merkle, JSON,
the whole envelope state machine — in 100% pure-Rust crypto.

## Testing

The SDK has a wasm-bindgen-test suite that exercises the
verify path inside a real wasm runtime:

```sh
# Node.js target (default; no browser deps needed):
wasm-pack test --node

# Browser target (Chrome via WebDriver):
# Uncomment `wasm_bindgen_test_configure!(run_in_browser);` in
# tests/web.rs first.
wasm-pack test --chrome --headless
```

These tests run against the same wasm artifact npm consumers
receive, so a passing run is genuine evidence the published SDK
behaves as documented.

## Publishing to npm (GATED — operator go-live call)

Publishes are triggered ONLY by the GitHub Actions workflow at
`.github/workflows/publish-verifier-sdk.yml` (`workflow_dispatch`), and even
then only when the repo variable `PUBLISH_VERIFY_SDK == "true"` and
`dry_run == false`. There is no push trigger and no auto-publish — going live is
a deliberate operator decision, same posture as `DOCS_DEPLOY`. The workflow:

1. Installs Rust 1.95+ + wasm32-unknown-unknown + wasm-pack.
2. Runs `cargo clippy -p nucleus-envelope -- -D warnings`.
3. Runs `cargo test -p nucleus-envelope`.
4. Runs `wasm-pack test --node` (the suite in `tests/web.rs`).
5. Runs `wasm-pack build --target web --release` into `pkg/` (gitignored build
   product — the facade `index.js` auto-inits the `web` build in Node + browser).
6. Runs the Node smoke test (`npm test`: accept real + reject tampered).
7. Publishes the `sdks/verifier-js` package as **`@coproduct/verify`** (with npm
   provenance) under the chosen dist-tag — only if the gate passes.

To dispatch a DRY RUN (default — builds + packs, never publishes):

```sh
gh workflow run publish-verifier-sdk.yml -f dist_tag=next -f dry_run=true
```

To actually publish (operator only): set repo variable
`PUBLISH_VERIFY_SDK=true`, then:

```sh
gh workflow run publish-verifier-sdk.yml -f dist_tag=next -f dry_run=false
```

`dist_tag=next` is the default — promote a known-good build to
`latest` later via `npm dist-tag add @coproduct/verify@VERSION latest`.

Required secrets / variables:
- `NPM_TOKEN` — npm automation token with publish access to the `@coproduct`
  scope.
- `PUBLISH_VERIFY_SDK` (repo variable) — must equal `"true"` to publish.

Local maintainer-driven publishes (without the workflow) work the same way:

```sh
npm run build:wasm                       # wasm-pack build --target web --release
npm test                                 # accept real + reject tampered
npm publish --provenance --access public --tag next
```

The maintainer's local credentials sign the publish; never check the
npm token in.

## In-browser tamper demo (`demo.html`)

A self-contained, install-nothing page that verifies a **real** agent
execution-lineage bundle entirely in your browser — then lets you corrupt it
and watch the local verifier reject it. The verifier is this crate compiled to
WASM; the bundle + trust anchor are generated and self-verified (including a
tamper-rejection assertion) by
`crates/nucleus-envelope/examples/emit_demo_bundle.rs` — no fake data.

Run it locally:

```sh
# 1. real fixtures -> sdks/verifier-js/demo-fixtures/
cargo run -p nucleus-envelope --example emit_demo_bundle

# 2. build the WASM verifier -> sdks/verifier-js/pkg/
wasm-pack build sdks/verifier-js --target web --release

# 3. serve (file:// can't fetch the wasm/fixtures) and open /demo.html
python3 -m http.server -d sdks/verifier-js 8000
# -> http://localhost:8000/demo.html
```

To prove there is no server round-trip: open DevTools → Network, toggle
**Offline**, then click Verify — it still works.

Hosted: the CI `Docs` workflow builds the WASM + fixtures and publishes the demo
at `/verify/` on the docs site (only when the `DOCS_DEPLOY` repo variable is
`true`).

**Scope (honest):** the verifier proves the lineage is tamper-evident (hash
chain + Merkle inclusion) and authentic (signed/cosigned by the keys in *your*
trust anchor). It does **not** prove the agent behaved well, that
information-flow policy held, or that any computation was correct — those are
separate guarantees (see the IFC gateway and the Lean noninterference theorem).
