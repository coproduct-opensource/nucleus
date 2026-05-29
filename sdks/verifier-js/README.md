# nucleus-verifier-wasm

WASM bindings for verifying [nucleus](https://github.com/coproduct-opensource/nucleus)
provenance bundles **in the browser or Node**, with no trust in any
hosted verifier service.

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

## Publishing to npm

Publishes are triggered by the GitHub Actions workflow at
`.github/workflows/publish-verifier-sdk.yml` (workflow_dispatch).
The workflow:

1. Installs Rust 1.95+ + wasm32-unknown-unknown + wasm-pack.
2. Runs `cargo clippy -p nucleus-envelope -- -D warnings`.
3. Runs `cargo test -p nucleus-envelope`.
4. Runs `wasm-pack test --node` (the suite in `tests/web.rs`).
5. Runs `wasm-pack build --target bundler --release --scope coproduct`.
6. Publishes `sdks/verifier-js/pkg/` to npm under
   `@coproduct/nucleus-verifier-wasm` with the chosen dist-tag.

To dispatch a publish:

```sh
gh workflow run publish-verifier-sdk.yml \
  -f dist_tag=next \
  -f dry_run=false
```

`dist_tag=next` is the default — promote a known-good build to
`latest` later via `npm dist-tag add @coproduct/nucleus-verifier-wasm@VERSION latest`.

Required secrets:
- `NPM_TOKEN` — npm automation token with publish access to the
  `@coproduct` scope.

Local maintainer-driven publishes (without the workflow) work the
same way:

```sh
wasm-pack build --target bundler --release --scope coproduct
cd pkg && npm publish --access public --tag next
```

The maintainer's local credentials sign the publish; never check the
npm token in.
