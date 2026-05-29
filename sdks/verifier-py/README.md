# nucleus-verifier

Python bindings for verifying [nucleus](https://github.com/coproduct-opensource/nucleus)
provenance bundles **in your own backend**, with no trust in any
hosted verifier service.

Mirrors the [JS SDK](../verifier-js/) for browser/Node — same wire
contract, same trust posture, same guarantees. Use this when you
want to verify bundles inside a Python pipeline (FastAPI, Django,
data-ingestion workers, etc.) without taking a network dependency
on `verifier.coproduct.io`.

## Build

Requires Rust 1.95+, Python 3.8+, and [maturin](https://www.maturin.rs/).

```sh
uv tool install maturin            # one-time
cd sdks/verifier-py
maturin develop --release          # installs into the current venv
# OR for a distributable wheel:
maturin build --release            # output → target/wheels/*.whl
```

ABI3 (`abi3-py38`) means one wheel per (OS, arch) covers every
CPython interpreter from 3.8 onward — no per-version rebuild.

## Use

```python
from nucleus_verifier import verify_bundle, sdk_version

bundle = open("bundle.json").read()
trust_anchor = json.dumps({
    "trust_jwks": {              # OOB JWKS — NOT the bundle's embedded JWKS
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "...", "x": "...",
        }],
    },
    # Optional knobs:
    # "allow_empty": False,
    # "trust_witness_pubkey_hex": "<32-byte hex>",
    # "trusted_witnesses_hex": ["..."],
    # "cosignature_threshold": 2,
    # "require_payload_binding": True,
})

try:
    report = verify_bundle(bundle, trust_anchor)
except ValueError as e:
    # Malformed input — caller's fault.
    raise
except RuntimeError as e:
    # Verification rejected — bundle is bad.
    raise

assert report["ok"] is True
assert report["trust_mode"] in ("out_of_band", "self_check_only")
```

### Report shape

```python
{
    "ok": True,
    "trust_mode": "out_of_band",          # "self_check_only" without JWKS
    "trust_domain": "prod.example.com",
    "edge_count": 5,
    "checkpoint_count": 1,
    "head_edge_hash_hex": "<64-char SHA-256 hex>",
    "schema_version": 1,
    "kids": ["..."],                       # every kid covered by the JWKS
    "merkle_verified": True,
    "cosignatures_verified": 2,
    "matched_witness_pubkeys_hex": ["..."],
    "payload_binding_verified": True,
}
```

## Trust posture

Pure-math primitive. Verifies every Ed25519 per-edge proof + chain
hash + Merkle inclusion (when present) + cosignature threshold +
payload binding. Does NOT fetch JWKS, cache results, or produce
bundles.

Same Rust verifier as the JS SDK + verifier-service binary — byte-
for-byte identical implementation across all three surfaces.

## Publishing to PyPI

```sh
maturin publish --release           # needs PYPI_API_TOKEN env
# OR via the matrix builder:
cibuildwheel --output-dir wheelhouse
twine upload wheelhouse/*.whl
```

CI publishes wheels for cp38–cp313 × manylinux2014/macos11/windows
via `cibuildwheel` and `maturin-action`. Local dev just uses
`maturin develop`.
