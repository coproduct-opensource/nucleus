# nucleus-bundle-cas

Content-addressed transport for nucleus provenance `Bundle`s — BLAKE3 root +
[iroh-blobs](https://docs.rs/iroh-blobs).

[![docs.rs](https://img.shields.io/docsrs/nucleus-bundle-cas)](https://docs.rs/nucleus-bundle-cas)

Addresses a serialized [`Bundle`](../nucleus-envelope) by the BLAKE3 hash of its
JSON bytes (`BundleHash`) and fetches + verifies it from an untrusted peer over a
bao-verified `iroh-blobs` stream. Delivered bytes are then piped into the
existing `nucleus_envelope::verify_bundle` — content-addressing is a *transport*
concern, deliberately orthogonal to provenance.

## Trust model — read this before pitching it to anyone

The guarantees are intentionally narrow. This is the smallest shippable slice of
content-addressed fetch, and its honesty is load-bearing:

- **No content discovery.** The node ticket (`iroh::NodeAddr`) is passed
  out-of-band. There is **no DHT, no content routing, no provider
  advertisement** — that's deferred and aspirational; do not claim it exists.
- **No NAT traversal in this slice.** Relays/holepunching are iroh's job but are
  not exercised or guaranteed here; addresses are supplied directly.
- **No availability guarantee.** A peer can be offline or refuse to serve. The
  only guarantee is **correctness of delivered bytes**: the bao-verified stream
  rejects anything whose BLAKE3 root ≠ the requested `BundleHash`. A peer cannot
  *substitute* content.
- **`fetched != trusted`.** BLAKE3 byte-integrity is orthogonal to envelope
  provenance. A perfect-hash fetch can still fail `verify_bundle` (e.g.
  forged/unknown issuer JWKS). You **must** run `verify_bundle` with an
  out-of-band `TrustAnchor` after fetching.
- **A raw 32-byte BLAKE3 hash is not a CID.** No multihash/multicodec/multibase
  framing; don't interoperate with IPLD/IPFS tooling as if it were one.
- **`BundleHash` is a transport id, distinct from the SHA-256
  `canonical_bundle_hash`** in `nucleus-envelope`. The canonical hash is a
  stable, attestation-bearing identity over selected fields; this BLAKE3 hash is
  over the full serialized bytes (any byte change alters it). Never conflate them.
- **Not wired into the WASM/browser verifier.** iroh-blobs is a native
  (tokio + QUIC) transport; this crate is server/CLI-side only.

## Single-tenant value

Useful to **one** operator with zero counterparties: content-addressed,
bao-verified replication of your own provenance bundles across your own
machines / regions / clouds — tamper-evident archival and disaster recovery
where any replica's bytes self-validate against the `BundleHash`. The "mesh"
value is *failure-domain diversity*, not other organizations; peer fan-out is
additive, not a prerequisite. (Again: `fetched != trusted`.)

## API

```rust,ignore
use nucleus_bundle_cas::{blake3_bundle_hash, publish_bundle, fetch_bundle};

// Address by the BLAKE3 root over the bundle's JSON bytes.
let hash = blake3_bundle_hash(&bundle);

// Publisher side: add the bundle to a content-addressed store.
let hash = publish_bundle(&store, &bundle).await?;

// Fetcher side: bao-verified fetch by hash from an out-of-band peer address.
let bundle = fetch_bundle(&endpoint, &store, node_addr, hash).await?;

// MANDATORY: a hash-correct fetch is NOT provenance. Verify against an
// out-of-band trust anchor before trusting the bundle.
// nucleus_envelope::verify_bundle(&bundle, &trust_anchor)?;
```

## Versioning note

`iroh` / `iroh-blobs` are pre-1.0 and pinned exactly (`iroh =1.0.0-rc.1`,
`iroh-blobs =0.102.0`) because they move together; expect churn on upgrades.

## License

MIT
