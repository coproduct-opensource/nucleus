# nucleus-envelope

Portable provenance bundles for nucleus agent sessions — agent payload + signed
IFC lineage envelope.

[![docs.rs](https://img.shields.io/docsrs/nucleus-envelope)](https://docs.rs/nucleus-envelope)

A `Bundle` is the on-wire artifact a nucleus control plane hands its customer at
the end of a session: the agent's structured payload (hard stats, summary, any
JSON) plus an `Envelope` carrying the signed IFC lineage subgraph that proves how
the payload was produced.

## Trust model — read this before pitching it to anyone

The bundle is **portable** (anyone can carry the bytes) but **not
self-anchoring**. The JWKS embedded in the envelope is producer-supplied; a
forger fabricating a whole bundle controls it. Therefore `verify_bundle`
requires a `TrustAnchor` obtained **out-of-band** (a `chmod 400` file, OIDC
discovery, a signed operator bundle). Every signature is checked against the
trust anchor's JWKS — never the embedded one.

`TrustAnchor::self_check_only` is an explicit opt-in to "verify the envelope
against the JWKS it carries." That proves internal consistency (no later
mutation goes undetected) but **does not prove the producer is who they claim**.
The `VerificationReport` flags this mode so downstream code can refuse to treat
it as a provenance claim.

## What integrity is enforced

1. **Per-edge proofs** — each lineage edge's Ed25519 signature covers
   `canonical_edge_bytes(edge, prev_hash)`; tampering breaks verification.
2. **Hash chain** — each edge's `prev_hash` points at the previous edge's
   content hash; splicing/reordering breaks the chain.
3. **Signed tree heads (STHs)** — a witness Ed25519 signature over
   `(tree_size, timestamp_ms, root_hash)` attests "the log had N entries at this
   moment." The Merkle anchor's STH binds the session edges by inclusion proof;
   `checkpoints` are verified against the same witness key, the anchor, and —
   when the bundle carries the whole log — roots recomputed from its edges.
4. **Payload binding** — the producer's signature over the RFC 8785 payload
   hash, the chain head, the Merkle root and the envelope metadata.

### Schema version 2

Version 2 hashes the payload's RFC 8785 form (version 1 used
`serde_json::to_vec`, whose key order depends on `serde_json/preserve_order`)
and signs `meta` (`schema_version`, `created_at`), which version 1 left
unauthenticated. Verifiers refuse version 1 (`SchemaTooOld`): re-emit old
bundles.

### Scope limits

Checkpoints of a log larger than the session are checked for signature,
equivocation and agreement with the anchor, but cannot be recomputed from the
bundle. A bundle without a payload binding has no producer signature over its
payload or metadata — require one with `TrustAnchor::require_payload_binding`.

## Interop exports

The `interop` module emits the same provenance as ecosystem-standard formats:
in-toto / DSSE statements, Sigstore bundles, and SLSA. With the `c2pa` feature,
`c2pa_export` produces a C2PA assertion.

## Example

```rust,ignore
use nucleus_envelope::BundleBuilder;
use nucleus_lineage::{InMemorySink, CallSpiffeId};

let pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer")?;
// ... agent runs, sink fills with edges ...
let bundle = BundleBuilder::new(pod)
    .payload(serde_json::json!({ "summary": "..." }))
    .sink(&sink)
    .jwks(issuer_jwks)
    .checkpoints(checkpoints)
    .build()?;
let json = serde_json::to_string(&bundle)?;

// Verifier side — anchor MUST come from out-of-band:
// let report = nucleus_envelope::verify_bundle(&bundle, &trust_anchor)?;
```

## Feature flags

| Feature | Effect |
|---|---|
| *(default)* | core bundle + verify + in-toto/Sigstore/SLSA interop |
| `c2pa` | C2PA assertion export via the `c2pa` crate |

## License

MIT
