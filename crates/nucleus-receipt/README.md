# nucleus-receipt

The **colimit receipt envelope** for agent actions:

- **`Session`** — the unit of authorship (SPIFFE id, issuer key id,
  issue time, delegation `parent_chain`). Every projection projects
  from this object.
- **`Projection`** — one independently-verifiable view of a session,
  adjacently tagged on the wire (`{"kind": "...", "body": ...}`) for
  in-toto/SLSA predicate compatibility. Current kinds: `identity`,
  `capability`, `flow`, `economic`.
- **`Receipt`** — the Ed25519-signed envelope holding a session plus
  any subset of its projections, with a BLAKE3 root hash over the
  canonical signing bytes. Verification is offline: re-canonicalize,
  re-hash, re-verify.

Categorically: the receipt is a colimit of projections of one session
— each projection is a functor's-eye view of the same action, and the
signed envelope is the universal object that all of them commute
through. This crate is the *law layer*; the concrete body types and
the mechanisms that emit them (identity issuers, flow trackers, VCG
clearing) live downstream and instantiate the envelope.

## Wire-format stability

`canonical_signing_bytes` is sorted-key JSON of
`{projections, session, version}` and is **byte-pinned by a golden
test**, so signer/verifier splits (e.g. a transitive dependency
enabling `serde_json/preserve_order`) fail CI loudly instead of
breaking verification silently.

This crate is the upstream home of the envelope formerly defined in
`nucleus-substrate-core` (nucleus-platform), which now re-exports
these types; receipts produced by either are interchangeable.

## Example

```rust
use nucleus_receipt::{Session, Receipt, Projection};
use ed25519_dalek::SigningKey;

let sk = SigningKey::from_bytes(&[7u8; 32]);
let session = Session {
    session_id: "spiffe://test/agent-x".into(),
    issuer_kid: "test-kid".into(),
    issued_at_micros: 1_717_000_000_000_000,
    parent_chain: vec![],
};
let receipt = Receipt::sign(
    session,
    vec![Projection::Identity(serde_json::json!({"sub": "spiffe://test/agent-x"}))],
    &sk,
);
let vk: [u8; 32] = sk.verifying_key().to_bytes();
receipt.verify(&vk).expect("verifies offline");
```
