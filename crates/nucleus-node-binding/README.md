# nucleus-node-binding

A signed binding layer that unifies an agent's **transport identity** — an
iroh `NodeId`, i.e. a 32-byte ed25519 transport public key — with its
**passport principal**, so you can *dial an agent by its proven identity*.

This is the pure binding slice of the iroh trust-fabric transport RFC
(integration #4). It deliberately has **no iroh dependency**: the
`NodeId <-> [u8; 32]` conversions are a later, feature-gated slice.

## What a binding asserts (and what it does not)

A `NodeBinding` asserts exactly:

> **"this passport controls this transport key"**

It does **not** assert that the agent is well-behaved, attested, sandboxed, or
otherwise trustworthy. Possessing a `NodeId` only proves control of a
transport key. Binding it to a passport principal requires a *signed
statement* — the passport key vouches for the `NodeId`. Co-location or
self-assertion is not enough. Attested capabilities/behaviour live in other
layers and are out of scope here.

## Invariants

- **Fail-closed.** A forged, tampered, unsigned, or wrong-key binding verifies
  to `Err(..)` and contributes no trust.
- **No key smuggling.** Verification trusts a passport public key the
  **caller** supplies (keyed by the principal in their own identity system).
  The binding carries no passport public key that verification trusts.
- **Domain separation.** The signed bytes are prefixed with
  `nucleus-node-binding/v1\n:`, so a passport signature minted for another
  purpose cannot be replayed as a node binding, and vice versa.
- **Pure.** Depends only on `ed25519-dalek` (workspace-pinned) plus
  `serde`/`hex`/`thiserror`. No iroh / iroh-gossip / QUIC.

## Usage

```rust
use ed25519_dalek::SigningKey;
use nucleus_node_binding::{sign_binding, verify_binding};

let passport_sk = SigningKey::from_bytes(&[7u8; 32]);
let passport_pk = passport_sk.verifying_key().to_bytes();
let node_id = [42u8; 32]; // an iroh NodeId is exactly these 32 bytes

let binding = sign_binding(&node_id, "spiffe://example/agent-x", &passport_sk);

// A verifier that already trusts `passport_pk` (keyed by the principal in its
// own system) confirms the passport vouches for this transport key.
verify_binding(&binding, &passport_pk).expect("binding verifies");
```

## Test

```bash
cargo test -p nucleus-node-binding
```

Licensed under MIT OR Apache-2.0.
