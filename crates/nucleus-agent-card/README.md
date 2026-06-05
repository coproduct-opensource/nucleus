# nucleus-agent-card

Verify-before-you-act identity layer for nucleus agents — sign/verify an
A2A-style signed Agent Card and derive a `TrustAnchor` for the bundle verifier.

[![docs.rs](https://img.shields.io/docsrs/nucleus-agent-card)](https://docs.rs/nucleus-agent-card)

An `AgentCard` is the [A2A](https://a2a-protocol.org/)-style document an agent
publishes to say **who** it is and which JWKS its provenance bundles are signed
under. This crate signs (`sign_card`, feature `sign`) and verifies
(`verify_card`) a `SignedAgentCard`, then derives a
[`nucleus_envelope::TrustAnchor`](../nucleus-envelope) (`trust_anchor_from_card`)
so the existing bundle verifier can decide whether to **act** on a bundle.

## Trust model — read this before using

- **Verify needs no secret.** `verify_card` is always compiled and secret-free;
  a browser/WASM verifier can use it directly. Only `sign_card` (behind the
  non-default `sign` feature) touches a private key, and it must stay
  server/dev-side — never ship it to a client.
- **Never trust a key embedded in the card.** `verify_card` reads its
  verification key *only* from the caller's out-of-band-resolved `resolved_key`
  argument (DID resolution, a pinned JWKS, an operator file). It does not read
  any key — or `kid` — from the card or signature. The card's `jwks_uri` is a
  *hint* for where to resolve the key, not the key itself.
- **This is the WHO-layer, not the WHAT-layer.** Verifying a card establishes
  identity and the claimed JWKS. It does **not** verify any payload or bundle —
  that's `nucleus_envelope::verify_bundle`'s job, anchored by the `TrustAnchor`
  this crate derives. A recipient must do **both**.
- **A card verified against an attacker-supplied key is "verified garbage."**
  The signature math passes but proves nothing. The whole guarantee rests on
  `resolved_key` coming from a trustworthy out-of-band channel — by design, the
  crate refuses to hide that decision inside the card.

## End-to-end shape

```rust,ignore
// server side (feature = "sign"):
let signed = sign_card(card, &pkcs8_der)?;

// recipient side (secret-free):
let resolved = resolve_key_out_of_band(&signed.card.did)?; // YOUR job
let verified = verify_card(&signed, &resolved)?;
let anchor   = trust_anchor_from_card(&verified);
let report   = nucleus_envelope::verify_bundle(&bundle, &anchor)?; // ACT only if this succeeds
```

Cards are canonicalized with JCS (`canonicalize`) before signing/verifying so the
signature is over a deterministic byte representation.

## Feature flags

| Feature | Effect |
|---|---|
| *(default)* | `verify_card` + `trust_anchor_from_card` — secret-free, WASM-safe |
| `sign` | adds `sign_card` (private key). **Server/dev only — never in a browser build.** |

## License

MIT
