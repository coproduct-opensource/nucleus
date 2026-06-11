# nucleus-agent-card

Verify-before-you-act identity layer for nucleus agents — sign/verify an
**A2A protocol v1.0** Agent Card and derive a `TrustAnchor` for the bundle
verifier.

[![docs.rs](https://img.shields.io/docsrs/nucleus-agent-card)](https://docs.rs/nucleus-agent-card)

An `AgentCard` is the [A2A v1.0](https://a2a-protocol.org/) manifest an agent
publishes to say **who** it is. Nucleus claims — SPIFFE/DID identity, envelope
schema versions, and the JWKS its provenance bundles are signed under — travel
inside the spec's extension mechanism (`capabilities.extensions[]`) as the
registered extension `https://coproduct.one/a2a/ext/runtime-guarantees/v1`
(`NucleusClaims`). This crate signs (`sign_card`, feature `sign`) and verifies
(`verify_card`) cards per spec §8.4 — a detached RFC 7515 JWS over the RFC 8785
(JCS) canonicalization of the card with its `signatures` field excluded,
protected header `{alg, typ: "JOSE", kid}`, carried in the card's own
`signatures` array — then derives a
[`nucleus_envelope::TrustAnchor`](../nucleus-envelope) (`trust_anchor_from_card`)
so the existing bundle verifier can decide whether to **act** on a bundle.

## Verification surface — pick the right entry point

- `verify_card_signature` / `verify_card_signature_json` — **pure A2A §8.4.3
  signature verification**, no nucleus policy. A validly signed *plain* A2A
  card (no nucleus extension — e.g. one published by any other A2A
  implementation) verifies here.
- `verify_card` / `verify_card_json` — the §8.4.3 check **plus the nucleus
  claims policy** (extension required, usable `trust_jwks`), yielding a
  `VerifiedCard` for the verify-before-you-act flow. Policy rejections are
  labelled as policy, never as signature failures.
- The `*_json` variants verify **the received document** (§8.4.3 steps 3–6
  operate on "the received Agent Card"): canonicalization keeps every received
  member, so an injected unknown member is rejected and a card signed by a
  newer implementation over an unmodeled member still verifies. Prefer them
  whenever the card reached you as raw JSON.
- Every entry of the `signatures` array is checked against the caller's
  resolved key (§8.4.3 allows multiple signatures for key rotation); any one
  verifying suffices, and the key is always the caller's — iterating entries
  introduces no card-controlled key selection.

## Trust model — read this before using

- **Verify needs no secret.** `verify_card` is always compiled and secret-free;
  a browser/WASM verifier can use it directly. Only `sign_card` (behind the
  non-default `sign` feature) touches a private key, and it must stay
  server/dev-side — never ship it to a client.
- **Never trust a key embedded in the card.** `verify_card` reads its
  verification key *only* from the caller's out-of-band-resolved `resolved_key`
  argument (DID resolution, a pinned JWKS, an operator file). It does not read
  any key — or the protected header's `kid`/`jku` — from the card or signature.
  The claims' `jwks_uri` is a *hint* for where to resolve the key, not the key
  itself. (A2A §8.4.3 permits resolving "from a trusted key store"; that is the
  only mode implemented here.)
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
let card   = base_card.with_nucleus_claims(&claims)?;
let signed = sign_card(card, &pkcs8_der, "card-key-1")?;

// recipient side (secret-free):
let resolved = resolve_key_out_of_band(did)?; // YOUR job
let verified = verify_card(&signed, &resolved)?;
let anchor   = trust_anchor_from_card(&verified);
let report   = nucleus_envelope::verify_bundle(&bundle, &anchor)?; // ACT only if this succeeds
```

Cards are canonicalized with RFC 8785 JCS (`canonicalize`, `signatures`
excluded per A2A §8.4.1) before signing/verifying so the signature is over a
deterministic byte representation.

## Feature flags

| Feature | Effect |
|---|---|
| *(default)* | `verify_card` + `trust_anchor_from_card` — secret-free, WASM-safe |
| `sign` | adds `sign_card` (private key). **Server/dev only — never in a browser build.** |

## License

MIT
