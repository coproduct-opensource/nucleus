# A2A extension: nucleus runtime-guarantee claims (v1)

**Extension URI:** `https://coproduct.one/a2a/ext/runtime-guarantees/v1`
**Status:** stable (v1; the URI is versioned — breaking changes get a new URI, per A2A §4.6)
**Declared in:** `AgentCard.capabilities.extensions[]`, `required: false`
**Implementation:** `crates/nucleus-agent-card` (`NucleusClaims`, `AgentCard::with_nucleus_claims`, `AgentCard::nucleus_claims`)

A2A v1.0 made Signed Agent Cards first-class (§8.4): a verified signature
proves the card's *metadata* is authentic and untampered. This extension
defines what nucleus puts behind that signature — workload identity, a
trust anchor for provenance bundles, and a declared runtime
information-flow-control (IFC) guarantee profile — so that "verify the
card" becomes the entry point to *verify-before-you-act*.

It is an ordinary A2A v1.0 extension: agents declare it in
`capabilities.extensions` with `required: false`, so generic A2A clients
that don't understand it interoperate untouched. Nucleus-aware recipients
extract the claims after (and only after) card signature verification.

## Declaration shape

```json
{
  "capabilities": {
    "extensions": [
      {
        "uri": "https://coproduct.one/a2a/ext/runtime-guarantees/v1",
        "description": "nucleus verify-before-you-act claims: SPIFFE/DID identity, trust JWKS, envelope schema versions, runtime-guarantee profile",
        "params": {
          "spiffeId": "spiffe://prod.example.com/ns/agents/sa/coder",
          "did": "did:web:coder.prod.example.com",
          "supportedEnvelopeSchemaVersions": ["1"],
          "trustJwks": {
            "keys": [
              {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "kid": "issuer-2026-06",
                "x": "…base64url(32 bytes)…"
              }
            ]
          },
          "runtimeGuarantees": {
            "profileVersion": "1.0",
            "trackedSources": ["web_content", "secret", "file_read"],
            "enforcementRules": [
              {
                "name": "no_adversarial_to_outbound",
                "description": "Adversarial-tainted data cannot reach outbound sinks without explicit human promotion."
              }
            ],
            "attestationReference": "https://example.com/policy/acs-1234"
          }
        }
      }
    ]
  }
}
```

## `params` schema

All names are lowerCamelCase (the card is ProtoJSON-serialized; the
extension `params` is a `google.protobuf.Struct`).

| field | type | presence | meaning |
|---|---|---|---|
| `spiffeId` | string | REQUIRED | Workload identity of the agent (`spiffe://<trust-domain>/ns/<ns>/sa/<name>`). |
| `did` | string | REQUIRED | Decentralized identifier (W3C `did:web`) for the same agent. |
| `supportedEnvelopeSchemaVersions` | string[] | optional (omit when empty) | Provenance envelope/bundle schema versions the agent produces or consumes. |
| `jwksUri` | string | optional | Where the agent's CARD-verification JWKS is published. A hint for out-of-band resolution — never trusted material on its own. |
| `trustJwks` | JWKS object | REQUIRED | The JWKS the agent claims is authoritative for its **provenance bundles** (RFC 7517 subset: `OKP`/`Ed25519`; unset optional members are omitted, never `null`; optional `not_before`/`not_after` rotation windows). |
| `runtimeGuarantees` | object | optional | Declared runtime IFC guarantee profile, below. |

`runtimeGuarantees`:

| field | type | presence | meaning |
|---|---|---|---|
| `profileVersion` | string | REQUIRED | Profile schema version (versioned independently of the card). |
| `trackedSources` | string[] | optional (omit when empty) | Data-flow source kinds the agent declares it labels and tracks — the lethal-trifecta surface (`web_content`, `secret`, `file_read`, …). Tokens match `nucleus-verify-commerce`'s `DeclaredInput` serde names. |
| `enforcementRules` | `{name, description}[]` | REQUIRED | Named IFC rules the agent declares it applies at runtime (e.g. `no_adversarial_to_outbound`). |
| `attestationReference` | string | optional | Advisory pointer to external policy evidence (e.g. an ACS policy id, a Sigstore bundle URL). |

## Verification semantics

Order of operations is the contract:

1. **Verify the card first.** The card signature (A2A §8.4: detached JWS,
   ES256, RFC 8785 JCS, `signatures` excluded from signed content) is
   verified against a key the recipient resolved **out-of-band** — a
   trusted key store in §8.4.3's terms. Nucleus's `verify_card` never
   selects a key from the card's own material or the protected header's
   `kid`/`jku`; a card verified against attacker-supplied key material is
   verified garbage.
2. **Only then read the claims.** `verify_card` returns
   `VerifiedCard { card, claims }`; the claims are meaningful *because*
   the signature over them verified. Nucleus's verifier REQUIRES this
   extension to be present and well-formed (a card with no claims cannot
   anchor anything); it also rejects an empty or malformed `trustJwks` up
   front.
3. **`trustJwks` becomes a trust anchor.** After verification,
   `trust_anchor_from_card` turns the advertised JWKS into the
   `TrustAnchor` used to verify the agent's provenance bundles
   (`nucleus-envelope::verify_bundle`). Before verification it is just a
   claim.

### What a verified profile proves — and what it does not

A verified `runtimeGuarantees` profile proves exactly this: **the holder
of the signing key made this declaration, and nobody altered it.** The
declaration is covered by the card's JCS signature, so any post-signing
tamper — including inside `params` — fails verification.

It does **not** prove:

- that the declared enforcement actually runs (attestation, not
  enforcement — the runtime enforces; the card declares);
- that the agent behaves correctly within whatever IS enforced;
- anything about `attestationReference` — it is advisory; a verifier
  with no out-of-band knowledge of the referenced policy system cannot
  confirm it.

Closing the declaration→enforcement gap (runtime-measured attestation) is
the subject of the attestation-stack roadmap in
[`docs/rfcs/signed-ifc-attested-agents.md`](rfcs/signed-ifc-attested-agents.md)
— this extension is its Layer 1.

## Interop notes

- Generic A2A v1.0 clients see an optional extension and may ignore it;
  every spec-required card field is present and meaningful without it.
- The extension declaration is static card content; it does not use the
  per-request `A2A-Extensions` activation header (that mechanism is for
  message/artifact-level extension data, §4.6).
- Conformance of the card container itself (canonicalization presence
  rules, header parameters, signature exclusion) is pinned by the
  `nucleus-agent-card` §8.4 conformance suite
  (`crates/nucleus-agent-card/src/conformance_tests.rs`), including a
  golden-bytes pin of a card carrying this extension.
