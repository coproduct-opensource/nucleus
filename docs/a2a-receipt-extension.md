# A2A extension: nucleus signed response receipts (v1)

**Extension URI:** `https://coproduct.one/a2a/ext/receipt/v1`
**Status:** stable (v1; the URI is versioned — breaking changes get a new URI, per A2A §4.6.3)
**Declared in:** `AgentCard.capabilities.extensions[]`, `required: false`
**Carried in:** the response object's `metadata`, keyed by the extension URI (A2A §4.6.2 extension data)
**Implementation:** `examples/a2a-server` (`src/receipt.rs`); verification via `nucleus_verify_commerce::verify_receipt_bundle` (Rust) or `verify_receipt_js` (browser/Node)

A serving agent signs, for every response it delivers, a portable
provenance receipt binding *who was served* (the verified caller's SPIFFE
id), *what resource*, and *which bytes*. The receipt is a
`nucleus-envelope` bundle that any third party can verify **offline**
against the JWKS the agent's signed card advertises (`trustJwks` in the
[runtime-guarantees extension](a2a-runtime-guarantees-extension.md)).

This extension carries that bundle in the A2A spec's own extension-data
mechanism instead of (only) a custom header: ordinary A2A v1.0 clients
see optional metadata they may ignore; receipt-aware clients find the
proof attached to the very object it attests.

## Declaration shape

```json
{
  "capabilities": {
    "extensions": [
      {
        "uri": "https://coproduct.one/a2a/ext/receipt/v1",
        "description": "Signed provenance receipts: each response object's metadata carries a nucleus-envelope bundle …",
        "params": { "responseHeader": "X-Nucleus-Receipt" }
      }
    ]
  }
}
```

`required` is omitted (false): clients that ignore the extension
interoperate untouched. `params.responseHeader` names the legacy/curl
convenience header (below).

## Carriage

The bundle rides in the `metadata` of the **carrier object** — the Task,
`TaskStatusUpdateEvent`, `TaskArtifactUpdateEvent`, or Message that the
response delivers — keyed by the extension URI, exactly like the §4.6.2
examples:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "task": {
      "id": "…",
      "status": { "state": "TASK_STATE_COMPLETED", "…": "…" },
      "metadata": {
        "https://coproduct.one/a2a/ext/receipt/v1": { /* envelope bundle */ }
      }
    }
  }
}
```

- **Non-streaming responses**: one receipt over the whole response
  payload, in the carrier's metadata. The same bundle is ALSO sent
  base64url-encoded in the `X-Nucleus-Receipt` response header (curl
  ergonomics; the metadata entry is the spec-idiomatic carriage and the
  two are byte-identical bundles).
- **SSE streams**: **one receipt per event**, in that event's carrier
  metadata. A live stream has no final byte string to bind, so each
  event is bound individually; the `X-Nucleus-Receipt` header is set to
  the literal `per-event` to signal where to look.
- Payloads with no carrier (JSON-RPC error envelopes, list responses)
  get a header-only receipt on non-streaming responses and pass through
  unreceipted inside streams.

## Payload schema

The metadata value is a `nucleus-envelope` **bundle** (schema version 1):
`{ "envelope": { "edges": […] }, "payload": {…}, "jwks": {…} }`, whose
signed payload is the commerce binding:

| payload field | meaning |
|---|---|
| `kind` | `"verify-commerce-receipt"` |
| `resource` | The served path; for SSE events, `"<path>#sse-<n>"` with `n` the zero-based position of the data event in the stream |
| `caller_spiffe_id` | SPIFFE id of the verified caller (from its signed card) |
| `payment_scheme`, `payment_reference` | Settlement reference (`"none"` / `"a2a-demo"` in this example) |
| `body_sha256` | Hex SHA-256 of the **pre-image** (below) |
| `ifc_verdict` | IFC verdict when served through the IFC gate; `null` here |

## The pre-image: exactly which bytes a receipt binds

A receipt cannot bind bytes that contain the receipt itself, so
`body_sha256` covers a deterministic pre-image rather than the raw wire
bytes:

> **RFC 8785 (JCS) canonicalization of the payload JSON with the receipt
> entry removed** — remove the extension-URI key from the carrier's
> `metadata`, remove `metadata` entirely if that leaves it empty (or if
> it was `null`), then canonicalize.

- For non-streaming responses, "the payload JSON" is the **entire
  response body** (JSON-RPC envelope included).
- For SSE, it is that **event's `data:` payload JSON** (the JSON-RPC
  per-event envelope included on `/jsonrpc`; the bare stream-response
  object on REST). SSE framing (`data: ` prefixes, newlines, any
  `event:`/`id:` lines) and HTTP headers are **not** covered.

Issuer and verifier converge because both apply the same procedure: the
issuer canonicalizes before injecting the bundle; the verifier strips the
bundle and re-canonicalizes. The unit test
`preimage_is_invariant_under_injection` pins this round-trip, and the
e2e suite pins that a manual strip + `serde_jcs` reproduces the library
helper byte-for-byte.

## Verification

1. Verify the agent's **card** first (§8.4, out-of-band key — see the
   runtime-guarantees extension). Its verified `trustJwks` claim is your
   trust anchor for receipts.
2. Extract the bundle from the carrier's metadata (or base64url-decode
   `X-Nucleus-Receipt`).
3. `verify_receipt_bundle(&bundle, &TrustAnchor::from_jwks(jwks))`
   (Rust) or `verify_receipt_js` (browser) — checks every edge
   signature, the hash chain, and that the signed content hash matches
   the payload binding.
4. Recompute the pre-image from the payload you received (strip +
   JCS) and compare its SHA-256 against the verified `body_sha256`.
5. Check `resource` is the path you called — and, for streams, that the
   `#sse-<n>` index matches the position you observed the event at.

## Streaming semantics

Event indices count **data-bearing SSE events** in order, starting at 0.
A receipt therefore attests not only an event's bytes but **where in the
stream the server placed it** — reordering or dropping receipted events
is detectable by comparing indices against observed positions. Events
the server could not receipt (mid-stream error envelopes, carrier-less
payloads) pass through unmodified and simply carry no receipt.

## What a receipt does NOT prove

A verified receipt proves exactly: **the holder of the signing key
asserted that it served these payload bytes, for this resource, to this
verified caller** — and nobody altered that assertion.

It does **not** prove:

- that the content is *correct*, useful, or produced by any particular
  model or skill — it binds bytes, not quality;
- that the caller actually *received* the bytes (it is a server-side
  assertion, not a delivery acknowledgment);
- anything about events or responses **without** receipts — absence
  proves nothing, and a client that requires receipts must enforce
  their presence itself;
- transport security: the receipt does not bind the TLS channel,
  HTTP headers, or SSE framing;
- freshness or uniqueness, beyond what the bundle's lineage timestamps
  carry — replay detection is the verifier's policy;
- payment settlement (`payment_*` are references for the rail, not
  proof of settlement).

## Interop notes

- Generic A2A v1.0 clients see optional metadata under an unknown URI
  and may ignore it (§4.6.3); every spec-required response field is
  present and meaningful without it.
- The extension is response-side and always on; it does not require the
  per-request `A2A-Extensions` activation header.
- Injecting the bundle re-serializes the response/event JSON, so byte
  layout (key order, whitespace) may differ from an unreceipted
  response; consumers must treat JSON, not raw bytes, as the payload —
  which is what the JCS pre-image definition encodes.
