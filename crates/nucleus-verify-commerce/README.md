# nucleus-verify-commerce

Seller-side **verify → serve → receipt** middleware for verified agent commerce
on x402 / A2A.

[![docs.rs](https://img.shields.io/docsrs/nucleus-verify-commerce)](https://docs.rs/nucleus-verify-commerce)

See [`docs/rfcs/verified-agent-commerce-quickstart.md`](../../docs/rfcs/verified-agent-commerce-quickstart.md).

## Why

The agent-payments rail (x402 / A2A / AP2) is solved and commoditized. The open
gap is **trust**: a seller can't verify a buyer-agent it didn't build, and after
serving has no portable proof of *what was delivered for what payment*. This
crate is the thin seller-side layer that closes that gap around an existing paid
endpoint — without touching the payment rail.

## Flow

```text
request ─▶ verify caller ─▶ serve paid work ─▶ issue receipt ─▶ (body, receipt)
            CallerVerifier      your handler        ReceiptIssuer
```

The handler runs **only after** verification succeeds, so an unverified caller
never reaches the paid work. The receipt binds the verified caller + payment +
delivered-bytes hash, so the buyer can verify-then-settle and the seller has a
dispute-defence artifact.

## Implementations

| Trait | In-memory (dev / minimal) | Production |
|---|---|---|
| `CallerVerifier` | `AllowlistVerifier` | **`AgentCardVerifier`** — verifies a signed [Agent Card](../nucleus-agent-card) against an out-of-band-resolved key |
| `ReceiptIssuer` | `HashingReceiptIssuer` | **`EnvelopeReceiptIssuer`** — emits a signed [`nucleus-envelope`](../nucleus-envelope) provenance bundle |

All four are real and tested. Verify a receipt bundle with
`verify_receipt_bundle` (or the public verifier / browser `@coproduct/verify`).

## The IFC gate (`serve_verified_ifc`)

`serve_verified_ifc` adds an **information-flow-control gate** strictly between
caller verification and the paid handler — making a paid action *contingent on an
information-flow decision*. The caller hands a `FlowDeclaration` of the inputs the
handler will be exposed to; the gate runs nucleus's lethal-trifecta lattice
([`nucleus-ifc`](../nucleus-ifc)) over them, modelling the paid action as an
outbound sink:

- untrusted content reaching the action (e.g. `WebContent`) → **deny** (integrity);
- `Secret` data reaching the response → **deny** (confidentiality);
- internal data to the authenticated buyer → allowed (set `.public_sink()` to
  forbid that too).

On **deny** the handler is **never invoked** and you get
`CommerceError::IfcDenied { verdict }`. On **allow**, the `IfcVerdict` is folded
into the receipt's **signed content hash** (not just the payload), so
`verify_receipt_bundle` re-derives and checks it — tampering the recorded verdict
breaks verification.

```rust,ignore
use nucleus_verify_commerce::{serve_verified_ifc, FlowDeclaration, DeclaredInput};

let flow = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]);
let (body, receipt) = serve_verified_ifc(&req, &flow, &verifier, &issuer, handler).await?;
// A web-content input would have returned CommerceError::IfcDenied before the handler ran.
```

**Honesty boundary:** this enforces the **model-level** IFC decision over the
inputs the caller **declares**. It is not an end-to-end proof that exfiltration
cannot happen — the limiting factor is **coverage** (an undeclared input is one
the lattice never sees), and the decision is **per-call** (no cross-call taint
ratchet). The verdict carries the declared input set verbatim so a verifier can
judge coverage rather than trust a bare "allow".

## Usage

```rust
use nucleus_verify_commerce::{
    serve_verified, AllowlistVerifier, HashingReceiptIssuer, CommerceRequest,
    CallerClaims, PaymentProof,
};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let verifier = AllowlistVerifier::new().allow("buyer-agent", "spiffe://nucleus.io/buyer");
let issuer = HashingReceiptIssuer;

let req = CommerceRequest::new(
    "/v1/summarize",
    CallerClaims { agent_id: "buyer-agent".into(), credential: "…".into() },
    PaymentProof { scheme: "x402".into(), reference: "0xpay123".into() },
);

let (body, receipt) = serve_verified(&req, &verifier, &issuer, |caller, r| {
    let r = r.resource.clone();
    async move { Ok(format!("served {r}").into_bytes()) }
}).await?;
# let _ = (body, receipt);
# Ok(())
# }
```

Full end-to-end (signed card → verify → serve → signed receipt → independent
verification):

```bash
cargo run -p nucleus-verify-commerce --example quickstart
```

## What is cryptographically bound

`nucleus_lineage::canonical_edge_bytes` signs a lineage edge's `child`, `kind`,
`parents`, **`content_hash_hex`**, `ts`, and `prev_hash` — but **not** the edge's
free-form `attrs` nor the bundle's `payload`. So `EnvelopeReceiptIssuer` folds
the whole commerce binding (resource + caller + payment + body hash) into the
delivery edge's **content hash**, which is signed. `verify_receipt_bundle`
re-derives the binding from the bundle's payload and checks it equals that signed
content hash — so tampering any field (caller, payment, resource, body) is
detected. (Putting the binding only in the payload would be a false guarantee.)

## x402 transport

`x402::parse_payment_header` decodes a base64 `X-PAYMENT` header into a
`PaymentProof`. Exact field names track the x402 spec version, so it is tolerant
and documented; a deployment can always construct `PaymentProof` directly.

## License

MIT
