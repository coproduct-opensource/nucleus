# nucleus-verify-commerce

Seller-side **verify → serve → receipt** middleware for verified agent commerce
on x402 / A2A.

[![docs.rs](https://img.shields.io/docsrs/nucleus-verify-commerce)](https://docs.rs/nucleus-verify-commerce)

> **Status: scaffold.** The orchestration + in-memory implementations are real
> and tested; the production implementations that wire the existing nucleus
> crates are honest `NotWired` skeletons. See
> [`docs/rfcs/verified-agent-commerce-quickstart.md`](../../docs/rfcs/verified-agent-commerce-quickstart.md).

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
never reaches the paid work. The receipt binds the verified caller + payment
reference + a hash of the delivered bytes, so the buyer can verify-then-settle
and the seller has a dispute-defence artifact.

## Usage

```rust
use nucleus_verify_commerce::{
    serve_verified, AllowlistVerifier, HashingReceiptIssuer, CommerceRequest,
    CallerClaims, PaymentProof,
};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let verifier = AllowlistVerifier::new().allow("buyer-agent", "spiffe://nucleus.io/buyer");
let issuer = HashingReceiptIssuer;

let req = CommerceRequest {
    resource: "/v1/summarize".into(),
    caller: CallerClaims { agent_id: "buyer-agent".into(), credential: "…".into() },
    payment: PaymentProof { scheme: "x402".into(), reference: "0xpay123".into() },
};

let (body, receipt) = serve_verified(&req, &verifier, &issuer, |caller, r| {
    let r = r.resource.clone();
    async move { Ok(format!("served {r}").into_bytes()) }
}).await?;
# let _ = (body, receipt);
# Ok(())
# }
```

## Implementations

| Trait | In-memory (real, tested) | Production (skeleton) |
|---|---|---|
| `CallerVerifier` | `AllowlistVerifier` | `AgentCardVerifier` → `nucleus-agent-card` + `nucleus-*-oidc` |
| `ReceiptIssuer` | `HashingReceiptIssuer` | `EnvelopeReceiptIssuer` → `nucleus-envelope` + `nucleus-verifier-service` |

The production skeletons return `CommerceError::NotWired` rather than faking a
result. Wiring them to the already-shipped crates is the next step behind the RFC.

## License

MIT
