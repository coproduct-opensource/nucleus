# nucleus-identity

SPIFFE-based workload identity for Firecracker VMs.

[![docs.rs](https://img.shields.io/docsrs/nucleus-identity)](https://docs.rs/nucleus-identity)

Provides SPIFFE identity management for nucleus pods running in Firecracker VMs,
enabling mTLS authentication for both in-node and cross-cluster networking. It
also carries the W3C DID / WebFinger / DPoP machinery used for verifiable
cross-agent identity and signed approval bundles.

## Components

**Workload identity & mTLS**

- `identity` — SPIFFE ID types and parsing
- `session` — ephemeral session identity for AI agent conversations
- `attestation` — launch attestation for VM integrity verification
- `csr` — CSR generation using P-256 ECDSA
- `certificate` — X.509 certificate handling
- `manager` — `SecretManager` for multi-identity cert caching and rotation
- `verifier` — SPIFFE-aware mTLS verification
- `tls` — rustls client/server configuration
- `ca` — CA client trait and implementations (self-signed, SPIRE)
- `workload_api` — Workload API server for VMs
- `ifc_extension` / `oid` — IFC label encoding in X.509 extensions

**Decentralized identity (DID / discovery / proof-of-possession)**

- `did`, `did_binding`, `did_crypto`, `did_builder`, `did_resolver` — W3C DID
  documents for the `did:web` method, SPIFFE↔DID binding proofs, and resolution
- `webfinger` — WebFinger discovery (RFC 7033)
- `dpop` — OAuth2 DPoP proof-of-possession tokens (RFC 9449)
- `approval_bundle` — signed preflight approval bundles (JWS ES256)
- `cross_agent`, `wallet` — cross-agent identity and key custody

## Feature flags

| Feature | Effect |
|---|---|
| *(default)* | self-signed CA, in-memory resolver — no network deps |
| `spire` | SPIRE Workload API integration for production (`spiffe` crate) |
| `resolver` | HTTP-based `did:web` resolution (pulls in `reqwest`) |

```toml
[dependencies]
nucleus-identity = { version = "*", features = ["spire"] }
```

## Cryptography

P-256 ECDSA throughout (CSRs, JWS ES256), `rustls` + `rustls-webpki` for TLS,
`ring` for primitives, `x509-parser` for certificate parsing. IFC capability
labels from [`portcullis-core`](../portcullis-core) are embedded as custom X.509
extensions so a workload's certificate carries its information-flow class.

## License

MIT
