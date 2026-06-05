# nucleus-verifier-service

Public verifier-as-a-service for nucleus provenance bundles.

[![docs.rs](https://img.shields.io/docsrs/nucleus-verifier-service)](https://docs.rs/nucleus-verifier-service)

An HTTP service (axum) that verifies provenance [`Bundle`s](../nucleus-envelope),
appends verified results to a Merkle transparency log, and publishes signed tree
heads — so a third party can check a bundle and audit the log without trusting
the operator's word.

## Endpoints

| Method + path | Purpose |
|---|---|
| `POST /v1/verify` | verify a submitted bundle |
| `GET /v1/bundles/{hash}/verify` | look up a previously-verified bundle (**DB mode only**; 503 when stateless) |
| `GET /v1/log/size` | current transparency-log size |
| `GET /v1/log/sth` | signed tree head (STH) |
| `GET /v1/log/inclusion-proof` | Merkle inclusion proof for an entry |
| `GET /.well-known/jwks.json` | STH signing public key (stable `kid`) |
| `GET /v1/witness/peers` | configured witness peers |
| `GET /healthz` | liveness |
| `GET /metrics` | Prometheus exposition format (requires `--metrics`; else 503) |
| `GET /`, `GET /quickstart` | landing + quickstart pages |

## Running

```bash
nucleus-verifier-service \
  --bind 0.0.0.0:8080 \
  --db sqlite:/data/verifier.db \
  --signing-key-hex "$NUCLEUS_VERIFIER_SIGNING_KEY"
```

| Flag | Env | Effect |
|---|---|---|
| `--bind` | `NUCLEUS_VERIFIER_BIND` | bind address (default `0.0.0.0:8080`) |
| `--db` | `NUCLEUS_VERIFIER_DB` | SQLite URL/path; **presence enables persistence** + the bundle-lookup endpoint. Stateless without it. |
| `--signing-key-hex` | `NUCLEUS_VERIFIER_SIGNING_KEY` | hex Ed25519 secret for STH signing |
| `--retention-days` | — | sweep `verifications` older than N days (hourly) |

> **Production must set `--signing-key-hex`.** Without it an ephemeral key is
> generated at startup, so the `kid` changes on every restart and any client that
> cached the public key breaks. Accepted DB forms: `sqlite::memory:` (CI),
> `sqlite:/data/verifier.db`, or a bare path (treated as `sqlite:<path>`).

## Library

The binary is a thin wrapper; `build_app`, `connect_and_migrate`, `MerkleLog`,
`VerifierSigner`, and the `retention` sweeper are exposed from the crate root so
the service can be embedded or integration-tested in-process.

## License

MIT
