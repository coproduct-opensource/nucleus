# nucleus-oidc-provider

The OIDC Identity Provider (OP) for the nucleus mesh.

## Role

This service is the cryptographic identity root of a nucleus deployment.
It mints JWT-SVIDs / OAuth 2.0 access tokens for nucleus pods, and
performs RFC 8693 token exchange so an externally-issued SVID (e.g.,
from a SPIRE Agent on the same node) can be traded for an
audience-bound token a downstream relying party will accept.

It is a peer to `nucleus-verifier-service`:

| Service | Role | What it signs / verifies |
|---|---|---|
| `nucleus-oidc-provider` | identity root | mints tokens; publishes JWKS |
| `nucleus-verifier-service` | provenance root | verifies bundles against caller-supplied trust anchors |

Together they form the public surface of a nucleus mesh.

## Wire surface (v1)

- `GET /.well-known/openid-configuration` — RFC 8414 discovery doc.
- `GET /jwks.json` — the OP's verify-set. RFC 7517 + RFC 8037 (Ed25519
  OKP).
- `POST /oauth/token` — RFC 8693 token exchange. Subject token is a
  workload-presented SVID; response is an audience-bound access token.
- `GET /healthz` — operator-meaningful liveness.

## Non-goals

- **No user authentication.** No browser flows, no `/authorize`
  endpoint, no consent screens. This OP issues workload identity only;
  user identity belongs to the relying parties that integrate.
- **No token storage.** Stateless mint + verify. The `JtiCache` holds
  *seen* jtis (inbound replay defense), not issued ones.
- **No vendor-specific extensions.** Per `nucleus/CLAUDE.md`, this <!-- vendor-allow: cite project guidelines file -->
  crate must remain vendor-neutral. Relying-party-specific adapters
  (which external IdPs we federate with, which token-prefix shapes we
  emit) live in sibling crates that register with the federation
  module at startup. See `docs/oidc-vendor-neutrality-audit.md`.
- **No UI.** Clients are workloads, not humans.

## Skeleton scope

The skeleton in this commit wires only `/healthz` so the crate
compiles. The eight production routes / modules land progressively
under the OIDC scoping DAG (tasks #32 through #56). The companion
`THREAT_MODEL.md` is already complete and pins the security spec for
every subsequent implementation task.

## Threat model

See `THREAT_MODEL.md` in this directory. 13 enumerated threats
(T01-T13) each map to one or more implementing tasks. Read before
changing any wire-format module.

## Cross-references

- `THREAT_MODEL.md` — security spec for v1
- `../../docs/oidc-vendor-neutrality-audit.md` — what moves from
  `nucleus-platform/nucleus-oidc-core` into this tree, and what stays
- `../../docs/wimse-aims-conformance-gap.md` — the AIMS / WIMSE /
  RFC 9068 gap analysis that drives the claim schema in `JwtIssuer`
- `../../docs/local-issuer-prod-readiness-gap.md` — gap analysis on
  the existing `LocalIssuer` (in `crates/nucleus-lineage/`); inputs
  for the production-grade `JwtIssuer` in this tree
- `../../ci/no-vendor-strings.sh` — the CI gate that scans this tree
  for vendor names / hostnames / token shapes

## License

MIT.
