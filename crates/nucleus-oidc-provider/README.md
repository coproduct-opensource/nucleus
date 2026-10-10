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
- `GET /jwks.json` — the OP's verify-set. RFC 7517, holding the keys of
  the OP's ONE signing algorithm: Ed25519 OKP (RFC 8037) for the in-process
  key stores, or P-256 EC (RFC 7518 §6.2, ES256) for the keyring store
  (`--signing-key-dir`). ES256 is what cloud workload-identity federation
  and SPIFFE JWT-SVID verifiers accept.
- `POST /oauth/token` — RFC 8693 token exchange. The subject token is a
  workload-presented JWT-SVID, or a token from a bound outside issuer
  (`[[outside_issuer]]`), which is exchanged as the one SPIFFE ID its binding
  names. The response is an audience-bound access token.
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

## Running it

`docs/oidc-provider-runbook.md` is the operator's guide: choosing the key
store (§1a), custody (§1b), federation rules and outside-issuer bindings (§3),
and rotation (§2E). `deploy/` holds the federation configs of deployments
run from this tree; the Dockerfile bakes them into the image, inert unless
`NUCLEUS_OIDC_FEDERATION_CONFIG` selects one.

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
