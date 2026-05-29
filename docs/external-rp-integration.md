# External RP Integration

Pattern for federating `nucleus-oidc-provider` with an external Relying Party (RP) that accepts SPIFFE/OIDC JWT tokens — vendor-neutral integration guide.

This document validates that the public `nucleus-oidc-provider` (the OP shipped in this repo) exposes everything an external RP needs to federate without requiring vendor-specific code in the public nucleus tree. Vendor-specific adapters (the per-RP wire-up + secret extraction) live in downstream closed-source orchestrators per the project's vendor-neutrality discipline (see `nucleus/CLAUDE.md`).

## Flow

```
nucleus pod  ──①── POST /oauth/token  ──→  nucleus-oidc-provider
                  (subject_token=JWT-SVID,
                   audience=https://rp.vendor.example/)
                                              │
                                              ②
                                              ▼
                                   verify subject_token sig via
                                   SpireBundleProvider
                                              │
                                              ③ federation rule check
                                              ▼
                                   mint access_token bound to
                                   audience=https://rp.vendor.example/
                                              │
                                              ④
                  ◄────────────────────────────
                  (RFC 8693 response: access_token=<JWS>)

nucleus pod  ──⑤── POST <RP's WIF endpoint> ──→  External RP
                  (access_token, grant_type=jwt-bearer)
                                              │
                                              ⑥ fetch /jwks.json from
                                              ▼  configured nucleus-oidc-provider
                                                 issuer URL — discovery mode
                                                 OR inline JWKS registration
                                              │
                                              ⑦
                                              ▼
                                   verify sig against nucleus-oidc-provider's
                                   public Ed25519 key, check iss/iat/exp/aud,
                                   match against RP's federation rule
                                              │
                                              ⑧
                  ◄────────────────────────────
                  (vendor access token, e.g. session credential)
```

## What the OP exposes (zero gaps verified)

The public `nucleus-oidc-provider` ships every wire surface an external RP needs:

| Requirement | Endpoint / Mechanism | Crate location |
|---|---|---|
| OIDC discovery — discovery mode federation | `GET /.well-known/openid-configuration` | `src/discovery.rs` |
| JWKS — for inline-mode RPs + as `jwks_uri` target | `GET /jwks.json` with `Cache-Control: public, max-age=300` | `src/jwks.rs` |
| Issued tokens carry `iss` | Set from `state.issuer_url` (config: `NUCLEUS_OIDC_ISSUER_URL`) | `src/issuer.rs:336` |
| Issued tokens carry `iat` | Unix-second from `SystemTime::now()` at mint | `src/issuer.rs:338` |
| Issued tokens carry `exp` | `iat + lifetime` (capped 1 h) | `src/issuer.rs:339` |
| Issued tokens carry `aud` | From `MintRequest::audience` (RP target URL) | `src/issuer.rs:331` |
| Issued tokens carry SPIFFE-ID `sub` | From `MintRequest::subject` | `src/issuer.rs:330` |
| `typ: at+jwt` header per RFC 9068 | Hard-coded in JWS header build | `src/issuer.rs:354` |
| EdDSA-only signing alg | Hard-coded; CI-gated by `alg-pin-check.sh` | `src/issuer.rs:354` + `ci/alg-pin-check.sh` |
| Federation rule per (subject, audience) pair | TOML-loaded `FederationRegistry` | `src/federation.rs` |
| Replay defense over `jti` | Bounded `JtiCache` | `src/jti_cache.rs` (re-export from `nucleus-oidc-core`) |

## What lives in the downstream orchestrator (NOT in nucleus)

Per the project's open-source/closed-source split:

- The per-RP **client SDK adapter** that calls into the RP's WIF endpoint
- The per-RP **credential extraction / storage** mechanics (keychain, KMS, session secret rotation)
- The per-RP **cost models** and rate-limit handling
- Any vendor-specific token-prefix recognition / unwrapping

These all map to existing patterns in the orchestrator's `*ExecutorAdapter` layer — they consume the standard wire shapes the OP emits and do not require modifying the OP itself.

## Operator wire-up checklist

A downstream operator integrating with any external RP follows these steps. All actions are **operator configuration only** — no public-nucleus code changes required.

1. **Register the OP's issuer URL with the external RP.**
   Most modern RPs accept either discovery mode (point them at the OP's `/.well-known/openid-configuration`) or inline mode (copy the OP's `/jwks.json` into the RP's federation config).

2. **Configure the RP's federation rule.**
   Tell the RP which `(iss, sub, aud)` triples it should accept. The OP's `iss` is the configured issuer URL; `sub` is a SPIFFE ID matching `spiffe://<trust-domain>/...`; `aud` is the RP's WIF endpoint URL.

3. **Add a nucleus federation rule on the OP side.**
   Add to `oidc-federation.toml`:
   ```toml
   [[rule]]
   id = "<stable-identifier>"
   subject_prefix = "spiffe://<trust-domain>/ns/<env>/*"
   audience = "<RP's WIF audience URL>"
   allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
   max_token_lifetime_secs = 3600
   ```
   See `src/federation.rs` for schema + validation. Default-deny applies until the rule lands.

4. **On the pod side, request an access token bound to the RP's audience.**
   Pod's SPIRE Agent → JWT-SVID → POST to OP's `/oauth/token` with `audience=<RP's WIF endpoint URL>` → receive an audience-bound access token signed by the OP.

5. **Pod presents the access token to the RP's WIF endpoint.**
   Wire shape depends on the RP. Common patterns:
   - RFC 7523 `jwt-bearer` grant → POST `{grant_type, assertion=<jwt>}` to RP's `/oauth/token`
   - AWS STS `AssumeRoleWithWebIdentity`
   - GCP STS `https://sts.googleapis.com/v1/token`
   - Vault JWT auth method (`/v1/auth/jwt/login`)

6. **RP verifies the token signature against the OP's `/jwks.json`.**
   The OP's JWKS endpoint serves `Cache-Control: max-age=300` so RPs poll at most every 5 min during steady state. Key rotations propagate within one poll cycle; new keys land in `/jwks.json` before they're used to sign tokens (grace window).

## Audit trail validation

Per `project_spiffe_wif_anthropic` memory: the value of this integration pattern is that the pod's SPIFFE ID (the OP's `sub` claim) appears verbatim in the external RP's audit log via the standard JWT `sub` field. This canonicalizes the cross-system principal — eliminating the non-canonical iso of secret-mediated translation paths.

Verify in production:
- Pod's SPIFFE ID matches `OP-issued-token.sub`
- RP's audit log records `sub` from the JWT payload
- Cross-correlation of SPIFFE ID + RP audit-log entries works without a translation layer

## Status: zero gaps

✅ The public `nucleus-oidc-provider` exposes every wire surface an external SPIFFE/OIDC RP needs.
✅ All required JWT claims (`iss`, `iat`, `exp`, `aud`, `sub`) are emitted by `JwtIssuer::mint`.
✅ The discovery doc + JWKS endpoint enable both federation modes (discovery + inline).
✅ The federation rule schema accommodates any per-RP audience constraint.

No code changes required in the public nucleus repo to enable any specific external RP integration. Vendor-specific work lives in the downstream orchestrator per `nucleus/CLAUDE.md`.

## Cross-references

- `THREAT_MODEL.md` — T01 (key compromise), T03 (cross-audience replay), T05 (federation misconfiguration)
- `docs/oidc-provider-runbook.md` §3 — Federation rule deployment
- `docs/oidc-vendor-neutrality-audit.md` — what stays vendor-neutral vs platform-specific
- `crates/nucleus-oidc-provider/tests/aims_interop.rs` — RFC 8693 / 9068 / 7638 / 7517 KAT vectors
