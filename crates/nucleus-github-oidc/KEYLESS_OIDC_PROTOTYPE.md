# Keyless GitHub Actions OIDC → SPIFFE (honest spike)

A buildable, tested prototype that takes a **GitHub Actions OIDC JWT**, validates
it through the **real** `nucleus-github-oidc` validator (RS256 signature via
JWKS, issuer/audience/exp/nbf, repo/org allowlist, replay), and derives the
**SPIFFE caller id** — with **no long-lived secret anywhere**.

This is an *honest spike* (the zk-spike rule): a live GitHub OIDC token can
**only** be minted inside a running CI job, so it is split into three clearly
labelled parts — two are **proven locally**, one is **PENDING CI**.

---

## The flow

```
                 PHASE 1: request (CI-only)            PHASE 2: verify (real validator)
┌──────────────────────────────┐        ┌──────────────────────────────────────────────┐
│ GitHub Actions runner          │        │ nucleus-github-oidc::GitHubOidcValidator       │
│  permissions: id-token: write  │        │   .validate(token).await                       │
│  injects:                      │        │                                                │
│   ACTIONS_ID_TOKEN_REQUEST_URL │        │ 1. decode_header → alg ∈ {RS256}               │
│   ACTIONS_ID_TOKEN_REQUEST_…   │        │ 2. require kid                                 │
│            │                   │        │ 3. peek iss == token.actions.githubusercontent │
│            ▼                   │        │ 4. DiscoveryKeyResolver: GET issuer            │
│  GET ${URL}&audience=nucleus.io│  JWT   │      /.well-known/openid-configuration         │
│  Authorization: Bearer ${TOK}  │──────► │      → jwks_uri → GET JWKS (RS256 key by kid)  │
│  → JSON { "value": "<jwt>" }   │        │ 5. jsonwebtoken::decode: sig + iss + aud + exp │
└──────────────────────────────┘        │ 6. JtiCache replay check (after verify)        │
                                          │ 7. repo/org allowlist                          │
                                          │ 8. derive_spiffe_id (from VERIFIED repository  │
                                          │      claim, never from `sub`)                  │
                                          └───────────────────────┬────────────────────────┘
                                                                  ▼
        spiffe://nucleus.io/ns/github/sa/{owner}/{repo}/refs/{sanitized_ref}
        e.g. spiffe://nucleus.io/ns/github/sa/coproduct-opensource/nucleus-agent-starter/refs/refs-heads-main
```

PHASE 1 mirrors `@actions/core` `getIDToken(audience)` (actions/toolkit
`packages/core/src/oidc-utils.ts`) and the request half of
`google-github-actions/auth` / `aws-actions/configure-aws-credentials`. The
only per-vendor knob in phase 1 is the **audience** — Nucleus requests
`nucleus.io` (AWS uses `sts.amazonaws.com`, GCP uses the WIF provider name).

> **Audience pitfall.** GitHub's *default* `aud` is the repository-owner URL.
> The validator pins `aud == nucleus.io`, so the workflow MUST request that
> exact audience (`core.getIDToken("nucleus.io")` / `&audience=nucleus.io`) or
> validation fails on `aud`. Covered by `wrong_audience_is_rejected`.

> **Never authorize on `sub`.** `derive_spiffe_id` uses the verified
> `repository` / `repository_owner` claims and enforces
> `repository_owner == owner` (`OrgMismatch`). The `sub` string is
> attacker-influenceable formatting and is never parsed for identity.

---

## What's in this spike (file paths)

| Part | File | Status |
|------|------|--------|
| (a) Buildable prototype calling the **real** validate API | `examples/keyless_oidc_prototype.rs` | **Builds + runs** (exits non-zero "PENDING CI" outside a CI job; never fabricates a token) |
| (b1) Synthetic unit tests (StaticKeyResolver) | `src/validator.rs` `mod tests` | **14 PASS** |
| (b2) Synthetic E2E test (real `DiscoveryKeyResolver` vs a localhost mock issuer) | `tests/synthetic_discovery_e2e.rs` | **2 PASS** |
| (b) Synthetic JWKS fixture | `testdata/synthetic_jwks.json` | labelled "NOT a live GitHub JWKS" |
| (c) Live workflow (genuine E2E) | `.github/workflows/oidc-keyless-prototype.yml` | **PENDING CI** |
| (d) This README | `crates/nucleus-github-oidc/KEYLESS_OIDC_PROTOTYPE.md` | — |

### Synthetic vs. live — read this

- **Synthetic (proven here).** `tests/synthetic_discovery_e2e.rs` mints a
  GitHub-*shaped* RS256 token with the checked-in workspace test key
  (`crates/nucleus-fly-oidc/testdata/jwt_test_priv.pem`, `kid=test-kid`) and
  stands up a localhost HTTP server serving a real OIDC discovery doc +
  `testdata/synthetic_jwks.json` (the `n`/`e` of the matching test public key).
  It then runs the **real** `DiscoveryKeyResolver` discovery → JWKS-fetch →
  `DecodingKey` → RS256-verify → claims → replay → SPIFFE path end to end. These
  tokens are **clearly labelled synthetic** and can **never** verify against
  GitHub's real JWKS.
- **Live (PENDING CI).** Only `.github/workflows/oidc-keyless-prototype.yml`,
  running on a real runner with `id-token: write`, exercises a **real** GitHub
  token against **GitHub's real JWKS**. Its result is **PENDING CI** until the
  Actions run is green — it is **not** claimed as passing here.

---

## The RFC 8693 exchange step (next leg)

`nucleus-github-oidc` is the **verify half**. The SPIFFE id it derives is the
*subject* a `nucleus-oidc-provider` token-exchange would mint an audience-bound
token for (RFC 8693, the same role AWS STS / GCP STS / Fulcio play).

> **Cross-algorithm reality (not a hand-wave).** GitHub tokens are **RS256**,
> but `nucleus-oidc-provider`'s `/oauth/token` accepts only **EdDSA**
> `subject_token`s (its `T04` algorithm pin). So a raw GitHub token is **not**
> directly a `subject_token`. The composition is two hops:
>
> ```
> GitHub RS256 token
>   → nucleus-github-oidc.validate  → CallSpiffeId (verified)
>   → nucleus-oidc-provider mints an EdDSA JWT-SVID with sub = that SPIFFE id
>   → THAT EdDSA SVID is the subject_token for the exchange below
> ```

The exact exchange request (`POST /oauth/token`,
`application/x-www-form-urlencoded`) against `nucleus-oidc-provider`:

```
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token=<EdDSA JWT-SVID whose sub is the derived SPIFFE id>
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt
&audience=https%3A%2F%2Frp.example%2Fapi
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
```

Success response (RFC 8693 §2.2.1):

```json
{
  "access_token": "<compact JWS>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Issued lifetime is `min(subject_exp - now, 3600, federation rule max_lifetime)`.
A matching federation rule is required, e.g.:

```toml
[[rule]]
id = "github-to-nucleus"
subject_prefix = "spiffe://nucleus.io/ns/github/sa/*"
audience = "https://rp.example/api"
allowed_grants = ["urn:ietf:params:oauth:grant-type:token-exchange"]
max_token_lifetime_secs = 3600
```

**Honest status of this leg.** This prototype wires and proves PHASE 1 + PHASE
2 (request + validate + SPIFFE derivation). The RFC 8693 exchange is documented
above with the exact request; minting the EdDSA SVID and calling
`nucleus-oidc-provider` is **not yet wired** in this spike (the provider lives
in the public `nucleus` repo and is not a dependency of this crate) — it is the
clearly-labelled next leg, not a claim of done.

---

## Exact repro

```bash
# (b) Offline proof — the REAL validation path, synthetic tokens. EXPECT PASS.
cargo test -p nucleus-github-oidc
#   14 unit + 2 synthetic-e2e + 1 doctest, all pass

# (a) Run the prototype locally. EXPECT non-zero exit + "PENDING CI" message
#     (no live token can be minted outside CI; it does NOT fabricate one).
cargo run -p nucleus-github-oidc --example keyless_oidc_prototype

# Default workspace build stays green (networked example deps are dev-only).
cargo build --workspace

# (c) Genuine end-to-end proof: push to main / dispatch
#     .github/workflows/oidc-keyless-prototype.yml — result is PENDING CI.
```
