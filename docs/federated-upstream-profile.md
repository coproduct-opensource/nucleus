# Federated upstream profile: keyless calls between nucleus pods and external services (v1)

**Profile URI:** `https://coproduct.one/federation/upstream/v1`
**Status:** draft v1 (2026-09-24). The URI is versioned — a breaking change gets a new URI.
**Decision record:** [ADR 0010](adr/0010-a-credential-minted-per-exchange-never-stored.md)
**Implementation:** phased; see ADR 0010 §Phases. Until P3 (outbound) and P5 (inbound) land,
this document is a specification, not a description of running code.

This profile is the document handed to a service that wants to be called by nucleus pods
without a stored key, or to call into nucleus with its own OIDC token. It names no vendor.
A service implements one or both roles and is then configured by the nucleus operator; no
nucleus code changes per service.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
**RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Roles

| role | who | direction | what they implement |
|---|---|---|---|
| **Upstream** | a resource a nucleus pod calls (for example a model-serving API) | nucleus → service | a token endpoint that accepts a nucleus-signed assertion and returns a short-lived access token |
| **Caller issuer** | an external runtime that creates and calls nucleus pods | service → nucleus | an OIDC issuer whose tokens nucleus validates and exchanges for a node-rooted delegation |

## The flow

```
Outbound (Upstream role)

  guest ── POST /v1/egress/<name>/… ──► nucleus node (host)
                                          │ 1. PDP approves the call
                                          │ 2. mint ES256 assertion (iss = node issuer,
                                          │    aud = registered audience, fresh jti)
                                          ▼
                                   upstream token endpoint
                                          │ 3. verify signature, iss, aud, claims, jti
                                          │ 4. return access_token + expires_in
                                          ▼
                                   nucleus node ── <header>: <prefix><access_token> ──► upstream API
  guest ◄── response body (never the token or the assertion) ──┘

Inbound (Caller-issuer role)

  external runtime ── POST /v1/federation/exchange ──► nucleus federation listener
     (Authorization: Bearer <its OIDC token>, CSR)       │ validate against a [[caller]] binding
                                                         ▼
     ◄── short-lived X.509 SVID + node-rooted delegation certificate
  external runtime ── mTLS POST /v1/pods (x-nucleus-delegation-cert) ──► nucleus node
```

## 1. The assertion nucleus sends (Upstream role input)

A compact JWS (RFC 7515) with this header and claim set. Every claim below is present on
every assertion.

**Header**

| field | value | example |
|---|---|---|
| `alg` | always `ES256` | `ES256` |
| `typ` | always `JWT` | `JWT` |
| `kid` | RFC 7638 JWK thumbprint of the signing key | `0Yp3v2Qm6xk1n8Hc4tQ9sW7bLr5eJdFa2uGiKoMzXyE` |

**Claims**

| claim | type | meaning | example |
|---|---|---|---|
| `iss` | string (HTTPS URL) | the node's federation issuer | `https://federation.nodes.example.com` |
| `sub` | string (SPIFFE ID) | the calling pod, as observed by the host. Opaque and per-pod; do not match on it | `spiffe://nodes.example.com/pod/4f1c2a9e` |
| `aud` | string | the audience the operator registered for this upstream; exactly one value | `https://auth.model.example.com` |
| `iat` | NumericDate | issue time | `1790208000` |
| `exp` | NumericDate | expiry; `exp − iat` is 300 by default and never more than 3600 | `1790208300` |
| `jti` | string | 128 random bits, base64url, unique per assertion | `r4Jq0bVt8xN2mE6kPz3wAg` |
| `nucleus_tenant` | string (DNS name) | the tenant: trust domain of the pod certificate's root identity | `tenant-a.example.com` |
| `nucleus_upstream` | string | the operator's name for this upstream | `model-api` |
| `nucleus_root` | string (SPIFFE ID) | root identity of the pod's delegation-certificate chain | `spiffe://tenant-a.example.com/ns/ci/sa/release` |
| `nucleus_chain` | string (64 lowercase hex) | SHA-256 fingerprint of the pod's delegation certificate | `9f2b…c41d` |

The `nucleus_*` claims are top-level strings on purpose, so that an upstream's ordinary
claim-matching rules can reach them. Nucleus does not send `act`, `scope`, or `nbf`.

The issuer's JWKS contains only `{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig"}` keys.
Nucleus publishes the next key before signing with it, for at least the upstream's JWKS
cache lifetime plus the maximum assertion lifetime.

## 2. Upstream role

### 2.1 Token endpoint

1. The Upstream **MUST** expose an HTTPS token endpoint implementing at least one of:
   - **RFC 8693 token exchange**: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
     `subject_token=<assertion>`,
     `subject_token_type=urn:ietf:params:oauth:token-type:jwt`;
   - **RFC 7523 JWT bearer**: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
     `assertion=<assertion>`.
2. The request body **MUST** be accepted as `application/x-www-form-urlencoded`, or as
   `application/json` with the same parameter names as top-level string members. The
   Upstream states which.
3. The Upstream **MAY** require additional opaque string parameters (an account, project,
   pool, or policy identifier). Nucleus sends them verbatim from operator configuration and
   does not interpret them.
4. The Upstream **MAY** accept `audience`, `scope`, `resource`, and `requested_token_type`.
   Nucleus sends them only when the operator configured them.
5. The Upstream **MUST NOT** require client authentication beyond the assertion itself (no
   client secret). The assertion is the credential; a stored client secret would defeat the
   purpose of this profile.

### 2.2 Validating the assertion

6. The Upstream **MUST** accept `ES256`. It **SHOULD** also accept `RS256` and `PS256` so
   that other issuers can use it. It is **not required** to accept `EdDSA`, and nucleus never
   sends it on this path.
7. The Upstream **MUST** take the algorithm set from its own registration of the issuer, not
   from the token header; **MUST** reject `none` and every `HS*` algorithm; and **MUST**
   check that the selected JWK's `kty` and `crv` match the header `alg`.
8. The Upstream **MUST** obtain the issuer's keys by at least one of:
   - OIDC discovery at `<iss>/.well-known/openid-configuration`, using its `jwks_uri`;
   - an explicit JWKS URL;
   - an inline JWKS stored with the registration.

   It **SHOULD** support discovery or an explicit URL, because inline registration must be
   re-done by hand on every rotation.
9. The Upstream **MUST** select the key by the header `kid` and **MUST** reject an assertion
   with no `kid`. It **SHOULD** re-fetch the JWKS, rate-limited, when it sees an unknown
   `kid`.
10. The Upstream **MUST** match `iss` exactly (byte-for-byte) and `aud` exactly against the
    registration.
11. The Upstream **MUST** support rules that require exact values of top-level string claims,
    and **MUST** support at least `nucleus_upstream` and `nucleus_tenant`. A registration for
    a nucleus issuer **SHOULD** match `iss`, `aud`, and `nucleus_upstream` together; matching
    `iss` alone matches every pod on the node.
12. The Upstream **MUST** require `exp`, `iat`, and `kid`, and **MUST** reject an expired
    assertion.
13. The Upstream **MUST** treat `jti` as single-use for at least the assertion's lifetime.
14. The Upstream **MUST** tolerate at least 30 seconds of clock skew and **SHOULD NOT**
    tolerate more than 300.
15. The Upstream **MUST NOT** require `typ: at+jwt`. The assertion is not an access token.

### 2.3 Response

16. A successful response **MUST** be RFC 6749 §5.1 JSON: `access_token`, `token_type`
    (`Bearer`), and **`expires_in`, which this profile makes REQUIRED**. (Nucleus uses a
    token with no `expires_in` exactly once and never caches it.)
17. The Upstream **MUST** state a bound `B`, and the minted token **MUST NOT** remain valid
    later than the assertion's `exp` plus `B`. `B` **SHOULD** be at most 3600 seconds. A
    token whose lifetime ignores the assertion's lifetime turns a five-minute assertion into
    a long-lived credential.
18. The minted token **MUST** be usable as `Authorization: Bearer <token>` or in another
    single request header the Upstream documents.
19. The Upstream **SHOULD** offer a scope limited to data-plane calls (for a model-serving
    Upstream, inference only), so that a nucleus registration never carries administrative
    authority such as key management, membership, or billing.

### 2.4 Refusals

20. A refusal **MUST** be RFC 6749 §5.2 JSON and **MUST NOT** reveal which check failed,
    which scopes or claims would have been accepted, or whether the issuer is registered at
    all. `invalid_grant` for every assertion failure is sufficient. (This is ADR 0004's
    rule: a refusal never tells the caller what it could have had.) Nucleus never forwards
    a refusal body to the guest, but the Upstream's logs and other clients may see it.
21. An API call made with an expired or revoked token **MUST** fail with `401`. Nucleus
    evicts its cached token on `401` and does **not** retry the call automatically.
22. The Upstream **SHOULD NOT** echo the `Authorization` header, or any credential, in a
    response body. A body is returned to the guest.

### 2.5 Wire shapes already in the field

Three large providers already accept federated assertions at a token endpoint, and their
shapes differ only in ways the nucleus registry's `grant`, `encoding`, and `params` fields
absorb. How closely each meets the rest of §2 (the lifetime bound in particular) is a
property of that provider, checked per provider and recorded outside this repository:

- one uses **RFC 7523** with a **JSON** body and three opaque identifiers as extra
  parameters;
- the others use **RFC 8693** with **form** bodies and one opaque policy identifier.

All of them accept RSA or ECDSA assertions and reject EdDSA, which is why the nucleus
federation issuer is ES256.

## 3. Caller-issuer role

An external runtime that holds tokens from its own OIDC issuer can use them to obtain a
node-rooted delegation from nucleus, then create and call pods within the ceiling the
operator bound to it.

1. The issuer **MUST** serve OIDC discovery at `<iss>/.well-known/openid-configuration` over
   HTTPS, and the document's `issuer` member **MUST** equal `iss` byte-for-byte. Nucleus
   refuses a discovery document whose `issuer` differs, even by a trailing slash.
   (A binding may instead configure a JWKS URL or an inline JWKS, in which case discovery
   is not fetched.)
2. The issuer **MUST** sign every token for a given binding with a **single** algorithm,
   which the operator pins in the binding. Nucleus supports `ES256`, `RS256`, `PS256`, and
   `EdDSA`; `none` and `HS*` are never accepted.
3. Every token **MUST** carry `kid` in its header, naming a key in the issuer's JWKS.
4. `aud` **MUST** equal the binding's audience exactly.
5. `exp` and `iat` are **REQUIRED**, and `exp − iat` **MUST NOT** exceed the binding's
   `max_lifetime`.
6. `sub` **MUST** be stable for the principal the binding maps — or the binding names
   another stable top-level string claim that nucleus maps instead. A `sub` that changes
   per invocation still works for authentication, but the principal and the budget are the
   binding's, never the `sub`'s.
7. `jti` is **OPTIONAL**. Nucleus keys replay on `sha256(compact token)` until `exp`, so a
   token is accepted at most once whether or not it carries a `jti`.
8. Any claim the binding lists in `required_claims` **MUST** be present with the configured
   value.

### 3.1 What nucleus does with it (informative)

- The token is presented once, at `POST /v1/federation/exchange` on a server-auth-only TLS
  listener, as `Authorization: Bearer <token>` together with a PKCS#10 CSR whose SAN is the
  mapped principal.
- The principal is `spiffe://<binding.trust_domain>/ns/<label>/sa/<sanitized sub>`.
- The response is a short-lived X.509 SVID for that principal (lifetime at most the token's
  remaining lifetime and the binding's `svid_ttl`), plus a node-rooted delegation
  certificate whose ceiling is the binding's and whose `provenance` is `sha256(token)`.
- The caller then uses mTLS `POST /v1/pods` with that certificate in
  `x-nucleus-delegation-cert`. Pods are visible only to callers in the same trust domain;
  every other caller sees `404`. The budget is shared by every exchange under the binding.

Field names of the exchange request and response are fixed when P5 lands; the token
requirements above are not expected to change.

## 4. Operator configuration

These are nucleus-side examples with placeholder values. Key names are illustrative until
P0, P3, and P5 land.

### 4.1 An Upstream entry (`--upstreams upstreams.toml`)

```toml
[[upstream]]
name         = "model-api"
base_url     = "https://api.model.example.com"
header       = "authorization"
value_prefix = "Bearer "

[upstream.credential.federated]
token_endpoint     = "https://auth.model.example.com/oauth/token"
grant              = "token-exchange"   # or "jwt-bearer"
encoding           = "form"             # or "json"
audience           = "https://auth.model.example.com"
scope              = "inference"        # optional; sent only if set
request_audience   = "https://api.model.example.com"  # optional; RFC 8693 `audience` body param
assertion_ttl_secs = 300                # default 300, cap 3600

[upstream.credential.federated.params]  # opaque, sent verbatim
policy_id = "example-policy-0001"

# The static form, still available, now chosen by the operator:
[[upstream]]
name         = "search-api"
base_url     = "https://search.example.com"
header       = "x-api-key"
value_prefix = ""

[upstream.credential.env]
var = "SEARCH_API_TOKEN"
```

A pod spec selects an upstream by `name`. A spec whose `credentialed_egress` entry differs
from the registry entry in any field is refused at admission.

The matching registration on the Upstream's side, stated generically:

```text
issuer:   https://federation.nodes.example.com   (keys: discovery | JWKS URL | inline)
audience: https://auth.model.example.com
require:  nucleus_upstream == "model-api"
          nucleus_tenant   == "tenant-a.example.com"   (when one account serves one tenant)
grants:   an inference-only principal
```

### 4.2 A caller binding (`[[caller]]`)

```toml
[[caller]]
label            = "example-runtime"
issuer           = "https://oidc.runtime.example.com/org/example-org-0001"
audience         = "https://federation.nodes.example.com"
algs             = ["ES256"]
jwks             = { discovery = true }          # or { uri = "…" } or { inline = "…" }
max_lifetime_secs = 900
trust_domain     = "runtime.example.com"
required_claims  = { org = "example-org-0001" }
ceiling          = { profile = "codegen" }
upstreams        = ["model-api"]
svid_ttl_secs    = 600
```

## 5. For a runtime that already issues tokens but accepts only static keys

A runtime with its own OIDC issuer for the calls it makes, and static keys for calls into
it, is already most of the way there.

- **It already satisfies the Caller-issuer role** for calling into nucleus, provided its
  discovery document's `issuer` matches `iss` exactly, it signs with one algorithm and a
  `kid`, and its `aud` and lifetime fit a binding. A missing `jti` is fine.
- **To become a keyless Upstream**, it adds two things and changes nothing else:
  1. **one token endpoint** implementing §2.1 (RFC 8693 or RFC 7523, either encoding);
  2. **a rule store** mapping `(iss, aud, required top-level claims)` to one of its own
     principals — the same principal a static key maps to today, ideally narrowed to a
     data-plane scope.

  Its existing API keeps its existing authorization; the minted token is simply another way
  to authenticate as that principal. Its issuer, its signing keys, and its API are unchanged.
- **Nothing in nucleus changes.** The operator adds an `[[upstream]]` entry naming the new
  token endpoint and, if the runtime also calls in, a `[[caller]]` binding.

## 6. Conformance checklist

### Upstream

- [ ] Token endpoint over HTTPS: RFC 8693 (`subject_token_type=urn:ietf:params:oauth:token-type:jwt`) or RFC 7523
- [ ] Form or JSON body (stated); opaque extra parameters accepted
- [ ] No client secret required
- [ ] ES256 accepted; algorithm set from the registration; `none`/`HS*` refused; `kty`/`crv` checked against `alg`
- [ ] Keys by discovery, JWKS URL, or inline; selected by `kid`; missing `kid` refused
- [ ] Exact `iss`, exact `aud`
- [ ] Top-level string-claim rules, including `nucleus_upstream` and `nucleus_tenant`
- [ ] `exp`, `iat` required; `jti` single-use; skew tolerance ≥ 30 s
- [ ] `typ: at+jwt` not required
- [ ] RFC 6749 §5.1 response with `expires_in`
- [ ] Stated bound `B`; token never valid past assertion `exp + B`
- [ ] Refusals are RFC 6749 §5.2 and reveal neither the failed check nor the available scopes
- [ ] `401` on an expired or revoked token
- [ ] A data-plane-only scope offered (SHOULD)
- [ ] No credential echoed in response bodies (SHOULD)

### Caller issuer

- [ ] Discovery at `<iss>/.well-known/openid-configuration` with `issuer` equal to `iss` byte-for-byte (or a configured JWKS URL / inline JWKS)
- [ ] One signing algorithm per binding, from `ES256`, `RS256`, `PS256`, `EdDSA`
- [ ] `kid` in every header
- [ ] Exact `aud` per binding
- [ ] `exp` and `iat` present; `exp − iat` ≤ the binding's maximum
- [ ] Stable `sub`, or a stable claim the binding maps
- [ ] `jti` optional
