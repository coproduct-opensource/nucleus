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
   which the operator pins in the binding. Nucleus accepts `ES256`, `ES384`, `RS256`,
   `RS384`, `RS512`, `PS256`, `PS384`, and `PS512`; `none`, `HS*`, and `EdDSA` are not
   accepted. RSA keys **MUST** be at least 2048 bits, and a key's `kty`/`crv` **MUST** match
   the header `alg`.
3. Every token **MUST** carry `kid` in its header, naming a key in the issuer's JWKS.
4. `aud` **MUST** equal the binding's audience exactly.
5. `exp` and `iat` are **REQUIRED**, and `exp − iat` **MUST NOT** exceed the binding's
   `max_lifetime`.
6. `sub` **MUST** be present and non-empty. Nucleus maps `sub` into the principal, so a
   `sub` that is stable per principal gives stable pod ownership. A `sub` that changes per
   invocation still authenticates, but each value is a distinct principal. The budget is
   the binding's (one per binding trust domain), never the `sub`'s. The escaped `sub` must
   fit in 200 bytes.
7. `jti` is **OPTIONAL**. Nucleus keys replay on `sha256(compact token)` until `exp`, so a
   token is accepted at most once whether or not it carries a `jti`.
8. Any claim the binding lists in `required_claims` **MUST** be present with the configured
   value.

### 3.1 What nucleus does with it (informative)

- The token is presented once, at `POST /v1/federation/exchange` on a server-auth-only TLS
  listener, as `Authorization: Bearer <token>`. The JSON body is
  `{ "csr": "<PEM or base64 DER PKCS#10>", "requested_ceiling"?: {"profile": "…"} | {"inline": {…}} }`.
  The CSR **MUST** carry exactly one SAN: a SPIFFE URI equal to the mapped principal.
- The principal is `spiffe://<binding.trust_domain>/ns/<label>/sa/<escaped sub>`. Letters,
  digits and `-` are kept; every other byte, including `_`, becomes `_xx` (hex), so the
  mapping is injective. Nothing is truncated.
- A token that validates is spent, even if its CSR is then refused.
- The response is a short-lived X.509 SVID for that principal (lifetime at most the token's
  remaining lifetime and the binding's `svid_ttl`), plus a node-rooted delegation
  certificate whose ceiling is the binding's and whose `provenance` is `sha256(token)`.
- The response is `{ "spiffe_id", "svid_chain_pem", "trust_bundle_pem", "delegation_cert",
  "expires_at" }`. Errors carry only `{"error": "<word>"}`: `400` malformed body, `401`
  anything about the token, `403` CSR or unmappable `sub`, `503` issuer keys unreachable or
  too many exchanges in flight.
- The caller then uses mTLS `POST /v1/pods` with that certificate in
  `x-nucleus-delegation-cert`. Pods are visible only to callers in the same trust domain;
  every other caller sees `404`. The budget is shared by every exchange under the binding.


## 4. Operator configuration

These are nucleus-side examples with placeholder values, in the shapes P0 (#3017), P3
(#3020) and P5 (#3022) implement.

### 4.1 An Upstream entry (`--upstreams upstreams.toml`)

```toml
[[upstream]]
name         = "model-api"
base_url     = "https://api.model.example.com"
header       = "authorization"
value_prefix = "Bearer "
call_charge_micro_usd = 1000 # example operator tariff, not a provider price

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
call_charge_micro_usd = 1000
value_prefix = ""

[upstream.credential.env]
var = "SEARCH_API_TOKEN"
```

A pod spec selects an upstream by `name`. A spec whose `credentialed_egress` entry differs
from the registry entry in any field is refused at admission.

An entry may list `request_headers = ["accept", "git-protocol", ...]`: the request header
names a guest may set on calls to it (default: none beyond `content-type`). A guest-proposed
header outside the list is dropped and the call's record names what was forwarded. The node
refuses to start on a list naming `authorization`, `cookie`, `proxy-authorization`, a
framing or forwarding header, or the entry's own credential `header`. Streamed calls carry
`GET` or `POST` and an optional query, both bound into the effect digest; a query with a
credential-looking parameter name is refused. See `examples/egress-git-remote/` for a git
remote reached this way.

An entry may set `value_encoding` to say how the host turns the credential into the header
value (#3252). The default, `"raw"`, sends `value_prefix` followed by the credential.
`{ basic = { username = "<name>" } }` sends `Basic base64("<name>:" + credential)` (RFC 7617),
which is what a git smart-HTTP endpoint expects. The host applies the encoding when it injects
the header, on buffered and streamed calls alike, so a minted token is never stored
pre-encoded. `value_prefix` is refused beside `basic`, and so is a username that is empty,
longer than 256 bytes, or contains `:` or a control character. The encoding is not part of
the spec projection: the guest never sees it, and a pod gets the encoding the operator wrote
for the entry it selected. Records name the credential header only.

```toml
value_encoding = { basic = { username = "token-user" } }
```

Two more header kinds are the operator's alone:

```toml
secret_headers = ["x-account-binding"]   # never guest-supplied; host-injected only

[upstream.fixed_headers]                  # added by the host to every call
x-api-version = "2026-01-01"
```

A fixed header (an API version an upstream requires, say) is added to every call, streamed
or buffered. It is not secret: its value is in the effect an operator reviews and the
digest an approval binds. A secret name is one only the host may set; the entry's own
credential `header` is always one. A guest proposal of a fixed or secret name is dropped
even when `request_headers` lists it, and the node refuses to start on a registry that
lists one there, on a fixed header that is credential-shaped, framing or forwarding, or on
a fixed header that is also marked secret. The call's record names the forwarded headers,
fixed ones included, and never a value.

### What a call does: the effect table

What a write to an upstream DOES depends on the upstream, so the operator declares it per
entry (#3229):

```toml
kind    = "forge"   # or "api", the default
effects = [
  { method = "POST", path = "/repos/*/*/pulls", operation = "create_pr" },
  { method = "POST", path = "*/*/git-upload-pack", operation = "web_fetch" },
]
```

A request whose method and path match an effect is decided as that operation (`web_fetch`,
`git_push` or `create_pr`): by the guest's kernel, and again by the host, which recomputes the
classification and refuses a call labelled as anything weaker. A path segment is a literal or
`*` (exactly one segment); the request path is percent-decoded before matching. A push (the
`POST …/git-receive-pack` that carries the pack) is `git_push` whatever the table says; its
bodiless ref advertisement (`GET …/info/refs?service=git-receive-pack`) is a read (#3266). On a
`forge`, a write (`POST`) that matches no effect is refused rather than decided as a fetch; on
an `api`, it is a `web_fetch`, as every call was before the table existed. Two effects for one method whose
patterns overlap with different operations refuse the registry.

The table is part of the entry's projection: the pod spec carries it and admission compares
it like every other field, so a pod holds exactly the operator's table. So under a profile
with `create_pr: never`, opening a pull request is refused by the host's PDP before a byte
leaves; under a profile that allows it, the host still asks the operator (opening a pull
request publishes data), and the approval is bound to the request's digest: method, path,
query, forwarded headers and body.

A forge credential is best minted per call by an operator-run RFC 8693 token exchange, through
the `federated` credential source above (ADR 0010): nucleus never holds the forge's app key.

`call_charge_micro_usd` is the operator's fixed tariff for each authorized dispatch
attempt (1,000,000 micro-USD = 1 USD). It is not copied from the pod spec or inferred
from a model/provider. Omission leaves the entry unpriced: PERFORM and streaming
refuse it before retrieving credentials. Explicit zero declares a free attempt.
Existing registry files must declare a tariff before their calls can execute.

The host checks affordability before token exchange and debits the shared pod
budget at final authorization. Failed exchange or absent credentials do not debit;
an authorized attempt retains its charge on timeout, cancellation, or upstream
failure. Cached PERFORM retries do not debit again. Approval details and signed
authorization records include the charge, and a price change invalidates the
effect binding. This is accounting for an operator tariff, not a guarantee about
variable provider bills. Variable usage pricing and terminal settlement require
additional trusted evidence.

Without `--upstreams` the node has no registry, and every request for a credentialed
upstream is refused, the root minter's included: a pod spec never chooses which node
variable is read. A pod caller is admitted only upstreams its own pod holds; an external
caller, the registry's, until caller bindings (§4.2) carry their own list.

A third source is reserved: `subject = "client-certificate"` in the `federated` table, for a
token endpoint that takes the caller's X.509 certificate from the TLS handshake as the RFC 8693
subject (`client_certificate = "pod-svid" | "node-svid"`, `grant = "token-exchange"`, an
`https` endpoint, `request_audience` required, `audience` and `assertion_ttl_secs` refused).
It is parsed and validated today and then refused as "not supported yet", so the node will not
start on it; the format is fixed now so such a registry loads unchanged once it is served.

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
jwks             = { discovery = true }          # or { uri = "…" } or { inline = '<JWKS JSON>' }
max_lifetime_secs = 900
leeway_secs      = 30                            # optional; at most 60
trust_domain     = "runtime.example.com"
required_claims  = { org = "example-org-0001" }
ceiling          = { profile = "codegen" }       # or { inline = { …lattice… } }
upstreams        = ["model-api"]
svid_ttl_secs    = 600                           # optional; default 600, 5-3600
```

`[[caller]]` entries live in the same file as `[[upstream]]` entries, because a binding's
`upstreams` must name entries in it. Label, issuer and trust domain are each unique across
bindings, and a trust domain may never be the node's own.

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
- [ ] One signing algorithm per binding, from `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384` or `PS512` (never `none`, `HS*` or `EdDSA`; see §3.2)
- [ ] `kid` in every header
- [ ] Exact `aud` per binding
- [ ] `exp` and `iat` present; `exp − iat` ≤ the binding's maximum
- [ ] Stable `sub`, or a stable claim the binding maps
- [ ] `jti` optional

## 7. The operator assertion (v1)

The same signer also speaks for the **operator**, so automation acting for the operator
(reaching its own build machines, say) holds no stored credential and no human login that
expires. The relying party is an OIDC workload-identity provider the operator configures; it
runs `nucleus federation operator-assertion` as an executable credential source each time it
needs a token.

**Subject.** `spiffe://<trust domain>/ns/system/sa/operator-automation`: the operator's
`system` namespace (`docs/spiffe-taxonomy.md`), as a sibling of the interactive
`ns/system/sa/cli` rather than a child of it. The node grants `ns/system/sa/cli` by exact
match, so the automation identity holds nothing on a node; its reach is only what the
relying party binds to it.

**Claims.** Exactly `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti` (no `nucleus_*` claims:
there is no pod). `alg` is `ES256` and `kid` is the RFC 7638 thumbprint, as in §1.
`nbf = iat`, `exp − iat` is the requested `--lifetime` (default 300 s, at most 900), and `jti`
is fresh per call.

**Key.** Created by `nucleus federation operator-key init`; its JWKS (`operator-key jwks`) is
registered **inline** with the relying party, so `iss` need not resolve (a `.invalid` name is
fine). `operator-key rotate --stage` publishes a second key, `--promote` makes it sign. On
macOS the key is a Keychain item read and written only through `/usr/bin/security`, never by
the `nucleus` process: Keychain access lists are per binary, so a rebuilt `nucleus` reading
the item itself would raise a dialog and an unattended credential helper would wait on it
forever. Every `security` call is killed after `--keychain-timeout-ms` (default 5000) with a
named error. Elsewhere the key is an owner-only file under `~/.config/nucleus/operator-key`.

**Output.** `--format jwt` (default) prints the compact JWT. `--format executable-credential`
prints the "executable-credential v1" interop response that OIDC token-exchange clients read
from an executable credential source:

```json
{"version":1,"success":true,"token_type":"urn:ietf:params:oauth:token-type:jwt",
 "id_token":"<jwt>","expiration_time":<exp>}
```

On failure it prints `{"version":1,"success":false,"code":"…","message":"…"}` and exits
non-zero; `code` is `keychain_timeout`, `operator_key_unavailable` or `invalid_request`.

**Relying-party registration**, stated generically: issuer = the `--issuer` string; keys =
the inline JWKS; allowed audience = the `--audience` the helper is configured with; a
condition requiring `sub` to equal the operator subject exactly; and the principal it maps to
holds only the permissions the automation needs.
