# ADR 0010 — A pod reaches an upstream with a credential minted per exchange, never stored

- Status: **proposed** (2026-09-24). Implementation is phased P0–P6 (below). **Nothing here
  is wired yet**: today the host-side broker still reads a static credential from a node
  environment variable the pod spec names.
- Tracks: #2698 (per-upstream registry, RFC 8693), #2705 (an external OIDC token becomes a
  root block with provenance), #2906 (credentialed egress on the live path). Bounded by
  #2724 (a guest can fetch its pod's SVID key); P6 is blocked by #2904.
- Extends: [ADR 0001](0001-trust-domain-tenancy.md) (a federated caller's tenant is its
  binding's trust domain), [ADR 0004](0004-delegation-compiler.md) (minimum authority out; a
  refusal never tells the caller what it could have had), [ADR 0009](0009-the-public-private-line.md)
  (the issuer mechanism is neutral and lives here; a production signer behind a KMS plugs in
  downstream behind a trait).
- Applies to: `nucleus-node` (the broker, `PodAuthority`, a new federation listener), a new
  neutral crate `nucleus-federation`, `nucleus-spec` (`CredentialedEgressSpec`,
  `WorkloadIdentitySpec`), and the wire profile
  [`docs/federated-upstream-profile.md`](../federated-upstream-profile.md), which is the
  document an upstream or an external runtime implements.

## Context

The goal is a pod that has identity (a node-assigned SPIFFE ID) and authority (a
`LatticeCertificate`), calls an external model API, and holds **no static credential
anywhere** — not in the guest, not in the pod spec, not in the node's environment. The
reverse direction is in scope too: an external agent runtime holding an OIDC token from its
own issuer should be able to create and call nucleus pods, inside a ceiling the operator
set.

What exists on `main`:

- **The host already performs the call.** A guest `POST /v1/egress/{name}/*` goes through
  the in-guest tool proxy over vsock to `broker_perform::handle_perform` on the node, which
  asks the PDP, fetches the credential from the credential-delivery point (`cdp_fetch`), and
  makes the upstream call. The guest receives the result, never the credential.
- **The credential is static, and the pod spec chooses it.**
  `broker_launch::store_from_node_environment` reads the node environment variable named by
  the spec's `credential_env`. That is the seam this ADR replaces.
- **The node never clamps `spec.credentialed_egress`.** `create_pod_internal` replaces the
  spec's `policy` and passes the egress list through; the only clamp is inside the guest.
  Any mTLS caller of `POST /v1/pods` can therefore name any node environment variable and
  any upstream URL — and with #2724 open, that includes a guest workload holding its own
  pod's SVID key. Federation built on top of this would let a pod mint assertions for any
  audience, so closing it is phase P0 and blocks the outbound path.
- **The identity pieces do not fit the ecosystem.** The node issues X.509 SVIDs only. The
  OIDC provider in this repository signs EdDSA only (its THREAT_MODEL T04, enforced by
  `ci/alg-pin-check.sh`) and its binary is not wired. The large model providers checked all
  accept federated tokens — one by RFC 7523 `jwt-bearer`, two by RFC 8693 `token-exchange` —
  and all accept RSA or ECDSA and **reject EdDSA**. `nucleus-oidc-core`'s `JwkPublicKey` has
  no EC variant, so a P-256 JWKS resolves to "no usable keys".
- **The inbound direction has no door.** The node's HTTP listener is mTLS-only, which
  already makes its one bearer-token route (the hard-coded CI-provider exchange at
  `oidc.rs:599`) unreachable by anyone who does not already hold an SVID.

The runtime that prompted this runs a per-organization OIDC issuer (ES256, one P-256 key,
claims `iss aud sub session iat exp`, no `jti`) for the calls it makes, and accepts only
static organization-wide keys for calls into it. That shape — "issues tokens, accepts only
keys" — is common, and the profile has to tell such a runtime exactly what to add.

## Decision

**A pod's credential for an upstream is minted on the host, per exchange, from an operator
registry the pod spec can only select from, after the PDP has approved the call. It is held
by the node for at most its own lifetime and never enters the guest. An external runtime
enters by exchanging its OIDC token for an ordinary node-rooted delegation certificate, not
by a second authentication path.**

### 1. The operator owns the upstream registry; the spec only selects

The node takes `--upstreams <toml>`. Each entry is `name`, `base_url`, `header`,
`value_prefix`, and `credential`, which is one of:

- `env { var }` — today's behavior, now chosen by the operator rather than the spec author;
- `federated { token_endpoint, grant, encoding, audience, scope?, request_audience?, params, assertion_ttl_secs? }`.
  `request_audience` is the RFC 8693 `audience` body parameter, kept separate from the
  assertion's `aud` because the token client refuses `audience` inside the opaque `params`.

A pod spec's `credentialed_egress` names upstreams by `name`. Admission refuses a spec whose
entry differs from the registry's in any field. The clamp is one function in `nucleus-spec`
(`CredentialedEgressSpec::admitted_by(&[Self])`), called both by the in-guest clamp and by
`create_pod_internal`, next to `authority.admit`, per admission case: a pod caller is
bounded by its parent's registered upstreams, an external caller by its binding's, the root
minter by the registry.

When the registry is configured, `store_from_node_environment` reads it and ignores
`spec.credential_env`.

### 2. A separate issuer, ES256 only

A new neutral crate, `nucleus-federation`, holds the claims builder, a `trait
AssertionSigner { alg, kid, sign }`, the token client, and the inbound validator. The node
supplies a file-backed ES256 signer (`jwt_svid_p256_signing_key.der`, mode 0400, `ring`),
following the persisted-key pattern in `keys.rs`. A KMS-backed signer is a downstream
implementation of the same trait (ADR 0009, test 2).

The issuer signs **ES256 and nothing else**, as a `const`, under its own `iss`
(`--federation-issuer`), distinct from the EdDSA provider's. One issuer, one pinned
algorithm, is exactly the property T04 protects; two issuers with one algorithm each keep
it, where one issuer with two algorithms would be the T04 attack shape. The inbound
validator's algorithm set comes from each caller binding's configuration, never from the
token header, and the JWK's `kty`/`crv` must match the header `alg`.

### 3. The assertion

| claim | value |
|---|---|
| `iss` | `--federation-issuer` |
| `sub` | the pod's SPIFFE ID, as observed by the host |
| `aud` | the registry entry's `audience`, exactly |
| `iat`, `exp` | `exp − iat` defaults to 300 s, capped at 3600 s |
| `jti` | 128 random bits, fresh per exchange |
| header `kid` | RFC 7638 thumbprint of the signing key |
| `nucleus_tenant` | trust domain of the pod certificate's root identity (ADR 0001) |
| `nucleus_upstream` | the registry `name` |
| `nucleus_root` | root identity of the pod's certificate chain |
| `nucleus_chain` | fingerprint of the pod's certificate |

The `nucleus_*` claims are **flat, top-level strings** because the providers that federate
today match rules on top-level string claims and nothing else. RFC 8693's nested `act`
would carry the same facts in a place no provider rule can reach, and it inverts `sub`: at
least one existing provider already mishandles `act.sub == sub`.

`AssertionClaims` can be built only from a host-side pod identity type that does not
implement `Deserialize`, so nothing a guest sends can choose `sub`.

### 4. The node's mint decision is the gate

THREAT_MODEL T05 names the dominant failure of OIDC federation: a relying-party rule that
matches more subjects than intended. Here the relying party's rule matches an issuer, and
every pod on the node shares that issuer, so a provider rule of `iss = X` matches **all
pods**. The answer is that the provider's rule is not the gate. The node mints only

- for a request the PDP has already approved,
- for a registry upstream the pod was admitted to,
- with that upstream's `aud` and no other.

`refill` takes `&broker::Approved`, which only `pdp_decide` returns and whose field is private
to `broker.rs`, so a mint before the decision does not compile. (`AuthorizedRequest` alone
could not carry this: its fields are public and its constructor takes a `bool`.) The profile tells providers to match exact `iss`,
exact `aud`, and `nucleus_upstream` (and `nucleus_tenant` where one provider account serves
one tenant); that is defense in depth on top of the node's decision, not a substitute for
it.

### 5. Freshness

- Every exchange uses a **fresh assertion** with a new `jti`.
- The minted token is cached per `(pod, upstream)` until
  `min(expires_in, certificate not_after) − 60 s`, with single-flight per key, and is never
  shared across pods.
- A failed exchange re-mints; an assertion is never replayed.
- A response with no `expires_in` is used once and not cached.
- An upstream `401` evicts the cache entry and is returned as a refusal. There is **no
  automatic retry**: the upstream call is a POST with side effects.
- Receipts record `iss`, `jti`, the endpoint name, `expires_in`, and cache hit or miss —
  never the token or the assertion.

`CredentialStore` gains `insert_expiring`, and `for_request` refuses an expired entry. The
credential-delivery point stays a pure holder; minting lives in the node's
`federated_credential.rs`, and `refill` is registered as a CDP root in
`tools/nucleus-cb4a-lint`.

### 6. Inbound: exchange once, then use the door that exists

A separate, **server-auth-only** TLS listener (`--federation-listen`) serves one route,
`POST /v1/federation/exchange`. The request carries `Authorization: Bearer <OIDC token>` and
a CSR. For a token that validates against a `[[caller]]` binding, the response is:

- a short-lived X.509 SVID for the binding's mapped principal (`sign_csr_only`, TTL at most
  `min(token remaining, binding svid_ttl)`, CSR SAN must equal the principal), and
- a **node-rooted `LatticeCertificate`** (`mint_with_holder_key`) whose ceiling is the
  binding's and whose `provenance` is `sha256(token)`.

The caller then uses the **existing** mTLS `POST /v1/pods` with that certificate in
`x-nucleus-delegation-cert` — admission case 2, unchanged. There is no new admit branch and
no second authentication path on the pod API. The hard-coded CI-provider route moves onto
this listener as one binding.

### 7. Tenancy is the binding's trust domain

Each caller binding declares its own trust domain. The principal is
`spiffe://<binding.trust_domain>/ns/<label>/sa/<sanitized sub>`. Pod operations are scoped
to "certificate root trust domain equals caller trust domain", and every other tenant's pod
answers `404` (ADR 0001, decision 3). The budget ledger for node-rooted certificates is
keyed by the binding's trust domain — not by certificate fingerprint, and not by the
token's `sub`, which may be per-invocation and would give every exchange a fresh budget.

### 8. Inbound replay is keyed on the token hash

A presented token is refused if `sha256(compact token)` was seen before and has not yet
reached its `exp`. `jti` is optional in the profile because the runtime that prompted this
issues none.

### 9. `WorkloadIdentitySpec` is superseded

`CredentialsSpec::workload_identity` describes writing a JWT **into the guest** at a token
path and refreshing it there — the opposite of this design, in which no assertion or token
is ever guest-visible. It has no runtime consumer. It stays in the schema so existing specs
still parse, and its documentation says it is superseded by this ADR.

## First consumer

A pod calling a model-serving upstream through credentialed egress. The upstream is a
registry entry with a `federated` credential; the guest calls its local egress address; the
node, after the PDP approves, mints an assertion, exchanges it at the upstream's token
endpoint, and calls the upstream with the minted token. The guest's reply carries the
upstream's response body and nothing that authenticated it.

The acceptance run (P6, with #2906) boots on real KVM, makes that call through a mock
upstream and a mock token endpoint, and in the same run shows no credential in any guest
`/proc/*/environ` and a refusal for an unregistered target. Then one call against a real
provider that federates today, configured through operator TOML only, with the provider's
opaque identifiers in `params`. Vendor-specific worked configurations live outside this
repository.

## Phases

Each phase is one PR that can land on its own. Order: P0 → (P1 ∥ P2 ∥ P4) → P3 → P5 → P6.

| phase | what | blocks / blocked by |
|---|---|---|
| P0 | node-side upstream admission (decision 1): the clamp, `upstreams.rs`, a perturbation test | blocks P3 |
| P1 | this ADR and the wire profile | — |
| P2 | `nucleus-federation`: assertion, signer trait, token client, inbound validator, EC P-256 JWK | — |
| P3 | the node outbound path: `refill`, the cache, `insert_expiring`, receipts | after P0, P2 |
| P4 | `nucleus federation issuer --export \| --jwks \| --claims-for <upstream>`; key rotation | — |
| P5 | the inbound listener, caller bindings, tenancy and ledger scoping | after P2 |
| P6 | the live acceptance run above | #2904 |

## Consequences

- No upstream credential exists at rest anywhere nucleus controls. What exists at rest is a
  P-256 signing key on the node, which is one key per node rather than one per upstream, and
  whose compromise is bounded by the upstreams' rules on `iss` and `aud`.
- Provider rules are written once per `(issuer, upstream)`. Adding a pod does not touch the
  provider.
- An upstream token endpoint becomes a runtime dependency of credentialed egress. The cache
  keeps it off the per-call path; single-flight keeps a burst of calls from becoming a burst
  of exchanges.
- A spec that worked by naming an arbitrary `credential_env` stops being admitted once a
  registry is configured. That is the P0 fix, not a regression.
- The profile is versioned by URI. A runtime that implements it — in either role — drops in
  with operator configuration only; nothing in nucleus changes per vendor.
- A multi-node fleet either shares one issuer with a union JWKS or registers one issuer per
  node. Both work; the second multiplies provider rules.
- Rotation (P4): publish the next key, overlap for at least the provider's JWKS cache TTL
  plus the maximum assertion TTL, then switch.

## Rejected

- **A `CredentialSource` enum in `PodSpec`.** On Firecracker the spec is copied into the
  guest rootfs at build time, so token endpoints and parameters would be baked into the
  guest — and the spec author, not the operator, would still choose the source.
- **Putting the signer in `nucleus-oidc-core` or the OIDC provider.** It collides with T04
  and the algorithm-pin gate, which exist precisely to keep that issuer single-algorithm.
- **One issuer that signs both EdDSA and ES256.** That is the algorithm-confusion shape T04
  describes; it buys nothing a second `iss` does not.
- **Carrying tenant and chain in a nested `act`.** Providers match top-level string claims
  only, and `act` inverts `sub`.
- **Encoding the upstream in `sub`.** Pod ids are random, so no provider rule could match
  them, and one pod may use several upstreams.
- **A fresh mint and exchange per call.** It makes the token endpoint a hot dependency and
  grows the provider's `jti` store without bound.
- **Bearer tokens accepted directly on `POST /v1/pods`.** A second authentication path on
  the pod API, and a token replayable for its whole lifetime against it.
- **A sub-path of the node's own trust domain for federated callers.** ADR 0001 already
  rejects a path-segment tenant.
- **`JtiCache` for inbound replay.** Useless against tokens that carry no `jti`.
- **Giving `WorkloadIdentitySpec` a consumer.** It puts a JWT in the guest.

## What this does not claim

- **No streaming.** `PerformReply` is POST-only, buffered, truncated at
  `MAX_UPSTREAM_BODY_BYTES`, and carries no response headers. Model calls through
  credentialed egress must be non-streaming.
- **An upstream that echoes `Authorization`** in a response body hands the guest a token.
  Nucleus does not inspect response bodies for it; only the token's short lifetime bounds
  the damage.
- **Inline JWKS registration needs a manual re-registration on every rotation.** P4 prints
  the diff; nothing pushes it.
- **The authority gate is nucleus's own.** Provider-side claim matching is defense in depth.
  A provider that ignores `aud` or `nucleus_upstream` is weaker than the profile asks, and
  nucleus cannot detect that from its side.
- **#2724 bounds "a workload cannot act as its pod".** Until a guest cannot read its pod's
  SVID key, a guest can present itself to the node as its pod. P0 closes the route by which
  that would reach an unregistered upstream, and assertions and tokens exist only on the
  host, but this ADR does not claim the stronger property.
- **Nothing here is live.** Status moves to accepted when P0 and P3 land, and the headline
  claim — no static credential anywhere — is earned only by the P6 run.
