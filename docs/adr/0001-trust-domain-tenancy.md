# ADR 0001 — Tenancy is the SPIFFE trust domain; ownership is the SPIFFE subject

- Status: accepted (2026-09-04)
- Tracks: #2428 (epic), #2447 (this decision), #2441, #2442, #2433
- Applies to: `nucleus-control-plane-server` first; every multi-principal server after it

## Context

The September 2026 audit found that nucleus had **no tenant type anywhere**. The one
long-lived, multi-principal server — the job control plane — verified the caller's
identity and then discarded it: every job-scoped route bound `_: RequireSpiffeAuth`,
`JobSpec`/`JobState` carried no owner, and the gRPC job service had no authentication
at all, with its boundary asserted in a comment ("a private listener only same-org
machines reach"). Any authenticated caller could read, cancel, or fetch the bundle of
any job.

The obvious fix — a bespoke `tenant_id: String` on the request — would have added a
second, *unauthenticated* identity next to the one the codebase already enforces
everywhere (SPIFFE, via mTLS SVIDs on the node and JWT-SVIDs on the control plane).
Two identities that must agree is the shape that drifts.

## Decision

1. **A tenant is a SPIFFE trust domain.** `spiffe://<trust-domain>/...` — the
   authority component of the identity the caller already proved. Trust domains
   are the unit at which keys are federated (`nucleus-oidc-core`'s pinned per-domain
   bundles), so they are already the unit at which one operator's identities are
   distinguishable from another's.
2. **Ownership of a resource is the full SPIFFE subject** (`sub`), which implies its
   trust domain. A resource records the *verified* subject that created it at
   creation time and carries it forward unchanged through every state transition;
   it is never re-derived from a later request.
3. **Every resource-scoped operation compares the verified caller to the recorded
   owner.** A non-owner is answered exactly as a non-existent resource (`404` /
   `NOT_FOUND`), never `403` — a distinguishable refusal is an existence oracle that
   lets a caller enumerate other tenants' resources by id.
4. **Parsing is the OIDC federation parser.** `nucleus_oidc_core::SpiffeId::parse`
   lowercases the authority; a mixed-case subject must not dodge an equality check.
   No new string-slicing implementation is introduced (the codebase had four).
5. **Idempotency keys are scoped to the owner.** A key is hashed with the caller's
   subject, so one tenant's key cannot return another tenant's resource id.
6. **Every surface authenticates the same way.** The gRPC surface uses the same
   `verify_jwt_svid`, trust JWKS, audience, and subject prefix as REST; a production
   build refuses to bind it without auth, and it binds loopback by default.

## First consumer

`nucleus-control-plane-server`: `AuthenticatedPrincipal::trust_domain()` and
`AuthenticatedPrincipal::owns()` (`auth.rs`); `require_owner` on `GET /v1/jobs/{id}`,
`POST /v1/jobs/{id}/cancel`, `GET /v1/jobs/{id}/events/stream`, `GET /v1/jobs/{id}/bundle`;
the JWT-SVID interceptor on `JobService` with the same check on `Get`; the
principal-scoped idempotency hash; `JobRegistry::update_if` so a cancel cannot overwrite
a completion that landed between the read and the write.

## Consequences

- The node's per-pod certificates (`pod_authority`) already record the creator's
  SPIFFE subject as the chain's root identity and the pod's own as the leaf, so the
  same primitive extends to pods without a new type: a pod's tenant is the trust
  domain of its certificate's root identity.
- Cross-tenant sharing, if ever wanted, is an explicit grant (a delegation
  certificate whose leaf is the grantee), not a looser equality check.
- Under an `insecure-dev` build with auth disabled every caller is the single
  sentinel principal and every owner is the sentinel; `owns()` states that case
  explicitly rather than letting it fall out of a string comparison.

## Rejected

- **A bespoke tenant string on the request or spec.** Caller-declared, hence
  unauthenticated; would duplicate the identity already enforced.
- **A path-segment tenant under one trust domain** (`spiffe://td/tenant/<x>/...`).
  Workable, but it re-invents the boundary the trust domain already draws and
  leaves key federation and tenancy on different axes. Can be layered later as a
  *sub*-tenant convention within one domain if a single operator needs it.
- **403 for non-owners.** Cleaner HTTP semantics, but an existence oracle.
