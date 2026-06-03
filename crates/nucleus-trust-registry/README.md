# nucleus-trust-registry

**"Let's Encrypt for agents"** — a PR-rooted, GitHub-OIDC-attested,
transparency-logged SPIFFE **federation enrollment** registry.

It records which foreign SPIFFE trust domains you federate with, who
attested each one, and produces a deterministic federation set that feeds
the inbound validator (`nucleus-oidc-core::FederationStore`), plus an
append-only, witness-cosigned transparency log of every trust-root
binding.

## Non-custodial — this is NOT a CA

The registry **records, distributes, and verifies** trust-domain → JWK-Set
bindings. It is **never** a certificate authority and **never** a
keyholder. It does not mint keys, sign on behalf of enrolled domains, or
hold any private material. Each enrolled domain runs its own SPIFFE
authority; the registry only pins the public JWK Set it publishes.

## Honest caveats (read these)

1. **The OIDC proof proves GitHub-ORG control, NOT trust-domain
   ownership.** The GitHub Actions OIDC proof-of-control proves the
   enrolling PR ran inside a repo owned by the GitHub org whose **numeric
   id** (`repository_owner_id`) is pinned in the metadata — the numeric
   pin defeats org-rename squatting. It does **not** prove you own the
   SPIFFE trust-domain name. A DNS-01-style trust-domain proof is **v2**.

2. **Auditable, not un-backdoorable.** The transparency log makes a
   misbehaving maintainer *detectable*, not *impossible*. A binding is
   trusted only if its leaf is in a witness-cosigned Signed Tree Head, so
   a backdated/out-of-band insertion that never entered the cosigned log
   is rejected, and tampering with a bundle breaks its inclusion proof.
   But a maintainer colluding with the witness can still enroll a binding.

3. **MVP trust base = single maintainer + single witness.** There is no
   threshold signing and no key ceremony here — we do **not** borrow
   Sigstore's quorum/ceremony language. Adding witnesses is a drop-in (the
   cosign primitive is per-witness), but until then the witness is a
   single point of trust.

## Single-tenant value

The immediate, real use is enrolling your **own** trust domains —
`prod` / `staging` / `edge` / `ci` — each running its own SPIFFE authority
across failure domains, with the registry as the auditable record of which
ones federate. No external party is required.

## Repo format

```
registry/
  .github/CODEOWNERS                       # path-scoped per-domain ownership
  domains/
    <trust-domain>/
      bundle.json     # SPIFFE bundle = JWK Set + spiffe_sequence
      metadata.toml   # trust_domain, owner_github_org, owner_id (numeric),
                      # bundle_endpoint_url, profile = "https_web"
```

All three SPIFFE-federation parameters (`trust_domain`,
`bundle_endpoint_url`, `profile`) are **required** — the SPIFFE Federation
spec states the binding "cannot be securely inferred", so none is
defaulted, and an endpoint host equal to the trust-domain name is rejected
as an inferred binding.

## CLI

```
nucleus-trust-registry verify-pr   # fail-closed PR enrollment gate
nucleus-trust-registry compile     # deterministic federation set
nucleus-trust-registry log-append  # append binding + seal cosigned STH
```

The OIDC token *request* is enroller-side workflow config
(`.github/workflows/trust-registry.yml`); the *verifier* is this Rust
binary.

## Dormant metering seam

Verifying an enrollment (proof-of-control + transparency inclusion) is a
unit of proven work and a natural metering point. That seam is
**documented only** — there is no payment, no token, and no counter wired
anywhere in this crate.

## Reuse map (net-new logic is thin)

- SPIFFE bundle / JWK Set parsing + inbound validator: `nucleus-oidc-core`
  (`SpiffeBundle`, `Jwks`, `FederationStore`).
- Alg-pinned `jsonwebtoken` verify pattern for the OIDC proof: mirrors
  `nucleus-oidc-core::spiffe_federation`.
- Merkle log + STH: `ct_merkle` + `nucleus-lineage` (`Ed25519Witness`,
  `SignedTreeHead`, `format_checkpoint_body`).
- Witness cosignature: `nucleus-witness` (`WitnessKey`,
  `verify_cosign_line`).
</content>
