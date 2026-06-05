# nucleus-github-oidc

Validate GitHub Actions OIDC tokens and map the verified workflow identity
(repo + ref + actor) to a Nucleus SPIFFE caller id — federated identity instead
of a long-lived API key.

[![docs.rs](https://img.shields.io/docsrs/nucleus-github-oidc)](https://docs.rs/nucleus-github-oidc)

Sibling to [`nucleus-fly-oidc`](../nucleus-fly-oidc); both build on
[`nucleus-oidc-core`](../nucleus-oidc-core). Once a workflow's token is verified,
the derived SPIFFE id can authorize bucket pushes, tool registration, or any
other call that wants federated identity.

## Usage

```rust,no_run
use nucleus_oidc_core::DiscoveryKeyResolver;
use nucleus_github_oidc::{GitHubOidcConfig, GitHubOidcValidator};

# async fn run(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let validator = GitHubOidcValidator::new(
    GitHubOidcConfig::new("nucleus.io").allow_org("coproduct-opensource"),
    DiscoveryKeyResolver::new(),
);
let id = validator.validate(token).await?;
println!("verified GH workflow: {}", id.spiffe_id);
# Ok(())
# }
```

## What gets checked

- **Signature** against GitHub's OIDC JWKS (`DiscoveryKeyResolver` fetches from
  the issuer discovery doc; `StaticKeyResolver` pins for tests).
- **Issuer** must be `GITHUB_ISSUER`.
- **Org allowlist** via `GitHubOidcConfig::allow_org`.
- **Replay** via a `JtiCache`.

On success, `derive_spiffe_id` maps the verified claims to a
`ValidatedGitHubIdentity` carrying the SPIFFE id.

## Formal backing (and an honest caveat)

The OIDC→SPIFFE derivation (`sanitize_segment` / `derive_spiffe_id`) has a
subset-safe mirror in the [`extracted`](src/extracted/mod.rs) module that
**Aeneas** translates to Lean (`lean/`); production code is bound to the
extracted form by **parity proptests**.

The proofs document a real, deliberately-surfaced finding: `sanitize_segment` is
**lossy** (distinct inputs can collapse to the same segment), so the derivation
is **not injective** — distinct claim-sets can mint the *same* SPIFFE id, an
authz-confusion surface. This is proven, not hidden (see the `collision_*`
proptests and `lean/OidcSpiffeProofs.lean::collapse_lossy_step`). Callers that
need a 1:1 identity mapping must account for it.

## License

MIT
