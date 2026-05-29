# nucleus-oidc-core

Provider-agnostic OIDC primitives for the nucleus mesh.

## Role

`nucleus-oidc-core` provides the **vendor-neutral building blocks** that every per-provider OIDC validator and the OP itself need:

- `OidcError` — shared error type.
- `Jwk` + `Jwks` + `JwkPublicKey` — RFC 7517 wire shape with both RSA and Ed25519/OKP (RFC 8037) extraction. Returns a neutral key form; no jsonwebtoken dep.
- `KeyResolver` + `DiscoveryKeyResolver` + `StaticKeyResolver` — fetch verifying keys by `kid`, with OIDC discovery + JWKS cache.
- `JtiCache` — bounded replay-defense cache for JWT `jti` claims.
- `FederationRegistry` + `IssuerProvider` trait + `peek_jwt_issuer` — vendor-neutral federation dispatch. Per-provider impls register at startup.

## Vendor neutrality

This crate ships in the public, MIT-licensed nucleus repo per the
project guidelines. It contains **no** vendor-specific URLs, names,
or token-prefix shapes. Per-provider validators (e.g., for specific
SaaS-issued JWTs) live in vendor-aware sibling crates that depend on
this one and register their `IssuerProvider` impls via
`FederationRegistry::register`.

The CI gate `ci/no-vendor-strings.sh` enforces this on every PR
touching `crates/nucleus-oidc-core/`. See
`docs/oidc-vendor-neutrality-audit.md` for the structural rationale.

## Cross-references

- `crates/nucleus-oidc-provider/` — the OP. Consumes this crate for
  validating inbound subject-tokens at the token-exchange endpoint.
- `docs/oidc-vendor-neutrality-audit.md` — the structural cut.
- `docs/wimse-aims-conformance-gap.md` — claim-schema gap analysis.

## License

MIT.
