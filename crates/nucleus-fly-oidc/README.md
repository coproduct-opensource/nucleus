# nucleus-fly-oidc

Validate Fly.io Machine OIDC tokens and derive the SPIFFE identity a Nucleus
runner runs under.

[![docs.rs](https://img.shields.io/docsrs/nucleus-fly-oidc)](https://docs.rs/nucleus-fly-oidc)

Every Fly Machine can mint a short-lived OIDC token from its in-machine
`/v1/tokens/oidc` endpoint. The Nucleus control plane exchanges that token for a
SPIFFE certificate; **this crate is the validation half** of that exchange — it
verifies the token and turns its claims into a `CallSpiffeId`.

## Usage

```rust,no_run
use nucleus_fly_oidc::{DiscoveryKeyResolver, FlyOidcConfig, FlyOidcValidator};

# async fn run(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let validator = FlyOidcValidator::new(
    FlyOidcConfig::new("nucleus-control").allow_org("coproduct"),
    DiscoveryKeyResolver::new(),
);
let identity = validator.validate(token).await?;
println!("runner identity: {}", identity.spiffe_id);
# Ok(())
# }
```

## What gets checked

- **Signature** against the Fly OIDC JWKS. `DiscoveryKeyResolver` fetches keys
  from the issuer's discovery document; `StaticKeyResolver` pins them for tests.
- **Issuer** must match the Fly issuer prefix (`FLY_ISSUER_PREFIX`).
- **Org allowlist** — `FlyOidcConfig::allow_org` restricts which Fly org's
  machines are accepted.
- **Replay** — a `JtiCache` rejects reused token IDs.

On success, `derive_spiffe_id` maps the validated claims to a SPIFFE ID
(`ValidatedIdentity`).

## Public surface

| Item | Role |
|---|---|
| `FlyOidcValidator`, `FlyOidcConfig` | the validator + its policy |
| `KeyResolver` (`DiscoveryKeyResolver` / `StaticKeyResolver`) | JWKS resolution |
| `FlyClaims`, `ValidatedIdentity`, `derive_spiffe_id` | claims → identity |
| `JtiCache` | anti-replay |
| `fetch_machine_oidc_token`, `obtain_fly_token` | the **minting** side (for a runner inside a Fly Machine) |

## License

MIT
