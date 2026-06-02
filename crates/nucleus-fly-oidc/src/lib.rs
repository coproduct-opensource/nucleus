//! `nucleus-fly-oidc` — validate Fly.io machine OIDC tokens and derive the
//! SPIFFE identity a Nucleus runner runs under.
//!
//! Every Fly Machine can mint a short-lived OIDC token from its in-machine
//! `/v1/tokens/oidc` endpoint. The Nucleus control plane exchanges that token
//! for a SPIFFE certificate; this crate is the validation half of that
//! exchange.
//!
//! ```no_run
//! use nucleus_fly_oidc::{DiscoveryKeyResolver, FlyOidcConfig, FlyOidcValidator};
//!
//! # async fn run(token: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let validator = FlyOidcValidator::new(
//!     FlyOidcConfig::new("nucleus-control").allow_org("coproduct"),
//!     DiscoveryKeyResolver::new(),
//! );
//! let identity = validator.validate(token).await?;
//! println!("runner identity: {}", identity.spiffe_id);
//! # Ok(())
//! # }
//! ```

mod claims;
mod error;
mod jwks;
mod machine;
mod validator;

pub use claims::{FlyClaims, SubParts, derive_spiffe_id, parse_sub};
pub use error::OidcError;
pub use jwks::{DiscoveryKeyResolver, JtiCache, Jwk, Jwks, KeyResolver, StaticKeyResolver};
pub use machine::{fetch_machine_oidc_token, obtain_fly_token};
pub use validator::{FLY_ISSUER_PREFIX, FlyOidcConfig, FlyOidcValidator, ValidatedIdentity};

pub use jsonwebtoken::Algorithm;
pub use nucleus_lineage::CallSpiffeId;
