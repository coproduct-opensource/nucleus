//! `nucleus-github-oidc` — validate GitHub Actions OIDC tokens, map them
//! to a Nucleus SPIFFE id, and trust the result for bucket pushes /
//! tool registration / any other API call that wants federated identity
//! instead of a long-lived API key.
//!
//! Sibling to `nucleus-fly-oidc`; both build on `nucleus-oidc-core`.
//!
//! ```no_run
//! use nucleus_oidc_core::DiscoveryKeyResolver;
//! use nucleus_github_oidc::{GitHubOidcConfig, GitHubOidcValidator};
//!
//! # async fn run(token: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let validator = GitHubOidcValidator::new(
//!     GitHubOidcConfig::new("nucleus.io").allow_org("coproduct-opensource"),
//!     DiscoveryKeyResolver::new(),
//! );
//! let id = validator.validate(token).await?;
//! println!("verified GH workflow: {}", id.spiffe_id);
//! # Ok(())
//! # }
//! ```

mod claims;
/// Subset-safe, Aeneas-extractable mirrors of the OIDC→SPIFFE derivation
/// (`sanitize_segment` / `derive_spiffe_id`). The Lean proofs in `lean/` are
/// stated over the Charon→Aeneas extraction of this module; the production
/// code in [`claims`] is bound to it by parity proptests. See the module docs
/// for the trust chain and the (honest) lossiness/collision finding.
pub mod extracted;
mod validator;

pub use claims::{derive_spiffe_id, GitHubClaims};
pub use validator::{
    GitHubOidcConfig, GitHubOidcValidator, ValidatedGitHubIdentity, GITHUB_ISSUER,
};

// Re-export shared OIDC primitives so downstream callers only need one
// crate import. `Algorithm` is jsonwebtoken's enum — nucleus-oidc-core is
// crypto-library-agnostic and exposes a neutral `JwkPublicKey` instead of
// re-exporting jsonwebtoken types, so we pull `Algorithm` straight from
// jsonwebtoken here.
pub use jsonwebtoken::Algorithm;
pub use nucleus_oidc_core::{
    DiscoveryKeyResolver, JtiCache, Jwk, JwkPublicKey, Jwks, KeyResolver, OidcError,
    StaticKeyResolver,
};
