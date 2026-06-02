//! Errors raised while validating a Fly.io OIDC token.

use thiserror::Error;

/// A failure during Fly OIDC token validation or SPIFFE ID derivation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OidcError {
    /// The token was not a well-formed three-segment JWT.
    #[error("token is not a well-formed JWT")]
    InvalidTokenFormat,
    /// The token header carried no `kid`, so no verifying key can be chosen.
    #[error("token header has no key id (kid)")]
    MissingKeyId,
    /// The token's `alg` is not in the configured allowlist (this is the
    /// defense against algorithm-confusion downgrade attacks).
    #[error("token algorithm {0} is not accepted")]
    UnacceptedAlgorithm(String),
    /// The `iss` claim is not a recognized Fly OIDC issuer.
    #[error("issuer {0:?} is not a trusted Fly OIDC issuer")]
    UntrustedIssuer(String),
    /// The issuer's organization is not in the allowlist.
    #[error("organization {0:?} is not in the allowlist")]
    OrgNotAllowed(String),
    /// The org in the verified claims disagrees with the issuer's org.
    #[error("organization mismatch: issuer says {issuer_org:?}, claim says {claim_org:?}")]
    OrgMismatch {
        /// Org parsed from the `iss` claim.
        issuer_org: String,
        /// Org carried in the `org_name` claim.
        claim_org: String,
    },
    /// The application is not in the allowlist.
    #[error("application {0:?} is not in the allowlist")]
    AppNotAllowed(String),
    /// No verifying key was found for the token's `kid`.
    #[error("no verifying key for kid {0:?}")]
    KeyNotFound(String),
    /// The JWT signature or registered-claim validation failed.
    #[error("JWT validation failed: {0}")]
    Jwt(String),
    /// The token's `jti` has already been seen — a replayed token.
    #[error("token replay detected for jti {0:?}")]
    TokenReplay(String),
    /// OIDC discovery (`.well-known/openid-configuration`) failed.
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    /// A network error reaching the issuer.
    #[error("network error: {0}")]
    Network(String),
    /// The JWKS document was missing or malformed.
    #[error("invalid JWKS: {0}")]
    InvalidJwks(String),
    /// The validated claims could not be turned into a SPIFFE ID.
    #[error("could not derive SPIFFE ID: {0}")]
    SpiffeId(String),
}
