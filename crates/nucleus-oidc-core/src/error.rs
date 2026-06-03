// SPDX-License-Identifier: MIT
//
//! Provider-agnostic OIDC validation error.
//!
//! Variants are abstract enough to fit any per-provider validator that
//! builds on this base. Per-provider crates may add their own narrower
//! error types, but every shared primitive (JWKS resolver, JtiCache,
//! KeyResolver, FederationRegistry) raises `OidcError`.

use thiserror::Error;

/// A failure during OIDC token validation, JWKS resolution, or
/// federation dispatch.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OidcError {
    /// The token was not a well-formed three-segment JWT.
    #[error("token is not a well-formed JWT")]
    InvalidTokenFormat,
    /// The token header carried no `kid`, so no verifying key can be chosen.
    #[error("token header has no key id (kid)")]
    MissingKeyId,
    /// The token's `alg` is not in the configured allowlist (defense
    /// against algorithm-confusion downgrade attacks per RFC 8725 §3.1).
    #[error("token algorithm {0} is not accepted")]
    UnacceptedAlgorithm(String),
    /// The `iss` claim is not a recognized OIDC issuer (no registered
    /// [`crate::IssuerProvider`] in the registry matched).
    #[error("issuer {0:?} is not a trusted OIDC issuer")]
    UntrustedIssuer(String),
    /// The issuer's intra-issuer namespace identifier is not in the
    /// allowlist. (The semantic of "namespace" is per-provider — could
    /// be an org, an account, a tenant.)
    #[error("namespace {0:?} is not in the allowlist")]
    NamespaceNotAllowed(String),
    /// The intra-namespace workload identifier (per-provider: app,
    /// repo, function name) is not in the allowlist.
    #[error("workload identifier {0:?} is not in the allowlist")]
    WorkloadNotAllowed(String),
    /// No verifying key was found for the token's `kid`.
    #[error("no verifying key for kid {0:?}")]
    KeyNotFound(String),
    /// The JWT signature or registered-claim validation failed.
    #[error("JWT validation failed: {0}")]
    JwtValidation(String),
    /// The token's `jti` has already been seen — a replayed token.
    #[error("token replay detected for jti {0:?}")]
    TokenReplay(String),
    /// OIDC discovery (`.well-known/openid-configuration`) failed.
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    /// A network error reaching the issuer.
    #[error("network error: {0}")]
    Network(String),
    /// The JWKS document was missing, malformed, or contained an
    /// unsupported key type.
    #[error("invalid JWKS: {0}")]
    InvalidJwks(String),
    /// The validated claims could not be turned into a SPIFFE/WIMSE ID.
    #[error("could not derive SPIFFE ID: {0}")]
    SpiffeId(String),
    /// A registration conflict in the federation registry.
    #[error("federation registry conflict: {0}")]
    FederationConflict(String),
    /// The token's `sub` was not a well-formed `spiffe://` SPIFFE ID,
    /// or its trust domain could not be extracted.
    #[error("malformed SPIFFE ID: {0}")]
    MalformedSpiffeId(String),
    /// The SPIFFE ID's trust domain is not in the operator-pinned
    /// federation set. Fail-closed: a foreign trust domain we do not
    /// federate with can never authenticate.
    #[error("trust domain {0:?} is not in the federation set")]
    TrustDomainNotFederated(String),
    /// A fetched trust-bundle was rejected as a rollback: its
    /// `spiffe_sequence` was not strictly greater than the
    /// last-accepted sequence. (Anti-rollback hardening; see
    /// `spiffe_federation` module docs.)
    #[error("trust-bundle rollback rejected: fetched seq {fetched} <= last accepted {last}")]
    BundleRollback {
        /// Sequence number on the freshly-fetched bundle.
        fetched: u64,
        /// Sequence number of the last bundle we accepted.
        last: u64,
    },
}
