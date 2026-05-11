//! [`IdentityFetcher`] — pluggable issuer for JWT-SVIDs scoped to a
//! [`CallSpiffeId`].
//!
//! Trait + claims + error type have no crypto dependency and are always
//! available. The in-process demo issuer ([`LocalIssuer`]) is only compiled
//! when the non-default `dev` feature is enabled, so production binaries
//! cannot accidentally link or re-export it.
//!
//! Production callers should write a `SpiffeWorkloadApi` impl (typically in
//! the same crate as their SPIRE Agent integration) and provide it to the
//! runtime via this trait. No such impl ships in this repo today.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::id::CallSpiffeId;

/// Errors a JWT-SVID issuer may surface.
///
/// Backend-specific failures are stringified rather than typed so this trait
/// stays free of any specific JWT library dependency.
#[derive(Debug, Error)]
pub enum IssuerError {
    #[error("issuer backend error: {0}")]
    Backend(String),
    #[error("system clock before unix epoch")]
    Clock,
    #[error("key encoding error: {0}")]
    KeyEncoding(String),
}

/// Standard JWT-SVID claims, plus a short-form `nucleus_kind` for routing.
///
/// Wire-compatible with what a SPIRE-issued JWT-SVID would carry: the
/// non-standard claims live alongside the SPIFFE-required `sub`, `aud`,
/// `iss`, `iat`, `exp`, `jti`. Relying parties that only inspect standard
/// claims will round-trip unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SvidClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    /// Optional: a kind hint set by the issuer (e.g. "tool_call", "llm_call").
    /// Useful for routing/audit but not part of the SPIFFE JWT-SVID spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nucleus_kind: Option<String>,
}

/// Pluggable JWT-SVID issuer.
///
/// Implementations must be safe to call concurrently (`&self`).
pub trait IdentityFetcher: Send + Sync {
    /// Mint a JWT-SVID with the given subject SPIFFE ID and audience. The
    /// returned string is a compact JWS (three base64url segments separated
    /// by `.`).
    fn fetch_jwt_svid(&self, subject: &CallSpiffeId, audience: &str)
        -> Result<String, IssuerError>;

    /// Optional kind hint; defaults to `None`. Issuers may attach this to
    /// the `nucleus_kind` claim.
    fn fetch_jwt_svid_with_kind(
        &self,
        subject: &CallSpiffeId,
        audience: &str,
        _kind: Option<&str>,
    ) -> Result<String, IssuerError> {
        self.fetch_jwt_svid(subject, audience)
    }
}

/// Sign canonical edge bytes to produce a [`crate::Proof`].
///
/// Separated from [`IdentityFetcher`] because edge signing and JWT-SVID
/// minting can have distinct lifecycles — e.g., an issuer may want to sign
/// edges with a long-lived key while minting JWT-SVIDs with a per-call key.
/// The default impl on [`IdentityFetcher`] is intentionally absent so each
/// issuer makes the choice deliberately.
pub trait EdgeSigner: Send + Sync {
    /// JWS algorithm identifier this signer uses (e.g., "EdDSA").
    fn alg(&self) -> &str;

    /// JWS key id this signer uses; resolves to a verifying key in the JWKS.
    fn kid(&self) -> &str;

    /// Sign the given canonical bytes. Returns the raw signature bytes.
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, IssuerError>;
}
