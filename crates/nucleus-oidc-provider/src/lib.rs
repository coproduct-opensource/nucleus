//! `nucleus-oidc-provider` — OIDC Identity Provider (OP) for the nucleus mesh.
//!
//! Mints JWT-SVIDs / OAuth 2.0 access tokens for nucleus pods and
//! performs RFC 8693 token exchange (subject-token = externally-issued
//! SVID → audience-bound token). Peer to `nucleus-verifier-service`:
//! both are public HTTPS services; this one is the identity root, the
//! other validates provenance bundles.
//!
//! # Wire surface (v1)
//!
//! - `GET /.well-known/openid-configuration` — RFC 8414 discovery doc.
//! - `GET /jwks.json` — JSON Web Key Set; the OP's verify-set.
//! - `POST /oauth/token` — RFC 8693 token exchange (subject_token → access_token).
//! - `GET /healthz` — operator-meaningful liveness.
//!
//! # What this service does NOT do
//!
//! - **It does not host user authentication flows.** No browser, no
//!   consent screens, no `/authorize` endpoint. This is a workload-identity
//!   OP; user identity is a relying party's concern.
//! - **It does not store issued tokens.** Stateless mint + verify only.
//!   The replay-defense `JtiCache` (task #42) holds *seen* jtis on the
//!   inbound side, not issued ones.
//! - **It does not perform UI rendering.** Clients are workloads, not
//!   humans; everything is JSON.
//!
//! # Threat model
//!
//! See `THREAT_MODEL.md` in this crate. The 13 enumerated threats
//! (T01-T13) each map to one or more implementing tasks; the threat
//! model is the spec for what this service must defend against.
//!
//! # Module map
//!
//! | Module | Owns |
//! |---|---|
//! | `app` | router assembly, middleware stack |
//! | `routes` | HTTP handlers (delegating to per-endpoint modules) |
//! | `discovery` | `/.well-known/openid-configuration` (RFC 8414) |
//! | `jwks` | `/jwks.json` (RFC 7517) |
//! | `token` | `/oauth/token` (RFC 8693 token-exchange) |
//! | `error` | `OidcApiError` → RFC 6749 / 8693 error responses |
//! | `federation` | trusted-issuer registry + dispatch |
//! | `keystore` | `JwtKeyStore` trait + backends (task #33) |
//! | `spire` | SPIRE Workload API bundle client (task #45) |

pub mod app;
pub mod discovery;
pub mod error;
pub mod federation;
pub mod issuer;
pub mod jwks;
pub mod keystore;
pub mod routes;
pub mod spire;
pub mod token;

/// Re-export the public `JtiCache` so callers don't take a second
/// dependency just to name the cache type. Wire-compatible with the
/// previous local stub (task #42 hardening landed in both impls).
pub use nucleus_oidc_core::JtiCache;

pub use app::{build_app, AppState};
pub use error::OidcApiError;
pub use federation::{
    Decision, DenyReason, FederationError, FederationRegistry, FederationRule, FederationRules,
};
pub use issuer::{
    AccessTokenClaims, BoundaryKind, BoundarySvidRequest, DelegatedActor, JwtIssuer,
    JwtIssuerError, MintRequest, MintedBoundarySvid,
};
