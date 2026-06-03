// SPDX-License-Identifier: MIT
//
//! `nucleus-oidc-core` — provider-agnostic OIDC primitives.
//!
//! Consumed by per-provider validator crates (e.g., a SaaS-specific
//! token validator that registers its `IssuerProvider` impl with the
//! [`FederationRegistry`]) and by `nucleus-oidc-provider`'s token
//! endpoint when validating inbound subject-tokens from external IdPs.
//!
//! # Pieces
//!
//! - [`OidcError`] — shared error variant set.
//! - [`Jwk`] + [`Jwks`] — RFC 7517 wire shapes with both RSA and
//!   Ed25519/OKP (RFC 8037) key extraction; consumer-chosen crypto.
//! - [`KeyResolver`] + [`DiscoveryKeyResolver`] + [`StaticKeyResolver`] —
//!   look up a verifying key by `kid`, fetching JWKS via OIDC discovery
//!   when needed.
//! - [`JtiCache`] — reject replayed tokens within their validity window.
//! - [`FederationRegistry`] + [`IssuerProvider`] trait + [`peek_jwt_issuer`] —
//!   the vendor-neutral half of federation dispatch. Per-provider crates
//!   register their own [`IssuerProvider`] implementations.
//! - [`spiffe_federation`] — inbound SPIFFE Federation: fetch/refresh
//!   trust-domain bundles (`https_web` profile) with anti-rollback, and
//!   validate cross-domain JWT-SVIDs against operator-pinned bundles
//!   (EC/RSA/PS only; the verifying key is chosen solely from the bundle
//!   pinned for the token's trust domain).
//!
//! # Vendor neutrality
//!
//! This crate ships in nucleus (MIT, public). It contains no
//! vendor-specific URLs, names, or token-prefix shapes. Per-provider
//! validators live in vendor-aware sibling crates that depend on this
//! one and register their issuer patterns at startup. See
//! `docs/oidc-vendor-neutrality-audit.md` for the structural rationale.

pub mod error;
pub mod federation;
pub mod jti_cache;
pub mod jwks;
pub mod spiffe_federation;

pub use error::OidcError;
pub use federation::{peek_jwt_issuer, sanitize_scope, FederationRegistry, IssuerProvider};
pub use jti_cache::JtiCache;
pub use jwks::{DiscoveryKeyResolver, Jwk, JwkPublicKey, Jwks, KeyResolver, StaticKeyResolver};
pub use spiffe_federation::{
    BundleFetcher, FederatesWith, FederationStore, Profile, SpiffeBundle, SpiffeId, ALLOWED_ALGS,
    DEFAULT_REFRESH_SECS,
};
