//! Verify-before-you-act identity layer for nucleus agents, on the
//! **A2A protocol v1.0** Agent Card.
//!
//! An [`AgentCard`] is the A2A v1.0 manifest an agent publishes to say WHO
//! it is; nucleus's claims — including which JWKS its provenance bundles
//! are signed under — travel inside the card's extension mechanism as
//! [`NucleusClaims`] (extension URI [`NUCLEUS_EXTENSION_URI`]). This crate
//! signs ([`sign_card`], feature `sign`) and verifies ([`verify_card`])
//! cards per spec §8.4 (detached JWS over RFC 8785 JCS), then derives a
//! [`nucleus_envelope::TrustAnchor`] ([`trust_anchor_from_card`]) so the
//! EXISTING bundle verifier can decide whether to ACT on a bundle.
//!
//! # Trust model — read this before using
//!
//! - **Verify needs no secret.** [`verify_card`] is always compiled and is
//!   secret-free; a browser/WASM verifier can use it directly. Only
//!   [`sign_card`] (behind the non-default `sign` feature) touches a
//!   private key, and it MUST stay server/dev-side — never ship it to a
//!   client.
//!
//! - **NEVER trust a key embedded in the card.** [`verify_card`] reads its
//!   verification key ONLY from the caller's out-of-band-resolved
//!   `resolved_key` argument (DID resolution, a pinned JWKS, an operator
//!   file). It does not read any key — or the protected header's
//!   `kid`/`jku` — from the card or the signature. The claims' `jwks_uri`
//!   is a *hint* for where to resolve the key, not the key itself. (A2A
//!   §8.4.3 permits resolving "from a trusted key store"; that is the only
//!   mode implemented here.)
//!
//! - **This is the WHO-layer, not the WHAT-layer.** Verifying a card
//!   establishes the agent's identity and the JWKS it claims. It does NOT
//!   verify any payload or provenance bundle — that is
//!   [`nucleus_envelope::verify_bundle`]'s job, anchored by the
//!   [`TrustAnchor`](nucleus_envelope::TrustAnchor) this crate derives. A
//!   recipient must do BOTH: verify the card, then refuse to act on any
//!   bundle that doesn't verify against the card's advertised anchor.
//!
//! - **A card verified against an attacker-supplied key is "verified
//!   garbage."** The signature math passes, but it proves nothing about
//!   the agent's identity. The whole guarantee rests on `resolved_key`
//!   coming from a trustworthy out-of-band channel. If the caller resolves
//!   the key from the same place the attacker controls, there is no
//!   security here — by construction, and by design (we refuse to hide that
//!   decision inside the card).
//!
//! # End-to-end shape
//!
//! ```ignore
//! // server side (feature = "sign"):
//! let card = base_card.with_nucleus_claims(&claims)?;
//! let signed = sign_card(card, &pkcs8_der, "card-key-1")?;
//!
//! // recipient side (secret-free):
//! let resolved = resolve_key_out_of_band(did)?; // YOUR job
//! let verified = verify_card(&signed, &resolved)?;
//! let anchor = trust_anchor_from_card(&verified);
//! let report = nucleus_envelope::verify_bundle(&bundle, &anchor)?; // ACT only if this succeeds
//! ```

pub mod anchor;
pub mod card;
#[cfg(feature = "envelope")]
pub mod envelope;
pub mod jcs;
pub mod jwk;
pub mod verify;

#[cfg(feature = "sign")]
pub mod sign;

#[cfg(all(test, feature = "sign"))]
mod sign_verify_tests;

#[cfg(all(test, feature = "sign"))]
mod conformance_tests;

#[cfg(all(test, feature = "sign", feature = "envelope"))]
mod envelope_e2e_tests;

pub use anchor::trust_anchor_from_card;
pub use card::{
    AgentCapabilities, AgentCard, AgentCardSignature, AgentExtension, AgentInterface,
    AgentProvider, AgentSkill, ApiKeySecurityScheme, AuthorizationCodeOAuthFlow,
    ClientCredentialsOAuthFlow, DeviceCodeOAuthFlow, EnforcementRule, HttpAuthSecurityScheme,
    ImplicitOAuthFlow, MutualTlsSecurityScheme, NucleusClaims, OAuth2SecurityScheme, OAuthFlows,
    OpenIdConnectSecurityScheme, PasswordOAuthFlow, RuntimeGuaranteeProfile, SecurityRequirement,
    SecurityScheme, StringList, A2A_PROTOCOL_VERSION, NUCLEUS_EXTENSION_URI,
};
pub use jcs::canonicalize;
pub use jwk::JsonWebKey;
pub use verify::{verify_card, VerifiedCard};

#[cfg(feature = "sign")]
pub use sign::sign_card;

/// Convenience result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the agent-card layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// RFC 8785 JCS canonicalization of the card failed.
    #[error("agent-card canonicalization failed: {0}")]
    Canonicalize(String),

    /// Card verification failed (no signatures, bad signature, payload
    /// mismatch, missing nucleus extension, or unusable advertised JWKS).
    #[error("agent-card verification failed: {0}")]
    Verify(String),

    /// The nucleus extension is declared but malformed (missing params or
    /// params that do not deserialize as [`NucleusClaims`]), or the claims
    /// failed to serialize when attaching them.
    #[error("agent-card nucleus extension error: {0}")]
    Extension(String),

    /// Card signing failed (only reachable with feature `sign`).
    #[error("agent-card signing failed: {0}")]
    Sign(String),
}
