//! Bridge a [`VerifiedCard`] to the existing bundle verifier's
//! [`nucleus_envelope::TrustAnchor`].
//!
//! This is the join point: once a card is verified (the WHO question is
//! answered), its advertised JWKS becomes the out-of-band trust anchor the
//! recipient uses to decide whether to ACT on a provenance bundle (the
//! WHAT question). A bundle that doesn't verify against this anchor MUST be
//! refused even though the card was perfectly valid — see the negative
//! handshake integration test.

use crate::verify::VerifiedCard;

/// Build a [`nucleus_envelope::TrustAnchor`] from a verified card's
/// advertised JWKS.
///
/// The anchor is the *only* JWKS the recipient will accept bundle
/// signatures against; the bundle's own embedded JWKS is ignored by
/// [`nucleus_envelope::verify_bundle`]. This is what closes the loop: the
/// card said "trust these keys," the card is authentic, so a bundle that
/// doesn't match those keys is not from this agent.
pub fn trust_anchor_from_card(v: &VerifiedCard) -> nucleus_envelope::TrustAnchor {
    nucleus_envelope::TrustAnchor::from_jwks(v.advertised_jwks().clone())
}
