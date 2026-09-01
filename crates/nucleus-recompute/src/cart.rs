//! # Cart mandate — the human authorizes an exact cart, or nothing happens
//!
//! [AP2](https://ap2-protocol.org) defines a **Cart Mandate**: the user's final,
//! explicit authorization for a specific cart at a specific price, signed with a
//! hardware-backed device key so the approval is non-repudiable.
//!
//! Nucleus already has that primitive, under a different name.
//! `nucleus_identity::approval_bundle::ApprovalBundle` is an ES256 JWS carrying
//! a `jti` (anti-replay), an `iss` that is a **human** SPIFFE id
//! (`spiffe://…/human/alice`), an `exp`, and a `manifest_hash` that its verifier
//! checks against a caller-supplied expected value. An AP2 Cart Mandate is that
//! bundle with `manifest_hash` = the hash of the cart.
//!
//! So this module does **not** reimplement mandates. It supplies the two things
//! that were missing: a canonical cart with a stable hash, and the checks that
//! make the binding meaningful.
//!
//! ## Why the cart is hashed rather than described
//!
//! An approval over a *description* ("groceries, about $50") authorizes a range
//! the approver never saw. Hashing the exact line items means a cart that
//! differs by one item, one unit, or one micro-USD is a **different cart** and
//! the mandate simply does not cover it. There is no partial match to argue
//! about at settlement time.
//!
//! ## Order of checks, and why it matters
//!
//! [`verify_cart`] runs **before** any mandate is consulted. A cart whose stated
//! total disagrees with its own line items is malformed, and it must be
//! impossible to get such a cart signed in the first place — otherwise an
//! approver's signature ends up over a total that was never the sum of what they
//! approved. Internal consistency first, authorization second.
//!
//! ## What this does NOT claim
//!
//! **This module verifies no signatures.** It is deliberately wasm-pure so a
//! buyer's browser can recompute its own cart hash, and pulling ES256 in would
//! end that. The signature check stays in `nucleus-identity`, where the crypto
//! already lives; the caller passes the *verified* `manifest_hash` in. That split
//! is the same one `nucleus_ifc::decision` uses so the production gate and the
//! recompute SDK cannot drift.
//!
//! **A mandate proves authorization, not delivery.** That the human approved
//! this cart says nothing about whether the goods arrived — that is what the
//! settlement's `delivered_bps` is for, one layer down.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ClearingReceipt;

/// Domain separator for the canonical cart bytes (versioned).
const CART_DOMAIN: &[u8] = b"nucleus-recompute/cart/v1\0";

/// One line of a cart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CartItem {
    /// The offer being bought, by content hash — not a name or a description.
    /// Two offers with the same title and different terms are different items.
    pub offer_hash_hex: String,
    /// How many.
    pub quantity: u32,
    /// Price per unit, micro-USD.
    pub unit_price_micro: u64,
}

/// An exact cart, as approved by a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cart {
    /// The line items. Order is part of the hash: a reordered cart is a
    /// different cart, which is stricter than necessary but avoids arguing about
    /// canonical ordering at settlement time.
    pub items: Vec<CartItem>,
    /// The total the approver was shown, micro-USD. Checked against the lines
    /// rather than trusted — see [`verify_cart`].
    pub total_micro: u64,
    /// Currency tag. Only `"USD"` is meaningful today; carried so a future
    /// currency cannot be silently reinterpreted as this one.
    pub currency: String,
    /// Who is paying, as a SPIFFE id.
    pub payer_spiffe_id: String,
}

/// The result of checking a cart, and of checking a mandate against one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CartOutcome {
    /// The cart is internally consistent and, where checked, authorized.
    Match,
    /// A cart with no items cannot be approved. An empty approval is a blank
    /// cheque with a signature on it.
    Empty,
    /// The stated total is not the sum of the line items.
    TotalMismatch {
        /// What the cart claims.
        claimed: u64,
        /// What the lines actually sum to.
        recomputed: u64,
    },
    /// A line item's `quantity × unit_price` (or the running sum) overflowed.
    /// Rejected rather than saturated: a saturated total is a wrong number that
    /// looks like a right one.
    Overflow,
    /// The mandate does not authorize this cart. The mandate's hash covers some
    /// other cart — one item different, one unit different, one micro-USD
    /// different, all the same verdict.
    NotAuthorized {
        /// The cart hash the mandate carries.
        mandate_covers: String,
        /// The hash of the cart actually presented.
        cart_is: String,
    },
    /// The cart's total does not match the amount actually being cleared.
    ClearingMismatch {
        /// The approved cart total.
        cart_total_micro: u64,
        /// The price the clearing settles.
        clearing_price_micro: u64,
    },
}

impl CartOutcome {
    /// `true` only for [`CartOutcome::Match`].
    pub fn is_match(&self) -> bool {
        matches!(self, CartOutcome::Match)
    }
}

/// Sum the line items, or `None` on overflow.
///
/// Checked arithmetic throughout: `quantity` is a `u32` and prices are
/// micro-USD, so a hostile cart can reach `u64::MAX` easily, and a wrapped or
/// saturated total is a wrong number wearing the costume of a right one.
pub fn cart_total_micro(cart: &Cart) -> Option<u64> {
    let mut sum: u64 = 0;
    for item in &cart.items {
        let line = u64::from(item.quantity).checked_mul(item.unit_price_micro)?;
        sum = sum.checked_add(line)?;
    }
    Some(sum)
}

/// Check a cart against itself: non-empty, and its stated total is the sum of
/// its lines.
///
/// This runs before authorization is considered. It must be impossible to get a
/// cart signed whose total was never the sum of what it contains.
pub fn verify_cart(cart: &Cart) -> CartOutcome {
    if cart.items.is_empty() {
        return CartOutcome::Empty;
    }
    match cart_total_micro(cart) {
        None => CartOutcome::Overflow,
        Some(sum) if sum != cart.total_micro => CartOutcome::TotalMismatch {
            claimed: cart.total_micro,
            recomputed: sum,
        },
        Some(_) => CartOutcome::Match,
    }
}

/// Canonical, domain-tagged bytes for a cart.
pub fn cart_canonical_bytes(cart: &Cart) -> Vec<u8> {
    let mut out = Vec::with_capacity(CART_DOMAIN.len() + 256);
    out.extend_from_slice(CART_DOMAIN);
    // Infallible for this concrete, map-free type.
    serde_json::to_writer(&mut out, cart).expect("cart serialization is infallible");
    out
}

/// `sha256` over [`cart_canonical_bytes`], hex-encoded.
///
/// **This is the value that goes in a Cart Mandate's `manifest_hash`.** Pass it
/// to `ApprovalBundleVerifier::verify` as the expected hash and the existing
/// verifier does the binding check; a mandate over any other cart fails there.
pub fn cart_content_hash_hex(cart: &Cart) -> String {
    let mut h = Sha256::new();
    h.update(cart_canonical_bytes(cart));
    hex::encode(h.finalize())
}

/// Does a mandate authorize this exact cart?
///
/// `mandate_manifest_hash` must come from a bundle whose **signature has already
/// been verified** — this function checks coverage, not authenticity, and cannot
/// tell a real mandate from a string. Verify first, then call this.
///
/// The cart is checked against itself first: an inconsistent cart is rejected
/// even if a mandate happens to cover it, because a signature over a malformed
/// cart is worth nothing.
pub fn verify_mandate_covers_cart(mandate_manifest_hash: &str, cart: &Cart) -> CartOutcome {
    match verify_cart(cart) {
        CartOutcome::Match => {}
        other => return other,
    }
    let cart_is = cart_content_hash_hex(cart);
    if mandate_manifest_hash != cart_is {
        return CartOutcome::NotAuthorized {
            mandate_covers: mandate_manifest_hash.to_string(),
            cart_is,
        };
    }
    CartOutcome::Match
}

/// Does the approved cart match what is actually being charged?
///
/// Closes the last gap between authorization and money: a mandate can cover a
/// cart perfectly while the clearing settles a different price. Only
/// [`ClearingReceipt::Settlement`] is meaningful here — a commons routing or a
/// VCG clearing is not "the price of this cart".
pub fn verify_cart_matches_clearing(cart: &Cart, clearing: &ClearingReceipt) -> CartOutcome {
    match verify_cart(cart) {
        CartOutcome::Match => {}
        other => return other,
    }
    let ClearingReceipt::Settlement(s) = clearing else {
        return CartOutcome::ClearingMismatch {
            cart_total_micro: cart.total_micro,
            clearing_price_micro: 0,
        };
    };
    if s.price_micro != cart.total_micro {
        return CartOutcome::ClearingMismatch {
            cart_total_micro: cart.total_micro,
            clearing_price_micro: s.price_micro,
        };
    }
    CartOutcome::Match
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(offer: &str, qty: u32, price: u64) -> CartItem {
        CartItem {
            offer_hash_hex: offer.repeat(64 / offer.len().max(1)),
            quantity: qty,
            unit_price_micro: price,
        }
    }

    fn cart() -> Cart {
        Cart {
            items: vec![item("a", 2, 300_000), item("b", 1, 400_000)],
            total_micro: 1_000_000,
            currency: "USD".into(),
            payer_spiffe_id: "spiffe://nucleus.local/human/alice".into(),
        }
    }

    #[test]
    fn a_consistent_cart_verifies_and_its_mandate_covers_it() {
        let c = cart();
        assert_eq!(verify_cart(&c), CartOutcome::Match);
        let mandate = cart_content_hash_hex(&c);
        assert_eq!(verify_mandate_covers_cart(&mandate, &c), CartOutcome::Match);
    }

    /// **The bite.** A mandate is approval for ONE cart. Replaying it against a
    /// cart with an extra item — the classic "add to the order after the human
    /// clicked approve" — is not covered.
    #[test]
    fn a_mandate_does_not_cover_a_cart_with_an_added_item() {
        let approved = cart();
        let mandate = cart_content_hash_hex(&approved);

        let mut tampered = approved.clone();
        tampered.items.push(item("c", 1, 500_000));
        tampered.total_micro += 500_000; // kept internally consistent, on purpose

        assert_eq!(
            verify_cart(&tampered),
            CartOutcome::Match,
            "the tamper is well-formed"
        );
        match verify_mandate_covers_cart(&mandate, &tampered) {
            CartOutcome::NotAuthorized { .. } => {}
            other => panic!("an added item must not be authorized, got {other:?}"),
        }
    }

    /// One micro-USD is enough. There is no "close enough" cart.
    ///
    /// The nudge is applied to the quantity-1 line and the total moved by the
    /// same 1, so the cart stays INTERNALLY CONSISTENT. An earlier version
    /// nudged the quantity-2 line by 1 and the total by 1, which made the cart
    /// fail `verify_cart` first — so the test passed without ever exercising the
    /// hash comparison, and stayed green when that comparison was deleted.
    #[test]
    fn one_micro_usd_of_difference_is_a_different_cart() {
        let approved = cart();
        let mandate = cart_content_hash_hex(&approved);

        let mut nudged = approved.clone();
        nudged.items[1].unit_price_micro += 1; // quantity 1, so total moves by 1
        nudged.total_micro += 1;

        assert_eq!(
            verify_cart(&nudged),
            CartOutcome::Match,
            "the nudged cart must be well-formed, or this tests the wrong thing"
        );
        match verify_mandate_covers_cart(&mandate, &nudged) {
            CartOutcome::NotAuthorized { .. } => {}
            other => panic!("one micro-USD is a different cart, got {other:?}"),
        }
    }

    /// A cart whose stated total is not the sum of its lines must be rejected
    /// BEFORE authorization is considered — otherwise a human's signature ends
    /// up over a total that was never what they approved.
    #[test]
    fn an_inconsistent_cart_is_rejected_before_the_mandate_is_consulted() {
        let mut lying = cart();
        lying.total_micro = 10; // the human is shown 0.00001 USD, the lines say 1.00

        // Even with a mandate that covers this exact byte-string, it fails.
        let mandate = cart_content_hash_hex(&lying);
        match verify_mandate_covers_cart(&mandate, &lying) {
            CartOutcome::TotalMismatch {
                claimed,
                recomputed,
            } => {
                assert_eq!(claimed, 10);
                assert_eq!(recomputed, 1_000_000);
            }
            other => panic!("a lying cart must not be authorizable, got {other:?}"),
        }
    }

    /// An empty approval is a blank cheque with a signature on it.
    #[test]
    fn an_empty_cart_cannot_be_approved() {
        let mut empty = cart();
        empty.items.clear();
        empty.total_micro = 0;
        assert_eq!(verify_cart(&empty), CartOutcome::Empty);
    }

    /// A hostile cart reaches u64::MAX easily. Overflow is rejected, never
    /// saturated — a saturated total is a wrong number that looks right.
    #[test]
    fn an_overflowing_cart_is_rejected_not_saturated() {
        let mut huge = cart();
        huge.items = vec![item("a", u32::MAX, u64::MAX / 2)];
        assert_eq!(verify_cart(&huge), CartOutcome::Overflow);
        assert_eq!(cart_total_micro(&huge), None);
    }

    /// The last gap: a mandate can cover a cart perfectly while the clearing
    /// settles a different price.
    #[test]
    fn a_clearing_at_the_wrong_price_is_caught() {
        let c = cart();
        let right = crate::issue_settlement(1_000_000, 10_000);
        assert_eq!(verify_cart_matches_clearing(&c, &right), CartOutcome::Match);

        let wrong = crate::issue_settlement(1_500_000, 10_000);
        match verify_cart_matches_clearing(&c, &wrong) {
            CartOutcome::ClearingMismatch {
                cart_total_micro,
                clearing_price_micro,
            } => {
                assert_eq!(cart_total_micro, 1_000_000);
                assert_eq!(clearing_price_micro, 1_500_000);
            }
            other => panic!("a price change must be caught, got {other:?}"),
        }
    }

    /// Reordering the lines produces a different cart. Stricter than strictly
    /// necessary, and deliberately so: it removes any argument about canonical
    /// ordering at settlement time.
    #[test]
    fn reordering_the_lines_changes_the_cart() {
        let a = cart();
        let mut b = a.clone();
        b.items.reverse();
        assert_ne!(cart_content_hash_hex(&a), cart_content_hash_hex(&b));
    }

    /// The payer is inside the commitment: a mandate cannot be lifted onto
    /// someone else's account.
    #[test]
    fn the_payer_is_part_of_the_cart() {
        let a = cart();
        let mut b = a.clone();
        b.payer_spiffe_id = "spiffe://nucleus.local/human/mallory".into();
        assert_ne!(cart_content_hash_hex(&a), cart_content_hash_hex(&b));
    }
}
