//! # Offer — the thing `offer_hash_hex` has been pointing at
//!
//! [`Attribution::offer_hash_hex`](crate::payout::Attribution) and
//! [`CartItem::offer_hash_hex`](crate::cart::CartItem) both identify an offer by
//! content hash. Until now there was no offer type: every production occurrence
//! of that field was an empty string, and every other was a test literal. Three
//! shipped slices carried a dangling reference.
//!
//! ## Sponsorship is stated, never omitted
//!
//! [`Sponsorship`] is a required field, and "not sponsored" is a *value* —
//! [`SponsorshipKind::Organic`] — rather than an absent field. That distinction
//! is the whole point. An `Option<Sponsorship>` can be forgotten; a required
//! enum cannot. Whoever publishes an offer has to say what it is, and saying
//! "organic" is an assertion they made rather than a default they inherited.
//!
//! This is the same move the IFC label makes one layer down: make the dishonest
//! state unrepresentable instead of policing it. AdCP's documentation says the
//! protocol carries *"no technical proof that sponsorship labeling happened"*;
//! here it is not possible to construct an offer that has not answered.
//!
//! ## What binding the hash buys
//!
//! [`offer_content_hash_hex`] covers the price, the sponsorship, the disclosure
//! and the terms. So a payout naming an offer names the *exact* commercial terms
//! that were transacted — a seller cannot re-price after the fact, or quietly
//! reclassify a paid placement as organic, without producing a different hash
//! and breaking every receipt that cited the old one.
//!
//! [`verify_cart_offers`] closes the remaining gap: a cart may not cite an offer
//! at a price that offer does not have.
//!
//! ## What this does NOT claim
//!
//! **No signatures.** Deliberately wasm-pure so a buyer's browser recomputes the
//! offer hash; publishing an offer signed is `nucleus-agent-card`'s job, and the
//! skill itself is referenced by card hash rather than embedded so this stays in
//! the light dependency closure.
//!
//! **Disclosure text is checked for presence, not adequacy.** A sponsored offer
//! must carry non-empty disclosure, and that text is inside the hash so it cannot
//! be swapped later. Whether the wording satisfies the FTC's 2026 requirement to
//! disclose *both* the sponsorship and the AI involvement is a human judgement no
//! hash can make, and this module does not pretend otherwise.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cart::Cart;

/// Domain separator for the canonical offer bytes (versioned).
const OFFER_DOMAIN: &[u8] = b"nucleus-recompute/offer/v1\0";

/// Domain separator for an offer's disclosure record.
const DISCLOSURE_DOMAIN: &[u8] = b"nucleus-recompute/offer-disclosure/v1\0";

/// What commercial relationship placed this offer in front of the model.
///
/// There is no "unspecified": a publisher answers, and `Organic` is an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipKind {
    /// Nobody paid for this placement.
    Organic,
    /// Paid to appear at all.
    PaidPlacement,
    /// Paid to appear higher than merit alone would put it.
    PaidRanking,
    /// The publisher earns a share of the resulting purchase.
    Affiliate,
}

impl SponsorshipKind {
    /// Does this kind involve money changing hands for the placement?
    ///
    /// Everything except [`Organic`](Self::Organic) requires a named sponsor and
    /// disclosure text.
    pub fn is_paid(self) -> bool {
        !matches!(self, SponsorshipKind::Organic)
    }
}

/// The sponsorship status of an offer. Required, never optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sponsorship {
    /// What the commercial relationship is.
    pub kind: SponsorshipKind,
    /// Who paid, when anyone did. Must be non-empty unless `kind` is `Organic`.
    pub sponsor: String,
    /// The disclosure a human must be shown. Must be non-empty unless `kind` is
    /// `Organic`. Inside the offer hash, so it cannot be softened after the fact.
    pub disclosure: String,
}

impl Sponsorship {
    /// An unsponsored offer. Named so the honest case is as easy to write as the
    /// dishonest one would have been to forget.
    pub fn organic() -> Self {
        Self {
            kind: SponsorshipKind::Organic,
            sponsor: String::new(),
            disclosure: String::new(),
        }
    }

    /// A paid placement, with its sponsor and the disclosure text.
    pub fn paid(
        kind: SponsorshipKind,
        sponsor: impl Into<String>,
        disclosure: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            sponsor: sponsor.into(),
            disclosure: disclosure.into(),
        }
    }
}

/// The terms attached to an offer beyond its price.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Terms {
    /// Whether the purchase can be refunded, and under what condition.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refund_policy: String,
    /// How long the offer stands, as a Unix timestamp. `0` = no stated expiry.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub valid_until_unix: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// A purchasable capability at a stated price, with its sponsorship declared.
///
/// The capability is referenced by `(skill_id, skill_card_hash_hex)` rather than
/// embedded: the describing `AgentCard` is already a signed, content-addressed
/// artifact, and duplicating it here would both bloat the offer and create a
/// second place for the description to drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// Publisher-assigned identifier, unique within the seller.
    pub offer_id: String,
    /// SPIFFE id of the seller.
    pub seller_spiffe_id: String,
    /// The `AgentSkill.id` being sold.
    pub skill_id: String,
    /// SHA-256 of the `AgentCard` that describes that skill. Pins the
    /// description: a card edited after the offer was published no longer
    /// matches.
    pub skill_card_hash_hex: String,
    /// Price, micro-USD. Zero is allowed — a free tier is an offer.
    pub price_micro: u64,
    /// Currency tag. Only `"USD"` is meaningful today; carried so a future
    /// currency cannot be silently reinterpreted as this one.
    pub currency: String,
    /// Required. See the module docs.
    pub sponsorship: Sponsorship,
    /// Refund policy, validity.
    pub terms: Terms,
}

impl Offer {
    /// Construct an offer.
    ///
    /// `sponsorship` is taken **by value and not by `Option`**: there is no way
    /// to build an `Offer` without answering the sponsorship question. Use
    /// [`Sponsorship::organic`] to say "nobody paid" — which is an assertion,
    /// not a default.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offer_id: impl Into<String>,
        seller_spiffe_id: impl Into<String>,
        skill_id: impl Into<String>,
        skill_card_hash_hex: impl Into<String>,
        price_micro: u64,
        currency: impl Into<String>,
        sponsorship: Sponsorship,
        terms: Terms,
    ) -> Self {
        Self {
            offer_id: offer_id.into(),
            seller_spiffe_id: seller_spiffe_id.into(),
            skill_id: skill_id.into(),
            skill_card_hash_hex: skill_card_hash_hex.into(),
            price_micro,
            currency: currency.into(),
            sponsorship,
            terms,
        }
    }
}

/// Why an offer is not well-formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferOutcome {
    /// The offer is well-formed.
    Match,
    /// A paid placement with no named sponsor. "Someone paid, undisclosed who"
    /// is exactly the state disclosure exists to prevent.
    PaidWithoutSponsor,
    /// A paid placement with no disclosure text.
    PaidWithoutDisclosure,
    /// An `Organic` offer that nonetheless names a sponsor or carries disclosure
    /// text — the fields contradict the declared kind, and a reader cannot tell
    /// which to believe.
    OrganicButSponsored,
    /// A required identifier is empty.
    MissingField {
        /// Which one.
        field: &'static str,
    },
}

impl OfferOutcome {
    /// `true` only for [`OfferOutcome::Match`].
    pub fn is_match(&self) -> bool {
        matches!(self, OfferOutcome::Match)
    }
}

/// Check an offer against itself.
///
/// The sponsorship rules are the load-bearing part: a paid placement must name
/// its sponsor and carry disclosure, and an organic one must not carry either.
/// Both directions matter — a "sponsored" flag with no sponsor is unactionable,
/// and an "organic" offer carrying a sponsor's name is self-contradictory.
pub fn verify_offer(offer: &Offer) -> OfferOutcome {
    for (field, value) in [
        ("offer_id", &offer.offer_id),
        ("seller_spiffe_id", &offer.seller_spiffe_id),
        ("skill_id", &offer.skill_id),
        ("currency", &offer.currency),
    ] {
        if value.is_empty() {
            return OfferOutcome::MissingField { field };
        }
    }

    let s = &offer.sponsorship;
    if s.kind.is_paid() {
        if s.sponsor.trim().is_empty() {
            return OfferOutcome::PaidWithoutSponsor;
        }
        if s.disclosure.trim().is_empty() {
            return OfferOutcome::PaidWithoutDisclosure;
        }
    } else if !s.sponsor.trim().is_empty() || !s.disclosure.trim().is_empty() {
        return OfferOutcome::OrganicButSponsored;
    }
    OfferOutcome::Match
}

/// Canonical, domain-tagged bytes for an offer.
pub fn offer_canonical_bytes(offer: &Offer) -> Vec<u8> {
    let mut out = Vec::with_capacity(OFFER_DOMAIN.len() + 512);
    out.extend_from_slice(OFFER_DOMAIN);
    // Infallible for this concrete, map-free type.
    serde_json::to_writer(&mut out, offer).expect("offer serialization is infallible");
    out
}

/// `sha256` over [`offer_canonical_bytes`], hex-encoded.
///
/// **This is the value that belongs in `Attribution.offer_hash_hex` and
/// `CartItem.offer_hash_hex`.** It covers the price, the sponsorship and the
/// terms, so a seller cannot re-price or reclassify after the fact without
/// breaking every receipt that cited the old offer.
pub fn offer_content_hash_hex(offer: &Offer) -> String {
    let mut h = Sha256::new();
    h.update(offer_canonical_bytes(offer));
    hex::encode(h.finalize())
}

/// `sha256` over the offer's disclosure record — the value that belongs in
/// `Attribution.disclosure_hash_hex` and in a `FlowDeclaration`'s
/// `disclosure_hash_hex`.
///
/// Separately domain-separated from the offer hash so the two can never collide,
/// and so a disclosure can be shown and checked without revealing the price.
pub fn disclosure_hash_hex(offer: &Offer) -> String {
    let mut h = Sha256::new();
    h.update(DISCLOSURE_DOMAIN);
    h.update(offer.sponsorship.kind.token().as_bytes());
    h.update([0]);
    h.update(offer.sponsorship.sponsor.as_bytes());
    h.update([0]);
    h.update(offer.sponsorship.disclosure.as_bytes());
    hex::encode(h.finalize())
}

impl SponsorshipKind {
    /// Stable wire token, used in the disclosure preimage.
    pub fn token(self) -> &'static str {
        match self {
            SponsorshipKind::Organic => "organic",
            SponsorshipKind::PaidPlacement => "paid_placement",
            SponsorshipKind::PaidRanking => "paid_ranking",
            SponsorshipKind::Affiliate => "affiliate",
        }
    }
}

/// Why a cart's items do not match the offers they cite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CartOffersOutcome {
    /// Every item cites a supplied offer, at that offer's price.
    Match,
    /// An item cites an offer hash that none of the supplied offers produces.
    UnknownOffer {
        /// The hash cited.
        offer_hash_hex: String,
    },
    /// An item cites a real offer but at a different unit price than the offer
    /// states. This is the case that matters: it is how a cart quietly re-prices
    /// a legitimate offer.
    PriceMismatch {
        /// The offer cited.
        offer_hash_hex: String,
        /// The price the cart claims.
        cart_price_micro: u64,
        /// The price the offer states.
        offer_price_micro: u64,
    },
    /// One of the supplied offers is not itself well-formed.
    MalformedOffer(OfferOutcome),
}

/// Check that every cart item cites a supplied offer, at that offer's price.
///
/// This is what makes `CartItem.offer_hash_hex` load-bearing rather than
/// decorative. Without it a cart can name any hash it likes and set its own unit
/// price; with it, a cart is a selection *from* a published price list and the
/// human's mandate covers terms the seller actually published.
pub fn verify_cart_offers(cart: &Cart, offers: &[Offer]) -> CartOffersOutcome {
    // A malformed offer cannot license anything, so it is rejected before the
    // cart is compared against it.
    for o in offers {
        let v = verify_offer(o);
        if !v.is_match() {
            return CartOffersOutcome::MalformedOffer(v);
        }
    }
    let indexed: Vec<(String, &Offer)> = offers
        .iter()
        .map(|o| (offer_content_hash_hex(o), o))
        .collect();

    for item in &cart.items {
        let Some((_, offer)) = indexed.iter().find(|(h, _)| *h == item.offer_hash_hex) else {
            return CartOffersOutcome::UnknownOffer {
                offer_hash_hex: item.offer_hash_hex.clone(),
            };
        };
        if item.unit_price_micro != offer.price_micro {
            return CartOffersOutcome::PriceMismatch {
                offer_hash_hex: item.offer_hash_hex.clone(),
                cart_price_micro: item.unit_price_micro,
                offer_price_micro: offer.price_micro,
            };
        }
    }
    CartOffersOutcome::Match
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cart::{Cart, CartItem};

    fn organic_offer() -> Offer {
        Offer::new(
            "offer-1",
            "spiffe://vendor.example/seller",
            "summarise",
            "c".repeat(64),
            500_000,
            "USD",
            Sponsorship::organic(),
            Terms::default(),
        )
    }

    fn sponsored_offer() -> Offer {
        Offer::new(
            "offer-2",
            "spiffe://vendor.example/seller",
            "summarise",
            "c".repeat(64),
            500_000,
            "USD",
            Sponsorship::paid(
                SponsorshipKind::PaidPlacement,
                "AcmeCorp",
                "Sponsored by AcmeCorp. Placement paid for; ranking unaffected.",
            ),
            Terms::default(),
        )
    }

    #[test]
    fn a_well_formed_offer_verifies_in_both_sponsorship_directions() {
        assert_eq!(verify_offer(&organic_offer()), OfferOutcome::Match);
        assert_eq!(verify_offer(&sponsored_offer()), OfferOutcome::Match);
    }

    /// **Bite 1.** "Someone paid, undisclosed who" is exactly the state
    /// disclosure exists to prevent.
    #[test]
    fn a_paid_placement_without_a_sponsor_or_disclosure_is_rejected() {
        let mut no_sponsor = sponsored_offer();
        no_sponsor.sponsorship.sponsor = "   ".into();
        assert_eq!(verify_offer(&no_sponsor), OfferOutcome::PaidWithoutSponsor);

        let mut no_text = sponsored_offer();
        no_text.sponsorship.disclosure = String::new();
        assert_eq!(verify_offer(&no_text), OfferOutcome::PaidWithoutDisclosure);
    }

    /// The other direction, which is easy to forget: an offer declaring itself
    /// organic while naming a sponsor is self-contradictory, and a reader cannot
    /// tell which half to believe.
    #[test]
    fn an_organic_offer_that_names_a_sponsor_is_rejected() {
        let mut contradictory = organic_offer();
        contradictory.sponsorship.sponsor = "AcmeCorp".into();
        assert_eq!(
            verify_offer(&contradictory),
            OfferOutcome::OrganicButSponsored
        );
    }

    /// **Bite 2.** Every commercial term is inside the hash, so a seller cannot
    /// re-price or reclassify after the fact without breaking every receipt that
    /// cited the old offer.
    #[test]
    fn changing_any_commercial_term_changes_the_offer_hash() {
        let base = sponsored_offer();
        let h = offer_content_hash_hex(&base);

        let mut repriced = base.clone();
        repriced.price_micro += 1;
        assert_ne!(h, offer_content_hash_hex(&repriced), "price is bound");

        let mut relabelled = base.clone();
        relabelled.sponsorship.kind = SponsorshipKind::Organic;
        relabelled.sponsorship.sponsor = String::new();
        relabelled.sponsorship.disclosure = String::new();
        assert_ne!(
            h,
            offer_content_hash_hex(&relabelled),
            "reclassifying paid as organic is bound"
        );

        let mut softened = base.clone();
        softened.sponsorship.disclosure = "Ad.".into();
        assert_ne!(
            h,
            offer_content_hash_hex(&softened),
            "disclosure text is bound"
        );

        let mut retermed = base;
        retermed.terms.refund_policy = "no refunds".into();
        assert_ne!(h, offer_content_hash_hex(&retermed), "terms are bound");
    }

    /// The disclosure hash is separately domain-separated: it can be shown and
    /// checked without revealing the price, and can never collide with the offer
    /// hash.
    #[test]
    fn the_disclosure_hash_is_independent_of_the_price() {
        let a = sponsored_offer();
        let mut b = a.clone();
        b.price_micro += 100_000;

        assert_eq!(
            disclosure_hash_hex(&a),
            disclosure_hash_hex(&b),
            "the disclosure did not change, so its hash must not"
        );
        assert_ne!(disclosure_hash_hex(&a), offer_content_hash_hex(&a));
    }

    fn cart_for(offer: &Offer, qty: u32, unit: u64) -> Cart {
        Cart {
            items: vec![CartItem {
                offer_hash_hex: offer_content_hash_hex(offer),
                quantity: qty,
                unit_price_micro: unit,
            }],
            total_micro: u64::from(qty) * unit,
            currency: "USD".into(),
            payer_spiffe_id: "spiffe://nucleus.local/human/alice".into(),
        }
    }

    #[test]
    fn a_cart_citing_a_real_offer_at_its_real_price_verifies() {
        let o = sponsored_offer();
        let c = cart_for(&o, 2, 500_000);
        assert_eq!(verify_cart_offers(&c, &[o]), CartOffersOutcome::Match);
    }

    /// **Bite 3.** A cart citing an offer nobody published is not a selection
    /// from a price list — it is a number the buyer was handed.
    #[test]
    fn a_cart_citing_an_offer_that_does_not_exist_is_rejected() {
        let o = sponsored_offer();
        let mut c = cart_for(&o, 1, 500_000);
        c.items[0].offer_hash_hex = "f".repeat(64);

        match verify_cart_offers(&c, &[o]) {
            CartOffersOutcome::UnknownOffer { .. } => {}
            other => panic!("expected UnknownOffer, got {other:?}"),
        }
    }

    /// The case that makes `offer_hash_hex` load-bearing rather than
    /// decorative: a cart quietly re-pricing a legitimate offer.
    #[test]
    fn a_cart_repricing_a_real_offer_is_caught() {
        let o = sponsored_offer();
        let c = cart_for(&o, 1, 900_000); // the offer says 500_000

        match verify_cart_offers(&c, &[o]) {
            CartOffersOutcome::PriceMismatch {
                cart_price_micro,
                offer_price_micro,
                ..
            } => {
                assert_eq!(cart_price_micro, 900_000);
                assert_eq!(offer_price_micro, 500_000);
            }
            other => panic!("a re-priced cart must be caught, got {other:?}"),
        }
    }

    /// A malformed offer cannot license a cart, even one that cites it exactly.
    #[test]
    fn a_malformed_offer_licenses_nothing() {
        let mut broken = sponsored_offer();
        broken.sponsorship.disclosure = String::new();
        let c = cart_for(&broken, 1, 500_000);

        assert!(matches!(
            verify_cart_offers(&c, &[broken]),
            CartOffersOutcome::MalformedOffer(OfferOutcome::PaidWithoutDisclosure)
        ));
    }

    /// A free offer is an offer: price zero is legitimate and must not be
    /// mistaken for a missing field.
    #[test]
    fn a_free_offer_is_well_formed() {
        let mut free = organic_offer();
        free.price_micro = 0;
        assert_eq!(verify_offer(&free), OfferOutcome::Match);
        assert_eq!(
            verify_cart_offers(&cart_for(&free, 3, 0), &[free.clone()]),
            CartOffersOutcome::Match
        );
    }
}
