//! Cart Mandate end-to-end: a human's ES256 signature over an exact cart.
//!
//! AP2's Cart Mandate is `ApprovalBundle` with `manifest_hash` = the cart hash.
//! The unit tests in `nucleus_recompute::cart` cover coverage arithmetic against
//! a *string*; these cover the part that needs real crypto, and in particular
//! the question a capability system must always answer:
//!
//!   **can an attacker obtain a mandate for a cart the human never approved?**
//!
//! A capability test that only shows the happy path proves nothing — the
//! interesting claim is UNOBTAINABILITY, so most of this file is attempts to
//! forge one.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nucleus_identity::JsonWebKey;
use nucleus_identity::approval_bundle::{
    ApprovalBundleBuilder, ApprovalBundleClaims, ApprovalBundleVerifier,
};
use nucleus_recompute::cart::{
    Cart, CartItem, CartOutcome, cart_content_hash_hex, verify_mandate_covers_cart,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};

fn make_key() -> (Vec<u8>, JsonWebKey) {
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();
    let pub_bytes = kp.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
    (pkcs8.as_ref().to_vec(), JsonWebKey::ec_p256(&x, &y))
}

fn cart() -> Cart {
    Cart {
        items: vec![
            CartItem {
                offer_hash_hex: "a".repeat(64),
                quantity: 2,
                unit_price_micro: 300_000,
            },
            CartItem {
                offer_hash_hex: "b".repeat(64),
                quantity: 1,
                unit_price_micro: 400_000,
            },
        ],
        total_micro: 1_000_000,
        currency: "USD".into(),
        payer_spiffe_id: "spiffe://nucleus.local/human/alice".into(),
    }
}

/// Mint a Cart Mandate: an approval bundle whose `manifest_hash` is the cart.
fn mint(cart: &Cart, key: &[u8]) -> String {
    ApprovalBundleBuilder::new("spiffe://nucleus.local/human/alice")
        .approve_operation("purchase")
        .manifest_hash(cart_content_hash_hex(cart))
        .ttl_seconds(300)
        .reason("cart approved by the human")
        .build(key)
        .expect("mandate mints")
}

/// The happy path: a human signs an exact cart, and the verifier confirms both
/// that the signature is theirs and that it covers this cart.
#[test]
fn a_human_signed_mandate_authorizes_its_exact_cart() {
    let (key, jwk) = make_key();
    let c = cart();
    let jws = mint(&c, &key);

    let claims = ApprovalBundleVerifier::new()
        .verify(&jws, &jwk, &cart_content_hash_hex(&c))
        .expect("the human's own mandate verifies");

    assert_eq!(claims.iss, "spiffe://nucleus.local/human/alice");
    assert!(claims.approved_operations.contains("purchase"));
    assert_eq!(
        verify_mandate_covers_cart(&claims.manifest_hash, &c),
        CartOutcome::Match
    );
}

/// **The vacuity check.** A capability is only worth something if it cannot be
/// obtained another way. An attacker who wants a mandate over a cart the human
/// never saw has exactly one option — sign it — and that requires the human's
/// private key.
#[test]
fn a_mandate_for_an_unapproved_cart_is_unobtainable_without_the_humans_key() {
    let (human_key, human_jwk) = make_key();
    let (attacker_key, _attacker_jwk) = make_key();

    let approved = cart();
    let mut attacker_cart = approved.clone();
    attacker_cart.items[0].quantity = 20; // ten times the goods
    attacker_cart.total_micro = 6_400_000;

    // Route 1 — sign it themselves. The signature is real, but it is not the
    // human's, and verification is against the human's key.
    let forged = mint(&attacker_cart, &attacker_key);
    assert!(
        ApprovalBundleVerifier::new()
            .verify(&forged, &human_jwk, &cart_content_hash_hex(&attacker_cart))
            .is_err(),
        "a mandate signed by anyone else must not verify as the human's"
    );

    // Route 2 — reuse the human's genuine mandate for the real cart. The
    // signature verifies, but the bundle covers a different cart.
    let genuine = mint(&approved, &human_key);
    assert!(
        ApprovalBundleVerifier::new()
            .verify(&genuine, &human_jwk, &cart_content_hash_hex(&attacker_cart))
            .is_err(),
        "a genuine mandate must not stretch to another cart"
    );

    // Route 3 — take the human's mandate and edit the hash in the payload. The
    // JWS signature covers the payload, so editing it breaks the signature.
    let mut parts: Vec<String> = genuine.split('.').map(str::to_string).collect();
    let payload = URL_SAFE_NO_PAD.decode(&parts[1]).unwrap();
    let mut claims: ApprovalBundleClaims = serde_json::from_slice(&payload).unwrap();
    claims.manifest_hash = cart_content_hash_hex(&attacker_cart);
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let edited = parts.join(".");
    assert!(
        ApprovalBundleVerifier::new()
            .verify(&edited, &human_jwk, &cart_content_hash_hex(&attacker_cart))
            .is_err(),
        "editing the covered cart must break the signature"
    );

    // And the human's real mandate still works for the cart they actually
    // approved — so the test is not passing because everything fails.
    assert!(
        ApprovalBundleVerifier::new()
            .verify(&genuine, &human_jwk, &cart_content_hash_hex(&approved))
            .is_ok(),
        "the genuine mandate must still authorize the genuine cart"
    );
}

/// The verifier's own hash check and the cart module's coverage check must agree.
/// Two independent paths to the same verdict — if they ever disagree, one of
/// them is lying about what was authorized.
#[test]
fn the_verifier_and_the_cart_module_agree_on_coverage() {
    let (key, jwk) = make_key();
    let approved = cart();
    let jws = mint(&approved, &key);

    let mut other = approved.clone();
    other.items.push(CartItem {
        offer_hash_hex: "c".repeat(64),
        quantity: 1,
        unit_price_micro: 1,
    });
    other.total_micro += 1;

    // Path A: the ES256 verifier, given the other cart's hash as expected.
    let verifier_says = ApprovalBundleVerifier::new()
        .verify(&jws, &jwk, &cart_content_hash_hex(&other))
        .is_ok();

    // Path B: verify against the approved cart, then ask the cart module whether
    // those claims cover the other cart.
    let claims = ApprovalBundleVerifier::new()
        .verify(&jws, &jwk, &cart_content_hash_hex(&approved))
        .expect("genuine");
    let cart_module_says = verify_mandate_covers_cart(&claims.manifest_hash, &other).is_match();

    assert_eq!(verifier_says, cart_module_says, "the two paths must agree");
    assert!(!verifier_says, "and both must say NO");
}
