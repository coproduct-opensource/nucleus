//! Outbound assertions: what they claim, that they verify under the key we
//! publish, and that the key id is the one a provider will compute.

use std::collections::HashSet;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use nucleus_federation::{
    AssertionClaims, AssertionSigner, AssertionSubject, ClaimsError, DEFAULT_TTL, EcdsaP256Signer,
    MAX_TTL, SIGNING_ALG, SignError, mint,
};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

/// A P-256 PKCS#8 key generated with `openssl genpkey -algorithm EC
/// -pkeyopt ec_paramgen_curve:P-256` for this test only.
const FIXTURE_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9M7KfRr+h4OkUtQyi+yEiLujfq+fWvltVdraE3eQdd2hRANCAATBgIhx1QqON+ox2mxARGiL7hcWbmXCq8P2Sngwt/tTYOXjwWnPytVCd5oPiSYdNq5LJQ7WKxda8qZYoJLwxyrt";
/// The fixture's public coordinates, extracted with `openssl ec -pubout`.
const FIXTURE_X: &str = "wYCIcdUKjjfqMdpsQERoi-4XFm5lwqvD9kp4MLf7U2A";
const FIXTURE_Y: &str = "5ePBac_K1UJ3mg-JJh02rkslDtYrF1rypligkvDHKu0";
/// RFC 7638 thumbprint of the fixture, computed independently of this crate
/// (Python `hashlib.sha256` over the canonical `{"crv","kty","x","y"}` JSON).
const FIXTURE_KID: &str = "ABgeLNqjUq9i3iHWlStncE9gajZTSs5rBQZlEseDLq0";

fn fixture_signer() -> EcdsaP256Signer {
    EcdsaP256Signer::from_pkcs8(&STANDARD.decode(FIXTURE_PKCS8_B64).unwrap()).unwrap()
}

fn subject() -> AssertionSubject {
    AssertionSubject::new(
        "spiffe://node.example/pod/7f3a",
        "tenant.example",
        "spiffe://tenant.example/root",
        "sha256:abcd",
    )
    .unwrap()
}

fn claims(now: u64) -> AssertionClaims {
    AssertionClaims::new(
        &subject(),
        "https://issuer.node.example",
        "https://upstream.example/token",
        "model-upstream",
        now,
        DEFAULT_TTL,
    )
    .unwrap()
}

fn parts(jwt: &str) -> (serde_json::Value, serde_json::Value, Vec<u8>, String) {
    let v: Vec<&str> = jwt.split('.').collect();
    assert_eq!(v.len(), 3);
    let h = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(v[0]).unwrap()).unwrap();
    let p = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(v[1]).unwrap()).unwrap();
    (
        h,
        p,
        URL_SAFE_NO_PAD.decode(v[2]).unwrap(),
        format!("{}.{}", v[0], v[1]),
    )
}

#[test]
fn the_kid_is_the_rfc7638_thumbprint_computed_independently() {
    let s = fixture_signer();
    let jwk = s.public_jwk();
    assert_eq!(jwk.x, FIXTURE_X);
    assert_eq!(jwk.y, FIXTURE_Y);
    assert_eq!(s.kid(), FIXTURE_KID);
    assert_eq!(jwk.kid, FIXTURE_KID);
}

#[test]
fn a_minted_assertion_verifies_under_the_exported_jwk_with_ring() {
    let s = fixture_signer();
    let jwt = mint(&claims(1_700_000_000), &s).unwrap();
    let (h, _, sig, input) = parts(jwt.expose());
    assert_eq!(h["alg"], SIGNING_ALG);
    assert_eq!(h["kid"], FIXTURE_KID);
    assert_eq!(h["typ"], "JWT");
    // JOSE form, not DER: exactly 64 bytes.
    assert_eq!(sig.len(), 64);

    // Rebuild the public key from the EXPORTED jwk alone.
    let jwks = s.jwks();
    let k = &jwks["keys"][0];
    assert_eq!(k["kty"], "EC");
    assert_eq!(k["crv"], "P-256");
    assert_eq!(k["use"], "sig");
    let mut point = vec![0x04];
    point.extend(URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(k["y"].as_str().unwrap()).unwrap());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(input.as_bytes(), &sig)
        .expect("signature verifies under the published key");

    // And a flipped byte does not.
    let mut bad = sig.clone();
    bad[10] ^= 1;
    assert!(
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(input.as_bytes(), &bad)
            .is_err()
    );
}

#[test]
fn a_minted_assertion_verifies_with_jsonwebtoken_too() {
    // A second, unrelated verifier: what a provider running a stock JWT
    // library would do with our JWKS.
    let s = fixture_signer();
    let jwt = mint(&claims(1_700_000_000), &s).unwrap();
    let (_, _, _, input) = parts(jwt.expose());
    let sig_b64 = jwt.expose().rsplit('.').next().unwrap();
    let key = jsonwebtoken::DecodingKey::from_ec_components(FIXTURE_X, FIXTURE_Y).unwrap();
    let ok = jsonwebtoken::crypto::verify(
        sig_b64,
        input.as_bytes(),
        &key,
        jsonwebtoken::Algorithm::ES256, // alg-pin-allow: test verifies our ES256 output with an independent library
    )
    .unwrap();
    assert!(ok);
}

#[test]
fn the_claims_are_the_host_observed_ones() {
    let s = fixture_signer();
    let c = claims(1_700_000_000);
    let jwt = mint(&c, &s).unwrap();
    let (_, p, _, _) = parts(jwt.expose());
    assert_eq!(p["iss"], "https://issuer.node.example");
    assert_eq!(p["sub"], "spiffe://node.example/pod/7f3a");
    assert_eq!(p["aud"], "https://upstream.example/token");
    assert_eq!(p["iat"], 1_700_000_000u64);
    assert_eq!(p["exp"], 1_700_000_300u64);
    assert_eq!(p["nucleus_tenant"], "tenant.example");
    assert_eq!(p["nucleus_upstream"], "model-upstream");
    assert_eq!(p["nucleus_root"], "spiffe://tenant.example/root");
    assert_eq!(p["nucleus_chain"], "sha256:abcd");
    assert_eq!(p["jti"], c.jti());
    // Flat: every claim is a string or an integer, nothing nested.
    for (k, v) in p.as_object().unwrap() {
        assert!(v.is_string() || v.is_u64(), "{k} is nested");
    }
}

#[test]
fn the_lifetime_is_capped_and_must_be_positive() {
    let mk = |ttl| AssertionClaims::new(&subject(), "https://iss.example", "aud", "up", 0, ttl);
    assert!(mk(MAX_TTL).is_ok());
    assert_eq!(
        mk(MAX_TTL + Duration::from_secs(1)).unwrap_err(),
        ClaimsError::Lifetime
    );
    assert_eq!(mk(Duration::ZERO).unwrap_err(), ClaimsError::Lifetime);
    assert_eq!(mk(DEFAULT_TTL).unwrap().expires_at(), 300);
}

#[test]
fn issuer_audience_and_subject_are_checked() {
    let s = subject();
    let mk =
        |iss: &str, aud: &str, up: &str| AssertionClaims::new(&s, iss, aud, up, 0, DEFAULT_TTL);
    assert_eq!(
        mk("http://iss.example", "a", "u").unwrap_err(),
        ClaimsError::Issuer
    );
    assert_eq!(mk("https://", "a", "u").unwrap_err(), ClaimsError::Issuer);
    assert_eq!(
        mk("https://iss.example", "", "u").unwrap_err(),
        ClaimsError::Empty
    );
    assert_eq!(
        mk("https://iss.example", "a", "").unwrap_err(),
        ClaimsError::Empty
    );
    assert_eq!(
        AssertionSubject::new("pod-7f3a", "t", "r", "f").unwrap_err(),
        ClaimsError::Subject
    );
    assert_eq!(
        AssertionSubject::new("spiffe://", "t", "r", "f").unwrap_err(),
        ClaimsError::Subject
    );
}

#[test]
fn jti_is_unique_across_a_thousand_mints() {
    let s = fixture_signer();
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        let c = claims(1_700_000_000);
        // 128 bits, base64url without padding.
        assert_eq!(c.jti().len(), 22);
        let jwt = mint(&c, &s).unwrap();
        let (_, p, _, _) = parts(jwt.expose());
        assert!(seen.insert(p["jti"].as_str().unwrap().to_string()));
    }
}

#[test]
fn a_generated_key_round_trips_and_gets_its_own_kid() {
    let der = EcdsaP256Signer::generate_pkcs8().unwrap();
    let s = EcdsaP256Signer::from_pkcs8(&der).unwrap();
    assert_ne!(s.kid(), FIXTURE_KID);
    assert_eq!(s.kid().len(), 43);
}

#[test]
fn a_non_p256_key_is_refused() {
    let rng = ring::rand::SystemRandom::new();
    let p384 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    assert_eq!(
        EcdsaP256Signer::from_pkcs8(p384.as_ref()).unwrap_err(),
        SignError::Key
    );
    assert_eq!(
        EcdsaP256Signer::from_pkcs8(b"not a key").unwrap_err(),
        SignError::Key
    );
}

#[test]
fn debug_output_carries_neither_the_key_nor_the_assertion() {
    let s = fixture_signer();
    let jwt = mint(&claims(1), &s).unwrap();
    let d = format!("{jwt:?}");
    assert!(!d.contains(jwt.expose().split('.').next().unwrap()), "{d}");
    let d = format!("{s:?}");
    assert!(d.contains(FIXTURE_KID) && !d.contains("MIGHAgEA"), "{d}");
}

/// A custom signer whose kid would inject into the header is refused.
#[test]
fn a_kid_outside_base64url_is_refused() {
    struct Bad(EcdsaP256Signer);
    impl AssertionSigner for Bad {
        fn kid(&self) -> &str {
            "k\",\"alg\":\"x"
        }
        fn sign_es256(&self, i: &[u8]) -> Result<nucleus_federation::Es256Signature, SignError> {
            self.0.sign_es256(i)
        }
        fn public_jwk(&self) -> nucleus_federation::PublicJwk {
            self.0.public_jwk()
        }
    }
    assert_eq!(
        mint(&claims(1), &Bad(fixture_signer())).unwrap_err(),
        SignError::Kid
    );
}
