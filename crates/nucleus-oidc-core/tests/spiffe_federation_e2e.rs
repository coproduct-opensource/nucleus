// SPDX-License-Identifier: MIT
//
//! Inbound SPIFFE Federation end-to-end tests.
//!
//! The merge gate is the four NEGATIVE tests plus two positive controls.
//! Everything here mints REAL JWT-SVIDs and verifies them through the real
//! [`FederationStore::validate_jwt_svid`] path — no mocks of the crypto.
//!
//! Test key material (generated offline with OpenSSL, embedded as
//! constants so the suite is deterministic and needs no RNG dev-dep):
//!   * `SVID_*`     — the FEDERATED domain's P-256 JWT-SVID signing key.
//!   * `ATTACKER_*` — a fresh P-256 key NOT in any pinned bundle.
//!   * `ED25519_*`  — an Ed25519 key, used to mint an out-of-spec EdDSA SVID.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use nucleus_oidc_core::spiffe_federation::{FederatesWith, FederationStore, Profile, SpiffeBundle};
use nucleus_oidc_core::OidcError;
use serde_json::json;

// ---- federated domain's P-256 JWT-SVID key ----
const SVID_PRIV_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8QBklzAZ+ClJWMEf
ffyt/fTwPs4bH0Z5Jde69PJpdyOhRANCAASj+6zyzUTGr19+snfoRxOe0HTCpqkN
Av3cQeW1auNiO2LflCA1h4e7xEQ9FfVbV/VzB3Z5Ol7Ywz3cv7eHMbMZ
-----END PRIVATE KEY-----";
const SVID_X: &str = "o_us8s1Exq9ffrJ36EcTntB0wqapDQL93EHltWrjYjs";
const SVID_Y: &str = "Yt-UIDWHh7vERD0V9VtX9XMHdnk6XtjDPdy_t4cxsxk";
const SVID_KID: &str = "ci-jwt-svid-1";

// ---- attacker P-256 key (never in any pinned bundle) ----
const ATTACKER_PRIV_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnr5mT+hJLAK8cT/O
lz0KqZXIYQfkVsQ+koTKsL/cTP6hRANCAARvKGhoCQOYaW2LRCsabuZEQNdhL69K
9lkqYsoyDN150EgsmDJsChOLPrFSDvzNVNcLMSxXtXDrpTr/w3wpAtjc
-----END PRIVATE KEY-----";

// ---- Ed25519 key for the out-of-spec EdDSA SVID ----
const ED25519_PRIV_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJlzfwIgczo36oI7wy/E3uG66cinGEcRh3VaizkjG4Fe
-----END PRIVATE KEY-----";

const TRUST_DOMAIN: &str = "ci.example.org";
const SUB: &str = "spiffe://ci.example.org/runner/42";
const AUD: &str = "spiffe://prod.example.org/api";
const BUNDLE_URL: &str = "https://ci.example.org/bundle"; // pinned, out-of-band

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A bundle JSON carrying the federated domain's P-256 JWT-SVID key at the
/// given sequence (plus, optionally, an x509-svid entry that MUST be
/// ignored).
fn bundle_json(seq: u64) -> Vec<u8> {
    json!({
        "spiffe_sequence": seq,
        "spiffe_refresh_hint": 120,
        "keys": [
            // jwt-svid key — the one that should be selected.
            {
                "kty": "EC", "crv": "P-256", "use": "jwt-svid",
                "kid": SVID_KID, "x": SVID_X, "y": SVID_Y
            },
            // x509-svid in the SAME bundle — MUST be ignored for JWT-SVID.
            {
                "kty": "EC", "crv": "P-256", "use": "x509-svid",
                "kid": "ci-x509-1", "x": SVID_X, "y": SVID_Y
            }
        ]
    })
    .to_string()
    .into_bytes()
}

/// A store with `ci.example.org` pinned and its seq-`seq` bundle ingested.
fn federated_store(seq: u64) -> FederationStore {
    let store = FederationStore::new(AUD);
    store.federate_with(FederatesWith {
        trust_domain: TRUST_DOMAIN.to_string(),
        bundle_endpoint_url: BUNDLE_URL.to_string(),
        profile: Profile::HttpsWeb,
    });
    let bundle = SpiffeBundle::from_json(&bundle_json(seq)).unwrap();
    store.ingest_bundle(TRUST_DOMAIN, &bundle).unwrap();
    store
}

/// Mint an ES256 SVID with the given key, sub, aud, exp, and kid.
fn mint_es256(priv_pkcs8: &str, sub: &str, aud: &str, exp: u64, kid: Option<&str>) -> String {
    let key = EncodingKey::from_ec_pem(priv_pkcs8.as_bytes()).expect("EC pem parses");
    let mut header = Header::new(Algorithm::ES256);
    header.kid = kid.map(|k| k.to_string());
    let claims = json!({ "sub": sub, "aud": aud, "exp": exp });
    encode(&header, &claims, &key).expect("ES256 sign")
}

// =====================================================================
// POSITIVE CONTROLS
// =====================================================================

#[test]
fn positive_es256_from_federated_domain_accepted() {
    let store = federated_store(1);
    let token = mint_es256(SVID_PRIV_PKCS8, SUB, AUD, now() + 300, Some(SVID_KID));
    let id = store
        .validate_jwt_svid(&token, AUD)
        .expect("valid ES256 SVID from a federated domain must be accepted");
    assert_eq!(id.trust_domain, TRUST_DOMAIN);
    assert_eq!(id.path, "/runner/42");
}

#[test]
fn positive_es256_no_kid_falls_back_to_all_jwt_svid_keys() {
    // A token with no `kid` should still verify by trying every jwt-svid
    // key in the pinned bundle.
    let store = federated_store(1);
    let token = mint_es256(SVID_PRIV_PKCS8, SUB, AUD, now() + 300, None);
    let id = store
        .validate_jwt_svid(&token, AUD)
        .expect("no-kid SVID accepted");
    assert_eq!(id.trust_domain, TRUST_DOMAIN);
}

#[test]
fn control_eddsa_rejected_by_alg_allowlist() {
    // EdDSA is OUT OF SPEC for JWT-SVID. Even if signed by a key the
    // verifier had, the alg allowlist rejects it before key work.
    let store = federated_store(1);
    let key = EncodingKey::from_ed_pem(ED25519_PRIV_PKCS8.as_bytes()).expect("ed pem parses");
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(SVID_KID.to_string());
    let claims = json!({ "sub": SUB, "aud": AUD, "exp": now() + 300 });
    let token = encode(&header, &claims, &key).expect("EdDSA sign");

    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    assert!(
        matches!(err, OidcError::UnacceptedAlgorithm(_)),
        "EdDSA must be rejected by the alg allowlist, got {err:?}"
    );
}

// =====================================================================
// NEGATIVE TEST (a): trust domain NOT in the federation set
// =====================================================================

#[test]
fn negative_a_untrusted_trust_domain_rejected_before_signature() {
    // Store federates ONLY ci.example.org. A perfectly-signed token whose
    // sub names a different domain must be rejected fail-closed, before any
    // signature work.
    let store = federated_store(1);
    let foreign_sub = "spiffe://evil.example.org/runner/1";
    let token = mint_es256(
        SVID_PRIV_PKCS8,
        foreign_sub,
        AUD,
        now() + 300,
        Some(SVID_KID),
    );

    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    match err {
        OidcError::TrustDomainNotFederated(td) => assert_eq!(td, "evil.example.org"),
        other => panic!("expected TrustDomainNotFederated, got {other:?}"),
    }
}

// =====================================================================
// NEGATIVE TEST (b): expired SVID, and absent exp
// =====================================================================

#[test]
fn negative_b_expired_svid_rejected() {
    let store = federated_store(1);
    // exp well in the past, beyond the 60s leeway.
    let token = mint_es256(SVID_PRIV_PKCS8, SUB, AUD, now() - 600, Some(SVID_KID));
    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    assert!(
        matches!(err, OidcError::JwtValidation(_)),
        "expired SVID must be rejected, got {err:?}"
    );
}

#[test]
fn negative_b_absent_exp_rejected() {
    let store = federated_store(1);
    let key = EncodingKey::from_ec_pem(SVID_PRIV_PKCS8.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(SVID_KID.to_string());
    // No `exp` claim at all.
    let claims = json!({ "sub": SUB, "aud": AUD });
    let token = encode(&header, &claims, &key).unwrap();

    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    assert!(
        matches!(err, OidcError::JwtValidation(_)),
        "SVID without exp must be rejected, got {err:?}"
    );
}

#[test]
fn negative_b_absent_aud_rejected() {
    // aud MUST be present and contain the expected audience.
    let store = federated_store(1);
    let key = EncodingKey::from_ec_pem(SVID_PRIV_PKCS8.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(SVID_KID.to_string());
    let claims = json!({ "sub": SUB, "exp": now() + 300 });
    let token = encode(&header, &claims, &key).unwrap();

    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    assert!(
        matches!(err, OidcError::JwtValidation(_)),
        "SVID without aud must be rejected, got {err:?}"
    );
}

#[test]
fn negative_b_wrong_aud_rejected() {
    let store = federated_store(1);
    let token = mint_es256(
        SVID_PRIV_PKCS8,
        SUB,
        "spiffe://someone-else/api",
        now() + 300,
        Some(SVID_KID),
    );
    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    assert!(
        matches!(err, OidcError::JwtValidation(_)),
        "SVID with wrong aud must be rejected, got {err:?}"
    );
}

// =====================================================================
// NEGATIVE TEST (c): signed by a key NOT in the pinned bundle
// =====================================================================

#[test]
fn negative_c_foreign_key_rejected_at_verify() {
    // Token signed by a freshly-generated keypair not in any bundle,
    // carrying the federated domain's sub. Trust domain IS federated, so we
    // reach signature verify — which must fail.
    let store = federated_store(1);
    // kid present but unknown -> KeyNotFound (no candidate selected).
    let token_unknown_kid = mint_es256(
        ATTACKER_PRIV_PKCS8,
        SUB,
        AUD,
        now() + 300,
        Some("attacker-kid"),
    );
    let err = store
        .validate_jwt_svid(&token_unknown_kid, AUD)
        .unwrap_err();
    assert!(
        matches!(err, OidcError::KeyNotFound(_)),
        "foreign key with unknown kid must not select a key, got {err:?}"
    );
}

#[test]
fn negative_c_kid_collision_self_sign_rejected() {
    // Attacker reuses the LEGITIMATE kid but signs with their own key.
    // The verifier selects the pinned key for that kid (correct key), so
    // the signature check fails.
    let store = federated_store(1);
    let token = mint_es256(ATTACKER_PRIV_PKCS8, SUB, AUD, now() + 300, Some(SVID_KID));
    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    assert!(
        matches!(err, OidcError::JwtValidation(_)),
        "kid-collision self-sign must fail signature verify, got {err:?}"
    );
}

#[test]
fn negative_c_foreign_key_no_kid_rejected() {
    // No kid -> verifier tries every pinned jwt-svid key; none is the
    // attacker's, so verify fails.
    let store = federated_store(1);
    let token = mint_es256(ATTACKER_PRIV_PKCS8, SUB, AUD, now() + 300, None);
    let err = store.validate_jwt_svid(&token, AUD).unwrap_err();
    assert!(
        matches!(err, OidcError::JwtValidation(_)),
        "foreign key (no kid) must fail verify against all pinned keys, got {err:?}"
    );
}

// =====================================================================
// NEGATIVE TEST (d): anti-rollback on spiffe_sequence
// =====================================================================

#[test]
fn negative_d_anti_rollback_sequence() {
    let store = FederationStore::new(AUD);
    store.federate_with(FederatesWith {
        trust_domain: TRUST_DOMAIN.to_string(),
        bundle_endpoint_url: BUNDLE_URL.to_string(),
        profile: Profile::HttpsWeb,
    });

    // Accept seq 5.
    let b5 = SpiffeBundle::from_json(&bundle_json(5)).unwrap();
    store.ingest_bundle(TRUST_DOMAIN, &b5).unwrap();
    assert_eq!(store.last_accepted_seq(TRUST_DOMAIN), Some(5));
    let keys_after_5 = store.served_key_count(TRUST_DOMAIN);
    assert_eq!(keys_after_5, Some(1), "exactly the one jwt-svid key served");

    // Feed 4, then 3, then 5 again -> all REJECTED as rollback, and the
    // served key set / last-accepted seq must be UNCHANGED.
    for seq in [4u64, 3, 5] {
        let b = SpiffeBundle::from_json(&bundle_json(seq)).unwrap();
        let err = store.ingest_bundle(TRUST_DOMAIN, &b).unwrap_err();
        match err {
            OidcError::BundleRollback { fetched, last } => {
                assert_eq!(fetched, seq);
                assert_eq!(last, 5);
            }
            other => panic!("expected BundleRollback for seq {seq}, got {other:?}"),
        }
        assert_eq!(
            store.last_accepted_seq(TRUST_DOMAIN),
            Some(5),
            "rollback must not advance the accepted sequence"
        );
        assert_eq!(
            store.served_key_count(TRUST_DOMAIN),
            keys_after_5,
            "rollback must leave the served key set unchanged"
        );
    }

    // A token still verifies against the kept (seq-5) key set.
    let token = mint_es256(SVID_PRIV_PKCS8, SUB, AUD, now() + 300, Some(SVID_KID));
    assert!(
        store.validate_jwt_svid(&token, AUD).is_ok(),
        "served keys must survive the rollback attempts"
    );

    // Finally seq 6 -> ACCEPTED, sequence advances.
    let b6 = SpiffeBundle::from_json(&bundle_json(6)).unwrap();
    store.ingest_bundle(TRUST_DOMAIN, &b6).unwrap();
    assert_eq!(store.last_accepted_seq(TRUST_DOMAIN), Some(6));
}

// =====================================================================
// SUPPORTING: ingesting a bundle for an un-pinned domain is rejected
// =====================================================================

#[test]
fn ingest_for_unpinned_domain_rejected() {
    let store = FederationStore::new(AUD);
    let b = SpiffeBundle::from_json(&bundle_json(1)).unwrap();
    let err = store
        .ingest_bundle("not-pinned.example.org", &b)
        .unwrap_err();
    assert!(matches!(err, OidcError::TrustDomainNotFederated(_)));
}
