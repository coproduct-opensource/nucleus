//! The outside-issuer validator. One accepted token, then one refusal per
//! check, each asserting WHICH check refused (the internal reason) so a test
//! cannot pass because an earlier, unrelated check happened to fire.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nucleus_federation::{
    ExternalIssuerConfig, ExternalIssuerValidator, InboundError, JwksSource, RefusalReason,
    VerifyAlg, default_client,
};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, KeyPair,
};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISS: &str = "https://runtime.example/org/42";
const AUD: &str = "https://nucleus.example/federation";
const NOW: u64 = 1_700_000_000;

struct Key {
    pair: EcdsaKeyPair,
    x: String,
    y: String,
}

fn key(alg: &'static EcdsaSigningAlgorithm) -> Key {
    let rng = SystemRandom::new();
    let der = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(alg, der.as_ref(), &rng).unwrap();
    let pt = pair.public_key().as_ref().to_vec();
    let n = (pt.len() - 1) / 2;
    Key {
        x: URL_SAFE_NO_PAD.encode(&pt[1..1 + n]),
        y: URL_SAFE_NO_PAD.encode(&pt[1 + n..]),
        pair,
    }
}

fn ec_jwk(kid: &str, crv: &str, k: &Key) -> Value {
    json!({"kty": "EC", "kid": kid, "crv": crv, "x": k.x, "y": k.y, "use": "sig"})
}

fn sign(header: Value, claims: Value, k: &Key) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig = k.pair.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
}

fn claims() -> Value {
    json!({"iss": ISS, "aud": AUD, "sub": "agent-session-1", "iat": NOW, "exp": NOW + 300, "session": "s-1"})
}

fn es256_header(kid: &str) -> Value {
    json!({"alg": VerifyAlg::Es256.name(), "kid": kid, "typ": "JWT"})
}

fn client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    default_client().unwrap()
}

fn inline(keys: Vec<Value>) -> JwksSource {
    JwksSource::Inline(serde_json::from_value(json!({ "keys": keys })).unwrap())
}

fn validator_with(jwks: JwksSource, algs: &[VerifyAlg]) -> ExternalIssuerValidator {
    let cfg = ExternalIssuerConfig::new(ISS, AUD, algs.iter().copied(), jwks);
    ExternalIssuerValidator::new(cfg, client()).unwrap()
}

/// The standard fixture: one P-256 key under kid "k1", ES256 only.
fn fixture() -> (Key, ExternalIssuerValidator) {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let v = validator_with(inline(vec![ec_jwk("k1", "P-256", &k)]), &[VerifyAlg::Es256]);
    (k, v)
}

async fn reason(v: &ExternalIssuerValidator, token: &str) -> RefusalReason {
    let err = v.validate(token, NOW).await.unwrap_err();
    // The caller-facing text never names the check.
    let shown = err.to_string();
    assert!(
        shown == "token refused" || shown.starts_with("token could not"),
        "{shown}"
    );
    err.reason()
}

#[tokio::test]
async fn a_valid_es256_token_is_accepted() {
    let (k, v) = fixture();
    let tok = sign(es256_header("k1"), claims(), &k);
    let caller = v.validate(&tok, NOW).await.expect("valid token");
    assert_eq!(caller.sub, "agent-session-1");
    assert_eq!(caller.exp, NOW + 300);
    assert_eq!(caller.claims["session"], "s-1");
    let want: [u8; 32] = sha2::Sha256::digest(tok.as_bytes()).into();
    assert_eq!(caller.token_hash, want);
}

use sha2::Digest as _;

#[tokio::test]
async fn an_audience_array_containing_ours_is_accepted() {
    let (k, v) = fixture();
    let mut c = claims();
    c["aud"] = json!(["https://other.example", AUD]);
    v.validate(&sign(es256_header("k1"), c, &k), NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn alg_none_is_refused_before_any_key_work() {
    let (k, v) = fixture();
    let signed = sign(es256_header("k1"), claims(), &k);
    let body = signed.split('.').nth(1).unwrap();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"k1"}"#); // alg-pin-allow: negative test, alg=none must be refused
    assert_eq!(
        reason(&v, &format!("{header}.{body}.")).await,
        RefusalReason::AlgNotAllowed
    );
}

/// The classic confusion: sign with HMAC using the issuer's PUBLIC key as the
/// secret, and hope the verifier feeds that same key to HMAC.
#[tokio::test]
async fn hs256_with_the_public_key_as_secret_is_refused() {
    let (k, v) = fixture();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"k1"}"#); // alg-pin-allow: negative test, HMAC with the public key must be refused
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims()).unwrap());
    let input = format!("{header}.{body}");
    let mut secret = URL_SAFE_NO_PAD.decode(&k.x).unwrap();
    secret.extend(URL_SAFE_NO_PAD.decode(&k.y).unwrap());
    let mac = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret),
        input.as_bytes(),
    );
    let tok = format!("{input}.{}", URL_SAFE_NO_PAD.encode(mac.as_ref()));
    assert_eq!(reason(&v, &tok).await, RefusalReason::AlgNotAllowed);
    // And no binding can opt in: HS256 is not a name VerifyAlg knows.
    assert!("HS256".parse::<VerifyAlg>().is_err()); // alg-pin-allow: negative test, HS256 is not a configurable algorithm
    assert!("none".parse::<VerifyAlg>().is_err());
}

#[tokio::test]
async fn a_header_alg_outside_the_binding_set_is_refused() {
    // A real ES384 token under a real P-384 key — but the binding is ES256 only.
    let k = key(&ECDSA_P384_SHA384_FIXED_SIGNING);
    let v = validator_with(inline(vec![ec_jwk("k1", "P-384", &k)]), &[VerifyAlg::Es256]);
    let tok = sign(
        json!({"alg": VerifyAlg::Es384.name(), "kid": "k1"}),
        claims(),
        &k,
    );
    assert_eq!(reason(&v, &tok).await, RefusalReason::AlgNotAllowed);
}

#[tokio::test]
async fn an_rsa_key_presented_for_es256_is_refused() {
    let (k, _) = fixture();
    // A 2048-bit-shaped modulus; its value is irrelevant, the type is wrong.
    let mut n = vec![0xC5u8; 256];
    n[255] = 0x01;
    let rsa = json!({"kty": "RSA", "kid": "k1", "n": URL_SAFE_NO_PAD.encode(&n), "e": "AQAB"});
    let v = validator_with(inline(vec![rsa]), &[VerifyAlg::Es256, VerifyAlg::Rs256]);
    let tok = sign(es256_header("k1"), claims(), &k);
    assert_eq!(reason(&v, &tok).await, RefusalReason::KeyAlgMismatch);
}

#[tokio::test]
async fn a_p384_key_used_for_es256_is_refused() {
    let k = key(&ECDSA_P384_SHA384_FIXED_SIGNING);
    let v = validator_with(
        inline(vec![ec_jwk("k1", "P-384", &k)]),
        &[VerifyAlg::Es256, VerifyAlg::Es384],
    );
    let tok = sign(es256_header("k1"), claims(), &k);
    assert_eq!(reason(&v, &tok).await, RefusalReason::KeyAlgMismatch);
}

/// THE PERTURBATION TARGET. A P-384 key published as `crv: "P-256"`, and an
/// ES384 token it really did sign. The signature is mathematically valid;
/// the crypto backend is handed only coordinates and accepts it. Only the
/// key↔algorithm binding (RFC 8725 §3.1) sees that the issuer published
/// this key for a different curve. Remove `VerifyKey::admits` and this test
/// goes red — it did, see the commit message.
#[tokio::test]
async fn a_key_published_for_one_curve_and_used_on_another_is_refused() {
    let k = key(&ECDSA_P384_SHA384_FIXED_SIGNING);
    let v = validator_with(
        inline(vec![ec_jwk("k1", "P-256", &k)]),
        &[VerifyAlg::Es256, VerifyAlg::Es384],
    );
    let tok = sign(
        json!({"alg": VerifyAlg::Es384.name(), "kid": "k1"}),
        claims(),
        &k,
    );
    assert_eq!(reason(&v, &tok).await, RefusalReason::KeyAlgMismatch);
}

#[tokio::test]
async fn a_jwk_declaring_another_alg_is_refused() {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let mut jwk = ec_jwk("k1", "P-256", &k);
    jwk["alg"] = json!(VerifyAlg::Es384.name());
    let v = validator_with(inline(vec![jwk]), &[VerifyAlg::Es256]);
    let tok = sign(es256_header("k1"), claims(), &k);
    assert_eq!(reason(&v, &tok).await, RefusalReason::KeyAlgMismatch);
}

#[tokio::test]
async fn a_missing_kid_is_refused() {
    let (k, v) = fixture();
    let tok = sign(json!({"alg": VerifyAlg::Es256.name()}), claims(), &k);
    assert_eq!(reason(&v, &tok).await, RefusalReason::MissingKid);
}

#[tokio::test]
async fn an_unknown_kid_is_refused() {
    let (k, v) = fixture();
    let tok = sign(es256_header("k2"), claims(), &k);
    assert_eq!(reason(&v, &tok).await, RefusalReason::UnknownKid);
}

#[tokio::test]
async fn a_signature_by_another_key_is_refused() {
    let (_, v) = fixture();
    let other = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let tok = sign(es256_header("k1"), claims(), &other);
    assert_eq!(reason(&v, &tok).await, RefusalReason::BadSignature);
}

#[tokio::test]
async fn crit_headers_are_refused() {
    let (k, v) = fixture();
    let mut h = es256_header("k1");
    h["crit"] = json!(["exp"]);
    assert_eq!(
        reason(&v, &sign(h, claims(), &k)).await,
        RefusalReason::CriticalHeader
    );
}

async fn refused_for(mutate: impl FnOnce(&mut Value)) -> RefusalReason {
    let (k, v) = fixture();
    let mut c = claims();
    mutate(&mut c);
    reason(&v, &sign(es256_header("k1"), c, &k)).await
}

#[tokio::test]
async fn a_wrong_issuer_is_refused() {
    assert_eq!(
        refused_for(|c| c["iss"] = json!(format!("{ISS}/"))).await,
        RefusalReason::Issuer
    );
    assert_eq!(
        refused_for(|c| c["iss"] = json!("https://runtime.example/org/4")).await,
        RefusalReason::Issuer
    );
}

#[tokio::test]
async fn a_wrong_audience_is_refused() {
    assert_eq!(
        refused_for(|c| c["aud"] = json!("https://other.example")).await,
        RefusalReason::Audience
    );
    assert_eq!(
        refused_for(|c| c["aud"] = json!(["https://other.example"])).await,
        RefusalReason::Audience
    );
    assert_eq!(
        refused_for(|c| {
            c.as_object_mut().unwrap().remove("aud");
        })
        .await,
        RefusalReason::Audience
    );
}

#[tokio::test]
async fn times_are_required_and_enforced() {
    assert_eq!(
        refused_for(|c| {
            c.as_object_mut().unwrap().remove("iat");
        })
        .await,
        RefusalReason::MissingTime
    );
    assert_eq!(
        refused_for(|c| c["exp"] = json!(NOW - 31)).await,
        RefusalReason::Expired
    );
    assert_eq!(
        refused_for(|c| c["iat"] = json!(NOW + 31)).await,
        RefusalReason::NotYetValid
    );
    assert_eq!(
        refused_for(|c| c["nbf"] = json!(NOW + 120)).await,
        RefusalReason::NotYetValid
    );
}

#[tokio::test]
async fn a_token_living_longer_than_the_binding_allows_is_refused() {
    // Default max_lifetime is one hour; this token claims one hour and a second.
    assert_eq!(
        refused_for(|c| {
            c["iat"] = json!(NOW - 10);
            c["exp"] = json!(NOW - 10 + 3601);
        })
        .await,
        RefusalReason::Lifetime
    );
}

#[tokio::test]
async fn a_missing_subject_is_refused() {
    assert_eq!(
        refused_for(|c| c["sub"] = json!("")).await,
        RefusalReason::Subject
    );
}

#[tokio::test]
async fn a_required_claim_must_match_exactly() {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let mut cfg = ExternalIssuerConfig::new(
        ISS,
        AUD,
        [VerifyAlg::Es256],
        inline(vec![ec_jwk("k1", "P-256", &k)]),
    );
    cfg.required_claims = BTreeMap::from([("session".to_string(), "s-1".to_string())]);
    let v = ExternalIssuerValidator::new(cfg, client()).unwrap();
    v.validate(&sign(es256_header("k1"), claims(), &k), NOW)
        .await
        .unwrap();

    for bad in [json!("s-2"), json!("S-1"), json!(["s-1"]), Value::Null] {
        let mut c = claims();
        c["session"] = bad;
        assert_eq!(
            reason(&v, &sign(es256_header("k1"), c, &k)).await,
            RefusalReason::RequiredClaim
        );
    }
}

#[tokio::test]
async fn the_same_token_twice_is_a_replay() {
    let (k, v) = fixture();
    let tok = sign(es256_header("k1"), claims(), &k);
    v.validate(&tok, NOW).await.unwrap();
    assert_eq!(reason(&v, &tok).await, RefusalReason::Replayed);
    // Still refused later in its life.
    assert_eq!(
        v.validate(&tok, NOW + 200).await.unwrap_err().reason(),
        RefusalReason::Replayed
    );
}

#[tokio::test]
async fn a_refused_token_does_not_occupy_the_replay_cache() {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let mut cfg = ExternalIssuerConfig::new(
        ISS,
        AUD,
        [VerifyAlg::Es256],
        inline(vec![ec_jwk("k1", "P-256", &k)]),
    );
    cfg.replay_capacity = 1;
    let v = ExternalIssuerValidator::new(cfg, client()).unwrap();
    let mut bad = claims();
    bad["aud"] = json!("x");
    for _ in 0..3 {
        let _ = v
            .validate(&sign(es256_header("k1"), bad.clone(), &k), NOW)
            .await;
    }
    v.validate(&sign(es256_header("k1"), claims(), &k), NOW)
        .await
        .unwrap();
    // Capacity 1, one live token: the next distinct valid token fails closed.
    let err = v
        .validate(&sign(es256_header("k1"), claims(), &k), NOW)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        InboundError::Unavailable(RefusalReason::ReplayCacheFull)
    ));
    // Once the first has expired, room again.
    v.validate(
        &sign(
            es256_header("k1"),
            json!({"iss": ISS, "aud": AUD, "sub": "a", "iat": NOW + 400, "exp": NOW + 500}),
            &k,
        ),
        NOW + 400,
    )
    .await
    .unwrap();
}

#[test]
fn a_binding_cannot_be_built_unsafely() {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let keys = || inline(vec![ec_jwk("k1", "P-256", &k)]);
    let build = |cfg| ExternalIssuerValidator::new(cfg, client()).map(|_| ());
    use nucleus_federation::inbound::ConfigError;

    assert_eq!(
        build(ExternalIssuerConfig::new(ISS, AUD, [], keys())),
        Err(ConfigError::Algorithm)
    );
    assert_eq!(
        build(ExternalIssuerConfig::new(
            "http://runtime.example",
            AUD,
            [VerifyAlg::Es256],
            keys()
        )),
        Err(ConfigError::Issuer)
    );
    let mut c = ExternalIssuerConfig::new(ISS, AUD, [VerifyAlg::Es256], keys());
    c.leeway = Duration::from_secs(61);
    assert_eq!(build(c), Err(ConfigError::Leeway));
    // An inline set with nothing usable (an Ed25519 key) is refused up front.
    let okp = json!({"kty": "OKP", "kid": "e", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
    assert_eq!(
        build(ExternalIssuerConfig::new(
            ISS,
            AUD,
            [VerifyAlg::Es256],
            inline(vec![okp])
        )),
        Err(ConfigError::Jwks)
    );
}

// ── discovery ─────────────────────────────────────────────────────────────

async fn discovery_server(doc_issuer: impl FnOnce(&str) -> String, k: &Key) -> MockServer {
    let server = MockServer::start().await;
    let iss = format!("{}/org/42", server.uri());
    Mock::given(method("GET"))
        .and(path("/org/42/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": doc_issuer(&iss),
            "jwks_uri": format!("{}/jwks", server.uri()),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [
                // A key type this validator does not model sits beside the
                // real one and must not take it down.
                {"kty": "oct", "kid": "sym", "k": "c2VjcmV0"},
                ec_jwk("k1", "P-256", k),
            ]
        })))
        .mount(&server)
        .await;
    server
}

fn discovery_validator(server: &MockServer) -> (String, ExternalIssuerValidator) {
    let iss = format!("{}/org/42", server.uri());
    let cfg =
        ExternalIssuerConfig::new(iss.clone(), AUD, [VerifyAlg::Es256], JwksSource::Discovery);
    (iss, ExternalIssuerValidator::new(cfg, client()).unwrap())
}

#[tokio::test]
async fn discovery_resolves_keys_when_the_document_names_our_issuer() {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let server = discovery_server(|iss| iss.to_string(), &k).await;
    let (iss, v) = discovery_validator(&server);
    let mut c = claims();
    c["iss"] = json!(iss);
    v.validate(&sign(es256_header("k1"), c, &k), NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_discovery_document_naming_another_issuer_is_refused() {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    // A trailing slash is enough: the comparison is byte for byte.
    let server = discovery_server(|iss| format!("{iss}/"), &k).await;
    let (iss, v) = discovery_validator(&server);
    let mut c = claims();
    c["iss"] = json!(iss);
    assert_eq!(
        reason(&v, &sign(es256_header("k1"), c, &k)).await,
        RefusalReason::DiscoveryIssuerMismatch
    );
}

#[tokio::test]
async fn an_unreachable_key_source_is_unavailable_not_accepted() {
    let k = key(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let server = MockServer::start().await; // serves nothing: 404 everywhere
    let (iss, v) = discovery_validator(&server);
    let mut c = claims();
    c["iss"] = json!(iss);
    let err = v
        .validate(&sign(es256_header("k1"), c, &k), NOW)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        InboundError::Unavailable(RefusalReason::KeysUnavailable)
    ));
}
