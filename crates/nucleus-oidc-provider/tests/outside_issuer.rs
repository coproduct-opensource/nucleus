//! An outside issuer's token, exchanged at `/oauth/token` as one configured
//! SPIFFE ID, and the ES256 token that comes back.
//!
//! The outside issuer here is a real HTTP server on loopback: an OIDC
//! discovery document and a JWKS, RS256 keys (the algorithm such issuers
//! commonly sign with), and claims that name an organisation and an
//! application. The OP is the production shape: a keyring-backed ES256 key
//! store, and a federation config parsed from TOML exactly as `main` reads it.
//!
//! What is asserted is the whole contract a relying party depends on: the
//! issued token's `sub`, `aud`, `scope`, `iss`, lifetime and algorithm, checked
//! by an off-the-shelf JWT library against the OP's published JWKS — plus every
//! refusal the binding and the rule are supposed to make.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt as _;
use nucleus_federation::keyring::{KeyDir, RotationPolicy};
use nucleus_federation::{FileCustody, KeyCustody};
use nucleus_oidc_provider::keystore::{JwtKeyStore, KeyringKeyStore};
use nucleus_oidc_provider::{
    AppState, FederationRegistry, FederationRules, JtiCache, JwtIssuer, OutsideIssuers, build_app,
};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const OP_ISSUER: &str = "https://oidc.tenant.example";
const RP_AUDIENCE: &str = "https://rp.tenant.example/admin";
const SPIFFE_ID: &str = "spiffe://tenant.example/ns/app/sa/web";
const SCOPE: &str = "admin:data";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const FILE: KeyCustody = KeyCustody::File(FileCustody::NoTpmConfigured);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn rsa_key(name: &str) -> RsaKeyPair {
    let path = format!(
        "{}/tests/fixtures/outside_issuer_test_rsa_{name}.pkcs1.der",
        env!("CARGO_MANIFEST_DIR")
    );
    RsaKeyPair::from_der(&std::fs::read(path).unwrap()).unwrap()
}

fn rsa_jwk(key: &RsaKeyPair, kid: &str) -> Value {
    let c: RsaPublicKeyComponents<Vec<u8>> = key.public().into();
    let strip = |b: &[u8]| {
        b.iter()
            .skip_while(|x| **x == 0)
            .copied()
            .collect::<Vec<u8>>()
    };
    json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256", // alg-pin-allow: the outside test issuer's JWKS entry; the OP verifies it, never signs it
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(strip(&c.n)),
        "e": URL_SAFE_NO_PAD.encode(strip(&c.e)),
    })
}

/// The outside issuer: discovery + a JWKS the test can change.
struct OutsideIdp {
    issuer: String,
    jwks: Arc<Mutex<Value>>,
    key_a: RsaKeyPair,
    key_b: RsaKeyPair,
}

impl OutsideIdp {
    async fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}/tenant");
        let key_a = rsa_key("a");
        let key_b = rsa_key("b");
        let jwks = Arc::new(Mutex::new(json!({ "keys": [rsa_jwk(&key_a, "kid-a")] })));
        let doc = json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/jwks") });
        let served = Arc::clone(&jwks);
        let app = axum::Router::new()
            .route(
                "/tenant/.well-known/openid-configuration",
                get(move || {
                    let doc = doc.clone();
                    async move { axum::Json(doc) }
                }),
            )
            .route(
                "/tenant/jwks",
                get(move || {
                    let v = served.lock().unwrap().clone();
                    async move { axum::Json(v) }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            issuer,
            jwks,
            key_a,
            key_b,
        }
    }

    fn claims(&self) -> Value {
        let t = now();
        json!({
            "iss": self.issuer,
            "aud": OP_ISSUER,
            "sub": "tenant-org:web:machine-1",
            "org_name": "tenant-org",
            "app_name": "web",
            "machine_id": "machine-1",
            "iat": t,
            "nbf": t,
            "exp": t + 600,
            "jti": uuid::Uuid::new_v4().to_string(),
        })
    }

    fn sign(&self, key: &RsaKeyPair, kid: &str, claims: &Value) -> String {
        let header = json!({ "alg": "RS256", "kid": kid, "typ": "JWT" }); // alg-pin-allow: the outside issuer's token, which the OP verifies and never signs
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut sig = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn token(&self, claims: &Value) -> String {
        self.sign(&self.key_a, "kid-a", claims)
    }
}

fn config(issuer: &str) -> String {
    format!(
        r#"
[[outside_issuer]]
id = "tenant-web"
issuer = "{issuer}"
algs = ["RS256"] # alg-pin-allow: the outside issuer's verification algorithm, operator config
jwks = "discovery"
max_lifetime_secs = 3600
leeway_secs = 30
spiffe_id = "{SPIFFE_ID}"
[outside_issuer.required_claims]
org_name = "tenant-org"
app_name = "web"

[[rule]]
id = "web-admin"
subject_prefix = "{SPIFFE_ID}"
audience = "{RP_AUDIENCE}"
allowed_grants = ["{GRANT}"]
max_token_lifetime_secs = 300
max_scope = ["{SCOPE}"]
"#
    )
}

struct Op {
    app: axum::Router,
    keys: tempfile::TempDir,
}

fn op(idp: &OutsideIdp) -> Op {
    let keys = tempfile::tempdir().unwrap();
    let store: Arc<dyn JwtKeyStore> = Arc::new(
        KeyringKeyStore::open_or_create(keys.path(), FILE, RotationPolicy::default()).unwrap(),
    );
    let issuer = Arc::new(
        JwtIssuer::new(
            store.clone(),
            OP_ISSUER.to_string(),
            Duration::from_secs(300),
        )
        .unwrap(),
    );
    let rules = FederationRules::parse_toml(&config(&idp.issuer)).unwrap();
    let outside = OutsideIssuers::build(&rules.outside_issuer, OP_ISSUER).unwrap();
    let app = build_app(AppState {
        keystore: store,
        issuer_url: Arc::from(OP_ISSUER),
        issuer,
        jti_cache: Arc::new(JtiCache::new()),
        federation: Arc::new(FederationRegistry::new(rules)),
        outside_issuers: Arc::new(outside),
        bundle_provider: Arc::new(nucleus_oidc_provider::spire::StaticBundleProvider::new()),
        cert_root_pubkey: None,
    });
    Op { app, keys }
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            let enc: String = v
                .bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect();
            format!("{k}={enc}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

async fn exchange(
    app: &axum::Router,
    subject: &str,
    audience: &str,
    scope: Option<&str>,
) -> (StatusCode, Value) {
    let mut pairs = vec![
        ("grant_type", GRANT),
        ("subject_token", subject),
        ("subject_token_type", JWT_TYPE),
        ("audience", audience),
    ];
    if let Some(s) = scope {
        pairs.push(("scope", s));
    }
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&pairs)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get_json(app: &axum::Router, path: &str) -> Value {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{path}");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn header_of(token: &str) -> Value {
    let h = token.split('.').next().unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).unwrap()).unwrap()
}

/// Verify `token` as an off-the-shelf relying party does: the key by `kid`
/// from the OP's `/jwks.json`, ES256, exact `iss` and `aud`, `exp`/`nbf` with
/// 30 s leeway. This is the check a SPIFFE JWT-SVID verifier makes.
async fn verify_as_relying_party(app: &axum::Router, token: &str) -> Value {
    let kid = header_of(token)["kid"].as_str().unwrap().to_string();
    let jwks = get_json(app, "/jwks.json").await;
    let key = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == kid.as_str())
        .expect("the token's kid is published")
        .clone();
    for member in ["kty", "crv", "x", "y", "kid", "alg"] {
        assert!(key.get(member).is_some(), "JWK lacks {member}: {key}");
    }
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(key).unwrap();
    let dk = jsonwebtoken::DecodingKey::from_jwk(&jwk).unwrap();
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256); // alg-pin-allow: the relying party's verification of the OP's ES256 token
    v.set_audience(&[RP_AUDIENCE]);
    v.set_issuer(&[OP_ISSUER]);
    v.validate_nbf = true;
    v.leeway = 30;
    jsonwebtoken::decode::<Value>(token, &dk, &v)
        .expect("a relying party accepts the issued token")
        .claims
}

#[tokio::test]
async fn a_bound_token_becomes_exactly_the_spiffe_id_scope_and_audience() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    let claims = idp.claims();
    let (status, body) = exchange(&op.app, &idp.token(&claims), RP_AUDIENCE, Some(SCOPE)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], SCOPE);
    let token = body["access_token"].as_str().unwrap();

    let header = header_of(token);
    assert_eq!(header["alg"], "ES256"); // alg-pin-allow: asserting the OP's one signing algorithm
    assert_eq!(header["typ"], "at+jwt");

    let c = verify_as_relying_party(&op.app, token).await;
    assert_eq!(
        c["sub"], SPIFFE_ID,
        "sub is the binding's SPIFFE ID, not the outside sub"
    );
    assert_eq!(c["aud"], RP_AUDIENCE);
    assert_eq!(c["iss"], OP_ISSUER);
    assert_eq!(
        c["scope"], SCOPE,
        "scope claim: space-delimited `scope` (RFC 8693 §4.2)"
    );
    let lived = c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap();
    assert!(
        lived <= 300,
        "within the rule's and issuer's 300 s, got {lived}"
    );
    assert_eq!(body["expires_in"].as_u64().unwrap(), lived);
    assert!(c["exp"].as_u64().unwrap() <= claims["exp"].as_u64().unwrap());
    assert!(
        c.get("act").is_none(),
        "the outside sub is not named in act"
    );

    let discovery = get_json(&op.app, "/.well-known/openid-configuration").await;
    assert_eq!(discovery["issuer"], OP_ISSUER);
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        json!(["ES256"])
    ); // alg-pin-allow: asserting the advertised pin
    let health = get_json(&op.app, "/healthz").await;
    assert_eq!(health["signing_alg"], "ES256"); // alg-pin-allow: asserting the reported pin
    assert_eq!(health["outside_issuers"], 1);
}

async fn refused(claims_edit: impl FnOnce(&mut Value)) -> (StatusCode, Value) {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    let mut claims = idp.claims();
    claims_edit(&mut claims);
    exchange(&op.app, &idp.token(&claims), RP_AUDIENCE, Some(SCOPE)).await
}

fn assert_invalid_grant((status, body): (StatusCode, Value)) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

#[tokio::test]
async fn the_wrong_org_is_refused() {
    assert_invalid_grant(refused(|c| c["org_name"] = json!("other-org")).await);
}

#[tokio::test]
async fn the_wrong_app_is_refused() {
    assert_invalid_grant(refused(|c| c["app_name"] = json!("other-app")).await);
}

#[tokio::test]
async fn a_token_without_the_required_claims_is_refused() {
    assert_invalid_grant(
        refused(|c| {
            c.as_object_mut().unwrap().remove("app_name");
        })
        .await,
    );
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let t = now();
    assert_invalid_grant(
        refused(|c| {
            c["iat"] = json!(t - 700);
            c["nbf"] = json!(t - 700);
            c["exp"] = json!(t - 100);
        })
        .await,
    );
}

/// The outside validator admits a token until `exp + leeway`. Before the
/// review fix, such a token was exchanged and the 1 s lifetime floor issued a
/// credential that started life past its subject token's `exp`. The SPIFFE
/// path refuses at `exp`; the outside path now does too.
#[tokio::test]
async fn a_token_inside_the_leeway_but_past_exp_is_refused() {
    let t = now();
    assert_invalid_grant(
        refused(|c| {
            c["iat"] = json!(t - 600);
            c["nbf"] = json!(t - 600);
            c["exp"] = json!(t - 10);
        })
        .await,
    );
}

#[tokio::test]
async fn a_token_minted_for_another_audience_is_refused() {
    assert_invalid_grant(refused(|c| c["aud"] = json!("https://someone-else.example")).await);
}

#[tokio::test]
async fn an_audience_the_rule_does_not_name_is_refused() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    let (status, body) = exchange(
        &op.app,
        &idp.token(&idp.claims()),
        "https://other-rp.tenant.example/",
        Some(SCOPE),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target", "{body}");
}

#[tokio::test]
async fn a_forged_signature_is_refused() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    // Signed by key B, claiming to be key A.
    let forged = idp.sign(&idp.key_b, "kid-a", &idp.claims());
    assert_invalid_grant(exchange(&op.app, &forged, RP_AUDIENCE, Some(SCOPE)).await);
}

#[tokio::test]
async fn an_unknown_issuer_is_refused() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    let mut claims = idp.claims();
    claims["iss"] = json!(format!("{}-other", idp.issuer));
    assert_invalid_grant(exchange(&op.app, &idp.token(&claims), RP_AUDIENCE, Some(SCOPE)).await);
}

#[tokio::test]
async fn a_scope_beyond_the_rule_ceiling_is_refused() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    for scope in ["admin:data admin:root", "admin:root", "*"] {
        let (status, body) =
            exchange(&op.app, &idp.token(&idp.claims()), RP_AUDIENCE, Some(scope)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{scope}: {body}");
        assert_eq!(body["error"], "invalid_target", "{scope}: {body}");
    }
}

#[tokio::test]
async fn the_same_outside_token_is_exchanged_once() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    let token = idp.token(&idp.claims());
    let (first, _) = exchange(&op.app, &token, RP_AUDIENCE, Some(SCOPE)).await;
    assert_eq!(first, StatusCode::OK);
    assert_invalid_grant(exchange(&op.app, &token, RP_AUDIENCE, Some(SCOPE)).await);
}

/// The outside issuer rotates: a new key appears in its JWKS and signs. The
/// OP refetches on the unknown `kid` — but no sooner than 30 s after its last
/// fetch, so a caller spraying random `kid`s cannot turn it into a request
/// amplifier against the issuer. Inside that window the new key is refused;
/// after it, accepted; and the retired key stops verifying once it is gone.
#[tokio::test]
async fn an_outside_jwks_rotation_is_followed_after_the_refetch_window() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    let (status, _) = exchange(&op.app, &idp.token(&idp.claims()), RP_AUDIENCE, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "key A accepted; the JWKS is now cached"
    );

    *idp.jwks.lock().unwrap() = json!({ "keys": [rsa_jwk(&idp.key_b, "kid-b")] });
    let by_b = || idp.sign(&idp.key_b, "kid-b", &idp.claims());
    assert_invalid_grant(exchange(&op.app, &by_b(), RP_AUDIENCE, None).await);

    tokio::time::sleep(Duration::from_secs(31)).await;
    let (status, body) = exchange(&op.app, &by_b(), RP_AUDIENCE, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the rotated key is followed: {body}"
    );
    assert_invalid_grant(exchange(&op.app, &idp.token(&idp.claims()), RP_AUDIENCE, None).await);
}

/// The OP's OWN key rotates by the keyring protocol: a staged key is published
/// before it signs, and after a promote the OP signs with it without a
/// restart, while the old key stays published for tokens already issued.
#[tokio::test]
async fn the_ops_own_key_rotates_without_a_restart() {
    let idp = OutsideIdp::start().await;
    let op = op(&idp);
    let (_, before) = exchange(&op.app, &idp.token(&idp.claims()), RP_AUDIENCE, None).await;
    let old = before["access_token"].as_str().unwrap().to_string();
    let old_kid = header_of(&old)["kid"].as_str().unwrap().to_string();

    let keys = KeyDir::new(op.keys.path());
    let policy = RotationPolicy::default();
    let staged_at = now() - policy.promote_overlap().as_secs() - 1;
    keys.stage(staged_at, &FILE).unwrap();
    assert_eq!(
        get_json(&op.app, "/jwks.json").await["keys"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    keys.promote(now(), &policy).unwrap();

    let (_, after) = exchange(&op.app, &idp.token(&idp.claims()), RP_AUDIENCE, None).await;
    let new = after["access_token"].as_str().unwrap();
    assert_ne!(
        header_of(new)["kid"].as_str().unwrap(),
        old_kid,
        "signs with the promoted key"
    );
    verify_as_relying_party(&op.app, new).await;
    verify_as_relying_party(&op.app, &old).await;
}

fn binding_error(edit: &str) -> String {
    let base = config("https://idp.tenant.example/tenant");
    let toml = base.replacen(
        edit.split("=>").next().unwrap().trim(),
        edit.split("=>").nth(1).unwrap().trim(),
        1,
    );
    assert_ne!(toml, base, "the edit {edit:?} must change the config");
    format!("{:?}", FederationRules::parse_toml(&toml).expect_err(edit))
}

#[test]
fn bindings_that_would_grant_too_much_are_refused_at_load() {
    // No required claims: every workload of the issuer would become SPIFFE_ID.
    let msg = binding_error(
        r#"org_name = "tenant-org"
app_name = "web" => "#,
    );
    assert!(msg.contains("required_claims"), "{msg}");
    // A wildcard identity.
    let msg = binding_error(&format!(
        "spiffe_id = \"{SPIFFE_ID}\" => spiffe_id = \"spiffe://tenant.example/ns/app/*\""
    ));
    assert!(msg.contains("spiffe_id"), "{msg}");
    // Algorithms that cannot be verified safely, or that no such issuer uses.
    for alg in ["none", "HS256", "EdDSA"] {
        // alg-pin-allow: negative cases, each refused at load
        let msg = binding_error(&format!("algs = [\"RS256\"] => algs = [\"{alg}\"]")); // alg-pin-allow: replacing the configured algorithm with a refused one
        assert!(msg.contains("algorithm"), "{alg}: {msg}");
    }
}

#[test]
fn a_binding_for_this_ops_own_issuer_is_refused() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    for own in [OP_ISSUER.to_string(), format!("{OP_ISSUER}/")] {
        let rules = FederationRules::parse_toml(&config(&own)).unwrap();
        let msg = format!(
            "{:?}",
            OutsideIssuers::build(&rules.outside_issuer, OP_ISSUER).unwrap_err()
        );
        assert!(msg.contains("own issuer"), "{own}: {msg}");
    }
}

#[test]
fn leeway_is_stated_never_defaulted() {
    let base = config("https://idp.tenant.example/tenant");
    let without = base.replacen("leeway_secs = 30\n", "", 1);
    assert_ne!(without, base);
    assert!(FederationRules::parse_toml(&without).is_err());
}

#[test]
fn an_issuer_bound_twice_is_refused() {
    let base = config("https://idp.tenant.example/tenant");
    let binding = &base[..base.find("[[rule]]").unwrap()];
    let twice = format!("{}{}", binding.replace("tenant-web", "tenant-web-2"), base);
    let msg = format!("{:?}", FederationRules::parse_toml(&twice).unwrap_err());
    assert!(msg.contains("bound twice"), "{msg}");
}

#[test]
fn an_outside_token_must_name_this_op_as_audience_by_construction() {
    // The binding has no audience field to get wrong: it is the OP's issuer.
    let base = config("https://idp.tenant.example/tenant");
    let with_aud = base.replacen(
        "jwks = \"discovery\"",
        "jwks = \"discovery\"\naudience = \"https://x\"",
        1,
    );
    assert!(
        FederationRules::parse_toml(&with_aud).is_err(),
        "unknown field refused"
    );
}

/// The config the coproduct.one deployment ships loads exactly as `main`
/// loads it, and says what it is meant to: one binding to one identity, one
/// rule, one scope. A typo in it fails here rather than at deploy.
#[test]
fn the_shipped_coproduct_one_config_loads_and_grants_only_admin_data() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rules =
        FederationRules::parse_toml(include_str!("../deploy/federation.coproduct-one.toml"))
            .expect("the shipped config parses");
    let outside = OutsideIssuers::build(&rules.outside_issuer, "https://oidc.coproduct.one")
        .expect("the shipped bindings build");
    assert_eq!(outside.len(), 1);
    let b = &rules.outside_issuer[0];
    assert_eq!(b.spiffe_id, "spiffe://coproduct.one/ns/olog/sa/coproduct");
    assert_eq!(b.required_claims.len(), 2);
    assert_eq!(rules.rule.len(), 1);
    let r = &rules.rule[0];
    assert_eq!(
        r.subject_prefix, b.spiffe_id,
        "the rule names exactly the bound identity"
    );
    assert_eq!(
        r.max_scope.as_deref(),
        Some(&["admin:data".to_string()][..])
    );
    assert!(r.max_token_lifetime_secs <= 300);
}
