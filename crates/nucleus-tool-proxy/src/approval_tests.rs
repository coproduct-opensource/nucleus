//! Tests for `approval`. Every `VerifiedApproval` here is minted through one
//! of the two real verifiers, from a request or bundle signed for real: there
//! is no test-only constructor, so a test cannot pass by skipping the check it
//! exists to exercise.

use super::*;
use axum::http::HeaderValue;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

const SKEW: Duration = Duration::from_secs(30);

fn approver() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn verifier_for(key: &SigningKey) -> auth::ApprovalVerifier {
    auth::ApprovalVerifier::from_hex_list(&hex::encode(key.verifying_key().to_bytes()), SKEW, None)
        .unwrap()
}

fn approve_body(operation: &str, count: usize, expires: Option<u64>, nonce: &str) -> Vec<u8> {
    let mut v = serde_json::json!({"operation": operation, "count": count, "nonce": nonce});
    if let Some(exp) = expires {
        v["expires_at_unix"] = serde_json::json!(exp);
    }
    serde_json::to_vec(&v).unwrap()
}

/// Headers carrying `sign("{ts}.{actor}.{body}")` — the framing the node's
/// signed proxy uses when drand is off.
fn signed_headers(sign: impl Fn(&[u8]) -> String, body: &[u8]) -> HeaderMap {
    let ts = now_unix().to_string();
    let mut message = format!("{ts}.approver.").into_bytes();
    message.extend_from_slice(body);
    let mut headers = HeaderMap::new();
    headers.insert("x-nucleus-timestamp", HeaderValue::from_str(&ts).unwrap());
    headers.insert("x-nucleus-actor", HeaderValue::from_static("approver"));
    headers.insert(
        "x-nucleus-signature",
        HeaderValue::from_str(&sign(&message)).unwrap(),
    );
    headers
}

fn ed25519_headers(key: &SigningKey, body: &[u8]) -> HeaderMap {
    signed_headers(|m| hex::encode(key.sign(m).to_bytes()), body)
}

fn mint_with(
    headers: &HeaderMap,
    body: &[u8],
    key: &SigningKey,
    nonces: &ApprovalNonceCache,
) -> Result<VerifiedApproval, ApiError> {
    let verifier = verifier_for(key);
    VerifiedApproval::verify_request(
        headers,
        body,
        ApprovalKeys::Ed25519(&verifier),
        nonces,
        now_unix(),
    )
}

fn mint(key: &SigningKey, body: &[u8]) -> Result<VerifiedApproval, ApiError> {
    mint_with(
        &ed25519_headers(key, body),
        body,
        key,
        &ApprovalNonceCache::default(),
    )
}

#[test]
fn test_rate_limiter_allows_burst() {
    let limiter = ApprovalRateLimiter::new(5, 1);
    // Should allow burst of 5
    for i in 0..5 {
        assert!(limiter.try_acquire(), "request {} should be allowed", i);
    }
    // 6th should be rejected
    assert!(!limiter.try_acquire(), "request 6 should be rate limited");
}

#[test]
fn test_rate_limiter_default_config() {
    let limiter = ApprovalRateLimiter::default();
    // Default is 20 burst, 10/sec refill
    for i in 0..20 {
        assert!(limiter.try_acquire(), "request {} should be allowed", i);
    }
    assert!(!limiter.try_acquire(), "request 21 should be rate limited");
}

#[test]
fn test_nonce_cache_rejects_replay() {
    let cache = ApprovalNonceCache::default();
    let now = 1000;
    let expiry = 2000;

    // First use should succeed
    assert!(cache.check_and_insert("nonce-1", expiry, now));
    // Replay should fail
    assert!(!cache.check_and_insert("nonce-1", expiry, now));
    // Different nonce should succeed
    assert!(cache.check_and_insert("nonce-2", expiry, now));
}

#[test]
fn test_nonce_cache_expires_old_entries() {
    let cache = ApprovalNonceCache::default();
    let now = 1000;
    let expiry = 1500;

    assert!(cache.check_and_insert("nonce-old", expiry, now));

    // Time passes, entry expires
    let later = 2000;
    // Old nonce was cleaned up, so this should succeed
    assert!(cache.check_and_insert("nonce-old", 3000, later));
}

#[test]
fn test_approval_registry_consume() {
    let registry = ApprovalRegistry::default();

    // Approve 2 uses, signed for real.
    let body = approve_body("read /etc/passwd", 2, None, "n-consume");
    registry.approve(mint(&approver(), &body).unwrap());

    // Should consume successfully twice
    assert!(registry.consume("read /etc/passwd"));
    assert!(registry.consume("read /etc/passwd"));
    // Third should fail
    assert!(!registry.consume("read /etc/passwd"));
}

// ── Approval Bundle Tests ──────────────────────────────────────────

fn make_test_key() -> (Vec<u8>, nucleus_identity::did::JsonWebKey) {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();
    let pub_bytes = key_pair.public_key().as_ref();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
    let jwk = nucleus_identity::did::JsonWebKey::ec_p256(&x, &y);
    (pkcs8.as_ref().to_vec(), jwk)
}

#[test]
fn test_approval_bundle_populates_registry() {
    let (pkcs8, jwk) = make_test_key();
    let spec = "apiVersion: nucleus/v1\nkind: Pod\nspec:\n  work_dir: .";
    let manifest_hash = compute_manifest_hash(spec.as_bytes());

    let jws =
        nucleus_identity::approval_bundle::ApprovalBundleBuilder::new("spiffe://test/human/alice")
            .approve_operation("write_files")
            .approve_operation("run_bash")
            .manifest_hash(&manifest_hash)
            .ttl_seconds(3600)
            .build(&pkcs8)
            .unwrap();

    let registry = ApprovalRegistry::default();
    let result = verify_and_load_approval_bundle(&jws, spec, &registry, std::slice::from_ref(&jwk));

    assert!(result.is_ok(), "verify_and_load failed: {:?}", result);
    assert!(
        registry.consume("write_files"),
        "write_files should be approved"
    );
    assert!(registry.consume("run_bash"), "run_bash should be approved");
    assert!(
        !registry.consume("web_fetch"),
        "web_fetch should NOT be approved"
    );
}

#[test]
fn test_approval_bundle_wrong_manifest() {
    let (pkcs8, jwk) = make_test_key();
    let manifest_hash = compute_manifest_hash(b"different-manifest");

    let jws =
        nucleus_identity::approval_bundle::ApprovalBundleBuilder::new("spiffe://test/human/bob")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .ttl_seconds(3600)
            .build(&pkcs8)
            .unwrap();

    let registry = ApprovalRegistry::default();
    let result = verify_and_load_approval_bundle(
        &jws,
        "actual-manifest-content",
        &registry,
        std::slice::from_ref(&jwk),
    );
    assert!(result.is_err(), "should fail with manifest hash mismatch");
}

#[test]
fn test_approval_bundle_max_uses() {
    let (pkcs8, jwk) = make_test_key();
    let spec = "spec: limited-use";
    let manifest_hash = compute_manifest_hash(spec.as_bytes());

    let jws =
        nucleus_identity::approval_bundle::ApprovalBundleBuilder::new("spiffe://test/human/carol")
            .approve_operation("write_files")
            .manifest_hash(&manifest_hash)
            .max_uses(2)
            .ttl_seconds(3600)
            .build(&pkcs8)
            .unwrap();

    let registry = ApprovalRegistry::default();
    verify_and_load_approval_bundle(&jws, spec, &registry, std::slice::from_ref(&jwk)).unwrap();

    // Should only allow 2 uses
    assert!(registry.consume("write_files"));
    assert!(registry.consume("write_files"));
    assert!(
        !registry.consume("write_files"),
        "third use should be denied"
    );
}

#[test]
fn test_approval_bundle_invalid_jws() {
    let (_pkcs8, jwk) = make_test_key();
    let registry = ApprovalRegistry::default();
    // A trusted key IS configured, so this exercises the invalid-JWS rejection
    // (not the fail-closed-empty path).
    let result = verify_and_load_approval_bundle(
        "not.a.valid.jws",
        "spec",
        &registry,
        std::slice::from_ref(&jwk),
    );
    assert!(result.is_err());
}

/// SECURITY (approval-gate bypass): the approval bundle must be verified against a
/// PINNED trusted approver key, never the key embedded in the JWS header. Old code
/// passed `&header.jwk` (attacker-controlled) as the expected key → any
/// self-signed bundle verified → the human-approval gate was bypassable. RED on
/// that code; GREEN now (pinned-key + fail-closed).
#[test]
fn approval_bundle_requires_pinned_trusted_key_not_header_self_trust() {
    use nucleus_identity::approval_bundle::{ApprovalBundleBuilder, compute_manifest_hash};

    let spec = "pod: spec yaml";
    let manifest_hash = compute_manifest_hash(spec.as_bytes());

    // Attacker signs a bundle approving a dangerous op with THEIR OWN key.
    let (attacker_key, attacker_jwk) = make_test_key();
    let jws = ApprovalBundleBuilder::new("spiffe://attacker/evil")
        .approve_operation("run_bash")
        .manifest_hash(&manifest_hash)
        .ttl_seconds(3600)
        .build(&attacker_key)
        .unwrap();

    // (1) Fail-closed: no trusted approver key configured ⇒ refuse.
    let approvals = ApprovalRegistry::default();
    let err = verify_and_load_approval_bundle(&jws, spec, &approvals, &[]).unwrap_err();
    assert!(
        format!("{err}").contains("no trusted approver keys"),
        "empty trusted set must refuse fail-closed, got: {err}"
    );

    // (2) THE FIX: attacker's self-signed bundle REJECTED when the pinned trusted
    // approver is a DIFFERENT (legit) key. Old self-trust code ACCEPTED it.
    let (_legit_key, legit_jwk) = make_test_key();
    let approvals = ApprovalRegistry::default();
    assert!(
        verify_and_load_approval_bundle(&jws, spec, &approvals, std::slice::from_ref(&legit_jwk))
            .is_err(),
        "a bundle signed by a non-trusted key must be rejected (no header self-trust)"
    );
    assert!(
        !approvals.consume("run_bash"),
        "the attacker's operation must NOT be registered"
    );

    // (3) No false-negative: a bundle whose signer IS the pinned trusted approver verifies.
    let approvals = ApprovalRegistry::default();
    assert!(
        verify_and_load_approval_bundle(
            &jws,
            spec,
            &approvals,
            std::slice::from_ref(&attacker_jwk)
        )
        .is_ok(),
        "a bundle from the configured trusted approver must verify"
    );
    assert!(
        approvals.consume("run_bash"),
        "the trusted-signed operation must be registered"
    );
}

// ── The mint: VerifiedApproval::verify_request ──────────────────────────────

/// No signature headers at all: nothing mints, whatever the body says.
#[test]
fn a_request_without_a_signature_mints_nothing() {
    let body = approve_body("run_bash", 1, None, "n-unsigned");
    let err = mint_with(
        &HeaderMap::new(),
        &body,
        &approver(),
        &ApprovalNonceCache::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, ApiError::Auth(AuthError::MissingHeader(_))),
        "an unsigned approval must be refused as unauthenticated, got {err:?}"
    );
}

/// A signature over one body does not cover another.
#[test]
fn a_tampered_body_mints_nothing() {
    let key = approver();
    let signed = approve_body("read_files", 1, None, "n-tamper");
    let tampered = approve_body("run_bash", 1, None, "n-tamper");
    let err = mint_with(
        &ed25519_headers(&key, &signed),
        &tampered,
        &key,
        &ApprovalNonceCache::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, ApiError::Auth(AuthError::InvalidSignature)),
        "got {err:?}"
    );
}

/// A signature from a key that is not configured mints nothing.
#[test]
fn a_signature_from_another_key_mints_nothing() {
    let configured = approver();
    let stranger = SigningKey::from_bytes(&[9; 32]);
    let body = approve_body("run_bash", 1, None, "n-stranger");
    let err = mint_with(
        &ed25519_headers(&stranger, &body),
        &body,
        &configured,
        &ApprovalNonceCache::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, ApiError::Auth(AuthError::InvalidSignature)),
        "got {err:?}"
    );
}

/// The signature is checked BEFORE the nonce is burned. Otherwise anyone who
/// can see a nonce in flight could pre-spend it with an unsigned request and
/// the real approval would then be refused as a replay.
#[test]
fn an_unsigned_request_burns_no_nonce() {
    let key = approver();
    let nonces = ApprovalNonceCache::default();
    let body = approve_body("run_bash", 1, None, "n-shared");

    assert!(mint_with(&HeaderMap::new(), &body, &key, &nonces).is_err());
    let forged = approve_body("run_bash", 5, None, "n-shared");
    assert!(mint_with(&ed25519_headers(&key, &body), &forged, &key, &nonces).is_err());

    let _minted = mint_with(&ed25519_headers(&key, &body), &body, &key, &nonces)
        .expect("the signed request must still mint: the refused ones burned nothing");
}

#[test]
fn a_replayed_nonce_mints_nothing() {
    let key = approver();
    let nonces = ApprovalNonceCache::default();
    let body = approve_body("run_bash", 1, None, "n-replay");
    let headers = ed25519_headers(&key, &body);

    let _minted = mint_with(&headers, &body, &key, &nonces).expect("first use mints");
    let err = mint_with(&headers, &body, &key, &nonces).unwrap_err();
    assert!(err.to_string().contains("replayed"), "got {err}");
}

/// A short-lived approval still keeps its nonce for as long as the signed
/// bytes verify. Keeping it only until the approval's own expiry let the
/// same request be replayed inside the timestamp window once the nonce was
/// purged.
#[test]
fn a_short_lived_approval_keeps_its_nonce_for_the_signature_window() {
    let key = approver();
    let nonces = ApprovalNonceCache::default();
    let now = now_unix();
    let body = approve_body("run_bash", 1, Some(now + 1), "n-short");
    let _minted = mint_with(&ed25519_headers(&key, &body), &body, &key, &nonces).expect("mints");

    let later = now + SKEW.as_secs();
    assert!(
        !nonces.check_and_insert("n-short", later + 1, later),
        "the nonce must outlive the approval while the signature is still acceptable"
    );
}

#[test]
fn zero_count_is_refused() {
    let key = approver();
    let nonces = ApprovalNonceCache::default();
    let body = approve_body("run_bash", 0, None, "n-zero");
    let err = mint_with(&ed25519_headers(&key, &body), &body, &key, &nonces).unwrap_err();
    assert!(err.to_string().contains("at least 1"), "got {err}");
    assert!(
        nonces.check_and_insert("n-zero", now_unix() + 60, now_unix()),
        "a refused count burns no nonce"
    );
}

#[test]
fn expiry_is_clamped_to_ttl() {
    let key = approver();
    let now = now_unix();
    let far = approve_body("run_bash", 1, Some(now + 86_400), "n-far");
    let v = mint(&key, &far).unwrap();
    assert!(
        v.expires_at_unix <= now_unix() + MAX_APPROVAL_TTL_SECS
            && v.expires_at_unix >= now + MAX_APPROVAL_TTL_SECS,
        "a day-long request is clamped to the TTL, got {}",
        v.expires_at_unix
    );

    let unset = approve_body("run_bash", 1, None, "n-unset");
    let v = mint(&key, &unset).unwrap();
    assert!(v.expires_at_unix >= now + MAX_APPROVAL_TTL_SECS);

    let past = approve_body("run_bash", 1, Some(now - 10), "n-past");
    let err = mint(&key, &past).unwrap_err();
    assert!(err.to_string().contains("in the past"), "got {err}");
}

/// The legacy HMAC tier mints when signed with the approval secret, and the
/// Ed25519 tier refuses that same HMAC signature: configuring keys removes
/// the secret as a way in.
#[test]
fn hmac_signs_only_where_no_keys_are_configured() {
    let secret = b"approval-secret-for-tests-only-32b";
    let config = AuthConfig::new(secret, SKEW);
    let body = approve_body("run_bash", 1, None, "n-hmac");
    let headers = signed_headers(|m| auth::sign_message(secret, m), &body);

    let _minted = VerifiedApproval::verify_request(
        &headers,
        &body,
        ApprovalKeys::Hmac(&config),
        &ApprovalNonceCache::default(),
        now_unix(),
    )
    .expect("the HMAC tier mints from an HMAC signature");

    let key = approver();
    let err = mint_with(&headers, &body, &key, &ApprovalNonceCache::default()).unwrap_err();
    assert!(
        matches!(err, ApiError::Auth(AuthError::InvalidSignature)),
        "got {err:?}"
    );
}

/// The bypass, end to end at the layer that decides it. A caller holding an
/// SVID asks `/v1/approve` for a grant with no signature. The tier is an
/// approval tier — the certificate does not stand in for a person — and the
/// mint refuses, so the registry has nothing to hold.
#[test]
fn an_svid_without_a_signature_grants_nothing() {
    for pubkeys in [false, true] {
        let tier = auth::select_auth_tier(true, true, pubkeys, false);
        assert!(
            matches!(
                tier,
                auth::AuthTier::ApprovalEd25519Drand | auth::AuthTier::ApprovalHmacDrand
            ),
            "an SVID on /v1/approve selected {tier:?}"
        );
    }
    let registry = ApprovalRegistry::default();
    let body = approve_body("run_bash", 1, None, "n-svid");
    if let Ok(v) = mint_with(
        &HeaderMap::new(),
        &body,
        &approver(),
        &ApprovalNonceCache::default(),
    ) {
        registry.approve(v);
    }
    assert!(!registry.is_granted("run_bash"));
}

// ── The mint: VerifiedApproval::verify_bundle ───────────────────────────────

fn bundle(ops: &[&str], max_uses: Option<u32>, key: &[u8], spec: &str) -> String {
    let manifest_hash = compute_manifest_hash(spec.as_bytes());
    let mut b = nucleus_identity::approval_bundle::ApprovalBundleBuilder::new(
        "spiffe://test/human/approver",
    )
    .manifest_hash(&manifest_hash)
    .ttl_seconds(3600);
    for op in ops {
        b = b.approve_operation(*op);
    }
    if let Some(n) = max_uses {
        b = b.max_uses(n);
    }
    b.build(key).unwrap()
}

#[test]
fn an_untrusted_bundle_key_mints_nothing() {
    let spec = "spec: untrusted";
    let hash = compute_manifest_hash(spec.as_bytes());
    let (signer, _signer_jwk) = make_test_key();
    let (_other, other_jwk) = make_test_key();
    let jws = bundle(&["run_bash"], None, &signer, spec);

    assert!(VerifiedApproval::verify_bundle(&jws, &hash, &[]).is_err());
    assert!(
        VerifiedApproval::verify_bundle(&jws, &hash, std::slice::from_ref(&other_jwk)).is_err()
    );
}

#[test]
fn bundle_mints_one_approval_per_operation() {
    let spec = "spec: per-op";
    let hash = compute_manifest_hash(spec.as_bytes());
    let (signer, jwk) = make_test_key();

    let jws = bundle(&["write_files", "run_bash"], None, &signer, spec);
    let minted = VerifiedApproval::verify_bundle(&jws, &hash, std::slice::from_ref(&jwk)).unwrap();
    let mut ops: Vec<&str> = minted.iter().map(|v| v.operation.as_str()).collect();
    ops.sort_unstable();
    assert_eq!(ops, ["run_bash", "write_files"]);
    assert!(
        minted.iter().all(|v| v.count == ApprovalCount::UntilExpiry),
        "no max_uses is the bundle format's until-expiry, said as such"
    );

    let jws = bundle(&["write_files"], Some(2), &signer, spec);
    let minted = VerifiedApproval::verify_bundle(&jws, &hash, std::slice::from_ref(&jwk)).unwrap();
    assert_eq!(minted.len(), 1);
    assert_eq!(
        minted[0].count,
        ApprovalCount::Bounded(NonZeroUsize::new(2).unwrap())
    );
}

#[test]
fn a_zero_use_bundle_is_refused() {
    let spec = "spec: zero";
    let hash = compute_manifest_hash(spec.as_bytes());
    let (signer, jwk) = make_test_key();
    let jws = bundle(&["run_bash"], Some(0), &signer, spec);
    assert!(VerifiedApproval::verify_bundle(&jws, &hash, std::slice::from_ref(&jwk)).is_err());
}

/// `UntilExpiry` used to be `usize::MAX`, and the registry added counts with
/// `+=`. Two bundles naming one operation overflowed it — a panic in a debug
/// build, a wrap to a tiny count in release.
#[test]
fn until_expiry_is_never_spent_and_never_overflows() {
    let spec = "spec: until-expiry";
    let (signer, jwk) = make_test_key();
    let jws = bundle(&["run_bash"], None, &signer, spec);
    let registry = ApprovalRegistry::default();
    verify_and_load_approval_bundle(&jws, spec, &registry, std::slice::from_ref(&jwk)).unwrap();
    verify_and_load_approval_bundle(&jws, spec, &registry, std::slice::from_ref(&jwk)).unwrap();
    for _ in 0..100 {
        assert!(registry.consume("run_bash"));
    }
}
