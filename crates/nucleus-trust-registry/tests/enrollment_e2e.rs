// SPDX-License-Identifier: MIT
//
//! Adversarial enrollment merge gate + positive end-to-end.
//!
//! Every negative below is a fail-closed requirement: the registry MUST
//! reject the attack. The positive control runs the whole pipeline:
//! parse → valid OIDC proof-of-control → compile → append+cosign →
//! `FederationStore` validates a real ES256 JWT-SVID minted by the
//! enrolled domain's key.
//!
//! Tokens are minted with the SAME shared workspace test keys the
//! `nucleus-github-oidc` (RSA, for the GitHub OIDC proof) and
//! `nucleus-oidc-core` SPIFFE-federation (P-256, for the JWT-SVID) suites
//! use — no mocks of the crypto.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use nucleus_lineage::checkpoint::Ed25519Witness;
use nucleus_oidc_core::Jwks;
use nucleus_trust_registry::{
    build_federation_store, check_no_silent_rotation, check_pr_diff, compile, tlog,
    verify_proof_of_control, DomainMetadata, RegistryError, TrustLog,
};
use nucleus_witness::cosign::WitnessKey;
use serde_json::json;

// ---- shared RSA test key (GitHub OIDC RS256 proof), same as nucleus-fly-oidc ----
const RSA_PRIV: &str = include_str!("../../nucleus-fly-oidc/testdata/jwt_test_priv.pem");
const RSA_KID: &str = "test-kid";
const GITHUB_JWKS: &str = include_str!("../testdata/github_jwks.json");

// ---- shared P-256 JWT-SVID key (the ci.example.org enrolled domain) ----
const SVID_PRIV_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8QBklzAZ+ClJWMEf
ffyt/fTwPs4bH0Z5Jde69PJpdyOhRANCAASj+6zyzUTGr19+snfoRxOe0HTCpqkN
Av3cQeW1auNiO2LflCA1h4e7xEQ9FfVbV/VzB3Z5Ol7Ywz3cv7eHMbMZ
-----END PRIVATE KEY-----";
const SVID_KID: &str = "ci-jwt-svid-1";

const REGISTRY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/registry");
const TRUST_DOMAIN: &str = "ci.example.org";
const OWNER_ORG: &str = "coproduct-opensource";
const OWNER_ID: u64 = 12345;
const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn github_jwks() -> Jwks {
    serde_json::from_str(GITHUB_JWKS).expect("github jwks parses")
}

fn metadata() -> DomainMetadata {
    let md = std::fs::read(format!(
        "{REGISTRY_DIR}/domains/{TRUST_DOMAIN}/metadata.toml"
    ))
    .unwrap();
    DomainMetadata::from_toml(&md).unwrap()
}

/// Mint a GitHub Actions OIDC proof-of-control token with overridable
/// claims, signed RS256 by the shared test key.
fn mint_oidc(
    iss: &str,
    owner: &str,
    owner_id_claim: serde_json::Value,
    exp_offset: i64,
    kid: &str,
) -> String {
    let n = now() as i64;
    let claims = json!({
        "iss": iss,
        "aud": "nucleus-trust-registry",
        "exp": n + exp_offset,
        "iat": n - 30,
        "jti": "j-1",
        "repository": format!("{owner}/registry-enroll"),
        "repository_owner": owner,
        "repository_owner_id": owner_id_claim,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(RSA_PRIV.as_bytes()).expect("rsa pem parses");
    encode(&header, &claims, &key).expect("token encodes")
}

/// The well-formed, valid proof for ci.example.org.
fn valid_oidc() -> String {
    mint_oidc(GITHUB_ISSUER, OWNER_ORG, json!("12345"), 600, RSA_KID)
}

fn mint_es256_svid(sub: &str, aud: &str, exp: u64) -> String {
    let key = EncodingKey::from_ec_pem(SVID_PRIV_PKCS8.as_bytes()).expect("EC pem parses");
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(SVID_KID.to_string());
    let claims = json!({ "sub": sub, "aud": aud, "exp": exp });
    encode(&header, &claims, &key).expect("ES256 sign")
}

// =====================================================================
// PROOF-OF-CONTROL NEGATIVES
// =====================================================================

#[test]
fn neg_forged_wrong_owner_id_rejected() {
    // Correct org login, WRONG numeric id → org-rename squat defense.
    let token = mint_oidc(GITHUB_ISSUER, OWNER_ORG, json!("99999"), 600, RSA_KID);
    let err = verify_proof_of_control(&token, &metadata(), &github_jwks()).unwrap_err();
    assert!(
        matches!(err, RegistryError::ProofOfControl(ref m) if m.contains("owner_id")),
        "got {err:?}"
    );
}

#[test]
fn neg_wrong_owner_org_rejected() {
    // Right numeric id is impossible to fake for a different org, but test
    // the login cross-check independently: id matches, login differs.
    // (Construct a metadata whose id matches the token but org differs.)
    let token = mint_oidc(GITHUB_ISSUER, "attacker-org", json!("12345"), 600, RSA_KID);
    let err = verify_proof_of_control(&token, &metadata(), &github_jwks()).unwrap_err();
    assert!(
        matches!(err, RegistryError::ProofOfControl(ref m) if m.contains("repository_owner")),
        "got {err:?}"
    );
}

#[test]
fn neg_expired_token_rejected() {
    let token = mint_oidc(GITHUB_ISSUER, OWNER_ORG, json!("12345"), -3600, RSA_KID);
    let err = verify_proof_of_control(&token, &metadata(), &github_jwks()).unwrap_err();
    assert!(
        matches!(err, RegistryError::ProofOfControl(_)),
        "got {err:?}"
    );
}

#[test]
fn neg_wrong_issuer_rejected() {
    let token = mint_oidc(
        "https://evil.example.com",
        OWNER_ORG,
        json!("12345"),
        600,
        RSA_KID,
    );
    let err = verify_proof_of_control(&token, &metadata(), &github_jwks()).unwrap_err();
    assert!(
        matches!(err, RegistryError::ProofOfControl(_)),
        "got {err:?}"
    );
}

#[test]
fn neg_forged_signature_unknown_kid_rejected() {
    // A token whose kid is not in GitHub's JWKS → no verifying key.
    let token = mint_oidc(
        GITHUB_ISSUER,
        OWNER_ORG,
        json!("12345"),
        600,
        "attacker-kid",
    );
    let err = verify_proof_of_control(&token, &metadata(), &github_jwks()).unwrap_err();
    assert!(
        matches!(err, RegistryError::ProofOfControl(ref m) if m.contains("kid")),
        "got {err:?}"
    );
}

#[test]
fn neg_missing_proof_rejected() {
    // An empty / non-JWT token string is rejected as a malformed proof.
    let err = verify_proof_of_control("", &metadata(), &github_jwks()).unwrap_err();
    assert!(
        matches!(err, RegistryError::ProofOfControl(_)),
        "got {err:?}"
    );
}

#[test]
fn neg_wrong_signing_key_rejected() {
    // Sign with an attacker RSA key but reuse the legitimate kid; the
    // verifier selects GitHub's pinned key for that kid → signature fails.
    const ATTACKER_PRIV: &str = include_str!("../testdata/attacker_rsa_priv.pem");
    let n = now() as i64;
    let claims = json!({
        "iss": GITHUB_ISSUER, "aud": "a", "exp": n + 600, "iat": n - 30, "jti": "j",
        "repository": "coproduct-opensource/x",
        "repository_owner": OWNER_ORG, "repository_owner_id": "12345",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(RSA_KID.to_string());
    let key = EncodingKey::from_rsa_pem(ATTACKER_PRIV.as_bytes()).expect("attacker rsa parses");
    let token = encode(&header, &claims, &key).unwrap();
    let err = verify_proof_of_control(&token, &metadata(), &github_jwks()).unwrap_err();
    assert!(
        matches!(err, RegistryError::ProofOfControl(_)),
        "got {err:?}"
    );
}

// =====================================================================
// BUNDLE / METADATA NEGATIVES
// =====================================================================

#[test]
fn neg_malformed_bundle_rejected() {
    use nucleus_oidc_core::spiffe_federation::SpiffeBundle;
    let err = SpiffeBundle::from_json(b"{not json").unwrap_err();
    // The bundle parser (reused) rejects non-JWKS / malformed bundles.
    assert!(matches!(err, nucleus_oidc_core::OidcError::InvalidJwks(_)));
}

#[test]
fn neg_inferred_binding_host_equals_trust_domain_rejected() {
    let toml = r#"
trust_domain = "ci.example.org"
owner_github_org = "org"
owner_id = 1
bundle_endpoint_url = "https://ci.example.org/bundle"
profile = "https_web"
"#;
    let err = DomainMetadata::from_toml(toml.as_bytes()).unwrap_err();
    assert!(
        matches!(err, RegistryError::InferredBinding { .. }),
        "got {err:?}"
    );
}

#[test]
fn neg_missing_federation_param_rejected() {
    // Missing bundle_endpoint_url (a required, un-inferable param).
    let toml = r#"
trust_domain = "ci.example.org"
owner_github_org = "org"
owner_id = 1
profile = "https_web"
"#;
    let err = DomainMetadata::from_toml(toml.as_bytes()).unwrap_err();
    assert!(matches!(err, RegistryError::Metadata(_)), "got {err:?}");
}

// =====================================================================
// SILENT-ROTATION + DIFF-SMUGGLING NEGATIVES
// =====================================================================

#[test]
fn neg_silent_rotation_rejected() {
    // Incumbent set has ci.example.org with owner_id 12345 (on disk).
    let incumbent = compile(std::path::Path::new(REGISTRY_DIR)).unwrap();
    // A new proof for the SAME domain with a DIFFERENT owner_id is a
    // takeover attempt.
    let err = check_no_silent_rotation(&incumbent, TRUST_DOMAIN, 99999).unwrap_err();
    assert!(
        matches!(err, RegistryError::SilentRotation { .. }),
        "got {err:?}"
    );
    // Same owner_id (a legitimate key rotation by the incumbent) is OK.
    check_no_silent_rotation(&incumbent, TRUST_DOMAIN, OWNER_ID).unwrap();
}

#[test]
fn neg_diff_smuggling_rejected() {
    let changed = vec![
        format!("registry/domains/{TRUST_DOMAIN}/bundle.json"),
        "registry/domains/other.example.org/bundle.json".to_string(),
        ".github/workflows/release.yml".to_string(),
    ];
    let err = check_pr_diff(&changed, TRUST_DOMAIN, "registry").unwrap_err();
    match err {
        RegistryError::DiffSmuggling { offending, .. } => {
            assert_eq!(offending.len(), 2);
        }
        other => panic!("expected DiffSmuggling, got {other:?}"),
    }
}

// =====================================================================
// TRANSPARENCY-LOG NEGATIVES
// =====================================================================

#[test]
fn neg_binding_not_in_cosigned_sth_rejected() {
    let witness = Ed25519Witness::from_seed([3u8; 32]);
    let cosigner = WitnessKey::from_seed([9u8; 32], "w");
    let bundle = b"{\"keys\":[],\"spiffe_sequence\":1}";
    let mut log = TrustLog::new();
    log.append_binding("a.example.org", bundle, 1, 100).unwrap();
    let sealed = log.seal(&witness, &cosigner, 1_700_000_000).unwrap();
    // A rogue binding never appended → no inclusion proof in the cosigned STH.
    let err = tlog::verify_binding_in_log(
        &sealed,
        "rogue.example.org",
        bundle,
        2,
        200,
        &cosigner.verifying_key_bytes(),
    )
    .unwrap_err();
    assert!(matches!(err, RegistryError::NotInLog(_)), "got {err:?}");
}

#[test]
fn neg_tampered_bundle_breaks_inclusion() {
    let witness = Ed25519Witness::from_seed([3u8; 32]);
    let cosigner = WitnessKey::from_seed([9u8; 32], "w");
    let bundle = b"{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"jwt-svid\",\"kid\":\"k\",\"x\":\"AA\",\"y\":\"BB\"}],\"spiffe_sequence\":1}";
    let mut log = TrustLog::new();
    log.append_binding(TRUST_DOMAIN, bundle, OWNER_ID, 100)
        .unwrap();
    let sealed = log.seal(&witness, &cosigner, 1_700_000_000).unwrap();
    let tampered = b"{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"jwt-svid\",\"kid\":\"ATTACKER\",\"x\":\"AA\",\"y\":\"BB\"}],\"spiffe_sequence\":1}";
    let err = tlog::verify_binding_in_log(
        &sealed,
        TRUST_DOMAIN,
        tampered,
        OWNER_ID,
        100,
        &cosigner.verifying_key_bytes(),
    )
    .unwrap_err();
    assert!(matches!(err, RegistryError::NotInLog(_)), "got {err:?}");
}

// =====================================================================
// POSITIVE END-TO-END
// =====================================================================

#[test]
fn positive_full_pipeline_enrolls_and_validates_svid() {
    // 1. Diff scope: PR touches only the claimed domain's files.
    let changed = vec![
        format!("registry/domains/{TRUST_DOMAIN}/bundle.json"),
        format!("registry/domains/{TRUST_DOMAIN}/metadata.toml"),
    ];
    check_pr_diff(&changed, TRUST_DOMAIN, "registry").unwrap();

    // 2. Parse the enrollment from the registry dir.
    let md = metadata();
    assert_eq!(md.owner_id, OWNER_ID);

    // 3. Valid OIDC proof-of-control (numeric owner_id pin passes).
    let claims = verify_proof_of_control(&valid_oidc(), &md, &github_jwks()).unwrap();
    assert_eq!(claims.repository_owner_id, OWNER_ID);
    assert_eq!(claims.repository_owner, OWNER_ORG);

    // 4. Compile the registry deterministically.
    let set = compile(std::path::Path::new(REGISTRY_DIR)).unwrap();
    assert_eq!(set.len(), 1);
    let binding = set.bindings.get(TRUST_DOMAIN).unwrap();

    // 5. Append the binding to the transparency log + cosign the STH.
    let witness = Ed25519Witness::from_seed([3u8; 32]);
    let cosigner = WitnessKey::from_seed([9u8; 32], "nucleus.trust-registry/witness-1");
    let ts = 1_700_000_000u64;
    let mut log = TrustLog::new();
    log.append_binding(
        TRUST_DOMAIN,
        &binding.bundle_bytes,
        claims.repository_owner_id,
        ts,
    )
    .unwrap();
    let sealed = log.seal(&witness, &cosigner, ts).unwrap();

    // 6. Binding is trusted ONLY because its leaf is in the cosigned STH.
    tlog::verify_binding_in_log(
        &sealed,
        TRUST_DOMAIN,
        &binding.bundle_bytes,
        claims.repository_owner_id,
        ts,
        &cosigner.verifying_key_bytes(),
    )
    .unwrap();

    // 7. Wire the compiled set into the inbound FederationStore and
    //    validate a REAL ES256 JWT-SVID minted by the enrolled domain.
    let aud = "spiffe://prod.example.org/api";
    let store = build_federation_store(&set, aud).unwrap();
    let sub = "spiffe://ci.example.org/runner/42";
    let token = mint_es256_svid(sub, aud, now() + 300);
    let id = store
        .validate_jwt_svid(&token, aud)
        .expect("JWT-SVID from the enrolled domain must validate end-to-end");
    assert_eq!(id.trust_domain, TRUST_DOMAIN);
    assert_eq!(id.path, "/runner/42");
}
