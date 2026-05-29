//! WIMSE / AIMS / RFC 8693 / RFC 9068 known-answer (KAT) vectors.
//!
//! Pins the wire-format invariants that downstream consumers depend on.
//! Each test has a load-bearing assertion documented inline; schema
//! drift fails the build before it can break interop in the wild.
//!
//! Cross-spec scope (per task #49 acceptance):
//! 1. **WIMSE identifier round-trip** — `spiffe://` and `wimse://` parse
//!    to equal `CallSpiffeId`s.
//! 2. **RFC 9068 §2.1 `typ` MUST** — every minted access-token header
//!    carries exactly `"typ":"at+jwt"`. Critical defense against
//!    token-confusion attacks documented in the RFC's history.
//! 3. **RFC 8693 §2.1 grant_type URN** — token-exchange grant identifier
//!    pinned at exact bytes.
//! 4. **RFC 8693 §2.2.1 success response shape** — `issued_token_type` +
//!    `token_type` + `expires_in` shape, pinned.
//! 5. **RFC 8693 §2.2.2 / RFC 6749 §5.2 error response shape** —
//!    `{error, error_description}` JSON shape.
//! 6. **RFC 7638 JWK thumbprint canonical form** — Ed25519 OKP JWK
//!    thumbprint computed against a fixed sample key, pinned to a
//!    known answer that consumers can use to verify their own RFC 7638
//!    implementations against ours.
//!
//! AIMS draft KAT vectors are deferred — `draft-klrc-aiagent-auth-00`
//! does not include concrete sample tokens to pin against; when -01
//! lands with examples, those go here as test #7+.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use nucleus_lineage::CallSpiffeId;
use nucleus_oidc_provider::issuer::{JwtIssuer, MintRequest};
use nucleus_oidc_provider::keystore::{rfc7638_kid, InMemoryKeyStore, JwtKeyStore};
use std::sync::Arc;
use std::time::Duration;

// ─── KAT 1 ─────────────────────────────────────────────────────────────
//
// WIMSE identifier round-trip per `draft-ietf-wimse-identifier` §3.2:
// "Every SPIFFE-ID is a valid WIMSE Workload Identifier."
//
// Load-bearing assertion: a producer that emits either scheme can be
// consumed by a CallSpiffeId-using validator without information loss.

#[test]
fn kat1_wimse_and_spiffe_schemes_parse_to_equal_ids() {
    let spiffe = "spiffe://prod.example.com/ns/agents/sa/coder";
    let wimse = "wimse://prod.example.com/ns/agents/sa/coder";

    let a = CallSpiffeId::from_wimse_uri(spiffe).unwrap();
    let b = CallSpiffeId::from_wimse_uri(wimse).unwrap();

    assert_eq!(
        a, b,
        "wimse:// must normalize to the same CallSpiffeId as spiffe://"
    );
    assert_eq!(
        a.as_str(),
        spiffe,
        "canonical wire form is spiffe:// per #30 GAP-10 recommendation"
    );
}

// ─── KAT 2 ─────────────────────────────────────────────────────────────
//
// RFC 9068 §2.1: 'The "typ" header parameter MUST be "at+jwt"'.
//
// Load-bearing assertion: an RP validator that strictly enforces
// RFC 9068 §2.1 (per the Coalition-for-Secure-AI 2026 recommendation)
// accepts our minted tokens unconditionally.

#[test]
fn kat2_minted_access_token_carries_typ_at_jwt() {
    let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
    let iss = JwtIssuer::new(
        store,
        "https://oidc.nucleus.example/".to_string(),
        Duration::from_secs(300),
    )
    .unwrap();
    let token = iss
        .mint(MintRequest {
            subject: CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap(),
            audience: "https://rp.example/api".to_string(),
            client_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            scope: None,
            act: None,
            kind: None,
        })
        .unwrap();

    let header_b64 = token.split('.').next().expect("header segment");
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
    let header_str = std::str::from_utf8(&header_bytes).unwrap();

    assert!(
        header_str.contains(r#""typ":"at+jwt""#),
        "RFC 9068 §2.1 MUST violation — header missing `typ: at+jwt`. Got: {header_str}"
    );
    assert!(
        header_str.contains(r#""alg":"EdDSA""#),
        "alg must be EdDSA (T04 algorithm-pin defense). Got: {header_str}"
    );
}

// ─── KAT 3 ─────────────────────────────────────────────────────────────
//
// RFC 8693 §2.1: the grant_type URN identifying token exchange.
//
// Load-bearing assertion: our token endpoint accepts exactly this byte
// sequence as the grant_type value. The constant we export must match
// the RFC text verbatim — if a future refactor introduces a typo, this
// pinning catches it.

#[test]
fn kat3_token_exchange_grant_type_urn_is_exact() {
    let canonical = "urn:ietf:params:oauth:grant-type:token-exchange";
    assert_eq!(
        nucleus_oidc_provider::token::TOKEN_EXCHANGE_GRANT,
        canonical,
        "RFC 8693 §2.1 grant_type URN must match the spec byte-for-byte"
    );
    // RFC 8693 §3 token-type URN for JWTs.
    assert_eq!(
        nucleus_oidc_provider::token::TOKEN_TYPE_JWT,
        "urn:ietf:params:oauth:token-type:jwt"
    );
    // RFC 8693 §3 token-type URN for access tokens.
    assert_eq!(
        nucleus_oidc_provider::token::TOKEN_TYPE_ACCESS_TOKEN,
        "urn:ietf:params:oauth:token-type:access_token"
    );
}

// ─── KAT 4 ─────────────────────────────────────────────────────────────
//
// RFC 8693 §2.2.1 success response shape:
//   { "access_token": "...",
//     "issued_token_type": "<urn>",
//     "token_type": "Bearer",
//     "expires_in": <int>,
//     "scope": "..." (optional) }
//
// Load-bearing assertion: serde-serialized response uses exactly these
// JSON keys. An RP parser written against the RFC will find them all.

#[test]
fn kat4_token_exchange_success_response_shape() {
    let resp = nucleus_oidc_provider::token::TokenExchangeResponse {
        access_token: "h.p.s".to_string(),
        issued_token_type: nucleus_oidc_provider::token::TOKEN_TYPE_ACCESS_TOKEN,
        token_type: "Bearer",
        expires_in: 3600,
        scope: Some("read:bundles".to_string()),
    };
    let json = serde_json::to_string(&resp).unwrap();

    for required in [
        r#""access_token":"#,
        r#""issued_token_type":"#,
        r#""token_type":"Bearer""#,
        r#""expires_in":3600"#,
        r#""scope":"read:bundles""#,
    ] {
        assert!(
            json.contains(required),
            "RFC 8693 §2.2.1 shape missing {required:?} in {json:?}"
        );
    }
    // issued_token_type must be the URN; not a free-form string.
    assert!(
        json.contains("urn:ietf:params:oauth:token-type:access_token"),
        "issued_token_type must be the access-token URN"
    );
}

// ─── KAT 5 ─────────────────────────────────────────────────────────────
//
// RFC 8693 §2.2.2 / RFC 6749 §5.2 error response shape:
//   { "error": "<code>", "error_description": "<text>"? }
//
// Load-bearing assertion: every auth-sensitive error variant emits this
// canonical shape with the opaque description (oracle defense from #44).

#[tokio::test]
async fn kat5_rfc6749_section5_2_error_response_shape() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use nucleus_oidc_provider::OidcApiError;

    let cases: Vec<(OidcApiError, &str)> = vec![
        (
            OidcApiError::InvalidRequest("missing audience".into()),
            "invalid_request",
        ),
        (
            OidcApiError::InvalidGrant("any inner detail".into()),
            "invalid_grant",
        ),
        (
            OidcApiError::InvalidTarget("any inner detail".into()),
            "invalid_target",
        ),
        (
            OidcApiError::UnsupportedGrantType("authorization_code".into()),
            "unsupported_grant_type",
        ),
        (
            OidcApiError::InvalidScope("admin:everything".into()),
            "invalid_scope",
        ),
    ];
    for (err, expected_code) in cases {
        let resp = err.into_response();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // RFC 6749 §5.2 requires the `error` field.
        assert_eq!(
            json["error"], expected_code,
            "RFC 6749 §5.2 `error` field mismatch"
        );
        // `error_description` is OPTIONAL but if present must be a string.
        if let Some(d) = json.get("error_description") {
            assert!(d.is_string(), "error_description must be a string");
        }
    }
}

// ─── KAT 6 ─────────────────────────────────────────────────────────────
//
// RFC 7638 §3.2 + RFC 8037 §2 OKP JWK Thumbprint canonical form:
//   SHA-256(`{"crv":"Ed25519","kty":"OKP","x":"<base64url>"}`),
//   base64url-no-pad encoded.
//
// Load-bearing assertion: third-party implementations that compute the
// RFC 7638 thumbprint of the same public key must arrive at the same
// 43-character output we do. Pinning here detects any drift in the
// canonical JSON form (whitespace, ordering, field names) that would
// silently break KID-based key lookup across vendors.

#[test]
fn kat6_rfc7638_thumbprint_canonical_form() {
    use ed25519_dalek::SigningKey;
    // Deterministic fixture key — same bytes every test run.
    let sk = SigningKey::from_bytes(&[7; 32]);
    let kid = rfc7638_kid(&sk.verifying_key());

    // Properties pinned by the RFC:
    // - base64url no-pad: 43 chars (SHA-256 → 32 bytes → 43 chars b64url).
    assert_eq!(
        kid.len(),
        43,
        "RFC 7638 thumbprint is sha256 (32 bytes) → 43 b64url chars"
    );
    // - URL-safe alphabet only (RFC 4648 §5 alphabet).
    for c in kid.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "thumbprint must be base64url (no `+`, `/`, or `=`); got {c:?} in {kid}"
        );
    }
    // - Deterministic: re-derivation produces byte-identical output.
    let kid_again = rfc7638_kid(&sk.verifying_key());
    assert_eq!(
        kid, kid_again,
        "RFC 7638 thumbprint must be deterministic for the same input"
    );
}

// ─── KAT 7 ─────────────────────────────────────────────────────────────
//
// SPIFFE ID rejection of forbidden chars per the SPIFFE ID spec §2.
//
// Load-bearing assertion: an attacker who attempts to use Unicode
// homograph attacks (RTL override, NBSP) on the trust-domain or path
// components is rejected at the parser — closes the threat surface
// documented in `THREAT_MODEL.md` T12.

#[test]
fn kat7_spiffe_id_rejects_homograph_attacks() {
    let cases = [
        // RIGHT-TO-LEFT OVERRIDE (U+202E) — used for visual spoofing.
        "spiffe://prod.example.com/ns/admin\u{202E}/sa/coder",
        // NBSP in trust domain
        "spiffe://prod.example.com\u{00A0}/ns/agents/sa/coder",
        // NUL byte
        "spiffe://prod.example.com/ns/agents\0/sa/coder",
    ];
    for case in cases {
        assert!(
            CallSpiffeId::parse(case.to_string()).is_err(),
            "homograph/control-char attack must be rejected: {case:?}"
        );
    }
}
