//! SPIFFE JWT-SVID Bearer authentication for the control-plane-server.
//!
//! Closes the strategic loop: the [`nucleus-oidc-provider`][op] OIDC
//! OP we shipped earlier mints JWT-SVIDs; the control plane verifies
//! them and uses the SPIFFE subject for federation decisions. Same
//! trust domain, same SPIFFE identity hierarchy, end-to-end.
//!
//! [op]: ../../nucleus-oidc-provider/index.html
//!
//! # Wire shape
//!
//! Clients present a JWT-SVID per RFC 6750 §2.1:
//!
//! ```text
//! Authorization: Bearer <compact-jws>
//! ```
//!
//! The JWS:
//! - MUST use `alg = "EdDSA"` (RFC 8037; SPIFFE JWT-SVID spec)
//! - MUST carry a `kid` resolvable in the configured trust JWKS
//! - MUST set `aud` containing the configured audience
//! - MUST set `sub` starting with the configured SPIFFE prefix
//!   (e.g. `spiffe://prod.example.com/ns/agents/sa/`)
//! - MUST have an `exp` in the future (clock-skew leeway: 60s)
//! - MAY have an `nbf` in the past
//!
//! # Auth-disabled mode
//!
//! When [`AppState::spiffe_auth`](crate::state::AppState::spiffe_auth)
//! is `None`, the [`RequireSpiffeAuth`] extractor admits a synthetic
//! "unauthenticated" principal. This preserves the v0 unauthenticated
//! behavior for existing demos and CI tests. Production deploys MUST
//! configure SPIFFE auth.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use nucleus_oidc_core::{JwkPublicKey, Jwks};
use serde::Deserialize;
use thiserror::Error;

use crate::state::AppState;

/// Default clock-skew leeway in seconds. Matches the nucleus-oidc-provider
/// HIGH-2 setting so a token minted by the OP within the leeway window
/// is accepted by both.
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 60;

/// SPIFFE-JWT-SVID Bearer auth configuration. Carried by
/// [`AppState`] as an `Arc<SpiffeAuthConfig>`; absent means
/// auth-disabled.
#[derive(Debug, Clone)]
pub struct SpiffeAuthConfig {
    /// Trust JWKS published by the OIDC OP. Verifiers look up the
    /// header `kid` here.
    pub trust_jwks: Jwks,
    /// Required `aud` claim value. Bundles minted for a DIFFERENT
    /// audience must not be replayable against the control plane —
    /// this is the RFC 8693 confused-deputy guard.
    pub allowed_audience: String,
    /// Required `sub` prefix. Restricts callers to a specific SPIFFE
    /// namespace / service account. Example:
    /// `spiffe://prod.example.com/ns/agents/sa/`
    pub allowed_subject_prefix: String,
    /// Clock-skew leeway in seconds (default
    /// [`DEFAULT_CLOCK_SKEW_SECS`]).
    pub clock_skew_secs: u64,
}

impl SpiffeAuthConfig {
    /// Builder helper with sensible defaults.
    pub fn new(
        trust_jwks: Jwks,
        allowed_audience: impl Into<String>,
        allowed_subject_prefix: impl Into<String>,
    ) -> Self {
        Self {
            trust_jwks,
            allowed_audience: allowed_audience.into(),
            allowed_subject_prefix: allowed_subject_prefix.into(),
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        }
    }
}

/// Information the verifier extracts from a valid JWT-SVID. Handlers
/// downstream may inspect `sub` for fine-grained federation decisions.
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal {
    /// SPIFFE subject id. `spiffe://...` URL.
    pub sub: String,
    /// All `aud` values from the token.
    pub aud: Vec<String>,
    /// True iff verification was performed against a configured trust
    /// JWKS. False when auth is disabled (synthetic admit path).
    pub authenticated: bool,
}

impl AuthenticatedPrincipal {
    /// Synthetic admit path for auth-disabled deployments. The `sub`
    /// is the literal string `"<unauthenticated>"` so handlers that
    /// log it can't be tricked into reading it as a real SPIFFE id.
    pub fn unauthenticated() -> Self {
        Self {
            sub: "<unauthenticated>".to_string(),
            aud: Vec::new(),
            authenticated: false,
        }
    }
}

/// Reasons a JWT-SVID may be rejected.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing Authorization header")]
    MissingAuthorizationHeader,
    #[error("Authorization header is not a Bearer token")]
    NotBearer,
    #[error("token is structurally malformed")]
    Malformed,
    #[error("alg {0:?} is not in the allowed set (EdDSA only)")]
    DisallowedAlg(String),
    #[error("kid {kid:?} is not present in the trust JWKS")]
    UnknownKid { kid: Option<String> },
    #[error("only Ed25519 JWKs are supported (RSA/EC rejected)")]
    UnsupportedKeyType,
    #[error("signature failed verification")]
    BadSignature,
    #[error("token has expired (exp={exp}, now={now})")]
    Expired { exp: u64, now: u64 },
    #[error("token not yet valid (nbf={nbf}, now={now})")]
    NotYetValid { nbf: u64, now: u64 },
    #[error("audience claim does not match")]
    AudienceMismatch,
    #[error("subject {sub:?} does not start with allowed prefix")]
    SubjectPrefixMismatch { sub: String },
    #[error("system clock before unix epoch (server misconfigured)")]
    ClockBeforeEpoch,
}

impl AuthError {
    /// Map to an HTTP status. Malformed / missing → 401; mismatched
    /// audience or subject → 403 (auth recognized, authz denied).
    pub fn status(&self) -> StatusCode {
        match self {
            AuthError::MissingAuthorizationHeader
            | AuthError::NotBearer
            | AuthError::Malformed
            | AuthError::DisallowedAlg(_)
            | AuthError::UnknownKid { .. }
            | AuthError::UnsupportedKeyType
            | AuthError::BadSignature
            | AuthError::Expired { .. }
            | AuthError::NotYetValid { .. } => StatusCode::UNAUTHORIZED,
            AuthError::AudienceMismatch | AuthError::SubjectPrefixMismatch { .. } => {
                StatusCode::FORBIDDEN
            }
            AuthError::ClockBeforeEpoch => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwsClaims {
    sub: String,
    #[serde(default)]
    aud: AudienceClaim,
    exp: u64,
    #[serde(default)]
    nbf: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl Default for AudienceClaim {
    fn default() -> Self {
        AudienceClaim::Many(Vec::new())
    }
}

impl AudienceClaim {
    fn into_vec(self) -> Vec<String> {
        match self {
            AudienceClaim::One(s) => vec![s],
            AudienceClaim::Many(v) => v,
        }
    }
}

/// Verify a compact-JWS JWT-SVID against the configured trust JWKS
/// + audience + subject prefix.
pub fn verify_jwt_svid(
    token: &str,
    config: &SpiffeAuthConfig,
) -> Result<AuthenticatedPrincipal, AuthError> {
    let mut parts = token.splitn(3, '.');
    let header_b64 = parts.next().ok_or(AuthError::Malformed)?;
    let payload_b64 = parts.next().ok_or(AuthError::Malformed)?;
    let sig_b64 = parts.next().ok_or(AuthError::Malformed)?;
    if parts.next().is_some() {
        return Err(AuthError::Malformed);
    }

    let header_bytes = B64URL
        .decode(header_b64)
        .map_err(|_| AuthError::Malformed)?;
    let header: JwsHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| AuthError::Malformed)?;

    // RFC 8725 §3.1: enforce alg allowlist. Only EdDSA — matches the
    // OIDC OP we ship.
    if header.alg != "EdDSA" {
        return Err(AuthError::DisallowedAlg(header.alg));
    }

    let jwk = config
        .trust_jwks
        .keys
        .iter()
        .find(|k| header.kid.as_deref() == Some(k.kid.as_str()))
        .ok_or_else(|| AuthError::UnknownKid {
            kid: header.kid.clone(),
        })?;

    let JwkPublicKey::Ed25519(vk_bytes) = jwk
        .public_key()
        .map_err(|_| AuthError::UnsupportedKeyType)?
    else {
        return Err(AuthError::UnsupportedKeyType);
    };

    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| AuthError::UnsupportedKeyType)?;

    let sig_bytes = B64URL
        .decode(sig_b64)
        .map_err(|_| AuthError::BadSignature)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_array);

    let signed_input = format!("{header_b64}.{payload_b64}");
    vk.verify_strict(signed_input.as_bytes(), &signature)
        .map_err(|_| AuthError::BadSignature)?;

    let payload_bytes = B64URL
        .decode(payload_b64)
        .map_err(|_| AuthError::Malformed)?;
    let claims: JwsClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| AuthError::Malformed)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::ClockBeforeEpoch)?
        .as_secs();

    if claims.exp + config.clock_skew_secs < now {
        return Err(AuthError::Expired {
            exp: claims.exp,
            now,
        });
    }
    if let Some(nbf) = claims.nbf {
        if nbf > now + config.clock_skew_secs {
            return Err(AuthError::NotYetValid { nbf, now });
        }
    }

    let auds = claims.aud.into_vec();
    if !auds.iter().any(|a| a == &config.allowed_audience) {
        return Err(AuthError::AudienceMismatch);
    }

    if !claims.sub.starts_with(&config.allowed_subject_prefix) {
        return Err(AuthError::SubjectPrefixMismatch { sub: claims.sub });
    }

    Ok(AuthenticatedPrincipal {
        sub: claims.sub,
        aud: auds,
        authenticated: true,
    })
}

/// Outcome of bootstrap-time SPIFFE config resolution from optional
/// inputs (typically three CLI flags). Returned by
/// [`resolve_spiffe_auth`].
#[derive(Debug, Error)]
pub enum SpiffeConfigError {
    /// Operator set 1 or 2 of the 3 SPIFFE flags. Partial config is
    /// the worst posture (operator believes they have auth, attacker
    /// walks past), so the boot path MUST fail loud.
    #[error(
        "partial SPIFFE auth config: set ALL of \
         trust_jwks/allowed_audience/allowed_subject_prefix, or NONE. Got {set_count}/3."
    )]
    Partial { set_count: usize },

    /// Production build booted with SPIFFE auth UNCONFIGURED. The orchestration
    /// API (submit/get/cancel/stream job) must not run open — fail-closed
    /// (most-paranoid #6), mirroring the lineage-signer discipline in main.rs.
    #[error(
        "SPIFFE JWT-SVID auth is REQUIRED in production but is unconfigured — set \
         --spiffe-trust-jwks-path / --spiffe-allowed-audience / --spiffe-allowed-subject-prefix \
         (or build with `--features insecure-dev` to run WITHOUT auth, which is dangerous and \
         must never be used in production)"
    )]
    AuthRequiredInProduction,
}

/// Resolve SPIFFE auth config from optional inputs. `None` from all
/// three → auth disabled (the demo posture). All three `Some` →
/// config bundled into a [`SpiffeAuthConfig`]. Anything else → loud
/// error.
///
/// Decoupled from CLI parsing so it can be unit-tested without
/// shelling out to the binary.
pub fn resolve_spiffe_auth(
    trust_jwks: Option<Jwks>,
    allowed_audience: Option<String>,
    allowed_subject_prefix: Option<String>,
) -> Result<Option<SpiffeAuthConfig>, SpiffeConfigError> {
    let set_count = [
        trust_jwks.is_some(),
        allowed_audience.is_some(),
        allowed_subject_prefix.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    match (
        set_count,
        trust_jwks,
        allowed_audience,
        allowed_subject_prefix,
    ) {
        (0, _, _, _) => Ok(None),
        (3, Some(jwks), Some(aud), Some(prefix)) => {
            Ok(Some(SpiffeAuthConfig::new(jwks, aud, prefix)))
        }
        _ => Err(SpiffeConfigError::Partial { set_count }),
    }
}

/// Fail-closed gate (most-paranoid #6): a PRODUCTION build REQUIRES SPIFFE
/// JWT-SVID auth. Given the resolved config, returns it when present; when it is
/// ABSENT (`None` — no SPIFFE flags set), a production build returns
/// `Err(AuthRequiredInProduction)` so the server refuses to boot with the
/// orchestration API open. Only a build with `--features insecure-dev` may boot
/// without auth (`Ok(None)`). Mirrors the lineage-signer fail-closed discipline
/// in `main.rs` (production `anyhow::bail!` when no signing key is configured).
pub fn require_auth_or_insecure(
    resolved: Option<SpiffeAuthConfig>,
) -> Result<Option<SpiffeAuthConfig>, SpiffeConfigError> {
    match resolved {
        Some(c) => Ok(Some(c)),
        None => {
            #[cfg(not(feature = "insecure-dev"))]
            {
                Err(SpiffeConfigError::AuthRequiredInProduction)
            }
            #[cfg(feature = "insecure-dev")]
            {
                Ok(None)
            }
        }
    }
}

/// Axum extractor that gates a handler on a valid JWT-SVID OR admits
/// a synthetic principal when SPIFFE auth is disabled. Use this on
/// every protected endpoint.
pub struct RequireSpiffeAuth(pub AuthenticatedPrincipal);

impl FromRequestParts<AppState> for RequireSpiffeAuth {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let config = match &state.spiffe_auth {
            Some(c) => c,
            None => {
                return Ok(RequireSpiffeAuth(AuthenticatedPrincipal::unauthenticated()));
            }
        };

        let header_val = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "missing Authorization header".to_string(),
            ))?;

        let token = header_val.strip_prefix("Bearer ").ok_or((
            StatusCode::UNAUTHORIZED,
            "Authorization scheme must be Bearer".to_string(),
        ))?;

        let principal = verify_jwt_svid(token, config).map_err(|e| (e.status(), e.to_string()))?;
        Ok(RequireSpiffeAuth(principal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey, SECRET_KEY_LENGTH};
    use nucleus_oidc_core::Jwk;
    use serde_json::json;

    /// Fail-closed: a PRODUCTION build (no `insecure-dev`) must REFUSE to boot
    /// when SPIFFE auth is unconfigured. On main the `None` branch only warned
    /// and booted the orchestration API open — this is the RED→GREEN.
    #[cfg(not(feature = "insecure-dev"))]
    #[test]
    fn production_fails_closed_without_spiffe_auth() {
        assert!(
            matches!(
                require_auth_or_insecure(None),
                Err(SpiffeConfigError::AuthRequiredInProduction)
            ),
            "production must fail closed when SPIFFE auth is unconfigured"
        );
    }

    /// The escape hatch: an `insecure-dev` build may boot without auth.
    #[cfg(feature = "insecure-dev")]
    #[test]
    fn insecure_dev_permits_no_auth() {
        assert!(matches!(require_auth_or_insecure(None), Ok(None)));
    }

    /// No regression: a configured auth always passes through, in any build.
    #[test]
    fn configured_auth_always_passes() {
        let f = Fixture::new();
        assert!(require_auth_or_insecure(Some(config(f.jwks()))).is_ok());
    }

    /// Helpers for building a signed JWT-SVID against a known signing key.
    struct Fixture {
        signing_key: SigningKey,
        kid: String,
    }

    impl Fixture {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&[17u8; SECRET_KEY_LENGTH]);
            Self {
                signing_key,
                kid: "test-key-1".to_string(),
            }
        }

        fn jwks(&self) -> Jwks {
            let vk = self.signing_key.verifying_key();
            let x_b64 = B64URL.encode(vk.to_bytes());
            Jwks {
                keys: vec![Jwk {
                    kty: "OKP".to_string(),
                    kid: self.kid.clone(),
                    alg: Some("EdDSA".to_string()),
                    use_: Some("sig".to_string()),
                    crv: Some("Ed25519".to_string()),
                    x: Some(x_b64),
                    y: None,
                    n: None,
                    e: None,
                }],
            }
        }

        fn mint(&self, sub: &str, aud: &str, exp_offset_secs: i64) -> String {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let exp = (now + exp_offset_secs).max(0) as u64;
            let header_json = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, self.kid);
            let payload = json!({
                "sub": sub,
                "aud": aud,
                "exp": exp,
                "iat": now,
            });
            let header_b64 = B64URL.encode(header_json.as_bytes());
            let payload_b64 = B64URL.encode(payload.to_string().as_bytes());
            let signed_input = format!("{header_b64}.{payload_b64}");
            let sig = self.signing_key.sign(signed_input.as_bytes());
            let sig_b64 = B64URL.encode(sig.to_bytes());
            format!("{header_b64}.{payload_b64}.{sig_b64}")
        }
    }

    fn config(jwks: Jwks) -> SpiffeAuthConfig {
        SpiffeAuthConfig::new(
            jwks,
            "https://control.nucleus.local/api",
            "spiffe://prod.example.com/ns/agents/sa/",
        )
    }

    #[test]
    fn valid_jwt_svid_accepted() {
        let f = Fixture::new();
        let token = f.mint(
            "spiffe://prod.example.com/ns/agents/sa/coder",
            "https://control.nucleus.local/api",
            600,
        );
        let cfg = config(f.jwks());
        let principal = verify_jwt_svid(&token, &cfg).unwrap();
        assert_eq!(
            principal.sub,
            "spiffe://prod.example.com/ns/agents/sa/coder"
        );
        assert!(principal.authenticated);
    }

    /// M-3 strong-binding regression for the control-plane JWT-SVID trust
    /// root (site: `verify_jwt_svid`, the `vk.verify_strict(...)` call). The
    /// Ed25519 identity/neutral key (`[1, 0, ..., 0]`) with the identity-
    /// triple signature (R = identity encoding, s = 0) satisfies the
    /// COFACTORED verification equation for EVERY message, so non-strict
    /// `verify()` ACCEPTS it. The crafted JWT below is otherwise fully valid
    /// (matching subject prefix + audience, fresh exp) and the identity key
    /// is the sole trusted JWKS key, so under non-strict `verify()`
    /// authentication SUCCEEDS for a FORGED principal. `verify_strict()`
    /// rejects the small-order key → `BadSignature`. If the site reverts to
    /// `vk.verify(...)`, assertion (ii) sees `Ok(..)` and fails.
    #[test]
    fn small_order_key_is_rejected_by_verify_strict() {
        // (i) No regression: an honest JWT-SVID still authenticates.
        let f = Fixture::new();
        let token = f.mint(
            "spiffe://prod.example.com/ns/agents/sa/coder",
            "https://control.nucleus.local/api",
            600,
        );
        verify_jwt_svid(&token, &config(f.jwks()))
            .expect("honest JWT-SVID must still authenticate through verify_strict");

        // (ii) Strong binding: trust the small-order identity key and present
        //      a JWT "signed" with the identity triple.
        let mut id = [0u8; 32];
        id[0] = 1; // identity/neutral point encoding — a small-order key
        let kid = "id-key".to_string();
        let jwks = Jwks {
            keys: vec![Jwk {
                kty: "OKP".to_string(),
                kid: kid.clone(),
                alg: Some("EdDSA".to_string()),
                use_: Some("sig".to_string()),
                crv: Some("Ed25519".to_string()),
                x: Some(B64URL.encode(id)),
                y: None,
                n: None,
                e: None,
            }],
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#);
        let payload = json!({
            "sub": "spiffe://prod.example.com/ns/agents/sa/coder",
            "aud": "https://control.nucleus.local/api",
            "exp": (now + 600) as u64,
            "iat": now,
        });
        let header_b64 = B64URL.encode(header_json.as_bytes());
        let payload_b64 = B64URL.encode(payload.to_string().as_bytes());
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&id); // R = identity, s = 0
        let sig_b64 = B64URL.encode(sig);
        let forged = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let err = verify_jwt_svid(&forged, &config(jwks)).unwrap_err();
        assert!(
            matches!(err, AuthError::BadSignature),
            "identity-triple JWT-SVID must be REFUSED by verify_strict; a \
             revert to non-strict verify() would authenticate a forged \
             principal (got {err:?})"
        );
    }

    #[test]
    fn malformed_token_rejected() {
        let f = Fixture::new();
        let cfg = config(f.jwks());
        let err = verify_jwt_svid("not.a.valid.jwt.too.many.parts", &cfg).unwrap_err();
        assert!(matches!(err, AuthError::Malformed));
    }

    #[test]
    fn empty_token_rejected() {
        let f = Fixture::new();
        let cfg = config(f.jwks());
        assert!(verify_jwt_svid("", &cfg).is_err());
    }

    #[test]
    fn wrong_audience_rejected_403() {
        let f = Fixture::new();
        let token = f.mint(
            "spiffe://prod.example.com/ns/agents/sa/coder",
            "https://OTHER.example/api",
            600,
        );
        let cfg = config(f.jwks());
        let err = verify_jwt_svid(&token, &cfg).unwrap_err();
        assert!(matches!(err, AuthError::AudienceMismatch));
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn wrong_subject_prefix_rejected_403() {
        let f = Fixture::new();
        let token = f.mint(
            "spiffe://prod.example.com/ns/OTHER/sa/coder",
            "https://control.nucleus.local/api",
            600,
        );
        let cfg = config(f.jwks());
        let err = verify_jwt_svid(&token, &cfg).unwrap_err();
        assert!(matches!(err, AuthError::SubjectPrefixMismatch { .. }));
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn expired_token_rejected_401() {
        let f = Fixture::new();
        // -3600 - skew = clearly expired.
        let token = f.mint(
            "spiffe://prod.example.com/ns/agents/sa/coder",
            "https://control.nucleus.local/api",
            -3600,
        );
        let cfg = config(f.jwks());
        let err = verify_jwt_svid(&token, &cfg).unwrap_err();
        assert!(matches!(err, AuthError::Expired { .. }));
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unknown_kid_rejected_401() {
        let f = Fixture::new();
        let mut jwks = f.jwks();
        // Replace the kid in the JWKS — the token's header.kid no longer matches.
        jwks.keys[0].kid = "different-kid".to_string();
        let token = f.mint(
            "spiffe://prod.example.com/ns/agents/sa/coder",
            "https://control.nucleus.local/api",
            600,
        );
        let cfg = config(jwks);
        let err = verify_jwt_svid(&token, &cfg).unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid { .. }));
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn forged_signature_rejected_401() {
        let f = Fixture::new();
        let token = f.mint(
            "spiffe://prod.example.com/ns/agents/sa/coder",
            "https://control.nucleus.local/api",
            600,
        );
        // Tamper with one byte of the signature segment.
        let parts: Vec<_> = token.split('.').collect();
        let mut bad_sig = B64URL.decode(parts[2]).unwrap();
        bad_sig[0] ^= 0xff;
        let bad_sig_b64 = B64URL.encode(&bad_sig);
        let bad_token = format!("{}.{}.{}", parts[0], parts[1], bad_sig_b64);

        let cfg = config(f.jwks());
        let err = verify_jwt_svid(&bad_token, &cfg).unwrap_err();
        assert!(matches!(err, AuthError::BadSignature));
    }

    #[test]
    fn alg_none_rejected_loud() {
        let f = Fixture::new();
        // Forge a token with alg=none. The verifier MUST reject it
        // because EdDSA is the only allowed alg per RFC 8725 §3.1.
        let header_json = format!(r#"{{"alg":"none","kid":"{}"}}"#, f.kid);
        let payload = json!({
            "sub": "spiffe://prod.example.com/ns/agents/sa/coder",
            "aud": "https://control.nucleus.local/api",
            "exp": 9_999_999_999u64,
        });
        let header_b64 = B64URL.encode(header_json.as_bytes());
        let payload_b64 = B64URL.encode(payload.to_string().as_bytes());
        let token = format!("{header_b64}.{payload_b64}.");
        let cfg = config(f.jwks());
        let err = verify_jwt_svid(&token, &cfg).unwrap_err();
        assert!(matches!(err, AuthError::DisallowedAlg(_)));
    }

    // ── resolve_spiffe_auth (boot-time partial-config gate) ──────

    #[test]
    fn resolve_returns_none_when_all_unset() {
        let r = resolve_spiffe_auth(None, None, None).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_returns_some_when_all_set() {
        let f = Fixture::new();
        let r = resolve_spiffe_auth(
            Some(f.jwks()),
            Some("https://aud".to_string()),
            Some("spiffe://td/ns/x/sa/".to_string()),
        )
        .unwrap();
        let cfg = r.expect("Some(_)");
        assert_eq!(cfg.allowed_audience, "https://aud");
        assert_eq!(cfg.allowed_subject_prefix, "spiffe://td/ns/x/sa/");
    }

    #[test]
    fn resolve_errors_on_one_of_three() {
        let f = Fixture::new();
        let err = resolve_spiffe_auth(Some(f.jwks()), None, None).unwrap_err();
        assert!(matches!(err, SpiffeConfigError::Partial { set_count: 1 }));
    }

    #[test]
    fn resolve_errors_on_two_of_three() {
        let err = resolve_spiffe_auth(None, Some("aud".to_string()), Some("prefix".to_string()))
            .unwrap_err();
        assert!(matches!(err, SpiffeConfigError::Partial { set_count: 2 }));
    }

    #[test]
    fn audience_array_accepted_when_one_entry_matches() {
        // RFC 7519 §4.1.3 allows `aud` to be an array. The verifier
        // must accept the token if ANY array entry matches.
        let f = Fixture::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, f.kid);
        let payload = json!({
            "sub": "spiffe://prod.example.com/ns/agents/sa/coder",
            "aud": ["https://other.example/api", "https://control.nucleus.local/api"],
            "exp": now + 600,
        });
        let header_b64 = B64URL.encode(header_json.as_bytes());
        let payload_b64 = B64URL.encode(payload.to_string().as_bytes());
        let signed_input = format!("{header_b64}.{payload_b64}");
        let sig = f.signing_key.sign(signed_input.as_bytes());
        let sig_b64 = B64URL.encode(sig.to_bytes());
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let cfg = config(f.jwks());
        let p = verify_jwt_svid(&token, &cfg).unwrap();
        assert_eq!(p.aud.len(), 2);
    }
}
