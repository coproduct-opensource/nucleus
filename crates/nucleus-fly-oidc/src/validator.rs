//! The Fly OIDC token validator.
//!
//! [`FlyOidcValidator::validate`] performs, in order: algorithm allowlist
//! check, issuer trust check, key resolution, signature + registered-claim
//! verification, replay protection, app/org allowlist checks, and SPIFFE ID
//! derivation. Every step must pass for a token to be accepted.

use std::collections::HashSet;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use nucleus_lineage::CallSpiffeId;
use serde::Deserialize;

use crate::claims::{FlyClaims, derive_spiffe_id};
use crate::error::OidcError;
use crate::jwks::{JtiCache, KeyResolver};

/// The canonical Fly OIDC issuer prefix.
pub const FLY_ISSUER_PREFIX: &str = "https://oidc.fly.io/";

/// Configuration for a [`FlyOidcValidator`].
#[derive(Debug, Clone)]
pub struct FlyOidcConfig {
    /// Required prefix of the `iss` claim.
    pub issuer_prefix: String,
    /// Required `aud` claim — the audience the runner requested.
    pub audience: String,
    /// SPIFFE trust domain stamped onto derived identities.
    pub trust_domain: String,
    /// Allowed organizations; empty means any org under `issuer_prefix`.
    pub allowed_orgs: HashSet<String>,
    /// Allowed applications; empty means any app.
    pub allowed_apps: HashSet<String>,
    /// Accepted signing algorithms. Defaults to RS256; never HMAC — an HMAC
    /// entry would open an algorithm-confusion attack against the JWKS keys.
    pub accepted_algorithms: Vec<Algorithm>,
    /// Clock-skew tolerance, seconds.
    pub leeway_secs: u64,
}

impl FlyOidcConfig {
    /// A config for `audience` with Nucleus defaults: Fly's `oidc.fly.io`
    /// issuer, the `nucleus.io` trust domain, RS256 only, 60s leeway.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            issuer_prefix: FLY_ISSUER_PREFIX.to_string(),
            audience: audience.into(),
            trust_domain: "nucleus.io".to_string(),
            allowed_orgs: HashSet::new(),
            allowed_apps: HashSet::new(),
            accepted_algorithms: vec![Algorithm::RS256],
            leeway_secs: 60,
        }
    }

    /// Override the SPIFFE trust domain.
    pub fn with_trust_domain(mut self, trust_domain: impl Into<String>) -> Self {
        self.trust_domain = trust_domain.into();
        self
    }

    /// Restrict accepted tokens to a specific organization.
    pub fn allow_org(mut self, org: impl Into<String>) -> Self {
        self.allowed_orgs.insert(org.into());
        self
    }

    /// Restrict accepted tokens to a specific application.
    pub fn allow_app(mut self, app: impl Into<String>) -> Self {
        self.allowed_apps.insert(app.into());
        self
    }

    /// Override the accepted signing algorithms.
    pub fn with_accepted_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.accepted_algorithms = algorithms;
        self
    }
}

/// A successfully validated Fly OIDC token.
#[derive(Debug, Clone)]
pub struct ValidatedIdentity {
    /// The verified token claims.
    pub claims: FlyClaims,
    /// The SPIFFE identity derived for this Fly machine.
    pub spiffe_id: CallSpiffeId,
}

/// Validates Fly OIDC tokens against a [`KeyResolver`].
pub struct FlyOidcValidator<R: KeyResolver> {
    config: FlyOidcConfig,
    resolver: R,
    jti_cache: JtiCache,
}

impl<R: KeyResolver> FlyOidcValidator<R> {
    /// Build a validator from a config and a key resolver.
    pub fn new(config: FlyOidcConfig, resolver: R) -> Self {
        Self {
            config,
            resolver,
            jti_cache: JtiCache::new(),
        }
    }

    /// The validator's configuration.
    pub fn config(&self) -> &FlyOidcConfig {
        &self.config
    }

    /// Validate a Fly OIDC token, returning the verified identity.
    pub async fn validate(&self, token: &str) -> Result<ValidatedIdentity, OidcError> {
        let header = decode_header(token).map_err(|e| OidcError::Jwt(e.to_string()))?;
        if !self.config.accepted_algorithms.contains(&header.alg) {
            return Err(OidcError::UnacceptedAlgorithm(format!("{:?}", header.alg)));
        }
        let kid = header.kid.ok_or(OidcError::MissingKeyId)?;

        // Peek the (unverified) issuer to decide trust and pick the key set.
        // This is safe: the signature is still verified below against the
        // key fetched *from that exact issuer*, so a forged `iss` cannot
        // both name a trusted issuer and carry a verifiable signature.
        let issuer = peek_issuer(token)?;
        let org = issuer
            .strip_prefix(&self.config.issuer_prefix)
            .map(str::to_string)
            .filter(|o| !o.is_empty() && !o.contains('/'))
            .ok_or_else(|| OidcError::UntrustedIssuer(issuer.clone()))?;
        if !self.config.allowed_orgs.is_empty() && !self.config.allowed_orgs.contains(&org) {
            return Err(OidcError::OrgNotAllowed(org));
        }

        let key = self.resolver.resolve(&issuer, &kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = self.config.leeway_secs;

        let data = decode::<FlyClaims>(token, &key, &validation)
            .map_err(|e| OidcError::Jwt(e.to_string()))?;
        let claims = data.claims;

        // Replay protection only after the signature + claims are trusted,
        // so an invalid token can never poison the cache.
        self.jti_cache.check_and_mark(&claims.jti, claims.exp)?;

        if !self.config.allowed_apps.is_empty()
            && !self.config.allowed_apps.contains(&claims.app_name)
        {
            return Err(OidcError::AppNotAllowed(claims.app_name.clone()));
        }
        // Defense in depth: the org in the verified claims must agree with
        // the org named in the issuer URL.
        if claims.org_name != org {
            return Err(OidcError::OrgMismatch {
                issuer_org: org,
                claim_org: claims.org_name.clone(),
            });
        }

        let spiffe_id = derive_spiffe_id(&claims, &self.config.trust_domain)?;
        Ok(ValidatedIdentity { claims, spiffe_id })
    }
}

/// Read the `iss` claim from a token without verifying its signature.
fn peek_issuer(token: &str) -> Result<String, OidcError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or(OidcError::InvalidTokenFormat)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| OidcError::InvalidTokenFormat)?;

    #[derive(Deserialize)]
    struct IssOnly {
        iss: String,
    }
    let parsed: IssOnly =
        serde_json::from_slice(&bytes).map_err(|_| OidcError::InvalidTokenFormat)?;
    Ok(parsed.iss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::StaticKeyResolver;
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_PRIV: &str = include_str!("../testdata/jwt_test_priv.pem");
    const TEST_PUB: &str = include_str!("../testdata/jwt_test_pub.pem");
    const TEST_KID: &str = "test-kid";

    fn enc_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(TEST_PRIV.as_bytes()).expect("test private key parses")
    }

    fn dec_key() -> DecodingKey {
        DecodingKey::from_rsa_pem(TEST_PUB.as_bytes()).expect("test public key parses")
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Build a Fly-shaped claims object.
    #[allow(clippy::too_many_arguments)]
    fn fly_claims(
        iss: &str,
        app: &str,
        machine: &str,
        org: &str,
        aud: &str,
        jti: &str,
        exp_offset: i64,
    ) -> serde_json::Value {
        let n = now();
        serde_json::json!({
            "iss": iss,
            "sub": format!("{org}:{app}:{machine}-name"),
            "aud": aud,
            "exp": n + exp_offset,
            "iat": n - 30,
            "nbf": n - 30,
            "jti": jti,
            "app_name": app,
            "machine_id": machine,
            "org_name": org,
            "machine_name": format!("{machine}-name"),
            "region": "ord",
            "app_id": 90210,
            "image": "registry.fly.io/app:deployment-01",
            "image_digest": "sha256:abcdef"
        })
    }

    fn mint(claims: serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, &enc_key()).expect("token encodes")
    }

    /// A validator with the test key registered and default config.
    fn validator() -> FlyOidcValidator<StaticKeyResolver> {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, dec_key());
        FlyOidcValidator::new(FlyOidcConfig::new("nucleus-control"), resolver)
    }

    #[tokio::test]
    async fn valid_token_yields_identity() {
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "weather-bot",
                "m148ed",
                "test-org",
                "nucleus-control",
                "jti-valid",
                600,
            ),
            TEST_KID,
        );
        let identity = validator().validate(&token).await.unwrap();
        assert_eq!(
            identity.spiffe_id.as_str(),
            "spiffe://nucleus.io/ns/fly/sa/weather-bot/m148ed"
        );
        assert_eq!(identity.claims.app_name, "weather-bot");
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-exp",
                -3600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::Jwt(_))
        ));
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "test-org",
                "some-other-service",
                "jti-aud",
                600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::Jwt(_))
        ));
    }

    #[tokio::test]
    async fn untrusted_issuer_is_rejected() {
        let token = mint(
            fly_claims(
                "https://evil.example.com/test-org",
                "bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-iss",
                600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::UntrustedIssuer(_))
        ));
    }

    #[tokio::test]
    async fn org_not_in_allowlist_is_rejected() {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, dec_key());
        let validator = FlyOidcValidator::new(
            FlyOidcConfig::new("nucleus-control").allow_org("only-this-org"),
            resolver,
        );
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-org",
                600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator.validate(&token).await,
            Err(OidcError::OrgNotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn app_not_in_allowlist_is_rejected() {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, dec_key());
        let validator = FlyOidcValidator::new(
            FlyOidcConfig::new("nucleus-control").allow_app("approved-app"),
            resolver,
        );
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "weather-bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-app",
                600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator.validate(&token).await,
            Err(OidcError::AppNotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn replayed_token_is_rejected() {
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-replay",
                600,
            ),
            TEST_KID,
        );
        let validator = validator();
        validator.validate(&token).await.unwrap();
        assert!(matches!(
            validator.validate(&token).await,
            Err(OidcError::TokenReplay(_))
        ));
    }

    #[tokio::test]
    async fn unaccepted_algorithm_is_rejected() {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, dec_key());
        let validator = FlyOidcValidator::new(
            FlyOidcConfig::new("nucleus-control").with_accepted_algorithms(vec![Algorithm::ES256]),
            resolver,
        );
        // The token is RS256; the validator only accepts ES256.
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-alg",
                600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator.validate(&token).await,
            Err(OidcError::UnacceptedAlgorithm(_))
        ));
    }

    #[tokio::test]
    async fn unknown_kid_is_rejected() {
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-kid",
                600,
            ),
            "some-other-kid",
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::KeyNotFound(_))
        ));
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected() {
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "test-org",
                "nucleus-control",
                "jti-tamper",
                600,
            ),
            TEST_KID,
        );
        let parts: Vec<&str> = token.split('.').collect();
        let mut sig = parts[2].to_string();
        let last = sig.pop().unwrap();
        sig.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = format!("{}.{}.{}", parts[0], parts[1], sig);
        assert!(matches!(
            validator().validate(&tampered).await,
            Err(OidcError::Jwt(_))
        ));
    }

    #[tokio::test]
    async fn org_mismatch_between_issuer_and_claim_is_rejected() {
        // Issuer URL names `test-org`; the `org_name` claim says otherwise.
        let token = mint(
            fly_claims(
                "https://oidc.fly.io/test-org",
                "bot",
                "m1",
                "different-org",
                "nucleus-control",
                "jti-mismatch",
                600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::OrgMismatch { .. })
        ));
    }
}
