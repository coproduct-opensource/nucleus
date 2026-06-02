//! GitHub Actions OIDC validator.
//!
//! Mirrors the per-provider validator shape `nucleus-fly-oidc` uses, with
//! GitHub-specific claims + allowlists. Builds on the shared `KeyResolver`
//! / `JtiCache` primitives from `nucleus-oidc-core`.

use std::collections::HashSet;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey};
use nucleus_lineage::CallSpiffeId;
use nucleus_oidc_core::{JtiCache, JwkPublicKey, KeyResolver, OidcError};
use serde::Deserialize;

use crate::claims::{derive_spiffe_id, GitHubClaims};

/// The canonical GitHub Actions OIDC issuer.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Configuration for a [`GitHubOidcValidator`].
#[derive(Debug, Clone)]
pub struct GitHubOidcConfig {
    /// Required `iss` claim. Defaults to [`GITHUB_ISSUER`]; override only
    /// for GitHub Enterprise.
    pub issuer: String,
    /// Required `aud` claim. Workflows opt into a specific audience via
    /// `core.getIDToken("nucleus.io")` (or the curl `audience=…` query
    /// param). Nucleus expects them to ask for our audience.
    pub audience: String,
    /// SPIFFE trust domain stamped onto derived identities.
    pub trust_domain: String,
    /// Allowed `org/repo` pairs. Empty ≡ any repo (in an allowed org).
    pub allowed_repos: HashSet<String>,
    /// Allowed `repository_owner` values. Empty ≡ any owner. If both
    /// `allowed_orgs` and `allowed_repos` are empty, the validator accepts
    /// any repository — typically only OK in dev.
    pub allowed_orgs: HashSet<String>,
    /// Accepted signing algorithms. GitHub signs RS256 today.
    pub accepted_algorithms: Vec<Algorithm>,
    /// Clock-skew tolerance, seconds.
    pub leeway_secs: u64,
}

impl GitHubOidcConfig {
    /// A config for `audience` with Nucleus defaults: token.actions issuer,
    /// `nucleus.io` trust domain, RS256 only, 60s leeway.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            issuer: GITHUB_ISSUER.to_string(),
            audience: audience.into(),
            trust_domain: "nucleus.io".to_string(),
            allowed_repos: HashSet::new(),
            allowed_orgs: HashSet::new(),
            accepted_algorithms: vec![Algorithm::RS256],
            leeway_secs: 60,
        }
    }

    /// Override the SPIFFE trust domain.
    pub fn with_trust_domain(mut self, trust_domain: impl Into<String>) -> Self {
        self.trust_domain = trust_domain.into();
        self
    }

    /// Restrict accepted tokens to a specific `org/repo`.
    pub fn allow_repo(mut self, repo: impl Into<String>) -> Self {
        self.allowed_repos.insert(repo.into());
        self
    }

    /// Restrict accepted tokens to any repo in `org`.
    pub fn allow_org(mut self, org: impl Into<String>) -> Self {
        self.allowed_orgs.insert(org.into());
        self
    }

    /// Override the accepted signing algorithms.
    pub fn with_accepted_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.accepted_algorithms = algorithms;
        self
    }

    /// Override the issuer (GitHub Enterprise deployments).
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }
}

/// A successfully validated GitHub OIDC token.
#[derive(Debug, Clone)]
pub struct ValidatedGitHubIdentity {
    /// The verified token claims.
    pub claims: GitHubClaims,
    /// The SPIFFE identity derived for this workflow run.
    pub spiffe_id: CallSpiffeId,
}

/// Validates GitHub Actions OIDC tokens against a [`KeyResolver`].
pub struct GitHubOidcValidator<R: KeyResolver> {
    config: GitHubOidcConfig,
    resolver: R,
    jti_cache: JtiCache,
}

impl<R: KeyResolver> GitHubOidcValidator<R> {
    /// Build a validator from a config and a key resolver.
    pub fn new(config: GitHubOidcConfig, resolver: R) -> Self {
        Self {
            config,
            resolver,
            jti_cache: JtiCache::new(),
        }
    }

    /// The validator's configuration.
    pub fn config(&self) -> &GitHubOidcConfig {
        &self.config
    }

    /// Validate a GitHub OIDC token, returning the verified identity.
    pub async fn validate(&self, token: &str) -> Result<ValidatedGitHubIdentity, OidcError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| OidcError::JwtValidation(e.to_string()))?;
        if !self.config.accepted_algorithms.contains(&header.alg) {
            return Err(OidcError::UnacceptedAlgorithm(format!("{:?}", header.alg)));
        }
        let kid = header.kid.ok_or(OidcError::MissingKeyId)?;

        // Peek the (unverified) issuer to confirm it's our trusted issuer
        // *before* hitting the network. Safe because the signature is still
        // verified below against the key fetched from that issuer.
        let issuer = peek_issuer(token)?;
        if issuer != self.config.issuer {
            return Err(OidcError::UntrustedIssuer(issuer));
        }

        // nucleus-oidc-core's KeyResolver hands back a crypto-library-neutral
        // `JwkPublicKey`; convert it to the jsonwebtoken `DecodingKey` this
        // validator verifies with. GitHub signs RS256, so only the RSA
        // variant is meaningful here.
        let public_key = self.resolver.resolve(&issuer, &kid).await?;
        let decoding_key = to_decoding_key(&public_key)?;

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_issuer(&[issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_exp = true;
        validation.leeway = self.config.leeway_secs;

        let data = jsonwebtoken::decode::<GitHubClaims>(token, &decoding_key, &validation)
            .map_err(|e| OidcError::JwtValidation(e.to_string()))?;
        let claims = data.claims;

        // Replay protection AFTER signature + claim verification, so an
        // invalid token can never poison the cache.
        self.jti_cache.check_and_mark(&claims.jti, claims.exp)?;

        // Allowlist checks. `allowed_repos` is the narrowest knob; an
        // explicit repo overrides the org-level allowlist.
        let allowed_by_repo = self.config.allowed_repos.is_empty()
            || self.config.allowed_repos.contains(&claims.repository);
        let allowed_by_org = self.config.allowed_orgs.is_empty()
            || self.config.allowed_orgs.contains(&claims.repository_owner);
        if !(allowed_by_repo && allowed_by_org) {
            return Err(OidcError::WorkloadNotAllowed(claims.repository.clone()));
        }

        let spiffe_id = derive_spiffe_id(&claims, &self.config.trust_domain)?;
        Ok(ValidatedGitHubIdentity { claims, spiffe_id })
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

/// Convert a neutral [`JwkPublicKey`] into a jsonwebtoken [`DecodingKey`].
///
/// GitHub Actions OIDC tokens are RS256, so only the RSA variant is
/// expected. An Ed25519 key in GitHub's JWKS would be unusable for an
/// RS256 token anyway; reject it explicitly rather than silently picking a
/// mismatched algorithm (defense in depth against algorithm confusion).
fn to_decoding_key(key: &JwkPublicKey) -> Result<DecodingKey, OidcError> {
    match key {
        JwkPublicKey::Rsa { n, e } => DecodingKey::from_rsa_components(n, e)
            .map_err(|err| OidcError::InvalidJwks(err.to_string())),
        JwkPublicKey::Ed25519(_) => Err(OidcError::InvalidJwks(
            "Ed25519 keys are not usable for RS256 GitHub OIDC tokens".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use nucleus_oidc_core::StaticKeyResolver;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Reuse the same test RSA private key as nucleus-fly-oidc so we don't
    // carry another PEM. The matching public key's RSA components (`n`/`e`)
    // are the same ones served from this crate's `synthetic_jwks.json`.
    const TEST_PRIV: &str = include_str!("../../nucleus-fly-oidc/testdata/jwt_test_priv.pem");
    const TEST_KID: &str = "test-kid";
    // base64url RSA modulus + exponent of the shared workspace test key (see
    // testdata/synthetic_jwks.json). nucleus-oidc-core's StaticKeyResolver
    // takes a neutral `JwkPublicKey`, not a jsonwebtoken `DecodingKey`.
    const TEST_RSA_N: &str = "t3O6H8Xpz9aU3OppK73EBK0cNtuM4sZaf4LelxRCvbP9e1g6fyBndxS7lxx-Dkv4EpBwj7WohO2yMLVNTevAM9NnfPEpWwJm6ztWuNrdhnuHMqnY_p0jy0Mp-vBzyaR-fswwIgt_MGd_IiccYCNyIo286AH16uPEy8DMaINg3E3onLm9618McuhdCNAMHH50DP2-1CnlduareyK_sLxHmKvLyYrbZIxOGWo7O1A864i2ZbJvivMQ_bcGR6fdDdHR856WIrk-8D4y8W3k59gXv74jOxT1YD6jO71ztfiAsgtqLo0ZfJk0kONLHMc26Knl__8RcEMFtwu037BsuQnb7Q";
    const TEST_RSA_E: &str = "AQAB";

    fn enc_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(TEST_PRIV.as_bytes()).expect("test private key parses")
    }
    fn pub_key() -> JwkPublicKey {
        JwkPublicKey::Rsa {
            n: TEST_RSA_N.to_string(),
            e: TEST_RSA_E.to_string(),
        }
    }
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn gh_claims(
        repo: &str,
        owner: &str,
        git_ref: &str,
        aud: &str,
        jti: &str,
        exp_offset: i64,
    ) -> serde_json::Value {
        let n = now();
        serde_json::json!({
            "iss": GITHUB_ISSUER,
            "sub": format!("repo:{repo}:ref:{git_ref}"),
            "aud": aud,
            "exp": n + exp_offset,
            "iat": n - 30,
            "jti": jti,
            "repository": repo,
            "repository_owner": owner,
            "ref": git_ref,
            "actor": "octocat",
            "event_name": "push",
        })
    }

    fn mint(claims: serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims, &enc_key()).expect("token encodes")
    }

    fn validator() -> GitHubOidcValidator<StaticKeyResolver> {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, pub_key());
        GitHubOidcValidator::new(GitHubOidcConfig::new("nucleus.io"), resolver)
    }

    #[tokio::test]
    async fn valid_token_yields_identity() {
        let token = mint(
            gh_claims(
                "coproduct-opensource/nucleus-agent-starter",
                "coproduct-opensource",
                "refs/heads/main",
                "nucleus.io",
                "j-valid",
                600,
            ),
            TEST_KID,
        );
        let identity = validator().validate(&token).await.unwrap();
        assert!(identity
            .spiffe_id
            .as_str()
            .contains("/ns/github/sa/coproduct-opensource/nucleus-agent-starter/"));
        assert_eq!(identity.claims.actor, "octocat");
    }

    #[tokio::test]
    async fn untrusted_issuer_is_rejected() {
        let mut claims = gh_claims("o/r", "o", "refs/heads/main", "nucleus.io", "j-iss", 600);
        claims["iss"] = serde_json::Value::String("https://evil.example.com".to_string());
        let token = mint(claims, TEST_KID);
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::UntrustedIssuer(_))
        ));
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let token = mint(
            gh_claims("o/r", "o", "refs/heads/main", "wrong-aud", "j-aud", 600),
            TEST_KID,
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::JwtValidation(_))
        ));
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let token = mint(
            gh_claims("o/r", "o", "refs/heads/main", "nucleus.io", "j-exp", -3600),
            TEST_KID,
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::JwtValidation(_))
        ));
    }

    #[tokio::test]
    async fn repo_not_in_allowlist_is_rejected() {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, pub_key());
        let validator = GitHubOidcValidator::new(
            GitHubOidcConfig::new("nucleus.io").allow_repo("only-this/repo"),
            resolver,
        );
        let token = mint(
            gh_claims(
                "other/repo",
                "other",
                "refs/heads/main",
                "nucleus.io",
                "j-r",
                600,
            ),
            TEST_KID,
        );
        assert!(matches!(
            validator.validate(&token).await,
            Err(OidcError::WorkloadNotAllowed(_))
        ));
    }

    #[tokio::test]
    async fn org_allowlist_admits_any_repo_in_org() {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, pub_key());
        let validator = GitHubOidcValidator::new(
            GitHubOidcConfig::new("nucleus.io").allow_org("trusted-org"),
            resolver,
        );
        let token = mint(
            gh_claims(
                "trusted-org/anything",
                "trusted-org",
                "refs/heads/main",
                "nucleus.io",
                "j-o",
                600,
            ),
            TEST_KID,
        );
        assert!(validator.validate(&token).await.is_ok());
    }

    #[tokio::test]
    async fn replayed_token_is_rejected() {
        let token = mint(
            gh_claims("o/r", "o", "refs/heads/main", "nucleus.io", "j-replay", 600),
            TEST_KID,
        );
        let v = validator();
        v.validate(&token).await.unwrap();
        assert!(matches!(
            v.validate(&token).await,
            Err(OidcError::TokenReplay(_))
        ));
    }

    #[tokio::test]
    async fn unknown_kid_is_rejected() {
        let token = mint(
            gh_claims("o/r", "o", "refs/heads/main", "nucleus.io", "j-kid", 600),
            "some-other-kid",
        );
        assert!(matches!(
            validator().validate(&token).await,
            Err(OidcError::KeyNotFound(_))
        ));
    }

    #[tokio::test]
    async fn unaccepted_algorithm_is_rejected() {
        let resolver = StaticKeyResolver::new().with_key(TEST_KID, pub_key());
        let validator = GitHubOidcValidator::new(
            GitHubOidcConfig::new("nucleus.io").with_accepted_algorithms(vec![Algorithm::ES256]),
            resolver,
        );
        let token = mint(
            gh_claims("o/r", "o", "refs/heads/main", "nucleus.io", "j-alg", 600),
            TEST_KID,
        );
        assert!(matches!(
            validator.validate(&token).await,
            Err(OidcError::UnacceptedAlgorithm(_))
        ));
    }
}
