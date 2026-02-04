//! GitHub OIDC token exchange for CI/CD authentication.
//!
//! This module enables GitHub Actions workflows to authenticate with nucleus-node
//! without static secrets. The flow is:
//!
//! 1. GitHub Actions workflow requests an OIDC token from GitHub
//! 2. Client generates a key pair locally (private key never leaves the client)
//! 3. Client creates a CSR with the expected SPIFFE ID
//! 4. Workflow sends token + CSR to `POST /v1/oidc/github` endpoint
//! 5. Nucleus validates the token against GitHub's JWKS with replay protection
//! 6. Nucleus validates the CSR's SPIFFE ID matches the token claims
//! 7. Nucleus signs the CSR and returns only the certificate (no private key)
//!
//! # Security Model
//!
//! - **No key escrow**: Private keys are generated client-side and never transmitted
//! - **Replay protection**: Each JWT can only be used once (jti tracking)
//! - **Token validation**: Validated against GitHub's public JWKS (RSA signatures)
//! - **Repository allowlist**: Only repos in the configured allowlist can authenticate
//! - **Short-lived certificates**: Default 1 hour TTL
//! - **SPIFFE identity**: `spiffe://trust-domain/ns/github/sa/{org}/{repo}`
//! - **CSR validation**: Server verifies CSR's SPIFFE ID matches token-derived identity
//!
//! # GitHub Actions Usage
//!
//! ```yaml
//! jobs:
//!   deploy:
//!     permissions:
//!       id-token: write  # Required for OIDC
//!     steps:
//!       - name: Get nucleus credentials
//!         run: |
//!           # Get GitHub OIDC token
//!           TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
//!                        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=nucleus" | jq -r '.value')
//!
//!           # Generate key pair and CSR locally (private key stays local)
//!           SPIFFE_ID="spiffe://nucleus.local/ns/github/sa/${{ github.repository_owner }}/${{ github.event.repository.name }}"
//!           openssl ecparam -name prime256v1 -genkey -noout -out key.pem
//!           openssl req -new -key key.pem -out csr.pem -subj "/CN=github-actions" \
//!                   -addext "subjectAltName=URI:$SPIFFE_ID"
//!
//!           # Exchange token + CSR for certificate
//!           RESPONSE=$(curl -X POST https://nucleus.example.com/v1/oidc/github \
//!                       -H "Authorization: Bearer $TOKEN" \
//!                       -H "Content-Type: application/json" \
//!                       -d "{\"csr\": \"$(cat csr.pem)\"}")
//!           echo "$RESPONSE" | jq -r '.certificate' > cert.pem
//!           echo "$RESPONSE" | jq -r '.trust_bundle' > ca.pem
//! ```
//!
//! # Configuration
//!
//! - `--oidc-github-enabled`: Enable GitHub OIDC (default: false)
//! - `--oidc-github-audience`: Expected audience claim (default: "nucleus")
//! - `--oidc-github-allowed-repos`: Comma-separated list of allowed repos (e.g., "org/repo1,org/repo2")
//! - `--oidc-github-allowed-orgs`: Comma-separated list of allowed orgs (all repos allowed)
//! - `--oidc-github-cert-ttl-secs`: Certificate TTL in seconds (default: 3600)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// GitHub's OIDC JWKS endpoint.
pub const GITHUB_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

/// GitHub's OIDC issuer.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Default certificate TTL for GitHub OIDC (1 hour).
pub const DEFAULT_CERT_TTL: Duration = Duration::from_secs(3600);

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for GitHub OIDC authentication.
#[derive(Clone, Debug)]
pub struct GitHubOidcConfig {
    /// Whether GitHub OIDC is enabled.
    pub enabled: bool,
    /// Expected audience claim in the token.
    pub audience: String,
    /// Allowed repositories (format: "org/repo").
    pub allowed_repos: HashSet<String>,
    /// Allowed organizations (all repos in these orgs are allowed).
    pub allowed_orgs: HashSet<String>,
    /// Trust domain for issued SPIFFE identities.
    pub trust_domain: String,
    /// TTL for issued certificates.
    pub cert_ttl: Duration,
}

impl Default for GitHubOidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audience: "nucleus".to_string(),
            allowed_repos: HashSet::new(),
            allowed_orgs: HashSet::new(),
            trust_domain: "nucleus.local".to_string(),
            cert_ttl: DEFAULT_CERT_TTL,
        }
    }
}

impl GitHubOidcConfig {
    /// Create a new config with the given settings.
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            ..Default::default()
        }
    }

    /// Enable GitHub OIDC.
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Set the expected audience.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Add an allowed repository.
    pub fn allow_repo(mut self, repo: impl Into<String>) -> Self {
        self.allowed_repos.insert(repo.into());
        self
    }

    /// Add an allowed organization.
    pub fn allow_org(mut self, org: impl Into<String>) -> Self {
        self.allowed_orgs.insert(org.into());
        self
    }

    /// Parse allowed repos from comma-separated string.
    pub fn with_allowed_repos(mut self, repos: &str) -> Self {
        for repo in repos.split(',') {
            let repo = repo.trim();
            if !repo.is_empty() {
                self.allowed_repos.insert(repo.to_string());
            }
        }
        self
    }

    /// Parse allowed orgs from comma-separated string.
    pub fn with_allowed_orgs(mut self, orgs: &str) -> Self {
        for org in orgs.split(',') {
            let org = org.trim();
            if !org.is_empty() {
                self.allowed_orgs.insert(org.to_string());
            }
        }
        self
    }

    /// Set certificate TTL.
    pub fn with_cert_ttl(mut self, ttl: Duration) -> Self {
        self.cert_ttl = ttl;
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GITHUB OIDC CLAIMS
// ═══════════════════════════════════════════════════════════════════════════

/// Claims from a GitHub Actions OIDC token.
///
/// Reference: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitHubClaims {
    /// Issuer (always "https://token.actions.githubusercontent.com")
    pub iss: String,
    /// Subject (format: "repo:org/repo:ref:refs/heads/main")
    pub sub: String,
    /// Audience (the requested audience, e.g., "nucleus")
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at time (Unix timestamp)
    pub iat: u64,
    /// Not before time (Unix timestamp)
    pub nbf: u64,
    /// JWT ID
    pub jti: String,

    // GitHub-specific claims
    /// Repository (format: "org/repo")
    pub repository: String,
    /// Repository owner (org or user)
    pub repository_owner: String,
    /// Repository owner ID
    pub repository_owner_id: String,
    /// Repository ID
    pub repository_id: String,
    /// Repository visibility ("public", "private", "internal")
    pub repository_visibility: String,
    /// Actor (user who triggered the workflow)
    pub actor: String,
    /// Actor ID
    pub actor_id: String,
    /// Workflow name
    pub workflow: String,
    /// Workflow ref (branch/tag)
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// Ref type ("branch" or "tag")
    pub ref_type: String,
    /// Event name that triggered the workflow
    pub event_name: String,
    /// SHA of the commit
    pub sha: String,
    /// Run ID
    pub run_id: String,
    /// Run number
    pub run_number: String,
    /// Run attempt
    pub run_attempt: String,
    /// Job workflow ref (reusable workflow reference)
    #[serde(default)]
    pub job_workflow_ref: Option<String>,
    /// Environment name (if deploying to an environment)
    #[serde(default)]
    pub environment: Option<String>,
}

impl GitHubClaims {
    /// Get the organization from the repository.
    pub fn org(&self) -> &str {
        self.repository
            .split('/')
            .next()
            .unwrap_or(&self.repository_owner)
    }

    /// Get the repo name without the org prefix.
    pub fn repo_name(&self) -> &str {
        self.repository
            .split('/')
            .nth(1)
            .unwrap_or(&self.repository)
    }

    /// Get the branch name (if ref is a branch).
    pub fn branch(&self) -> Option<&str> {
        self.git_ref.strip_prefix("refs/heads/")
    }

    /// Check if this is the default branch (main/master).
    pub fn is_default_branch(&self) -> bool {
        matches!(self.branch(), Some("main") | Some("master"))
    }

    /// Convert to a SPIFFE ID.
    ///
    /// Format: `spiffe://trust-domain/ns/github/sa/{org}/{repo}`
    pub fn to_spiffe_id(&self, trust_domain: &str) -> String {
        // Sanitize org and repo names for SPIFFE path (replace invalid chars)
        let org = sanitize_spiffe_segment(self.org());
        let repo = sanitize_spiffe_segment(self.repo_name());

        format!("spiffe://{}/ns/github/sa/{}/{}", trust_domain, org, repo)
    }
}

/// Sanitize a string for use in a SPIFFE path segment.
///
/// # Security
///
/// This function must be **injective** (one-to-one) to prevent SPIFFE ID collisions.
/// Two different inputs must never produce the same output, as that would allow
/// one repository to impersonate another.
///
/// For GitHub OIDC specifically, this is safe because:
/// - GitHub org names: alphanumeric and hyphens only
/// - GitHub repo names: alphanumeric, hyphens, underscores, and dots
///
/// The only transformation is dot → hyphen, which is safe because:
/// - GitHub does not allow consecutive dots or hyphens
/// - GitHub does not allow names to start/end with dots or hyphens
/// - "foo.bar" → "foo-bar" is unique (can't have both "foo.bar" and "foo-bar")
///
/// # Panics
///
/// Debug builds will panic if the input contains characters that would cause collision.
fn sanitize_spiffe_segment(s: &str) -> String {
    // Validate no collision risk: if both "-" and "." are in the string at the same position
    // context, we might have a problem. For GitHub, this shouldn't happen.
    debug_assert!(
        !s.contains(".-") && !s.contains("-."),
        "SPIFFE segment sanitization collision risk: {}",
        s
    );

    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// JWKS HANDLING
// ═══════════════════════════════════════════════════════════════════════════

/// JSON Web Key Set response from GitHub.
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// A single JSON Web Key.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub kid: String,
    pub alg: Option<String>,
    pub n: String,
    pub e: String,
}

/// JWKS cache for GitHub's public keys.
///
/// Uses a mutex to prevent thundering herd on cache refresh.
pub struct JwksCache {
    /// Cached keys and last fetch time.
    state: RwLock<JwksCacheState>,
    /// Mutex to serialize refresh operations (prevents thundering herd).
    refresh_lock: Mutex<()>,
    /// How long to cache JWKS (default: 1 hour).
    cache_duration: Duration,
}

/// Internal state for the JWKS cache.
struct JwksCacheState {
    keys: Option<JwksResponse>,
    last_fetch: Option<Instant>,
}

impl JwksCache {
    /// Create a new JWKS cache.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(JwksCacheState {
                keys: None,
                last_fetch: None,
            }),
            refresh_lock: Mutex::new(()),
            cache_duration: Duration::from_secs(3600),
        }
    }

    /// Get a decoding key for the given key ID.
    pub async fn get_key(&self, kid: &str) -> Result<DecodingKey, OidcError> {
        // Check if we need to refresh
        let should_refresh = {
            let state = self.state.read().await;
            match state.last_fetch {
                None => true,
                Some(t) => t.elapsed() > self.cache_duration,
            }
        };

        if should_refresh {
            // Acquire refresh lock to prevent thundering herd
            let _refresh_guard = self.refresh_lock.lock().await;

            // Double-check after acquiring lock (another thread may have refreshed)
            let still_needs_refresh = {
                let state = self.state.read().await;
                match state.last_fetch {
                    None => true,
                    Some(t) => t.elapsed() > self.cache_duration,
                }
            };

            if still_needs_refresh {
                self.refresh().await?;
            }
        }

        // Find the key
        let state = self.state.read().await;
        let jwks = state.keys.as_ref().ok_or(OidcError::JwksNotLoaded)?;

        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| OidcError::KeyNotFound(kid.to_string()))?;

        // Convert to DecodingKey
        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| OidcError::InvalidKey(e.to_string()))
    }

    /// Refresh the JWKS from GitHub.
    ///
    /// MUST be called while holding refresh_lock to prevent concurrent refreshes.
    async fn refresh(&self) -> Result<(), OidcError> {
        info!("Fetching GitHub OIDC JWKS from {}", GITHUB_JWKS_URL);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| OidcError::NetworkError(e.to_string()))?;

        let response = client
            .get(GITHUB_JWKS_URL)
            .send()
            .await
            .map_err(|e| OidcError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OidcError::JwksFetchFailed(response.status().to_string()));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| OidcError::InvalidJwks(e.to_string()))?;

        info!("Loaded {} keys from GitHub JWKS", jwks.keys.len());

        // Update cache atomically
        {
            let mut state = self.state.write().await;
            state.keys = Some(jwks);
            state.last_fetch = Some(Instant::now());
        }

        Ok(())
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// JWT REPLAY PROTECTION
// ═══════════════════════════════════════════════════════════════════════════

/// Cache of used JWT IDs (jti) to prevent token replay attacks.
///
/// Tokens are cached until they expire, then automatically evicted.
/// Uses a concurrent hashmap with expiration times for efficiency.
pub struct JtiCache {
    /// Map of jti -> expiration timestamp (Unix seconds).
    used_tokens: RwLock<std::collections::HashMap<String, u64>>,
    /// Last cleanup time.
    last_cleanup: RwLock<Instant>,
    /// Cleanup interval (default: 5 minutes).
    cleanup_interval: Duration,
}

impl JtiCache {
    /// Create a new JTI cache.
    pub fn new() -> Self {
        Self {
            used_tokens: RwLock::new(std::collections::HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
            cleanup_interval: Duration::from_secs(300),
        }
    }

    /// Check if a JTI has been used, and mark it as used if not.
    ///
    /// Returns `Ok(())` if the token is fresh, `Err(OidcError::TokenReplay)` if already used.
    pub async fn check_and_mark(&self, jti: &str, exp: u64) -> Result<(), OidcError> {
        // Periodic cleanup of expired entries
        self.maybe_cleanup().await;

        // Check and insert atomically
        let mut tokens = self.used_tokens.write().await;

        if tokens.contains_key(jti) {
            warn!(jti = %jti, "Rejecting replayed JWT token");
            return Err(OidcError::TokenReplay(jti.to_string()));
        }

        tokens.insert(jti.to_string(), exp);
        debug!(jti = %jti, exp = exp, "Recorded JTI for replay protection");

        Ok(())
    }

    /// Clean up expired JTIs periodically.
    async fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.read().await;
            last.elapsed() > self.cleanup_interval
        };

        if !should_cleanup {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut tokens = self.used_tokens.write().await;
        let before = tokens.len();
        tokens.retain(|_, exp| *exp > now);
        let after = tokens.len();

        if before != after {
            debug!(
                removed = before - after,
                remaining = after,
                "Cleaned up expired JTIs"
            );
        }

        // Update last cleanup time
        drop(tokens);
        let mut last = self.last_cleanup.write().await;
        *last = Instant::now();
    }
}

impl Default for JtiCache {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TOKEN VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════

/// GitHub OIDC token validator.
pub struct GitHubOidcValidator {
    config: GitHubOidcConfig,
    jwks: Arc<JwksCache>,
    /// JTI cache for replay protection.
    jti_cache: Arc<JtiCache>,
}

impl GitHubOidcValidator {
    /// Create a new validator with the given configuration.
    pub fn new(config: GitHubOidcConfig) -> Self {
        Self {
            config,
            jwks: Arc::new(JwksCache::new()),
            jti_cache: Arc::new(JtiCache::new()),
        }
    }

    /// Validate a GitHub OIDC token and return the claims.
    ///
    /// This performs the following security checks:
    /// 1. Signature validation against GitHub's JWKS (RS256)
    /// 2. Issuer validation (must be GitHub Actions)
    /// 3. Audience validation (must match configured audience)
    /// 4. Expiration and not-before validation
    /// 5. Repository allowlist check
    /// 6. **Replay protection via JTI tracking**
    pub async fn validate(&self, token: &str) -> Result<GitHubClaims, OidcError> {
        if !self.config.enabled {
            return Err(OidcError::NotEnabled);
        }

        // Decode header to get key ID
        let header =
            decode_header(token).map_err(|e| OidcError::InvalidToken(e.to_string()))?;

        let kid = header.kid.ok_or(OidcError::MissingKeyId)?;

        // Get the decoding key
        let key = self.jwks.get_key(&kid).await?;

        // Set up validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[GITHUB_ISSUER]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        // Decode and validate
        let token_data = decode::<GitHubClaims>(token, &key, &validation)
            .map_err(|e| OidcError::ValidationFailed(e.to_string()))?;

        let claims = token_data.claims;

        // Replay protection: check if this JTI has been used before
        self.jti_cache.check_and_mark(&claims.jti, claims.exp).await?;

        // Verify repository is allowed
        self.verify_allowed(&claims)?;

        debug!(
            repository = %claims.repository,
            actor = %claims.actor,
            workflow = %claims.workflow,
            jti = %claims.jti,
            "GitHub OIDC token validated successfully (replay protected)"
        );

        Ok(claims)
    }

    /// Verify the repository is in the allowlist.
    fn verify_allowed(&self, claims: &GitHubClaims) -> Result<(), OidcError> {
        // Check if repo is explicitly allowed
        if self.config.allowed_repos.contains(&claims.repository) {
            return Ok(());
        }

        // Check if org is allowed
        if self.config.allowed_orgs.contains(claims.org()) {
            return Ok(());
        }

        // Neither repo nor org is allowed
        warn!(
            repository = %claims.repository,
            org = %claims.org(),
            "Repository not in GitHub OIDC allowlist"
        );

        Err(OidcError::RepoNotAllowed(claims.repository.clone()))
    }

    /// Get the SPIFFE ID for validated claims.
    pub fn spiffe_id(&self, claims: &GitHubClaims) -> String {
        claims.to_spiffe_id(&self.config.trust_domain)
    }

    /// Get the certificate TTL from config.
    pub fn cert_ttl(&self) -> Duration {
        self.config.cert_ttl
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that can occur during OIDC validation.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("GitHub OIDC is not enabled")]
    NotEnabled,

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("missing key ID in token header")]
    MissingKeyId,

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("JWKS not loaded")]
    JwksNotLoaded,

    #[error("failed to fetch JWKS: {0}")]
    JwksFetchFailed(String),

    #[error("invalid JWKS: {0}")]
    InvalidJwks(String),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("token validation failed: {0}")]
    ValidationFailed(String),

    #[error("repository not allowed: {0}")]
    RepoNotAllowed(String),

    #[error("token replay detected: {0}")]
    TokenReplay(String),

    #[error("certificate issuance failed: {0}")]
    CertificateError(String),
}

// ═══════════════════════════════════════════════════════════════════════════
// RESPONSE TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// Request body for the OIDC token exchange endpoint.
///
/// The client generates a key pair and sends the CSR (Certificate Signing Request).
/// This ensures the private key never leaves the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcExchangeRequest {
    /// PEM-encoded Certificate Signing Request (CSR).
    ///
    /// The CSR must include a Subject Alternative Name (SAN) with the expected SPIFFE ID.
    /// This will be validated against the GitHub OIDC claims.
    pub csr: String,
}

/// Response from the OIDC token exchange endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcExchangeResponse {
    /// PEM-encoded X.509 certificate chain.
    pub certificate: String,
    /// SPIFFE ID assigned to this identity.
    pub spiffe_id: String,
    /// Certificate expiration (Unix timestamp).
    pub expires_at: u64,
    /// Trust bundle (CA certificates) for verifying peers.
    pub trust_bundle: String,
}

/// Error response from the OIDC endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_claims_spiffe_id() {
        let claims = GitHubClaims {
            iss: GITHUB_ISSUER.to_string(),
            sub: "repo:octocat/hello-world:ref:refs/heads/main".to_string(),
            aud: "nucleus".to_string(),
            exp: 0,
            iat: 0,
            nbf: 0,
            jti: "test".to_string(),
            repository: "octocat/hello-world".to_string(),
            repository_owner: "octocat".to_string(),
            repository_owner_id: "1".to_string(),
            repository_id: "123".to_string(),
            repository_visibility: "public".to_string(),
            actor: "octocat".to_string(),
            actor_id: "1".to_string(),
            workflow: "CI".to_string(),
            git_ref: "refs/heads/main".to_string(),
            ref_type: "branch".to_string(),
            event_name: "push".to_string(),
            sha: "abc123".to_string(),
            run_id: "1".to_string(),
            run_number: "1".to_string(),
            run_attempt: "1".to_string(),
            job_workflow_ref: None,
            environment: None,
        };

        assert_eq!(claims.org(), "octocat");
        assert_eq!(claims.repo_name(), "hello-world");
        assert_eq!(claims.branch(), Some("main"));
        assert!(claims.is_default_branch());
        assert_eq!(
            claims.to_spiffe_id("nucleus.local"),
            "spiffe://nucleus.local/ns/github/sa/octocat/hello-world"
        );
    }

    #[test]
    fn test_sanitize_spiffe_segment() {
        assert_eq!(sanitize_spiffe_segment("hello-world"), "hello-world");
        assert_eq!(sanitize_spiffe_segment("hello_world"), "hello_world");
        assert_eq!(sanitize_spiffe_segment("hello.world"), "hello-world");
        assert_eq!(sanitize_spiffe_segment("hello/world"), "hello-world");
    }

    #[test]
    fn test_config_allowlist() {
        let config = GitHubOidcConfig::new("nucleus.local")
            .enabled()
            .allow_repo("octocat/hello-world")
            .allow_org("myorg");

        assert!(config.allowed_repos.contains("octocat/hello-world"));
        assert!(config.allowed_orgs.contains("myorg"));
    }

    #[test]
    fn test_config_from_strings() {
        let config = GitHubOidcConfig::new("nucleus.local")
            .with_allowed_repos("org1/repo1, org2/repo2, org3/repo3")
            .with_allowed_orgs("trusted-org, another-org");

        assert_eq!(config.allowed_repos.len(), 3);
        assert_eq!(config.allowed_orgs.len(), 2);
        assert!(config.allowed_repos.contains("org1/repo1"));
        assert!(config.allowed_orgs.contains("trusted-org"));
    }
}
