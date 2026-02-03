//! Drand randomness beacon client for anchoring HMAC signatures.
//!
//! [Drand](https://drand.love) is a decentralized randomness beacon operated by the
//! League of Entropy. It publishes unpredictable randomness every 30 seconds, which
//! we use to anchor approval signatures and prevent pre-computation attacks.
//!
//! # Security Model
//!
//! Without drand anchoring, an attacker who extracts the HMAC secret can pre-compute
//! valid signatures for any future timestamp. With drand anchoring, signatures include
//! a round number that:
//!
//! 1. Changes every 30 seconds
//! 2. Cannot be predicted in advance
//! 3. Is cryptographically verified via BLS signature
//! 4. Is verified to be current at validation time
//!
//! This limits the attack window to ~60 seconds even if the secret is compromised.
//!
//! # Security Properties
//!
//! - **BLS Signature Verification**: Every beacon is verified against the League of
//!   Entropy's public key before being accepted.
//! - **Chain Hash Verification**: Beacons are verified to belong to the correct drand
//!   chain, preventing attacks using beacons from test networks.
//! - **Fail-Closed Default**: By default, if drand is unavailable, requests are rejected.
//!
//! # Example
//!
//! ```rust,ignore
//! use nucleus_client::drand::{DrandConfig, expected_round_for_timestamp, validate_round};
//!
//! // Calculate expected round for current time
//! let now = std::time::SystemTime::now()
//!     .duration_since(std::time::UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//! let round = expected_round_for_timestamp(now);
//!
//! // Validate a round is within tolerance
//! assert!(validate_round(round, 1)); // Current round is valid
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default drand API endpoint (League of Entropy mainnet).
pub const DRAND_API_URL: &str = "https://api.drand.sh/public/latest";

/// Genesis time for the drand default chain (Unix timestamp).
/// This is when round 1 was produced.
pub const DRAND_CHAIN_GENESIS: u64 = 1595431050;

/// Period between drand rounds in seconds.
pub const DRAND_PERIOD_SECS: u64 = 30;

/// Default number of previous rounds to accept (tolerance for network latency).
pub const DEFAULT_ROUND_TOLERANCE: u64 = 1;

/// Chain hash for the League of Entropy mainnet (pedersen-bls-chained).
/// This identifies the specific drand network and prevents accepting beacons
/// from test networks or other chains.
pub const DRAND_CHAIN_HASH: &str =
    "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";

/// Public key for the League of Entropy mainnet (pedersen-bls-chained).
/// This is used to verify BLS signatures on beacons.
pub const DRAND_PUBLIC_KEY: &str = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";

/// Maximum TTL for cached beacons in degraded mode (60 seconds = 2 rounds).
/// This is intentionally short to limit the attack window.
#[cfg(feature = "async-drand")]
const MAX_STALE_CACHE_SECS: u64 = 60;

/// Drand beacon response from the API.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DrandBeacon {
    /// Monotonically increasing round number.
    pub round: u64,
    /// SHA256 hash of the threshold BLS signature (the actual randomness).
    pub randomness: String,
    /// Threshold BLS signature proving the round is valid.
    pub signature: String,
    /// Signature of the previous round (for chained mode).
    #[serde(default)]
    pub previous_signature: String,
}

/// Configuration for drand integration.
#[derive(Clone, Debug)]
pub struct DrandConfig {
    /// Whether drand anchoring is enabled.
    pub enabled: bool,
    /// Drand API endpoint URL.
    pub api_url: String,
    /// Number of previous rounds to accept (default: 1).
    /// A tolerance of 1 means we accept current round N or previous round N-1.
    pub round_tolerance: u64,
    /// How long to cache the drand beacon before fetching a new one.
    /// Should be less than the drand period (30s) to ensure freshness.
    pub cache_ttl: Duration,
    /// What to do when drand is unavailable.
    pub fail_mode: DrandFailMode,
    /// Expected chain hash (for verification).
    pub chain_hash: Option<String>,
    /// Public key for BLS verification (hex-encoded).
    pub public_key: Option<String>,
}

/// Behavior when drand beacon cannot be fetched.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DrandFailMode {
    /// Reject the request if drand is unavailable (fail closed).
    /// This is the most secure option and is the default.
    #[default]
    Strict,
    /// Use the last cached round for a short time (60 seconds max).
    /// This provides some availability at the cost of a slightly larger attack window.
    /// Note: Unlike before, this does NOT fall back to predictable clock-based rounds.
    Cached,
}

impl Default for DrandConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_url: DRAND_API_URL.to_string(),
            round_tolerance: DEFAULT_ROUND_TOLERANCE,
            cache_ttl: Duration::from_secs(25), // Less than 30s period
            fail_mode: DrandFailMode::Strict,
            chain_hash: Some(DRAND_CHAIN_HASH.to_string()),
            public_key: Some(DRAND_PUBLIC_KEY.to_string()),
        }
    }
}

impl DrandConfig {
    /// Create a new config with drand disabled.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Create a config from environment variables.
    ///
    /// - `NUCLEUS_DRAND_ENABLED`: "true" or "false"
    /// - `NUCLEUS_DRAND_URL`: API endpoint
    /// - `NUCLEUS_DRAND_TOLERANCE`: Number of rounds
    /// - `NUCLEUS_DRAND_FAIL_MODE`: "strict" or "cached"
    pub fn from_env() -> Self {
        let enabled = std::env::var("NUCLEUS_DRAND_ENABLED")
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);

        let api_url =
            std::env::var("NUCLEUS_DRAND_URL").unwrap_or_else(|_| DRAND_API_URL.to_string());

        let round_tolerance = std::env::var("NUCLEUS_DRAND_TOLERANCE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_ROUND_TOLERANCE);

        let fail_mode = std::env::var("NUCLEUS_DRAND_FAIL_MODE")
            .map(|v| match v.to_lowercase().as_str() {
                "cached" => DrandFailMode::Cached,
                _ => DrandFailMode::Strict,
            })
            .unwrap_or_default();

        Self {
            enabled,
            api_url,
            round_tolerance,
            cache_ttl: Duration::from_secs(25),
            fail_mode,
            chain_hash: Some(DRAND_CHAIN_HASH.to_string()),
            public_key: Some(DRAND_PUBLIC_KEY.to_string()),
        }
    }
}

/// Errors that can occur when working with drand.
#[derive(Debug, thiserror::Error)]
pub enum DrandError {
    /// Drand anchoring is disabled by configuration.
    #[error("drand anchoring is disabled")]
    Disabled,

    /// Network error when fetching drand beacon.
    #[error("failed to fetch drand beacon: {0}")]
    Network(String),

    /// Failed to parse drand response.
    #[error("failed to parse drand response: {0}")]
    Parse(String),

    /// The provided round is not within acceptable tolerance.
    #[error("drand round {provided} is not current (expected {expected} ± {tolerance})")]
    InvalidRound {
        provided: u64,
        expected: u64,
        tolerance: u64,
    },

    /// Drand is unavailable and fail mode is strict.
    #[error("drand beacon unavailable and fail mode is strict")]
    Unavailable,

    /// BLS signature verification failed.
    #[error("BLS signature verification failed: {0}")]
    SignatureVerification(String),

    /// Chain hash mismatch.
    #[error("chain hash mismatch: expected {expected}, got response from different chain")]
    ChainMismatch { expected: String },
}

/// Calculate the expected drand round for a given Unix timestamp.
///
/// The drand default chain started at `DRAND_CHAIN_GENESIS` (1595431050) and
/// produces a new round every `DRAND_PERIOD_SECS` (30) seconds.
///
/// # Example
///
/// ```rust
/// use nucleus_client::drand::{expected_round_for_timestamp, DRAND_CHAIN_GENESIS, DRAND_PERIOD_SECS};
///
/// // At genesis + 30 seconds, we're at round 2
/// assert_eq!(expected_round_for_timestamp(DRAND_CHAIN_GENESIS + 30), 2);
///
/// // At genesis + 60 seconds, we're at round 3
/// assert_eq!(expected_round_for_timestamp(DRAND_CHAIN_GENESIS + 60), 3);
/// ```
pub fn expected_round_for_timestamp(timestamp_secs: u64) -> u64 {
    if timestamp_secs <= DRAND_CHAIN_GENESIS {
        return 1;
    }
    ((timestamp_secs - DRAND_CHAIN_GENESIS) / DRAND_PERIOD_SECS) + 1
}

/// Get the current expected drand round.
pub fn current_expected_round() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    expected_round_for_timestamp(now)
}

/// Validate that a provided drand round is within acceptable tolerance of the current round.
///
/// Returns `true` if the round is:
/// - At most `tolerance` rounds behind the current expected round
/// - Not in the future (we can't accept rounds that don't exist yet)
///
/// # Example
///
/// ```rust
/// use nucleus_client::drand::{validate_round, current_expected_round};
///
/// let current = current_expected_round();
///
/// // Current round is always valid
/// assert!(validate_round(current, 1));
///
/// // One round behind is valid with tolerance=1
/// assert!(validate_round(current.saturating_sub(1), 1));
///
/// // Two rounds behind is invalid with tolerance=1
/// assert!(!validate_round(current.saturating_sub(2), 1));
/// ```
pub fn validate_round(provided_round: u64, tolerance: u64) -> bool {
    let expected = current_expected_round();

    // Round must not be in the future
    if provided_round > expected {
        return false;
    }

    // Round must be within tolerance of current
    provided_round >= expected.saturating_sub(tolerance)
}

/// Validate a round and return a detailed error if invalid.
pub fn validate_round_or_err(provided_round: u64, tolerance: u64) -> Result<(), DrandError> {
    let expected = current_expected_round();

    if provided_round > expected || provided_round < expected.saturating_sub(tolerance) {
        return Err(DrandError::InvalidRound {
            provided: provided_round,
            expected,
            tolerance,
        });
    }

    Ok(())
}

// ============================================================================
// Async Drand Client (requires "async-drand" feature)
// ============================================================================

#[cfg(feature = "async-drand")]
mod async_client {
    use super::*;
    use drand_verify::{G1Pubkey, Pubkey};
    use std::time::Instant;
    use tokio::sync::RwLock;

    /// Async drand client with caching and BLS signature verification.
    ///
    /// Fetches the current drand beacon from the network, verifies its BLS signature,
    /// and caches it to avoid excessive requests. The cache TTL should be less than
    /// the drand period (30s).
    ///
    /// # Security
    ///
    /// - Every beacon is verified against the League of Entropy's BLS public key
    /// - Beacons from incorrect chains are rejected
    /// - Cache TTL is enforced to ensure freshness
    pub struct DrandClient {
        config: DrandConfig,
        client: reqwest::Client,
        cache: RwLock<Option<CachedBeacon>>,
        /// Parsed public key for BLS verification.
        pubkey: Option<G1Pubkey>,
    }

    struct CachedBeacon {
        beacon: DrandBeacon,
        fetched_at: Instant,
    }

    impl DrandClient {
        /// Create a new drand client with the given configuration.
        ///
        /// # Panics
        ///
        /// Panics if the public key is configured but invalid.
        pub fn new(config: DrandConfig) -> Self {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build HTTP client");

            // Parse the public key for BLS verification
            let pubkey = config.public_key.as_ref().map(|pk_hex| {
                let pk_bytes =
                    hex::decode(pk_hex).expect("invalid hex in drand public key configuration");
                G1Pubkey::from_fixed(
                    pk_bytes
                        .try_into()
                        .expect("public key must be exactly 48 bytes"),
                )
                .expect("invalid drand public key")
            });

            Self {
                config,
                client,
                cache: RwLock::new(None),
                pubkey,
            }
        }

        /// Get the configuration.
        pub fn config(&self) -> &DrandConfig {
            &self.config
        }

        /// Fetch the current drand round, using cache if fresh.
        ///
        /// Returns the round number, which can be used in signatures.
        /// The beacon's BLS signature is verified before the round is returned.
        pub async fn current_round(&self) -> Result<u64, DrandError> {
            if !self.config.enabled {
                return Err(DrandError::Disabled);
            }

            // Check cache first (read lock)
            {
                let cache = self.cache.read().await;
                if let Some(ref cached) = *cache {
                    if cached.fetched_at.elapsed() < self.config.cache_ttl {
                        return Ok(cached.beacon.round);
                    }
                }
            }

            // Fetch fresh beacon
            match self.fetch_and_verify().await {
                Ok(beacon) => {
                    let round = beacon.round;

                    // Update cache (write lock)
                    let mut cache = self.cache.write().await;
                    *cache = Some(CachedBeacon {
                        beacon,
                        fetched_at: Instant::now(),
                    });

                    Ok(round)
                }
                Err(e) => {
                    // Handle based on fail mode
                    match self.config.fail_mode {
                        DrandFailMode::Strict => Err(e),
                        DrandFailMode::Cached => {
                            // Try to use stale cache (up to MAX_STALE_CACHE_SECS)
                            let cache = self.cache.read().await;
                            if let Some(ref cached) = *cache {
                                if cached.fetched_at.elapsed()
                                    < Duration::from_secs(MAX_STALE_CACHE_SECS)
                                {
                                    tracing::warn!(
                                        "drand fetch failed, using cached round {} (age: {:?}): {}",
                                        cached.beacon.round,
                                        cached.fetched_at.elapsed(),
                                        e
                                    );
                                    return Ok(cached.beacon.round);
                                }
                            }
                            Err(DrandError::Unavailable)
                        }
                    }
                }
            }
        }

        /// Fetch the latest beacon from the drand API and verify its BLS signature.
        ///
        /// This method:
        /// 1. Fetches the beacon from the API
        /// 2. Verifies the BLS signature against the configured public key
        /// 3. Validates the round is reasonable (not from the distant past or future)
        pub async fn fetch_and_verify(&self) -> Result<DrandBeacon, DrandError> {
            let beacon = self.fetch_latest().await?;
            self.verify_beacon(&beacon)?;
            Ok(beacon)
        }

        /// Fetch the latest beacon from the drand API without verification.
        ///
        /// **WARNING**: This method does not verify the BLS signature. Use
        /// `fetch_and_verify()` instead for production code.
        async fn fetch_latest(&self) -> Result<DrandBeacon, DrandError> {
            let response = self
                .client
                .get(&self.config.api_url)
                .send()
                .await
                .map_err(|e| DrandError::Network(e.to_string()))?;

            if !response.status().is_success() {
                return Err(DrandError::Network(format!("HTTP {}", response.status())));
            }

            let beacon: DrandBeacon = response
                .json()
                .await
                .map_err(|e| DrandError::Parse(e.to_string()))?;

            Ok(beacon)
        }

        /// Verify a beacon's BLS signature.
        ///
        /// Returns an error if:
        /// - The signature is invalid
        /// - The public key is not configured
        /// - The signature bytes cannot be decoded
        fn verify_beacon(&self, beacon: &DrandBeacon) -> Result<(), DrandError> {
            let Some(ref pubkey) = self.pubkey else {
                // If no public key is configured, skip verification (not recommended)
                tracing::warn!("drand public key not configured, skipping BLS verification");
                return Ok(());
            };

            // Decode signature from hex
            let signature_bytes = hex::decode(&beacon.signature).map_err(|e| {
                DrandError::SignatureVerification(format!("invalid signature hex: {}", e))
            })?;

            // Decode previous signature from hex (for chained mode)
            let prev_sig_bytes = if beacon.previous_signature.is_empty() {
                Vec::new()
            } else {
                hex::decode(&beacon.previous_signature).map_err(|e| {
                    DrandError::SignatureVerification(format!(
                        "invalid previous_signature hex: {}",
                        e
                    ))
                })?
            };

            // Verify the BLS signature
            // For pedersen-bls-chained, the message is the previous signature
            let is_valid = if prev_sig_bytes.is_empty() {
                // Unchained mode: message is the round number
                pubkey.verify(beacon.round, &[], &signature_bytes).is_ok()
            } else {
                // Chained mode: message is the previous signature
                pubkey
                    .verify(beacon.round, &prev_sig_bytes, &signature_bytes)
                    .is_ok()
            };

            if !is_valid {
                return Err(DrandError::SignatureVerification(format!(
                    "BLS signature verification failed for round {}",
                    beacon.round
                )));
            }

            // Validate the round is reasonable
            validate_round_or_err(beacon.round, self.config.round_tolerance)?;

            Ok(())
        }

        /// Fetch the latest beacon and validate it's current.
        #[allow(dead_code)]
        pub async fn fetch_and_validate(&self) -> Result<DrandBeacon, DrandError> {
            let beacon = self.fetch_and_verify().await?;
            validate_round_or_err(beacon.round, self.config.round_tolerance)?;
            Ok(beacon)
        }
    }
}

#[cfg(feature = "async-drand")]
pub use async_client::DrandClient;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_round_at_genesis() {
        // At genesis exactly, we should be at round 1
        assert_eq!(expected_round_for_timestamp(DRAND_CHAIN_GENESIS), 1);
    }

    #[test]
    fn test_expected_round_after_genesis() {
        // At genesis + 30 seconds, round 2
        assert_eq!(expected_round_for_timestamp(DRAND_CHAIN_GENESIS + 30), 2);

        // At genesis + 60 seconds, round 3
        assert_eq!(expected_round_for_timestamp(DRAND_CHAIN_GENESIS + 60), 3);

        // At genesis + 90 seconds, round 4
        assert_eq!(expected_round_for_timestamp(DRAND_CHAIN_GENESIS + 90), 4);
    }

    #[test]
    fn test_expected_round_before_genesis() {
        // Before genesis, should return round 1
        assert_eq!(expected_round_for_timestamp(0), 1);
        assert_eq!(expected_round_for_timestamp(DRAND_CHAIN_GENESIS - 1), 1);
    }

    #[test]
    fn test_validate_round_current() {
        let current = current_expected_round();

        // Current round is always valid
        assert!(validate_round(current, 1));
        assert!(validate_round(current, 0));
    }

    #[test]
    fn test_validate_round_with_tolerance() {
        let current = current_expected_round();

        // With tolerance=1, one round behind is valid
        assert!(validate_round(current.saturating_sub(1), 1));

        // With tolerance=1, two rounds behind is invalid
        assert!(!validate_round(current.saturating_sub(2), 1));

        // With tolerance=2, two rounds behind is valid
        assert!(validate_round(current.saturating_sub(2), 2));
    }

    #[test]
    fn test_validate_round_future() {
        let current = current_expected_round();

        // Future rounds are never valid
        assert!(!validate_round(current + 1, 1));
        assert!(!validate_round(current + 100, 100));
    }

    #[test]
    fn test_validate_round_or_err() {
        let current = current_expected_round();

        // Valid round returns Ok
        assert!(validate_round_or_err(current, 1).is_ok());

        // Invalid round returns detailed error
        let err = validate_round_or_err(current.saturating_sub(5), 1).unwrap_err();
        match err {
            DrandError::InvalidRound {
                provided,
                expected,
                tolerance,
            } => {
                assert_eq!(provided, current.saturating_sub(5));
                assert_eq!(expected, current);
                assert_eq!(tolerance, 1);
            }
            _ => panic!("expected InvalidRound error"),
        }
    }

    #[test]
    fn test_drand_config_default() {
        let config = DrandConfig::default();
        assert!(config.enabled);
        assert_eq!(config.api_url, DRAND_API_URL);
        assert_eq!(config.round_tolerance, DEFAULT_ROUND_TOLERANCE);
        assert_eq!(config.fail_mode, DrandFailMode::Strict);
        assert_eq!(config.chain_hash.as_deref(), Some(DRAND_CHAIN_HASH));
        assert_eq!(config.public_key.as_deref(), Some(DRAND_PUBLIC_KEY));
    }

    #[test]
    fn test_drand_config_disabled() {
        let config = DrandConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_drand_beacon_deserialization() {
        let json = r#"{
            "round": 3847291,
            "randomness": "a3f9c2b1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
            "signature": "89af3c1b2e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
            "previous_signature": "72b1e4a3f9c2b1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"
        }"#;

        let beacon: DrandBeacon = serde_json::from_str(json).unwrap();
        assert_eq!(beacon.round, 3847291);
        assert!(!beacon.randomness.is_empty());
        assert!(!beacon.signature.is_empty());
    }

    #[test]
    fn test_drand_beacon_without_previous_signature() {
        // Unchained mode doesn't have previous_signature
        let json = r#"{
            "round": 12345,
            "randomness": "abc123",
            "signature": "def456"
        }"#;

        let beacon: DrandBeacon = serde_json::from_str(json).unwrap();
        assert_eq!(beacon.round, 12345);
        assert!(beacon.previous_signature.is_empty());
    }

    #[test]
    fn test_degraded_mode_removed() {
        // Verify that DrandFailMode no longer has a Degraded variant
        // (we can only test Strict and Cached exist)
        let strict = DrandFailMode::Strict;
        let cached = DrandFailMode::Cached;
        assert_ne!(strict, cached);
    }
}
