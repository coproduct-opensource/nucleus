//! SPIRE trust-bundle provider — validates inbound subject-token
//! JWT-SVIDs against per-trust-domain verifying keys.
//!
//! # Three deployment modes
//!
//! Per the `spiffe` crate's documented JWT-SVID verification options:
//!
//! 1. **Trusted-by-construction** (production, future): the OP itself
//!    is a SPIRE workload; JWT-SVIDs fetched directly from the local
//!    SPIRE Agent are trusted without further verification. Implemented
//!    by [`WorkloadApiBundleProvider`] — **stubbed in v1**; production
//!    integration lifts the `transducer-agent/src/spiffe_auth.rs`
//!    pattern (`tonic` over UNIX socket; bundle streaming with
//!    auto-refresh on rotation).
//! 2. **Workload-API-mediated validation** (production, future): the
//!    OP delegates `validate_jwt_token` RPC to its local SPIRE Agent.
//!    Same code path as (1) once `WorkloadApiBundleProvider` lands.
//! 3. **Offline local verification** (v1, this slice): trust bundle is
//!    statically configured at OP startup. Used for tests, air-gapped
//!    deployments, and the v1 deployment posture where the OP is not
//!    itself a SPIRE workload. Implemented by [`StaticBundleProvider`].
//!
//! # Why no mTLS on the OP → SPIRE Agent leg
//!
//! When `WorkloadApiBundleProvider` lands, transport is the
//! co-located SPIRE Agent's UNIX domain socket. Kernel namespace
//! isolation is the trust boundary; mTLS would add ceremony without
//! security gain. See `THREAT_MODEL.md` T08 (SPIRE Agent compromise
//! propagation) for the residual risk we accept.
//!
//! # Fail-closed behavior (acceptance criterion e)
//!
//! [`WorkloadApiBundleProvider::connect_strict`] returns an error if
//! the SPIRE Agent socket is unavailable at boot. The OP's `main.rs`
//! propagates that error and exits non-zero, refusing to start. We
//! reject the alternative of silent fall-through to a permissive
//! mode — that's how T08 ("forged trust bundle accepted because we
//! couldn't reach the real one") happens.

use std::collections::HashMap;
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpireError {
    #[error("SPIRE Agent socket {0:?} unreachable")]
    Unreachable(String),
    #[error("trust bundle empty for trust-domain {0:?}")]
    EmptyBundle(String),
    #[error("workload-api bundle provider is not implemented in v1; use StaticBundleProvider")]
    WorkloadApiNotImplemented,
    #[error("spire backend: {0}")]
    Backend(String),
}

/// Trust-bundle provider — given `(trust_domain, kid)`, returns the
/// Ed25519 verifying key to use for JWT signature checks, or `None`
/// if no such key is in the bundle.
pub trait SpireBundleProvider: Send + Sync {
    /// Look up a verifying key for the given trust-domain + key-id.
    fn verify_key(&self, trust_domain: &str, kid: &str) -> Option<VerifyingKey>;

    /// Trust-domain count — for `/healthz` and observability.
    fn trust_domain_count(&self) -> usize;

    /// Total key count across all trust-domains — for `/healthz`.
    fn total_key_count(&self) -> usize;
}

/// Static bundle, configured at startup. Production-suitable for
/// air-gapped + multi-IdP deployments where the OP is not itself a
/// SPIRE workload (the v1 default posture).
pub struct StaticBundleProvider {
    /// trust_domain → kid → VerifyingKey
    bundles: RwLock<HashMap<String, HashMap<String, VerifyingKey>>>,
}

impl StaticBundleProvider {
    pub fn new() -> Self {
        Self {
            bundles: RwLock::new(HashMap::new()),
        }
    }

    /// Register a verifying key. Replaces any prior key with the same
    /// (trust_domain, kid). Returns the count of distinct trust-domains.
    pub fn add_key(
        &self,
        trust_domain: impl Into<String>,
        kid: impl Into<String>,
        vk: VerifyingKey,
    ) -> usize {
        let mut bundles = self.bundles.write().unwrap_or_else(|p| p.into_inner());
        bundles
            .entry(trust_domain.into())
            .or_default()
            .insert(kid.into(), vk);
        bundles.len()
    }

    /// Atomically replace the bundle for one trust-domain. Useful for
    /// scripted-reload deployments.
    pub fn replace_trust_domain(
        &self,
        trust_domain: impl Into<String>,
        keys: HashMap<String, VerifyingKey>,
    ) {
        let mut bundles = self.bundles.write().unwrap_or_else(|p| p.into_inner());
        bundles.insert(trust_domain.into(), keys);
    }
}

impl Default for StaticBundleProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SpireBundleProvider for StaticBundleProvider {
    fn verify_key(&self, trust_domain: &str, kid: &str) -> Option<VerifyingKey> {
        let bundles = self.bundles.read().unwrap_or_else(|p| p.into_inner());
        bundles.get(trust_domain)?.get(kid).copied()
    }

    fn trust_domain_count(&self) -> usize {
        self.bundles.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    fn total_key_count(&self) -> usize {
        self.bundles
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|m| m.len())
            .sum()
    }
}

/// Production placeholder. Real implementation lifts the
/// `transducer-agent/src/spiffe_auth.rs` SPIRE Workload API client
/// pattern (tonic over UNIX socket, bundle streaming, auto-refresh).
///
/// In v1, calling [`connect_strict`](Self::connect_strict) errors with
/// [`SpireError::WorkloadApiNotImplemented`] — fail-closed by design.
pub struct WorkloadApiBundleProvider;

impl WorkloadApiBundleProvider {
    /// Connect to the SPIRE Agent at `socket_path` with strict-mode
    /// semantics: fail at boot if the agent is unreachable. There is
    /// NO `connect_auto()` permissive sibling — silent fallback to a
    /// degraded provider is forbidden per `THREAT_MODEL.md` T08.
    pub fn connect_strict(_socket_path: &str) -> Result<Self, SpireError> {
        // v2 work: tonic::transport::Endpoint::unix(socket_path) →
        // spiffe::WorkloadApiClient::new(channel).await →
        // client.fetch_jwt_bundles() → poll a watch_jwt_bundles stream.
        Err(SpireError::WorkloadApiNotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn static_provider_returns_registered_key() {
        let (_, vk) = keypair();
        let p = StaticBundleProvider::new();
        p.add_key("td.example.com", "k1", vk);
        assert!(p.verify_key("td.example.com", "k1").is_some());
        assert!(p.verify_key("td.example.com", "k2").is_none());
        assert!(p.verify_key("other.example.com", "k1").is_none());
    }

    #[test]
    fn static_provider_replace_trust_domain_atomic() {
        let (_, vk_a) = keypair();
        let sk_b = SigningKey::from_bytes(&[9; 32]);
        let vk_b = sk_b.verifying_key();
        let p = StaticBundleProvider::new();
        p.add_key("td.example.com", "k1", vk_a);

        let mut next = HashMap::new();
        next.insert("k2".to_string(), vk_b);
        p.replace_trust_domain("td.example.com", next);

        // k1 was wiped by the replace.
        assert!(p.verify_key("td.example.com", "k1").is_none());
        assert!(p.verify_key("td.example.com", "k2").is_some());
    }

    #[test]
    fn workload_api_provider_fails_closed_in_v1() {
        let result = WorkloadApiBundleProvider::connect_strict("/run/spire/agent.sock");
        match result {
            Ok(_) => panic!("v1 must fail-closed"),
            Err(e) => assert!(matches!(e, SpireError::WorkloadApiNotImplemented)),
        }
    }

    #[test]
    fn observability_counts_track_state() {
        let p = StaticBundleProvider::new();
        let (_, vk) = keypair();
        assert_eq!(p.trust_domain_count(), 0);
        assert_eq!(p.total_key_count(), 0);
        p.add_key("td.example.com", "k1", vk);
        p.add_key("td.example.com", "k2", vk);
        p.add_key("other.example.com", "k1", vk);
        assert_eq!(p.trust_domain_count(), 2);
        assert_eq!(p.total_key_count(), 3);
    }
}
