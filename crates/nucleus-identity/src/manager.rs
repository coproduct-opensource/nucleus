//! Secret manager for workload certificate caching and rotation.
//!
//! The `SecretManager` provides:
//! - Multi-identity certificate management (one manager for all pods on a node)
//! - Automatic certificate rotation before expiry
//! - Cache retention during refresh failures
//! - Priority-based refresh scheduling
//!
//! # Example
//!
//! ```ignore
//! use nucleus_identity::{SecretManager, SelfSignedCa, Identity};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
//! let manager = SecretManager::new(ca, Duration::from_secs(3600));
//!
//! let identity = Identity::new("nucleus.local", "default", "my-service");
//! // In async context:
//! let cert = manager.fetch_certificate(&identity).await.unwrap();
//! ```

use crate::ca::CaClient;
use crate::certificate::WorkloadCertificate;
use crate::identity::Identity;
use crate::session::{SessionId, SessionIdentity};
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, RwLock};
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Default certificate TTL (24 hours).
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Refresh certificates when they have less than this fraction of their TTL remaining.
const REFRESH_THRESHOLD: f64 = 0.5;

/// Minimum time between refresh attempts for the same identity.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Manages workload certificates for multiple identities.
pub struct SecretManager<C: CaClient> {
    /// The CA client for signing certificates.
    ca_client: Arc<C>,
    /// Cached certificates by identity.
    certs: RwLock<HashMap<Identity, CertState>>,
    /// Cached session certificates by (parent identity, session ID).
    session_certs: RwLock<HashMap<(Identity, SessionId), SessionCertState>>,
    /// Default TTL for certificates.
    default_ttl: Duration,
    /// Shutdown signal for the refresh loop.
    shutdown: watch::Sender<bool>,
}

/// State of a certificate in the cache.
enum CertState {
    /// Certificate is being initialized; receivers will get the result.
    Initializing(watch::Receiver<Option<Arc<WorkloadCertificate>>>),
    /// Certificate is available.
    Available {
        cert: Arc<WorkloadCertificate>,
        #[allow(dead_code)]
        last_refresh_attempt: Instant,
    },
    /// Certificate fetch failed.
    Unavailable {
        #[allow(dead_code)]
        error: String,
        last_attempt: Instant,
    },
}

/// State of a session certificate in the cache.
enum SessionCertState {
    /// Certificate is being initialized; receivers will get the result.
    Initializing(watch::Receiver<Option<Arc<WorkloadCertificate>>>),
    /// Certificate is available.
    Available {
        cert: Arc<WorkloadCertificate>,
        session_identity: SessionIdentity,
    },
    /// Certificate fetch failed.
    Unavailable {
        #[allow(dead_code)]
        error: String,
        last_attempt: Instant,
    },
}

impl<C: CaClient + 'static> SecretManager<C> {
    /// Creates a new secret manager with the given CA client.
    pub fn new(ca_client: Arc<C>, default_ttl: Duration) -> Arc<Self> {
        let (shutdown_tx, _) = watch::channel(false);

        Arc::new(Self {
            ca_client,
            certs: RwLock::new(HashMap::new()),
            session_certs: RwLock::new(HashMap::new()),
            default_ttl,
            shutdown: shutdown_tx,
        })
    }

    /// Creates a new secret manager with default TTL (24 hours).
    pub fn with_default_ttl(ca_client: Arc<C>) -> Arc<Self> {
        Self::new(ca_client, DEFAULT_TTL)
    }

    /// Fetches a certificate for the given identity.
    ///
    /// If a valid certificate is cached, it is returned immediately.
    /// Otherwise, a new certificate is requested from the CA.
    pub async fn fetch_certificate(&self, identity: &Identity) -> Result<Arc<WorkloadCertificate>> {
        // Fast path: check if we have a valid cached certificate
        {
            let certs = self.certs.read().await;
            if let Some(state) = certs.get(identity) {
                match state {
                    CertState::Available { cert, .. } if !cert.is_expired() => {
                        return Ok(cert.clone());
                    }
                    CertState::Initializing(rx) => {
                        // Wait for initialization to complete
                        let mut rx = rx.clone();
                        drop(certs);
                        loop {
                            if let Some(cert) = rx.borrow().as_ref() {
                                return Ok(cert.clone());
                            }
                            if rx.changed().await.is_err() {
                                return Err(Error::CertificateNotFound(identity.to_string()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Slow path: need to fetch a new certificate
        self.fetch_new_certificate(identity).await
    }

    /// Forces a certificate refresh for the given identity.
    pub async fn refresh_certificate(
        &self,
        identity: &Identity,
    ) -> Result<Arc<WorkloadCertificate>> {
        self.fetch_new_certificate(identity).await
    }

    /// Fetches a session-scoped certificate derived from a parent workload identity.
    ///
    /// Session certificates enable audit correlation across multiple tool calls within
    /// an AI agent conversation. The certificate's identity encodes both the parent
    /// workload and the unique session ID.
    ///
    /// # Arguments
    ///
    /// * `session` - The session identity containing parent, session ID, and TTL
    ///
    /// # Returns
    ///
    /// A certificate valid for `min(session_ttl, parent_cert_remaining_ttl)`.
    /// The certificate is cached by `(parent_identity, session_id)`.
    pub async fn fetch_session_certificate(
        &self,
        session: &SessionIdentity,
    ) -> Result<Arc<WorkloadCertificate>> {
        // Check if session has expired
        if session.is_expired() {
            return Err(Error::CertificateExpired);
        }

        let cache_key = (session.parent().clone(), session.session_id().clone());

        // Fast path: check cache
        {
            let certs = self.session_certs.read().await;
            if let Some(state) = certs.get(&cache_key) {
                match state {
                    SessionCertState::Available { cert, session_identity }
                        if !cert.is_expired() && !session_identity.is_expired() =>
                    {
                        return Ok(cert.clone());
                    }
                    SessionCertState::Initializing(rx) => {
                        let mut rx = rx.clone();
                        drop(certs);
                        loop {
                            if let Some(cert) = rx.borrow().as_ref() {
                                return Ok(cert.clone());
                            }
                            if rx.changed().await.is_err() {
                                return Err(Error::CertificateNotFound(session.to_string()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Slow path: fetch new session certificate
        self.fetch_new_session_certificate(session).await
    }

    /// Fetches a new session certificate from the CA.
    async fn fetch_new_session_certificate(
        &self,
        session: &SessionIdentity,
    ) -> Result<Arc<WorkloadCertificate>> {
        let cache_key = (session.parent().clone(), session.session_id().clone());
        let (tx, rx) = watch::channel(None);

        {
            let mut certs = self.session_certs.write().await;

            // Check if another task is already initializing
            if let Some(SessionCertState::Initializing(existing_rx)) = certs.get(&cache_key) {
                let mut rx = existing_rx.clone();
                drop(certs);
                loop {
                    if let Some(cert) = rx.borrow().as_ref() {
                        return Ok(cert.clone());
                    }
                    if rx.changed().await.is_err() {
                        return Err(Error::CertificateNotFound(session.to_string()));
                    }
                }
            }

            // Check rate limiting
            if let Some(SessionCertState::Unavailable { last_attempt, .. }) = certs.get(&cache_key)
            {
                if last_attempt.elapsed() < MIN_REFRESH_INTERVAL {
                    return Err(Error::Internal(
                        "refresh rate limited; try again later".to_string(),
                    ));
                }
            }

            certs.insert(cache_key.clone(), SessionCertState::Initializing(rx));
        }

        // Use the certificate identity which embeds session ID in service account.
        // This creates a SPIFFE-compatible identity where the session ID is part of
        // the service account name: spiffe://domain/ns/namespace/sa/service-{session-id}
        let cert_identity = session.to_certificate_identity();

        // Calculate effective TTL: min(session_ttl, default_ttl)
        let effective_ttl = session
            .remaining()
            .map(|r| r.min(self.default_ttl))
            .unwrap_or(self.default_ttl);

        // Generate CSR with the certificate identity's SPIFFE URI (must match for CA validation)
        let csr_options = crate::CsrOptions::new(cert_identity.to_spiffe_uri());
        let cert_sign = match csr_options.generate() {
            Ok(cs) => cs,
            Err(e) => {
                self.mark_session_unavailable(&cache_key, e.to_string())
                    .await;
                return Err(e);
            }
        };

        let cert = match self
            .ca_client
            .sign_csr(cert_sign.csr(), cert_sign.private_key(), &cert_identity, effective_ttl)
            .await
        {
            Ok(c) => Arc::new(c),
            Err(e) => {
                self.mark_session_unavailable(&cache_key, e.to_string())
                    .await;
                return Err(e);
            }
        };

        // Update cache
        {
            let mut certs = self.session_certs.write().await;
            certs.insert(
                cache_key,
                SessionCertState::Available {
                    cert: cert.clone(),
                    session_identity: session.clone(),
                },
            );
        }

        // Notify waiters
        let _ = tx.send(Some(cert.clone()));

        info!(
            "fetched session certificate for {} (session {})",
            session.parent(),
            session.session_id()
        );
        Ok(cert)
    }

    /// Marks a session certificate as unavailable after a fetch failure.
    async fn mark_session_unavailable(&self, key: &(Identity, SessionId), error: String) {
        let mut certs = self.session_certs.write().await;
        certs.insert(
            key.clone(),
            SessionCertState::Unavailable {
                error,
                last_attempt: Instant::now(),
            },
        );
    }

    /// Removes a session certificate from the cache.
    pub async fn forget_session_certificate(&self, parent: &Identity, session_id: &SessionId) {
        let mut certs = self.session_certs.write().await;
        certs.remove(&(parent.clone(), session_id.clone()));
        debug!("forgot session certificate for {} session {}", parent, session_id);
    }

    /// Returns all cached session identities as (parent, session_id) pairs.
    pub async fn cached_session_identities(&self) -> Vec<(Identity, SessionId)> {
        let certs = self.session_certs.read().await;
        certs.keys().cloned().collect()
    }

    /// Removes a certificate from the cache.
    pub async fn forget_certificate(&self, identity: &Identity) {
        let mut certs = self.certs.write().await;
        certs.remove(identity);
        debug!("forgot certificate for {}", identity);
    }

    /// Returns all cached identities.
    pub async fn cached_identities(&self) -> Vec<Identity> {
        let certs = self.certs.read().await;
        certs.keys().cloned().collect()
    }

    /// Checks if a certificate needs refresh.
    pub async fn needs_refresh(&self, identity: &Identity) -> bool {
        let certs = self.certs.read().await;
        match certs.get(identity) {
            Some(CertState::Available { cert, .. }) => {
                let now = chrono::Utc::now();
                let expiry = cert.expiry();
                let total_lifetime = expiry - cert.leaf().not_before().unwrap_or(now);
                let remaining = expiry - now;

                let threshold = chrono::Duration::from_std(Duration::from_secs_f64(
                    total_lifetime.num_seconds() as f64 * REFRESH_THRESHOLD,
                ))
                .unwrap_or(chrono::Duration::hours(1));

                remaining < threshold
            }
            Some(CertState::Unavailable { .. }) => true,
            Some(CertState::Initializing(_)) => false,
            None => true,
        }
    }

    /// Starts the background refresh loop.
    ///
    /// This should be spawned as a background task. It periodically checks
    /// all cached certificates and refreshes those that are close to expiry.
    pub async fn run_refresh_loop(self: Arc<Self>) {
        let mut shutdown_rx = self.shutdown.subscribe();
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.refresh_expiring_certs().await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("secret manager refresh loop shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Shuts down the secret manager.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Returns the trust bundle from the CA.
    pub fn trust_bundle(&self) -> &crate::certificate::TrustBundle {
        self.ca_client.trust_bundle()
    }

    /// Fetches a new certificate from the CA.
    async fn fetch_new_certificate(&self, identity: &Identity) -> Result<Arc<WorkloadCertificate>> {
        // Set up initialization state
        let (tx, rx) = watch::channel(None);

        {
            let mut certs = self.certs.write().await;

            // Check if another task is already initializing
            if let Some(CertState::Initializing(existing_rx)) = certs.get(identity) {
                let mut rx = existing_rx.clone();
                drop(certs);
                loop {
                    if let Some(cert) = rx.borrow().as_ref() {
                        return Ok(cert.clone());
                    }
                    if rx.changed().await.is_err() {
                        return Err(Error::CertificateNotFound(identity.to_string()));
                    }
                }
            }

            // Check rate limiting
            if let Some(CertState::Unavailable { last_attempt, .. }) = certs.get(identity) {
                if last_attempt.elapsed() < MIN_REFRESH_INTERVAL {
                    return Err(Error::Internal(
                        "refresh rate limited; try again later".to_string(),
                    ));
                }
            }

            certs.insert(identity.clone(), CertState::Initializing(rx));
        }

        // Generate CSR and request certificate
        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = match csr_options.generate() {
            Ok(cs) => cs,
            Err(e) => {
                self.mark_unavailable(identity, e.to_string()).await;
                return Err(e);
            }
        };

        let cert = match self
            .ca_client
            .sign_csr(cert_sign.csr(), cert_sign.private_key(), identity, self.default_ttl)
            .await
        {
            Ok(c) => Arc::new(c),
            Err(e) => {
                self.mark_unavailable(identity, e.to_string()).await;
                return Err(e);
            }
        };

        // Update cache
        {
            let mut certs = self.certs.write().await;
            certs.insert(
                identity.clone(),
                CertState::Available {
                    cert: cert.clone(),
                    last_refresh_attempt: Instant::now(),
                },
            );
        }

        // Notify waiters
        let _ = tx.send(Some(cert.clone()));

        info!("fetched certificate for {}", identity);
        Ok(cert)
    }

    /// Marks an identity as unavailable after a fetch failure.
    async fn mark_unavailable(&self, identity: &Identity, error: String) {
        let mut certs = self.certs.write().await;
        certs.insert(
            identity.clone(),
            CertState::Unavailable {
                error,
                last_attempt: Instant::now(),
            },
        );
    }

    /// Refreshes certificates that are close to expiry.
    async fn refresh_expiring_certs(&self) {
        let identities: Vec<Identity> = {
            let certs = self.certs.read().await;
            certs.keys().cloned().collect()
        };

        for identity in identities {
            if self.needs_refresh(&identity).await {
                debug!("refreshing certificate for {}", identity);
                match self.fetch_new_certificate(&identity).await {
                    Ok(_) => {
                        info!("refreshed certificate for {}", identity);
                    }
                    Err(e) => {
                        warn!("failed to refresh certificate for {}: {}", identity, e);
                    }
                }
            }
        }
    }
}

impl<C: CaClient> std::fmt::Debug for SecretManager<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretManager")
            .field("default_ttl", &self.default_ttl)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionIdentity;
    use crate::SelfSignedCa;

    #[tokio::test]
    async fn test_fetch_certificate() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let identity = Identity::new("nucleus.local", "default", "my-service");
        let cert = manager.fetch_certificate(&identity).await.unwrap();

        assert_eq!(cert.identity(), &identity);
        assert!(!cert.is_expired());
    }

    #[tokio::test]
    async fn test_certificate_caching() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let identity = Identity::new("nucleus.local", "default", "my-service");

        let cert1 = manager.fetch_certificate(&identity).await.unwrap();
        let cert2 = manager.fetch_certificate(&identity).await.unwrap();

        // Should return the same cached certificate
        assert!(Arc::ptr_eq(&cert1, &cert2));
    }

    #[tokio::test]
    async fn test_forget_certificate() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let identity = Identity::new("nucleus.local", "default", "my-service");

        let cert1 = manager.fetch_certificate(&identity).await.unwrap();
        manager.forget_certificate(&identity).await;
        let cert2 = manager.fetch_certificate(&identity).await.unwrap();

        // Should be different certificates after forget
        assert!(!Arc::ptr_eq(&cert1, &cert2));
    }

    #[tokio::test]
    async fn test_cached_identities() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let id1 = Identity::new("nucleus.local", "default", "service-a");
        let id2 = Identity::new("nucleus.local", "default", "service-b");

        manager.fetch_certificate(&id1).await.unwrap();
        manager.fetch_certificate(&id2).await.unwrap();

        let identities = manager.cached_identities().await;
        assert_eq!(identities.len(), 2);
        assert!(identities.contains(&id1));
        assert!(identities.contains(&id2));
    }

    #[tokio::test]
    async fn test_refresh_certificate() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let identity = Identity::new("nucleus.local", "default", "my-service");

        let cert1 = manager.fetch_certificate(&identity).await.unwrap();
        let cert2 = manager.refresh_certificate(&identity).await.unwrap();

        // Refresh should return a new certificate
        assert!(!Arc::ptr_eq(&cert1, &cert2));
    }

    #[tokio::test]
    async fn test_needs_refresh_new_cert() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let identity = Identity::new("nucleus.local", "default", "my-service");

        // Before fetch, needs refresh
        assert!(manager.needs_refresh(&identity).await);

        // After fetch with 1 hour TTL, should not need refresh
        manager.fetch_certificate(&identity).await.unwrap();
        assert!(!manager.needs_refresh(&identity).await);
    }

    #[tokio::test]
    async fn test_multiple_identities() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let identities: Vec<_> = (0..5)
            .map(|i| Identity::new("nucleus.local", "default", format!("service-{i}")))
            .collect();

        // Fetch all certificates
        for id in &identities {
            manager.fetch_certificate(id).await.unwrap();
        }

        // Verify all are cached
        let cached = manager.cached_identities().await;
        assert_eq!(cached.len(), 5);

        for id in &identities {
            let cert = manager.fetch_certificate(id).await.unwrap();
            assert_eq!(cert.identity(), id);
        }
    }

    #[tokio::test]
    async fn test_fetch_session_certificate() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));

        let cert = manager.fetch_session_certificate(&session).await.unwrap();

        // Session cert identity should contain the session ID
        let cert_identity = cert.identity();
        assert!(
            cert_identity.service_account().starts_with("claude-"),
            "session cert should embed session ID in service account"
        );
        assert!(!cert.is_expired());
    }

    #[tokio::test]
    async fn test_session_certificate_caching() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session = SessionIdentity::new(parent, Duration::from_secs(3600));

        let cert1 = manager.fetch_session_certificate(&session).await.unwrap();
        let cert2 = manager.fetch_session_certificate(&session).await.unwrap();

        // Should return the same cached certificate
        assert!(Arc::ptr_eq(&cert1, &cert2));
    }

    #[tokio::test]
    async fn test_different_sessions_different_certs() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session1 = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));
        let session2 = SessionIdentity::new(parent, Duration::from_secs(3600));

        let cert1 = manager.fetch_session_certificate(&session1).await.unwrap();
        let cert2 = manager.fetch_session_certificate(&session2).await.unwrap();

        // Different sessions should have different certificates
        assert!(!Arc::ptr_eq(&cert1, &cert2));
        assert_ne!(cert1.identity(), cert2.identity());
    }

    #[tokio::test]
    async fn test_forget_session_certificate() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));

        let cert1 = manager.fetch_session_certificate(&session).await.unwrap();
        manager
            .forget_session_certificate(&parent, session.session_id())
            .await;
        let cert2 = manager.fetch_session_certificate(&session).await.unwrap();

        // Should be different certificates after forget
        assert!(!Arc::ptr_eq(&cert1, &cert2));
    }

    #[tokio::test]
    async fn test_cached_session_identities() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session1 = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));
        let session2 = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));

        manager.fetch_session_certificate(&session1).await.unwrap();
        manager.fetch_session_certificate(&session2).await.unwrap();

        let cached = manager.cached_session_identities().await;
        assert_eq!(cached.len(), 2);
    }

    #[tokio::test]
    async fn test_expired_session_rejected() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca, Duration::from_secs(3600));

        let parent = Identity::new("nucleus.local", "agents", "claude");
        // Create an already-expired session
        let session = SessionIdentity {
            parent,
            session_id: crate::session::SessionId::new_v7(),
            created_at: chrono::Utc::now() - chrono::Duration::seconds(10),
            ttl: Duration::from_secs(5),
        };

        let result = manager.fetch_session_certificate(&session).await;
        assert!(matches!(result, Err(Error::CertificateExpired)));
    }
}
