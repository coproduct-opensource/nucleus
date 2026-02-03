//! Identity management integration for nucleus-node.
//!
//! This module integrates the nucleus-identity crate to provide SPIFFE-based
//! workload identity for Firecracker VMs.

use nucleus_identity::{
    CaClient, Identity, SecretManager, SelfSignedCa, VmRegistry, WorkloadApiClient,
    WorkloadApiServer,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info};
use uuid::Uuid;

/// Identity manager for the node daemon.
///
/// Wraps the SecretManager and WorkloadApiServer to provide SPIFFE identities
/// to Firecracker VMs over Unix sockets (which bridge to vsock).
#[derive(Clone)]
pub struct IdentityManager {
    /// The secret manager for certificate operations.
    secret_manager: Arc<SecretManager<SelfSignedCa>>,
    /// The CA client (needed for trust bundle access).
    ca: Arc<SelfSignedCa>,
    /// Registry mapping pod IDs to their SPIFFE identities.
    vm_registry: Arc<VmRegistry>,
    /// Trust domain for this node.
    trust_domain: String,
}

impl IdentityManager {
    /// Creates a new identity manager with a self-signed CA.
    ///
    /// For production, this should be replaced with a SPIRE CA client.
    pub fn new(trust_domain: impl Into<String>, cert_ttl: Duration) -> Result<Self, String> {
        let trust_domain = trust_domain.into();
        let ca = Arc::new(
            SelfSignedCa::new(&trust_domain)
                .map_err(|e| format!("failed to create self-signed CA: {e}"))?,
        );
        let secret_manager = SecretManager::new(ca.clone(), cert_ttl);
        let vm_registry = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            secret_manager,
            ca,
            vm_registry,
            trust_domain,
        })
    }

    /// Returns the trust domain.
    #[allow(dead_code)]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Creates a SPIFFE identity for a pod.
    #[allow(dead_code)]
    pub fn identity_for_pod(
        &self,
        pod_id: Uuid,
        namespace: &str,
        service_account: &str,
    ) -> Identity {
        // Use the service account if provided, otherwise use pod ID
        let sa = if service_account.is_empty() {
            pod_id.to_string()
        } else {
            service_account.to_string()
        };
        Identity::new(&self.trust_domain, namespace, sa)
    }

    /// Registers a pod's identity in the VM registry.
    #[allow(dead_code)]
    pub async fn register_pod(&self, connection_id: impl Into<String>, identity: Identity) {
        let mut registry = self.vm_registry.write().await;
        registry.insert(connection_id.into(), identity);
    }

    /// Unregisters a pod from the VM registry.
    #[allow(dead_code)]
    pub async fn unregister_pod(&self, connection_id: &str) {
        let mut registry = self.vm_registry.write().await;
        registry.remove(connection_id);
    }

    /// Starts the Workload API server on a Unix socket.
    ///
    /// This should be called once at startup and the server runs in the background.
    #[allow(dead_code)]
    pub async fn start_workload_api_server(&self, socket_path: &Path) -> Result<(), String> {
        let server = WorkloadApiServer::new(
            self.secret_manager.clone(),
            self.ca.clone(),
            self.vm_registry.clone(),
        );

        let socket_path_for_spawn = socket_path.to_path_buf();
        let socket_path_display = socket_path.display().to_string();
        tokio::spawn(async move {
            #[allow(deprecated)]
            if let Err(e) = server.serve(&socket_path_for_spawn).await {
                error!("workload API server error: {}", e);
            }
        });

        info!("workload API server started on {}", socket_path_display);
        Ok(())
    }

    /// Starts the certificate refresh loop in the background.
    #[allow(dead_code)]
    pub fn start_refresh_loop(&self) {
        let manager = self.secret_manager.clone();
        tokio::spawn(async move {
            manager.run_refresh_loop().await;
        });
    }

    /// Pre-fetches a certificate for the given identity.
    ///
    /// This is useful to warm the cache before the VM starts requesting certificates.
    #[allow(dead_code)]
    pub async fn prefetch_certificate(&self, identity: &Identity) -> Result<(), String> {
        self.secret_manager
            .fetch_certificate(identity)
            .await
            .map(|_| ())
            .map_err(|e| format!("failed to prefetch certificate: {e}"))
    }

    /// Fetches a certificate for the given identity, returning the certificate.
    ///
    /// Uses the cache if available, otherwise generates a new certificate.
    #[allow(dead_code)]
    pub async fn fetch_certificate(
        &self,
        identity: &Identity,
    ) -> Result<std::sync::Arc<nucleus_identity::WorkloadCertificate>, String> {
        self.secret_manager
            .fetch_certificate(identity)
            .await
            .map_err(|e| format!("failed to fetch certificate: {e}"))
    }

    /// Forgets a certificate for the given identity.
    ///
    /// Called when a pod is terminated to clean up cached certificates.
    #[allow(dead_code)]
    pub async fn forget_certificate(&self, identity: &Identity) {
        self.secret_manager.forget_certificate(identity).await;
    }

    /// Returns the trust bundle (root CA certificates).
    #[allow(dead_code)]
    pub fn trust_bundle(&self) -> &nucleus_identity::TrustBundle {
        self.ca.trust_bundle()
    }

    /// Creates a Workload API client for the given socket path.
    #[allow(dead_code)]
    pub fn client(socket_path: impl Into<std::path::PathBuf>) -> WorkloadApiClient {
        WorkloadApiClient::new(socket_path)
    }
}

impl std::fmt::Debug for IdentityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityManager")
            .field("trust_domain", &self.trust_domain)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_manager_creation() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        assert_eq!(manager.trust_domain(), "test.local");
    }

    #[tokio::test]
    async fn test_identity_for_pod() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let pod_id = Uuid::new_v4();

        let identity = manager.identity_for_pod(pod_id, "default", "my-service");
        assert_eq!(identity.trust_domain(), "test.local");
        assert_eq!(identity.namespace(), "default");
        assert_eq!(identity.service_account(), "my-service");
    }

    #[tokio::test]
    async fn test_identity_for_pod_no_service_account() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let pod_id = Uuid::new_v4();

        let identity = manager.identity_for_pod(pod_id, "default", "");
        assert_eq!(identity.service_account(), pod_id.to_string());
    }

    #[tokio::test]
    async fn test_pod_registration() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let pod_id = Uuid::new_v4();
        let identity = manager.identity_for_pod(pod_id, "default", "my-service");

        manager
            .register_pod(pod_id.to_string(), identity.clone())
            .await;

        // Verify registration
        let registry = manager.vm_registry.read().await;
        assert!(registry.contains_key(&pod_id.to_string()));
        assert_eq!(registry.get(&pod_id.to_string()), Some(&identity));
        drop(registry);

        // Unregister
        manager.unregister_pod(&pod_id.to_string()).await;
        let registry = manager.vm_registry.read().await;
        assert!(!registry.contains_key(&pod_id.to_string()));
    }

    #[tokio::test]
    async fn test_prefetch_certificate() {
        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let identity = Identity::new("test.local", "default", "my-service");

        // Should succeed - CA will sign the certificate
        manager.prefetch_certificate(&identity).await.unwrap();
    }
}
