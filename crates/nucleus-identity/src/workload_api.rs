//! SPIFFE Workload API server for Firecracker VMs.
//!
//! This module implements a simplified SPIFFE Workload API that serves certificates
//! to guest VMs over a Unix socket (which bridges to vsock).
//!
//! # Protocol
//!
//! The Workload API uses a simple request/response protocol over the Unix socket:
//!
//! - `FETCH_SVID\n` - Request the X.509 SVID (certificate + key) for this VM
//! - `FETCH_BUNDLE\n` - Request the trust bundle (root CA certificates)
//!
//! Responses are newline-delimited JSON.
//!
//! # Example
//!
//! ```ignore
//! use nucleus_identity::{WorkloadApiServer, SecretManager, SelfSignedCa, Identity};
//! use std::sync::Arc;
//! use std::time::Duration;
//! use std::collections::HashMap;
//! use tokio::sync::RwLock;
//!
//! let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
//! let manager = SecretManager::new(ca.clone(), Duration::from_secs(3600));
//!
//! // VM registry maps socket paths to identities
//! let vm_registry = Arc::new(RwLock::new(HashMap::new()));
//!
//! let server = WorkloadApiServer::new(manager, ca, vm_registry);
//! // In async context:
//! // server.serve("/tmp/workload-api.sock").await.unwrap();
//! ```

use crate::ca::CaClient;
use crate::certificate::{TrustBundle, WorkloadCertificate};
use crate::identity::Identity;
use crate::manager::SecretManager;
use crate::tls::{server_name_from_trust_domain, TlsClientConfig, TlsServerConfig};
use crate::{Error, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Registry mapping connection identifiers to SPIFFE identities.
///
/// For Unix sockets, we use the peer credentials (PID/UID) or a pre-registered
/// identity based on the socket path.
pub type VmRegistry = RwLock<HashMap<String, Identity>>;

/// SPIFFE Workload API server.
///
/// Serves certificates and trust bundles to workloads (Firecracker VMs) over
/// a Unix socket connection.
pub struct WorkloadApiServer<C: CaClient> {
    /// Secret manager for certificate operations.
    secret_manager: Arc<SecretManager<C>>,
    /// CA client for trust bundle access.
    ca_client: Arc<C>,
    /// Registry mapping connection IDs to identities.
    vm_registry: Arc<VmRegistry>,
}

impl<C: CaClient + 'static> WorkloadApiServer<C> {
    /// Creates a new Workload API server.
    pub fn new(
        secret_manager: Arc<SecretManager<C>>,
        ca_client: Arc<C>,
        vm_registry: Arc<VmRegistry>,
    ) -> Self {
        Self {
            secret_manager,
            ca_client,
            vm_registry,
        }
    }

    /// Registers a VM's identity in the registry.
    pub async fn register_vm(&self, connection_id: impl Into<String>, identity: Identity) {
        let mut registry = self.vm_registry.write().await;
        registry.insert(connection_id.into(), identity);
    }

    /// Unregisters a VM from the registry.
    pub async fn unregister_vm(&self, connection_id: &str) {
        let mut registry = self.vm_registry.write().await;
        registry.remove(connection_id);
    }

    /// Starts the Workload API server on the given Unix socket path for a single identity.
    ///
    /// This server serves certificates for a single, pre-configured identity.
    /// All connections to this socket receive the same identity's certificate.
    ///
    /// For multi-identity scenarios, use separate sockets per identity or
    /// use `handle_stream()` with explicit identity binding.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path for the Unix socket
    /// * `identity` - The single identity this server will serve
    ///
    /// This method runs until the server is stopped or an error occurs.
    pub async fn serve_single_identity(
        &self,
        socket_path: impl AsRef<Path>,
        identity: Identity,
    ) -> Result<()> {
        let path = socket_path.as_ref();

        // Remove existing socket if present
        if path.exists() {
            tokio::fs::remove_file(path).await?;
        }

        let listener = UnixListener::bind(path)?;
        info!(
            "workload API server listening on {} for identity {}",
            path.display(),
            identity.to_spiffe_uri()
        );

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let manager = self.secret_manager.clone();
                    let ca = self.ca_client.clone();
                    let conn_identity = identity.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_connection_with_identity(stream, manager, ca, conn_identity)
                                .await
                        {
                            error!("workload API connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("workload API accept error: {}", e);
                }
            }
        }
    }

    /// Starts the Workload API server on the given Unix socket path.
    ///
    /// **Security Warning:** This method uses the VM registry to look up identities.
    /// Ensure that only one identity is registered, or use `serve_single_identity()`
    /// for explicit identity binding.
    ///
    /// This method runs until the server is stopped or an error occurs.
    #[deprecated(
        note = "use serve_single_identity() for explicit identity binding to prevent identity confusion attacks"
    )]
    pub async fn serve(&self, socket_path: impl AsRef<Path>) -> Result<()> {
        let path = socket_path.as_ref();

        // Remove existing socket if present
        if path.exists() {
            tokio::fs::remove_file(path).await?;
        }

        let listener = UnixListener::bind(path)?;
        info!("workload API server listening on {}", path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let manager = self.secret_manager.clone();
                    let ca = self.ca_client.clone();
                    let registry = self.vm_registry.clone();

                    tokio::spawn(async move {
                        #[allow(deprecated)]
                        if let Err(e) = handle_connection(stream, manager, ca, registry).await {
                            error!("workload API connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("workload API accept error: {}", e);
                }
            }
        }
    }

    /// Serves a single connection with an explicit identity.
    ///
    /// This is the secure way to handle a single connection where the caller
    /// has already determined the correct identity for this connection.
    pub async fn handle_stream(&self, stream: UnixStream, identity: Identity) -> Result<()> {
        handle_connection_with_identity(
            stream,
            self.secret_manager.clone(),
            self.ca_client.clone(),
            identity,
        )
        .await
    }

    /// Starts the mTLS Workload API server on the given Unix socket path.
    ///
    /// This is the secure production method that wraps Unix socket connections
    /// with mutual TLS authentication. Both server and client must present
    /// valid SPIFFE certificates.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path for the Unix socket
    /// * `identity` - The identity this server serves
    /// * `server_cert` - Server's workload certificate for TLS
    /// * `trust_bundle` - Trust bundle for client certificate validation
    ///
    /// # Security
    ///
    /// - Requires client certificates (mutual TLS)
    /// - Validates client certs against trust bundle
    /// - Explicit identity binding prevents confusion attacks
    pub async fn serve_mtls(
        &self,
        socket_path: impl AsRef<Path>,
        identity: Identity,
        server_cert: WorkloadCertificate,
        trust_bundle: TrustBundle,
    ) -> Result<()> {
        let path = socket_path.as_ref();

        // Build TLS acceptor
        let acceptor = TlsServerConfig::new(server_cert, trust_bundle).build_acceptor()?;

        // Remove existing socket if present
        if path.exists() {
            tokio::fs::remove_file(path).await?;
        }

        let listener = UnixListener::bind(path)?;
        info!(
            "mTLS workload API server listening on {} for identity {}",
            path.display(),
            identity.to_spiffe_uri()
        );

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let manager = self.secret_manager.clone();
                    let ca = self.ca_client.clone();
                    let conn_identity = identity.clone();
                    let acceptor = acceptor.clone();

                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(e) =
                                    handle_tls_connection(tls_stream, manager, ca, conn_identity)
                                        .await
                                {
                                    error!("mTLS workload API connection error: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("TLS handshake failed: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("mTLS workload API accept error: {}", e);
                }
            }
        }
    }
}

impl<C: CaClient> std::fmt::Debug for WorkloadApiServer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadApiServer").finish()
    }
}

/// Handles a single Workload API connection with an explicit identity.
///
/// This is the secure version that requires the caller to specify the identity
/// rather than looking it up from an unverified registry.
async fn handle_connection_with_identity<C: CaClient + 'static>(
    stream: UnixStream,
    manager: Arc<SecretManager<C>>,
    ca: Arc<C>,
    identity: Identity,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            // Connection closed
            break;
        }

        let command = line.trim();
        debug!(
            "workload API received command: {} for {}",
            command, identity
        );

        let response = match command {
            "FETCH_SVID" => match manager.fetch_certificate(&identity).await {
                Ok(cert) => {
                    let response = SvidResponse {
                        spiffe_id: identity.to_spiffe_uri(),
                        certificate_chain: cert.chain_pem(),
                        private_key: cert.private_key_pem().to_string(),
                        expires_at: cert.expiry().timestamp(),
                    };
                    serde_json::to_string(&response)
                        .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
                }
                Err(e) => {
                    format!(r#"{{"error":"{}"}}"#, e)
                }
            },

            "FETCH_BUNDLE" => {
                let bundle = ca.trust_bundle();
                let pem: String = bundle
                    .roots()
                    .iter()
                    .map(|c| c.to_pem().to_string())
                    .collect();
                let response = BundleResponse {
                    trust_domain: ca.trust_domain().to_string(),
                    bundle_pem: pem,
                };
                serde_json::to_string(&response)
                    .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
            }

            "PING" => r#"{"status":"ok"}"#.to_string(),

            _ => {
                format!(r#"{{"error":"unknown command: {}"}}"#, command)
            }
        };

        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Handles a TLS-wrapped Workload API connection.
///
/// This is the secure version for mTLS connections.
async fn handle_tls_connection<S, C>(
    stream: S,
    manager: Arc<SecretManager<C>>,
    ca: Arc<C>,
    identity: Identity,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: CaClient + 'static,
{
    handle_generic_connection(stream, manager, ca, identity).await
}

/// Generic connection handler that works with any async read/write stream.
async fn handle_generic_connection<S, C>(
    stream: S,
    manager: Arc<SecretManager<C>>,
    ca: Arc<C>,
    identity: Identity,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: CaClient + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            // Connection closed
            break;
        }

        let command = line.trim();
        debug!(
            "workload API received command: {} for {}",
            command, identity
        );

        let response = match command {
            "FETCH_SVID" => match manager.fetch_certificate(&identity).await {
                Ok(cert) => {
                    let response = SvidResponse {
                        spiffe_id: identity.to_spiffe_uri(),
                        certificate_chain: cert.chain_pem(),
                        private_key: cert.private_key_pem().to_string(),
                        expires_at: cert.expiry().timestamp(),
                    };
                    serde_json::to_string(&response)
                        .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
                }
                Err(e) => {
                    format!(r#"{{"error":"{}"}}"#, e)
                }
            },

            "FETCH_BUNDLE" => {
                let bundle = ca.trust_bundle();
                let pem: String = bundle
                    .roots()
                    .iter()
                    .map(|c| c.to_pem().to_string())
                    .collect();
                let response = BundleResponse {
                    trust_domain: ca.trust_domain().to_string(),
                    bundle_pem: pem,
                };
                serde_json::to_string(&response)
                    .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
            }

            "PING" => r#"{"status":"ok"}"#.to_string(),

            _ => {
                format!(r#"{{"error":"unknown command: {}"}}"#, command)
            }
        };

        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Handles a single Workload API connection using registry lookup.
///
/// **Security Warning:** This function looks up the identity from the registry,
/// which may return an incorrect identity if multiple identities are registered.
/// Prefer `handle_connection_with_identity()` for explicit identity binding.
#[deprecated(note = "use handle_connection_with_identity() for explicit identity binding")]
async fn handle_connection<C: CaClient + 'static>(
    stream: UnixStream,
    manager: Arc<SecretManager<C>>,
    ca: Arc<C>,
    registry: Arc<VmRegistry>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Security: This picks the first registered identity, which is only safe
    // when exactly one identity is registered. For multi-identity scenarios,
    // use handle_connection_with_identity() with explicit identity binding.
    let identity = {
        let reg = registry.read().await;
        if reg.len() > 1 {
            tracing::warn!(
                "multiple identities registered ({}) - using first one; this is a security risk",
                reg.len()
            );
        }
        reg.values().next().cloned()
    };

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            // Connection closed
            break;
        }

        let command = line.trim();
        debug!("workload API received command: {}", command);

        let response = match command {
            "FETCH_SVID" => {
                if let Some(ref id) = identity {
                    match manager.fetch_certificate(id).await {
                        Ok(cert) => {
                            let response = SvidResponse {
                                spiffe_id: id.to_spiffe_uri(),
                                certificate_chain: cert.chain_pem(),
                                private_key: cert.private_key_pem().to_string(),
                                expires_at: cert.expiry().timestamp(),
                            };
                            serde_json::to_string(&response).unwrap_or_else(|e| {
                                format!(r#"{{"error":"serialization failed: {}"}}"#, e)
                            })
                        }
                        Err(e) => {
                            format!(r#"{{"error":"{}"}}"#, e)
                        }
                    }
                } else {
                    r#"{"error":"no identity registered for this connection"}"#.to_string()
                }
            }

            "FETCH_BUNDLE" => {
                let bundle = ca.trust_bundle();
                let pem: String = bundle
                    .roots()
                    .iter()
                    .map(|c| c.to_pem().to_string())
                    .collect();
                let response = BundleResponse {
                    trust_domain: ca.trust_domain().to_string(),
                    bundle_pem: pem,
                };
                serde_json::to_string(&response)
                    .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
            }

            "PING" => r#"{"status":"ok"}"#.to_string(),

            _ => {
                format!(r#"{{"error":"unknown command: {}"}}"#, command)
            }
        };

        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Response for FETCH_SVID command.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SvidResponse {
    spiffe_id: String,
    certificate_chain: String,
    private_key: String,
    expires_at: i64,
}

/// Response for FETCH_BUNDLE command.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BundleResponse {
    trust_domain: String,
    bundle_pem: String,
}

/// Client for connecting to the Workload API.
pub struct WorkloadApiClient {
    socket_path: std::path::PathBuf,
}

impl WorkloadApiClient {
    /// Creates a new client for the given socket path.
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Fetches the X.509 SVID from the Workload API.
    pub async fn fetch_svid(&self) -> Result<crate::WorkloadCertificate> {
        let response = self.send_command("FETCH_SVID").await?;

        let svid: SvidResponse = serde_json::from_str(&response)
            .map_err(|e| Error::Internal(format!("failed to parse SVID response: {}", e)))?;

        if svid.spiffe_id.is_empty() {
            return Err(Error::Internal("empty SVID response".to_string()));
        }

        crate::WorkloadCertificate::from_pem(&svid.certificate_chain, &svid.private_key)
    }

    /// Fetches the trust bundle from the Workload API.
    pub async fn fetch_bundle(&self) -> Result<crate::certificate::TrustBundle> {
        let response = self.send_command("FETCH_BUNDLE").await?;

        let bundle: BundleResponse = serde_json::from_str(&response)
            .map_err(|e| Error::Internal(format!("failed to parse bundle response: {}", e)))?;

        crate::certificate::TrustBundle::from_pem(&bundle.bundle_pem)
    }

    /// Pings the Workload API to check connectivity.
    pub async fn ping(&self) -> Result<()> {
        let response = self.send_command("PING").await?;
        if response.contains("ok") {
            Ok(())
        } else {
            Err(Error::Internal(format!("ping failed: {}", response)))
        }
    }

    /// Sends a command to the Workload API and returns the response.
    async fn send_command(&self, command: &str) -> Result<String> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        writer.write_all(command.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut response = String::new();
        reader.read_line(&mut response).await?;

        Ok(response.trim().to_string())
    }
}

/// mTLS client for connecting to the Workload API.
///
/// This client uses mutual TLS authentication, requiring both the client
/// to present a certificate and verifying the server's certificate.
pub struct MtlsWorkloadApiClient {
    socket_path: std::path::PathBuf,
    client_cert: WorkloadCertificate,
    trust_bundle: TrustBundle,
    trust_domain: String,
}

impl MtlsWorkloadApiClient {
    /// Creates a new mTLS client for the given socket path.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the Unix socket
    /// * `client_cert` - Client's workload certificate
    /// * `trust_bundle` - Trust bundle for server verification
    /// * `trust_domain` - Trust domain (used as server name for TLS)
    pub fn new(
        socket_path: impl Into<std::path::PathBuf>,
        client_cert: WorkloadCertificate,
        trust_bundle: TrustBundle,
        trust_domain: impl Into<String>,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            client_cert,
            trust_bundle,
            trust_domain: trust_domain.into(),
        }
    }

    /// Fetches the X.509 SVID from the Workload API over mTLS.
    pub async fn fetch_svid(&self) -> Result<crate::WorkloadCertificate> {
        let response = self.send_command("FETCH_SVID").await?;

        let svid: SvidResponse = serde_json::from_str(&response)
            .map_err(|e| Error::Internal(format!("failed to parse SVID response: {}", e)))?;

        if svid.spiffe_id.is_empty() {
            return Err(Error::Internal("empty SVID response".to_string()));
        }

        crate::WorkloadCertificate::from_pem(&svid.certificate_chain, &svid.private_key)
    }

    /// Fetches the trust bundle from the Workload API over mTLS.
    pub async fn fetch_bundle(&self) -> Result<crate::certificate::TrustBundle> {
        let response = self.send_command("FETCH_BUNDLE").await?;

        let bundle: BundleResponse = serde_json::from_str(&response)
            .map_err(|e| Error::Internal(format!("failed to parse bundle response: {}", e)))?;

        crate::certificate::TrustBundle::from_pem(&bundle.bundle_pem)
    }

    /// Pings the Workload API to check connectivity over mTLS.
    pub async fn ping(&self) -> Result<()> {
        let response = self.send_command("PING").await?;
        if response.contains("ok") {
            Ok(())
        } else {
            Err(Error::Internal(format!("ping failed: {}", response)))
        }
    }

    /// Sends a command to the Workload API over mTLS and returns the response.
    async fn send_command(&self, command: &str) -> Result<String> {
        // Build TLS connector with SPIFFE verification
        let connector = TlsClientConfig::new(self.client_cert.clone(), self.trust_bundle.clone())
            .with_spiffe_trust_domain(&self.trust_domain)
            .build_connector()?;

        // Connect Unix socket
        let stream = UnixStream::connect(&self.socket_path).await?;

        // Wrap with TLS
        let server_name = server_name_from_trust_domain(&self.trust_domain)?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| Error::Internal(format!("TLS handshake failed: {}", e)))?;

        let (reader, mut writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(reader);

        writer.write_all(command.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut response = String::new();
        reader.read_line(&mut response).await?;

        Ok(response.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CsrOptions, SelfSignedCa};
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_workload_api_server_creation() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca.clone(), Duration::from_secs(3600));
        let registry = Arc::new(RwLock::new(HashMap::new()));

        let server = WorkloadApiServer::new(manager, ca, registry);
        // Server created successfully
        drop(server);
    }

    #[tokio::test]
    async fn test_vm_registration() {
        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca.clone(), Duration::from_secs(3600));
        let registry = Arc::new(RwLock::new(HashMap::new()));

        let server = WorkloadApiServer::new(manager, ca, registry.clone());

        let identity = Identity::new("nucleus.local", "default", "my-service");
        server.register_vm("vm-1", identity.clone()).await;

        {
            let reg = registry.read().await;
            assert!(reg.contains_key("vm-1"));
            assert_eq!(reg.get("vm-1"), Some(&identity));
        }

        server.unregister_vm("vm-1").await;

        {
            let reg = registry.read().await;
            assert!(!reg.contains_key("vm-1"));
        }
    }

    #[tokio::test]
    async fn test_workload_api_client_server() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("workload-api.sock");

        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca.clone(), Duration::from_secs(3600));
        let registry = Arc::new(RwLock::new(HashMap::new()));

        // Register an identity
        let identity = Identity::new("nucleus.local", "default", "my-service");
        registry
            .write()
            .await
            .insert("default".to_string(), identity.clone());

        let server = WorkloadApiServer::new(manager, ca, registry);

        // Start server in background
        let socket_path_clone = socket_path.clone();
        #[allow(deprecated)]
        let server_handle = tokio::spawn(async move { server.serve(&socket_path_clone).await });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test client
        let client = WorkloadApiClient::new(&socket_path);

        // Test ping
        client.ping().await.unwrap();

        // Test fetch bundle
        let bundle = client.fetch_bundle().await.unwrap();
        assert!(!bundle.roots().is_empty());

        // Test fetch SVID
        let cert = client.fetch_svid().await.unwrap();
        assert_eq!(cert.identity(), &identity);

        // Cleanup
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_mtls_workload_api_client_server() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("mtls-workload-api.sock");

        let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(ca.clone(), Duration::from_secs(3600));
        let registry = Arc::new(RwLock::new(HashMap::new()));

        // Create server identity and certificate
        let server_identity = Identity::new("nucleus.local", "default", "workload-api-server");
        let server_cert_sign = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = ca
            .sign_csr(
                server_cert_sign.csr(),
                server_cert_sign.private_key(),
                &server_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Create client identity and certificate
        let client_identity = Identity::new("nucleus.local", "default", "workload-api-client");
        let client_cert_sign = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = ca
            .sign_csr(
                client_cert_sign.csr(),
                client_cert_sign.private_key(),
                &client_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let trust_bundle = ca.trust_bundle().clone();

        let server = WorkloadApiServer::new(manager, ca.clone(), registry);

        // Start mTLS server in background
        let socket_path_clone = socket_path.clone();
        let server_cert_clone = server_cert.clone();
        let trust_bundle_clone = trust_bundle.clone();
        let served_identity = server_identity.clone();
        let server_handle = tokio::spawn(async move {
            server
                .serve_mtls(
                    &socket_path_clone,
                    served_identity,
                    server_cert_clone,
                    trust_bundle_clone,
                )
                .await
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test mTLS client
        let client =
            MtlsWorkloadApiClient::new(&socket_path, client_cert, trust_bundle, "nucleus.local");

        // Test ping
        client.ping().await.unwrap();

        // Test fetch bundle
        let bundle = client.fetch_bundle().await.unwrap();
        assert!(!bundle.roots().is_empty());

        // Test fetch SVID - should return the server's served identity
        let cert = client.fetch_svid().await.unwrap();
        assert_eq!(cert.identity(), &server_identity);

        // Cleanup
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_mtls_rejects_untrusted_client() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("mtls-reject-test.sock");

        // Create server CA
        let server_ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
        let manager = SecretManager::new(server_ca.clone(), Duration::from_secs(3600));
        let registry = Arc::new(RwLock::new(HashMap::new()));

        // Create server identity and certificate
        let server_identity = Identity::new("nucleus.local", "default", "workload-api-server");
        let server_cert_sign = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = server_ca
            .sign_csr(
                server_cert_sign.csr(),
                server_cert_sign.private_key(),
                &server_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Create a DIFFERENT CA for the client (untrusted)
        let untrusted_ca = SelfSignedCa::new("untrusted.local").unwrap();
        let client_identity = Identity::new("untrusted.local", "evil", "attacker");
        let client_cert_sign = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = untrusted_ca
            .sign_csr(
                client_cert_sign.csr(),
                client_cert_sign.private_key(),
                &client_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let server_trust_bundle = server_ca.trust_bundle().clone();
        let untrusted_bundle = untrusted_ca.trust_bundle().clone();

        let server = WorkloadApiServer::new(manager, server_ca.clone(), registry);

        // Start mTLS server in background
        let socket_path_clone = socket_path.clone();
        let server_cert_clone = server_cert.clone();
        let trust_bundle_clone = server_trust_bundle.clone();
        let served_identity = server_identity.clone();
        let server_handle = tokio::spawn(async move {
            server
                .serve_mtls(
                    &socket_path_clone,
                    served_identity,
                    server_cert_clone,
                    trust_bundle_clone,
                )
                .await
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Try connecting with untrusted client cert
        // Client uses the untrusted CA's bundle (so it won't trust server)
        // Server uses server CA's bundle (so it won't trust client)
        let client = MtlsWorkloadApiClient::new(
            &socket_path,
            client_cert,
            untrusted_bundle,
            "untrusted.local",
        );

        // This should fail because:
        // 1. Server won't trust the client's certificate (different CA)
        // 2. Client won't trust the server's certificate (different CA)
        let result = client.ping().await;
        assert!(result.is_err());

        // Cleanup
        server_handle.abort();
    }
}

// Minimal UUID implementation for connection IDs
// Currently unused but kept for future vsock-based identity binding
#[allow(dead_code)]
mod uuid {
    use ring::rand::SecureRandom;

    pub struct Uuid([u8; 16]);

    impl Uuid {
        pub fn new_v4() -> Self {
            let mut bytes = [0u8; 16];
            // Use ring's random for generating UUID
            let rng = ring::rand::SystemRandom::new();
            let _ = rng.fill(&mut bytes);

            // Set version (4) and variant (RFC 4122)
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;

            Self(bytes)
        }
    }

    impl std::fmt::Display for Uuid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let hex: String = self.0.iter().map(|b| format!("{:02x}", b)).collect();
            write!(
                f,
                "{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            )
        }
    }
}
