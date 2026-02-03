//! Vsock bridge for the Workload API.
//!
//! This module provides a vsock server that accepts incoming connections from
//! Firecracker guests for the SPIFFE Workload API.
//!
//! # Firecracker Vsock Protocol
//!
//! For guest-to-host connections, Firecracker uses a socket naming convention:
//! - Host listens on: `{uds_path}_{port}` (e.g., `vsock.sock_15012`)
//! - Guest connects to CID 2 (host) on the specified port via AF_VSOCK
//! - Firecracker routes the connection to the host's Unix socket
//!
//! Reference: https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md
//!
//! # Workload API Protocol
//!
//! Once connected, the guest sends commands:
//! - `FETCH_SVID\n` - Request the X.509 SVID (certificate + key)
//! - `FETCH_BUNDLE\n` - Request the trust bundle (root CA certificates)
//! - `PING\n` - Health check
//!
//! Responses are newline-delimited JSON.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use crate::identity::IdentityManager;

/// Default port for the Workload API vsock server.
#[allow(dead_code)]
pub const DEFAULT_WORKLOAD_API_PORT: u32 = 15012;

/// Vsock bridge for the Workload API.
///
/// This server listens on a Unix socket following Firecracker's naming convention
/// (`{vsock_uds_path}_{port}`) and handles Workload API requests from guests.
///
/// Each bridge is associated with a specific pod and provides that pod's unique
/// SPIFFE identity.
pub struct WorkloadApiVsockBridge {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    socket_path: PathBuf,
    /// The pod ID this bridge serves (used for unique identity per pod).
    #[allow(dead_code)]
    pod_id: uuid::Uuid,
}

impl std::fmt::Debug for WorkloadApiVsockBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadApiVsockBridge")
            .field("socket_path", &self.socket_path)
            .finish()
    }
}

impl WorkloadApiVsockBridge {
    /// Starts the Workload API vsock bridge for a specific pod.
    ///
    /// Creates a Unix socket at `{vsock_uds_path}_{port}` following Firecracker's
    /// naming convention for guest-to-host connections.
    ///
    /// # Arguments
    ///
    /// * `vsock_uds_path` - The base vsock UDS path configured in Firecracker
    /// * `port` - The port number guests will connect to (e.g., 15012)
    /// * `pod_id` - The unique identifier for the pod this bridge serves
    /// * `identity_manager` - The identity manager for fetching certificates
    ///
    /// # Example
    ///
    /// If `vsock_uds_path` is `/tmp/pod/vsock.sock` and `port` is 15012,
    /// the bridge will listen on `/tmp/pod/vsock.sock_15012`.
    ///
    /// Each pod gets its own bridge with a unique SPIFFE identity based on `pod_id`.
    #[allow(dead_code)]
    pub async fn start(
        vsock_uds_path: impl AsRef<Path>,
        port: u32,
        pod_id: uuid::Uuid,
        identity_manager: IdentityManager,
    ) -> std::io::Result<Self> {
        // Firecracker naming convention: {uds_path}_{port}
        let socket_path = PathBuf::from(format!("{}_{}", vsock_uds_path.as_ref().display(), port));

        // Remove existing socket if present
        if socket_path.exists() {
            tokio::fs::remove_file(&socket_path).await?;
        }

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let socket_path_clone = socket_path.clone();
        let task = tokio::spawn(async move {
            info!(
                "workload API vsock bridge listening on {} (port {}) for pod {}",
                socket_path_clone.display(),
                port,
                pod_id
            );

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        info!("workload API vsock bridge shutting down for pod {}", pod_id);
                        break;
                    }
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _)) => {
                                let manager = identity_manager.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = handle_connection(stream, manager, pod_id).await {
                                        debug!("workload API connection closed: {err}");
                                    }
                                });
                            }
                            Err(err) => {
                                error!("workload API vsock bridge accept error: {err}");
                                // Don't break on accept errors - could be transient
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            task,
            socket_path,
            pod_id,
        })
    }

    /// Returns the pod ID this bridge serves.
    #[allow(dead_code)]
    pub fn pod_id(&self) -> uuid::Uuid {
        self.pod_id
    }

    /// Returns the socket path.
    #[allow(dead_code)]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Shuts down the bridge.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
        // Clean up socket file
        let _ = tokio::fs::remove_file(&self.socket_path).await;
    }
}

/// Handles a single Workload API connection from a guest.
#[allow(dead_code)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    manager: IdentityManager,
    pod_id: uuid::Uuid,
) -> std::io::Result<()> {
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
            "workload API received command: {} for pod {}",
            command, pod_id
        );

        let response = match command {
            "FETCH_SVID" => handle_fetch_svid(&manager, pod_id).await,
            "FETCH_BUNDLE" => handle_fetch_bundle(&manager),
            "PING" => r#"{"status":"ok"}"#.to_string(),
            _ => format!(r#"{{"error":"unknown command: {}"}}"#, command),
        };

        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Handles FETCH_SVID command - returns the workload certificate and key.
///
/// Each pod gets a unique SPIFFE identity based on its pod_id:
/// `spiffe://{trust_domain}/ns/pods/sa/{pod_id}`
#[allow(dead_code)]
async fn handle_fetch_svid(manager: &IdentityManager, pod_id: uuid::Uuid) -> String {
    // Create a unique identity for this specific pod
    // The identity is based on the pod's UUID, ensuring isolation between pods
    let identity =
        nucleus_identity::Identity::new(manager.trust_domain(), "pods", pod_id.to_string());

    // Fetch the certificate with the actual certificate data
    match manager.fetch_certificate(&identity).await {
        Ok(cert) => {
            #[derive(serde::Serialize)]
            struct SvidResponse {
                spiffe_id: String,
                certificate_chain: String,
                private_key: String,
                expires_at: i64,
            }

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
            error!("failed to fetch certificate for pod {}: {}", pod_id, e);
            format!(r#"{{"error":"{}"}}"#, e)
        }
    }
}

/// Handles FETCH_BUNDLE command - returns the trust bundle (CA certificates).
#[allow(dead_code)]
fn handle_fetch_bundle(manager: &IdentityManager) -> String {
    #[derive(serde::Serialize)]
    struct BundleResponse {
        trust_domain: String,
        bundle_pem: String,
    }

    let bundle = manager.trust_bundle();
    let pem: String = bundle
        .roots()
        .iter()
        .map(|c| c.to_pem().to_string())
        .collect();

    let response = BundleResponse {
        trust_domain: manager.trust_domain().to_string(),
        bundle_pem: pem,
    };

    serde_json::to_string(&response)
        .unwrap_or_else(|e| format!(r#"{{"error":"serialization failed: {}"}}"#, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

    #[tokio::test]
    async fn test_workload_api_vsock_bridge_ping() {
        let temp_dir = tempdir().unwrap();
        // Simulate Firecracker's vsock UDS path
        let vsock_uds_path = temp_dir.path().join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(&vsock_uds_path, 15012, pod_id, manager)
            .await
            .unwrap();

        // Verify socket path follows Firecracker convention
        assert_eq!(
            bridge.socket_path(),
            temp_dir.path().join("vsock.sock_15012")
        );
        // Verify pod_id is stored
        assert_eq!(bridge.pod_id(), pod_id);

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect to the socket (simulating Firecracker routing a guest connection)
        let stream = tokio::net::UnixStream::connect(bridge.socket_path())
            .await
            .unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"PING\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        assert!(response.contains("ok"));

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_workload_api_vsock_bridge_fetch_bundle() {
        let temp_dir = tempdir().unwrap();
        let vsock_uds_path = temp_dir.path().join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(&vsock_uds_path, 15012, pod_id, manager)
            .await
            .unwrap();

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect and send FETCH_BUNDLE
        let stream = tokio::net::UnixStream::connect(bridge.socket_path())
            .await
            .unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"FETCH_BUNDLE\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        assert!(response.contains("trust_domain"));
        assert!(response.contains("test.local"));
        assert!(response.contains("bundle_pem"));

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_socket_naming_convention() {
        let temp_dir = tempdir().unwrap();
        let vsock_uds_path = temp_dir.path().join("pod-123").join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(&vsock_uds_path, 8080, pod_id, manager)
            .await
            .unwrap();

        // Verify Firecracker naming convention: {uds_path}_{port}
        let expected_path = temp_dir.path().join("pod-123").join("vsock.sock_8080");
        assert_eq!(bridge.socket_path(), expected_path);

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_fetch_svid_returns_real_certificate() {
        let temp_dir = tempdir().unwrap();
        let vsock_uds_path = temp_dir.path().join("vsock.sock");
        let pod_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();
        let bridge = WorkloadApiVsockBridge::start(&vsock_uds_path, 15012, pod_id, manager)
            .await
            .unwrap();

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect and send FETCH_SVID
        let stream = tokio::net::UnixStream::connect(bridge.socket_path())
            .await
            .unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"FETCH_SVID\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        // Verify the response contains real certificate data
        assert!(
            response.contains("spiffe_id"),
            "response should contain spiffe_id"
        );
        assert!(
            response.contains(&pod_id.to_string()),
            "spiffe_id should contain pod_id"
        );
        assert!(
            response.contains("BEGIN CERTIFICATE"),
            "should contain real certificate"
        );
        assert!(
            response.contains("BEGIN PRIVATE KEY"),
            "should contain real private key"
        );
        assert!(response.contains("expires_at"), "should contain expiry");

        // Parse the response to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(
            parsed["expires_at"].as_i64().unwrap() > 0,
            "expires_at should be set"
        );

        bridge.shutdown().await;
    }

    #[tokio::test]
    async fn test_different_pods_get_different_identities() {
        let temp_dir = tempdir().unwrap();
        let pod1_id = uuid::Uuid::new_v4();
        let pod2_id = uuid::Uuid::new_v4();

        let manager = IdentityManager::new("test.local", Duration::from_secs(3600)).unwrap();

        // Create bridges for two different pods
        let vsock1_path = temp_dir.path().join("pod1").join("vsock.sock");
        let vsock2_path = temp_dir.path().join("pod2").join("vsock.sock");

        let bridge1 = WorkloadApiVsockBridge::start(&vsock1_path, 15012, pod1_id, manager.clone())
            .await
            .unwrap();
        let bridge2 = WorkloadApiVsockBridge::start(&vsock2_path, 15012, pod2_id, manager.clone())
            .await
            .unwrap();

        // Wait for servers to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fetch SVID from both bridges
        let svid1 = fetch_svid_from_socket(bridge1.socket_path()).await;
        let svid2 = fetch_svid_from_socket(bridge2.socket_path()).await;

        // Verify they have different identities
        assert!(
            svid1.contains(&pod1_id.to_string()),
            "svid1 should contain pod1_id"
        );
        assert!(
            svid2.contains(&pod2_id.to_string()),
            "svid2 should contain pod2_id"
        );
        assert!(
            !svid1.contains(&pod2_id.to_string()),
            "svid1 should NOT contain pod2_id"
        );
        assert!(
            !svid2.contains(&pod1_id.to_string()),
            "svid2 should NOT contain pod1_id"
        );

        bridge1.shutdown().await;
        bridge2.shutdown().await;
    }

    /// Helper to fetch SVID from a socket path
    async fn fetch_svid_from_socket(socket_path: &Path) -> String {
        let stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
        let (reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        writer.write_all(b"FETCH_SVID\n").await.unwrap();
        writer.flush().await.unwrap();

        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();
        response
    }
}
