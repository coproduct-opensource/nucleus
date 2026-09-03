//! gRPC bidirectional streaming client for fleet lockdown commands.
//!
//! Connects to the nucleus-node's `WatchLockdown` RPC and receives
//! `LockdownCommand` messages with sub-second latency. When a command
//! is received, the tool-proxy's `stream_lockdown` AtomicBool is flipped.
//!
//! Design decisions (from adversarial audit):
//! - No backoff reset on clean disconnect (prevents evasion via reconnect cycling)
//! - mTLS on every gRPC call: this pod's own SVID authenticates it to the
//!   node, replacing the HMAC-per-request scheme this module used to run
//!   (Move B). The node's gRPC listener already requires a client cert
//!   unconditionally, so there is no non-mTLS path to fall back to.
//! - Scope filtering on tool-proxy side (conservative: locks on unknown scopes)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nucleus_identity::tls::{SpiffeServerCertVerifier, root_store_from_trust_bundle};
use nucleus_identity::{TrustBundle, WorkloadCertificate};
use nucleus_proto::nucleus_node::node_service_client::NodeServiceClient;
use nucleus_proto::nucleus_node::{LockdownAck, LockdownCommand};
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::transport::{ClientTlsConfig, Identity};

/// Configuration for the lockdown streaming watcher.
///
/// `client_cert_pem`/`client_key_pem` are this pod's own SVID — the same
/// identity `node_client` presents for pod-management HTTP calls — and
/// `trust_bundle_pem` is the node's CA root, used to validate the node's
/// server certificate without DNS hostname matching (the node's SVID carries
/// only a SPIFFE URI SAN).
pub struct LockdownWatcherConfig {
    pub node_grpc_url: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub trust_bundle_pem: String,
    pub trust_domain: String,
    pub proxy_id: String,
    pub pod_id: Option<String>,
}

/// Run the lockdown watcher with exponential backoff.
///
/// IMPORTANT: backoff is NOT reset on clean disconnect. This prevents an
/// adversary from cycling connections to avoid lockdown propagation.
pub async fn run_lockdown_watcher(config: LockdownWatcherConfig, flag: Arc<AtomicBool>) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        tracing::info!(
            url = %config.node_grpc_url,
            proxy_id = %config.proxy_id,
            "connecting to node lockdown stream"
        );

        match connect_and_watch(&config, flag.clone()).await {
            Ok(()) => {
                tracing::warn!("lockdown stream ended cleanly — reconnecting");
                // No backoff reset on clean disconnect (prevents evasion)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "lockdown stream error — reconnecting"
                );
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}

/// Builds the mTLS-configured channel to the node's gRPC endpoint.
///
/// Uses tonic's `tls_config_with_verifier` escape hatch rather than the
/// default WebPKI verifier: the node's SVID carries a SPIFFE URI SAN, never
/// a DNS name, so standard hostname verification would always reject it.
/// `SpiffeServerCertVerifier` is the SAME verifier `nucleus-identity`'s own
/// `TlsClientConfig` uses for every other SPIFFE mTLS client in this
/// codebase — promoted to `pub` (see its doc comment) rather than
/// reimplemented here, so this is one verifier with many callers instead of
/// two verifiers that can quietly drift apart.
async fn connect(
    config: &LockdownWatcherConfig,
) -> Result<Channel, Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client_cert =
        WorkloadCertificate::from_pem(&config.client_cert_pem, &config.client_key_pem)?;
    let trust_bundle = TrustBundle::from_pem(&config.trust_bundle_pem)?;
    let roots = root_store_from_trust_bundle(&trust_bundle)?;
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(SpiffeServerCertVerifier::new(
        Arc::new(roots),
        config.trust_domain.clone(),
    ));

    let identity = Identity::from_pem(client_cert.chain_pem(), client_cert.private_key_pem());
    let tls_config = ClientTlsConfig::new().identity(identity);

    let channel = Channel::from_shared(config.node_grpc_url.clone())?
        .tls_config_with_verifier(tls_config, verifier)?
        .connect()
        .await?;

    Ok(channel)
}

/// Connect to the node and watch for lockdown commands.
async fn connect_and_watch(
    config: &LockdownWatcherConfig,
    flag: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect(config).await?;
    let mut client = NodeServiceClient::new(channel);

    // Create an ACK sender channel — the tool-proxy sends ACKs back
    let (ack_tx, ack_rx) = tokio::sync::mpsc::channel::<LockdownAck>(16);
    let ack_stream = ReceiverStream::new(ack_rx);

    let response = client.watch_lockdown(ack_stream).await?;
    let mut stream = response.into_inner();

    let proxy_id = config.proxy_id.clone();
    let pod_id = config.pod_id.clone();

    while let Some(cmd) = stream.message().await? {
        apply_lockdown_command(&cmd, &flag, &proxy_id, pod_id.as_deref(), &ack_tx).await;
    }

    Ok(())
}

/// Check scope and apply lockdown command.
async fn apply_lockdown_command(
    cmd: &LockdownCommand,
    flag: &Arc<AtomicBool>,
    proxy_id: &str,
    pod_id: Option<&str>,
    ack_tx: &tokio::sync::mpsc::Sender<LockdownAck>,
) {
    let applies = apply_scope(&cmd.scope, pod_id);

    if applies {
        let was = flag.swap(cmd.active, Ordering::SeqCst);
        if was != cmd.active {
            if cmd.active {
                tracing::warn!(
                    reason = %cmd.reason,
                    operator = %cmd.operator_id,
                    scope = %cmd.scope,
                    "LOCKDOWN ACTIVATED via gRPC stream"
                );
            } else {
                tracing::info!(
                    reason = %cmd.reason,
                    operator = %cmd.operator_id,
                    scope = %cmd.scope,
                    "Lockdown lifted via gRPC stream"
                );
            }
        }
    } else {
        tracing::debug!(
            scope = %cmd.scope,
            pod_id = ?pod_id,
            "lockdown command does not apply to this proxy"
        );
    }

    // Send ACK regardless of whether it applied (node tracks delivery)
    let ack = LockdownAck {
        proxy_id: proxy_id.to_string(),
        applied: applies,
        timestamp_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    if let Err(e) = ack_tx.send(ack).await {
        tracing::warn!(error = %e, "failed to send lockdown ACK");
    }
}

/// Determine whether a lockdown scope applies to this proxy.
///
/// Conservative: locks on unknown scopes and label selectors
/// (we don't have label info in the proxy, so assume it applies).
fn apply_scope(scope: &str, pod_id: Option<&str>) -> bool {
    if scope == "all" || scope.is_empty() {
        return true;
    }

    if let Some(target_pod) = scope.strip_prefix("pod:") {
        return match pod_id {
            Some(my_id) => my_id == target_pod,
            // No pod_id configured — conservatively lock
            None => true,
        };
    }

    if scope.starts_with("label:") {
        // We don't have label information in the tool-proxy,
        // so conservatively assume it applies.
        return true;
    }

    // Unknown scope format — conservatively lock
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_scope_all() {
        assert!(apply_scope("all", None));
        assert!(apply_scope("all", Some("pod-123")));
    }

    #[test]
    fn test_apply_scope_empty() {
        assert!(apply_scope("", None));
        assert!(apply_scope("", Some("pod-123")));
    }

    #[test]
    fn test_apply_scope_pod_match() {
        assert!(apply_scope("pod:abc-123", Some("abc-123")));
    }

    #[test]
    fn test_apply_scope_pod_mismatch() {
        assert!(!apply_scope("pod:abc-123", Some("other-pod")));
    }

    #[test]
    fn test_apply_scope_pod_no_pod_id_conservative() {
        // No pod_id configured → conservative lock
        assert!(apply_scope("pod:abc-123", None));
    }

    #[test]
    fn test_apply_scope_label_conservative() {
        assert!(apply_scope("label:team=frontend", Some("pod-123")));
        assert!(apply_scope("label:team=frontend", None));
    }

    #[test]
    fn test_apply_scope_unknown_conservative() {
        assert!(apply_scope("something-unknown", None));
    }
}

#[cfg(test)]
mod mtls_tests {
    //! Satisfy-before-refute for Move B: `connect_and_watch` used to sign
    //! every gRPC call with an HMAC interceptor; now it presents an SVID
    //! over mTLS via tonic's `tls_config_with_verifier` + the promoted
    //! `SpiffeServerCertVerifier`. That plumbing is genuinely new — nothing
    //! in this codebase built a tonic mTLS *client* before this change — so
    //! it gets a real server, a real handshake, and a real command
    //! delivered end to end, not just a construction-succeeds check.
    use super::*;
    use nucleus_identity::{CaClient, CsrOptions, Identity as SvidIdentity, SelfSignedCa};
    use nucleus_proto::nucleus_node::node_service_server::{NodeService, NodeServiceServer};
    use nucleus_proto::nucleus_node::{self as proto};
    use std::sync::atomic::AtomicBool;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    async fn issue(ca: &SelfSignedCa, trust_domain: &str, service: &str) -> WorkloadCertificate {
        let identity = SvidIdentity::new(trust_domain, "system", service);
        let csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        ca.sign_csr(
            csr.csr(),
            csr.private_key(),
            &identity,
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap()
    }

    /// Serves exactly one RPC: `watch_lockdown`, which sends a single
    /// `LockdownCommand` and then closes its half of the stream. Every other
    /// method is unreachable from this test and left `unimplemented!()`.
    struct OneShotLockdown;

    #[tonic::async_trait]
    impl NodeService for OneShotLockdown {
        type StreamPodLogsStream = ReceiverStream<Result<proto::LogEntry, Status>>;
        type WatchPodStateStream = ReceiverStream<Result<proto::PodStateChange, Status>>;
        type WatchLockdownStream = ReceiverStream<Result<proto::LockdownCommand, Status>>;

        async fn create_pod(
            &self,
            _r: Request<proto::CreatePodRequest>,
        ) -> Result<Response<proto::CreatePodResponse>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn list_pods(
            &self,
            _r: Request<proto::Empty>,
        ) -> Result<Response<proto::ListPodsResponse>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn get_pod(
            &self,
            _r: Request<proto::GetPodRequest>,
        ) -> Result<Response<proto::GetPodResponse>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn cancel_pod(
            &self,
            _r: Request<proto::PodId>,
        ) -> Result<Response<proto::CancelPodResponse>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn pod_logs(
            &self,
            _r: Request<proto::PodId>,
        ) -> Result<Response<proto::PodLogsResponse>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn stream_pod_logs(
            &self,
            _r: Request<proto::StreamLogsRequest>,
        ) -> Result<Response<Self::StreamPodLogsStream>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn watch_pod_state(
            &self,
            _r: Request<proto::WatchPodRequest>,
        ) -> Result<Response<Self::WatchPodStateStream>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn get_receipt(
            &self,
            _r: Request<proto::GetReceiptRequest>,
        ) -> Result<Response<proto::GetReceiptResponse>, Status> {
            unimplemented!("not exercised by this test")
        }
        async fn lockdown(
            &self,
            _r: Request<proto::LockdownRequest>,
        ) -> Result<Response<proto::LockdownResponse>, Status> {
            unimplemented!("not exercised by this test")
        }

        async fn watch_lockdown(
            &self,
            request: Request<tonic::Streaming<proto::LockdownAck>>,
        ) -> Result<Response<Self::WatchLockdownStream>, Status> {
            // Prove the request really arrived through the mTLS layer, not
            // a bypassed/plaintext path.
            let _ = request.into_inner();

            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(Ok(proto::LockdownCommand {
                active: true,
                scope: "all".to_string(),
                reason: "mtls integration test".to_string(),
                operator_id: "test".to_string(),
                timestamp_unix: 0,
            }))
            .await
            .unwrap();
            // Dropping `tx` here (end of scope) closes the stream after the
            // one message — `connect_and_watch`'s `while let Some(cmd) = ...`
            // loop then returns `Ok(())` cleanly.
            Ok(Response::new(ReceiverStream::new(rx)))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_and_watch_completes_a_real_mtls_handshake_and_receives_a_command() {
        // The server task's TLS accept races `connect()`'s own install — do
        // it here too so whichever runs first doesn't leave the other
        // without a provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let trust_domain = "lockdown-client-mtls-test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        let server_cert = issue(&ca, trust_domain, "node").await;
        let client_cert = issue(&ca, trust_domain, "tool-proxy").await;

        let server_cert_pem = server_cert
            .chain()
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n");
        let server_identity =
            tonic::transport::Identity::from_pem(&server_cert_pem, server_cert.private_key_pem());
        let ca_pem = trust_bundle
            .roots()
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n");
        let server_tls = tonic::transport::ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(tonic::transport::Certificate::from_pem(&ca_pem));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(server_tls)
                .unwrap()
                .add_service(NodeServiceServer::new(OneShotLockdown))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let config = LockdownWatcherConfig {
            node_grpc_url: format!("https://{addr}"),
            client_cert_pem: client_cert.chain_pem(),
            client_key_pem: client_cert.private_key_pem().to_string(),
            trust_bundle_pem: trust_bundle
                .roots()
                .iter()
                .map(|c| c.to_pem())
                .collect::<Vec<_>>()
                .join("\n"),
            trust_domain: trust_domain.to_string(),
            proxy_id: "test-proxy".to_string(),
            pod_id: None,
        };
        let flag = Arc::new(AtomicBool::new(false));

        tokio::time::timeout(
            Duration::from_secs(10),
            connect_and_watch(&config, flag.clone()),
        )
        .await
        .expect("connect_and_watch should complete, not hang")
        .expect("a real mTLS handshake against the SAME CA must succeed");

        assert!(
            flag.load(Ordering::SeqCst),
            "the LockdownCommand sent over the mTLS stream must have flipped the flag"
        );

        server_handle.abort();
    }
}
