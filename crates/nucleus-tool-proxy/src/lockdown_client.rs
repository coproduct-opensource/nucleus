//! gRPC bidirectional streaming client for fleet lockdown commands.
//!
//! Connects to the nucleus-node's `WatchLockdown` RPC and receives
//! `LockdownCommand` messages with sub-second latency. When a command
//! is received, the tool-proxy's `stream_lockdown` AtomicBool is flipped.
//!
//! Design decisions (from adversarial audit):
//! - No backoff reset on clean disconnect (prevents evasion via reconnect cycling)
//! - HMAC auth on every gRPC call (x-nucleus-timestamp/signature/method)
//! - Scope filtering on tool-proxy side (conservative: locks on unknown scopes)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{digest::KeyInit, Hmac, Mac};
use nucleus_proto::nucleus_node::node_service_client::NodeServiceClient;
use nucleus_proto::nucleus_node::{LockdownAck, LockdownCommand};
use sha2::Sha256;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

/// Configuration for the lockdown streaming watcher.
pub struct LockdownWatcherConfig {
    pub node_grpc_url: String,
    pub auth_secret: String,
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

/// Connect to the node and watch for lockdown commands.
async fn connect_and_watch(
    config: &LockdownWatcherConfig,
    flag: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = Channel::from_shared(config.node_grpc_url.clone())?
        .connect()
        .await?;

    let secret = config.auth_secret.clone();
    let mut client = NodeServiceClient::with_interceptor(channel, move |mut req: Request<()>| {
        let method = "WatchLockdown";
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();

        let signature = sign_hmac(&secret, method, &timestamp);

        req.metadata_mut().insert(
            "x-nucleus-timestamp",
            MetadataValue::try_from(&timestamp).unwrap(),
        );
        req.metadata_mut().insert(
            "x-nucleus-signature",
            MetadataValue::try_from(&signature).unwrap(),
        );
        req.metadata_mut()
            .insert("x-nucleus-method", MetadataValue::try_from(method).unwrap());

        Ok(req)
    });

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

/// Compute HMAC-SHA256 signature for gRPC auth.
fn sign_hmac(secret: &str, method: &str, timestamp: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key length is valid");
    mac.update(format!("{method}:{timestamp}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
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

    #[test]
    fn test_sign_hmac_deterministic() {
        let sig1 = sign_hmac("secret", "WatchLockdown", "12345");
        let sig2 = sign_hmac("secret", "WatchLockdown", "12345");
        assert_eq!(sig1, sig2);
        assert!(!sig1.is_empty());
    }

    #[test]
    fn test_sign_hmac_different_inputs() {
        let sig1 = sign_hmac("secret", "WatchLockdown", "12345");
        let sig2 = sign_hmac("secret", "WatchLockdown", "12346");
        assert_ne!(sig1, sig2);
    }
}
