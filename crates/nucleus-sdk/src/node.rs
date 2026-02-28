//! gRPC client for the nucleus-node service.
//!
//! [`NodeClient`] wraps the generated tonic stubs from `nucleus-proto`,
//! providing ergonomic async methods for pod lifecycle management.

use std::sync::Arc;

use nucleus_proto::nucleus_node::{
    self, node_service_client::NodeServiceClient, CreatePodRequest, Empty, GetPodRequest,
    GetReceiptRequest, PodId, StreamLogsRequest, WatchPodRequest,
};
use tonic::transport::Channel;

use crate::auth::AuthStrategy;
use crate::Error;

/// Information about a pod returned by the node service.
#[derive(Debug, Clone)]
pub struct PodInfo {
    /// Pod identifier.
    pub id: String,
    /// Pod name.
    pub name: String,
    /// Unix timestamp when the pod was created.
    pub created_at_unix: u64,
    /// Current pod state (pending, running, exited, error).
    pub state: String,
    /// Exit code (only meaningful when state is "exited").
    pub exit_code: i32,
    /// Error message (only set when state is "error").
    pub error: String,
    /// Tool-proxy address inside the pod.
    pub proxy_addr: String,
}

impl From<nucleus_node::PodInfo> for PodInfo {
    fn from(p: nucleus_node::PodInfo) -> Self {
        Self {
            id: p.id,
            name: p.name,
            created_at_unix: p.created_at_unix,
            state: p.state,
            exit_code: p.exit_code,
            error: p.error,
            proxy_addr: p.proxy_addr,
        }
    }
}

/// Execution receipt — cryptographic proof of pod execution outcome.
#[derive(Debug, Clone)]
pub struct ExecutionReceipt {
    /// Pod identifier.
    pub pod_id: String,
    /// SHA-256 hash of workspace contents at exit.
    pub workspace_hash: String,
    /// Hash of the last audit log entry.
    pub audit_tail_hash: String,
    /// Total number of audit log entries.
    pub audit_entry_count: u64,
    /// Unix timestamp when the report was generated.
    pub timestamp_unix: u64,
    /// SHA-256 hash of the serialized PodSpec manifest.
    pub manifest_hash: String,
    /// Sandbox proof tier (e.g., "attested", "spiffe_identity").
    pub sandbox_tier: String,
    /// SPIFFE ID of the pod's workload identity.
    pub spiffe_id: String,
}

impl From<nucleus_node::ExecutionReceipt> for ExecutionReceipt {
    fn from(r: nucleus_node::ExecutionReceipt) -> Self {
        Self {
            pod_id: r.pod_id,
            workspace_hash: r.workspace_hash,
            audit_tail_hash: r.audit_tail_hash,
            audit_entry_count: r.audit_entry_count,
            timestamp_unix: r.timestamp_unix,
            manifest_hash: r.manifest_hash,
            sandbox_tier: r.sandbox_tier,
            spiffe_id: r.spiffe_id,
        }
    }
}

/// Response from creating a pod.
#[derive(Debug, Clone)]
pub struct CreatePodResponse {
    /// Pod identifier.
    pub id: String,
    /// Tool-proxy address for the new pod.
    pub proxy_addr: String,
}

/// gRPC client for the nucleus-node service.
///
/// Wraps `nucleus-proto` generated stubs with auth header injection and
/// ergonomic return types.
///
/// # Example
///
/// ```rust,no_run
/// use nucleus_sdk::{NodeClient, HmacAuth};
///
/// # async fn example() -> nucleus_sdk::Result<()> {
/// let auth = HmacAuth::new(b"secret", Some("orchestrator"));
/// let client = NodeClient::connect("http://localhost:4001", Some(Box::new(auth))).await?;
///
/// let pods = client.list_pods().await?;
/// for pod in &pods {
///     println!("{}: {}", pod.id, pod.state);
/// }
/// # Ok(())
/// # }
/// ```
pub struct NodeClient {
    inner: NodeServiceClient<
        tonic::service::interceptor::InterceptedService<Channel, AuthInterceptor>,
    >,
}

/// Tonic interceptor that injects HMAC auth headers into gRPC requests.
#[derive(Clone)]
struct AuthInterceptor {
    auth: Option<Arc<dyn AuthStrategy>>,
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(auth) = &self.auth {
            // Note: tonic interceptor receives Request<()> without method path,
            // so we sign with an empty method. The server validates the timestamp
            // and signature format.
            let headers = auth.sign_grpc("");
            let metadata = request.metadata_mut();
            for (key, value) in headers {
                metadata.insert(
                    tonic::metadata::MetadataKey::from_bytes(key.as_bytes())
                        .map_err(|e| tonic::Status::internal(format!("bad header key: {}", e)))?,
                    value
                        .parse()
                        .map_err(|e| tonic::Status::internal(format!("bad header value: {}", e)))?,
                );
            }
        }
        Ok(request)
    }
}

impl NodeClient {
    /// Connect to a nucleus-node gRPC endpoint.
    pub async fn connect(
        endpoint: &str,
        auth: Option<Box<dyn AuthStrategy>>,
    ) -> Result<Self, Error> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| Error::Config(format!("invalid endpoint: {}", e)))?
            .connect()
            .await
            .map_err(|e| Error::Config(format!("gRPC connect failed: {}", e)))?;

        let interceptor = AuthInterceptor {
            auth: auth.map(Arc::from),
        };

        let inner = NodeServiceClient::with_interceptor(channel, interceptor);
        Ok(Self { inner })
    }

    /// Create a new pod from a YAML spec.
    pub async fn create_pod(
        &self,
        spec: &nucleus_spec::PodSpec,
    ) -> Result<CreatePodResponse, Error> {
        let yaml = serde_yaml::to_string(spec)
            .map_err(|e| Error::Spec(format!("failed to serialize PodSpec: {}", e)))?;
        let request = CreatePodRequest { yaml };
        let response = self.inner.clone().create_pod(request).await?;
        let inner = response.into_inner();
        Ok(CreatePodResponse {
            id: inner.id,
            proxy_addr: inner.proxy_addr,
        })
    }

    /// List all pods.
    pub async fn list_pods(&self) -> Result<Vec<PodInfo>, Error> {
        let response = self.inner.clone().list_pods(Empty {}).await?;
        Ok(response
            .into_inner()
            .pods
            .into_iter()
            .map(PodInfo::from)
            .collect())
    }

    /// Get a single pod's info.
    pub async fn get_pod(&self, pod_id: &str) -> Result<PodInfo, Error> {
        let request = GetPodRequest {
            pod_id: pod_id.to_string(),
        };
        let response = self.inner.clone().get_pod(request).await?;
        let pod = response
            .into_inner()
            .pod
            .ok_or_else(|| Error::Other(format!("pod not found: {}", pod_id)))?;
        Ok(PodInfo::from(pod))
    }

    /// Cancel a running pod.
    pub async fn cancel_pod(&self, pod_id: &str) -> Result<String, Error> {
        let request = PodId {
            id: pod_id.to_string(),
        };
        let response = self.inner.clone().cancel_pod(request).await?;
        Ok(response.into_inner().status)
    }

    /// Get pod logs (non-streaming).
    pub async fn pod_logs(&self, pod_id: &str) -> Result<String, Error> {
        let request = PodId {
            id: pod_id.to_string(),
        };
        let response = self.inner.clone().pod_logs(request).await?;
        Ok(response.into_inner().logs)
    }

    /// Stream pod logs in real time.
    pub async fn stream_pod_logs(
        &self,
        pod_id: &str,
        follow: bool,
    ) -> Result<tonic::Streaming<nucleus_node::LogEntry>, Error> {
        let request = StreamLogsRequest {
            pod_id: pod_id.to_string(),
            offset_bytes: 0,
            follow,
        };
        let response = self.inner.clone().stream_pod_logs(request).await?;
        Ok(response.into_inner())
    }

    /// Watch pod state changes in real time.
    pub async fn watch_pod_state(
        &self,
        pod_id: &str,
    ) -> Result<tonic::Streaming<nucleus_node::PodStateChange>, Error> {
        let request = WatchPodRequest {
            pod_id: pod_id.to_string(),
            include_initial: true,
        };
        let response = self.inner.clone().watch_pod_state(request).await?;
        Ok(response.into_inner())
    }

    /// Get execution receipt for a completed pod.
    pub async fn get_receipt(&self, pod_id: &str) -> Result<ExecutionReceipt, Error> {
        let request = GetReceiptRequest {
            pod_id: pod_id.to_string(),
        };
        let response = self.inner.clone().get_receipt(request).await?;
        let receipt = response
            .into_inner()
            .receipt
            .ok_or_else(|| Error::Other(format!("no receipt for pod: {}", pod_id)))?;
        Ok(ExecutionReceipt::from(receipt))
    }
}
