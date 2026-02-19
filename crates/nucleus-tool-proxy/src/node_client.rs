//! HTTP client for nucleus-node pod management.
//!
//! Used by orchestrator pods to create and manage sub-pods via
//! the nucleus-node REST API with HMAC request signing.

use nucleus_client::sign_http_headers;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Thin HTTP client wrapping nucleus-node pod management endpoints.
#[derive(Clone)]
pub struct NodeClient {
    base_url: String,
    auth_secret: Vec<u8>,
    http: reqwest::Client,
}

/// Information about a managed pod (mirrors nucleus-node PodInfo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInfo {
    pub id: Uuid,
    pub name: Option<String>,
    pub created_at_unix: u64,
    pub state: PodState,
    pub proxy_addr: Option<String>,
}

/// Pod state (mirrors nucleus-node PodState).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PodState {
    Running,
    Exited { code: Option<i32> },
    Error { message: String },
}

/// Response from creating a pod.
#[derive(Debug, Deserialize)]
pub struct CreatePodResponse {
    pub id: Uuid,
    pub proxy_addr: Option<String>,
}

/// Error from node client operations.
#[derive(Debug)]
pub struct NodeClientError {
    pub message: String,
}

impl std::fmt::Display for NodeClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node client error: {}", self.message)
    }
}

impl std::error::Error for NodeClientError {}

impl NodeClient {
    /// Create a new node client.
    pub fn new(base_url: String, auth_secret: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_secret: auth_secret.into_bytes(),
            http,
        }
    }

    /// Create a sub-pod from a PodSpec YAML string.
    pub async fn create_pod(&self, yaml: &str) -> Result<CreatePodResponse, NodeClientError> {
        let body = serde_json::json!({ "yaml": yaml });
        self.post_json("/v1/pods", &body).await
    }

    /// List all pods managed by this node.
    pub async fn list_pods(&self) -> Result<Vec<PodInfo>, NodeClientError> {
        self.get_json("/v1/pods").await
    }

    /// Get logs for a specific pod.
    pub async fn pod_logs(&self, id: Uuid) -> Result<String, NodeClientError> {
        let url = format!("{}/v1/pods/{}/logs", self.base_url, id);
        let body_bytes = b"";
        let signed = sign_http_headers(&self.auth_secret, Some("tool-proxy"), body_bytes);

        let mut request = self.http.get(&url);
        for (key, value) in &signed.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request.send().await.map_err(|e| NodeClientError {
            message: e.to_string(),
        })?;

        if !response.status().is_success() {
            return Err(NodeClientError {
                message: format!("pod_logs failed: HTTP {}", response.status()),
            });
        }

        response.text().await.map_err(|e| NodeClientError {
            message: e.to_string(),
        })
    }

    /// Cancel a running pod.
    pub async fn cancel_pod(&self, id: Uuid) -> Result<(), NodeClientError> {
        let url = format!("{}/v1/pods/{}/cancel", self.base_url, id);
        let body_bytes = b"{}";
        let signed = sign_http_headers(&self.auth_secret, Some("tool-proxy"), body_bytes);

        let mut request = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes.to_vec());
        for (key, value) in &signed.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request.send().await.map_err(|e| NodeClientError {
            message: e.to_string(),
        })?;

        if !response.status().is_success() {
            return Err(NodeClientError {
                message: format!("cancel_pod failed: HTTP {}", response.status()),
            });
        }

        Ok(())
    }

    /// POST with JSON body and HMAC signing.
    async fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, NodeClientError> {
        let url = format!("{}{}", self.base_url, path);
        let body_bytes = serde_json::to_vec(body).map_err(|e| NodeClientError {
            message: e.to_string(),
        })?;
        let signed = sign_http_headers(&self.auth_secret, Some("tool-proxy"), &body_bytes);

        let mut request = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes);
        for (key, value) in &signed.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request.send().await.map_err(|e| NodeClientError {
            message: e.to_string(),
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(NodeClientError {
                message: format!("HTTP {}: {}", status, text),
            });
        }

        response.json::<R>().await.map_err(|e| NodeClientError {
            message: e.to_string(),
        })
    }

    /// GET with HMAC signing.
    async fn get_json<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<R, NodeClientError> {
        let url = format!("{}{}", self.base_url, path);
        let body_bytes = b"";
        let signed = sign_http_headers(&self.auth_secret, Some("tool-proxy"), body_bytes);

        let mut request = self.http.get(&url);
        for (key, value) in &signed.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request.send().await.map_err(|e| NodeClientError {
            message: e.to_string(),
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(NodeClientError {
                message: format!("HTTP {}: {}", status, text),
            });
        }

        response.json::<R>().await.map_err(|e| NodeClientError {
            message: e.to_string(),
        })
    }
}
