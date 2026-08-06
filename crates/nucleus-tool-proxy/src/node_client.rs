#![allow(clippy::disallowed_types)] // #1216 exempt: node management HTTP client (infrastructure, not agent I/O)
//! HTTP client for nucleus-node pod management.
//!
//! Used by orchestrator pods to create and manage sub-pods via
//! the nucleus-node REST API with HMAC request signing.

use nucleus_client::sign_http_headers;

/// The header names, imported rather than restated. Both sides reading one
/// definition is what keeps a typo from silently degrading every caller to
/// "unidentified" — the fail-open direction, and one that raises no error.
pub(crate) use nucleus_client::{HEADER_POD_ID, HEADER_POD_TOKEN};

/// Whether a (pod id, token) pair amounts to an identity — the decision itself,
/// separated from where the values come from so it can be tested without
/// mutating process-wide environment state.
///
/// An EMPTY value is treated as absent. It would otherwise be presented as a
/// real claim: the node would see `x-nucleus-pod-id: ` on every request, fail to
/// parse it, and log "claimed an identity it could not prove" for traffic that
/// claimed nothing — turning a quiet default into a permanent false alarm, which
/// is how a genuine one stops being noticed.
fn caller_identity_from(id: Option<String>, token: Option<String>) -> Option<(String, String)> {
    let id = id.filter(|v| !v.is_empty())?;
    let token = token.filter(|v| !v.is_empty())?;
    Some((id, token))
}

/// The (pod id, token) pair this proxy presents so the node can tell WHICH pod
/// is calling.
///
/// Both come from guest-init, which fetched the token over this pod's own vsock
/// socket — the host decided which pod that is. `None` on a deployment where
/// identity was never fetched; the node still accepts unidentified callers, so
/// omitting the headers degrades to the older behaviour rather than failing.
pub(crate) fn caller_identity_headers() -> Option<(String, String)> {
    caller_identity_from(
        std::env::var("NUCLEUS_POD_ID").ok(),
        std::env::var("NUCLEUS_POD_CALLER_TOKEN").ok(),
    )
}
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
#[serde(rename_all = "snake_case")]
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
        if let Some((pod_id, token)) = caller_identity_headers() {
            request = request.header(HEADER_POD_ID, pod_id);
            request = request.header(HEADER_POD_TOKEN, token);
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
        if let Some((pod_id, token)) = caller_identity_headers() {
            request = request.header(HEADER_POD_ID, pod_id);
            request = request.header(HEADER_POD_TOKEN, token);
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
        if let Some((pod_id, token)) = caller_identity_headers() {
            request = request.header(HEADER_POD_ID, pod_id);
            request = request.header(HEADER_POD_TOKEN, token);
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
        if let Some((pod_id, token)) = caller_identity_headers() {
            request = request.header(HEADER_POD_ID, pod_id);
            request = request.header(HEADER_POD_TOKEN, token);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pod_state_deserialize_externally_tagged() {
        // nucleus-node uses externally-tagged serde (no `tag` attribute)
        let running: PodState = serde_json::from_str(r#""running""#).unwrap();
        assert!(matches!(running, PodState::Running));

        let exited: PodState = serde_json::from_str(r#"{"exited":{"code":0}}"#).unwrap();
        assert!(matches!(exited, PodState::Exited { code: Some(0) }));

        let error: PodState = serde_json::from_str(r#"{"error":{"message":"boom"}}"#).unwrap();
        assert!(matches!(error, PodState::Error { message } if message == "boom"));
    }

    #[test]
    fn test_pod_info_deserialize() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "test-pod",
            "created_at_unix": 1700000000,
            "state": "running",
            "proxy_addr": "127.0.0.1:8080"
        }"#;
        let info: PodInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.name, Some("test-pod".to_string()));
        assert!(matches!(info.state, PodState::Running));
    }

    #[test]
    fn test_pod_info_deserialize_exited() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": null,
            "created_at_unix": 1700000000,
            "state": {"exited": {"code": 42}},
            "proxy_addr": null
        }"#;
        let info: PodInfo = serde_json::from_str(json).unwrap();
        assert!(matches!(info.state, PodState::Exited { code: Some(42) }));
    }
}

#[cfg(test)]
mod caller_identity_tests {
    use super::caller_identity_from;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn both_present_is_an_identity() {
        assert_eq!(
            caller_identity_from(s("pod-1"), s("tok")),
            Some(("pod-1".to_string(), "tok".to_string()))
        );
    }

    /// A pod id without its token is not an identity — the id alone is a claim
    /// anyone could make, so presenting it would be worse than presenting
    /// nothing.
    #[test]
    fn an_id_without_a_token_is_not_an_identity() {
        assert_eq!(caller_identity_from(s("pod-1"), None), None);
        assert_eq!(caller_identity_from(None, s("tok")), None);
    }

    /// Empty is absent, not present-and-blank. See `caller_identity_from`.
    #[test]
    fn empty_values_are_absent() {
        assert_eq!(caller_identity_from(s(""), s("tok")), None);
        assert_eq!(caller_identity_from(s("pod-1"), s("")), None);
    }

    /// The two header names must differ, or one would overwrite the other and
    /// the token would travel under the id's name.
    #[test]
    fn the_two_headers_are_distinct() {
        assert_ne!(super::HEADER_POD_ID, super::HEADER_POD_TOKEN);
    }
}
