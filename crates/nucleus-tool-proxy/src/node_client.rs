#![allow(clippy::disallowed_types)] // #1216 exempt: node management HTTP client (infrastructure, not agent I/O)
//! HTTP client for nucleus-node pod management.
//!
//! Used by orchestrator pods to create and manage sub-pods via the
//! nucleus-node REST API, authenticating with the pod's OWN SVID over mTLS
//! — the same identity guest-init already fetches for Tier 1/2 sandbox proof
//! (`NUCLEUS_IDENTITY_CERT`/`_KEY`/`_TRUST_BUNDLE`), reused here rather than
//! minting a second one. Move B: this used to HMAC-sign every request with
//! `proxy_auth_secret` — a value the pod never independently held (the node
//! injected it at spawn) and which the node's `/v1/pods` API in fact
//! verified against a DIFFERENT secret (`auth_secret`), a pre-existing
//! mismatch this migration sidesteps rather than needing to first untangle.
//! Since the node's HTTP listener now requires mTLS unconditionally (see
//! `nucleus-node/src/http_serve.rs`), there is no HMAC fallback to keep.

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
    /// Build a node client that authenticates over mTLS with the given SVID
    /// identity, presenting it to a node whose HTTP listener now requires
    /// mTLS unconditionally.
    ///
    /// `identity_pem` is the SVID cert and key concatenated in one buffer —
    /// the same convention `nucleus-cli`'s `load_mtls_config` and
    /// `nucleus-sdk::MtlsConfig` already use, so callers can build it the
    /// same way: read cert bytes, push a newline, extend with key bytes.
    /// `trust_bundle_pem` is the node's CA root, used to validate the
    /// server's cert chain; hostname/SNI verification is skipped (see the
    /// comment on `tls_certs_only` below) because the node's SVID carries a
    /// SPIFFE URI SAN, never a DNS or IP SAN — SPIFFE identity, not
    /// hostname, is this system's trust model, matching every other mTLS
    /// client in this codebase (`nucleus-cli/src/node.rs`,
    /// `nucleus-sdk/src/auth.rs`).
    pub fn new(
        base_url: String,
        identity_pem: &[u8],
        trust_bundle_pem: &[u8],
    ) -> Result<Self, NodeClientError> {
        // Idempotent — see nucleus-cli's `create_client` for why this must
        // run before building any reqwest client on the `rustls-no-provider`
        // feature, and why installing it again here is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let identity = reqwest::Identity::from_pem(identity_pem).map_err(|e| NodeClientError {
            message: format!("failed to build client identity from SVID cert/key: {e}"),
        })?;
        let roots = reqwest::Certificate::from_pem_bundle(trust_bundle_pem).map_err(|e| {
            NodeClientError {
                message: format!("failed to parse trust bundle: {e}"),
            }
        })?;

        let http = reqwest::Client::builder()
            .identity(identity)
            .timeout(std::time::Duration::from_secs(30))
            // `tls_certs_only`, not repeated `add_root_certificate`: reqwest
            // refuses to combine `danger_accept_invalid_hostnames` with the
            // platform/webpki default roots, since that combination would
            // mean trusting a hostname-unverified cert from ANY public CA.
            // `tls_certs_only` replaces the trust store entirely with ONLY
            // the node's own CA root, so the chain is still fully validated
            // — only hostname matching is skipped, and only against a
            // pinned root.
            .tls_certs_only(roots)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| NodeClientError {
                message: format!("failed to build mTLS client: {e}"),
            })?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
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
        let mut request = self.http.get(&url);
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

        let mut request = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes.to_vec());
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

    /// POST with a JSON body, authenticated by the client cert presented at
    /// the TLS handshake — no per-request signing needed.
    async fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, NodeClientError> {
        let url = format!("{}{}", self.base_url, path);
        let body_bytes = serde_json::to_vec(body).map_err(|e| NodeClientError {
            message: e.to_string(),
        })?;

        let mut request = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes);
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

    /// GET, authenticated by the client cert presented at the TLS handshake.
    async fn get_json<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<R, NodeClientError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.http.get(&url);
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

#[cfg(test)]
mod mtls_tests {
    //! Satisfy-before-refute for Move B: construct a real client that
    //! completes an mTLS handshake and gets a real response before trusting
    //! that an unrelated CA is refused. Mirrors
    //! `nucleus-cli/src/node.rs`'s `create_client_completes_a_real_mtls_handshake`
    //! / `create_client_refuses_a_server_from_an_unrelated_ca` pair — same
    //! primitives, same two-sided proof, different client.
    use super::*;
    use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn issue(
        ca: &SelfSignedCa,
        trust_domain: &str,
        service: &str,
    ) -> nucleus_identity::WorkloadCertificate {
        let identity = Identity::new(trust_domain, "system", service);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_pods_completes_a_real_mtls_handshake() {
        let trust_domain = "node-client-mtls-test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        let server_cert = issue(&ca, trust_domain, "node").await;
        let client_cert = issue(&ca, trust_domain, "tool-proxy").await;

        let mut identity_pem = client_cert.chain_pem().into_bytes();
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(client_cert.private_key_pem().as_bytes());
        let bundle_pem = trust_bundle
            .roots()
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, trust_bundle)
                .build_acceptor()
                .unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with("GET /v1/pods"),
                "server should have received the real request the client sent, \
                 with no HMAC headers to sign or verify"
            );
            tls.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n[]",
            )
            .await
            .unwrap();
        });

        let client =
            NodeClient::new(format!("https://{addr}"), &identity_pem, &bundle_pem).unwrap();
        let pods = client
            .list_pods()
            .await
            .expect("a real mTLS handshake against the SAME CA must succeed");
        assert!(pods.is_empty());

        server_handle.await.unwrap();
    }

    /// The refute half: a server cert from an UNRELATED CA must be refused
    /// even though hostname verification is skipped — proving `tls_certs_only`
    /// is pinning to the SVID's own trust bundle, not a broader store.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_pods_refuses_a_server_from_an_unrelated_ca() {
        let real_domain = "node-client-refuse-test.nucleus.local";
        let real_ca = SelfSignedCa::new(real_domain).unwrap();
        let client_cert = issue(&real_ca, real_domain, "tool-proxy").await;
        let real_trust_bundle = real_ca.trust_bundle().clone();

        let stranger_domain = "stranger.node-client.nucleus.local";
        let stranger_ca = SelfSignedCa::new(stranger_domain).unwrap();
        let server_cert = issue(&stranger_ca, stranger_domain, "node").await;
        let stranger_trust_bundle = stranger_ca.trust_bundle().clone();

        let mut identity_pem = client_cert.chain_pem().into_bytes();
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(client_cert.private_key_pem().as_bytes());
        let bundle_pem = real_trust_bundle
            .roots()
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, stranger_trust_bundle)
                .build_acceptor()
                .unwrap();
            // A refused handshake never reaches `accept`'s Ok path — this
            // task's job is just to hold the listening socket open.
            let _ = acceptor.accept(stream).await;
        });

        let client =
            NodeClient::new(format!("https://{addr}"), &identity_pem, &bundle_pem).unwrap();
        let result = client.list_pods().await;
        assert!(
            result.is_err(),
            "a server cert from an unrelated CA must be refused, not silently trusted"
        );

        server_handle.abort();
    }
}
