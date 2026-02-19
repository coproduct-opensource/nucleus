//! HTTP client for the nucleus tool-proxy.
//!
//! [`ProxyClient`] mirrors the Python SDK's `ProxyClient`, providing typed methods
//! for all tool-proxy endpoints (`/v1/read`, `/v1/write`, `/v1/run`, etc.).
//!
//! All operations go through the tool-proxy which enforces the permission lattice
//! at the pod boundary.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::AuthStrategy;
use crate::auth::MtlsConfig;
use crate::error::{from_error_payload, Error};

/// Output from a `/v1/run` command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOutput {
    /// Process exit code.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Output from a `/v1/glob` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobOutput {
    /// Matching file paths.
    pub files: Vec<String>,
    /// Whether results were truncated.
    #[serde(default)]
    pub truncated: bool,
}

/// Output from a `/v1/grep` search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepOutput {
    /// Matching results.
    pub matches: Vec<GrepMatch>,
    /// Whether results were truncated.
    #[serde(default)]
    pub truncated: bool,
}

/// A single grep match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepMatch {
    /// File path.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Matched content.
    pub content: String,
}

/// HTTP client for the nucleus tool-proxy.
///
/// Provides typed methods for all tool-proxy endpoints. Authentication headers
/// are injected automatically via the configured [`AuthStrategy`].
///
/// # Example
///
/// ```rust,no_run
/// use nucleus_sdk::{ProxyClient, HmacAuth};
///
/// # async fn example() -> nucleus_sdk::Result<()> {
/// let auth = HmacAuth::new(b"secret", Some("user"));
/// let client = ProxyClient::new("http://127.0.0.1:8080", Some(Box::new(auth)), None)?;
///
/// let contents = client.read("/workspace/main.rs").await?;
/// println!("{}", contents);
/// # Ok(())
/// # }
/// ```
pub struct ProxyClient {
    base_url: String,
    client: reqwest::Client,
    auth: Option<Arc<dyn AuthStrategy>>,
}

impl ProxyClient {
    /// Create a new proxy client.
    pub fn new(
        base_url: &str,
        auth: Option<Box<dyn AuthStrategy>>,
        mtls: Option<&MtlsConfig>,
    ) -> Result<Self, Error> {
        let mut builder = reqwest::Client::builder();

        if let Some(mtls) = mtls {
            let identity = mtls.reqwest_identity()?;
            builder = builder.identity(identity);

            if let Some(ca) = mtls.reqwest_ca_cert()? {
                builder = builder.add_root_certificate(ca);
            }
        }

        let client = builder
            .build()
            .map_err(|e| Error::Config(format!("failed to build HTTP client: {}", e)))?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            auth: auth.map(Arc::from),
        })
    }

    /// Create from an existing reqwest client (for sharing connection pools).
    pub fn with_client(
        base_url: &str,
        client: reqwest::Client,
        auth: Option<Arc<dyn AuthStrategy>>,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            auth,
        }
    }

    /// Internal request method. Injects auth headers and parses error responses.
    async fn request(
        &self,
        method: &str,
        path: &str,
        payload: Option<&Value>,
    ) -> Result<Value, Error> {
        let url = format!("{}{}", self.base_url, path);

        let body_bytes = match payload {
            Some(v) => serde_json::to_vec(v)?,
            None => Vec::new(),
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        if let Some(auth) = &self.auth {
            for (key, value) in auth.sign_http(&body_bytes) {
                headers.insert(
                    reqwest::header::HeaderName::from_bytes(key.as_bytes())
                        .map_err(|e| Error::Config(format!("invalid header name: {}", e)))?,
                    value
                        .parse()
                        .map_err(|e| Error::Config(format!("invalid header value: {}", e)))?,
                );
            }
        }

        let request = match method {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            _ => return Err(Error::Config(format!("unsupported method: {}", method))),
        };

        let response = request.headers(headers).body(body_bytes).send().await?;

        let status = response.status().as_u16();

        if status >= 400 {
            let body: Value = response
                .json()
                .await
                .unwrap_or_else(|_| serde_json::json!({"error": "request failed"}));
            return Err(from_error_payload(status, &body));
        }

        let text = response.text().await?;
        if text.is_empty() {
            Ok(Value::Object(serde_json::Map::new()))
        } else {
            Ok(serde_json::from_str(&text)?)
        }
    }

    // -- File operations --

    /// Read a file's contents.
    pub async fn read(&self, path: &str) -> Result<String, Error> {
        let payload = serde_json::json!({"path": path});
        let data = self.request("POST", "/v1/read", Some(&payload)).await?;
        Ok(data
            .get("contents")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// Write contents to a file.
    pub async fn write(&self, path: &str, contents: &str) -> Result<(), Error> {
        let payload = serde_json::json!({"path": path, "contents": contents});
        self.request("POST", "/v1/write", Some(&payload)).await?;
        Ok(())
    }

    // -- Execution --

    /// Run a command.
    pub async fn run(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        directory: Option<&str>,
    ) -> Result<RunOutput, Error> {
        let mut payload = serde_json::json!({"args": args});
        if let Some(stdin) = stdin {
            payload["stdin"] = Value::String(stdin.to_string());
        }
        if let Some(dir) = directory {
            payload["directory"] = Value::String(dir.to_string());
        }
        let data = self.request("POST", "/v1/run", Some(&payload)).await?;
        Ok(RunOutput {
            exit_code: data.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1) as i32,
            stdout: data
                .get("stdout")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            stderr: data
                .get("stderr")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }

    // -- Search --

    /// Search for files matching a glob pattern.
    pub async fn glob(
        &self,
        pattern: &str,
        directory: Option<&str>,
        max_results: Option<u32>,
    ) -> Result<GlobOutput, Error> {
        let mut payload = serde_json::json!({"pattern": pattern});
        if let Some(dir) = directory {
            payload["directory"] = Value::String(dir.to_string());
        }
        if let Some(max) = max_results {
            payload["max_results"] = Value::Number(max.into());
        }
        let data = self.request("POST", "/v1/glob", Some(&payload)).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Search file contents with a regex pattern.
    pub async fn grep(
        &self,
        pattern: &str,
        path: Option<&str>,
        file_glob: Option<&str>,
        context_lines: Option<u32>,
        max_matches: Option<u32>,
        case_insensitive: Option<bool>,
    ) -> Result<GrepOutput, Error> {
        let mut payload = serde_json::json!({"pattern": pattern});
        if let Some(p) = path {
            payload["path"] = Value::String(p.to_string());
        }
        if let Some(g) = file_glob {
            payload["glob"] = Value::String(g.to_string());
        }
        if let Some(c) = context_lines {
            payload["context_lines"] = Value::Number(c.into());
        }
        if let Some(m) = max_matches {
            payload["max_matches"] = Value::Number(m.into());
        }
        if let Some(i) = case_insensitive {
            payload["case_insensitive"] = Value::Bool(i);
        }
        let data = self.request("POST", "/v1/grep", Some(&payload)).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Web --

    /// Fetch a URL.
    pub async fn web_fetch(
        &self,
        url: &str,
        method: Option<&str>,
        headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
    ) -> Result<Value, Error> {
        let mut payload = serde_json::json!({"url": url});
        if let Some(m) = method {
            payload["method"] = Value::String(m.to_string());
        }
        if let Some(h) = headers {
            payload["headers"] = serde_json::to_value(h)?;
        }
        if let Some(b) = body {
            payload["body"] = Value::String(b.to_string());
        }
        self.request("POST", "/v1/web_fetch", Some(&payload)).await
    }

    /// Search the web.
    pub async fn web_search(&self, query: &str, max_results: Option<u32>) -> Result<Value, Error> {
        let mut payload = serde_json::json!({"query": query});
        if let Some(max) = max_results {
            payload["max_results"] = Value::Number(max.into());
        }
        self.request("POST", "/v1/web_search", Some(&payload)).await
    }

    // -- Approval --

    /// Grant pre-approval for an operation.
    pub async fn approve(
        &self,
        operation: &str,
        count: u32,
        expires_at_unix: Option<u64>,
        nonce: Option<&str>,
    ) -> Result<Value, Error> {
        let mut payload = serde_json::json!({
            "operation": operation,
            "count": count,
        });
        if let Some(exp) = expires_at_unix {
            payload["expires_at_unix"] = Value::Number(exp.into());
        }
        if let Some(n) = nonce {
            payload["nonce"] = Value::String(n.to_string());
        }
        self.request("POST", "/v1/approve", Some(&payload)).await
    }

    // -- Pod management (orchestrator mode) --

    /// Create a sub-pod. Only available in orchestrator mode.
    pub async fn create_pod(&self, spec_yaml: &str, reason: &str) -> Result<Value, Error> {
        let payload = serde_json::json!({"spec_yaml": spec_yaml, "reason": reason});
        self.request("POST", "/v1/pod/create", Some(&payload)).await
    }

    /// List managed sub-pods.
    pub async fn list_pods(&self) -> Result<Value, Error> {
        let payload = serde_json::json!({});
        self.request("POST", "/v1/pod/list", Some(&payload)).await
    }

    /// Get sub-pod status.
    pub async fn pod_status(&self, pod_id: &str) -> Result<Value, Error> {
        let payload = serde_json::json!({"pod_id": pod_id});
        self.request("POST", "/v1/pod/status", Some(&payload)).await
    }

    /// Get sub-pod logs.
    pub async fn pod_logs(&self, pod_id: &str) -> Result<Value, Error> {
        let payload = serde_json::json!({"pod_id": pod_id});
        self.request("POST", "/v1/pod/logs", Some(&payload)).await
    }

    /// Cancel a running sub-pod.
    pub async fn cancel_pod(&self, pod_id: &str, reason: &str) -> Result<Value, Error> {
        let payload = serde_json::json!({"pod_id": pod_id, "reason": reason});
        self.request("POST", "/v1/pod/cancel", Some(&payload)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_client_trims_trailing_slash() {
        let client = ProxyClient::new("http://localhost:8080/", None, None).unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn test_proxy_client_no_slash() {
        let client = ProxyClient::new("http://localhost:8080", None, None).unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn test_run_output_deserialize() {
        let json = serde_json::json!({
            "exit_code": 0,
            "stdout": "hello\n",
            "stderr": ""
        });
        let output: RunOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "hello\n");
    }
}
